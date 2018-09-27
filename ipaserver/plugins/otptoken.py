# Authors:
#   Nathaniel McCallum <npmccallum@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from .baseldap import LDAPObject, LDAPAddMember, LDAPRemoveMember
from .baseldap import LDAPCreate, LDAPDelete, LDAPUpdate, LDAPSearch, LDAPRetrieve
from ipalib import api, Int, Str, Bool, DateTime, Flag, Bytes, IntEnum, StrEnum, _, ngettext
from ipalib.plugable import Registry
from ipalib.errors import (
    PasswordMismatch,
    ConversionError,
    NotFound,
    ValidationError)
from ipalib.request import context
from ipapython.dn import DN

import base64
import urllib
import uuid
import os

import six

if six.PY3:
    unicode = str

__doc__ = _("""
OTP Tokens
""") + _("""
Manage OTP tokens.
""") + _("""
IPA supports the use of OTP tokens for multi-factor authentication. This
code enables the management of OTP tokens.
""") + _("""
EXAMPLES:
""") + _("""
 Add a new token:
   ipa otptoken-add --type=totp --owner=jdoe --desc="My soft token"
""") + _("""
 Examine the token:
   ipa otptoken-show a93db710-a31a-4639-8647-f15b2c70b78a
""") + _("""
 Change the vendor:
   ipa otptoken-mod a93db710-a31a-4639-8647-f15b2c70b78a --vendor="Red Hat"
""") + _("""
 Delete a token:
   ipa otptoken-del a93db710-a31a-4639-8647-f15b2c70b78a
""")

register = Registry()

topic = 'otp'

TOKEN_TYPES = {
    u'totp': ['ipatokentotpclockoffset', 'ipatokentotptimestep'],
    u'hotp': ['ipatokenhotpcounter']
}

# NOTE: For maximum compatibility, KEY_LENGTH % 5 == 0
KEY_LENGTH = 35

class OTPTokenKey(Bytes):
    """A binary password type specified in base32."""

    password = True

    def _convert_scalar(self, value, index=None):
        if isinstance(value, (tuple, list)) and len(value) == 2:
            (p1, p2) = value
            if p1 != p2:
                raise PasswordMismatch(name=self.name)
            value = p1

        if isinstance(value, unicode):
            try:
                value = base64.b32decode(value, True)
            except TypeError as e:
                raise ConversionError(name=self.name, error=str(e))

        return super(OTPTokenKey, self)._convert_scalar(value)

def _convert_owner(userobj, entry_attrs, options):
    if 'ipatokenowner' in entry_attrs and not options.get('raw', False):
        entry_attrs['ipatokenowner'] = [userobj.get_primary_key_from_dn(o)
                                        for o in entry_attrs['ipatokenowner']]


def _normalize_owner(userobj, entry_attrs):
    owner = entry_attrs.get('ipatokenowner', None)
    if owner:
        try:
            entry_attrs['ipatokenowner'] = userobj._normalize_manager(
                owner
            )[0]
        except NotFound:
            raise userobj.handle_not_found(owner)


def _check_interval(not_before, not_after):
    if not_before and not_after:
        return not_before <= not_after
    return True


def _set_token_type(entry_attrs, **options):
    klasses = [x.lower() for x in entry_attrs.get('objectclass', [])]
    for ttype in TOKEN_TYPES:
        cls = 'ipatoken' + ttype
        if cls.lower() in klasses:
            entry_attrs['type'] = ttype.upper()

    if not options.get('all', False) or options.get('pkey_only', False):
        entry_attrs.pop('objectclass', None)


@register()
class otptoken(LDAPObject):
    """
    OTP Token object.
    """
    container_dn = api.env.container_otp
    object_name = _('OTP token')
    object_name_plural = _('OTP tokens')
    object_class = ['ipatoken']
    possible_objectclasses = ['ipatokentotp', 'ipatokenhotp']
    default_attributes = [
        'ipatokenuniqueid', 'description', 'ipatokenowner',
        'ipatokendisabled', 'ipatokennotbefore', 'ipatokennotafter',
        'ipatokenvendor', 'ipatokenmodel', 'ipatokenserial', 'managedby'
    ]
    attribute_members = {
        'managedby': ['user'],
    }
    relationships = {
        'managedby': ('Managed by', 'man_by_', 'not_man_by_'),
    }
    allow_rename = True

    label = _('OTP Tokens')
    label_singular = _('OTP Token')

    takes_params = (
        Str('ipatokenuniqueid',
            cli_name='id',
            label=_('Unique ID'),
            primary_key=True,
            flags=('optional_create'),
        ),
        StrEnum('type?',
            label=_('Type'),
            doc=_('Type of the token'),
            default=u'totp',
            autofill=True,
            values=tuple(list(TOKEN_TYPES) + [x.upper() for x in TOKEN_TYPES]),
            flags=('virtual_attribute', 'no_update'),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('Token description (informational only)'),
        ),
        Str('ipatokenowner?',
            cli_name='owner',
            label=_('Owner'),
            doc=_('Assigned user of the token (default: self)'),
        ),
        Str('managedby_user?',
            label=_('Manager'),
            doc=_('Assigned manager of the token (default: self)'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Bool('ipatokendisabled?',
            cli_name='disabled',
            label=_('Disabled'),
            doc=_('Mark the token as disabled (default: false)')
        ),
        DateTime('ipatokennotbefore?',
            cli_name='not_before',
            label=_('Validity start'),
            doc=_('First date/time the token can be used'),
        ),
        DateTime('ipatokennotafter?',
            cli_name='not_after',
            label=_('Validity end'),
            doc=_('Last date/time the token can be used'),
        ),
        Str('ipatokenvendor?',
            cli_name='vendor',
            label=_('Vendor'),
            doc=_('Token vendor name (informational only)'),
        ),
        Str('ipatokenmodel?',
            cli_name='model',
            label=_('Model'),
            doc=_('Token model (informational only)'),
        ),
        Str('ipatokenserial?',
            cli_name='serial',
            label=_('Serial'),
            doc=_('Token serial (informational only)'),
        ),
        OTPTokenKey('ipatokenotpkey?',
            cli_name='key',
            label=_('Key'),
            doc=_('Token secret (Base32; default: random)'),
            default_from=lambda: os.urandom(KEY_LENGTH),
            autofill=True,
            # force server-side conversion
            normalizer=lambda x: x,
            flags=('no_display', 'no_update', 'no_search'),
        ),
        StrEnum('ipatokenotpalgorithm?',
            cli_name='algo',
            label=_('Algorithm'),
            doc=_('Token hash algorithm'),
            default=u'sha1',
            autofill=True,
            flags=('no_update'),
            values=(u'sha1', u'sha256', u'sha384', u'sha512'),
        ),
        IntEnum('ipatokenotpdigits?',
            cli_name='digits',
            label=_('Digits'),
            doc=_('Number of digits each token code will have'),
            values=(6, 8),
            default=6,
            autofill=True,
            flags=('no_update'),
        ),
        Int('ipatokentotpclockoffset?',
            cli_name='offset',
            label=_('Clock offset'),
            doc=_('TOTP token / FreeIPA server time difference'),
            default=0,
            autofill=True,
            flags=('no_update'),
        ),
        Int('ipatokentotptimestep?',
            cli_name='interval',
            label=_('Clock interval'),
            doc=_('Length of TOTP token code validity'),
            default=30,
            autofill=True,
            minvalue=5,
            flags=('no_update'),
        ),
        Int('ipatokenhotpcounter?',
            cli_name='counter',
            label=_('Counter'),
            doc=_('Initial counter for the HOTP token'),
            default=0,
            autofill=True,
            minvalue=0,
            flags=('no_update'),
        ),
        Str('uri?',
            label=_('URI'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
    )


@register()
class otptoken_add(LDAPCreate):
    __doc__ = _('Add a new OTP token.')
    msg_summary = _('Added OTP token "%(value)s"')

    takes_options = LDAPCreate.takes_options + (
        Flag('qrcode?', label=_('(deprecated)'), flags=('no_option')),
        Flag('no_qrcode', label=_('Do not display QR code'), default=False),
    )

    def execute(self, ipatokenuniqueid=None, **options):
        return super(otptoken_add, self).execute(ipatokenuniqueid, **options)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # Fill in a default UUID when not specified.
        if entry_attrs.get('ipatokenuniqueid', None) is None:
            entry_attrs['ipatokenuniqueid'] = str(uuid.uuid4())
            dn = DN("ipatokenuniqueid=%s" % entry_attrs['ipatokenuniqueid'], dn)

        if not _check_interval(options.get('ipatokennotbefore', None),
                               options.get('ipatokennotafter', None)):
            raise ValidationError(name='not_after',
                                  error='is before the validity start')

        # Set the object class and defaults for specific token types
        options['type'] = options['type'].lower()
        entry_attrs['objectclass'] = otptoken.object_class + ['ipatoken' + options['type']]
        for ttype, tattrs in TOKEN_TYPES.items():
            if ttype != options['type']:
                for tattr in tattrs:
                    if tattr in entry_attrs:
                        del entry_attrs[tattr]

        # If owner was not specified, default to the person adding this token.
        # If managedby was not specified, attempt a sensible default.
        if 'ipatokenowner' not in entry_attrs or 'managedby' not in entry_attrs:
            cur_dn = DN(self.api.Backend.ldap2.conn.whoami_s()[4:])
            if cur_dn:
                cur_uid = cur_dn[0].value
                prev_uid = entry_attrs.setdefault('ipatokenowner', cur_uid)
                if cur_uid == prev_uid:
                    entry_attrs.setdefault('managedby', cur_dn.ldap_text())

        # Resolve the owner's dn
        _normalize_owner(self.api.Object.user, entry_attrs)

        # Get the issuer for the URI
        owner = entry_attrs.get('ipatokenowner', None)
        issuer = api.env.realm
        if owner is not None:
            try:
                issuer = ldap.get_entry(owner, ['krbprincipalname'])['krbprincipalname'][0]
            except (NotFound, IndexError):
                pass

        # Check if key is not empty
        if entry_attrs['ipatokenotpkey'] is None:
            raise ValidationError(name='key', error=_(u'cannot be empty'))

        # Build the URI parameters
        args = {}
        args['issuer'] = issuer
        args['secret'] = base64.b32encode(entry_attrs['ipatokenotpkey'])
        args['digits'] = entry_attrs['ipatokenotpdigits']
        args['algorithm'] = entry_attrs['ipatokenotpalgorithm'].upper()
        if options['type'] == 'totp':
            args['period'] = entry_attrs['ipatokentotptimestep']
        elif options['type'] == 'hotp':
            args['counter'] = entry_attrs['ipatokenhotpcounter']

        # Build the URI
        label = urllib.parse.quote(entry_attrs['ipatokenuniqueid'])
        parameters = urllib.parse.urlencode(args)
        uri = u'otpauth://%s/%s:%s?%s' % (options['type'], issuer, label, parameters)
        setattr(context, 'uri', uri)

        attrs_list.append("objectclass")
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        entry_attrs['uri'] = getattr(context, 'uri')
        _set_token_type(entry_attrs, **options)
        _convert_owner(self.api.Object.user, entry_attrs, options)
        return super(otptoken_add, self).post_callback(ldap, dn, entry_attrs, *keys, **options)


@register()
class otptoken_del(LDAPDelete):
    __doc__ = _('Delete an OTP token.')
    msg_summary = _('Deleted OTP token "%(value)s"')


@register()
class otptoken_mod(LDAPUpdate):
    __doc__ = _('Modify a OTP token.')
    msg_summary = _('Modified OTP token "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        notafter_set = True
        notbefore = options.get('ipatokennotbefore', None)
        notafter = options.get('ipatokennotafter', None)
        # notbefore xor notafter, exactly one of them is not None
        if bool(notbefore) ^ bool(notafter):
            result = self.api.Command.otptoken_show(keys[-1])['result']
            if notbefore is None:
                notbefore = result.get('ipatokennotbefore', [None])[0]
            if notafter is None:
                notafter_set = False
                notafter = result.get('ipatokennotafter', [None])[0]

        if not _check_interval(notbefore, notafter):
            if notafter_set:
                raise ValidationError(name='not_after',
                                      error='is before the validity start')
            else:
                raise ValidationError(name='not_before',
                                      error='is after the validity end')
        _normalize_owner(self.api.Object.user, entry_attrs)

        # ticket #4681: if the owner of the token is changed and the
        # user also manages this token, then we should automatically
        # set the 'managedby' attribute to the new owner
        if 'ipatokenowner' in entry_attrs and 'managedby' not in entry_attrs:
            new_owner = entry_attrs.get('ipatokenowner', None)
            prev_entry = ldap.get_entry(dn, attrs_list=['ipatokenowner',
                                                        'managedby'])
            prev_owner = prev_entry.get('ipatokenowner', None)
            prev_managedby = prev_entry.get('managedby', None)

            if (new_owner != prev_owner) and (prev_owner == prev_managedby):
                entry_attrs.setdefault('managedby', new_owner)

        attrs_list.append("objectclass")
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        _set_token_type(entry_attrs, **options)
        _convert_owner(self.api.Object.user, entry_attrs, options)
        return super(otptoken_mod, self).post_callback(ldap, dn, entry_attrs, *keys, **options)


@register()
class otptoken_find(LDAPSearch):
    __doc__ = _('Search for OTP token.')
    msg_summary = ngettext('%(count)d OTP token matched', '%(count)d OTP tokens matched', 0)

    def pre_callback(self, ldap, filters, attrs_list, *args, **kwargs):
        # This is a hack, but there is no other way to
        # replace the objectClass when searching
        type = kwargs.get('type', '')
        if type not in TOKEN_TYPES:
            type = ''
        filters = filters.replace("(objectclass=ipatoken)",
                                  "(objectclass=ipatoken%s)" % type)

        attrs_list.append("objectclass")
        return super(otptoken_find, self).pre_callback(ldap, filters, attrs_list, *args, **kwargs)

    def args_options_2_entry(self, *args, **options):
        entry = super(otptoken_find, self).args_options_2_entry(*args, **options)
        _normalize_owner(self.api.Object.user, entry)
        return entry

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry in entries:
            _set_token_type(entry, **options)
            _convert_owner(self.api.Object.user, entry, options)
        return super(otptoken_find, self).post_callback(ldap, entries, truncated, *args, **options)


@register()
class otptoken_show(LDAPRetrieve):
    __doc__ = _('Display information about an OTP token.')

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        attrs_list.append("objectclass")
        return super(otptoken_show, self).pre_callback(ldap, dn, attrs_list, *keys, **options)

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        _set_token_type(entry_attrs, **options)
        _convert_owner(self.api.Object.user, entry_attrs, options)
        return super(otptoken_show, self).post_callback(ldap, dn, entry_attrs, *keys, **options)

@register()
class otptoken_add_managedby(LDAPAddMember):
    __doc__ = _('Add users that can manage this token.')

    member_attributes = ['managedby']

@register()
class otptoken_remove_managedby(LDAPRemoveMember):
    __doc__ = _('Remove users that can manage this token.')

    member_attributes = ['managedby']
