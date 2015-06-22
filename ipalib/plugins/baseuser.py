# Authors:
#   Thierry Bordaz <tbordaz@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from time import gmtime, strftime
import string
import posixpath
import os

from ipalib import api, errors
from ipalib import Flag, Int, Password, Str, Bool, StrEnum, DateTime, Bytes
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import DN, LDAPObject, \
    LDAPCreate, LDAPUpdate, LDAPSearch, LDAPDelete, LDAPRetrieve
from ipalib.plugins.service import validate_certificate
from ipalib.plugins import baseldap
from ipalib.request import context
from ipalib import _, ngettext
from ipalib import output
from ipaplatform.paths import paths
from ipapython.ipautil import ipa_generate_password
from ipapython.ipavalidate import Email
from ipalib.capabilities import client_has_capability
from ipalib.util import (normalize_sshpubkey, validate_sshpubkey,
    convert_sshpubkey_post)

__doc__ = _("""
Baseuser

This contains common definitions for user/stageuser
""")

register = Registry()

NO_UPG_MAGIC = '__no_upg__'

baseuser_output_params = (
    Flag('has_keytab',
        label=_('Kerberos keys available'),
    ),
    Str('sshpubkeyfp*',
        label=_('SSH public key fingerprint'),
    ),
   )

status_baseuser_output_params = (
    Str('server',
        label=_('Server'),
    ),
    Str('krbloginfailedcount',
        label=_('Failed logins'),
    ),
    Str('krblastsuccessfulauth',
        label=_('Last successful authentication'),
    ),
    Str('krblastfailedauth',
        label=_('Last failed authentication'),
    ),
    Str('now',
        label=_('Time now'),
    ),
   )

UPG_DEFINITION_DN = DN(('cn', 'UPG Definition'),
                       ('cn', 'Definitions'),
                       ('cn', 'Managed Entries'),
                       ('cn', 'etc'),
                       api.env.basedn)

# characters to be used for generating random user passwords
baseuser_pwdchars = string.digits + string.ascii_letters + '_,.@+-='

def validate_nsaccountlock(entry_attrs):
    if 'nsaccountlock' in entry_attrs:
        nsaccountlock = entry_attrs['nsaccountlock']
        if not isinstance(nsaccountlock, (bool, Bool)):
            if not isinstance(nsaccountlock, basestring):
                raise errors.OnlyOneValueAllowed(attr='nsaccountlock')
            if nsaccountlock.lower() not in ('true', 'false'):
                raise errors.ValidationError(name='nsaccountlock',
                    error=_('must be TRUE or FALSE'))

def radius_dn2pk(api, entry_attrs):
    cl = entry_attrs.get('ipatokenradiusconfiglink', None)
    if cl:
        pk = api.Object['radiusproxy'].get_primary_key_from_dn(cl[0])
        entry_attrs['ipatokenradiusconfiglink'] = [pk]

def convert_nsaccountlock(entry_attrs):
    if not 'nsaccountlock' in entry_attrs:
        entry_attrs['nsaccountlock'] = False
    else:
        nsaccountlock = Bool('temp')
        entry_attrs['nsaccountlock'] = nsaccountlock.convert(entry_attrs['nsaccountlock'][0])

def split_principal(principal):
    """
    Split the principal into its components and do some basic validation.

    Automatically append our realm if it wasn't provided.
    """
    realm = None
    parts = principal.split('@')
    user = parts[0].lower()
    if len(parts) > 2:
        raise errors.MalformedUserPrincipal(principal=principal)

    if len(parts) == 2:
        realm = parts[1].upper()
        # At some point we'll support multiple realms
        if realm != api.env.realm:
            raise errors.RealmMismatch()
    else:
        realm = api.env.realm

    return (user, realm)

def validate_principal(ugettext, principal):
    """
    All the real work is done in split_principal.
    """
    (user, realm) = split_principal(principal)
    return None

def normalize_principal(principal):
    """
    Ensure that the name in the principal is lower-case. The realm is
    upper-case by convention but it isn't required.

    The principal is validated at this point.
    """
    (user, realm) = split_principal(principal)
    return unicode('%s@%s' % (user, realm))



def fix_addressbook_permission_bindrule(name, template, is_new,
                                        anonymous_read_aci,
                                        **other_options):
    """Fix bind rule type for Read User Addressbook/IPA Attributes permission

    When upgrading from an old IPA that had the global read ACI,
    or when installing the first replica with granular read permissions,
    we need to keep allowing anonymous access to many user attributes.
    This fixup_function changes the bind rule type accordingly.
    """
    if is_new and anonymous_read_aci:
        template['ipapermbindruletype'] = 'anonymous'



class baseuser(LDAPObject):
    """
    baseuser object.
    """

    stage_container_dn        = api.env.container_stageuser
    active_container_dn       = api.env.container_user
    delete_container_dn       = api.env.container_deleteuser
    object_class = ['posixaccount']
    object_class_config = 'ipauserobjectclasses'
    possible_objectclasses = [
        'meporiginentry', 'ipauserauthtypeclass', 'ipauser',
        'ipatokenradiusproxyuser'
    ]
    disallow_object_classes = ['krbticketpolicyaux']
    permission_filter_objectclasses = ['posixaccount']
    search_attributes_config = 'ipausersearchfields'
    default_attributes = [
        'uid', 'givenname', 'sn', 'homedirectory', 'loginshell',
        'uidnumber', 'gidnumber', 'mail', 'ou',
        'telephonenumber', 'title', 'memberof', 'nsaccountlock',
        'memberofindirect', 'ipauserauthtype', 'userclass',
        'ipatokenradiusconfiglink', 'ipatokenradiususername',
        'krbprincipalexpiration', 'usercertificate',
    ]
    search_display_attributes = [
        'uid', 'givenname', 'sn', 'homedirectory', 'loginshell',
        'mail', 'telephonenumber', 'title', 'nsaccountlock',
        'uidnumber', 'gidnumber', 'sshpubkeyfp',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'memberof': ['group', 'netgroup', 'role', 'hbacrule', 'sudorule'],
        'memberofindirect': ['group', 'netgroup', 'role', 'hbacrule', 'sudorule'],
    }
    rdn_is_primary_key = True
    bindable = True
    password_attributes = [('userpassword', 'has_password'),
                           ('krbprincipalkey', 'has_keytab')]
    label = _('Users')
    label_singular = _('User')

    takes_params = (
        Str('uid',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='login',
            label=_('User login'),
            primary_key=True,
            default_from=lambda givenname, sn: givenname[0] + sn,
            normalizer=lambda value: value.lower(),
        ),
        Str('givenname',
            cli_name='first',
            label=_('First name'),
        ),
        Str('sn',
            cli_name='last',
            label=_('Last name'),
        ),
        Str('cn',
            label=_('Full name'),
            default_from=lambda givenname, sn: '%s %s' % (givenname, sn),
            autofill=True,
        ),
        Str('displayname?',
            label=_('Display name'),
            default_from=lambda givenname, sn: '%s %s' % (givenname, sn),
            autofill=True,
        ),
        Str('initials?',
            label=_('Initials'),
            default_from=lambda givenname, sn: '%c%c' % (givenname[0], sn[0]),
            autofill=True,
        ),
        Str('homedirectory?',
            cli_name='homedir',
            label=_('Home directory'),
        ),
        Str('gecos?',
            label=_('GECOS'),
            default_from=lambda givenname, sn: '%s %s' % (givenname, sn),
            autofill=True,
        ),
        Str('loginshell?',
            cli_name='shell',
            label=_('Login shell'),
        ),
        Str('krbprincipalname?', validate_principal,
            cli_name='principal',
            label=_('Kerberos principal'),
            default_from=lambda uid: '%s@%s' % (uid.lower(), api.env.realm),
            autofill=True,
            flags=['no_update'],
            normalizer=lambda value: normalize_principal(value),
        ),
        DateTime('krbprincipalexpiration?',
            cli_name='principal_expiration',
            label=_('Kerberos principal expiration'),
        ),
        Str('mail*',
            cli_name='email',
            label=_('Email address'),
        ),
        Password('userpassword?',
            cli_name='password',
            label=_('Password'),
            doc=_('Prompt to set the user password'),
            # FIXME: This is temporary till bug is fixed causing updates to
            # bomb out via the webUI.
            exclude='webui',
        ),
        Flag('random?',
            doc=_('Generate a random user password'),
            flags=('no_search', 'virtual_attribute'),
            default=False,
        ),
        Str('randompassword?',
            label=_('Random password'),
            flags=('no_create', 'no_update', 'no_search', 'virtual_attribute'),
        ),
        Int('uidnumber?',
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number (system will assign one if not provided)'),
            minvalue=1,
        ),
        Int('gidnumber?',
            label=_('GID'),
            doc=_('Group ID Number'),
            minvalue=1,
        ),
        Str('street?',
            cli_name='street',
            label=_('Street address'),
        ),
        Str('l?',
            cli_name='city',
            label=_('City'),
        ),
        Str('st?',
            cli_name='state',
            label=_('State/Province'),
        ),
        Str('postalcode?',
            label=_('ZIP'),
        ),
        Str('telephonenumber*',
            cli_name='phone',
            label=_('Telephone Number')
        ),
        Str('mobile*',
            label=_('Mobile Telephone Number')
        ),
        Str('pager*',
            label=_('Pager Number')
        ),
        Str('facsimiletelephonenumber*',
            cli_name='fax',
            label=_('Fax Number'),
        ),
        Str('ou?',
            cli_name='orgunit',
            label=_('Org. Unit'),
        ),
        Str('title?',
            label=_('Job Title'),
        ),
        Str('manager?',
            label=_('Manager'),
        ),
        Str('carlicense*',
            label=_('Car License'),
        ),
        Str('ipasshpubkey*', validate_sshpubkey,
            cli_name='sshpubkey',
            label=_('SSH public key'),
            normalizer=normalize_sshpubkey,
            csv=True,
            flags=['no_search'],
        ),
        StrEnum('ipauserauthtype*',
            cli_name='user_auth_type',
            label=_('User authentication types'),
            doc=_('Types of supported user authentication'),
            values=(u'password', u'radius', u'otp'),
            csv=True,
        ),
        Str('userclass*',
            cli_name='class',
            label=_('Class'),
            doc=_('User category (semantics placed on this attribute are for '
                  'local interpretation)'),
        ),
        Str('ipatokenradiusconfiglink?',
            cli_name='radius',
            label=_('RADIUS proxy configuration'),
        ),
        Str('ipatokenradiususername?',
            cli_name='radius_username',
            label=_('RADIUS proxy username'),
        ),
        Str('departmentnumber*',
            label=_('Department Number'),
        ),
        Str('employeenumber?',
            label=_('Employee Number'),
        ),
        Str('employeetype?',
            label=_('Employee Type'),
        ),
        Str('preferredlanguage?',
            label=_('Preferred Language'),
            pattern='^(([a-zA-Z]{1,8}(-[a-zA-Z]{1,8})?(;q\=((0(\.[0-9]{0,3})?)|(1(\.0{0,3})?)))?' \
             + '(\s*,\s*[a-zA-Z]{1,8}(-[a-zA-Z]{1,8})?(;q\=((0(\.[0-9]{0,3})?)|(1(\.0{0,3})?)))?)*)|(\*))$',
            pattern_errmsg='must match RFC 2068 - 14.4, e.g., "da, en-gb;q=0.8, en;q=0.7"',
        ),
        Bytes('usercertificate*', validate_certificate,
            cli_name='certificate',
            label=_('Certificate'),
            doc=_('Base-64 encoded server certificate'),
        ),
    )

    def normalize_and_validate_email(self, email, config=None):
        if not config:
            config = self.backend.get_ipa_config()

        # check if default email domain should be added
        defaultdomain = config.get('ipadefaultemaildomain', [None])[0]
        if email:
            norm_email = []
            if not isinstance(email, (list, tuple)):
                email = [email]
            for m in email:
                if isinstance(m, basestring):
                    if '@' not in m and defaultdomain:
                        m = m + u'@' + defaultdomain
                    if not Email(m):
                        raise errors.ValidationError(name='email', error=_('invalid e-mail format: %(email)s') % dict(email=m))
                    norm_email.append(m)
                else:
                    if not Email(m):
                        raise errors.ValidationError(name='email', error=_('invalid e-mail format: %(email)s') % dict(email=m))
                    norm_email.append(m)
            return norm_email

        return email

    def normalize_manager(self, manager, container):
        """
        Given a userid verify the user's existence (in the appropriate containter) and return the dn.
        """
        if not manager:
            return None

        if not isinstance(manager, list):
            manager = [manager]
        try:
            container_dn = DN(container, api.env.basedn)
            for m in xrange(len(manager)):
                if isinstance(manager[m], DN) and manager[m].endswith(container_dn):
                    continue
                entry_attrs = self.backend.find_entry_by_attr(
                        self.primary_key.name, manager[m], self.object_class, [''],
                        container_dn
                    )
                manager[m] = entry_attrs.dn
        except errors.NotFound:
            raise errors.NotFound(reason=_('manager %(manager)s not found') % dict(manager=manager[m]))

        return manager

    def convert_manager(self, entry_attrs, **options):
        """
        Convert a manager dn into a userid
        """
        if options.get('raw', False):
             return

        if 'manager' in entry_attrs:
            for m in xrange(len(entry_attrs['manager'])):
                entry_attrs['manager'][m] = self.get_primary_key_from_dn(entry_attrs['manager'][m])

    def _user_status(self, user, container):
        assert isinstance(user, DN)
        return user.endswith(container)

    def active_user(self, user):
        assert isinstance(user, DN)
        return self._user_status(user, DN(self.active_container_dn, api.env.basedn))

    def stage_user(self, user):
        assert isinstance(user, DN)
        return self._user_status(user, DN(self.stage_container_dn, api.env.basedn))

    def delete_user(self, user):
        assert isinstance(user, DN)
        return self._user_status(user, DN(self.delete_container_dn, api.env.basedn))

class baseuser_add(LDAPCreate):
    """
    Prototype command plugin to be implemented by real plugin
    """

class baseuser_del(LDAPDelete):
    """
    Prototype command plugin to be implemented by real plugin
    """

class baseuser_mod(LDAPUpdate):
    """
    Prototype command plugin to be implemented by real plugin
    """
    def check_namelength(self, ldap, **options):
        if options.get('rename') is not None:
            config = ldap.get_ipa_config()
            if 'ipamaxusernamelength' in config:
                if len(options['rename']) > int(config.get('ipamaxusernamelength')[0]):
                    raise errors.ValidationError(
                        name=self.obj.primary_key.cli_name,
                        error=_('can be at most %(len)d characters') % dict(
                            len = int(config.get('ipamaxusernamelength')[0])
                        )
                    )
    def check_mail(self, entry_attrs):
        if 'mail' in entry_attrs:
            entry_attrs['mail'] = self.obj.normalize_and_validate_email(entry_attrs['mail'])

    def check_manager(self, entry_attrs, container):
        if 'manager' in entry_attrs:
            entry_attrs['manager'] = self.obj.normalize_manager(entry_attrs['manager'], container)

    def check_userpassword(self, entry_attrs, **options):
        if 'userpassword' not in entry_attrs and options.get('random'):
            entry_attrs['userpassword'] = ipa_generate_password(baseuser_pwdchars)
            # save the password so it can be displayed in post_callback
            setattr(context, 'randompassword', entry_attrs['userpassword'])

    def check_objectclass(self, ldap, dn, entry_attrs):
        if ('ipasshpubkey' in entry_attrs or 'ipauserauthtype' in entry_attrs
            or 'userclass' in entry_attrs or 'ipatokenradiusconfiglink' in entry_attrs):
            if 'objectclass' in entry_attrs:
                obj_classes = entry_attrs['objectclass']
            else:
                _entry_attrs = ldap.get_entry(dn, ['objectclass'])
                obj_classes = entry_attrs['objectclass'] = _entry_attrs['objectclass']

            if 'ipasshpubkey' in entry_attrs and 'ipasshuser' not in obj_classes:
                obj_classes.append('ipasshuser')

            if 'ipauserauthtype' in entry_attrs and 'ipauserauthtypeclass' not in obj_classes:
                obj_classes.append('ipauserauthtypeclass')

            if 'userclass' in entry_attrs and 'ipauser' not in obj_classes:
                obj_classes.append('ipauser')

            if 'ipatokenradiusconfiglink' in entry_attrs:
                cl = entry_attrs['ipatokenradiusconfiglink']
                if cl:
                    if 'ipatokenradiusproxyuser' not in obj_classes:
                        obj_classes.append('ipatokenradiusproxyuser')

                    answer = self.api.Object['radiusproxy'].get_dn_if_exists(cl)
                    entry_attrs['ipatokenradiusconfiglink'] = answer

    def pre_common_callback(self, ldap, dn, entry_attrs, **options):
        assert isinstance(dn, DN)
        self.check_namelength(ldap, **options)

        self.check_mail(entry_attrs)

        self.check_manager(entry_attrs, self.obj.active_container_dn)

        self.check_userpassword(entry_attrs, **options)

        self.check_objectclass(ldap, dn, entry_attrs)

    def post_common_callback(self, ldap, dn, entry_attrs, **options):
        assert isinstance(dn, DN)
        if options.get('random', False):
            try:
                entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
            except AttributeError:
                # if both randompassword and userpassword options were used
                pass
        convert_nsaccountlock(entry_attrs)
        self.obj.convert_manager(entry_attrs, **options)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        convert_sshpubkey_post(ldap, dn, entry_attrs)
        radius_dn2pk(self.api, entry_attrs)

class baseuser_find(LDAPSearch):
    """
    Prototype command plugin to be implemented by real plugin
    """
    def common_enhance_options(self, newoptions, **options):
        # assure the manager attr is a dn, not just a bare uid
        manager = options.get('manager')
        if manager is not None:
            newoptions['manager'] = self.obj.normalize_manager(manager, self.obj.active_container_dn)

        # Ensure that the RADIUS config link is a dn, not just the name
        cl = 'ipatokenradiusconfiglink'
        if cl in options:
            newoptions[cl] = self.api.Object['radiusproxy'].get_dn(options[cl])

    def post_common_callback(self, ldap, entries, lockout=False, **options):
        for attrs in entries:
            self.obj.convert_manager(attrs, **options)
            self.obj.get_password_attributes(ldap, attrs.dn, attrs)
            if (lockout):
                attrs['nsaccountlock'] = True
            else:
                convert_nsaccountlock(attrs)
            convert_sshpubkey_post(ldap, attrs.dn, attrs)

class baseuser_show(LDAPRetrieve):
    """
    Prototype command plugin to be implemented by real plugin
    """
    def post_common_callback(self, ldap, dn, entry_attrs, **options):
        assert isinstance(dn, DN)
        self.obj.convert_manager(entry_attrs, **options)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        convert_sshpubkey_post(ldap, dn, entry_attrs)
        radius_dn2pk(self.api, entry_attrs)
