# Authors:
#     Sumit Bose <sbose@redhat.com>
#
# Copyright (C) 2012  Red Hat
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

import six

from ipalib.plugable import Registry
from .baseldap import (LDAPObject, LDAPCreate, LDAPDelete,
                                     LDAPRetrieve, LDAPSearch, LDAPUpdate)
from ipalib import api, Int, Str, StrEnum, _, ngettext, messages
from ipalib import errors
from ipaplatform import services
from ipapython.dn import DN

if six.PY3:
    unicode = str

if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc
        _dcerpc_bindings_installed = True
    except ImportError:
        _dcerpc_bindings_installed = False
else:
    _dcerpc_bindings_installed = False


ID_RANGE_VS_DNA_WARNING = _("""=======
WARNING:

DNA plugin in 389-ds will allocate IDs based on the ranges configured for the
local domain. Currently the DNA plugin *cannot* be reconfigured itself based
on the local ranges set via this family of commands.

Manual configuration change has to be done in the DNA plugin configuration for
the new local range. Specifically, The dnaNextRange attribute of 'cn=Posix
IDs,cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config' has to be
modified to match the new range.
=======
""")

__doc__ = _("""
ID ranges

Manage ID ranges  used to map Posix IDs to SIDs and back.

There are two type of ID ranges which are both handled by this utility:

 - the ID ranges of the local domain
 - the ID ranges of trusted remote domains

Both types have the following attributes in common:

 - base-id: the first ID of the Posix ID range
 - range-size: the size of the range

With those two attributes a range object can reserve the Posix IDs starting
with base-id up to but not including base-id+range-size exclusively.

Additionally an ID range of the local domain may set
 - rid-base: the first RID(*) of the corresponding RID range
 - secondary-rid-base: first RID of the secondary RID range

and an ID range of a trusted domain must set
 - rid-base: the first RID of the corresponding RID range
 - sid: domain SID of the trusted domain



EXAMPLE: Add a new ID range for a trusted domain

Since there might be more than one trusted domain the domain SID must be given
while creating the ID range.

  ipa idrange-add --base-id=1200000 --range-size=200000 --rid-base=0 \\
                  --dom-sid=S-1-5-21-123-456-789 trusted_dom_range

This ID range is then used by the IPA server and the SSSD IPA provider to
assign Posix UIDs to users from the trusted domain.

If e.g. a range for a trusted domain is configured with the following values:
 base-id = 1200000
 range-size = 200000
 rid-base = 0
the RIDs 0 to 199999 are mapped to the Posix ID from 1200000 to 13999999. So
RID 1000 <-> Posix ID 1201000



EXAMPLE: Add a new ID range for the local domain

To create an ID range for the local domain it is not necessary to specify a
domain SID. But since it is possible that a user and a group can have the same
value as Posix ID a second RID interval is needed to handle conflicts.

  ipa idrange-add --base-id=1200000 --range-size=200000 --rid-base=1000 \\
                  --secondary-rid-base=1000000 local_range

The data from the ID ranges of the local domain are used by the IPA server
internally to assign SIDs to IPA users and groups. The SID will then be stored
in the user or group objects.

If e.g. the ID range for the local domain is configured with the values from
the example above then a new user with the UID 1200007 will get the RID 1007.
If this RID is already used by a group the RID will be 1000007. This can only
happen if a user or a group object was created with a fixed ID because the
automatic assignment will not assign the same ID twice. Since there are only
users and groups sharing the same ID namespace it is sufficient to have only
one fallback range to handle conflicts.

To find the Posix ID for a given RID from the local domain it has to be
checked first if the RID falls in the primary or secondary RID range and
the rid-base or the secondary-rid-base has to be subtracted, respectively,
and the base-id has to be added to get the Posix ID.

Typically the creation of ID ranges happens behind the scenes and this CLI
must not be used at all. The ID range for the local domain will be created
during installation or upgrade from an older version. The ID range for a
trusted domain will be created together with the trust by 'ipa trust-add ...'.

USE CASES:

  Add an ID range from a transitively trusted domain

    If the trusted domain (A) trusts another domain (B) as well and this trust
    is transitive 'ipa trust-add domain-A' will only create a range for
    domain A.  The ID range for domain B must be added manually.

  Add an additional ID range for the local domain

    If the ID range of the local domain is exhausted, i.e. no new IDs can be
    assigned to Posix users or groups by the DNA plugin, a new range has to be
    created to allow new users and groups to be added. (Currently there is no
    connection between this range CLI and the DNA plugin, but a future version
    might be able to modify the configuration of the DNS plugin as well)

In general it is not necessary to modify or delete ID ranges. If there is no
other way to achieve a certain configuration than to modify or delete an ID
range it should be done with great care. Because UIDs are stored in the file
system and are used for access control it might be possible that users are
allowed to access files of other users if an ID range got deleted and reused
for a different domain.

(*) The RID is typically the last integer of a user or group SID which follows
the domain SID. E.g. if the domain SID is S-1-5-21-123-456-789 and a user from
this domain has the SID S-1-5-21-123-456-789-1010 then 1010 is the RID of the
user. RIDs are unique in a domain, 32bit values and are used for users and
groups.

""") + ID_RANGE_VS_DNA_WARNING

register = Registry()

@register()
class idrange(LDAPObject):
    """
    Range object.
    """

    range_type = ('domain', 'ad', 'ipa')
    container_dn = api.env.container_ranges
    object_name = ('range')
    object_name_plural = ('ranges')
    object_class = ['ipaIDrange']
    permission_filter_objectclasses = ['ipaidrange']
    possible_objectclasses = ['ipadomainidrange', 'ipatrustedaddomainrange']
    default_attributes = ['cn', 'ipabaseid', 'ipaidrangesize', 'ipabaserid',
                          'ipasecondarybaserid', 'ipanttrusteddomainsid',
                          'iparangetype']
    managed_permissions = {
        'System: Read ID Ranges': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass',
                'ipabaseid', 'ipaidrangesize', 'iparangetype',
                'ipabaserid', 'ipasecondarybaserid', 'ipanttrusteddomainsid',
            },
        },
    }

    label = _('ID Ranges')
    label_singular = _('ID Range')

    # The commented range types are planned but not yet supported
    range_types = {
        u'ipa-local': unicode(_('local domain range')),
        # u'ipa-ad-winsync': unicode(_('Active Directory winsync range')),
        u'ipa-ad-trust': unicode(_('Active Directory domain range')),
        u'ipa-ad-trust-posix': unicode(_('Active Directory trust range with '
                                        'POSIX attributes')),
        # u'ipa-ipa-trust': unicode(_('IPA trust range')),
                  }

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Range name'),
            primary_key=True,
        ),
        Int('ipabaseid',
            cli_name='base_id',
            label=_("First Posix ID of the range"),
        ),
        Int('ipaidrangesize',
            cli_name='range_size',
            label=_("Number of IDs in the range"),
        ),
        Int('ipabaserid?',
            cli_name='rid_base',
            label=_('First RID of the corresponding RID range'),
        ),
        Int('ipasecondarybaserid?',
            cli_name='secondary_rid_base',
            label=_('First RID of the secondary RID range'),
        ),
        Str('ipanttrusteddomainsid?',
            cli_name='dom_sid',
            flags=('no_update',),
            label=_('Domain SID of the trusted domain'),
        ),
        Str('ipanttrusteddomainname?',
            cli_name='dom_name',
            flags=('no_search', 'virtual_attribute', 'no_update'),
            label=_('Name of the trusted domain'),
            ),
        StrEnum('iparangetype?',
                label=_('Range type'),
                cli_name='type',
                doc=_('ID range type, one of allowed values'),
                values=sorted(range_types),
                flags=['no_update'],
                )
    )

    def handle_iparangetype(self, entry_attrs, options,
                            keep_objectclass=False):
        if not any((options.get('pkey_only', False),
                    options.get('raw', False))):
            range_type = entry_attrs['iparangetype'][0]
            entry_attrs['iparangetyperaw'] = [range_type]
            entry_attrs['iparangetype'] = [self.range_types.get(range_type, None)]

        # Remove the objectclass
        if not keep_objectclass:
            if not options.get('all', False) or options.get('pkey_only', False):
                entry_attrs.pop('objectclass', None)

    def handle_ipabaserid(self, entry_attrs, options):
        if any((options.get('pkey_only', False), options.get('raw', False))):
            return
        if entry_attrs['iparangetype'][0] == u'ipa-ad-trust-posix':
            entry_attrs.pop('ipabaserid', None)

    def check_ids_in_modified_range(self, old_base, old_size, new_base,
                                    new_size):
        if new_base is None and new_size is None:
            # nothing to check
            return
        if new_base is None:
            new_base = old_base
        if new_size is None:
            new_size = old_size
        old_interval = (old_base, old_base + old_size - 1)
        new_interval = (new_base, new_base + new_size - 1)
        checked_intervals = []
        low_diff = new_interval[0] - old_interval[0]
        if low_diff > 0:
            checked_intervals.append((old_interval[0],
                                    min(old_interval[1], new_interval[0] - 1)))
        high_diff = old_interval[1] - new_interval[1]
        if high_diff > 0:
            checked_intervals.append((max(old_interval[0], new_interval[1] + 1),
                                     old_interval[1]))

        if not checked_intervals:
            # range is equal or covers the entire old range, nothing to check
            return

        ldap = self.backend
        id_filter_base = ["(objectclass=posixAccount)",
                          "(objectclass=posixGroup)",
                          "(objectclass=ipaIDObject)"]
        id_filter_ids = []

        for id_low, id_high in checked_intervals:
            id_filter_ids.append("(&(uidNumber>=%(low)d)(uidNumber<=%(high)d))"
                                 % dict(low=id_low, high=id_high))
            id_filter_ids.append("(&(gidNumber>=%(low)d)(gidNumber<=%(high)d))"
                                 % dict(low=id_low, high=id_high))
        id_filter = ldap.combine_filters(
                        [ldap.combine_filters(id_filter_base, "|"),
                          ldap.combine_filters(id_filter_ids, "|")],
                        "&")

        try:
            ldap.find_entries(filter=id_filter,
                    attrs_list=['uid', 'cn'],
                    base_dn=DN(api.env.container_accounts, api.env.basedn))
        except errors.NotFound:
            # no objects in this range found, allow the command
            pass
        else:
            raise errors.ValidationError(name="ipabaseid,ipaidrangesize",
                    error=_('range modification leaving objects with ID out '
                            'of the defined range is not allowed'))

    def get_domain_validator(self):
        if not _dcerpc_bindings_installed:
            raise errors.NotFound(reason=_('Cannot perform SID validation '
                'without Samba 4 support installed. Make sure you have '
                'installed server-trust-ad sub-package of IPA on the server'))

        domain_validator = ipaserver.dcerpc.DomainValidator(self.api)

        if not domain_validator.is_configured():
            raise errors.NotFound(reason=_('Cross-realm trusts are not '
                'configured. Make sure you have run ipa-adtrust-install '
                'on the IPA server first'))

        return domain_validator

    def validate_trusted_domain_sid(self, sid):

        domain_validator = self.get_domain_validator()

        if not domain_validator.is_trusted_domain_sid_valid(sid):
            raise errors.ValidationError(name='domain SID',
                  error=_('SID is not recognized as a valid SID for a '
                          'trusted domain'))

    def get_trusted_domain_sid_from_name(self, name):
        """ Returns unicode string representation for given trusted domain name
        or None if SID forthe given trusted domain name could not be found."""

        domain_validator = self.get_domain_validator()

        sid = domain_validator.get_sid_from_domain_name(name)

        if sid is not None:
            sid = unicode(sid)

        return sid

    # checks that primary and secondary rid ranges do not overlap
    def are_rid_ranges_overlapping(self, rid_base, secondary_rid_base, size):

        # if any of these is None, the check does not apply
        if any(attr is None for attr in (rid_base, secondary_rid_base, size)):
            return False

        # sort the bases
        if rid_base > secondary_rid_base:
            rid_base, secondary_rid_base = secondary_rid_base, rid_base

        # rid_base is now <= secondary_rid_base,
        # so the following check is sufficient
        if rid_base + size <= secondary_rid_base:
            return False
        else:
            return True


@register()
class idrange_add(LDAPCreate):
    __doc__ = _("""
    Add new ID range.

    To add a new ID range you always have to specify

        --base-id
        --range-size

    Additionally

        --rid-base
        --secondary-rid-base

    may be given for a new ID range for the local domain while

        --rid-base
        --dom-sid

    must be given to add a new range for a trusted AD domain.

""") + ID_RANGE_VS_DNA_WARNING

    msg_summary = _('Added ID range "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        is_set = lambda x: (x in entry_attrs) and (entry_attrs[x] is not None)

        # This needs to stay in options since there is no
        # ipanttrusteddomainname attribute in LDAP
        if options.get('ipanttrusteddomainname'):
            if is_set('ipanttrusteddomainsid'):
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options dom-sid and dom-name '
                            'cannot be used together'))

            sid = self.obj.get_trusted_domain_sid_from_name(
                options['ipanttrusteddomainname'])

            if sid is not None:
                entry_attrs['ipanttrusteddomainsid'] = sid
            else:
                raise errors.ValidationError(
                    name='ID Range setup',
                    error=_('Specified trusted domain name could not be '
                            'found.'))

        # ipaNTTrustedDomainSID attribute set, this is AD Trusted domain range
        if is_set('ipanttrusteddomainsid'):
            entry_attrs['objectclass'].append('ipatrustedaddomainrange')

            # Default to ipa-ad-trust if no type set
            if not is_set('iparangetype'):
                entry_attrs['iparangetype'] = u'ipa-ad-trust'

            if entry_attrs['iparangetype'] == u'ipa-ad-trust':
                if not is_set('ipabaserid'):
                    raise errors.ValidationError(
                        name='ID Range setup',
                        error=_('Options dom-sid/dom-name and rid-base must '
                                'be used together')
                    )
            elif entry_attrs['iparangetype'] == u'ipa-ad-trust-posix':
                if is_set('ipabaserid') and entry_attrs['ipabaserid'] != 0:
                    raise errors.ValidationError(
                        name='ID Range setup',
                        error=_('Option rid-base must not be used when IPA '
                                'range type is ipa-ad-trust-posix')
                    )
                else:
                    entry_attrs['ipabaserid'] = 0
            else:
                raise errors.ValidationError(name='ID Range setup',
                    error=_('IPA Range type must be one of ipa-ad-trust '
                            'or ipa-ad-trust-posix when SID of the trusted '
                            'domain is specified'))

            if is_set('ipasecondarybaserid'):
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options dom-sid/dom-name and secondary-rid-base '
                            'cannot be used together'))

            # Validate SID as the one of trusted domains
            self.obj.validate_trusted_domain_sid(
                                        entry_attrs['ipanttrusteddomainsid'])

        # ipaNTTrustedDomainSID attribute not set, this is local domain range
        else:
            entry_attrs['objectclass'].append('ipadomainidrange')

            # Default to ipa-local if no type set
            if 'iparangetype' not in entry_attrs:
                entry_attrs['iparangetype'] = 'ipa-local'

            # TODO: can also be ipa-ad-winsync here?
            if entry_attrs['iparangetype'] in (u'ipa-ad-trust',
                                               u'ipa-ad-trust-posix'):
                raise errors.ValidationError(name='ID Range setup',
                    error=_('IPA Range type must not be one of ipa-ad-trust '
                            'or ipa-ad-trust-posix when SID of the trusted '
                            'domain is not specified.'))

            # secondary base rid must be set if and only if base rid is set
            if is_set('ipasecondarybaserid') != is_set('ipabaserid'):
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options secondary-rid-base and rid-base must '
                            'be used together'))

            # and they must not overlap
            if is_set('ipabaserid') and is_set('ipasecondarybaserid'):
                if self.obj.are_rid_ranges_overlapping(
                    entry_attrs['ipabaserid'],
                    entry_attrs['ipasecondarybaserid'],
                    entry_attrs['ipaidrangesize']):
                        raise errors.ValidationError(name='ID Range setup',
                            error=_("Primary RID range and secondary RID range"
                                    " cannot overlap"))

            # rid-base and secondary-rid-base must be set if
            # ipa-adtrust-install has been run on the system
            adtrust_is_enabled = api.Command['adtrust_is_enabled']()['result']

            if adtrust_is_enabled and not (
                    is_set('ipabaserid') and is_set('ipasecondarybaserid')):
                raise errors.ValidationError(
                    name='ID Range setup',
                    error=_(
                        'You must specify both rid-base and '
                        'secondary-rid-base options, because '
                        'ipa-adtrust-install has already been run.'
                    )
                )
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.handle_ipabaserid(entry_attrs, options)
        self.obj.handle_iparangetype(entry_attrs, options,
                                     keep_objectclass=True)
        return dn


@register()
class idrange_del(LDAPDelete):
    __doc__ = _('Delete an ID range.')

    msg_summary = _('Deleted ID range "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        try:
            old_attrs = ldap.get_entry(dn, ['ipabaseid',
                                            'ipaidrangesize',
                                            'ipanttrusteddomainsid'])
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        # Check whether we leave any object with id in deleted range
        old_base_id = int(old_attrs.get('ipabaseid', [0])[0])
        old_range_size = int(old_attrs.get('ipaidrangesize', [0])[0])
        self.obj.check_ids_in_modified_range(
                old_base_id, old_range_size, 0, 0)

        # Check whether the range does not belong to the active trust
        range_sid = old_attrs.get('ipanttrusteddomainsid')

        if range_sid is not None:
            # Search for trusted domain with SID specified in the ID range entry
            range_sid = range_sid[0]
            domain_filter=('(&(objectclass=ipaNTTrustedDomain)'
                           '(ipanttrusteddomainsid=%s))' % range_sid)

            try:
                trust_domains, _truncated = ldap.find_entries(
                    base_dn=DN(api.env.container_trusts, api.env.basedn),
                    filter=domain_filter)
            except errors.NotFound:
                pass
            else:
                # If there's an entry, it means that there's active domain
                # of a trust that this range belongs to, so raise a
                # DependentEntry error
                raise errors.DependentEntry(
                    label='Active Trust domain',
                    key=keys[0],
                    dependent=trust_domains[0].dn[0].value)


        return dn


@register()
class idrange_find(LDAPSearch):
    __doc__ = _('Search for ranges.')

    msg_summary = ngettext(
        '%(count)d range matched', '%(count)d ranges matched', 0
    )

    # Since all range types are stored within separate containers under
    # 'cn=ranges,cn=etc' search can be done on a one-level scope
    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args,
                     **options):
        assert isinstance(base_dn, DN)
        attrs_list.append('objectclass')
        return (filters, base_dn, ldap.SCOPE_ONELEVEL)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry in entries:
            self.obj.handle_ipabaserid(entry, options)
            self.obj.handle_iparangetype(entry, options)
        return truncated


@register()
class idrange_show(LDAPRetrieve):
    __doc__ = _('Display information about a range.')

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        attrs_list.append('objectclass')
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.handle_ipabaserid(entry_attrs, options)
        self.obj.handle_iparangetype(entry_attrs, options)
        return dn


@register()
class idrange_mod(LDAPUpdate):
    __doc__ = _("""Modify ID range.

""") + ID_RANGE_VS_DNA_WARNING

    msg_summary = _('Modified ID range "%(value)s"')

    takes_options = LDAPUpdate.takes_options + (
        Str(
            'ipanttrusteddomainsid?',
            deprecated=True,
            cli_name='dom_sid',
            flags=('no_update', 'no_option'),
            label=_('Domain SID of the trusted domain'),
            autofill=False,
        ),
        Str(
            'ipanttrusteddomainname?',
            deprecated=True,
            cli_name='dom_name',
            flags=('no_search', 'virtual_attribute', 'no_update', 'no_option'),
            label=_('Name of the trusted domain'),
            autofill=False,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        attrs_list.append('objectclass')

        try:
            old_attrs = ldap.get_entry(dn, ['*'])
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        if old_attrs['iparangetype'][0] == 'ipa-local':
            raise errors.ExecutionError(
                message=_('This command can not be used to change ID '
                          'allocation for local IPA domain. Run '
                          '`ipa help idrange` for more information')
            )

        is_set = lambda x: (x in entry_attrs) and (entry_attrs[x] is not None)
        in_updated_attrs = lambda x:\
            (x in entry_attrs and entry_attrs[x] is not None) or\
            (x not in entry_attrs and x in old_attrs
                and old_attrs[x] is not None)

        # This needs to stay in options since there is no
        # ipanttrusteddomainname attribute in LDAP
        if 'ipanttrusteddomainname' in options:
            if is_set('ipanttrusteddomainsid'):
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options dom-sid and dom-name '
                            'cannot be used together'))

            sid = self.obj.get_trusted_domain_sid_from_name(
                options['ipanttrusteddomainname'])

            # we translate the name into sid so further validation can rely
            # on ipanttrusteddomainsid attribute only
            if sid is not None:
                entry_attrs['ipanttrusteddomainsid'] = sid
            else:
                raise errors.ValidationError(name='ID Range setup',
                    error=_('SID for the specified trusted domain name could '
                            'not be found. Please specify the SID directly '
                            'using dom-sid option.'))

        if in_updated_attrs('ipanttrusteddomainsid'):
            if in_updated_attrs('ipasecondarybaserid'):
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options dom-sid and secondary-rid-base cannot '
                            'be used together'))
            range_type = old_attrs['iparangetype'][0]
            if range_type == u'ipa-ad-trust':
                if not in_updated_attrs('ipabaserid'):
                    raise errors.ValidationError(
                        name='ID Range setup',
                        error=_('Options dom-sid and rid-base must '
                                'be used together'))
            elif (range_type == u'ipa-ad-trust-posix' and
                  'ipabaserid' in entry_attrs):
                if entry_attrs['ipabaserid'] is None:
                    entry_attrs['ipabaserid'] = 0
                elif entry_attrs['ipabaserid'] != 0:
                    raise errors.ValidationError(
                        name='ID Range setup',
                        error=_('Option rid-base must not be used when IPA '
                                'range type is ipa-ad-trust-posix')
                    )

            if is_set('ipanttrusteddomainsid'):
                # Validate SID as the one of trusted domains
                # perform this check only if the attribute was changed
                self.obj.validate_trusted_domain_sid(
                    entry_attrs['ipanttrusteddomainsid'])

            # Add trusted AD domain range object class, if it wasn't there
            if not 'ipatrustedaddomainrange' in old_attrs['objectclass']:
                entry_attrs['objectclass'].append('ipatrustedaddomainrange')

        else:
            # secondary base rid must be set if and only if base rid is set
            if in_updated_attrs('ipasecondarybaserid') !=\
                in_updated_attrs('ipabaserid'):
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options secondary-rid-base and rid-base must '
                            'be used together'))

        # ensure that primary and secondary rid ranges do not overlap
        if all(in_updated_attrs(base)
               for base in ('ipabaserid', 'ipasecondarybaserid')):

            # make sure we are working with updated attributes
            rid_range_attributes = ('ipabaserid', 'ipasecondarybaserid',
                                    'ipaidrangesize')
            updated_values = dict()

            for attr in rid_range_attributes:
                if is_set(attr):
                    updated_values[attr] = entry_attrs[attr]
                else:
                    updated_values[attr] = int(old_attrs[attr][0])

            if self.obj.are_rid_ranges_overlapping(
                updated_values['ipabaserid'],
                updated_values['ipasecondarybaserid'],
                updated_values['ipaidrangesize']):
                    raise errors.ValidationError(name='ID Range setup',
                            error=_("Primary RID range and secondary RID range"
                                 " cannot overlap"))

        # check whether ids are in modified range
        old_base_id = int(old_attrs.get('ipabaseid', [0])[0])
        old_range_size = int(old_attrs.get('ipaidrangesize', [0])[0])
        new_base_id = entry_attrs.get('ipabaseid')

        if new_base_id is not None:
            new_base_id = int(new_base_id)

        new_range_size = entry_attrs.get('ipaidrangesize')

        if new_range_size is not None:
            new_range_size = int(new_range_size)

        self.obj.check_ids_in_modified_range(old_base_id, old_range_size,
                                             new_base_id, new_range_size)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.handle_ipabaserid(entry_attrs, options)
        self.obj.handle_iparangetype(entry_attrs, options)
        self.add_message(
            messages.ServiceRestartRequired(
                service=services.knownservices['sssd'].systemd_name,
                server=keys[0]
            )
        )
        return dn
