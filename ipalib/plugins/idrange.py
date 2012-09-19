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

from ipalib.plugins.baseldap import *
from ipalib import api, Str, Password, DefaultFrom, _, ngettext, Object
from ipalib.parameters import Enum
from ipalib import Command
from ipalib import errors
from ipapython import ipautil
from ipalib import util
from ipapython.dn import DN

if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc
        _dcerpc_bindings_installed = True
    except ImportError:
        _dcerpc_bindings_installed = False

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
 - dom_sid: domain SID of the trusted domain



EXAMPLE: Add a new ID range for a trusted domain

Since there might be more than one trusted domain the domain SID must be given
while creating the ID range.

  ipa idrange-add --base-id=1200000 --range-size=200000 --rid-base=0 \\
                  --dom-sid=S-1-5-21-123-456-789 trusted_dom_range

This ID range is then used by the IPA server and the SSSD IPA provider to
assign Posix UIDs to users from the trusted domain.

If e.g a range for a trusted domain is configured with the following values:
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
The use cases for this CLI are

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
this domain has the SID S-1-5-21-123-456-789-1010 then 1010 id the RID of the
user. RIDs are unique in a domain, 32bit values and are used for users and
groups.
""")

class idrange(LDAPObject):
    """
    Range object.
    """

    range_type = ('domain', 'ad', 'ipa')
    container_dn = api.env.container_ranges
    object_name = ('range')
    object_name_plural = ('ranges')
    object_class = ['ipaIDrange']
    possible_objectclasses = ['ipadomainidrange', 'ipatrustedaddomainrange']
    default_attributes = ['cn', 'ipabaseid', 'ipaidrangesize', 'ipabaserid',
                          'ipasecondarybaserid', 'ipanttrusteddomainsid',
                          'iparangetype']

    label = _('ID Ranges')
    label_singular = _('ID Range')

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
            label=_('Domain SID of the trusted domain'),
        ),
        Str('iparangetype?',
            label=_('Range type'),
            flags=['no_option'],
        )
    )

    def handle_iparangetype(self, entry_attrs, options, keep_objectclass=False):
        if not options.get('pkey_only', False):
            if 'ipatrustedaddomainrange' in entry_attrs.get('objectclass', []):
                entry_attrs['iparangetype'] = [unicode(_('Active Directory domain range'))]
            else:
                entry_attrs['iparangetype'] = [unicode(_(u'local domain range'))]
        if not keep_objectclass:
            if not options.get('all', False) or options.get('pkey_only', False):
                entry_attrs.pop('objectclass', None)

    def check_ids_in_modified_range(self, old_base, old_size, new_base, new_size):
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
            checked_intervals.append(
                    (old_interval[0], min(old_interval[1], new_interval[0] - 1)))
        high_diff = old_interval[1] - new_interval[1]
        if high_diff > 0:
            checked_intervals.append(
                    (max(old_interval[0], new_interval[1] + 1), old_interval[1]))

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
            (objects, truncated) = ldap.find_entries(filter=id_filter,
                    attrs_list=['uid', 'cn'],
                    base_dn=DN(api.env.container_accounts, api.env.basedn))
        except errors.NotFound:
            # no objects in this range found, allow the command
            pass
        else:
            raise errors.ValidationError(name="ipabaseid,ipaidrangesize",
                    error=_('range modification leaving objects with ID out '
                            'of the defined range is not allowed'))

    def validate_trusted_domain_sid(self, sid):
        if not _dcerpc_bindings_installed:
            raise errors.NotFound(reason=_('Cannot perform SID validation without Samba 4 support installed. '
                         'Make sure you have installed server-trust-ad sub-package of IPA on the server'))
        domain_validator = ipaserver.dcerpc.DomainValidator(self.api)
        if not domain_validator.is_configured():
            raise errors.NotFound(reason=_('Cross-realm trusts are not configured. '
                          'Make sure you have run ipa-adtrust-install on the IPA server first'))
        if not domain_validator.is_trusted_sid_valid(sid):
            raise errors.ValidationError(name='domain SID',
                  error=_('SID is not recognized as a valid SID for a trusted domain'))

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

        --rid-bas
        --dom-sid

    must be given to add a new range for a trusted AD domain.
    """)

    msg_summary = _('Added ID range "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        if 'ipanttrusteddomainsid' in options:
            if 'ipasecondarybaserid' in options:
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options dom_sid and secondary_rid_base cannot ' \
                            'be used together'))

            if 'ipabaserid' not in options:
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options dom_sid and rid_base must ' \
                            'be used together'))

            # Validate SID as the one of trusted domains
            self.obj.validate_trusted_domain_sid(options['ipanttrusteddomainsid'])
            # Finally, add trusted AD domain range object class
            entry_attrs['objectclass'].append('ipatrustedaddomainrange')
        else:
            if (('ipasecondarybaserid' in options) != ('ipabaserid' in options)):
                raise errors.ValidationError(name='ID Range setup',
                    error=_('Options secondary_rid_base and rid_base must ' \
                            'be used together'))

            entry_attrs['objectclass'].append('ipadomainidrange')

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.handle_iparangetype(entry_attrs, options, keep_objectclass=True)
        return dn

class idrange_del(LDAPDelete):
    __doc__ = _('Delete an ID range.')

    msg_summary = _('Deleted ID range "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        try:
            (old_dn, old_attrs) = ldap.get_entry(dn, ['ipabaseid', 'ipaidrangesize'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        old_base_id = int(old_attrs.get('ipabaseid', [0])[0])
        old_range_size = int(old_attrs.get('ipaidrangesize', [0])[0])
        self.obj.check_ids_in_modified_range(
                old_base_id, old_range_size, 0, 0)
        return dn

class idrange_find(LDAPSearch):
    __doc__ = _('Search for ranges.')

    msg_summary = ngettext(
        '%(count)d range matched', '%(count)d ranges matched', 0
    )

    # Since all range types are stored within separate containers under
    # 'cn=ranges,cn=etc' search can be done on a one-level scope
    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        attrs_list.append('objectclass')
        return (filters, base_dn, ldap.SCOPE_ONELEVEL)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for dn,entry in entries:
            self.obj.handle_iparangetype(entry, options)
        return truncated

class idrange_show(LDAPRetrieve):
    __doc__ = _('Display information about a range.')

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        attrs_list.append('objectclass')
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.handle_iparangetype(entry_attrs, options)
        return dn

class idrange_mod(LDAPUpdate):
    __doc__ = _('Modify ID range.')

    msg_summary = _('Modified ID range "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        attrs_list.append('objectclass')

        try:
            (old_dn, old_attrs) = ldap.get_entry(dn, ['ipabaseid', 'ipaidrangesize'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if 'ipanttrusteddomainsid' in options:
            # Validate SID as the one of trusted domains
            self.obj.validate_trusted_domain_sid(options['ipanttrusteddomainsid'])

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
        self.obj.handle_iparangetype(entry_attrs, options)
        return dn

api.register(idrange)
api.register(idrange_add)
api.register(idrange_mod)
api.register(idrange_del)
api.register(idrange_find)
api.register(idrange_show)
