# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
from .baseldap import (LDAPObject, LDAPCreate, LDAPRetrieve,
                                     LDAPDelete, LDAPUpdate, LDAPSearch,
                                     LDAPAddMember, LDAPRemoveMember,
                                     entry_from_entry, wait_for_value)
from ipalib import Str, api, _, ngettext, errors
from .netgroup import NETGROUP_PATTERN, NETGROUP_PATTERN_ERRMSG
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
Groups of hosts.

Manage groups of hosts. This is useful for applying access control to a
number of hosts by using Host-based Access Control.

EXAMPLES:

 Add a new host group:
   ipa hostgroup-add --desc="Baltimore hosts" baltimore

 Add another new host group:
   ipa hostgroup-add --desc="Maryland hosts" maryland

 Add members to the hostgroup (using Bash brace expansion):
   ipa hostgroup-add-member --hosts={box1,box2,box3} baltimore

 Add a hostgroup as a member of another hostgroup:
   ipa hostgroup-add-member --hostgroups=baltimore maryland

 Remove a host from the hostgroup:
   ipa hostgroup-remove-member --hosts=box2 baltimore

 Display a host group:
   ipa hostgroup-show baltimore

 Add a member manager:
   ipa hostgroup-add-member-manager --users=user1 baltimore

 Remove a member manager
   ipa hostgroup-remove-member-manager --users=user1 baltimore

 Delete a hostgroup:
   ipa hostgroup-del baltimore
""")


def get_complete_hostgroup_member_list(hostgroup):
    result = api.Command['hostgroup_show'](hostgroup)['result']
    direct = list(result.get('member_host', []))
    indirect = list(result.get('memberindirect_host', []))
    return direct + indirect


register = Registry()

PROTECTED_HOSTGROUPS = (u'ipaservers',)


hostgroup_output_params = (
    Str(
        'membermanager_group',
        label='Membership managed by groups',
    ),
    Str(
        'membermanager_user',
        label='Membership managed by users',
    ),
    Str(
        'membermanager',
        label=_('Failed membermanager'),
    ),
)


@register()
class hostgroup(LDAPObject):
    """
    Hostgroup object.
    """
    container_dn = api.env.container_hostgroup
    object_name = _('host group')
    object_name_plural = _('host groups')
    object_class = ['ipaobject', 'ipahostgroup']
    permission_filter_objectclasses = ['ipahostgroup']
    search_attributes = ['cn', 'description', 'member', 'memberof']
    default_attributes = [
        'cn', 'description', 'member', 'memberof', 'memberindirect',
        'memberofindirect', 'membermanager',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['host', 'hostgroup'],
        'membermanager': ['user', 'group'],
        'memberof': ['hostgroup', 'netgroup', 'hbacrule', 'sudorule'],
        'memberindirect': ['host', 'hostgroup'],
        'memberofindirect': ['hostgroup', 'hbacrule', 'sudorule'],
    }
    managed_permissions = {
        'System: Read Hostgroups': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'businesscategory', 'cn', 'description', 'ipauniqueid', 'o',
                'objectclass', 'ou', 'owner', 'seealso', 'membermanager',
            },
        },
        'System: Read Hostgroup Membership': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'member', 'memberof', 'memberuser', 'memberhost',
            },
        },
        'System: Add Hostgroups': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=hostgroups,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Add Hostgroups";allow (add) groupdn = "ldap:///cn=Add Hostgroups,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Group Administrators'},
        },
        'System: Modify Hostgroup Membership': {
            'ipapermright': {'write'},
            'ipapermtargetfilter': [
                '(objectclass=ipahostgroup)',
                '(!(cn=ipaservers))',
            ],
            'ipapermdefaultattr': {'member'},
            'replaces': [
                '(targetattr = "member")(target = "ldap:///cn=*,cn=hostgroups,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Modify Hostgroup membership";allow (write) groupdn = "ldap:///cn=Modify Hostgroup membership,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Group Administrators'},
        },
        'System: Modify Hostgroups': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'cn', 'description', 'membermanager'},
            'replaces': [
                '(targetattr = "cn || description")(target = "ldap:///cn=*,cn=hostgroups,cn=accounts,$SUFFIX")(version 3.0; acl "permission:Modify Hostgroups";allow (write) groupdn = "ldap:///cn=Modify Hostgroups,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Group Administrators'},
        },
        'System: Remove Hostgroups': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=hostgroups,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Remove Hostgroups";allow (delete) groupdn = "ldap:///cn=Remove Hostgroups,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Host Group Administrators'},
        },
    }

    label = _('Host Groups')
    label_singular = _('Host Group')

    takes_params = (
        Str('cn',
            pattern=NETGROUP_PATTERN,
            pattern_errmsg=NETGROUP_PATTERN_ERRMSG,
            cli_name='hostgroup_name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host-group'),
        ),
    )

    def suppress_netgroup_memberof(self, ldap, dn, entry_attrs):
        """
        We don't want to show managed netgroups so remove them from the
        memberOf list.
        """
        hgdn = DN(dn)
        for member in list(entry_attrs.get('memberof', [])):
            ngdn = DN(member)
            if ngdn['cn'] != hgdn['cn']:
                continue

            filter = ldap.make_filter({'objectclass': 'mepmanagedentry'})
            try:
                ldap.get_entries(ngdn, ldap.SCOPE_BASE, filter, [''])
            except errors.NotFound:
                pass
            else:
                entry_attrs['memberof'].remove(member)


@register()
class hostgroup_add(LDAPCreate):
    __doc__ = _('Add a new hostgroup.')

    has_output_params = LDAPCreate.has_output_params + hostgroup_output_params
    msg_summary = _('Added hostgroup "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            # check duplicity with hostgroups first to provide proper error
            api.Object['hostgroup'].get_dn_if_exists(keys[-1])
            self.obj.handle_duplicate_entry(*keys)
        except errors.NotFound:
            pass

        try:
            # when enabled, a managed netgroup is created for every hostgroup
            # make sure that the netgroup can be created
            api.Object['netgroup'].get_dn_if_exists(keys[-1])
            raise errors.DuplicateEntry(message=unicode(_(
                    u'netgroup with name "%s" already exists. '
                    u'Hostgroups and netgroups share a common namespace'
                    ) % keys[-1]))
        except errors.NotFound:
            pass

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        # Always wait for the associated netgroup to be created so we can
        # be sure to ignore it in memberOf
        newentry = wait_for_value(ldap, dn, 'objectclass', 'mepOriginEntry')
        entry_from_entry(entry_attrs, newentry)
        self.obj.suppress_netgroup_memberof(ldap, dn, entry_attrs)

        return dn


@register()
class hostgroup_del(LDAPDelete):
    __doc__ = _('Delete a hostgroup.')

    msg_summary = _('Deleted hostgroup "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        if keys[0] in PROTECTED_HOSTGROUPS:
            raise errors.ProtectedEntryError(label=_(u'hostgroup'),
                                             key=keys[0],
                                             reason=_(u'privileged hostgroup'))

        return dn


@register()
class hostgroup_mod(LDAPUpdate):
    __doc__ = _('Modify a hostgroup.')

    has_output_params = LDAPUpdate.has_output_params + hostgroup_output_params
    msg_summary = _('Modified hostgroup "%(value)s"')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(ldap, dn, entry_attrs)
        return dn


@register()
class hostgroup_find(LDAPSearch):
    __doc__ = _('Search for hostgroups.')

    member_attributes = ['member', 'memberof', 'membermanager']
    has_output_params = LDAPSearch.has_output_params + hostgroup_output_params
    msg_summary = ngettext(
        '%(count)d hostgroup matched', '%(count)d hostgroups matched', 0
    )

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        for entry in entries:
            self.obj.suppress_netgroup_memberof(ldap, entry.dn, entry)
        return truncated


@register()
class hostgroup_show(LDAPRetrieve):
    __doc__ = _('Display information about a hostgroup.')

    has_output_params = (
        LDAPRetrieve.has_output_params + hostgroup_output_params
    )

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(ldap, dn, entry_attrs)
        return dn


@register()
class hostgroup_add_member(LDAPAddMember):
    __doc__ = _('Add members to a hostgroup.')

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(ldap, dn, entry_attrs)
        return (completed, dn)


@register()
class hostgroup_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from a hostgroup.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        if keys[0] in PROTECTED_HOSTGROUPS and 'host' in options:
            result = api.Command.hostgroup_show(keys[0])
            hosts_left = set(result['result'].get('member_host', []))
            hosts_deleted = set(options['host'])
            if hosts_left.issubset(hosts_deleted):
                raise errors.LastMemberError(key=sorted(hosts_deleted)[0],
                                             label=_(u'hostgroup'),
                                             container=keys[0])

        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.suppress_netgroup_memberof(ldap, dn, entry_attrs)
        return (completed, dn)


@register()
class hostgroup_add_member_manager(LDAPAddMember):
    __doc__ = _('Add users that can manage members of this hostgroup.')

    has_output_params = (
        LDAPAddMember.has_output_params + hostgroup_output_params
    )
    member_attributes = ['membermanager']


@register()
class hostgroup_remove_member_manager(LDAPRemoveMember):
    __doc__ = _('Remove users that can manage members of this hostgroup.')

    has_output_params = (
        LDAPRemoveMember.has_output_params + hostgroup_output_params
    )
    member_attributes = ['membermanager']
