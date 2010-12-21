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
"""
Netgroups

A netgroup is a group used for permission checking. It can contain both
user and host values.

EXAMPLES:

 Add a new netgroup:
   ipa netgroup-add --desc="NFS admins" admins

 Add members to the netgroup:
   ipa netgroup-add-member --users=tuser1,tuser2 admins

 Remove a member from the netgroup:
   ipa netgroup-remove-member --users=tuser2 admins

 Display infromation about a netgroup:
   ipa netgroup-show admins

 Delete a netgroup:
   ipa netgroup-del admins
"""

from ipalib import api, errors
from ipalib import Str, StrEnum
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
from ipalib.plugins.hbacrule import is_all


output_params = (
        Str('memberuser_user?',
            label='Member User',
        ),
        Str('memberuser_group?',
            label='Member Group',
        ),
        Str('memberhost_host?',
            label=_('Member Host'),
        ),
        Str('memberhost_hostgroup?',
            label='Member Hostgroup',
        ),
    )

class netgroup(LDAPObject):
    """
    Netgroup object.
    """
    container_dn = api.env.container_netgroup
    object_name = 'netgroup'
    object_name_plural = 'netgroups'
    object_class = ['ipaobject', 'ipaassociation', 'ipanisnetgroup']
    default_attributes = [
        'cn', 'description', 'memberof', 'externalhost', 'nisdomainname',
        'memberuser', 'memberhost', 'member', 'memberindirect',
        'usercategory', 'hostcategory',
    ]
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['netgroup'],
        'memberof': ['netgroup'],
        'memberindirect': ['netgroup'],
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
    }
    relationships = {
        'member': ('Member', '', 'no_'),
        'memberof': ('Member Of', 'in_', 'not_in_'),
        'memberindirect': (
            'Indirect Member', None, 'no_indirect_'
        ),
        'memberuser': ('Member', '', 'no_'),
        'memberhost': ('Member', '', 'no_'),
    }

    label = _('Net Groups')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Netgroup name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('Netgroup description'),
        ),
        Str('nisdomainname?',
            cli_name='nisdomain',
            label=_('NIS domain name'),
        ),
        Str('ipauniqueid?',
            cli_name='uuid',
            label='IPA unique ID',
            doc=_('IPA unique ID'),
            flags=['no_create', 'no_update'],
        ),
        StrEnum('usercategory?',
            cli_name='usercat',
            label=_('User category'),
            doc=_('User category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('hostcategory?',
            cli_name='hostcat',
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
            values=(u'all', ),
        ),
    )

api.register(netgroup)


class netgroup_add(LDAPCreate):
    """
    Add a new netgroup.
    """
    has_output_params = LDAPCreate.has_output_params + output_params
    msg_summary = _('Added netgroup "%(value)s"')
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        entry_attrs.setdefault('nisdomainname', self.api.env.domain)
        return dn

api.register(netgroup_add)


class netgroup_del(LDAPDelete):
    """
    Delete a netgroup.
    """
    msg_summary = _('Deleted netgroup "%(value)s"')

api.register(netgroup_del)


class netgroup_mod(LDAPUpdate):
    """
    Modify a netgroup.
    """
    has_output_params = LDAPUpdate.has_output_params + output_params
    msg_summary = _('Modified netgroup "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)
        if is_all(options, 'usercategory') and 'memberuser' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason="user category cannot be set to 'all' while there are allowed users")
        if is_all(options, 'hostcategory') and 'memberhost' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason="host category cannot be set to 'all' while there are allowed hosts")
        return dn

api.register(netgroup_mod)


class netgroup_find(LDAPSearch):
    """
    Search for a netgroup.
    """
    member_attributes = ['member', 'memberuser', 'memberhost', 'memberof']
    has_output_params = LDAPSearch.has_output_params + output_params
    msg_summary = ngettext(
        '%(count)d netgroup matched', '%(count)d netgroups matched'
    )

api.register(netgroup_find)


class netgroup_show(LDAPRetrieve):
    """
    Display information about a netgroup.
    """
    has_output_params = LDAPRetrieve.has_output_params + output_params

api.register(netgroup_show)


class netgroup_add_member(LDAPAddMember):
    """
    Add members to a netgroup.
    """
    member_attributes = ['memberuser', 'memberhost', 'member']
    has_output_params = LDAPAddMember.has_output_params + output_params
    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        completed_external = 0
        # Sift through the host failures. We assume that these are all
        # hosts that aren't stored in IPA, aka external hosts.
        if 'memberhost' in failed and 'host' in failed['memberhost']:
            (dn, entry_attrs_) = ldap.get_entry(dn, ['externalhost'])
            members = entry_attrs.get('memberhost', [])
            external_hosts = entry_attrs_.get('externalhost', [])
            failed_hosts = []
            for host in failed['memberhost']['host']:
                hostname = host[0].lower()
                host_dn = self.api.Object['host'].get_dn(hostname)
                if hostname not in external_hosts and host_dn not in members:
                    external_hosts.append(hostname)
                    completed_external += 1
                else:
                    failed_hosts.append(hostname)
            if completed_external:
                try:
                    ldap.update_entry(dn, {'externalhost': external_hosts})
                except errors.EmptyModlist:
                    pass
                failed['memberhost']['host'] = failed_hosts
                entry_attrs['externalhost'] = external_hosts
        return (completed + completed_external, dn)


api.register(netgroup_add_member)


class netgroup_remove_member(LDAPRemoveMember):
    """
    Remove members from a netgroup.
    """
    member_attributes = ['memberuser', 'memberhost', 'member']
    has_output_params = LDAPRemoveMember.has_output_params + output_params
    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        # Run through the host failures and gracefully remove any defined as
        # as an externalhost.
        if 'memberhost' in failed and 'host' in failed['memberhost']:
            (dn, entry_attrs) = ldap.get_entry(dn, ['externalhost'])
            external_hosts = entry_attrs.get('externalhost', [])
            failed_hosts = []
            completed_external = 0
            for host in failed['memberhost']['host']:
                hostname = host[0].lower()
                if hostname in external_hosts:
                    external_hosts.remove(hostname)
                    completed_external += 1
                else:
                    failed_hosts.append(hostname)
            if completed_external:
                try:
                    ldap.update_entry(dn, {'externalhost': external_hosts})
                except errors.EmptyModlist:
                    pass
                failed['memberhost']['host'] = failed_hosts
                entry_attrs['externalhost'] = external_hosts
        return (completed + completed_external, dn)

api.register(netgroup_remove_member)
