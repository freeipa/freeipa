# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext


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
        'memberuser', 'memberhost','member', 'memberindirect',
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
    )

api.register(netgroup)


class netgroup_add(LDAPCreate):
    """
    Add a new netgroup.
    """
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

api.register(netgroup_mod)


class netgroup_find(LDAPSearch):
    """
    Search for a netgroup.
    """

api.register(netgroup_find)


class netgroup_show(LDAPRetrieve):
    """
    Display information about a netgroup.
    """

api.register(netgroup_show)


class netgroup_add_member(LDAPAddMember):
    """
    Add members to a netgroup.
    """
    member_attributes = ['memberuser', 'memberhost', 'member']
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
    member_attributes = ['memberuser', 'memberhost']
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
