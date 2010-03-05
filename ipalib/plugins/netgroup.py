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
        'cn', 'description', 'member', 'memberof', 'externalhost',
        'nisdomainname',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['user', 'group', 'host', 'hostgroup', 'netgroup'],
        'memberof': ['netgroup'],
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
        Str('member_user?',
            label='Member User',
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member_group?',
            label='Member Group',
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member_host?',
            label=_('Member host'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member_hostgroup?',
            label='Member Hostgroup',
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('externalhost?',
            label=_('External host'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

    def get_dn(self, *keys, **kwargs):
        try:
            (dn, entry_attrs) = self.backend.find_entry_by_attr(
                self.primary_key.name, keys[-1], self.object_class, [''],
                self.container_dn
            )
        except errors.NotFound:
            dn = super(netgroup, self).get_dn(*keys, **kwargs)
        return dn

    def get_primary_key_from_dn(self, dn):
        pkey = self.primary_key.name
        (dn, entry_attrs) = self.backend.get_entry(dn, [pkey])
        try:
            return entry_attrs[pkey][0]
        except (KeyError, IndexError):
            return ''

api.register(netgroup)


class netgroup_add(LDAPCreate):
    """
    Create new netgroup.
    """
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if not dn.startswith('cn='):
            msg = 'netgroup with name "%s" already exists' % keys[-1]
            raise errors.DuplicateEntry(message=msg)
        entry_attrs.setdefault('nisdomainname', self.api.env.domain)
        dn = ldap.make_dn(
            entry_attrs, self.obj.uuid_attribute, self.obj.container_dn
        )
        return dn

api.register(netgroup_add)


class netgroup_del(LDAPDelete):
    """
    Delete netgroup.
    """

api.register(netgroup_del)


class netgroup_mod(LDAPUpdate):
    """
    Modify netgroup.
    """

api.register(netgroup_mod)


class netgroup_find(LDAPSearch):
    """
    Search the groups.
    """

api.register(netgroup_find)


class netgroup_show(LDAPRetrieve):
    """
    Display netgroup.
    """

api.register(netgroup_show)


class netgroup_add_member(LDAPAddMember):
    """
    Add members to netgroup.
    """
    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        if 'member' in failed and 'host' in failed['member']:
            (dn, entry_attrs_) = ldap.get_entry(dn, ['externalhost'])
            members = entry_attrs.get('member', [])
            external_hosts = entry_attrs_.get('externalhost', [])
            failed_hosts = []
            completed_external = 0
            for host in failed['member']['host']:
                host = host.lower()
                host_dn = self.api.Object['host'].get_dn(host)
                if host not in external_hosts and host_dn not in members:
                    external_hosts.append(host)
                    completed_external += 1
                else:
                    failed_hosts.append(host)
            if completed_external:
                try:
                    ldap.update_entry(dn, {'externalhost': external_hosts})
                except errors.EmptyModlist:
                    pass
                failed['member']['host'] = failed_hosts
                entry_attrs['externalhost'] = external_hosts
        return (completed + completed_external, dn)


api.register(netgroup_add_member)


class netgroup_remove_member(LDAPRemoveMember):
    """
    Remove members from netgroup.
    """
    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        if 'member' in failed and 'host' in failed['member']:
            (dn, entry_attrs) = ldap.get_entry(dn, ['externalhost'])
            external_hosts = entry_attrs.get('externalhost', [])
            failed_hosts = []
            completed_external = 0
            for host in failed['member']['host']:
                host = host.lower()
                if host in external_hosts:
                    external_hosts.remove(host)
                    completed_external += 1
                else:
                    failed_hosts.append(host)
            if completed_external:
                try:
                    ldap.update_entry(dn, {'externalhost': external_hosts})
                except errors.EmptyModlist:
                    pass
                failed['member']['host'] = failed_hosts
                entry_attrs['externalhost'] = external_hosts
        return (completed + completed_external, dn)

api.register(netgroup_remove_member)
