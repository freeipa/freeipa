# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Frontend plugins for netgroups.
"""

from ipalib import api
from ipalib.plugins.basegroup import *
from ipalib import uuid

display_attributes = ['cn','description','memberhost','externalhost','memberuser','member']
container_netgroup = "cn=ng, cn=alt"
default_class = "ipaNISNetgroup"

class netgroup(BaseGroup):
    """
    netgroup object.
    """
    container=container_netgroup
    takes_params = (
        Str('description',
            doc='A description of this group',
            attribute=True,
        ),
        Str('cn',
            cli_name='name',
            primary_key=True,
            normalizer=lambda value: value.lower(),
            attribute=True,
        ),
        Str('nisdomainname',
            doc='The NIS domain name',
            attribute=True,
        ),
    )

api.register(netgroup)


class netgroup_add(basegroup_add):
    'Add a new netgroup.'
    def execute(self, cn, **kw):
        """
        Execute the netgroup-add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        :param cn: The name of the netgroup
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        kw['cn'] = cn
        kw['ipauniqueid'] = str(uuid.uuid1())
        kw['dn'] = "ipauniqueid=%s,%s,%s" % (kw['ipauniqueid'], container_netgroup, api.env.basedn)
        if not kw.get('nisdomainname', False):
            kw['nisdomainname'] = api.env.domain

        # some required objectclasses
        kw['objectclass'] = ['top', 'ipaAssociation', 'ipaNISNetgroup']

        return ldap.create(**kw)

api.register(netgroup_add)


class netgroup_del(basegroup_del):
    'Delete an existing netgroup.'
    container = container_netgroup
    filter_class = default_class

api.register(netgroup_del)


class netgroup_mod(basegroup_mod):
    'Edit an existing netgroup.'
    container = container_netgroup
    filter_class = default_class

api.register(netgroup_mod)


class netgroup_find(basegroup_find):
    'Search the groups.'
    container = container_netgroup
    filter_class = default_class

api.register(netgroup_find)


class netgroup_show(basegroup_show):
    'Examine an existing netgroup.'
    default_attributes = display_attributes
    container = container_netgroup
    filter_class = default_class

api.register(netgroup_show)


class netgroup_add_member(basegroup_add_member):
    'Add a member to a netgroup.'
    default_attributes = display_attributes
    container = container_netgroup
    filter_class = default_class
    takes_options = basegroup_add_member.takes_options + (
        List('hosts?', doc='comma-separated list of hosts to add'),
        List('hostgroups?', doc='comma-separated list of host groups to add'),
        List('netgroups?', doc='comma-separated list of netgroups to add'),
    )

    def _add_external(self, ldap, completed, members, cn):
        failed = []
        kw = {"all": True}
        netgroup = api.Command['netgroup_show'](cn, **kw)
        external = netgroup.get('externalhost', [])
        if not isinstance(external, list):
            external = [external]
        external_len = len(external)
        for m in members:
            if not m in external:
                external.append(m)
                completed+=1
            else:
                failed.append(m)
        if len(external) > external_len:
            kw = {'externalhost': external}
            ldap.update(netgroup['dn'], **kw)

        return completed, failed

    def execute(self, cn, **kw):
        """
        Execute the group-add-member operation.

        Returns the updated group entry

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to add
        :param kw: users is a comma-separated list of users to add
        :param kw: hostgroups is a comma-separated list of hostgroups to add
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)
        add_failed = []
        to_add = []
        completed = 0

        # Hosts
        members = kw.get('hosts', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "cn", "ipaHost")

        # If a host is not found we'll consider it an externalHost. It will
        # be up to the user to handle typos
        if add_failed:
            (completed, add_failed) = self._add_external(ldap, completed, add_failed, cn)

        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "memberhost")

        # Hostgroups
        members = kw.get('hostgroups', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "cn", "ipaHostGroup", self.api.env.container_hostgroup)
        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "memberhost")

        # User
        members = kw.get('users', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "uid", "posixAccount", self.api.env.container_user)
        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "memberuser")

        # Groups
        members = kw.get('groups', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "cn", "ipaUserGroup", self.api.env.container_group)
        (completed, failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "memberuser")

        # Netgroups
        members = kw.get('netgroups', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "cn", self.filter_class, self.container)
        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "member")

        return add_failed

api.register(netgroup_add_member)


class netgroup_remove_member(basegroup_remove_member):
    'Remove a member from a netgroup.'
    default_attributes = display_attributes
    container = container_netgroup
    filter_class = default_class
    takes_options = basegroup_remove_member.takes_options + (
        List('hosts?', doc='comma-separated list of hosts to remove'),
        List('hostgroups?', doc='comma-separated list of host groups to remove'),
        List('netgroups?', doc='comma-separated list of netgroups to remove'),
    )

    def _remove_external(self, ldap, completed, members, cn):
        failed = []
        kw = {"all": True}
        netgroup = api.Command['netgroup_show'](cn, **kw)
        external = netgroup.get('externalhost', [])
        if not isinstance(external, list):
            external = [external]
        external_len = len(external)
        for m in members:
            try:
                external.remove(m)
                completed+=1
            except ValueError:
                failed.append(m)
        if len(external) < external_len:
            kw = {'externalhost': external}
            ldap.update(netgroup['dn'], **kw)

        return completed, failed

    def execute(self, cn, **kw):
        """
        Execute the group-remove-member operation.

        Returns the updated group entry

        :param cn: The group name to remove new members to.
        :param kw: groups is a comma-separated list of groups to remove
        :param kw: users is a comma-separated list of users to remove
        :param kw: hostgroups is a comma-separated list of hostgroups to remove
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)
        remove_failed = []
        to_remove = []
        completed = 0

        # Hosts
        members = kw.get('hosts', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "cn", "ipaHost")

        # If a host is not found we'll consider it an externalHost. It will
        # be up to the user to handle typos
        if remove_failed:
            (completed, remove_failed) = self._remove_external(ldap, completed, remove_failed, cn)

        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "memberhost")

        # Hostgroups
        members = kw.get('hostgroups', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "cn", "ipaHostGroup", self.api.env.container_hostgroup)
        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "memberhost")

        # User
        members = kw.get('users', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "uid", "posixAccount", self.api.env.container_user)
        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "memberuser")

        # Groups
        members = kw.get('groups', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "cn", "ipaUserGroup", self.api.env.container_group)
        (completed, failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "memberuser")

        # Netgroups
        members = kw.get('netgroups', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "cn", self.filter_class, self.container)
        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "member")

        return remove_failed

api.register(netgroup_remove_member)
