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
Frontend plugins for hostgroups.
"""

from ipalib import api
from ipalib.plugins.basegroup import *

container_hostgroup = api.env.container_hostgroup
default_class="ipaHostGroup"

class hostgroup(BaseGroup):
    """
    hostgroup object.
    """
    container=container_hostgroup

api.register(hostgroup)


class hostgroup_add(basegroup_add):
    'Add a new hostgroup.'
    base_classes = ["top", "groupofnames", "ipaHostGroup"]

api.register(hostgroup_add)


class hostgroup_del(basegroup_del):
    'Delete an existing hostgroup.'
    container = container_hostgroup

api.register(hostgroup_del)


class hostgroup_mod(basegroup_mod):
    'Edit an existing hostgroup.'
    container = container_hostgroup

api.register(hostgroup_mod)


class hostgroup_find(basegroup_find):
    'Search the groups.'
    container = container_hostgroup

api.register(hostgroup_find)


class hostgroup_show(basegroup_show):
    'Examine an existing hostgroup.'
    container = container_hostgroup

api.register(hostgroup_show)


class hostgroup_add_member(basegroup_add_member):
    'Add a member to a hostgroup.'
    container = container_hostgroup
    takes_options = (
        List('groups?', doc='comma-separated list of user groups to add'),
        List('hosts?', doc='comma-separated list of hosts to add'),
        List('hostgroups?', doc='comma-separated list of hostgroups to add'),
    )

    def execute(self, cn, **kw):
        """
        Execute the group-add-member operation.

        Returns the updated group entry

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to add
        :parem kw: users is a comma-separated list of users to add
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)
        add_failed = []
        to_add = []
        completed = 0

        # Do the base class additions first. Note that the super function
        # also supports users but since we never pass any in that code
        # will never execute
        add_failed = super(hostgroup_add_member, self).execute(cn, **kw)

        members = kw.get('hosts', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "cn", "ipaHost", self.api.env.container_host)
        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "member")

        members = kw.get('hostgroups', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "cn", default_class, self.api.env.container_hostgroup)
        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "member")

        return add_failed

api.register(hostgroup_add_member)


class hostgroup_remove_member(basegroup_remove_member):
    'Remove a member from a hostgroup.'
    container = container_hostgroup
    takes_options = (
        List('groups?', doc='comma-separated list of user groups to add'),
        List('hosts?', doc='comma-separated list of hosts to add'),
        List('hostgroups?', doc='comma-separated list of hostgroups to add'),
    )

    def execute(self, cn, **kw):
        """
        Execute the group-remove-member operation.

        Returns the updated group entry

        :param cn: The group name to remove new members from.
        :parem kw: users is a comma-separated list of users to remove
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)
        remove_failed = []
        to_remove = []
        completed = 0

        # Do the base class removals first
        remove_failed = super(hostgroup_remove_member, self).execute(cn, **kw)

        members = kw.get('hosts', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "cn", "ipaHost", self.api.env.container_host)
        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "member")

        members = kw.get('hostgroups', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "cn", default_class, self.api.env.container_hostgroup)
        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "member")

        return remove_failed

api.register(hostgroup_remove_member)
