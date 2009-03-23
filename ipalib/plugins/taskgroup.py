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
Frontend plugins for taskgroups.
"""

from ipalib import api
from ipalib.plugins.basegroup import *

display_attributes = ('cn','description', 'member', 'memberof')
container_taskgroup = "cn=taskgroups,cn=accounts"
container_rolegroup = "cn=rolegroups,cn=accounts"

class taskgroup(BaseGroup):
    """
    taskgroup object.
    """
    container=container_taskgroup

api.register(taskgroup)


class taskgroup_add(basegroup_add):
    'Add a new taskgroup.'

api.register(taskgroup_add)


class taskgroup_del(basegroup_del):
    'Delete an existing taskgroup.'
    container = container_taskgroup

api.register(taskgroup_del)


class taskgroup_mod(basegroup_mod):
    'Edit an existing taskgroup.'
    container = container_taskgroup

api.register(taskgroup_mod)


class taskgroup_find(basegroup_find):
    'Search the groups.'
    container = container_taskgroup

api.register(taskgroup_find)


class taskgroup_show(basegroup_show):
    'Examine an existing taskgroup.'
    default_attributes = display_attributes
    container = container_taskgroup

api.register(taskgroup_show)


class taskgroup_showall(Command):
    'List all taskgroups.'
    default_attributes = display_attributes
    container = container_taskgroup
    takes_args = ()

    def execute(self, **kw):
        ldap = self.api.Backend.ldap

        search_kw = {"cn": "*"}
        search_kw['objectclass'] = "groupofnames"
        search_kw['base'] = self.container
        search_kw['exactonly'] = True
        search_kw['attributes'] = ['cn', 'description']

        return ldap.search(**search_kw)

    def output_for_cli(self, textui, result, **options):
        counter = result[0]
        groups = result[1:]
        if counter == 0 or len(groups) == 0:
            textui.print_plain("No entries found")
            return
        for g in groups:
            textui.print_entry(g)
            textui.print_plain('')
        if counter == -1:
            textui.print_plain("These results are truncated.")
            textui.print_plain("Please refine your search and try again.")
        textui.print_count(groups, '%d groups matched')

api.register(taskgroup_showall)


class taskgroup_add_member(basegroup_add_member):
    'Add a member to a taskgroup.'
    container = container_taskgroup
    takes_options = basegroup_add_member.takes_options + (List('rolegroups?', doc='comma-separated list of role groups to add'),)

    def execute(self, cn, **kw):
        """
        Execute the group-add-member operation.

        Returns the updated group entry

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to add
        :param kw: users is a comma-separated list of users to add
        :param kw: rolegroups is a comma-separated list of rolegroups to add
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)
        add_failed = []
        to_add = []
        completed = 0

        # Do the base class additions first
        add_failed = super(taskgroup_add_member, self).execute(cn, **kw)

        members = kw.get('rolegroups', [])
        (to_add, add_failed) = self._find_members(ldap, add_failed, members, "cn", self.filter_class, container_rolegroup)
        (completed, add_failed) = self._add_members(ldap, completed, to_add, add_failed, dn, "member")

        return add_failed

api.register(taskgroup_add_member)


class taskgroup_remove_member(basegroup_remove_member):
    'Remove a member from a taskgroup.'
    container = container_taskgroup
    takes_options = basegroup_remove_member.takes_options + (List('rolegroups?', doc='comma-separated list of role groups to remove'),)

    def execute(self, cn, **kw):
        """
        Execute the group-remove-member operation.

        Returns the updated group entry

        :param cn: The group name to remove new members from.
        :param kw: groups is a comma-separated list of groups to remove
        :param kw: users is a comma-separated list of users to remove
        :param kw: rolegroups is a comma-separated list of rolegroups to remove
        """
        assert self.container
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", cn, self.filter_class, self.container)
        remove_failed = []
        to_remove = []
        completed = 0

        # Do the base class removals first
        remove_failed = super(taskgroup_remove_member, self).execute(cn, **kw)

        members = kw.get('rolegroups', [])
        (to_remove, remove_failed) = self._find_members(ldap, remove_failed, members, "cn", self.filter_class, container_rolegroup)
        (completed, remove_failed) = self._remove_members(ldap, completed, to_remove, remove_failed, dn, "member")

        return remove_failed

api.register(taskgroup_remove_member)
