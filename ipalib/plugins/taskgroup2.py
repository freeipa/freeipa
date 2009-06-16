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
Taskgroups
"""

from ipalib import api
from ipalib.plugins.basegroup2 import *

_container_dn = api.env.container_taskgroup
_default_attributes = ['cn', 'description', 'member', 'memberOf']

class taskgroup2(basegroup2):
    """
    Taskgroup object.
    """
    container = _container_dn

api.register(taskgroup2)


class taskgroup2_create(basegroup2_create):
    """
    Create new taskgroup.
    """

api.register(taskgroup2_create)


class taskgroup2_delete(basegroup2_delete):
    """
    Delete taskgroup.
    """
    container = _container_dn

api.register(taskgroup2_delete)


class taskgroup2_mod(basegroup2_mod):
    """
    Edit taskgroup.
    """
    container = _container_dn

api.register(taskgroup2_mod)


class taskgroup2_find(basegroup2_find):
    """
    Search for taskgroups.
    """
    container = _container_dn

api.register(taskgroup2_find)


class taskgroup2_show(basegroup2_show):
    """
    Display taskgroup.
    """
    default_attributes = _default_attributes
    container = _container_dn

api.register(taskgroup2_show)


class taskgroup2_add_member(basegroup2_add_member):
    """
    Add member to taskgroup.
    """
    container = _container_dn
    takes_options = basegroup2_add_member.takes_options + (
        List('rolegroups?',
            cli_name='rolegroups',
            doc='comma-separated list of role groups to add'
        ),
    )

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
        ldap = self.api.Backend.ldap2
        dn = get_dn_by_attr(ldap, 'cn', cn, self.filter_class, self.container)
        to_add = []
        add_failed = []
        completed = 0

        members = kw.get('groups', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', 'ipaUserGroup',
            self.api.env.container_group
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        members = kw.get('hosts', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', 'ipaHost',
            self.api.env.container_host
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        members = kw.get('rolegroups', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', self.filter_class,
            self.api.env.container_rolegroups
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        return (completed, ldap.get_entry(dn, _default_attributes))

api.register(taskgroup2_add_member)


class taskgroup2_del_member(basegroup2_del_member):
    """
    Remove member from taskgroup.
    """
    container = _container_dn
    takes_options = basegroup2_del_member.takes_options + (
        List('rolegroups?',
            cli_name='rolegroups',
            doc='comma-separated list of role groups to remove'
        ),
    )

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
        ldap = self.api.Backend.ldap2
        dn = get_dn_by_attr(ldap, 'cn', cn, self.filter_class, self.container)
        to_remove = []
        remove_failed = []
        completed = 0

        members = kw.get('groups', [])
        (to_remove, remove_failed) = find_members(
            ldap, remove_failed, members, 'cn', 'ipaUserGroup',
            self.api.env.container_group
        )
        (completed, remove_failed) = del_members(
            ldap, completed, to_remove, remove_failed, dn, 'member'
        )

        members = kw.get('hosts', [])
        (to_remove, remove_failed) = find_members(
            ldap, remove_failed, members, 'cn', 'ipaHost',
            self.api.env.container_host
        )
        (completed, remove_failed) = del_members(
            ldap, completed, to_remove, remove_failed, dn, 'member'
        )

        members = kw.get('rolegroups', [])
        (to_remove, remove_failed) = find_members(
            ldap, remove_failed, members, 'cn', self.filter_class,
            self.api.env.container_rolegroups
        )
        (completed, remove_failed) = del_members(
            ldap, completed, to_remove, remove_failed, dn, 'member'
        )

        return (completed, ldap.get_entry(dn, _default_attributes))

api.register(taskgroup2_del_member)

