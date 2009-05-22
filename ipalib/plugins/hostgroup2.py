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
Groups of hosts.
"""

from ipalib import api
from ipalib.plugins.basegroup2 import *

_container_dn = api.env.container_hostgroup
_default_attributes = ['cn', 'description', 'member', 'memberof']
_default_class = 'ipahostgroup'


class hostgroup2(basegroup2):
    """
    Hostgroup object.
    """
    container = _container_dn

api.register(hostgroup2)


class hostgroup2_create(basegroup2_create):
    """
    Create a new hostgroup.
    """
    base_classes = basegroup2_create.base_classes + (_default_class, )

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(hostgroup2_create, self).execute(cn, **kw)

api.register(hostgroup2_create)


class hostgroup2_delete(basegroup2_delete):
    """
    Delete an existing hostgroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(hostgroup2_delete, self).execute(cn, **kw)

api.register(hostgroup2_delete)


class hostgroup2_mod(basegroup2_mod):
    """
    Edit an existing hostgroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(hostgroup2_mod, self).execute(cn, **kw)

api.register(hostgroup2_mod)


class hostgroup2_find(basegroup2_find):
    """
    Search the groups.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(hostgroup2_find, self).execute(cn, **kw)

api.register(hostgroup2_find)


class hostgroup2_show(basegroup2_show):
    """
    Examine an existing hostgroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(hostgroup2_show, self).execute(cn, **kw)

api.register(hostgroup2_show)


class hostgroup2_add_member(basegroup2_add_member):
    """
    Add members to hostgroup.
    """
    container = _container_dn

    takes_options = (
        List('groups?',
            cli_name='groups',
            doc='comma-separated list of user groups to add'
        ),
        List('hosts?',
            cli_name='hosts',
            doc='comma-separated list of hosts to add'
        ),
        List('hostgroups?',
            cli_name='hostgroups',
            doc='comma-separated list of hostgroups to add'
        ),
    )

    def execute(self, cn, **kw):
        """
        Execute the group-add-member operation.

        Returns a tuple containing the number of members added
        and the updated entry.

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to add
        :parem kw: users is a comma-separated list of users to add
        """
        assert self.container
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        ldap = self.api.Backend.ldap2
        dn = get_dn_by_attr(ldap, 'cn', cn, self.filter_class, self.container)
        to_add = []
        add_failed = []
        completed = 0

        members = kw.get('groups', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', 'ipausergroup',
            self.api.env.container_group
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        members = kw.get('hosts', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', 'ipahost',
            self.api.env.container_host
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        members = kw.get('hostgroups', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', 'ipahostgroup',
            self.api.env.container_hostgroup
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        return (completed, ldap.get_entry(dn, self.default_attributes))

api.register(hostgroup2_add_member)


class hostgroup2_del_member(basegroup2_del_member):
    """
    Remove members from hostgroup.
    """
    container = _container_dn

    takes_options = (
        List('groups?',
            cli_name='groups',
            doc='comma-separated list of user groups to add'
        ),
        List('hosts?',
            cli_name='hosts',
            doc='comma-separated list of hosts to add'
        ),
        List('hostgroups?',
            cli_name='hostgroups',
            doc='comma-separated list of hostgroups to add'
        ),
    )

    def execute(self, cn, **kw):
        """
        Execute the group-del-member operation.

        Returns a tuple containing the number of members removed
        and the updated entry.

        :param cn: The group name to remove new members from.
        :parem kw: users is a comma-separated list of users to remove
        """
        assert self.container
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        ldap = self.api.Backend.ldap2
        dn = get_dn_by_attr(ldap, 'cn', cn, self.filter_class, self.container)
        to_remove = []
        remove_failed = []
        completed = 0

        members = kw.get('groups', [])
        (to_remove, remove_failed) = find_members(
            ldap, remove_failed, members, 'cn', 'ipausergroup',
            self.api.env.container_group
        )
        (completed, remove_failed) = del_members(
            ldap, completed, to_remove, remove_failed, dn, 'member'
        )

        members = kw.get('hosts', [])
        (to_remove, remove_failed) = find_members(
            ldap, remove_failed, members, 'cn', 'ipahost',
            self.api.env.container_host
        )
        (completed, remove_failed) = del_members(
            ldap, completed, to_remove, remove_failed, dn, 'member'
        )

        members = kw.get('hostgroups', [])
        (to_remove, remove_failed) = find_members(
            ldap, remove_failed, members, 'cn', 'ipahostgroup',
            self.api.env.container_hostgroup
        )
        (completed, remove_failed) = del_members(
            ldap, completed, to_remove, remove_failed, dn, 'member'
        )

        return (completed, ldap.get_entry(dn, _default_attributes))

api.register(hostgroup2_del_member)

