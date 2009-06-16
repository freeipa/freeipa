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
Netgroups.
"""

from ipalib import api
from ipalib.plugins.basegroup import *
from ipalib import uuid

_container_dn = 'cn=ng,cn=alt'
_default_attributes = [
    'cn', 'description', 'member', 'memberUser', 'memberhost','externalhost'
]
_default_class = 'ipanisnetgroup'


class netgroup(basegroup):
    """
    Netgroup object.
    """
    container = _container_dn

api.register(netgroup)


class netgroup_create(basegroup_create):
    """
    Create new netgroup.
    """
    takes_options = (
        Str('nisdomainname?',
            cli_name='nisdomain',
            doc='NIS domain name',
        ),
    )

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
        ldap = self.api.Backend.ldap2

        entry_attrs = self.args_options_2_entry(cn, **kw)
        entry_attrs['ipauniqueid'] = str(uuid.uuid1())
        entry_attrs['objectclass'] = ['top', 'ipaassociation', _default_class]
        entry_attrs.setdefault('nisdomainname', self.api.env.domain)

        dn = ldap.make_dn(entry_attrs, 'ipauniqueid', _container_dn)

        ldap.add_entry(dn, entry_attrs)

        return ldap.get_entry(dn, _default_attributes)

api.register(netgroup_create)


class netgroup_delete(basegroup_delete):
    """
    Delete netgroup.
    """
    container = _container_dn
    filter_class = _default_class

    def execute(self, cn, **kw):
        return super(netgroup_delete, self).execute(cn, **kw)

api.register(netgroup_delete)


class netgroup_mod(basegroup_mod):
    """
    Edit an existing netgroup.
    """
    container = _container_dn
    filter_class = _default_class

    def execute(self, cn, **kw):
        return super(netgroup_mod, self).execute(cn, **kw)

api.register(netgroup_mod)


class netgroup_find(basegroup_find):
    """
    Search the groups.
    """
    container = _container_dn
    filter_class = _default_class

    def execute(self, cn, **kw):
        return super(netgroup_find, self).execute(cn, **kw)

api.register(netgroup_find)


class netgroup_show(basegroup_show):
    """
    Display netgroup.
    """
    filter_class = _default_class
    default_attributes = _default_attributes
    container = _container_dn

    def execute(self, cn, **kw):
        return super(netgroup_show, self).execute(cn, **kw)

api.register(netgroup_show)


class netgroup_add_member(basegroup_add_member):
    """
    Add members to netgroup.
    """
    default_attributes = _default_attributes
    container = _container_dn
    filter_class = _default_class

    takes_options = basegroup_add_member.takes_options + (
        List('hosts?',
            cli_name='hosts',
            doc='comma-separated list of hosts to add'
        ),
        List('hostgroups?',
            cli_name='hostgroups',
            doc='comma-separated list of host groups to add'
        ),
        List('netgroups?',
            cli_name='netgroups',
            doc='comma-separated list of netgroups to add'
        ),
    )

    def _add_external(self, ldap, completed, members, group_dn):
        add_failed = []
        entry_attrs = ldap.get_entry(group_dn, ['externalhost'])
        external_hosts = entry_attrs.get('externalhost', [])

        for m in members:
            m = m.lower()
            if m not in external_hosts:
                external_hosts.append(m)
                completed += 1
            else:
                add_failed.append(m)

        try:
            ldap.update_entry(group_dn, **{'externalhost': external_hosts})
        except errors.EmptyModlist:
            pass

        return (completed, add_failed)

    def execute(self, cn, **kw):
        """
        Execute the group-add-member operation.

        Returns a tuple containing the number of members added
        and the updated entry.

        :param cn: The group name to add new members to.
        :param kw: groups is a comma-separated list of groups to add
        :param kw: users is a comma-separated list of users to add
        :param kw: hostgroups is a comma-separated list of hostgroups to add
        """
        assert self.container
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

        members = kw.get('users', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'uid', 'posixaccount',
            self.api.env.container_user
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        members = kw.get('hosts', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', 'ipahost',
            self.api.env.container_host
        )

        # If a host is not found we'll consider it an externalHost. It will
        # be up to the user to handle typos
        if add_failed:
            (completed, add_failed) = self._add_external(ldap, completed, add_failed, dn)

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

        members = kw.get('netgroups', [])
        (to_add, add_failed) = find_members(
            ldap, add_failed, members, 'cn', _default_class,
            _container_dn
        )
        (completed, add_failed) = add_members(
            ldap, completed, to_add, add_failed, dn, 'member'
        )

        return (completed, ldap.get_entry(dn, _default_attributes))

api.register(netgroup_add_member)


class netgroup_del_member(basegroup_del_member):
    """
    Remove a member from a netgroup.
    """
    default_attributes = _default_attributes
    container = _container_dn
    filter_class = _default_class

    takes_options = basegroup_del_member.takes_options + (
        List('hosts?',
            cli_name='hosts',
            doc='comma-separated list of hosts to remove'
        ),
        List('hostgroups?',
            cli_name='hostgroups',
            doc='comma-separated list of host groups to remove'
        ),
        List('netgroups?',
            cli_name='netgroups',
            doc='comma-separated list of netgroups to remove'
        ),
    )

    def _del_external(self, ldap, completed, members, group_dn):
        rem_failed = []
        entry_attrs = ldap.get_entry(group_dn, ['externalhost'])
        external_hosts = entry_attrs.get('externalhost', [])

        for m in members:
            m = m.lower()
            if m in external_hosts:
                external_hosts.remove(m)
                completed += 1
            else:
                rem_failed.append(m)

        try:
            ldap.update_entry(group_dn, **{'externalhost': external_hosts})
        except errors.EmptyModlist:
            pass

        return (completed, rem_failed)

    def execute(self, cn, **kw):
        """
        Execute the group-remove-member operation.

        Returns a tuple containing the number of members removed
        and the updated entry.

        :param cn: The group name to remove new members to.
        :param kw: groups is a comma-separated list of groups to remove
        :param kw: users is a comma-separated list of users to remove
        :param kw: hostgroups is a comma-separated list of hostgroups to remove
        """
        assert self.container
        ldap = self.api.Backend.ldap2
        dn = get_dn_by_attr(ldap, 'cn', cn, self.filter_class, self.container)
        to_rem = []
        rem_failed = []
        completed = 0

        members = kw.get('groups', [])
        (to_rem, rem_failed) = find_members(
            ldap, rem_failed, members, 'cn', 'ipausergroup',
            self.api.env.container_group
        )
        (completed, rem_failed) = del_members(
            ldap, completed, to_rem, rem_failed, dn, 'member'
        )

        members = kw.get('users', [])
        (to_rem, rem_failed) = find_members(
            ldap, rem_failed, members, 'uid', 'posixaccount',
            self.api.env.container_user
        )
        (completed, rem_failed) = del_members(
            ldap, completed, to_rem, rem_failed, dn, 'member'
        )

        members = kw.get('hosts', [])
        (to_rem, rem_failed) = find_members(
            ldap, rem_failed, members, 'cn', 'ipahost',
            self.api.env.container_host
        )

        # If a host is not found we'll consider it an externalHost. It will
        # be up to the user to handle typos
        if rem_failed:
            (completed, rem_failed) = self._del_external(ldap, completed, rem_failed, dn)

        (completed, rem_failed) = del_members(
            ldap, completed, to_rem, rem_failed, dn, 'member'
        )

        members = kw.get('hostgroups', [])
        (to_rem, rem_failed) = find_members(
            ldap, rem_failed, members, 'cn', 'ipahostgroup',
            self.api.env.container_hostgroup
        )
        (completed, rem_failed) = del_members(
            ldap, completed, to_rem, rem_failed, dn, 'member'
        )

        members = kw.get('netgroups', [])
        (to_rem, rem_failed) = find_members(
            ldap, rem_failed, members, 'cn', _default_class,
            _container_dn
        )
        (completed, rem_failed) = del_members(
            ldap, completed, to_rem, rem_failed, dn, 'member'
        )

        return (completed, ldap.get_entry(dn, _default_attributes))

api.register(netgroup_del_member)

