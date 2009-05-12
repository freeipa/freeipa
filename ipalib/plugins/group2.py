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
Groups of users.
"""

from ipalib import api
from ipalib.plugins.basegroup2 import *

_container_dn = api.env.container_group
_default_attributes = ['cn', 'description', 'gidNumber', 'member', 'memberOf']
_default_class = 'ipaUserGroup'


class group2(basegroup2):
    """
    Group object.
    """
    container = _container_dn

    takes_params = basegroup2.takes_params + (
        Int('gidnumber?',
            cli_name='gid',
            doc='GID (use this option to set it manually)',
        ),
    )

api.register(group2)


class group2_create(basegroup2_create):
    """
    Create new group.
    """
    takes_options = (
        Flag('posix',
             cli_name='posix',
             doc='create as posix group?',
        ),
    )

    def execute(self, cn, **kw):
        """
        Execute the group-add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        No need to explicitly set gidNumber. The dna_plugin will do this
        for us if the value isn't provided by the caller.

        :param cn: The name of the group being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        ldap = self.api.Backend.ldap2

        config = ldap.get_ipa_config()[1]

        kw['objectclass'] = config.get('ipaGroupObjectClasses')
        if kw['posix'] or 'gidnumber' in kw:
            kw['objectclass'].append('posixGroup')

        return super(group2_create, self).execute(cn, **kw)

api.register(group2_create)


class group2_delete(basegroup2_delete):
    """
    Delete group.
    """
    container = _container_dn
    filter_class = _default_class

    def execute(self, cn, **kw):
        """
        Delete a group

        The memberOf plugin handles removing the group from any other
        groups.

        :param cn: The name of the group being removed
        :param kw: Unused
        """
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        ldap = self.api.Backend.ldap2
        dn = get_dn_by_attr(ldap, 'cn', cn, self.filter_class, self.container)

        # Don't allow the default user group to be removed
        try:
            config = ldap.get_ipa_config()[1]
            def_group_cn = config.get('ipaDefaultPrimaryGroup')
            def_group_dn = get_dn_by_attr(
                ldap, 'cn', def_group_cn, self.filter_class, self.container
            )
            if dn == def_group_dn:
                raise errors.DefaultGroup()
        except errors.NotFound:
            pass

        return super(group2_delete, self).execute(cn, **kw)

api.register(group2_delete)


class group2_mod(basegroup2_mod):
    """
    Modify group.
    """
    container = _container_dn
    filter_class = _default_class

    takes_options = (
        Flag('posix',
             cli_name='posix',
             doc='change to posix group',
        ),
    )
    def execute(self, cn, **kw):
        """
        Execute the group-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param cn: The name of the group to update.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'cn' not in kw
        assert 'dn' not in kw
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        ldap = self.api.Backend.ldap2

        if kw['posix'] or 'gidnumber' in kw:
            dn = get_dn_by_attr(ldap, 'cn', cn, self.filter_class, self.container)
            (dn, entry_attrs) = ldap.get_entry(dn, ['objectClass'])
            if kw['posix'] and 'posixGroup' in entry_attrs['objectClass']:
                raise errors.AlreadyPosixGroup()
            else:
                entry_attrs['objectClass'].append('posixGroup')
                kw['objectclass'] = entry_attrs['objectClass']

        return super(group2_mod, self).execute(cn, **kw)

api.register(group2_mod)


class group2_find(basegroup2_find):
    """
    Search for groups.
    """
    default_attributes = _default_attributes
    container = _container_dn
    filter_class = _default_class

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(group2_find, self).execute(cn, **kw)

api.register(group2_find)


class group2_show(basegroup2_show):
    """
    Display group.
    """
    default_attributes = _default_attributes
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(group2_show, self).execute(cn, **kw)

api.register(group2_show)


class group2_add_member(basegroup2_add_member):
    """
    Add members to group.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(group2_add_member, self).execute(cn, **kw)

api.register(group2_add_member)


class group2_del_member(basegroup2_del_member):
    """
    Remove members from group.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(group2_del_member, self).execute(cn, **kw)

api.register(group2_del_member)

