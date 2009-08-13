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
Groups of users
"""

from ipalib import api
from ipalib.plugins.basegroup import *

_container_dn = api.env.container_group
_default_attributes = ['cn', 'description', 'gidnumber', 'member', 'memberof']
_default_class = 'ipausergroup'


class group(basegroup):
    """
    Group object.
    """
    container = _container_dn

    takes_params = basegroup.takes_params + (
        Int('gidnumber?',
            cli_name='gid',
            doc='GID (use this option to set it manually)',
        ),
    )

api.register(group)


class group_add(basegroup_add):
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
        ldap = self.api.Backend.ldap2

        config = ldap.get_ipa_config()[1]

        kw['objectclass'] = config.get('ipagroupobjectclasses')
        if kw['posix'] or 'gidnumber' in kw:
            kw['objectclass'].append('posixgroup')

        return super(group_add, self).execute(cn, **kw)

api.register(group_add)


class group_del(basegroup_del):
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
        ldap = self.api.Backend.ldap2
        (dn, entry_attrs) = ldap.find_entry_by_attr(
            'cn', cn, self.filter_class, [''], self.container
        )

        # Don't allow the default user group to be removed
        try:
            config = ldap.get_ipa_config()[1]
            def_group_cn = config.get('ipadefaultprimarygroup')
            (def_group_dn, entry_attrs) = ldap.find_entry_by_attr(
                'cn', def_group_cn, self.filter_class, [''], self.container
            )
            if dn == def_group_dn:
                raise errors.DefaultGroupError()
        except errors.NotFound:
            pass

        return super(group_del, self).execute(cn, **kw)

api.register(group_del)


class group_mod(basegroup_mod):
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
        ldap = self.api.Backend.ldap2

        if kw['posix'] or 'gidnumber' in kw:
            (dn, entry_attrs) = ldap.find_entry_by_attr(
                'cn', cn, self.filter_class, ['objectclass'], self.container
            )
            if 'posixgroup' in entry_attrs['objectclass']:
                if kw['posix'] in entry_attrs['objectclass']:
                    raise errors.AlreadyPosixGroup()
            else:
                entry_attrs['objectclass'].append('posixgroup')
                kw['objectclass'] = entry_attrs['objectclass']

        return super(group_mod, self).execute(cn, **kw)

api.register(group_mod)


class group_find(basegroup_find):
    """
    Search for groups.
    """
    default_attributes = _default_attributes
    container = _container_dn
    filter_class = _default_class

    def execute(self, term, **kw):
        return super(group_find, self).execute(term, **kw)

api.register(group_find)


class group_show(basegroup_show):
    """
    Display group.
    """
    default_attributes = _default_attributes
    container = _container_dn

    def execute(self, cn, **kw):
        return super(group_show, self).execute(cn, **kw)

api.register(group_show)


class group_add_member(basegroup_add_member):
    """
    Add members to group.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        return super(group_add_member, self).execute(cn, **kw)

api.register(group_add_member)


class group_remove_member(basegroup_remove_member):
    """
    Remove members from group.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        return super(group_remove_member, self).execute(cn, **kw)

api.register(group_remove_member)

