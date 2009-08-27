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
from ipalib import Int, Str
from ipalib.plugins.baseldap import *


class group(LDAPObject):
    """
    Group object.
    """
    container_dn = api.env.container_group
    object_name = 'group'
    object_name_plural = 'groups'
    object_class = ['ipausergroup']
    object_class_config = 'ipagroupobjectclasses'
    default_attributes = ['cn', 'description', 'gidnumber', 'memberof']
    uuid_attribute = 'ipauniqueid'
    attribute_names = {
        'cn': 'name',
        'gidnumber': 'group id',
        'member user': 'member users',
        'member group': 'member groups',
        'memberof group': 'member of groups',
        'memberof netgroup': 'member of netgroups',
        'memberof rolegroup': 'member of rolegroup',
        'memberof taskgroup': 'member of taskgroup',
    }
    attribute_members = {
        'member': ['user', 'group'],
        'memberof': ['group', 'netgroup', 'rolegroup', 'taskgroup'],
    }

    takes_params = (
        Str('cn',
            cli_name='name',
            doc='group name',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            doc='group description',
        ),
        Int('gidnumber?',
            cli_name='gid',
            doc='GID (use this option to set it manually)',
        ),
    )

api.register(group)


class group_add(LDAPCreate):
    """
    Create new group.
    """
    takes_options = LDAPCreate.takes_options + (
        Flag('posix',
             cli_name='posix',
             doc='create as posix group?',
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if options['posix'] or 'gidnumber' in options:
            options['objectclass'].append('posixgroup')
        return dn

api.register(group_add)


class group_del(LDAPDelete):
    """
    Delete group.
    """
    def pre_callback(self, ldap, dn, *keys, **options):
        config = ldap.get_ipa_config()[1]
        def_primary_group = config.get('ipadefaultprimarygroup', '')
        def_primary_group_dn = group_dn = self.obj.get_dn(def_primary_group)
        if dn == def_primary_group_dn:
            raise errors.DefaultGroup()
        return dn

api.register(group_del)


class group_mod(LDAPUpdate):
    """
    Modify group.
    """
    takes_options = LDAPUpdate.takes_options + (
        Flag('posix',
             cli_name='posix',
             doc='change to posix group',
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if options['posix'] or 'gidnumber' in options:
            (dn, old_entry_attrs) = ldap.get_entry(dn, ['objectclass'])
            if 'posixgroup' in old_entry_attrs['objectclass']:
                if options['posix']:
                    raise errors.AlreadyPosixGroup()
            else:
                old_entry_attrs['objectclass'].append('posixgroup')
                entry_attrs['objectclass'] = old_entry_attrs['objectclass']
        return dn

api.register(group_mod)


class group_find(LDAPSearch):
    """
    Search for groups.
    """

api.register(group_find)


class group_show(LDAPRetrieve):
    """
    Display group.
    """

api.register(group_show)


class group_add_member(LDAPAddMember):
    """
    Add members to group.
    """

api.register(group_add_member)


class group_remove_member(LDAPRemoveMember):
    """
    Remove members from group.
    """

api.register(group_remove_member)

