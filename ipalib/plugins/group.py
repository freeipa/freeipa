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

Manage groups of users. By default new groups are not Posix groups.
You can mark it as Posix at creation time with the --posix flag and
can promose a non-Posix group using the --posix flag in group-mod.
Once a group is a Posix group there is no way to undo this.

Every group must have a description.

Posix groups must have a group id number (gid). Changing a gid is
supported but can have impact on your file permissions.

EXAMPLES:

 Add a new group:
   ipa group-add --desc='local administrators' localadmins

 Add a new posix group:
   ipa group-add --posix --desc='remote administrators' remoteadmins

 Promote a non-posix group to posix:
   ipa group-mod --posix localadmins

 Create a group with a specific group ID number"
   ipa group-add --posix --gid=500 --desc='unix admins' unixadmins

 Remove a group:
   ipa group-del unixadmins

 Manage group membership, nested groups:
   ipa group-add-member --groups=remoteadmins localadmins

 Manage group membership, users:
   ipa group-add-member --users=test1,test2 localadmins

 Manage group membership, users:
   ipa group-remove-member --users=test2 localadmins

 Show a group:
   ipa group-show localadmins
"""

from ipalib import api
from ipalib import Int, Str
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext


class group(LDAPObject):
    """
    Group object.
    """
    container_dn = api.env.container_group
    object_name = 'group'
    object_name_plural = 'groups'
    object_class = ['ipausergroup']
    object_class_config = 'ipagroupobjectclasses'
    default_attributes = [
        'cn', 'description', 'gidnumber', 'member', 'memberof'
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['user', 'group'],
        'memberof': ['group', 'netgroup', 'rolegroup', 'taskgroup'],
    }

    label = _('User Groups')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Group name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('Group description'),
        ),
        Int('gidnumber?',
            cli_name='gid',
            label=_('GID'),
            doc=_('GID (use this option to set it manually)'),
        ),
        Str('member_group?',
            label=_('Member groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member_user?',
            label=_('Member users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member?',
            label=_('Failed members'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('user?',
            label=_('Users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('group?',
            label=_('Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

api.register(group)


class group_add(LDAPCreate):
    """
    Create new group.
    """

    msg_summary = _('Added group "%(value)s"')

    takes_options = LDAPCreate.takes_options + (
        Flag('posix',
             cli_name='posix',
             doc=_('Create as posix group?'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if options['posix'] or 'gidnumber' in options:
            entry_attrs['objectclass'].append('posixgroup')
        return dn


api.register(group_add)


class group_del(LDAPDelete):
    """
    Delete group.
    """

    msg_summary = _('Deleted group "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        config = ldap.get_ipa_config()[1]
        def_primary_group = config.get('ipadefaultprimarygroup', '')
        def_primary_group_dn = group_dn = self.obj.get_dn(def_primary_group)
        if dn == def_primary_group_dn:
            raise errors.DefaultGroup()
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        try:
            api.Command['pwpolicy_del'](keys[-1])
        except errors.NotFound:
            pass

        return True

api.register(group_del)


class group_mod(LDAPUpdate):
    """
    Modify group.
    """

    msg_summary = _('Modified group "%(value)s"')

    takes_options = LDAPUpdate.takes_options + (
        Flag('posix',
             cli_name='posix',
             doc=_('change to posix group'),
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

    msg_summary = ngettext(
        '%(count)d group matched', '%(count)d groups matched', 0
    )

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
