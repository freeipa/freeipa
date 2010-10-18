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
Rolegroups

A rolegroup is used for fine-grained delegation. Access control rules
(ACIs) grant permission to perform given tasks (add a user, modify a group,
etc.), to task groups. Rolegroups are members of taskgroups, giving them
permission to perform the task.

The logic behind ACIs and rolegroups proceeds as follows:

 ACIs grants permission to taskgroup
 rolegroups are members of taskgroups
 users, groups, hosts and hostgroups are members of rolegroups

Rolegroups can contain both hosts and hostgroups, enabling
operations using the host service principal associated with a machine.

Rolegroups can not contain other rolegroups.

EXAMPLES:

 Add a new rolegroup:
   ipa rolegroup-add --desc="Junior-level admin" junioradmin

 Add this role to some tasks:
   ipa taskgroup-add-member --rolegroups=junioradmin addusers
   ipa taskgroup-add-member --rolegroups=junioradmin change_password
   ipa taskgroup-add-member --rolegroups=junioradmin add_user_to_default_group

 Yes, this can seem backwards. The taskgroup is the entry that is granted
 permissions by the ACIs. By adding a rolegroup as a member of a taskgroup
 it inherits those permissions.

 Add a group of users to this role:
   ipa group-add --desc="User admins" useradmins
   ipa rolegroup-add-member --groups=useradmins junioradmin

 Display information about a rolegroup:
   ipa rolegroup-show junioradmin
"""

from ipalib.plugins.baseldap import *
from ipalib import api, Str, _, ngettext


class rolegroup(LDAPObject):
    """
    Rolegroup object.
    """
    container_dn = api.env.container_rolegroup
    object_name = 'rolegroup'
    object_name_plural = 'rolegroups'
    object_class = ['groupofnames', 'nestedgroup']
    default_attributes = ['cn', 'description', 'member', 'memberof']
    attribute_members = {
        'member': ['user', 'group', 'host', 'hostgroup'],
        'memberof': ['taskgroup'],
    }
    rdnattr='cn'

    label = _('Role Groups')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Role-group name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this role-group'),
        ),
        Str('member_group?',
            label=_('Member groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member_user?',
            label=_('Member users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberof_taskgroup?',
            label=_('Member of task-groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

api.register(rolegroup)


class rolegroup_add(LDAPCreate):
    """
    Add a new rolegroup.
    """

    msg_summary = _('Added rolegroup "%(value)s"')

api.register(rolegroup_add)


class rolegroup_del(LDAPDelete):
    """
    Delete a rolegroup.
    """

    msg_summary = _('Deleted rolegroup "%(value)s"')

api.register(rolegroup_del)


class rolegroup_mod(LDAPUpdate):
    """
    Modify a rolegroup.
    """

    msg_summary = _('Modified rolegroup "%(value)s"')

api.register(rolegroup_mod)


class rolegroup_find(LDAPSearch):
    """
    Search for rolegroups.
    """

    msg_summary = ngettext(
        '%(count)d rolegroup matched', '%(count)d rolegroups matched'
    )

api.register(rolegroup_find)


class rolegroup_show(LDAPRetrieve):
    """
    Display information about a rolegroup.
    """

api.register(rolegroup_show)


class rolegroup_add_member(LDAPAddMember):
    """
    Add members to a rolegroup.
    """

api.register(rolegroup_add_member)


class rolegroup_remove_member(LDAPRemoveMember):
    """
    Remove members from a rolegroup.
    """

api.register(rolegroup_remove_member)
