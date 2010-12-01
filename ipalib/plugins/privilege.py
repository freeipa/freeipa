# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Privileges

A privilege enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to privileges to perform
given tasks such as adding a user, modifying a group, etc.

A privilege may not be members of other privileges.

See role and permission for additional information.
"""

from ipalib.plugins.baseldap import *
from ipalib import api, _, ngettext


class privilege(LDAPObject):
    """
    Privilege object.
    """
    container_dn = api.env.container_privilege
    object_name = 'privilege'
    object_name_plural = 'privileges'
    object_class = ['nestedgroup', 'groupofnames']
    default_attributes = ['cn', 'description', 'member', 'memberof',
        'memberindirect'
    ]
    attribute_members = {
        'member': ['permission', 'role'],
        'memberof': ['permission'],
#        'memberindirect': ['permission'],
        # FIXME: privilege can be member of ???
    }
    reverse_members = {
        'member': ['permission'],
    }
    rdnattr='cn'

    label = _('Privileges')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Privilege name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('Privilege description'),
        ),
    )

api.register(privilege)


class privilege_add(LDAPCreate):
    """
    Add a new privilege.
    """

    msg_summary = _('Added privilege "%(value)s"')

api.register(privilege_add)


class privilege_del(LDAPDelete):
    """
    Delete a privilege.
    """

    msg_summary = _('Deleted privilege "%(value)s"')

api.register(privilege_del)


class privilege_mod(LDAPUpdate):
    """
    Modify a privilege.
    """

    msg_summary = _('Modified privilege "%(value)s"')

api.register(privilege_mod)


class privilege_find(LDAPSearch):
    """
    Search for privileges.
    """

    msg_summary = ngettext(
        '%(count)d privilege matched', '%(count)d privileges matched'
    )

api.register(privilege_find)


class privilege_show(LDAPRetrieve):
    """
    Display information about a privilege.
    """

api.register(privilege_show)


class privilege_add_member(LDAPAddMember):
    """
    Add members to a privilege
    """
    INTERNAL=True

api.register(privilege_add_member)


class privilege_remove_member(LDAPRemoveMember):
    """
    Remove members from a privilege
    """
    INTERNAL=True

api.register(privilege_remove_member)


class privilege_add_permission(LDAPAddReverseMember):
    """
    Add permissions to a privilege.
    """
    show_command = 'privilege_show'
    member_command = 'permission_add_member'
    reverse_attr = 'permission'
    member_attr = 'privilege'

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of permissions added'),
        ),
    )

api.register(privilege_add_permission)


class privilege_remove_permission(LDAPRemoveReverseMember):
    """
    Remove permissions from a privilege.
    """
    show_command = 'privilege_show'
    member_command = 'permission_remove_member'
    reverse_attr = 'permission'
    member_attr = 'privilege'

    permission_count_out = ('%i permission removed.', '%i permissions removed.')

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of permissions removed'),
        ),
    )

api.register(privilege_remove_permission)
