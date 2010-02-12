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

from ipalib.plugins.baseldap import *
from ipalib import api, _, ngettext



class taskgroup(LDAPObject):
    """
    Taskgroup object.
    """
    container_dn = api.env.container_taskgroup
    object_name = 'taskgroup'
    object_name_plural = 'taskgroups'
    object_class = ['groupofnames']
    default_attributes = ['cn', 'description', 'member', 'memberof']
    attribute_names = {
        'cn': 'name',
        'member_user': 'member users',
        'member_group': 'member groups',
        'member_rolegroup': 'member rolegroups',
        # FIXME: 'memberof ???': 'member of ???'
    }
    attribute_members = {
        'member': ['user', 'group', 'rolegroup'],
        # FIXME: taskgroup can be member of ???
    }

    label = _('Task Groups')

    takes_params = (
        Str('cn',
            cli_name='name',
            label='Taskgroup name',
            doc='taskgroup name',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label='Description',
            doc='taskgroup description',
        ),
        Str('member_group?',
            label='Member Groups',
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member_user?',
            label='Member Users',
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member_rolegroup?',
            label='Member Role Groups',
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

api.register(taskgroup)


class taskgroup_add(LDAPCreate):
    """
    Create new taskgroup.
    """

    msg_summary = _('Added taskgroup "%(value)s"')

api.register(taskgroup_add)


class taskgroup_del(LDAPDelete):
    """
    Delete taskgroup.
    """

    msg_summary = _('Deleted taskgroup "%(value)s"')

api.register(taskgroup_del)


class taskgroup_mod(LDAPUpdate):
    """
    Modify taskgroup.
    """

    msg_summary = _('Modified taskgroup "%(value)s"')

api.register(taskgroup_mod)


class taskgroup_find(LDAPSearch):
    """
    Search for taskgroups.
    """

    msg_summary = ngettext(
        '%(count)d taskgroup matched', '%(count)d taskgroups matched'
    )

api.register(taskgroup_find)


class taskgroup_show(LDAPRetrieve):
    """
    Display taskgroup.
    """

api.register(taskgroup_show)


class taskgroup_add_member(LDAPAddMember):
    """
    Add member to taskgroup.
    """

api.register(taskgroup_add_member)


class taskgroup_remove_member(LDAPRemoveMember):
    """
    Remove member from taskgroup.
    """

api.register(taskgroup_remove_member)
