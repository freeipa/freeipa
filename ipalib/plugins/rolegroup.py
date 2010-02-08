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
    attribute_names = {
        'cn': 'name',
        'member user': 'member users',
        'member group': 'member groups',
        'member host': 'member hosts',
        'member hostgroup': 'member hostgroups',
        'memberof taskgroup': 'member of taskgroup',
    }
    attribute_members = {
        'member': ['user', 'group', 'host', 'hostgroup'],
        'memberof': ['taskgroup'],
    }

    label = _('Role Groups')

    takes_params = (
        Str('cn',
            cli_name='name',
            label='Name',
            doc='rolegroup name',
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label='Description',
            doc='A description of this rolegroup',
        ),
    )

api.register(rolegroup)


class rolegroup_add(LDAPCreate):
    """
    Create new rolegroup.
    """

    msg_summary = _('Added rolegroup "%(value)s"')

api.register(rolegroup_add)


class rolegroup_del(LDAPDelete):
    """
    Delete rolegroup.
    """

    msg_summary = _('Deleted rolegroup "%(value)s"')

api.register(rolegroup_del)


class rolegroup_mod(LDAPUpdate):
    """
    Edit rolegroup.
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
    Display rolegroup.
    """

api.register(rolegroup_show)


class rolegroup_add_member(LDAPAddMember):
    """
    Add member to rolegroup.
    """

api.register(rolegroup_add_member)


class rolegroup_remove_member(LDAPRemoveMember):
    """
    Remove member from rolegroup.
    """

api.register(rolegroup_remove_member)
