# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
#
# Copyright (C) 2010  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Groups of Sudo commands

Manage groups of Sudo commands.

EXAMPLES:

 Add a new Sudo command group:
   ipa sudocmdgroup-add --desc='administrators commands' admincmds

 Remove a Sudo command group:
   ipa sudocmdgroup-del admincmds

 Manage Sudo command group membership, commands:
   ipa sudocmdgroup-add-member --sudocmds=/usr/bin/less,/usr/bin/vim admincmds

 Manage Sudo command group membership, commands:
   ipa group-remove-member --sudocmds=/usr/bin/less admincmds

 Show a Sudo command group:
   ipa group-show localadmins
"""

from ipalib import api
from ipalib import Str
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext

topic = ('sudo', 'commands for controlling sudo configuration')

class sudocmdgroup(LDAPObject):
    """
    Sudo Group object.
    """
    container_dn = api.env.container_sudocmdgroup
    object_name = 'sudo command group'
    object_name_plural = 'sudo command groups'
    object_class = ['ipaobject', 'ipasudocmdgrp']
    default_attributes = [
        'cn', 'description', 'member',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['sudocmd'],
    }

    label = _('Sudo Command Groups')
    label_singular = _('sudo command group')

    takes_params = (
        Str('cn',
            cli_name='sudocmdgroup_name',
            label=_('Sudo Command Group'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('Group description'),
        ),
        Str('membercmd_sudocmd?',
            label=_('Commands'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('membercmd_sudocmdgroup?',
            label=_('Sudo Command Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

api.register(sudocmdgroup)


class sudocmdgroup_add(LDAPCreate):
    """
    Create new sudo command group.
    """

    msg_summary = _('Added sudo command group "%(value)s"')

api.register(sudocmdgroup_add)


class sudocmdgroup_del(LDAPDelete):
    """
    Delete sudo command group.
    """

    msg_summary = _('Deleted sudo command group "%(value)s"')

api.register(sudocmdgroup_del)


class sudocmdgroup_mod(LDAPUpdate):
    """
    Modify group.
    """

    msg_summary = _('Modified sudo command group "%(value)s"')

api.register(sudocmdgroup_mod)


class sudocmdgroup_find(LDAPSearch):
    """
    Search for sudo command groups.
    """

    msg_summary = ngettext(
        '%(count)d sudo command group matched',
        '%(count)d sudo command groups matched', 0
    )

api.register(sudocmdgroup_find)


class sudocmdgroup_show(LDAPRetrieve):
    """
    Display sudo command group.
    """

api.register(sudocmdgroup_show)


class sudocmdgroup_add_member(LDAPAddMember):
    """
    Add members to sudo command group.
    """

api.register(sudocmdgroup_add_member)


class sudocmdgroup_remove_member(LDAPRemoveMember):
    """
    Remove members from sudo command group.
    """

api.register(sudocmdgroup_remove_member)
