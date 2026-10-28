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

from ipalib import api
from ipalib import Str
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPAddMember,
    LDAPRemoveMember)
from ipalib import _, ngettext

__doc__ = _("""
Groups of Sudo Commands

Manage groups of Sudo Commands.

EXAMPLES:

 Add a new Sudo Command Group:
   ipa sudocmdgroup-add --desc='administrators commands' admincmds

 Remove a Sudo Command Group:
   ipa sudocmdgroup-del admincmds

 Manage Sudo Command Group membership, commands:
   ipa sudocmdgroup-add-member --sudocmds=/usr/bin/less --sudocmds=/usr/bin/vim admincmds

 Manage Sudo Command Group membership, commands:
   ipa sudocmdgroup-remove-member --sudocmds=/usr/bin/less admincmds

 Show a Sudo Command Group:
   ipa sudocmdgroup-show admincmds
""")

register = Registry()

topic = 'sudo'

@register()
class sudocmdgroup(LDAPObject):
    """
    Sudo Command Group object.
    """
    container_dn = api.env.container_sudocmdgroup
    object_name = _('sudo command group')
    object_name_plural = _('sudo command groups')
    object_class = ['ipaobject', 'ipasudocmdgrp']
    permission_filter_objectclasses = ['ipasudocmdgrp']
    default_attributes = [
        'cn', 'description', 'member',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['sudocmd'],
    }
    managed_permissions = {
        'System: Read Sudo Command Groups': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'businesscategory', 'cn', 'description', 'ipauniqueid',
                'member', 'o', 'objectclass', 'ou', 'owner', 'seealso',
                'memberuser', 'memberhost',
            },
        },
        'System: Add Sudo Command Group': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=sudocmdgroups,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Add Sudo command group";allow (add) groupdn = "ldap:///cn=Add Sudo command group,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
        'System: Delete Sudo Command Group': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=sudocmdgroups,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Delete Sudo command group";allow (delete) groupdn = "ldap:///cn=Delete Sudo command group,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
        'System: Modify Sudo Command Group': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'description'},
            'default_privileges': {'Sudo Administrator'},
        },
        'System: Manage Sudo Command Group Membership': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'member'},
            'replaces': [
                '(targetattr = "member")(target = "ldap:///cn=*,cn=sudocmdgroups,cn=sudo,$SUFFIX")(version 3.0;acl "permission:Manage Sudo command group membership";allow (write) groupdn = "ldap:///cn=Manage Sudo command group membership,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Sudo Administrator'},
        },
    }

    label = _('Sudo Command Groups')
    label_singular = _('Sudo Command Group')

    takes_params = (
        Str('cn',
            cli_name='sudocmdgroup_name',
            label=_('Sudo Command Group'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
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



@register()
class sudocmdgroup_add(LDAPCreate):
    __doc__ = _('Create new Sudo Command Group.')

    msg_summary = _('Added Sudo Command Group "%(value)s"')



@register()
class sudocmdgroup_del(LDAPDelete):
    __doc__ = _('Delete Sudo Command Group.')

    msg_summary = _('Deleted Sudo Command Group "%(value)s"')



@register()
class sudocmdgroup_mod(LDAPUpdate):
    __doc__ = _('Modify Sudo Command Group.')

    msg_summary = _('Modified Sudo Command Group "%(value)s"')



@register()
class sudocmdgroup_find(LDAPSearch):
    __doc__ = _('Search for Sudo Command Groups.')

    msg_summary = ngettext(
        '%(count)d Sudo Command Group matched',
        '%(count)d Sudo Command Groups matched', 0
    )



@register()
class sudocmdgroup_show(LDAPRetrieve):
    __doc__ = _('Display Sudo Command Group.')



@register()
class sudocmdgroup_add_member(LDAPAddMember):
    __doc__ = _('Add members to Sudo Command Group.')



@register()
class sudocmdgroup_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from Sudo Command Group.')
