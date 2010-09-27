# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
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
Sudo Rule
"""

from ipalib import api, errors
from ipalib import Str, StrEnum
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext

class sudorule(LDAPObject):
    """
    Sudo Rule.
    """
    container_dn = api.env.container_sudorule
    object_name = 'Sudo Rule'
    object_name_plural = 'Sudo Rules'
    object_class = ['ipaassociation', 'ipasudorule']
    default_attributes = [
        'cn', 'accessruletype', 'description',

    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
        'membercmd': ['sudocmd', 'sudocmdgroup'],
    }

    label = _('SudoRule')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Rule name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
        StrEnum('accessruletype',
            cli_name='type',
            doc=_('Rule type (allow or deny)'),
            label=_('Rule type'),
            values=(u'allow', u'deny'),
        ),
            Str('memberuser_user?',
            label=_('Users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_host?',
            label=_('Hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_hostgroup?',
            label=_('Host Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('membercmd_sudocmd?',
            label=_('Sudo Commands'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('membercmd_sudocmdgroup?',
            label=_('Sudo Command Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

    def get_dn(self, *keys, **kwargs):
        try:
            (dn, entry_attrs) = self.backend.find_entry_by_attr(
                self.primary_key.name, keys[-1], self.object_class, [''],
                self.container_dn
            )
        except errors.NotFound:
            dn = super(sudorule, self).get_dn(*keys, **kwargs)
        return dn

api.register(sudorule)


class sudorule_add(LDAPCreate):
    """
    Create new Sudo Rule.
    """

    msg_summary = _('Added sudo rule "%(value)s"')

api.register(sudorule_add)


class sudorule_del(LDAPDelete):
    """
    Delete Sudo Rule.
    """

api.register(sudorule_del)


class sudorule_mod(LDAPUpdate):
    """
    Modify Sudo Rule.
    """

api.register(sudorule_mod)


class sudorule_find(LDAPSearch):
    """
    Search for Sudo Rule.
    """

api.register(sudorule_find)


class sudorule_show(LDAPRetrieve):
    """
    Dispaly Sudo Rule.
    """

api.register(sudorule_show)


class sudorule_add_command(LDAPAddMember):
    """
    Add commands and sudo command groups affected by Sudo Rule.
    """
    member_attributes = ['membercmd']
    member_count_out = ('%i object added.', '%i objects added.')

api.register(sudorule_add_command)


class sudorule_remove_command(LDAPRemoveMember):
    """
    Remove commands and sudo command groups affected by Sudo Rule.
    """
    member_attributes = ['membercmd']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(sudorule_remove_command)


class sudorule_add_user(LDAPAddMember):
    """
    Add users and groups affected by Sudo Rule.
    """
    member_attributes = ['memberuser']
    member_count_out = ('%i object added.', '%i objects added.')

api.register(sudorule_add_user)


class sudorule_remove_user(LDAPRemoveMember):
    """
    Remove users and groups affected by Sudo Rule.
    """
    member_attributes = ['memberuser']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(sudorule_remove_user)


class sudorule_add_host(LDAPAddMember):
    """
    Add hosts and hostgroups affected by Sudo Rule.
    """
    member_attributes = ['memberhost']
    member_count_out = ('%i object added.', '%i objects added.')

api.register(sudorule_add_host)


class sudorule_remove_host(LDAPRemoveMember):
    """
    Remove hosts and hostgroups affected by Sudo Rule.
    """
    member_attributes = ['memberhost']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(sudorule_remove_host)
