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

import platform
import os
import sys

from ipalib import api, errors, util
from ipalib import Str
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext

__doc__ = _("""
Sudo Commands

Commands used as building blocks for sudo

EXAMPLES:

 Create a new command
   ipa sudocmd-add --desc='For reading log files' /usr/bin/less

 Remove a command
   ipa sudocmd-del /usr/bin/less

""")

topic = ('sudo', _('commands for controlling sudo configuration'))

class sudocmd(LDAPObject):
    """
    Sudo Command object.
    """
    container_dn = api.env.container_sudocmd
    object_name = _('sudo command')
    object_name_plural = _('sudo commands')
    object_class = ['ipaobject', 'ipasudocmd']
    # object_class_config = 'ipahostobjectclasses'
    search_attributes = [
        'sudocmd', 'description',
    ]
    default_attributes = [
        'sudocmd', 'description', 'memberof',
    ]
    attribute_members = {
        'memberof': ['sudocmdgroup'],
    }
    uuid_attribute = 'ipauniqueid'
    label = _('Sudo Commands')
    label_singular = _('Sudo Command')

    takes_params = (
        Str('sudocmd',
            cli_name='command',
            label=_('Sudo Command'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this command'),
        ),
    )

    def get_dn(self, *keys, **options):
        if keys[-1].endswith('.'):
            keys[-1] = keys[-1][:-1]
        dn = super(sudocmd, self).get_dn(*keys, **options)
        try:
            self.backend.get_entry(dn, [''])
        except errors.NotFound:
            try:
                (dn, entry_attrs) = self.backend.find_entry_by_attr(
                    'sudocmd', keys[-1], self.object_class, [''],
                    self.container_dn
                )
            except errors.NotFound:
                pass
        return dn

api.register(sudocmd)

class sudocmd_add(LDAPCreate):
    __doc__ = _('Create new Sudo Command.')

    msg_summary = _('Added Sudo Command "%(value)s"')

api.register(sudocmd_add)

class sudocmd_del(LDAPDelete):
    __doc__ = _('Delete Sudo Command.')

    msg_summary = _('Deleted Sudo Command "%(value)s"')

api.register(sudocmd_del)

class sudocmd_mod(LDAPUpdate):
    __doc__ = _('Modify Sudo Command.')

    msg_summary = _('Modified Sudo Command "%(value)s"')

api.register(sudocmd_mod)

class sudocmd_find(LDAPSearch):
    __doc__ = _('Search for Sudo Commands.')

    msg_summary = ngettext(
        '%(count)d Sudo Command matched', '%(count)d Sudo Commands matched', 0
    )

api.register(sudocmd_find)

class sudocmd_show(LDAPRetrieve):
    __doc__ = _('Display Sudo Command.')

api.register(sudocmd_show)
