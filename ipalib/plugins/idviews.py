# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from ipalib.plugins.baseldap import (LDAPObject, LDAPCreate,
                                     LDAPDelete, LDAPUpdate, LDAPSearch,
                                     LDAPRetrieve)
from ipalib import api, Str, Int, _, ngettext
from ipalib.plugable import Registry


__doc__ = _("""
ID views
Manage ID views
IPA allows to override certain properties of users and groups per each host.
This functionality is primarily used to allow migration from older systems or
other Identity Management solutions.
""")

register = Registry()


@register()
class idview(LDAPObject):
    """
    ID view object.
    """

    container_dn = api.env.container_views
    object_name = _('ID view')
    object_name_plural = _('ID views')
    object_class = ['ipaIDView', 'top']
    default_attributes = ['cn', 'description']
    rdn_is_primary_key = True

    label = _('ID views')
    label_singular = _('ID view')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('ID View Name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
    )

    permission_filter_objectclasses = ['nsContainer']
    managed_permissions = {
        'System: Read ID Views': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'description', 'objectClass',
            },
        },
    }


@register()
class idview_add(LDAPCreate):
    __doc__ = _('Add a new ID View.')
    msg_summary = _('Added ID view "%(value)s"')


@register()
class idview_del(LDAPDelete):
    __doc__ = _('Delete an ID view.')
    msg_summary = _('Deleted ID view "%(value)s"')


@register()
class idview_mod(LDAPUpdate):
    __doc__ = _('Modify an ID view.')
    msg_summary = _('Modified an ID view "%(value)s"')


@register()
class idview_find(LDAPSearch):
    __doc__ = _('Search for an ID view.')
    msg_summary = ngettext('%(count)d ID view matched',
                           '%(count)d ID views matched', 0)


@register()
class idview_show(LDAPRetrieve):
    __doc__ = _('Display information about an ID view.')


@register()
class idoverride(LDAPObject):
    """
    ID override object.
    """

    parent_object = 'idview'
    container_dn = api.env.container_views

    object_name = _('ID override')
    object_name_plural = _('ID overrides')
    object_class = ['ipaOverrideAnchor', 'top']
    default_attributes = [
        'cn', 'description', 'ipaAnchorUUID', 'gidNumber',
        'homeDirectory', 'uidNumber', 'uid',
    ]

    label = _('ID overrides')
    label_singular = _('ID override')
    rdn_is_primary_key = True

    takes_params = (
        Str('ipaanchoruuid',
            cli_name='anchor',
            primary_key=True,
            label=_('Anchor to override'),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
        ),
        Str('cn?',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='group_name',
            label=_('Group name'),
            normalizer=lambda value: value.lower(),
        ),
        Int('gidnumber?',
            cli_name='gid',
            label=_('GID'),
            doc=_('Group ID Number'),
            minvalue=1,
        ),
        Str('uid?',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='login',
            label=_('User login'),
            normalizer=lambda value: value.lower(),
        ),
        Int('uidnumber?',
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number'),
            minvalue=1,
        ),
        Str('homedirectory?',
            cli_name='homedir',
            label=_('Home directory'),
        ),
    )

    permission_filter_objectclasses = ['ipaOverrideAnchor']
    managed_permissions = {
        'System: Read ID Overrides': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectClass', 'ipaAnchorUUID', 'uidNumber', 'gidNumber',
                'description', 'homeDirectory', 'uid',
            },
        },
    }


@register()
class idoverride_add(LDAPCreate):
    __doc__ = _('Add a new ID override.')
    msg_summary = _('Added ID override "%(value)s"')


@register()
class idoverride_del(LDAPDelete):
    __doc__ = _('Delete an ID override.')
    msg_summary = _('Deleted ID override "%(value)s"')


@register()
class idoverride_mod(LDAPUpdate):
    __doc__ = _('Modify an ID override.')
    msg_summary = _('Modified an ID override "%(value)s"')


@register()
class idoverride_find(LDAPSearch):
    __doc__ = _('Search for an ID override.')
    msg_summary = ngettext('%(count)d ID override matched',
                           '%(count)d ID overrides matched', 0)


@register()
class idoverride_show(LDAPRetrieve):
    __doc__ = _('Display information about an ID override.')
