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
Groups of hosts.
"""

from ipalib.plugins.baseldap import *
from ipalib import api, Int, _, ngettext


class hostgroup(LDAPObject):
    """
    Hostgroup object.
    """
    container_dn = api.env.container_hostgroup
    object_name = 'hostgroup'
    object_name_plurals = 'hostgroups'
    object_class = ['ipaobject', 'ipahostgroup']
    default_attributes = ['cn', 'description', 'member', 'memberof']
    uuid_attribute = 'ipauniqueid'
    attribute_names = {
        'cn': 'names',
        'member_host': 'member hosts',
        'member_hostgroup': 'member hostgroups',
        'memberof_hostgroup': 'member of hostgroup',
    }
    attribute_members = {
        'member': ['host', 'hostgroup'],
        'memberof': ['hostgroup'],
    }

    label = _('Host Groups')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host-group'),
        ),
        Str('member_host?',
            label=_('Member hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('member_hostgroup?',
            label=_('Member host-groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberof_hostgroup?',
            label=_('Member of host-groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

api.register(hostgroup)


class hostgroup_add(LDAPCreate):
    """
    Create new hostgroup.
    """

    msg_summary = _('Added hostgroup "%(value)s"')

api.register(hostgroup_add)


class hostgroup_del(LDAPDelete):
    """
    Delete hostgroup.
    """

    msg_summary = _('Deleted hostgroup "%(value)s"')

api.register(hostgroup_del)


class hostgroup_mod(LDAPUpdate):
    """
    Modify hostgroup.
    """

    msg_summary = _('Modified hostgroup "%(value)s"')

api.register(hostgroup_mod)


class hostgroup_find(LDAPSearch):
    """
    Search for hostgroups.
    """

    msg_summary = ngettext(
        '%(count)d hostgroup matched', '%(count)d hostgroups matched'
    )

api.register(hostgroup_find)


class hostgroup_show(LDAPRetrieve):
    """
    Display hostgroup.
    """

api.register(hostgroup_show)


class hostgroup_add_member(LDAPAddMember):
    """
    Add members to hostgroup.
    """

api.register(hostgroup_add_member)


class hostgroup_remove_member(LDAPRemoveMember):
    """
    Remove members from hostgroup.
    """

api.register(hostgroup_remove_member)
