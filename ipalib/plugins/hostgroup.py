# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Groups of hosts.

Manage groups of hosts. This is useful for applying access control to a
number of hosts by using Host-based Access Control.

EXAMPLES:

 Add a new host group:
   ipa hostgroup-add --desc="Baltimore hosts" baltimore

 Add another new host group:
   ipa hostgroup-add --desc="Maryland hosts" maryland

 Add members to the hostgroup:
   ipa hostgroup-add-member --hosts=box1,box2,box3 baltimore

 Add a hostgroup as a member of another hostgroup:
   ipa hostgroup-add-member --hostgroups=baltimore maryland

 Remove a host from the hostgroup:
   ipa hostgroup-remove-member --hosts=box2 baltimore

 Display a host group:
   ipa hostgroup-show baltimore

 Delete a hostgroup:
   ipa hostgroup-del baltimore
"""

from ipalib.plugins.baseldap import *
from ipalib import api, Int, _, ngettext


class hostgroup(LDAPObject):
    """
    Hostgroup object.
    """
    container_dn = api.env.container_hostgroup
    object_name = 'hostgroup'
    object_name_plural = 'hostgroups'
    object_class = ['ipaobject', 'ipahostgroup']
    default_attributes = ['cn', 'description', 'member', 'memberof',
        'memberindirect'
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['host', 'hostgroup'],
        'memberof': ['hostgroup'],
        'memberindirect': ['host', 'hostgroup'],
    }

    label = _('Host Groups')

    takes_params = (
        Str('cn',
            cli_name='hostgroup_name',
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
    )

api.register(hostgroup)


class hostgroup_add(LDAPCreate):
    """
    Add a new hostgroup.
    """

    msg_summary = _('Added hostgroup "%(value)s"')

api.register(hostgroup_add)


class hostgroup_del(LDAPDelete):
    """
    Delete a hostgroup.
    """

    msg_summary = _('Deleted hostgroup "%(value)s"')

api.register(hostgroup_del)


class hostgroup_mod(LDAPUpdate):
    """
    Modify a hostgroup.
    """

    msg_summary = _('Modified hostgroup "%(value)s"')

api.register(hostgroup_mod)


class hostgroup_find(LDAPSearch):
    """
    Search for hostgroups.
    """
    member_attributes = ['member', 'memberof']
    msg_summary = ngettext(
        '%(count)d hostgroup matched', '%(count)d hostgroups matched'
    )

api.register(hostgroup_find)


class hostgroup_show(LDAPRetrieve):
    """
    Display information about a hostgroup.
    """

api.register(hostgroup_show)


class hostgroup_add_member(LDAPAddMember):
    """
    Add members to a hostgroup.
    """

api.register(hostgroup_add_member)


class hostgroup_remove_member(LDAPRemoveMember):
    """
    Remove members from a hostgroup.
    """

api.register(hostgroup_remove_member)
