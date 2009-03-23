# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Frontend plugins for rolegroups.
"""

from ipalib import api
from ipalib.plugins.basegroup import *

display_attributes = ['cn','description', 'member', 'memberof']
container_rolegroup = "cn=rolegroups,cn=accounts"

class rolegroup(BaseGroup):
    """
    rolegroup object.
    """
    container=container_rolegroup

api.register(rolegroup)


class rolegroup_add(basegroup_add):
    'Add a new rolegroup.'
    base_classes = ("top", "groupofnames", "nestedgroup")

api.register(rolegroup_add)


class rolegroup_del(basegroup_del):
    'Delete an existing rolegroup.'
    container = container_rolegroup

api.register(rolegroup_del)


class rolegroup_mod(basegroup_mod):
    'Edit an existing rolegroup.'
    container = container_rolegroup

api.register(rolegroup_mod)


class rolegroup_find(basegroup_find):
    'Search the groups.'
    container = container_rolegroup

api.register(rolegroup_find)


class rolegroup_show(basegroup_show):
    'Examine an existing rolegroup.'
    default_attributes = display_attributes
    container = container_rolegroup

api.register(rolegroup_show)


class rolegroup_add_member(basegroup_add_member):
    'Add a member to a rolegroup.'
    container = container_rolegroup

api.register(rolegroup_add_member)


class rolegroup_remove_member(basegroup_remove_member):
    'Remove a member from a rolegroup.'
    container = container_rolegroup

api.register(rolegroup_remove_member)
