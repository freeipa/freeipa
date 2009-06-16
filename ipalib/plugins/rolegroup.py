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
Groups of roles
"""

from ipalib import api
from ipalib.plugins.basegroup import *

_container_dn = api.env.container_rolegroup
_default_attributes = ['cn', 'description', 'member', 'memberOf']
_default_class = 'nestedGroup'


class rolegroup(basegroup):
    """
    Rolegroup object.
    """
    container = _container_dn

api.register(rolegroup)


class rolegroup_create(basegroup_create):
    """
    Create new rolegroup.
    """
    base_classes = basegroup_create.base_classes + (_default_class, )

    def execute(self, cn, **kw):
        return super(rolegroup_create, self).execute(cn, **kw)

api.register(rolegroup_create)


class rolegroup_delete(basegroup_delete):
    """
    Delete rolegroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        return super(rolegroup_delete, self).execute(cn, **kw)

api.register(rolegroup_delete)


class rolegroup_mod(basegroup_mod):
    """
    Edit rolegroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        return super(rolegroup_mod, self).execute(cn, **kw)

api.register(rolegroup_mod)


class rolegroup_find(basegroup_find):
    """
    Search for rolegroups.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        return super(rolegroup_find, self).execute(cn, **kw)

api.register(rolegroup_find)


class rolegroup_show(basegroup_show):
    """
    Display rolegroup.
    """
    default_attributes = _default_attributes
    container = _container_dn

    def execute(self, cn, **kw):
        return super(rolegroup_show, self).execute(cn, **kw)

api.register(rolegroup_show)


class rolegroup_add_member(basegroup_add_member):
    """
    Add member to rolegroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        return super(rolegroup_add_member, self).execute(cn, **kw)

api.register(rolegroup_add_member)


class rolegroup_del_member(basegroup_del_member):
    """
    Remove member from rolegroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        return super(rolegroup_del_member, self).execute(cn, **kw)

api.register(rolegroup_del_member)

