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
from ipalib.plugins.basegroup2 import *

_container_dn = api.env.container_rolegroup
_default_attributes = ['cn', 'description', 'member', 'memberOf']
_default_class = 'nestedGroup'


class rolegroup2(basegroup2):
    """
    Rolegroup object.
    """
    container = _container_dn

api.register(rolegroup2)


class rolegroup2_create(basegroup2_create):
    """
    Create new rolegroup.
    """
    base_classes = basegroup2_create.base_classes + (_default_class, )

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(rolegroup2_create, self).execute(cn, **kw)

api.register(rolegroup2_create)


class rolegroup2_delete(basegroup2_delete):
    """
    Delete rolegroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(rolegroup2_delete, self).execute(cn, **kw)

api.register(rolegroup2_delete)


class rolegroup2_mod(basegroup2_mod):
    """
    Edit rolegroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(rolegroup2_mod, self).execute(cn, **kw)

api.register(rolegroup2_mod)


class rolegroup2_find(basegroup2_find):
    """
    Search for rolegroups.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(rolegroup2_find, self).execute(cn, **kw)

api.register(rolegroup2_find)


class rolegroup2_show(basegroup2_show):
    """
    Display rolegroup.
    """
    default_attributes = _default_attributes
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(rolegroup2_show, self).execute(cn, **kw)

api.register(rolegroup2_show)


class rolegroup2_add_member(basegroup2_add_member):
    """
    Add member to rolegroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(rolegroup2_add_member, self).execute(cn, **kw)

api.register(rolegroup2_add_member)


class rolegroup2_del_member(basegroup2_del_member):
    """
    Remove member from rolegroup.
    """
    container = _container_dn

    def execute(self, cn, **kw):
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        return super(rolegroup2_del_member, self).execute(cn, **kw)

api.register(rolegroup2_del_member)

