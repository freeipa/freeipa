# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Frontend plugins for delegations.
"""

from ipalib import frontend
from ipalib import crud
from ipalib.frontend import Param
from ipalib import api
from ipalib import errors
from ipa_server import servercore
from ipa_server import ipaldap
import ldap

class delegation(frontend.Object):
    """
    Delegation object.
    """
    takes_params = (
        'attributes',
        'source',
        'target',
        Param('name', primary_key=True)
    )
api.register(delegation)


class delegation_add(crud.Add):
    'Add a new delegation.'
api.register(delegation_add)


class delegation_del(crud.Del):
    'Delete an existing delegation.'
api.register(delegation_del)


class delegation_mod(crud.Mod):
    'Edit an existing delegation.'
api.register(delegation_mod)


class delegation_find(crud.Find):
    'Search for a delegation.'
api.register(delegation_find)


class delegation_show(crud.Get):
    'Examine an existing delegation.'
api.register(delegation_show)
