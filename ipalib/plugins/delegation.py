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
Delegations
"""

from ipalib import api, crud
from ipalib import Object
from ipalib import Str
from ipalib import api

class delegation(Object):
    """
    Delegation object.
    """
    takes_params = (
        Str('name',
            cli_name='name',
            doc='name',
            primary_key=True
        ),
        List('attributes',
            cli_name='attributes',
            doc='comma-separated list of attributes',
        ),
        Str('source',
            cli_name='source',
            doc='source',
        ),
        Str('target',
            cli_name='target',
            doc='target',
        ),
    )

api.register(delegation)


class delegation_create(crud.Create):
    """
    Create delegation.
    """

api.register(delegation_add)


class delegation_delete(crud.Delete):
    """
    Delete delegation.
    """

api.register(delegation_delete)


class delegation_mod(crud.Update):
    """
    Modify delegation.
    """

api.register(delegation_mod)


class delegation_find(crud.Search):
    """
    Search for delegations.
    """

api.register(delegation_find)


class delegation_show(crud.Retrieve):
    """
    Display delegation.
    """

api.register(delegation_show)

