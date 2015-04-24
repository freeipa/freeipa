# Authors:
#   Petr Vobornik <pvoborni@redhat.com>
#
# Copyright (C) 2013  Red Hat
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
RBAC tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import pytest

ROLE_ENTITY = 'role'
ROLE_DEF_FACET = 'member_user'
ROLE_PKEY = 'AAtest_role'
ROLE_DATA = {
    'pkey': ROLE_PKEY,
    'add': [
        ('textbox', 'cn', ROLE_PKEY),
        ('textarea', 'description', 'role desc'),
    ],
    'mod': [
        ('textarea', 'description', 'role desc mod'),
    ],
}

PRIVILEGE_ENTITY = 'privilege'
PRIVILEGE_DEF_FACET = 'memberof_permission'
PRIVILEGE_PKEY = 'AAtest_privilege'
PRIVILEGE_DATA = {
    'pkey': PRIVILEGE_PKEY,
    'add': [
        ('textbox', 'cn', PRIVILEGE_PKEY),
        ('textarea', 'description', 'privilege desc'),
    ],
    'mod': [
        ('textarea', 'description', 'privilege desc mod'),
    ],
}

PERMISSION_ENTITY = 'permission'
PERMISSION_PKEY = 'AAtest_perm'
PERMISSION_DATA = {
    'pkey': PERMISSION_PKEY,
    'add': [
        ('textbox', 'cn', PERMISSION_PKEY),
        ('checkbox', 'ipapermright', 'write'),
        ('checkbox', 'ipapermright', 'read'),
        ('selectbox', 'type', 'user'),
        ('checkbox', 'attrs', 'audio'),
        ('checkbox', 'attrs', 'cn'),
    ],
    'mod': [
        ('checkbox', 'attrs', 'carlicense'),
    ],
}


@pytest.mark.tier1
class test_rbac(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: RBAC
        """
        self.init_app()
        self.basic_crud(ROLE_ENTITY, ROLE_DATA,
                        default_facet=ROLE_DEF_FACET
                        )

        self.basic_crud(PRIVILEGE_ENTITY, PRIVILEGE_DATA,
                        default_facet=PRIVILEGE_DEF_FACET
                        )

        self.basic_crud(PERMISSION_ENTITY, PERMISSION_DATA)
