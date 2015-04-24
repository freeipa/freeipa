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
Password policy tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import pytest

ENTITY = 'pwpolicy'
DATA = {
    'pkey': 'admins',
    'add': [
        ('combobox', 'cn', 'admins'),
        ('textbox', 'cospriority', '364'),
    ],
    'mod': [
        ('textbox', 'krbmaxpwdlife', '3000'),
        ('textbox', 'krbminpwdlife', '1'),
        ('textbox', 'krbpwdhistorylength', '0'),
        ('textbox', 'krbpwdmindiffchars', '2'),
        ('textbox', 'krbpwdminlength', '2'),
        ('textbox', 'krbpwdmaxfailure', '15'),
        ('textbox', 'krbpwdfailurecountinterval', '5'),
        ('textbox', 'krbpwdlockoutduration', '3600'),
    ],
}


@pytest.mark.tier1
class test_pwpolicy(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: pwpolicy
        """
        self.init_app()
        self.basic_crud(ENTITY, DATA)
