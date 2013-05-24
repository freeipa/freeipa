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
User tests
"""

from ipatests.test_webui.ui_driver import UI_driver

ENTITY = 'idrange'
PKEY = 'itest-range'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'cn', PKEY),
        ('textbox', 'ipabaseid', '900000'),
        ('textbox', 'ipaidrangesize', '99999'),
        ('textbox', 'ipabaserid', '10000'),
        ('textbox', 'ipasecondarybaserid', '200000'),
    ],
    'mod': [
        ('textbox', 'ipaidrangesize', '100000'),
    ],
}

class test_range(UI_driver):

    def test_crud(self):
        """
        Basic CRUD: range
        """
        self.init_app()
        self.basic_crud(ENTITY, DATA)
