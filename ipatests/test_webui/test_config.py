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
Config tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot

ENTITY = 'config'

DATA = {
    'mod': [
        ('textbox', 'ipasearchrecordslimit', '200'),
        ('textbox', 'ipasearchtimelimit', '3'),
    ],
}

DATA2 = {
    'mod': [
        ('textbox', 'ipasearchrecordslimit', '100'),
        ('textbox', 'ipasearchtimelimit', '2'),
    ],
}


class test_config(UI_driver):

    @screenshot
    def test_mod(self):
        """
        Config mod tests
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        self.mod_record(ENTITY, DATA)
        self.mod_record(ENTITY, DATA2)
