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
Kerberos policy tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot

ENTITY = 'krbtpolicy'

DATA = {
    'mod': [
        ('textbox', 'krbmaxrenewableage', '599000'),
        ('textbox', 'krbmaxticketlife', '79800'),
    ],
}

DATA2 = {
    'mod': [
        ('textbox', 'krbmaxrenewableage', '604800'),
        ('textbox', 'krbmaxticketlife', '86400'),
    ],
}


class test_krbtpolicy(UI_driver):

    @screenshot
    def test_mod(self):
        """
        Kerberos policy mod test
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        self.mod_record(ENTITY, DATA)
        self.mod_record(ENTITY, DATA2)
