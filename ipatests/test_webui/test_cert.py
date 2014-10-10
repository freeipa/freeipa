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
Cert tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot

ENTITY = 'cert'


class test_cert(UI_driver):

    def setup(self, *args, **kwargs):
        super(test_cert, self).setup(*args, **kwargs)

        if not self.has_ca():
            self.skip('CA not configured')

    @screenshot
    def test_read(self):
        """
        Basic read: cert

        Certs don't have standard mod, add and delete methods.
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)
        rows = self.get_rows()
        self.navigate_to_row_record(rows[0])
        self.navigate_by_breadcrumb("Certificates")
