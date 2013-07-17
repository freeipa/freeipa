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

class test_range(UI_driver):

    def get_shifts(self, idranges=None):

        if not idranges:
            result = self.execute_api_from_ui('idrange_find', [], {})
            idranges = result['result']['result']

        id_shift = 0
        rid_shift = 0

        for idrange in idranges:
            size = int(idrange['ipaidrangesize'][0])
            base_id = int(idrange['ipabaseid'][0])

            id_end = base_id + size
            rid_end = 0

            if 'ipabaserid' in idrange:
                base_rid = int(idrange['ipabaserid'][0])
                rid_end = base_rid + size

                if 'ipasecondarybaserid' in idrange:
                    secondary_base_rid = int(idrange['ipasecondarybaserid'][0])
                    rid_end = max(base_rid, secondary_base_rid) + size

            if id_shift < id_end:
                id_shift = id_end + 1000000

            if rid_shift < rid_end:
                rid_shift = rid_end + 1000000

        self.id_shift = id_shift
        self.rid_shift = rid_shift
        self.sec_rid_shift = rid_shift + 1000
        self.shift = 0

    def get_data(self, pkey, size=50, shift=100):
        self.shift += shift
        data = {
            'pkey': pkey,
            'add': [
                ('textbox', 'cn', pkey),
                ('textbox', 'ipabaseid', str(self.id_shift + self.shift)),
                ('textbox', 'ipaidrangesize', str(size)),
                ('textbox', 'ipabaserid', str(self.rid_shift + self.shift)),
                ('textbox', 'ipasecondarybaserid', str(self.sec_rid_shift + self.shift)),
            ],
            'mod': [
                ('textbox', 'ipaidrangesize', str(size + 1)),
            ],
        }
        return data

    def test_crud(self):
        """
        Basic CRUD: range
        """
        self.init_app()
        self.get_shifts()
        self.basic_crud(ENTITY, self.get_data(PKEY))
