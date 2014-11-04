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
Range tasks
"""

from ipatests.test_webui.ui_driver import UI_driver


class range_tasks(UI_driver):

    def get_shifts(self, idranges=None):

        if not idranges:
            result = self.execute_api_from_ui('idrange_find', [], {})
            idranges = result['result']['result']

        max_id = 0
        max_rid = 0

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

            if max_id < id_end:
                max_id = id_end + 1000000

            if max_rid < rid_end:
                max_rid = rid_end + 1000000

        self.max_id = max_id
        self.max_rid = max_rid

    def get_domain(self):
        result = self.execute_api_from_ui('trust_find', [], {})
        trusts = result['result']['result']
        domain = None
        if trusts:
            domain = trusts[0]['cn']
        return domain

    def get_data(self, pkey, size=50, add_data=None):

        if not add_data:
            add_data = self.get_add_data(pkey, size=size)

        data = {
            'pkey': pkey,
            'add': add_data,
            'mod': [
                ('textbox', 'ipaidrangesize', str(size + 1)),
            ],
        }
        return data

    def get_add_data(self, pkey, range_type='ipa-local', size=50, shift=100, domain=None):

        base_id = self.max_id + shift
        self.max_id = base_id + size

        base_rid = self.max_rid + shift
        self.max_rid = base_rid + size

        add = [
            ('textbox', 'cn', pkey),
            ('textbox', 'ipabaseid', str(base_id)),
            ('textbox', 'ipaidrangesize', str(size)),
            ('textbox', 'ipabaserid', str(base_rid)),
            ('radio', 'iparangetype', range_type),
            ('callback', self.check_range_type_mod, range_type)
        ]

        if not domain:
            base_rid = self.max_rid + shift
            self.max_rid = base_rid + size
            add.append(('textbox', 'ipasecondarybaserid', str(base_rid)))
        if domain:
            add.append(('textbox', 'ipanttrusteddomainname', domain))

        return add

    def check_range_type_mod(self, range_type):
        if range_type == 'ipa-local':
            self.assert_disabled("[name=ipanttrusteddomainname]")
            self.assert_disabled("[name=ipasecondarybaserid]", negative=True)
        elif range_type == 'ipa-ad-trust':
            self.assert_disabled("[name=ipanttrusteddomainname]", negative=True)
            self.assert_disabled("[name=ipasecondarybaserid]")
