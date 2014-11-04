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
Range tests
"""

import ipatests.test_webui.test_trust as trust_mod
from ipatests.test_webui.ui_driver import screenshot
from ipatests.test_webui.task_range import range_tasks

ENTITY = 'idrange'
PKEY = 'itest-range'


class test_range(range_tasks):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: range
        """
        self.init_app()
        self.get_shifts()
        self.basic_crud(ENTITY, self.get_data(PKEY))

    @screenshot
    def test_types(self):
        """
        Test range types

        Only 'local' and 'ipa-ad-trust' types are tested since range validation
        made quite hard to test the other types:

        - 'ipa-ad-trust-posix' can be tested only with subdomains.
        - 'ipa-ad-winsync' and 'ipa-ipa-trust' and  are not supported yet
          https://fedorahosted.org/freeipa/ticket/4323
        """
        self.init_app()
        self.get_shifts()

        pkey_local = 'itest-local'
        pkey_ad = 'itest-ad'
        pkey_posix = 'itest-ad-posix'
        pkey_winsync = 'itest-ad-winsync'
        pkey_trust = 'itest-ipa-trust'
        column = 'iparangetype'

        add = self.get_add_data(pkey_local)
        data = self.get_data(pkey_local, add_data=add)
        self.add_record(ENTITY, data)
        self.assert_record_value('local domain range', pkey_local, column)

        if self.has_trusts():

            trust_tasks = trust_mod.trust_tasks()
            trust_data = trust_tasks.get_data()

            self.add_record(trust_mod.ENTITY, trust_data)

            domain = self.get_domain()

            self.navigate_to_entity(ENTITY)

            add = self.get_add_data(pkey_ad, range_type='ipa-ad-trust', domain=domain)
            data = self.get_data(pkey_ad, add_data=add)
            self.add_record(ENTITY, data, navigate=False)
            self.assert_record_value('Active Directory domain range', pkey_ad, column)

            self.delete(trust_mod.ENTITY, [trust_data])
            self.navigate_to_entity(ENTITY)
            self.delete_record(pkey_ad)

        self.delete_record(pkey_local)
