# Authors:
#   Pavel Vomacka <pvomacka@redhat.com>
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
Vault tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_vault as vault
import ipatests.test_webui.data_user as user
import ipatests.test_webui.data_group as group
import pytest


@pytest.mark.tier1
class vault_tasks(UI_driver):

    @pytest.fixture(autouse=True)
    def vault_tasks_setup(self, ui_driver_fsetup):
        pass

    def prep_service_data(self):

        host = self.config.get('ipa_server')
        realm = self.config.get('ipa_realm')
        pkey = 'itest'

        return {
            'entity': 'service',
            'pkey': '%s/%s@%s' % (pkey, host, realm),
            'add': [
                ('textbox', 'service', pkey),
                ('combobox', 'host', host)
            ]
        }

    def prepare_vault_service_data(self, data):
        s_data = self.prep_service_data()
        service = s_data['pkey']

        serv_field = [('combobox', 'service', service)]

        data['add'].extend(serv_field)

    def prepare_vault_user_data(self, data, user='admin'):
        user_field = [('combobox', 'username', user)]

        data['add'].extend(user_field)


@pytest.mark.tier1
class test_vault(vault_tasks):

    @pytest.fixture(autouse=True)
    def vault_setup(self, vault_tasks_setup):
        if not self.has_kra():
            self.skip('KRA not configured')

    @screenshot
    def test_crud(self):
        """
        Basic basic CRUD: user vault
        """
        self.init_app()
        self.prepare_vault_user_data(vault.DATA)
        self.basic_crud(vault.ENTITY, vault.DATA)

    @screenshot
    def test_add_service_vault(self):
        """
        Add Service vault
        """
        self.init_app()

        # Add itest service
        s_data = self.prep_service_data()
        self.add_record(s_data['entity'], s_data)

        self.prepare_vault_service_data(vault.DATA2)

        # Add and remove service vault
        self.add_record(vault.ENTITY, vault.DATA2, facet=vault.DATA2['facet'],
                        delete=True)

        # Remove test service
        self.navigate_to_entity(s_data['entity'])
        self.delete_record(s_data['pkey'])

    @screenshot
    def test_add_shared_vault(self):
        """
        Add Shared vault
        """
        self.init_app()

        # Add shared vault
        self.add_record(vault.ENTITY, vault.DATA3, facet=vault.DATA3['facet'],
                        delete=True)

    @screenshot
    def test_member_owner_vault(self):
        """
        Add User Vault and try to add member and owner
        """
        def fill_tables():
            self.add_table_associations('member_user', [user.PKEY])
            self.add_table_associations('member_group', [group.PKEY])
            self.add_table_associations('member_service', [s_data['pkey']])
            self.add_table_associations('owner_user', [user.PKEY])
            self.add_table_associations('owner_group', [group.PKEY])
            self.add_table_associations('owner_service', [s_data['pkey']])

        # Add user
        self.init_app()
        self.add_record(user.ENTITY, user.DATA)

        # Prepare items - user already exists
        s_data = self.prep_service_data()
        self.add_record(s_data['entity'], s_data)
        self.add_record(group.ENTITY, group.DATA)

        # USER
        # Add user vault
        self.add_record(vault.ENTITY, vault.DATA, facet='user_search')

        # Navigate to record
        self.navigate_to_record(vault.DATA['pkey'])

        # Try add values into table
        fill_tables()

        # Remove user vault record
        self.navigate_to_entity(vault.ENTITY, vault.DATA['facet'])
        self.delete_record(vault.PKEY)

        # SERVICE
        # Add service vault
        self.prepare_vault_service_data(vault.DATA2)
        self.add_record(vault.ENTITY, vault.DATA2, facet=vault.DATA2['facet'])

        # Navigate to record
        self.navigate_to_record(vault.DATA2['pkey'])

        # Try add values into table
        fill_tables()

        # Remove service vault record
        self.navigate_to_entity(vault.ENTITY, vault.DATA2['facet'])
        self.delete_record(vault.DATA2['pkey'])

        # SHARED
        # Add shared vault
        self.add_record(vault.ENTITY, vault.DATA3, facet=vault.DATA3['facet'])

        # Navigate to record
        self.navigate_to_record(vault.DATA3['pkey'])

        # Try add values into table
        fill_tables()

        # Remove shared vault record
        self.navigate_to_entity(vault.ENTITY, vault.DATA3['facet'])
        self.delete_record(vault.DATA3['pkey'])

        # Clean up
        self.navigate_to_entity(s_data['entity'])
        self.delete_record(s_data['pkey'])
        self.navigate_to_entity(user.ENTITY)
        self.delete_record(user.PKEY)
        self.navigate_to_entity(group.ENTITY)
        self.delete_record(group.PKEY)
