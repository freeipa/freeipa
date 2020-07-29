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
Trust tests
"""

import ipatests.test_webui.data_group as group
import ipatests.test_webui.data_idviews as idview
from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
from ipatests.test_webui.task_range import range_tasks
import pytest

ENTITY = 'trust'
CONFIG_ENTITY = 'trustconfig'

DEFAULT_TRUST_VIEW = 'Default Trust View'

CONFIG_DATA = {
    'mod': [
        ['combobox', 'ipantfallbackprimarygroup', 'admins'],
    ]
}

CONFIG_DATA2 = {
    'mod': [
        ['combobox', 'ipantfallbackprimarygroup', 'Default SMB Group']
    ]
}


@pytest.mark.tier1
class trust_tasks(UI_driver):

    @pytest.fixture(autouse=True)
    def trusttasks_setup(self, ui_driver_fsetup):
        pass

    def get_data(self, add_data=None):

        domain = self.config.get('ad_domain')

        if not add_data:
            add_data = self.get_add_data()

        data = {
            'pkey': domain,
            'add': add_data,
            'mod': [
                ('multivalued', 'ipantsidblacklistincoming', [
                    ('del', 'S-1-5-18'),
                    ('add', 'S-1-5-21'),
                ]),
                ('multivalued', 'ipantsidblacklistoutgoing', [
                    ('del', 'S-1-5-18'),
                    ('add', 'S-1-5-21'),
                ]),
            ],
        }

        return data

    def get_add_data(self, range_type=None, base_id=None, range_size=None):

        domain = self.config.get('ad_domain')
        admin = self.config.get('ad_admin')
        psw = self.config.get('ad_password')

        add = [
            ('textbox', 'realm_server', domain),
            ('textbox', 'realm_admin', admin),
            ('password', 'realm_passwd', psw),
        ]

        if range_type:
            add.append(('radio', 'range_type', range_type))
        if base_id:
            add.append(('textbox', 'base_id', base_id))
        if range_size:
            add.append(('textbox', 'range_size', range_size))

        return add

    def get_range_name(self):
        domain = self.config.get('ad_domain')
        return domain.upper() + '_id_range'


@pytest.mark.tier1
class test_trust(trust_tasks):

    request_timeout = 120

    @pytest.fixture(autouse=True)
    def trust_setup(self, trusttasks_setup):
        if not self.has_trusts():
            self.skip('Trusts not configured')

    @screenshot
    def test_crud(self):
        """
        Basic basic CRUD: trust

        Test establishing trust by using Windows admin credentials
        """
        self.init_app()
        data = self.get_data()
        self.navigate_to_entity('idrange')
        self.delete_record(self.get_range_name())
        self.basic_crud(ENTITY, data)
        self.navigate_to_entity('idrange')
        self.delete_record(self.get_range_name())

    @screenshot
    def test_range_types(self):

        self.init_app()

        r_tasks = range_tasks()
        r_tasks.driver = self.driver
        r_tasks.config = self.config
        r_tasks.get_shifts()
        range_form = r_tasks.get_add_form_data('')
        base_id = range_form.base_id
        range_size = range_form.size
        range_pkey = self.get_range_name()
        column = 'iparangetype'

        self.navigate_to_entity('idrange')
        self.delete_record(range_pkey)

        add = self.get_add_data('ipa-ad-trust', base_id, range_size)
        data = self.get_data(add_data=add)
        self.add_record(ENTITY, data, delete=True)
        self.navigate_to_entity('idrange')
        self.assert_record_value('Active Directory domain range', range_pkey, column)
        self.delete_record(range_pkey)

        add = self.get_add_data('ipa-ad-trust-posix', base_id, range_size)
        data = self.get_data(add_data=add)
        self.add_record(ENTITY, data, delete=True)
        self.navigate_to_entity('idrange')
        self.assert_record_value('Active Directory trust range with POSIX attributes', range_pkey, column)
        self.delete_record(range_pkey)

    @screenshot
    def test_config_mod(self):

        self.init_app()
        self.navigate_to_entity(CONFIG_ENTITY)

        self.mod_record(CONFIG_ENTITY, CONFIG_DATA)
        self.mod_record(CONFIG_ENTITY, CONFIG_DATA2)

    @screenshot
    def test_group_member_idoverrideuser(self):

        self.init_app()

        # Create new trust
        data = self.get_data()
        self.add_record(ENTITY, data)

        # Create an user ID override
        ad_domain = self.config.get('ad_domain')
        ad_admin = self.config.get('ad_admin')
        idoverrideuser_pkey = '{}@{}'.format(ad_admin, ad_domain).lower()

        self.navigate_to_record(DEFAULT_TRUST_VIEW, entity=idview.ENTITY)
        self.add_record(idview.ENTITY, {
            'pkey': idoverrideuser_pkey,
            'add': [
                ('textbox', 'ipaanchoruuid_default', idoverrideuser_pkey),
            ],
        }, facet='idoverrideuser')

        # Create new group and add the user ID override there
        self.navigate_to_entity(group.ENTITY)
        self.add_record(group.ENTITY, group.DATA)
        self.navigate_to_record(group.PKEY)
        self.add_associations([idoverrideuser_pkey],
                              facet='member_idoverrideuser', delete=True)

        # Clean up data
        self.navigate_to_entity(group.ENTITY)
        self.delete_record(group.PKEY)
        self.navigate_to_record(DEFAULT_TRUST_VIEW, entity=idview.ENTITY)
        self.delete_record(idoverrideuser_pkey)
        self.navigate_to_entity(ENTITY)
        self.delete_record(ad_domain)
