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

from ipatests.test_webui.ui_driver import UI_driver

ENTITY = 'trust'
CONFIG_ENTITY = 'trustconfig'

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


class test_trust(UI_driver):

    def __init__(self, *args, **kwargs):
        super(test_trust, self).__init__(args, kwargs)

        if not self.has_trusts():
            self.skip('Trusts not configured')

    def get_data(self):

        domain = self.config.get('ad_domain')
        admin = self.config.get('ad_admin')
        psw = self.config.get('ad_password')

        data = {
            'pkey': domain,
            'add': [
                ('textbox', 'realm_server', domain),
                ('textbox', 'realm_admin', admin),
                ('password', 'realm_passwd', psw),
            ],
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

    def test_crud(self):
        """
        Basic basic CRUD: trust

        Test establishing trust by using Windows admin credentials
        """
        self.init_app()
        data = self.get_data()
        self.basic_crud(ENTITY, data)

    def test_config_mod(self):
        self.init_app()
        self.navigate_to_entity(CONFIG_ENTITY)

        self.mod_record(CONFIG_ENTITY, CONFIG_DATA)
        self.mod_record(CONFIG_ENTITY, CONFIG_DATA2)
