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
Realm domains tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
from ipatests.test_webui.data_dns import (
    ZONE_ENTITY, ZONE_DATA, ZONE_PKEY, ZONE_DEFAULT_FACET
)
import pytest

ENTITY = 'realmdomains'


@pytest.mark.tier1
class test_realmdomains(UI_driver):

    def del_realm_domain(self, realmdomain, button):
        self.del_multivalued('associateddomain', realmdomain)
        self.facet_button_click('save')
        self.dialog_button_click(button)
        self.wait_for_request()
        self.close_notifications()

    @screenshot
    def test_read(self):
        """
        Realm domains mod tests
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        # add with force - skipping DNS check
        self.add_multivalued('associateddomain', 'itest.bar')
        self.facet_button_click('save')
        self.dialog_button_click('force')
        self.wait_for_request()
        self.close_notifications()

        # delete
        self.del_realm_domain('itest.bar', 'force')
        self.wait_for_request()

        # Try adding and deleting with "Check DNS" (in html 'ok' button)

        # DNS check expects that the added domain will have DNS record:
        #    TXT _kerberos.$domain "$REALM"
        # When a new domain is added using dnszone-add it automatically adds
        # this TXT record and adds a realm domain. So in order to test without
        # external DNS we must get into state where realm domain is not added
        # (in order to add it) but DNS domain with the TXT record
        # exists.

        # add DNS domain
        self.navigate_to_entity(ZONE_ENTITY)
        self.add_record(ZONE_ENTITY, ZONE_DATA)

        realmdomain = ZONE_PKEY.strip('.')
        realm = self.config.get('ipa_realm')

        # remove the added domain from Realm Domain
        self.navigate_to_entity(ENTITY)
        self.del_realm_domain(realmdomain, 'ok')
        self.close_notifications()

        # re-add _TXT kerberos.$domain "$REALM"
        self.navigate_to_entity(ZONE_ENTITY)
        self.navigate_to_record(ZONE_PKEY)

        DNS_RECORD_ADD_DATA = {
            'pkey': '_kerberos',
            'add': [
                ('textbox', 'idnsname', '_kerberos'),
                ('selectbox', 'record_type', 'txtrecord'),
                ('textbox', 'txt_part_data', realm),
            ]
        }
        self.add_record(ZONE_ENTITY, DNS_RECORD_ADD_DATA,
                        facet=ZONE_DEFAULT_FACET, navigate=False)

        # add Realm Domain and Check DNS
        self.navigate_to_entity(ENTITY)
        self.add_multivalued('associateddomain', realmdomain)
        self.facet_button_click('save')
        self.dialog_button_click('ok')
        self.wait_for_request()

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(ZONE_PKEY)
