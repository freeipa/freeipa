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
DNS tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
from ipatests.test_webui.data_dns import (
    ZONE_ENTITY, FORWARD_ZONE_ENTITY, CONFIG_ENTITY, RECORD_ENTITY,
    ZONE_DEFAULT_FACET, ZONE_PKEY, ZONE_DATA, FORWARD_ZONE_PKEY,
    FORWARD_ZONE_DATA, RECORD_PKEY, A_IP, RECORD_ADD_DATA, RECORD_MOD_DATA,
    CONFIG_MOD_DATA
)
import pytest


@pytest.mark.tier1
class test_dns(UI_driver):

    @pytest.fixture(autouse=True)
    def dns_setup(self, ui_driver_fsetup):
        if not self.has_dns():
            self.skip('DNS not configured')

    @screenshot
    def test_zone_record_crud(self):
        """
        Basic CRUD: dns
        """
        self.init_app()

        # add and mod zone
        self.basic_crud(ZONE_ENTITY, ZONE_DATA,
                        default_facet=ZONE_DEFAULT_FACET, delete=False)

        # add and mod record
        self.navigate_to_record(ZONE_PKEY)
        self.add_record(ZONE_ENTITY, RECORD_ADD_DATA,
                        facet=ZONE_DEFAULT_FACET, navigate=False)
        self.navigate_to_record(RECORD_PKEY)
        self.add_table_record('arecord', RECORD_MOD_DATA)

        # del record, del zone
        self.navigate_by_breadcrumb(ZONE_PKEY)
        self.delete_record(RECORD_PKEY)
        self.navigate_by_breadcrumb("DNS Zones")
        self.delete_record(ZONE_PKEY)

    @screenshot
    def test_forward_zone(self):
        """
        Forward DNS zones
        """
        self.init_app()

        # add and mod zone
        self.basic_crud(FORWARD_ZONE_ENTITY, FORWARD_ZONE_DATA, delete=False)

        # enable/disable
        self.navigate_to_record(FORWARD_ZONE_PKEY)

        self.disable_action()
        self.enable_action()
        self.action_list_action('add_permission')
        self.action_list_action('remove_permission')

        # del zone
        self.navigate_by_breadcrumb("DNS Forward Zones")
        self.delete_record(FORWARD_ZONE_PKEY)

    @screenshot
    def test_last_entry_deletion(self):
        """
        Test last entry deletion
        """
        self.init_app()
        self.add_record(ZONE_ENTITY, ZONE_DATA)
        self.navigate_to_record(ZONE_PKEY)
        self.add_record(ZONE_ENTITY, RECORD_ADD_DATA,
                        facet=ZONE_DEFAULT_FACET)
        self.navigate_to_record(RECORD_PKEY)
        self.delete_record(A_IP, parent=self.get_facet(), table_name='arecord')
        self.assert_dialog('message_dialog')
        self.dialog_button_click('ok')
        self.wait_for_request(n=2)
        self.assert_facet(ZONE_ENTITY, ZONE_DEFAULT_FACET)
        self.navigate_by_breadcrumb("DNS Zones")
        self.delete_record(ZONE_PKEY)

    @screenshot
    def test_config_crud(self):
        """
        Basic CRUD: dnsconfig
        """
        self.init_app()
        self.navigate_by_menu('network_services/dns/dnsconfig')
        self.mod_record(CONFIG_ENTITY, CONFIG_MOD_DATA)

    def test_ptr_from_host_creation(self):
        """
        Test scenario for RHBZ 2009114 - a PTR record is created correctly
        with trailing dot when navigated to DNS Records page from host details
        page.
        """
        self.init_app()

        zone = "ptrzone.test."
        reverse_zone = "12.168.192.in-addr.arpa."
        hostname = "server"
        fqdn = "server.ptrzone.test"
        dns_fqdn = fqdn + "."
        ip = "192.168.12.20"
        zone_add_data = {
            "add": [
                ("textbox", "idnsname", zone),
            ],
        }
        reverse_zone_add_data = {
            "add": [
                ("radio", "dnszone_name_type", "name_from_ip"),
                ("textbox", "name_from_ip", ip + "/24"),
            ],
        }
        record_add_data = {
            "add": [
                ("textbox", "idnsname", "server"),
                ("textbox", "a_part_ip_address", ip),
            ]
        }
        host_add_data = {
            "add": [
                ("textbox", "hostname", hostname),
                ("combobox", "dnszone", zone),
            ],
        }

        # Create needed DNS zones and record
        self.add_record(ZONE_ENTITY, zone_add_data, navigate=True)
        self.add_record(ZONE_ENTITY, reverse_zone_add_data, navigate=False)
        self.navigate_to_record(zone)
        self.add_record(ZONE_ENTITY, record_add_data,
                        facet=ZONE_DEFAULT_FACET)

        # Create host record
        self.navigate_by_menu("identity/host")
        self.add_record("host", host_add_data, navigate=False)
        self.navigate_to_record(fqdn)
        self.click_on_link(fqdn)
        self.wait_for_request(n=2, d=0.5)
        self.assert_facet(RECORD_ENTITY, "details")
        self.click_on_link(ip)
        self.wait_for_request(n=2, d=0.5)
        self.assert_dialog()
        self.click_on_link("Create dns record")
        self.wait_for_request(n=3, d=0.5)
        self.assert_facet(RECORD_ENTITY, "details")
        self.assert_record(dns_fqdn, table_name="ptrrecord")

        # Cleanup
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record([zone, reverse_zone])
        self.navigate_to_entity("host")
        self.delete_record([fqdn])
