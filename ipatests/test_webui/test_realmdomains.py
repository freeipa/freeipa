# -*- coding: utf-8 -*-
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

    def prepare_dns_zone(self, realmdomain):
        """
        Prepare dns zone record for realmdomain
        """

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

    def _add_associateddomain(self, values, force=False):
        """
        Add values to associated domains and click OK or Force
        """
        for val in values:
            self.add_multivalued('associateddomain', val)
        self.facet_button_click('save')
        self.dialog_button_click('force' if force else 'ok')
        self.wait_for_request()

    @screenshot
    def test_read(self):
        """
        Realm domains mod tests
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        # add with force - skipping DNS check
        self._add_associateddomain(['itest.bar'], force=True)
        self.close_notifications()

        # delete
        self.del_realm_domain('itest.bar', 'force')
        self.wait_for_request()

        realmdomain = ZONE_PKEY.strip('.')
        self.prepare_dns_zone(realmdomain)

        # add Realm Domain and Check DNS
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(ZONE_PKEY)

    @screenshot
    def test_add_domain_with_special_char(self):
        """
        Add domain with special_character
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        domain_with_special_char = u'﻿ipa@123#'

        # add with force - skipping DNS check
        self._add_associateddomain([domain_with_special_char], force=True)
        dialog = self.get_last_error_dialog()
        assert ("invalid 'domain': only letters, numbers, '-' are allowed. "
                "DNS label may not start or end with '-'"
                in dialog.text)

    @screenshot
    def test_add_domain_and_undo(self):
        """
        Add domain and undo
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        test_domain = u'﻿itest.bar'

        # add and undo
        self.add_multivalued('associateddomain', test_domain)
        self.undo_multivalued('associateddomain', test_domain)

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert test_domain not in domains

    @screenshot
    def test_add_domain_and_undo_all(self):
        """
        Add domain and undo all
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        test_domain = u'﻿itest.bar'

        # add and undo all
        self.add_multivalued('associateddomain', test_domain)
        self.undo_all_multivalued('associateddomain')

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert test_domain not in domains

    @screenshot
    def test_add_domain_and_refresh(self):
        """
        Add domain and refresh
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        test_domain = u'﻿itest.bar'

        # add and refresh
        self.add_multivalued('associateddomain', test_domain)
        self.facet_button_click('refresh')

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert test_domain not in domains
