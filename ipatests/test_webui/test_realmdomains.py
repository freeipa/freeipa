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

Update means Check DNS in WebUI.
Force udpate means Force Update in WebUI.
"""

import uuid

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
from ipatests.test_webui.data_dns import (
    ZONE_ENTITY, FORWARD_ZONE_ENTITY, ZONE_DATA, FORWARD_ZONE_DATA,
    ZONE_DEFAULT_FACET
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
        self.add_record(ZONE_ENTITY, self.copy_zone_data(realmdomain))

        realm = self.config.get('ipa_realm')

        # remove the added domain from Realm Domain
        self.navigate_to_entity(ENTITY)
        self.del_realm_domain(realmdomain, 'ok')
        self.close_notifications()

        # re-add _TXT kerberos.$domain "$REALM"
        self.navigate_to_entity(ZONE_ENTITY)
        self.navigate_to_record(realmdomain + '.')

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
        self.close_notifications()

    @staticmethod
    def copy_zone_data(realmdomain, zone_data=ZONE_DATA):
        data = zone_data.copy()
        data['pkey'] = realmdomain
        for i, field in enumerate(data['add']):
            if field[1] == 'idnsname':
                data['add'][i] = (field[0], field[1], realmdomain)
        return data

    @staticmethod
    def rand_realmdomain():
        return 'zone-{}.itest'.format(uuid.uuid4().hex[:8])

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

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        # add Realm Domain and Check DNS
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_add_single_labeled_domain(self):
        """
        Add single label domain
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        single_label_domain = u'single-label-domain'

        # add with force - skipping DNS check
        self._add_associateddomain([single_label_domain], force=True)
        dialog = self.get_last_error_dialog()
        assert ("invalid 'domain': single label domains are not supported"
                in dialog.text)

    @screenshot
    def test_add_domain_with_special_char(self):
        """
        Add domain with special_character
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        domain_with_special_char = u'﻿ipa@123#.com'

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
    def test_add_domain_and_update(self):
        """
        Add domain and update
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        # add Realm Domain and Check DNS
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

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

    @screenshot
    def test_add_domain_and_revert(self):
        """
        Add domain and revert
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        test_domain = u'﻿itest.bar'

        # add and revert
        self.add_multivalued('associateddomain', test_domain)
        self.facet_button_click('revert')

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert test_domain not in domains

    @screenshot
    def test_add_duplicate_domain(self):
        """
        Add duplicate domain
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        self.navigate_to_entity(ENTITY)

        # add two (same) domains with force - skipping DNS check
        self._add_associateddomain([realmdomain, realmdomain], force=True)

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # cleanup
        self.del_realm_domain(realmdomain, 'force')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_add_empty_domain(self):
        """
        Add empty domain
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        # add with force - skipping DNS check
        self._add_associateddomain([''], force=True)

        # check
        dialog = self.get_last_error_dialog()
        assert ("no modifications to be performed" in dialog.text)

    @screenshot
    def test_add_domain_with_leading_space(self):
        """
        Add domain with leading space
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        # add with force - skipping DNS check
        self._add_associateddomain([' ipa.test'], force=True)

        # check
        dialog = self.get_last_error_dialog()
        assert ("invalid 'domain': Leading and trailing spaces are not allowed"
                in dialog.text)

    @screenshot
    def test_add_domain_with_trailing_space(self):
        """
        Add domain with trailing space
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        # add with force - skipping DNS check
        self._add_associateddomain(['ipa.test '], force=True)

        # check
        dialog = self.get_last_error_dialog()
        assert ("invalid 'domain': Leading and trailing spaces are not allowed"
                in dialog.text)

    @screenshot
    def test_del_domain_undo(self):
        """
        Undo after deleting existing domain
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        # add
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        # check that domain is present
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # delete and undo
        self.navigate_to_entity(ENTITY)
        self.del_multivalued('associateddomain', realmdomain)
        self.undo_multivalued('associateddomain', realmdomain)

        # check that domain is present
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_del_domain_undo_all(self):
        """
        Undo all after deleting existing domain
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        # add
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        # check that domain is present
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # delete and undo
        self.navigate_to_entity(ENTITY)
        self.del_multivalued('associateddomain', realmdomain)
        self.undo_all_multivalued('associateddomain')

        # check that domain is present
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_del_domain_revert(self):
        """
        Revert after deleting existing domain
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        # add
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        # del and revert
        self.navigate_to_entity(ENTITY)
        self.del_multivalued('associateddomain', realmdomain)
        self.facet_button_click('revert')

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_del_domain_and_refresh(self):
        """
        Delete domain and refresh
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        # add
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        self.navigate_to_entity(ENTITY)

        # delete
        self.del_multivalued('associateddomain', realmdomain)
        self.facet_button_click('refresh')

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_del_domain_and_update(self):
        """
        Delete and update
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        # add
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        self.navigate_to_entity(ENTITY)

        # delete
        self.del_multivalued('associateddomain', realmdomain)
        self.facet_button_click('save')
        self.dialog_button_click('ok')
        self.wait_for_request()
        self.close_notifications()

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain not in domains

        # cleanup
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_del_domain_with_force_update(self):
        """
        Delete and force update
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        # add
        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        self.navigate_to_entity(ENTITY)

        # force delete
        self.del_multivalued('associateddomain', realmdomain)
        self.facet_button_click('save')
        self.dialog_button_click('force')
        self.wait_for_request()
        self.close_notifications()

        # check
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain not in domains

        # cleanup
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_add_non_dns_configured_domain_negative(self):
        """
        Domain shouldn't be added after:
        1) add DNS non configured domain
        2) click update
        3) check DNS
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()

        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        dialog = self.get_last_error_dialog()
        assert ("invalid 'domain': DNS zone for each realmdomain must contain "
                "SOA or NS records. "
                "No records found for: " + realmdomain
                in dialog.text)

    @screenshot
    def test_add_non_dns_configured_domain_positive(self):
        """
        Domain should be added fter:
        1) add DNS non configured domain
        2) click update
        3) click force
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()

        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain], force=True)

        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_del_domain_of_ipa_server_bug1035286(self):
        """
        Error should occur when:
        1) delete Domain of Ipa server
        2) select update
        3) select force update
        4) click "Cancel"
        """
        self.init_app()

        ipadomain = self.config.get('ipa_domain')

        realmdomain = self.rand_realmdomain()
        self.prepare_dns_zone(realmdomain)

        self.navigate_to_entity(ENTITY)
        self._add_associateddomain([realmdomain])

        self.navigate_to_entity(ENTITY)

        self.del_multivalued('associateddomain', ipadomain)
        self.facet_button_click('save')
        self.dialog_button_click('force')
        self.wait_for_request()

        dialog = self.get_last_error_dialog()
        assert ("invalid 'realmdomain list': "
                "IPA server domain cannot be omitted" in dialog.text)
        self.dialog_button_click('cancel')
        self.facet_button_click('refresh')

        # cleanup
        self.del_realm_domain(realmdomain, 'ok')
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_dnszone_add_hooked_to_realmdomains_mod(self):
        """
        DNSZone is hooked to realmdomains:
        1) Navigate Identity >> DNS
        2) Add Dnszone (newdom.com)
        3) go to DNS Resource Records(DNS Zone >> newdom.com)
        4) verify TXT record is exists
        5)﻿ navigate Identity >> RealmDomain
        6) verify newly added domain (newdom.com) exists in realmdomain list
        7) Delete domain (newdom.com) from realmdomain list
        8) go to DNS Resource Records(DNS Zone >> newdom.com)
        9) verify TXT record is not exists
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()
        realm = self.config.get('ipa_realm')

        # add DNS domain
        self.navigate_to_entity(ZONE_ENTITY)
        self.add_record(ZONE_ENTITY, self.copy_zone_data(realmdomain))
        self.assert_record(realmdomain + '.')

        self.navigate_to_record(realmdomain + '.')
        self.assert_record('_kerberos')
        self.assert_record_value('TXT', '_kerberos', 'type')
        self.assert_record_value(realm, '_kerberos', 'data')

        self.navigate_to_entity(ENTITY)
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        self.del_multivalued('associateddomain', realmdomain)
        self.facet_button_click('save')
        self.dialog_button_click('ok')
        self.wait_for_request()

        self.navigate_to_entity(ZONE_ENTITY)
        self.assert_record(realmdomain + '.')

        self.navigate_to_record(realmdomain + '.')
        self.facet_button_click('refresh')
        self.assert_record('_kerberos', negative=True)

        # cleanup
        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_dns_reversezone_add_hooked_to_realmdomains_mod(self):
        """
        Reverse DNS domain is not automatically add domain to the list of
        domain associated with IPA realm
        1) Navigate Identity >> DNS
        2) Add Dns Reverse Zone (222.65.10.in-addr.arpa.)
        3) navigate Identity >> RealmDomain
        4) verify newly added domain (222.65.10.in-addr.arpa.) is not exists
           in realmdomain list
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()

        # add DNS Reverse zone
        self.navigate_to_entity(FORWARD_ZONE_ENTITY)
        self.add_record(FORWARD_ZONE_ENTITY,
                        self.copy_zone_data(realmdomain, FORWARD_ZONE_DATA))
        self.assert_record(realmdomain + '.')

        self.navigate_to_entity(ENTITY)
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain not in domains

        # cleanup
        self.navigate_to_entity(FORWARD_ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

    @screenshot
    def test_dnszone_del_hooked_to_realmdomains_mod(self):
        """
        ipa dnszone-del also removes the entry from realmdomains list
        1) Navigate Identity >> DNS
        2) Add Dnszone (newdom.com)
        3)﻿ navigate Identity >> RealmDomain
        4) verify newly added domain (newdom.com) exists in realmdomain list
        7)﻿ Navigate Identity >> DNS
        8) Delete Dnszone(newdom.com)
        9)﻿ navigate Identity >> RealmDomain
        10) verify domain (newdom.com) is not exists in realmdomain list
        """
        self.init_app()

        realmdomain = self.rand_realmdomain()

        # add DNS domain
        self.navigate_to_entity(ZONE_ENTITY)
        self.add_record(ZONE_ENTITY, self.copy_zone_data(realmdomain))
        self.assert_record(realmdomain + '.')

        self.navigate_to_entity(ENTITY)
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain in domains

        self.navigate_to_entity(ZONE_ENTITY)
        self.delete_record(realmdomain + '.')

        self.navigate_to_entity(ENTITY)
        domains = self.get_multivalued_value('associateddomain')
        assert realmdomain not in domains
