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
HBAC tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_hbac as hbac
import ipatests.test_webui.data_hostgroup as hostgroup
import pytest


@pytest.mark.tier1
class test_hbac(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: hbac
        """
        self.init_app()
        self.basic_crud(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.basic_crud(hbac.SVC_ENTITY, hbac.SVC_DATA)
        self.basic_crud(hbac.SVCGROUP_ENTITY, hbac.SVCGROUP_DATA,
                        default_facet=hbac.SVCGROUP_DEF_FACET)

    @screenshot
    def test_mod(self):
        """
        Mod: hbac
        """
        self.init_app()
        host_key = self.config.get('ipa_server').strip()

        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)

        self.navigate_to_record(hbac.RULE_PKEY)

        tables = [
            ['memberuser_user', ['admin'], ],
            ['memberuser_group', ['editors'], ],
            ['memberhost_host', [host_key], ],
            ['memberhost_hostgroup', [hostgroup.PKEY], ],
            ['memberservice_hbacsvc', ['ftp'], ],
            ['memberservice_hbacsvcgroup', ['Sudo'], ],
        ]

        categories = [
            'usercategory',
            'hostcategory',
            'servicecategory',
        ]

        self.mod_rule_tables(tables, categories, [])

        # cleanup
        # -------
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(hostgroup.ENTITY, [hostgroup.DATA])

    @screenshot
    def test_actions(self):
        """
        Test hbac rule actions
        """
        self.init_app()

        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.navigate_to_record(hbac.RULE_PKEY)

        self.disable_action()
        self.enable_action()
        self.delete_action(hbac.RULE_ENTITY, hbac.RULE_PKEY)

    @screenshot
    def test_hbac_test(self):
        """
        Test HBAC test UI

        Test:
        * basic functionality
        * navigation by next/prev buttons
        * navigation by facet tabs
        * resetting test
        """

        self.init_app()
        host_key = self.config.get('ipa_server').strip()

        self.navigate_to_entity('hbactest', 'user')
        self.assert_facet('hbactest', 'user')
        self.select_record('admin')
        self.button_click('next')

        self.wait_for_request(n=2)
        self.assert_facet('hbactest', 'targethost')
        self.select_record(host_key)
        self.button_click('prev')
        self.assert_facet('hbactest', 'user')
        self.switch_to_facet('targethost')
        self.button_click('next')

        self.wait_for_request(n=2)
        self.assert_facet('hbactest', 'service')
        self.select_record('ftp')
        self.button_click('prev')
        self.assert_facet('hbactest', 'targethost')
        self.switch_to_facet('service')
        self.button_click('next')

        self.wait_for_request(n=2)
        self.assert_facet('hbactest', 'rules')
        self.select_record('allow_all')
        self.button_click('prev')
        self.assert_facet('hbactest', 'service')
        self.switch_to_facet('rules')
        self.button_click('next')

        self.wait_for_request(n=2)
        self.assert_facet('hbactest', 'run_test')
        self.button_click('run_test')
        self.assert_text("div.hbac-test-result-panel p", 'Access Granted'.upper())
        self.button_click('prev')
        self.assert_facet('hbactest', 'rules')
        self.switch_to_facet('run_test')
        self.wait_for_request(n=2)
        self.button_click('new_test')
        self.assert_facet('hbactest', 'user')

        # test pre-run validation and navigation to related facet
        def __hbac_ui_click_on_run_test(self):
            self.wait_for_request(n=2)
            self.switch_to_facet('run_test')
            self.wait_for_request(n=2)
            self.button_click('run_test')
            self.assert_dialog('message_dialog')

        __hbac_ui_click_on_run_test(self)
        self.click_on_link('Target host')
        self.assert_facet('hbactest', 'targethost')

        __hbac_ui_click_on_run_test(self)
        self.click_on_link('Service')
        self.assert_facet('hbactest', 'service')
