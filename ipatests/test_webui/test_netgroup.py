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
Netgroup tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_netgroup as netgroup
import ipatests.test_webui.data_user as user
import ipatests.test_webui.data_group as group
import ipatests.test_webui.data_hostgroup as hostgroup
from ipatests.test_webui.test_host import host_tasks, ENTITY as HOST_ENTITY
import pytest

try:
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    pass


@pytest.mark.tier1
class test_netgroup(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: netgroup
        """
        self.init_app()
        self.basic_crud(netgroup.ENTITY, netgroup.DATA)

    @screenshot
    def test_basic_workflows(self):
        """
        add and delete netgroup with various scenarios.
        """
        self.init_app()

        # add mixed case netgroup name
        self.add_record(netgroup.ENTITY, netgroup.DATA_MIXED_CASE)
        pkey = netgroup.DATA_MIXED_CASE['pkey'].lower()
        self.delete_record(pkey)

        # add long netgroup name
        self.add_record(netgroup.ENTITY, netgroup.DATA_LONG_NAME, delete=True)

        # add single character netgroup name ticket#2671
        self.add_record(netgroup.ENTITY, netgroup.DATA_SINGLE_CHAR,
                        delete=True)

        # add netgroup using enter
        self.add_record(netgroup.ENTITY, netgroup.DATA, dialog_btn=None)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.TAB)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(d=0.5)
        self.assert_record(netgroup.PKEY)
        self.close_notifications()

        # delete netgroup using enter
        self.select_record(netgroup.PKEY)
        self.facet_button_click('remove')
        self.wait_for_request()
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(d=0.5)
        self.assert_record(netgroup.PKEY, negative=True)
        self.close_all_dialogs()

        # delete and cancel
        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.select_record(netgroup.PKEY)
        self.facet_button_click('remove')
        self.dialog_button_click('cancel')
        self.assert_record(netgroup.PKEY)
        self.select_record(netgroup.PKEY, unselect=True)
        self.delete_record(netgroup.PKEY)

        # add multiple records using add_and_another button
        self.add_record(netgroup.ENTITY, [netgroup.DATA, netgroup.DATA2,
                                          netgroup.DATA3, netgroup.DATA4])
        # search record
        pkey = netgroup.DATA2['pkey']
        self.search_pkey(pkey)
        self.assert_record(pkey)

        # Negative search
        pkey = netgroup.DATA_MIXED_CASE['pkey']
        self.search_pkey(pkey)
        self.assert_record(pkey, negative=True)

        # delete multiple records
        records = [netgroup.DATA, netgroup.DATA2, netgroup.DATA3]
        self.navigate_to_entity(netgroup.ENTITY)
        self.select_multiple_records(records)
        self.facet_button_click('remove')
        self.dialog_button_click('ok')

        # Find and delete
        pkey = netgroup.DATA4['pkey']
        self.search_pkey(pkey)
        self.select_record(pkey)
        self.facet_button_click('remove')
        self.dialog_button_click('ok')

    def search_pkey(self, pkey):
        search_field_s = '.search-filter input[name=filter]'
        self.fill_text(search_field_s, pkey)
        self.action_button_click('find', parent=None)
        self.wait_for_request(n=2)

    @screenshot
    def test_add_netgroup_negative(self):
        """
        Negative test for adding netgroup
        """
        self.init_app()

        # add then cancel
        self.add_record(netgroup.ENTITY, netgroup.DATA, dialog_btn='cancel')

        # add duplicate
        self.add_record(netgroup.ENTITY, netgroup.DATA)
        expected_error = 'group with name "%s" already exists' % netgroup.PKEY
        self.navigate_to_entity(netgroup.ENTITY)
        self.facet_button_click('add')
        self.fill_input('cn', netgroup.PKEY)
        self.cancel_retry_dialog(expected_error)
        self.delete_record(netgroup.PKEY)

        # empty netgroup
        self.navigate_to_entity(netgroup.ENTITY)
        self.facet_button_click('add')
        self.dialog_button_click('add')
        elem = self.find(".widget[name='cn']")
        self.assert_field_validation_required(elem)
        self.dialog_button_click('cancel')

        # invalid_group_name
        expected_error = 'may only include letters, numbers, _, -, and .'
        pkey = ';test-gr@up'
        self.navigate_to_entity(netgroup.ENTITY)
        self.facet_button_click('add')
        self.fill_input('cn', pkey)
        elem = self.find(".widget[name='cn']")
        self.assert_field_validation(expected_error, parent=elem)
        self.dialog_button_click('cancel')

    def cancel_retry_dialog(self, expected_error):
        self.dialog_button_click('add')
        dialog = self.get_last_error_dialog()
        assert (expected_error in dialog.text)
        self.wait_for_request()
        # Key press for Retry
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(n=2)
        self.dialog_button_click('cancel')
        self.wait_for_request(n=2)
        self.dialog_button_click('cancel')

    @screenshot
    def test_unsaved_changes(self):
        """
        verifying unsaved changes dialog ticket#2075
        """
        self.init_app()
        self.add_record(netgroup.ENTITY, netgroup.DATA8,
                        dialog_btn='add_and_edit')
        mod_description = (netgroup.DATA8['mod'][0][2])

        # verifying Cancel button
        self.fill_fields(netgroup.DATA8['mod'])
        self.click_on_link('Netgroups')
        self.assert_dialog()
        self.dialog_button_click('cancel')
        self.assert_facet_button_enabled('save')

        # verifying Revert button
        self.click_on_link('Netgroups')
        self.assert_dialog()
        self.dialog_button_click('revert')
        self.navigate_to_record(netgroup.PKEY8)
        self.verify_btn_action(mod_description)

        # verifying Save button
        self.fill_fields(netgroup.DATA8['mod'])
        self.click_on_link('Netgroups')
        self.assert_dialog()
        self.dialog_button_click('save')
        self.navigate_to_record(netgroup.PKEY8)
        self.verify_btn_action(mod_description, negative=True)

    @screenshot
    def test_add_and_edit_group(self):
        """
        1. add and switch to edit mode
        2. verifying Save, Revert, Refresh and Undo button
        """
        self.init_app()

        # add and edit record
        self.add_record(netgroup.ENTITY, netgroup.DATA8,
                        dialog_btn='add_and_edit')
        mod_description = (netgroup.DATA8['mod'][0][2])

        # verifying undo button
        self.fill_fields(netgroup.DATA8['mod'])
        self.undo_click()
        self.verify_btn_action(mod_description)
        self.wait_for_request(n=2)

        # verifying revert button
        self.mod_record(netgroup.ENTITY, netgroup.DATA8, facet_btn='revert')
        self.wait_for_request()
        self.verify_btn_action(mod_description)
        self.wait_for_request(n=2)

        # verifying refresh button
        self.fill_fields(netgroup.DATA8['mod'], undo=True)
        self.facet_button_click('refresh')
        self.verify_btn_action(mod_description)
        self.wait_for_request(n=2)

        # verifying Save button
        self.mod_record(netgroup.ENTITY, netgroup.DATA8)
        self.wait_for_request()
        self.verify_btn_action(mod_description, negative=True)
        self.wait_for_request(n=2)

        # clean up
        self.navigate_to_entity(netgroup.ENTITY)
        self.delete_record(netgroup.PKEY8)

    def undo_click(self):
        facet = self.get_facet()
        s = ".textarea-widget button[name='undo']"
        self._button_click(s, facet)

    def verify_btn_action(self, mod_description, negative=False):
        """
        camparing current description with modified description
        """
        current_description = self.get_field_value("description",
                                                   element="textarea")
        if negative:
            assert current_description == mod_description
        else:
            assert current_description != mod_description

    @screenshot
    def test_add_members(self):
        """
        Adding members and membersof
        """
        self.init_app()

        records = [netgroup.DATA, netgroup.DATA2, netgroup.DATA3,
                   netgroup.DATA4, netgroup.DATA8]
        self.add_record(netgroup.ENTITY, records)
        # adding netgroup "members"
        self.navigate_to_record(netgroup.PKEY2)
        self.add_associations([netgroup.PKEY3, netgroup.PKEY4],
                              'member_netgroup', delete=True, search=True)
        # adding netgroup "memberof"
        self.add_associations([netgroup.PKEY, netgroup.PKEY8],
                              'memberof_netgroup', delete=True)
        self.delete(netgroup.ENTITY, records)

    @screenshot
    def test_mod(self):
        """
        Mod: netgroup
        """
        self.init_app()
        host = host_tasks()
        host.driver = self.driver
        host.config = self.config
        host.prep_data()
        host.prep_data2()

        self.add_record(netgroup.ENTITY, netgroup.DATA2)
        self.add_record(user.ENTITY, user.DATA)
        self.add_record(user.ENTITY, user.DATA2, navigate=False)
        self.add_record(group.ENTITY, group.DATA)
        self.add_record(group.ENTITY, group.DATA2, navigate=False)
        self.add_record(HOST_ENTITY, host.data)
        self.add_record(HOST_ENTITY, host.data2, navigate=False)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA2, navigate=False)
        self.add_record(netgroup.ENTITY, netgroup.DATA)

        self.navigate_to_record(netgroup.PKEY, entity=netgroup.ENTITY)

        tables = [
            ['memberuser_user', [user.PKEY, user.PKEY2], ],
            ['memberuser_group', [group.PKEY, group.PKEY2], ],
            ['memberhost_host', [host.pkey, host.pkey2], ],
            ['memberhost_hostgroup', [hostgroup.PKEY, hostgroup.PKEY2], ],
        ]

        categories = [
            'usercategory',
            'hostcategory',
        ]

        self.mod_rule_tables(tables, categories, [])

        # add associations then cancel
        def get_t_vals(t):
            table = t[0]
            k = t[1]
            e = []
            if len(t) > 2:
                e = t[2]
            return table, k, e

        for t in tables:
            table, keys, _exts = get_t_vals(t)
            self.add_table_associations(table, [keys[0]], confirm_btn='cancel')

            # verifying members listed as links ticket#2670
            self.add_table_associations(table, [keys[0]])
            self.wait_for_request(n=2)
            self.navigate_to_record(keys[0], table_name=table)
            page_pkey = self.get_text('.facet-pkey')
            assert keys[0] in page_pkey
            self.navigate_to_record(netgroup.PKEY, entity=netgroup.ENTITY)

        for cat in categories:
            # verifying undo on memberships
            self.check_option(cat, 'all')
            self.assert_facet_button_enabled('save', enabled=True)
            undo = "div[name = %s] > button[name='undo']" % cat
            self._button_click(undo, parent=None)
            self.assert_facet_button_enabled('save', enabled=False)

            # verifying Revert on memberships
            self.check_option(cat, 'all')
            self.facet_button_click('revert')
            self.assert_facet_button_enabled('save', enabled=False)

            # verifying refresh on memberships
            self.check_option(cat, 'all')
            self.facet_button_click('refresh')
            self.assert_facet_button_enabled('save', enabled=False)

        # cleanup
        # -------
        self.delete(netgroup.ENTITY, [netgroup.DATA, netgroup.DATA2])
        self.delete(user.ENTITY, [user.DATA, user.DATA2])
        self.delete(group.ENTITY, [group.DATA, group.DATA2])
        self.delete(HOST_ENTITY, [host.data, host.data2])
        self.delete(hostgroup.ENTITY, [hostgroup.DATA, hostgroup.DATA2])
