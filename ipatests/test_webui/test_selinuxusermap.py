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
SELinux user map tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_user as user
import ipatests.test_webui.data_group as group
import ipatests.test_webui.data_selinuxusermap as selinuxmap
import ipatests.test_webui.data_hostgroup as hostgroup
import ipatests.test_webui.data_hbac as hbac
from ipatests.test_webui.test_host import host_tasks, ENTITY as HOST_ENTITY
import pytest

try:
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    pass

RULE_ALR_EXIST = 'SELinux User Map rule with name "{}" already exists'
RULE_UPDATED = 'SELinux User Map {} updated'
RULE_ADDED = 'SELinux User Map successfully added'
INVALID_SEUSER = 'SELinux user {} not found in ordering list (in config)'
INVALID_MCS = ("invalid 'selinuxuser': Invalid MCS value, must match c[0-1023]"
               ".c[0-1023] and/or c[0-1023]-c[0-c0123]")
INVALID_MLS = ("invalid 'selinuxuser': Invalid MLS value, must match "
               "s[0-15](-s[0-15])")
HBAC_DEL_ERR = ('{} cannot be deleted because SELinux User Map {} requires '
                'it')
HBAC_MEMBER_ERR = 'HBAC rule and local members cannot both be set'


@pytest.mark.tier1
class test_selinuxusermap(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: selinuxusermap
        """
        self.init_app()
        self.basic_crud(selinuxmap.ENTITY, selinuxmap.DATA)

    @screenshot
    def test_mod(self):
        """
        Mod: selinuxusermap
        """
        self.init_app()
        host = host_tasks()
        host.driver = self.driver
        host.config = self.config
        host.prep_data()
        host.prep_data2()

        self.add_record(user.ENTITY, user.DATA)
        self.add_record(user.ENTITY, user.DATA2, navigate=False)
        self.add_record(group.ENTITY, group.DATA)
        self.add_record(group.ENTITY, group.DATA2, navigate=False)
        self.add_record(HOST_ENTITY, host.data)
        self.close_notifications()
        self.add_record(HOST_ENTITY, host.data2, navigate=False)
        self.close_notifications()
        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA2, navigate=False)
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA)

        self.navigate_to_record(selinuxmap.PKEY)

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
        for t in tables:
            table = t[0]
            keys = t[1]
            self.add_table_associations(table, [keys[0]], confirm_btn='cancel')

        # cleanup
        # -------
        self.delete(selinuxmap.ENTITY, [selinuxmap.DATA])
        self.delete(user.ENTITY, [user.DATA, user.DATA2])
        self.delete(group.ENTITY, [group.DATA, group.DATA2])
        self.delete(HOST_ENTITY, [host.data, host.data2])
        self.delete(hostgroup.ENTITY, [hostgroup.DATA, hostgroup.DATA2])

    @screenshot
    def test_actions(self):
        """
        Test SELinux user map actions
        """
        self.init_app()

        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA)
        self.navigate_to_record(selinuxmap.PKEY)

        self.disable_action()
        self.enable_action()
        self.delete_action(selinuxmap.ENTITY, selinuxmap.PKEY)

    @screenshot
    def test_misc(self):
        """
        Test various miscellaneous test cases under one roof to save init time
        """
        self.init_app()

        # test add and add another record
        self.add_record(selinuxmap.ENTITY, [selinuxmap.DATA, selinuxmap.DATA2])

        # test delete multiple records
        self.delete_record([selinuxmap.DATA, selinuxmap.DATA2])

        # test add and cancel adding record
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA,
                        dialog_btn='cancel')

        # test add and edit record
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA,
                        dialog_btn='add_and_edit')

        # test add duplicate rule (should FAIL)
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA, negative=True,
                        pre_delete=False)
        self.assert_last_error_dialog(RULE_ALR_EXIST.format(selinuxmap.PKEY))
        self.close_all_dialogs()

        # test add disabled HBAC rule to SElinux rule
        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.navigate_to_record(hbac.RULE_PKEY)
        self.disable_action()
        self.navigate_to_record(selinuxmap.PKEY, entity=selinuxmap.ENTITY)
        self.facet_button_click('refresh')
        self.select_combobox('seealso', hbac.RULE_PKEY)
        self.facet_button_click('save')
        self.wait_for_request()
        self.assert_notification(assert_text=RULE_UPDATED.format(
            selinuxmap.PKEY))
        self.close_all_dialogs()

        # test deleting HBAC rule used in SELinux user map (should FAIL)
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.assert_last_error_dialog(
            HBAC_DEL_ERR.format(hbac.RULE_PKEY, selinuxmap.PKEY), details=True)
        self.close_all_dialogs()
        self.select_record(hbac.RULE_PKEY, unselect=True)

        # test adding user to SELinux map together with HBAC rule (should FAIL)
        self.navigate_to_record(selinuxmap.PKEY, entity=selinuxmap.ENTITY)
        self.add_table_associations('memberuser_user', ['admin'],
                                    negative=True)
        self.assert_last_error_dialog(HBAC_MEMBER_ERR)
        self.close_all_dialogs()

        # test adding HBAC rule together with user (should FAIL)
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA2)
        self.navigate_to_record(selinuxmap.PKEY2)
        self.add_table_associations('memberuser_user', ['admin'],
                                    negative=True)
        self.select_combobox('seealso', hbac.RULE_PKEY)
        self.facet_button_click('save')
        self.assert_last_error_dialog(HBAC_MEMBER_ERR)
        self.close_all_dialogs()

        # test add rule without "SELinux user" (requires the field)
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA_FIELD_REQUIRED,
                        negative=True)
        self.assert_field_validation_required(field='ipaselinuxuser')
        self.close_all_dialogs()

        # test add rule with non-existent SELinux user
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA_NON_EXIST_SEUSER,
                        negative=True)
        self.assert_last_error_dialog(expected_err=INVALID_SEUSER.format(
            selinuxmap.DATA_NON_EXIST_SEUSER['add'][1][2]))
        self.close_all_dialogs()

        # test add invalid MCS
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA_INVALID_MCS,
                        negative=True)
        self.assert_last_error_dialog(expected_err=INVALID_MCS)
        self.close_all_dialogs()

        # test add invalid MLS
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA_INVALID_MLS,
                        negative=True)
        self.assert_last_error_dialog(expected_err=INVALID_MLS)
        self.close_all_dialogs()

        # test search SELinux usermap
        self.find_record(selinuxmap.ENTITY, selinuxmap.DATA)

        # test disable enable multiple SELinux rules
        self.select_multiple_records([selinuxmap.DATA, selinuxmap.DATA2])
        self.facet_button_click('disable')
        self.dialog_button_click('ok')
        self.assert_notification(assert_text='2 item(s) disabled')
        self.close_notifications()
        self.assert_record_value('Disabled',
                                 [selinuxmap.PKEY, selinuxmap.PKEY2],
                                 'ipaenabledflag')
        self.select_multiple_records([selinuxmap.DATA, selinuxmap.DATA2])
        self.facet_button_click('enable')
        self.dialog_button_click('ok')
        self.assert_notification(assert_text='2 item(s) enabled')
        self.close_notifications()
        self.assert_record_value('Enabled',
                                 [selinuxmap.PKEY, selinuxmap.PKEY2],
                                 'ipaenabledflag')
        self.delete(selinuxmap.ENTITY, [selinuxmap.DATA])

        # test add / delete SELinux usermap confirming using ENTER key
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA, dialog_btn=None)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(d=0.5)
        self.assert_notification(assert_text=RULE_ADDED)
        self.assert_record(selinuxmap.PKEY)
        self.close_notifications()
        self.delete_record(selinuxmap.PKEY, confirm_btn=None)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(d=0.5)
        self.assert_notification(assert_text='1 item(s) deleted')
        self.assert_record(selinuxmap.PKEY, negative=True)
        self.close_notifications()

        # cleanup
        self.delete(selinuxmap.ENTITY, [selinuxmap.DATA2])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])

    @screenshot
    def test_add_different_rules(self):
        """
        Test adding different SELinux usermap rules
        """
        self.init_app()

        self.navigate_to_entity('config')
        old_selinux_order = self.get_field_value('ipaselinuxusermaporder')
        new_selinux_order = '{}${}${}${}${}'.format(
            old_selinux_order,
            selinuxmap.DATA_MLS_RANGE['add'][1][2],
            selinuxmap.DATA_MCS_RANGE['add'][1][2],
            selinuxmap.DATA_MCS_COMMAS['add'][1][2],
            selinuxmap.DATA_MLS_SINGLE_VAL['add'][1][2])
        self.fill_input('ipaselinuxusermaporder', new_selinux_order)
        self.facet_button_click('save')

        # test add MLS range rule
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA_MLS_RANGE)
        self.assert_record(selinuxmap.PKEY_MLS_RANGE)

        # test add MCS range rule
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA_MCS_RANGE)
        self.assert_record(selinuxmap.PKEY_MCS_RANGE)

        # test add MCS rule with commas
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA_MCS_COMMAS)
        self.assert_record(selinuxmap.PKEY_MCS_COMMAS)

        # test add MLS single value rule
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA_MLS_SINGLE_VAL)
        self.assert_record(selinuxmap.PKEY_MLS_SINGLE_VAL)

        # restore original SELinux user map order
        self.navigate_to_entity('config')
        self.fill_input('ipaselinuxusermaporder', old_selinux_order)
        self.facet_button_click('save')

        # cleanup
        self.delete(selinuxmap.ENTITY,
                    [selinuxmap.DATA_MLS_RANGE,
                     selinuxmap.DATA_MCS_RANGE,
                     selinuxmap.DATA_MCS_COMMAS,
                     selinuxmap.DATA_MLS_SINGLE_VAL]
                    )

    @screenshot
    def test_undo_refresh_reset_update_cancel(self):
        """
        Test undo/refresh/reset/update/cancel buttons
        """
        self.init_app()

        mod_description = (selinuxmap.DATA['mod'][0][2])

        # test selinux usermap undo button
        self.add_record(selinuxmap.ENTITY, selinuxmap.DATA)
        self.navigate_to_record(selinuxmap.PKEY)
        self.fill_fields(selinuxmap.DATA['mod'])
        self.click_undo_button('description')
        self.verify_btn_action(mod_description)

        # test refresh button
        self.fill_fields(selinuxmap.DATA['mod'], undo=True)
        self.facet_button_click('refresh')
        self.verify_btn_action(mod_description)

        # test reset button
        self.mod_record(selinuxmap.ENTITY, selinuxmap.DATA, facet_btn='revert')
        self.wait_for_request()
        self.verify_btn_action(mod_description)

        # test update button
        self.fill_fields(selinuxmap.DATA['mod'], undo=True)
        self.facet_button_click('refresh')
        self.verify_btn_action(mod_description)

        # test reset button after trying to leave the details page
        self.fill_fields(selinuxmap.DATA2['mod'], undo=True)
        self.click_on_link('SELinux User Maps')
        self.dialog_button_click('revert')
        self.navigate_to_record(selinuxmap.PKEY)
        self.verify_btn_action(mod_description)
        self.wait_for_request(n=2)

        # test update button after trying to leave the details page
        self.fill_fields(selinuxmap.DATA['mod'], undo=True)
        self.click_on_link('SELinux User Maps')
        self.dialog_button_click('save')
        self.navigate_to_record(selinuxmap.PKEY)
        self.verify_btn_action(mod_description, negative=True)
        self.wait_for_request(n=2)

        # cleanup
        self.delete(selinuxmap.ENTITY, [selinuxmap.DATA])

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
