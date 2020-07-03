# Authors:
#   Richard Kalinec <rkalinec@gmail.com>
#
# Copyright (C) 2020  Red Hat
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
Apppw tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_apppw as apppw
import pytest

try:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    pass

APPPW_EXIST = 'app password with uid "{}" already exists'
APPPW_ADDED = 'App password successfully added'
FIELD_REQ = 'Required field'
ERR_BE_UID = 'may only be numbers 0 - 99'
ERR_SPACES_UID = "invalid 'uid': Leading and trailing spaces are not allowed"
ERR_INCLUDE_APPNAME = 'may only include letters, numbers, _, - and $'
ERR_SPACES_APPNAME = ("invalid 'appname': Leading and trailing spaces are "
                      "not allowed")


@pytest.mark.tier1
class apppw_tasks(UI_driver):
    def load_file(self, path):
        with open(path, 'r') as file_d:
            content = file_d.read()
        return content


@pytest.mark.tier1
class test_apppw(apppw_tasks):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: apppw
        """
        self.init_app()
        self.basic_crud(apppw.ENTITY, apppw.DATA)
        self.basic_crud(apppw.ENTITY, apppw.DATA2)

    @screenshot
    def test_actions(self):
        """
        Test apppw actions
        """
        self.init_app()

        self.add_record(apppw.ENTITY, apppw.DATA, navigate=False)
        self.navigate_to_record(apppw.PKEY)
        self.delete_action(apppw.ENTITY, apppw.PKEY, action='delete_apppw')

        self.add_record(apppw.ENTITY, apppw.DATA2, navigate=False)
        self.navigate_to_record(apppw.PKEY2)
        self.delete_action(apppw.ENTITY, apppw.PKEY2, action='delete_apppw')

    @screenshot
    def test_add_apppw_special(self):
        """
        Test various add app password special cases
        """

        self.init_app()

        # Test invalid uid
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_textbox('uid', apppw.PKEY_UID_TOO_HIGH)
        self.assert_field_validation(ERR_BE_UID)
        self.fill_textbox('uid', apppw.PKEY_UID_WITH_LOWERCASE_AND_TOO_LONG)
        self.assert_field_validation(ERR_BE_UID)
        self.fill_textbox('uid', apppw.PKEY_UID_WITH_UPPERCASE)
        self.assert_field_validation(ERR_BE_UID)
        self.fill_textbox('uid', apppw.PKEY_UID_LEAD_ZERO_1)
        self.assert_field_validation(ERR_BE_UID)
        self.fill_textbox('uid', apppw.PKEY_UID_LEAD_ZERO_2)
        self.assert_field_validation(ERR_BE_UID)
        self.dialog_button_click('cancel')

        # click add and cancel
        self.add_record(apppw.ENTITY, apppw.DATA, dialog_btn='cancel')

        # add leading space before uid (should FAIL)
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(apppw.DATA_UID_LEAD_SPACE['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(ERR_SPACES_UID)
        self.close_all_dialogs()

        # add trailing space after uid (should FAIL)
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(apppw.DATA_UID_TRAIL_SPACE['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(ERR_SPACES_UID)
        self.close_all_dialogs()

        # add app password with dots in appname (should FAIL)
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(apppw.DATA_APPNAME_WITH_DOTS['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(ERR_INCLUDE_APPNAME)
        self.close_all_dialogs()

        # add leading space before app name (should FAIL)
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(apppw.DATA_APPNAME_LEAD_SPACE['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(ERR_SPACES_APPNAME)
        self.close_all_dialogs()

        # add trailing space before app name (should FAIL)
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(apppw.DATA_APPNAME_TRAIL_SPACE['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(ERR_SPACES_APPNAME)
        self.close_all_dialogs()

        # add app password using enter
        self.add_record(apppw.ENTITY, apppw.DATA2, negative=True)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait()
        self.assert_notification(assert_text=APPPW_ADDED)
        self.assert_record(apppw.PKEY2)
        self.close_notifications()

        # delete app password using enter
        self.select_record(apppw.PKEY2)
        self.facet_button_click('remove')
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.assert_notification(assert_text='1 item(s) deleted')
        self.assert_record(apppw.PKEY2, negative=True)

    @screenshot
    def test_apppw_misc(self):
        """
        Test various miscellaneous test cases under one roof to save init time
        """
        self.init_app()

        # add already existing app password (should FAIL)
        self.add_record(apppw.ENTITY, apppw.DATA)
        self.add_record(apppw.ENTITY, apppw.DATA, negative=True,
                        pre_delete=False)
        self.assert_last_error_dialog(APPPW_EXIST.format(apppw.PKEY))
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.TAB)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.dialog_button_click('cancel')

        # try with blank uid (should FAIL)
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(apppw.DATA_NO_UID['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(FIELD_REQ)
        self.close_all_dialogs()

        # try with blank description (should FAIL)
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(apppw.DATA_NO_DESCRIPTION['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(FIELD_REQ)
        self.close_all_dialogs()

        # try with blank appname (should FAIL)
        self.navigate_to_entity(apppw.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(apppw.DATA_NO_APPNAME['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(FIELD_REQ)
        self.close_all_dialogs()

        # search app password / multiple app passwords
        self.navigate_to_entity(apppw.ENTITY)
        self.wait(0.5)
        self.find_record('apppw', apppw.DATA)
        self.add_record(apppw.ENTITY, apppw.DATA2)
        self.find_record('apppw', apppw.DATA2)
        # search for both app passwords (just the first one will do)
        self.find_record('apppw', apppw.DATA)
        self.assert_record(apppw.PKEY2)

        # cleanup
        self.delete_record([apppw.PKEY, apppw.PKEY2])

    @screenshot
    def test_menu_click_minimized_window(self):
        """
        Test if menu is clickable when there is notification
        in minimized browser window.

        related: https://pagure.io/freeipa/issue/8120
        """
        self.init_app()

        self.driver.set_window_size(570, 600)
        self.add_record(apppw.ENTITY, apppw.DATA2, negative=True)
        self.assert_notification(assert_text=APPPW_ADDED)
        menu_button = self.find('.navbar-toggle', By.CSS_SELECTOR)
        menu_button.click()
        self.assert_record(apppw.PKEY2)
        self.close_notifications()
        self.driver.maximize_window()

        # cleanup
        self.delete(apppw.ENTITY, [apppw.DATA2])
