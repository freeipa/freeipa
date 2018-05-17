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
Selfservice tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_selfservice as data_selfservice
import ipatests.test_webui.data_user as user
import pytest

try:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    pass

ENTRY_EXIST = 'This entry already exists'
FIELD_REQ = 'Required field'
INV_NAME = ("invalid 'name': Leading and trailing spaces are "
            "not allowed")
ERR_INCLUDE = 'May only contain letters, numbers, -, _, and space'
SERVICE_ADDED = 'Self Service Permission successfully added'


def reset_passwd(self, login, pwd):
            self.navigate_to_entity(user.ENTITY)
            self.navigate_to_record(login)
            self.action_list_action('reset_password', False)
            self.fill_password('password', pwd)
            self.fill_password('password2', pwd)
            self.dialog_button_click('confirm')


@pytest.mark.tier1
class test_selfservice(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: selfservice entity
        """
        self.init_app()
        self.basic_crud(data_selfservice.ENTITY, data_selfservice.DATA)

    @screenshot
    def test_add_all_attr(self):
        """
        Add self service with all attribute
        """
        self.init_app()
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA_ALL,
                        delete=True)

    @screenshot
    def test_add_scenarios(self):
        """
        Test various add scenarios
        """

        # Add self service with Add and Add Another button
        self.init_app()
        records = [data_selfservice.DATA, data_selfservice.DATA1]
        self.add_record(data_selfservice.ENTITY, records)

        # check if record is added
        for record in records:
            self.assert_record(record['pkey'])

        # cleanup
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.select_multiple_records(records)
        self.facet_button_click('remove')
        self.dialog_button_click('ok')
        for record in records:
            self.assert_record(record['pkey'], negative=True)

        # Add self service with Add and edit button
        self.add_record(data_selfservice.ENTITY,
                        data_selfservice.DATA1,
                        dialog_btn='add_and_edit')

        # cleanup
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.delete(data_selfservice.ENTITY, [data_selfservice.DATA1])

        # Add self service with Add and cancel button
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA1,
                        dialog_btn='cancel')

    @screenshot
    def test_undo_reset(self):
        """
        Test undo and reset operation
        """
        # Add self service permission and perform undo
        self.init_app()
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA1)
        self.navigate_to_record(data_selfservice.PKEY1)
        self.fill_fields(data_selfservice.DATA2)
        self.click_undo_button('attrs')
        self.wait_for_request()
        # if undo succeed, 'save' button remains disabled
        self.assert_facet_button_enabled('save', enabled=False)

        # Add self service permission and perform reset
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA1)
        self.navigate_to_record(data_selfservice.PKEY1)
        self.fill_fields(data_selfservice.DATA2)
        self.facet_button_click('revert')
        # if revert succeed, 'save' button remains disabled
        self.assert_facet_button_enabled('save', enabled=False)

    @screenshot
    def test_permission_negative(self):
        """
        Negative test cases for self service permission
        """
        self.init_app()

        # try to add duplicate entry
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA1)
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA1,
                        negative=True, pre_delete=False)
        self.assert_last_error_dialog(ENTRY_EXIST)
        self.close_all_dialogs()
        self.delete(data_selfservice.ENTITY, [data_selfservice.DATA1])
        self.close_notifications()

        # try to add permission without name and attribute
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.wait_for_request()
        self.facet_button_click('add')
        self.dialog_button_click('add')
        self.assert_field_validation(FIELD_REQ, field='aciname')
        self.dialog_button_click('cancel')

        # try to add permission without name but having attribute
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.wait_for_request()
        self.facet_button_click('add')
        self.check_option('attrs', 'displayname')
        self.dialog_button_click('add')
        self.assert_field_validation(FIELD_REQ, field='aciname')
        self.dialog_button_click('cancel')

        # try to add permission without having attribute.
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.wait_for_request()
        self.facet_button_click('add')
        self.fill_textbox('aciname', data_selfservice.DATA1['pkey'])
        self.dialog_button_click('add')
        self.assert_field_validation(FIELD_REQ, field='attrs')
        self.dialog_button_click('cancel')

        # try to add aciname with leading space.
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.wait_for_request()
        self.facet_button_click('add')
        self.fill_textbox('aciname',
                          ' {}'.format(data_selfservice.DATA1['pkey']))
        self.check_option('attrs', 'audio')
        self.dialog_button_click('add')
        self.assert_last_error_dialog(INV_NAME)
        self.close_all_dialogs()

        # try to add aciname with trailing space
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.wait_for_request()
        self.facet_button_click('add')
        self.fill_textbox('aciname',
                          '{} '.format(data_selfservice.DATA1['pkey']))
        self.check_option('attrs', 'audio')
        self.dialog_button_click('add')
        self.assert_last_error_dialog(INV_NAME)
        self.dialog_button_click('cancel')
        self.dialog_button_click('cancel')

        # try to add aciname with special char
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.wait_for_request()
        self.facet_button_click('add')
        self.fill_textbox('aciname', '#%^')
        self.dialog_button_click('add')
        self.assert_field_validation(ERR_INCLUDE, field='aciname')
        self.dialog_button_click('cancel')

        # try to modify pesmission by removing all attributes
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA1)
        self.navigate_to_record(data_selfservice.DATA1['pkey'])
        self.check_option('attrs', 'businesscategory')
        self.facet_button_click('save')
        self.assert_field_validation(FIELD_REQ, field='attrs')

    @screenshot
    def test_del_multiple_permission(self):
        """
        Try to delete multiple self service permission
        """
        self.init_app()
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA1)
        self.add_record(data_selfservice.ENTITY, data_selfservice.DATA)
        self.delete(data_selfservice.ENTITY,
                    [data_selfservice.DATA1,
                     data_selfservice.DATA])
        # check if record deleted
        for key in [data_selfservice.DATA1['pkey'],
                    data_selfservice.DATA['pkey']]:
            self.assert_record(key, negative=True)

    @screenshot
    def test_permission_using_enter_key(self):
        """
        Try to add/delete persmission using enter key
        """
        # try to add using enter key
        self.init_app()
        self.add_record(data_selfservice.ENTITY,
                        data_selfservice.DATA1,
                        dialog_btn=None)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait()
        self.assert_notification(assert_text=SERVICE_ADDED)
        self.assert_record(data_selfservice.DATA1['pkey'])
        self.close_notifications()

        # try to delete using enter key
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.select_record(data_selfservice.DATA1['pkey'])
        self.facet_button_click('remove')
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait()
        self.assert_notification(assert_text='1 item(s) deleted')
        self.close_notifications()

    @screenshot
    def test_reset_sshkey_permsission(self):
        """
        Try to delete sshkey after altering sshkey permission
        """
        pwd = self.config.get('ipa_password')

        self.init_app()
        self.add_record(user.ENTITY, user.DATA, navigate=False)
        reset_passwd(self, user.PKEY, pwd)
        self.logout()
        self.login(user.PKEY, password=pwd, new_password=pwd)
        self.add_sshkey_to_record(user.SSH_RSA, user.PKEY, navigate=True)
        self.assert_num_ssh_keys(1)
        self.close_notifications()
        self.logout()

        self.init_app()
        self.navigate_to_entity(data_selfservice.ENTITY)
        self.navigate_to_record('Users can manage their own SSH public keys')
        # to pass the validator, check some option from the options
        self.check_option('attrs', 'carlicense')
        # uncheck the ipasshpubkey checkbox.
        self.check_option('attrs', 'ipasshpubkey')
        self.facet_button_click('save')
        self.close_notifications()
        self.logout()

        # check if delete button is visible for ssh key.
        self.login(user.PKEY, password=pwd)
        s = "div[name='ipasshpubkey'].multivalued-widget"
        facet = self.get_facet()
        btn = self.find(s, By.CSS_SELECTOR, facet, strict=True)
        assert btn.is_displayed is not True
