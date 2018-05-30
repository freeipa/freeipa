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
Password policy tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_group as group
import ipatests.test_webui.data_pwpolicy as pwpolicy
import pytest

try:
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    pass

FIELDS = ['krbmaxpwdlife', 'krbminpwdlife', 'krbpwdhistorylength',
          'krbpwdmindiffchars', 'krbpwdminlength', 'krbpwdmaxfailure',
          'krbpwdfailurecountinterval', 'krbpwdlockoutduration',
          'cospriority']
EXPECTED_ERR = "invalid 'group': cannot delete global password policy"
EXPECTED_MSG = 'Password Policy successfully added'


@pytest.mark.tier1
class test_pwpolicy(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: pwpolicy
        """
        self.init_app()
        self.basic_crud(pwpolicy.ENTITY, pwpolicy.DATA)

    @screenshot
    def test_misc(self):
        """
        various test cases covered in one place
        """
        # Basic requirement : create user group for test
        self.init_app()
        self.navigate_to_entity(group.ENTITY)
        self.add_record(group.ENTITY, [group.DATA, group.DATA2, group.DATA3,
                                       group.DATA_SPECIAL_CHAR_GROUP])

        # add then cancel
        self.add_record(pwpolicy.ENTITY, pwpolicy.DATA1, dialog_btn='cancel')

        # test add and add another record
        self.add_record(pwpolicy.ENTITY, [pwpolicy.DATA1, pwpolicy.DATA2])

        # test add and edit record
        self.add_record(pwpolicy.ENTITY, pwpolicy.DATA,
                        dialog_btn='add_and_edit')

        # test delete multiple records
        self.navigate_to_entity(pwpolicy.ENTITY)
        records = [pwpolicy.DATA, pwpolicy.DATA1, pwpolicy.DATA2]
        self.select_multiple_records(records)
        self.facet_button_click('remove')
        self.dialog_button_click('ok')

        # test add password policy for special characters group
        self.add_record(pwpolicy.ENTITY, pwpolicy.DATA_SPECIAL_CHAR,
                        delete=True)

        # empty group and priority (requires the field)
        self.facet_button_click('add')
        self.dialog_button_click('add')
        self.assert_field_validation_required(field='cn')
        self.assert_field_validation_required(field='cospriority')
        self.close_all_dialogs()

        # test delete default policy and
        # confirming by keyboard to test ticket #4097
        self.select_record(pwpolicy.DEFAULT_POLICY)
        self.facet_button_click('remove')
        self.dialog_button_click('ok')
        self.assert_last_error_dialog(EXPECTED_ERR, details=True)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.TAB)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.assert_record(pwpolicy.DEFAULT_POLICY)

        # test add/delete Passwordpolicy confirming using
        # ENTER key ticket #3200
        self.add_record(pwpolicy.ENTITY, pwpolicy.DATA3, dialog_btn=None)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(d=0.5)
        self.assert_notification(assert_text=EXPECTED_MSG)
        self.assert_record(pwpolicy.PKEY3)
        self.close_notifications()
        self.delete_record(pwpolicy.PKEY3, confirm_btn=None)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(d=0.5)
        self.assert_notification(assert_text='1 item(s) deleted')
        self.assert_record(pwpolicy.PKEY3, negative=True)
        self.close_notifications()

        # cleanup
        self.delete(group.ENTITY, [group.DATA, group.DATA2, group.DATA3,
                                   group.DATA_SPECIAL_CHAR_GROUP])

    @screenshot
    def test_negative_value(self):
        """
        Negative test for Password policy fields in edit page
        """
        self.init_app()
        self.add_record(group.ENTITY, [group.DATA, group.DATA4])
        self.navigate_to_entity(pwpolicy.ENTITY)
        non_interger_expected_error = 'Must be an integer'
        minimum_value_expected_error = 'Minimum value is 0'
        non_integer = 'nonInteger'
        maximum_value = '2147483649'
        minimum_value = '-1'

        self.add_record(pwpolicy.ENTITY, pwpolicy.DATA1,
                        dialog_btn='add_and_edit')

        for field in FIELDS:
            # bigger than max value
            # verifying if field value is more then 20000
            if field == 'krbmaxpwdlife':
                self.check_expected_error(field, 'Maximum value is 20000',
                                          maximum_value)
            # verifying if field value is more then 5
            elif field == 'krbpwdmindiffchars':
                self.check_expected_error(field, 'Maximum value is 5',
                                          maximum_value)
            # verifying if field value is more then 2147483647
            else:
                self.check_expected_error(field, 'Maximum value is 2147483647',
                                          maximum_value)

            # string used instead of integer
            self.check_expected_error(field, non_interger_expected_error,
                                      non_integer)

            # smaller than max value
            self.check_expected_error(field, minimum_value_expected_error,
                                      minimum_value)
        self.navigate_to_entity(pwpolicy.ENTITY)
        self.delete_record(pwpolicy.group.PKEY)

        # Negative test for policy priority
        field_priority = 'cospriority'
        self.add_record(pwpolicy.ENTITY, pwpolicy.DATA7, dialog_btn=None)
        # non integer for policy priority
        self.fill_input(field_priority, non_integer)
        self.assert_field_validation(non_interger_expected_error,
                                     field=field_priority)
        #  lower bound of data range
        self.fill_input(field_priority, minimum_value)
        self.assert_field_validation(minimum_value_expected_error,
                                     field=field_priority)
        # upper bound of data range
        self.fill_input(field_priority, maximum_value)
        self.assert_field_validation(expect_error='Maximum value is'
                                                  ' 2147483647',
                                     field=field_priority)
        self.close_all_dialogs()

        # cleanup
        self.delete(group.ENTITY, [group.DATA, group.DATA4])

    def check_expected_error(self, pwdfield, expected_error, value):
        """
        Validating password policy fields and asserting expected error
        """
        self.fill_textbox(pwdfield, value)
        self.wait_for_request()
        self.assert_field_validation(expected_error, field=pwdfield)
        self.facet_button_click('revert')

    @screenshot
    def test_undo_refresh_revert(self):
        """
        Test to verify undo/refresh/revert
        """
        self.init_app()
        self.add_record(group.ENTITY, [group.DATA6])
        self.add_record(pwpolicy.ENTITY, pwpolicy.DATA_RESET)
        self.navigate_to_record(pwpolicy.PKEY6)

        # test undo
        self.fill_fields(pwpolicy.DATA_RESET['mod'])
        mod_field = 0
        for field in FIELDS:
            modified_value = (pwpolicy.DATA_RESET['mod'][mod_field][2])
            self.click_undo_button(field)
            self.field_equals(field, modified_value)
            mod_field += 1

        # test refresh
        mod_field = 0
        for field in FIELDS:
            self.fill_fields(pwpolicy.DATA_RESET['mod'])
            modified_value = (pwpolicy.DATA_RESET['mod'][mod_field][2])
            self.facet_button_click('refresh')
            self.field_equals(field, modified_value)
            mod_field += 1

        # test revert
        mod_field = 0
        for field in FIELDS:
            self.fill_fields(pwpolicy.DATA_RESET['mod'])
            modified_value = (pwpolicy.DATA_RESET['mod'][mod_field][2])
            self.facet_button_click('revert')
            self.field_equals(field, modified_value)
            mod_field += 1

        # cleanup
        self.navigate_to_entity(pwpolicy.ENTITY)
        self.delete_record(pwpolicy.group.PKEY6)
        self.delete(group.ENTITY, [group.DATA6])

    def field_equals(self, field, mod_value, negative=True):
        """
        comparing current value with modified value
        """
        current_value = self.get_field_value(field, element="input")
        if negative:
            assert current_value != mod_value
        else:
            assert current_value == mod_value

    @screenshot
    def test_verify_measurement_unit(self):
        """
        verifying measurement unit for password policy ticket #2437
        """
        self.init_app()
        self.navigate_to_entity(pwpolicy.ENTITY)
        self.navigate_to_record('global_policy')
        krbmaxpwdlife = self.get_text('label[name="krbmaxpwdlife"]')
        krbminpwdlife = self.get_text('label[name="krbminpwdlife"]')
        krbpwdhistorylen = self.get_text('label[name="krbpwdhistorylength"]')
        krbpwdfailurecountinterval = \
            self.get_text('label[name="krbpwdfailurecountinterval"]')
        krbpwdlockoutduration = \
            self.get_text('label[name="krbpwdlockoutduration"]')
        assert "Max lifetime (days)" in krbmaxpwdlife
        assert "Min lifetime (hours)" in krbminpwdlife
        assert "History size (number of passwords)" in krbpwdhistorylen
        assert "Failure reset interval (seconds)" in krbpwdfailurecountinterval
        assert "Lockout duration (seconds)" in krbpwdlockoutduration
