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
Config tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_config as config_data
import ipatests.test_webui.data_user as user_data
import ipatests.test_webui.data_group as group_data
import pytest

try:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
except ImportError:
    pass


ERR_USR_SEARCH_SPACES = ("invalid 'usersearch': Leading and trailing spaces "
                         "are not allowed")
ERR_USR_SEARCH_INV = ("invalid 'ipausersearchfields': attribute {} not "
                      "allowed")
ERR_GRP_SEARCH_SPACES = ("invalid 'groupsearch': Leading and trailing spaces "
                         "are not allowed")
ERR_GRP_SEARCH_INV = ("invalid 'ipagroupsearchfields': attribute {} not "
                      "allowed")
ERR_MAX_CHAR = "invalid 'login': can be at most {} characters"
ERR_HOMEDIR_SPACES = ("invalid 'homedirectory': Leading and trailing spaces "
                      "are not allowed")
ERR_EMAIL_SPACES = ("invalid 'emaildomain': Leading and trailing spaces are "
                    "not allowed")
ERR_SHELL_SPACES = ("invalid 'defaultshell': Leading and trailing spaces are "
                    "not allowed")

LEADING_SPACE = ' leading_space'
TRAILING_SPACE = 'trailing_space '


@pytest.mark.tier1
class test_config(UI_driver):

    def search_by_field(self, field):
        search_field_s = '.search-filter input[name=filter]'
        self.fill_text(search_field_s, field)
        self.action_button_click('find', parent=None)
        self.wait_for_request(n=2)

    def verify_btn_action(self, field, mod_value, negative=False):
        """
        Comparing current field with modified field
        """
        current_value = self.get_field_value(field)

        if negative:
            assert current_value != mod_value
        else:
            assert current_value == mod_value

    def verify_user_cfg_change(self, field, name, multivalued=False):
        """
        Helper function to verify that user config changes were reflected on
        newly created user
        """

        self.add_record(user_data.ENTITY, user_data.DATA2)
        self.navigate_to_record(user_data.DATA2['pkey'])
        if multivalued:
            s = "div[name={0}] input[name={0}-0]".format(field)
        else:
            s = "div[name={0}] input[name={0}]".format(field)
        assert self.get_value(s) == name
        self.delete(user_data.ENTITY, [user_data.DATA2])

    def assert_field_negative(self, field, value, err_msg, dialog=False):
        """
        Helper function for negative field tests
        """
        if value == '':
            field_s = "input[type='text'][name='{}']".format(field)
            input_el = self.find(field_s, By.CSS_SELECTOR,
                                 strict=True)
            input_el.clear()
            input_el.send_keys(Keys.BACKSPACE)
            self.facet_button_click('save')
            self.assert_field_validation(err_msg, field=field)
            self.facet_button_click('revert')
        else:
            self.fill_input(field, value)
            self.facet_button_click('save')
            if dialog:
                self.assert_last_error_dialog(err_msg)
                self.dialog_button_click('cancel')
                self.facet_button_click('revert')
            else:
                self.assert_field_validation(err_msg, field=field)
                self.facet_button_click('revert')

    @screenshot
    def test_mod(self):
        """
        Config mod tests
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        self.mod_record(config_data.ENTITY, config_data.DATA)
        self.mod_record(config_data.ENTITY, config_data.DATA2)

    @screenshot
    def test_size_limits(self):
        """
        Test "Search size limit" field
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        size_limit_s = 'ipasearchrecordslimit'
        def_val = self.get_field_value(size_limit_s)

        # test field with blank field
        self.assert_field_negative(size_limit_s, '',
                                   'Required field')

        # test field with invalid value
        self.assert_field_negative(size_limit_s, 'abc',
                                   'Must be an integer')

        # test field with negative value
        self.assert_field_negative(
            size_limit_s, '-10',
            "invalid 'searchrecordslimit': must be at least 10",
            dialog=True,
        )

        # test field with space
        self.assert_field_negative(size_limit_s, ' 11',
                                   'Must be an integer')

        # test minimum value
        self.fill_input(size_limit_s, '-1')
        self.facet_button_click('save')
        assert self.get_field_value(size_limit_s) == '-1'

        # restore previous value
        self.fill_input(size_limit_s, def_val)
        self.facet_button_click('save')

    @screenshot
    def test_time_limits(self):
        """
        Test "Search time limit" field
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        time_limit_s = 'ipasearchtimelimit'
        def_val = self.get_field_value(time_limit_s)

        # test field with blank field
        self.assert_field_negative(time_limit_s, '',
                                   'Required field')

        # test field with invalid value
        self.assert_field_negative(time_limit_s, 'abc',
                                   'Must be an integer')

        # test field with negative value
        self.assert_field_negative(time_limit_s, '-10',
                                   'Minimum value is -1')

        # test field with space
        self.assert_field_negative(time_limit_s, ' 11',
                                   'Must be an integer')

        # test no limit (-1) can be set
        self.fill_input(time_limit_s, '-1')
        self.facet_button_click('save')
        assert self.get_field_value(time_limit_s) == '-1'

        # restore previous value
        self.fill_input(time_limit_s, def_val)
        self.facet_button_click('save')

    @screenshot
    def test_username_lenght(self):
        """
        Test "Maximum username length" field
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        usr_length_s = 'ipamaxusernamelength'
        def_val = self.get_field_value(usr_length_s)

        # test field with blank field
        self.assert_field_negative(usr_length_s, '',
                                   'Required field')

        # test field with invalid value
        self.assert_field_negative(usr_length_s, 'abc',
                                   'Must be an integer')

        # test field with exceeding value
        self.assert_field_negative(usr_length_s, '9999',
                                   'Maximum value is 255')

        # test field with space in-between numbers
        self.assert_field_negative(usr_length_s, '1 2',
                                   'Must be an integer')

        # test field with special char
        self.assert_field_negative(usr_length_s, '*',
                                   'Must be an integer')

        # test if change of value is reflected
        self.fill_input(usr_length_s, 3)
        self.facet_button_click('save')
        self.add_record(user_data.ENTITY, user_data.DATA, negative=True)
        self.assert_last_error_dialog(ERR_MAX_CHAR.format(3))
        self.close_all_dialogs()
        self.navigate_to_entity(config_data.ENTITY)

        # restore previous value
        self.fill_input(usr_length_s, def_val)
        self.facet_button_click('save')

    @screenshot
    def test_passwd_exp_notice(self):
        """
        Test "Password Expiration Notification" field
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        exp_notice_s = 'ipapwdexpadvnotify'

        # test field with blank field
        self.assert_field_negative(exp_notice_s, '',
                                   'Required field')

        # test field with invalid value
        self.assert_field_negative(exp_notice_s, 'abc',
                                   'Must be an integer')

        # test field with exceeding value
        self.assert_field_negative(exp_notice_s, '9999999999',
                                   'Maximum value is 2147483647')

        # test field with space in-between numbers
        self.assert_field_negative(exp_notice_s, '1 2',
                                   'Must be an integer')

        # test field with special char
        self.assert_field_negative(exp_notice_s, '*',
                                   'Must be an integer')

    @screenshot
    def test_group_search_field(self):
        """
        Test "Group search fields"
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        group_search_s = 'ipagroupsearchfields'
        def_val = self.get_field_value(group_search_s)

        # test field with blank field
        self.assert_field_negative(group_search_s, '',
                                   'Required field')

        # test field with invalid value
        self.assert_field_negative(group_search_s, 'abc',
                                   ERR_GRP_SEARCH_INV.format('"abc"'),
                                   dialog=True)

        # test field with leading space
        self.assert_field_negative(group_search_s, LEADING_SPACE,
                                   ERR_GRP_SEARCH_SPACES, dialog=True)

        # test field with trailing space
        self.assert_field_negative(group_search_s, TRAILING_SPACE,
                                   ERR_GRP_SEARCH_SPACES, dialog=True)

        # test default values are ok
        assert config_data.GRP_SEARCH_FIELD_DEFAULT == def_val

    @screenshot
    def test_user_search_field(self):
        """
        Test "User search fields"
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)
        user_search_s = 'ipausersearchfields'
        def_val = self.get_field_value(user_search_s)

        # test field with blank field
        self.assert_field_negative(user_search_s, '',
                                   'Required field')

        # test field with invalid value
        self.assert_field_negative(user_search_s, 'abc',
                                   ERR_USR_SEARCH_INV.format('"abc"'),
                                   dialog=True)

        # test field with leading space
        self.assert_field_negative(user_search_s, LEADING_SPACE,
                                   ERR_USR_SEARCH_SPACES, dialog=True)

        # test field with trailing space
        self.assert_field_negative(user_search_s, TRAILING_SPACE,
                                   ERR_USR_SEARCH_SPACES, dialog=True)

        # test if changing "User search fields" is being reflected
        self.fill_input(user_search_s, 'postalcode')
        self.facet_button_click('save')
        self.close_all_dialogs()
        self.add_record(user_data.ENTITY, user_data.DATA2)
        self.navigate_to_record(user_data.DATA2['pkey'])
        self.mod_record(user_data.ENTITY, user_data.DATA2)
        self.navigate_to_entity(user_data.ENTITY)
        self.search_by_field(user_data.DATA2['mod'][2][2])
        self.assert_record(user_data.DATA2['pkey'])
        self.delete(user_data.ENTITY, [user_data.DATA2])
        self.navigate_to_entity(config_data.ENTITY)

        # restore previous value
        self.fill_input(user_search_s, def_val)
        self.facet_button_click('save')

    @screenshot
    def test_user_homedir_field(self):
        """
        Test "Home directory base" field
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)
        homedir_s = 'ipahomesrootdir'
        def_val = self.get_field_value(homedir_s)

        # test field with blank field
        self.assert_field_negative(homedir_s, '',
                                   'Required field')

        # test field with leading space
        self.assert_field_negative(homedir_s, LEADING_SPACE,
                                   ERR_HOMEDIR_SPACES, dialog=True)

        # test field with trailing space
        self.assert_field_negative(homedir_s, TRAILING_SPACE,
                                   ERR_HOMEDIR_SPACES, dialog=True)

        # test field with special chars
        self.fill_input(homedir_s, '^&/*)(h*o@m%e/!u^s:e~r`s')
        self.facet_button_click('save')
        self.verify_user_cfg_change('homedirectory', '{}/{}'.format(
            '^&/*)(h*o@m%e/!u^s:e~r`s', user_data.DATA2['pkey']))

        # test field with numbers
        self.navigate_to_entity(config_data.ENTITY)
        self.fill_input(homedir_s, '1/home2/3users4')
        self.facet_button_click('save')
        self.verify_user_cfg_change('homedirectory', '{}/{}'.format(
            '1/home2/3users4', user_data.DATA2['pkey']))

        # test field with spaces in between
        self.navigate_to_entity(config_data.ENTITY)
        self.fill_input(homedir_s, '12 34')
        self.facet_button_click('save')
        self.verify_user_cfg_change('homedirectory', '{}/{}'.format(
            '12 34', user_data.DATA2['pkey']))

        # restore previous value
        self.navigate_to_entity(config_data.ENTITY)
        self.fill_input(homedir_s, def_val)
        self.facet_button_click('save')

    @screenshot
    def test_user_email_field(self):
        """
        Test "Default e-mail domain" field
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)
        def_mail_s = 'ipadefaultemaildomain'
        def_val = self.get_field_value(def_mail_s)

        # test field with leading space
        self.assert_field_negative(def_mail_s, LEADING_SPACE,
                                   ERR_EMAIL_SPACES, dialog=True)

        # test field with trailing space
        self.assert_field_negative(def_mail_s, TRAILING_SPACE,
                                   ERR_EMAIL_SPACES, dialog=True)

        # test if changing "Default e-mail domain" is being reflected
        self.fill_input(def_mail_s, 'ipaui.test')
        self.facet_button_click('save')
        new_email = '{}@ipaui.test'.format(user_data.DATA2['pkey'])
        self.verify_user_cfg_change('mail', new_email, multivalued=True)

        # restore previous value
        self.navigate_to_entity(config_data.ENTITY)
        self.fill_input(def_mail_s, def_val)
        self.facet_button_click('save')

    @screenshot
    def test_user_default_shell(self):
        """
        Test "Default shell" field
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        def_shell_s = 'ipadefaultloginshell'
        def_val = self.get_field_value(def_shell_s)

        # test field with blank field
        self.assert_field_negative(def_shell_s, '',
                                   'Required field')

        # test field with leading space
        self.assert_field_negative(def_shell_s, LEADING_SPACE,
                                   ERR_SHELL_SPACES, dialog=True)

        # test field with trailing space
        self.assert_field_negative(def_shell_s, TRAILING_SPACE,
                                   ERR_SHELL_SPACES, dialog=True)

        # test if changing "Default e-mail domain" is being reflected
        self.fill_input(def_shell_s, '/bin/supershell')
        self.facet_button_click('save')
        self.verify_user_cfg_change('loginshell', '/bin/supershell')

        # restore previous value
        self.navigate_to_entity(config_data.ENTITY)
        self.fill_input(def_shell_s, def_val)
        self.facet_button_click('save')

    @screenshot
    def test_undo_reset(self):
        """
        Test undo and reset buttons
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        group_search_s = 'ipagroupsearchfields'

        # test selinux usermap undo button
        self.fill_input(group_search_s, 'test_string')
        self.click_undo_button(group_search_s)
        self.verify_btn_action(group_search_s, 'test_string', negative=True)

        # test revert button
        self.fill_input(group_search_s, 'test_string')
        self.facet_button_click('revert')
        self.verify_btn_action(group_search_s, 'test_string', negative=True)

    @screenshot
    def test_default_user_group(self):
        """
        Test "Default users group" field
        """
        self.init_app()
        def_usr_grp_s = 'ipadefaultprimarygroup'

        self.add_record(group_data.ENTITY, group_data.DATA)
        self.navigate_to_entity(config_data.ENTITY)
        self.select_combobox(def_usr_grp_s, group_data.DATA['pkey'])
        self.facet_button_click('save')
        self.add_record(user_data.ENTITY, user_data.DATA2)
        self.navigate_to_entity(group_data.ENTITY)
        self.navigate_to_record(group_data.DATA['pkey'])
        self.assert_record(user_data.DATA2['pkey'])
        self.delete(user_data.ENTITY, [user_data.DATA2])

        # restore previous value
        self.navigate_to_entity(config_data.ENTITY)
        self.select_combobox(def_usr_grp_s, 'ipausers')
        self.facet_button_click('save')
        self.delete(group_data.ENTITY, [group_data.DATA])

    @screenshot
    def test_misc(self):
        """
        Test various miscellaneous cases under one roof
        """
        self.init_app()
        self.navigate_to_entity(config_data.ENTITY)

        # test we can switch migration mode (enabled/disabled)
        self.check_option('ipamigrationenabled', 'checked')
        self.facet_button_click('save')
        assert self.get_field_checked('ipamigrationenabled')
        self.check_option('ipamigrationenabled', 'checked')
        self.facet_button_click('save')
        assert not self.get_field_checked('ipamigrationenabled')
