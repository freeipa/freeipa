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
User tests
"""

from ipatests.test_webui.crypto_utils import generate_csr
from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_user as user
import ipatests.test_webui.data_group as group
import ipatests.test_webui.data_netgroup as netgroup
import ipatests.test_webui.data_hbac as hbac
import ipatests.test_webui.test_rbac as rbac
import ipatests.test_webui.data_sudo as sudo
import pytest

try:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    pass

EMPTY_MOD = 'no modifications to be performed'
USR_EXIST = 'user with name "{}" already exists'
USR_ADDED = 'User successfully added'
INVALID_SSH_KEY = "invalid 'sshpubkey': invalid SSH public key"
INV_FIRSTNAME = ("invalid 'first': Leading and trailing spaces are "
                 "not allowed")
FIELD_REQ = 'Required field'
ERR_INCLUDE = 'may only include letters, numbers, _, -, . and $'
ERR_MISMATCH = 'Passwords must match'
ERR_ADMIN_DEL = ('admin cannot be deleted or disabled because it is the last '
                 'member of group admins')
USR_EXIST = 'user with name "{}" already exists'
ENTRY_EXIST = 'This entry already exists'
ACTIVE_ERR = 'active user with name "{}" already exists'
DISABLED = 'This entry is already disabled'
LONG_LOGIN = "invalid 'login': can be at most 32 characters"
INV_PASSWD = ("invalid 'password': Leading and trailing spaces are "
              "not allowed")

@pytest.mark.tier1
class user_tasks(UI_driver):
    def load_file(self, path):
        with open(path, 'r') as file_d:
            content = file_d.read()
        return content

    def create_email_addr(self, pkey):
        """
        Piece an email address together from hostname due possible different
        DNS setup
        """

        domain = '.'.join(self.config.get('ipa_server').split('.')[1:])
        return '{}@{}'.format(pkey, domain)

    def add_default_email_for_validation(self, data):
        """
        E-mail is generated automatically and we do not know domain yet in
        data_user so in order to validate all mail fields we need to get it
        there.
        """
        mail = self.create_email_addr(user.DATA.get('pkey'))

        for ele in data['mod_v']:
            if 'mail' in ele:
                ele[2].append(mail)

        return data


@pytest.mark.tier1
class test_user(user_tasks):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: user
        """
        self.init_app()
        data = self.add_default_email_for_validation(user.DATA)
        self.basic_crud(user.ENTITY, data)

    @screenshot
    def test_associations(self):
        """
        User direct associations
        """

        self.init_app()

        # prepare - add user, group, netgroup, role, hbac rule, sudo rule
        # ---------------------------------------------------------------
        self.add_record(user.ENTITY, user.DATA, navigate=False)
        self.add_record(group.ENTITY, group.DATA)
        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.add_record(rbac.ROLE_ENTITY, rbac.ROLE_DATA)
        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)

        # add & remove associations
        # -------------------------
        self.navigate_to_entity(user.ENTITY)
        self.navigate_to_record(user.PKEY)

        self.add_associations([group.PKEY, 'editors'], facet='memberof_group', delete=True)
        self.add_associations([netgroup.PKEY], facet='memberof_netgroup', delete=True)
        self.add_associations([rbac.ROLE_PKEY], facet='memberof_role', delete=True)
        self.add_associations([hbac.RULE_PKEY], facet='memberof_hbacrule', delete=True)
        self.add_associations([sudo.RULE_PKEY], facet='memberof_sudorule', delete=True)

        # cleanup
        # -------
        self.delete(user.ENTITY, [user.DATA])
        self.delete(group.ENTITY, [group.DATA])
        self.delete(netgroup.ENTITY, [netgroup.DATA])
        self.delete(rbac.ROLE_ENTITY, [rbac.ROLE_DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])

    @screenshot
    def test_indirect_associations(self):
        """
        User indirect associations
        """
        self.init_app()

        # add
        # ---
        self.add_record(user.ENTITY, user.DATA, navigate=False)

        self.add_record(group.ENTITY, group.DATA)
        self.navigate_to_record(group.PKEY)
        self.add_associations([user.PKEY])

        self.add_record(group.ENTITY, group.DATA2)
        self.navigate_to_record(group.PKEY2)
        self.add_associations([group.PKEY], facet='member_group')

        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.navigate_to_record(netgroup.PKEY)
        self.add_table_associations('memberuser_group', [group.PKEY2])

        self.add_record(rbac.ROLE_ENTITY, rbac.ROLE_DATA)
        self.navigate_to_record(rbac.ROLE_PKEY)
        self.add_associations([group.PKEY2], facet='member_group')

        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.navigate_to_record(hbac.RULE_PKEY)
        self.add_table_associations('memberuser_group', [group.PKEY2])

        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)
        self.navigate_to_record(sudo.RULE_PKEY)
        self.add_table_associations('memberuser_group', [group.PKEY2])

        # check indirect associations
        # ---------------------------
        self.navigate_to_entity(user.ENTITY, 'search')
        self.navigate_to_record(user.PKEY)

        self.assert_indirect_record(group.PKEY2, user.ENTITY, 'memberof_group')
        self.assert_indirect_record(netgroup.PKEY, user.ENTITY, 'memberof_netgroup')
        self.assert_indirect_record(rbac.ROLE_PKEY, user.ENTITY, 'memberof_role')
        self.assert_indirect_record(hbac.RULE_PKEY, user.ENTITY, 'memberof_hbacrule')
        self.assert_indirect_record(sudo.RULE_PKEY, user.ENTITY, 'memberof_sudorule')

        ## cleanup
        ## -------
        self.delete(user.ENTITY, [user.DATA])
        self.delete(group.ENTITY, [group.DATA, group.DATA2])
        self.delete(netgroup.ENTITY, [netgroup.DATA])
        self.delete(rbac.ROLE_ENTITY, [rbac.ROLE_DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])

    @screenshot
    def test_actions(self):
        """
        Test user actions
        """
        self.init_app()

        self.add_record(user.ENTITY, user.DATA, navigate=False)
        self.navigate_to_record(user.PKEY)

        self.disable_action()
        self.enable_action()

        # reset password
        pwd = self.config.get('ipa_password')
        self.reset_password_action(pwd)
        self.assert_text_field('has_password', '******')

        # unlock option should be disabled for new user
        self.assert_action_list_action('unlock', enabled=False)

        # delete
        self.delete_action(user.ENTITY, user.PKEY, action='delete_active_user')

    @screenshot
    def test_certificates(self):
        """
        Test user certificate actions

        Requires to have CA installed.
        """

        if not self.has_ca():
            self.skip('CA is not configured')

        self.init_app()
        cert_widget_sel = "div.certificate-widget"

        self.add_record(user.ENTITY, user.DATA)
        self.wait()
        self.close_notifications()
        self.navigate_to_record(user.PKEY)

        # cert request
        csr = generate_csr(user.PKEY, False)

        self.action_list_action('request_cert', confirm=False)
        self.wait(seconds=2)
        self.assert_dialog()
        self.fill_text("textarea[name='csr']", csr)
        self.dialog_button_click('issue')
        self.wait_for_request(n=2, d=3)
        self.assert_visible(cert_widget_sel)

        # cert view
        self.action_list_action('view', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.assert_dialog()
        self.dialog_button_click('close')

        # cert get
        self.action_list_action('get', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.assert_dialog()
        # check that the textarea is not empty
        self.assert_empty_value('textarea.certificate', negative=True)
        self.dialog_button_click('close')

        # cert download - we can only try to click the download action
        self.action_list_action('download', confirm=False,
                                parents_css_sel=cert_widget_sel)

        # check that revoke action is enabled
        self.assert_action_list_action('revoke',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action('remove_hold', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cert revoke
        self.action_list_action('revoke', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.select('select', '6')
        self.dialog_button_click('ok')
        self.wait_for_request(n=2, d=3)
        self.assert_visible(cert_widget_sel + " div.watermark")

        # check that revoke action is not enabled
        self.assert_action_list_action('revoke', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is enabled
        self.assert_action_list_action('remove_hold',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cert remove hold
        self.action_list_action('remove_hold', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.dialog_button_click('ok')
        self.wait_for_request(n=2)

        # check that revoke action is enabled
        self.assert_action_list_action('revoke',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action('remove_hold', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cleanup
        self.navigate_to_entity(user.ENTITY, 'search')
        self.delete_record(user.PKEY, user.DATA.get('del'))

    @screenshot
    def test_password_expiration_notification(self):
        """
        Test password expiration notification
        """

        pwd = self.config.get('ipa_password')

        self.init_app()

        self.set_ipapwdexpadvnotify('15')

        # create user and group and add user to that group
        self.add_record(user.ENTITY, user.DATA)
        self.add_record(group.ENTITY, group.DATA)
        self.navigate_to_entity(group.ENTITY)
        self.navigate_to_record(group.PKEY)
        self.add_associations([user.PKEY])

        # password policy for group
        self.add_record('pwpolicy', {
            'pkey': group.PKEY,
            'add': [
                ('combobox', 'cn', group.PKEY),
                ('textbox', 'cospriority', '12345'),
            ]})
        self.navigate_to_record(group.PKEY)
        self.mod_record('pwpolicy', {
            'pkey': group.PKEY,
            'mod': [
                ('textbox', 'krbmaxpwdlife', '7'),
                ('textbox', 'krbminpwdlife', '0'),
            ]})

        # reset password
        self.navigate_to_record(user.PKEY, entity=user.ENTITY)
        self.reset_password_action(pwd)

        #re-login as new user
        self.logout()
        self.init_app(user.PKEY, pwd)

        header = self.find('.navbar-pf', By.CSS_SELECTOR)
        self.assert_text(
            '.header-passwordexpires',
            'Your password expires in 6 days.',
            header)

        # test password reset
        self.profile_menu_action('password_reset')
        self.fill_password_dialog(pwd, pwd)

        # cleanup
        self.logout()
        self.init_app()
        self.set_ipapwdexpadvnotify('4')
        self.delete(user.ENTITY, [user.DATA])
        self.delete(group.ENTITY, [group.DATA])

    def set_ipapwdexpadvnotify(self, days):
        """
        Set ipa config "Password Expiration Notification (days)" field
        """

        self.navigate_to_entity('config')
        self.mod_record('config', {
            'mod': [
                ('textbox', 'ipapwdexpadvnotify', days),
            ]
        })

    def reset_password_action(self, password):
        """
        Execute reset password action
        """

        self.action_list_action('reset_password', False)
        self.fill_password_dialog(password)

    def fill_password_dialog(self, password, current=None):
        """
        Fill password dialog
        """

        self.assert_dialog()

        fields = [
            ('password', 'password', password),
            ('password', 'password2', password),
        ]

        if current:
            fields.append(('password', 'current_password', current))

        self.fill_fields(fields)
        self.dialog_button_click('confirm')
        self.wait_for_request(n=3)
        self.assert_no_error_dialog()

    @screenshot
    def test_login_without_username(self):
        """
        Try to login with no username provided
        """
        self.init_app(login='', password='xxx123')

        alert_e = self.find('.alert[data-name="username"]',
                            By.CSS_SELECTOR)
        assert 'Username: Required field' in alert_e.text, 'Alert expected'
        assert self.login_screen_visible()

    @screenshot
    def test_disable_delete_admin(self):
        """
        Test disabling/deleting admin is not allowed
        """
        self.init_app()
        self.navigate_to_entity(user.ENTITY)

        # try to disable admin user
        self.select_record('admin')
        self.facet_button_click('disable')
        self.dialog_button_click('ok')
        self.assert_last_error_dialog(ERR_ADMIN_DEL, details=True)
        self.dialog_button_click('ok')
        self.assert_record('admin')

        # try to delete admin user. Later we are
        # confirming by keyboard to test also ticket 4097
        self.select_record('admin')
        self.facet_button_click('remove')
        self.dialog_button_click('ok')
        self.assert_last_error_dialog(ERR_ADMIN_DEL, details=True)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.TAB)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.assert_record('admin')

    @screenshot
    def test_add_user_special(self):
        """
        Test various add user special cases
        """

        self.init_app()

        # Test invalid characters (#@*?) in login
        self.navigate_to_entity(user.ENTITY)
        self.facet_button_click('add')
        self.fill_textbox('uid', 'itest-user#')
        self.assert_field_validation(ERR_INCLUDE)
        self.fill_textbox('uid', 'itest-user@')
        self.assert_field_validation(ERR_INCLUDE)
        self.fill_textbox('uid', 'itest-user*')
        self.assert_field_validation(ERR_INCLUDE)
        self.fill_textbox('uid', 'itest-user?')
        self.assert_field_validation(ERR_INCLUDE)
        self.dialog_button_click('cancel')

        # Add an user with special chars
        self.basic_crud(user.ENTITY, user.DATA_SPECIAL_CHARS)

        # Add an user with long login (should FAIL)
        self.add_record(user.ENTITY, user.DATA_LONG_LOGIN, negative=True)
        self.assert_last_error_dialog(expected_err=LONG_LOGIN)
        self.close_all_dialogs()

        # Test password mismatch
        self.add_record(user.ENTITY, user.DATA_PASSWD_MISMATCH, negative=True)
        pass_e = self.find('.widget[name="userpassword2"]', By.CSS_SELECTOR)
        self.assert_field_validation(ERR_MISMATCH, parent=pass_e)
        self.dialog_button_click('cancel')
        self.assert_record(user.DATA_PASSWD_MISMATCH.get('pkey'),
                           negative=True)

        # test add and edit record
        self.add_record(user.ENTITY, user.DATA2, dialog_btn='add_and_edit')
        self.action_list_action('delete_active_user')

        # click add and cancel
        self.add_record(user.ENTITY, user.DATA, dialog_btn='cancel')

        # add leading space before password (should FAIL)
        self.navigate_to_entity(user.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(user.DATA_PASSWD_LEAD_SPACE['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(INV_PASSWD)
        self.close_all_dialogs()

        # add trailing space before password (should FAIL)
        self.navigate_to_entity(user.ENTITY)
        self.facet_button_click('add')
        self.fill_fields(user.DATA_PASSWD_TRAIL_SPACE['add'])
        self.dialog_button_click('add')
        self.assert_last_error_dialog(INV_PASSWD)
        self.close_all_dialogs()

        # add user using enter
        self.add_record(user.ENTITY, user.DATA2, negative=True)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait()
        self.assert_notification(assert_text=USR_ADDED)
        self.assert_record(user.PKEY2)
        self.close_notifications()

        # delete user using enter
        self.select_record(user.PKEY2)
        self.facet_button_click('remove')
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.assert_notification(assert_text='1 item(s) deleted')
        self.assert_record(user.PKEY2, negative=True)

    @screenshot
    def test_add_delete_undo_reset_multivalue(self):
        """
        Test add and delete multivalue with reset and undo
        """
        self.init_app()

        first_mail = self.create_email_addr(user.DATA.get('pkey'))

        self.add_record(user.ENTITY, user.DATA)
        self.wait()
        self.close_notifications()
        self.navigate_to_record(user.DATA.get('pkey'))

        # add a new mail (without save) and reset
        self.add_multivalued('mail', 'temp@ipa.test')
        self.assert_undo_button('mail')
        self.facet_button_click('revert')
        self.assert_undo_button('mail', visible=False)

        # click at delete on the first mail and reset
        self.del_multivalued('mail', first_mail)
        self.assert_undo_button('mail')
        self.facet_button_click('revert')
        self.assert_undo_button('mail', visible=False)

        # edit the first mail and reset
        self.edit_multivalued('mail', first_mail, 'temp@ipa.test')
        self.assert_undo_button('mail')
        self.facet_button_click('revert')
        self.assert_undo_button('mail', visible=False)

        # add a new mail and undo
        self.add_multivalued('mail', 'temp@ipa.test')
        self.assert_undo_button('mail')
        self.undo_multivalued('mail', 'temp@ipa.test')
        self.assert_undo_button('mail', visible=False)

        # edit the first mail and undo
        self.edit_multivalued('mail', first_mail, 'temp@ipa.test')
        self.assert_undo_button('mail')
        self.undo_multivalued('mail', 'temp@ipa.test')
        self.assert_undo_button('mail', visible=False)

        # cleanup
        self.delete(user.ENTITY, [user.DATA])

    @screenshot
    def test_user_misc(self):
        """
        Test various miscellaneous test cases under one roof to save init time
        """
        self.init_app()

        # add already existing user (should fail) / also test ticket 4098
        self.add_record(user.ENTITY, user.DATA)
        self.add_record(user.ENTITY, user.DATA, negative=True,
                        pre_delete=False)
        self.assert_last_error_dialog(USR_EXIST.format(user.PKEY))
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.TAB)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.dialog_button_click('cancel')

        # add user without login name
        self.add_record(user.ENTITY, user.DATA_NO_LOGIN)
        self.assert_record('nsurname10')

        # try to add same user without login name again (should fail)
        self.add_record(user.ENTITY, user.DATA_NO_LOGIN, negative=True,
                        pre_delete=False)
        self.assert_last_error_dialog(USR_EXIST.format('nsurname10'))
        self.close_all_dialogs()

        # try to modify user`s UID to -1 (should fail)
        self.navigate_to_record(user.PKEY)
        self.mod_record(
            user.ENTITY, {'mod': [('textbox', 'uidnumber', '-1')]},
            negative=True)
        uid_e = self.find('.widget[name="uidnumber"]', By.CSS_SELECTOR)
        self.assert_field_validation('Minimum value is 1', parent=uid_e)
        self.facet_button_click('revert')

        # edit user`s "First name" to value with leading space (should fail)
        self.fill_input('givenname', ' leading_space')
        self.facet_button_click('save')
        self.assert_last_error_dialog(INV_FIRSTNAME)
        self.dialog_button_click('cancel')

        # edit user`s "First name" to value with trailing space (should fail)
        self.fill_input('givenname', 'trailing_space ')
        self.facet_button_click('save')
        self.assert_last_error_dialog(INV_FIRSTNAME)
        self.dialog_button_click('cancel')

        # try with blank "First name" (should fail)
        gn_input_s = "input[type='text'][name='givenname']"
        gn_input_el = self.find(gn_input_s, By.CSS_SELECTOR, strict=True)
        gn_input_el.clear()
        gn_input_el.send_keys(Keys.BACKSPACE)
        self.facet_button_click('save')
        gn_e = self.find('.widget[name="givenname"]', By.CSS_SELECTOR)
        self.assert_field_validation(FIELD_REQ, parent=gn_e)
        self.close_notifications()

        # search user / multiple users
        self.navigate_to_entity(user.ENTITY)
        self.wait(0.5)
        self.find_record('user', user.DATA)
        self.add_record(user.ENTITY, user.DATA2)
        self.find_record('user', user.DATA2)
        # search for both users (just 'itest-user' will do)
        self.find_record('user', user.DATA)
        self.assert_record(user.PKEY2)

        # cleanup
        self.delete_record([user.PKEY, user.PKEY2, user.PKEY_NO_LOGIN,
                            'nsurname10'])

@pytest.mark.tier1
class test_user_no_private_group(UI_driver):

    @screenshot
    def test_noprivate_nonposix(self):
        """
        User without private group and without specified GID
        """
        self.init_app()

        with pytest.raises(AssertionError) as e:
            self.add_record(user.ENTITY, user.DATA3)
        assert (str(e.value) == 'Unexpected error: Default group for new '
                'users is not POSIX')

    @screenshot
    def test_noprivate_posix(self):
        """
        User without private group and specified existing posix GID
        """
        self.init_app()
        self.add_record(group.ENTITY, group.DATA6)

        self.add_record(user.ENTITY, user.DATA4)
        self.delete(user.ENTITY, [user.DATA4])

        self.delete(group.ENTITY, [group.DATA6])

    @screenshot
    def test_noprivate_gidnumber(self):
        """
        User without private group and specified unused GID
        """
        self.init_app()

        self.add_record(user.ENTITY, user.DATA4, combobox_input='gidnumber')
        self.delete(user.ENTITY, [user.DATA4])


@pytest.mark.tier1
class TestLifeCycles(UI_driver):

    @screenshot
    def test_life_cycles(self):
        """
        Test user life-cycles
        """

        self.init_app()

        # create "itest-user" and send him to preserved
        self.add_record(user.ENTITY, user.DATA)
        self.delete_record(user.PKEY, confirm_btn=None)
        self.check_option('preserve', value='true')
        self.dialog_button_click('ok')
        self.assert_notification(assert_text='1 item(s) deleted')

        # try to add the same user again (should fail)
        self.add_record(user.ENTITY, user.DATA, negative=True)
        self.assert_last_error_dialog(USR_EXIST.format(user.PKEY))
        self.close_all_dialogs()
        self.wait()

        # restore "itest-user" user
        self.switch_to_facet('search_preserved')
        self.select_record(user.PKEY)
        self.button_click('undel')
        self.dialog_button_click('ok')
        self.assert_no_error_dialog()
        self.assert_notification(assert_text='1 user(s) restored')
        self.wait()

        # add already existing user "itest-user" to stage and try to activate
        # the latter (should fail)
        self.add_record('stageuser', user.DATA)
        self.select_record(user.PKEY)
        self.button_click('activate')
        self.dialog_button_click('ok')

        err_msg = ACTIVE_ERR.format(user.PKEY)
        self.assert_last_error_dialog(err_msg, details=True)
        self.dialog_button_click('ok')

        # delete "itest-user" staged user
        self.delete_record(user.PKEY)
        self.assert_record(user.PKEY, negative=True)

        # add "itest-user2" and send him to staged (through preserved)
        self.close_all_dialogs()
        self.add_record(user.ENTITY, user.DATA2)
        self.delete_record(user.PKEY2, confirm_btn=None)
        self.check_option('preserve', value='true')
        self.dialog_button_click('ok')
        self.switch_to_facet('search_preserved')
        self.select_record(user.PKEY2)
        self.button_click('batch_stage')
        self.dialog_button_click('ok')
        self.assert_no_error_dialog()
        self.wait(2)
        # fix assert after https://pagure.io/freeipa/issue/7477 is closed
        self.assert_notification(assert_text='1 users(s) staged')

        # add new "itest-user2" - one is already staged (should pass)
        self.add_record(user.ENTITY, user.DATA2)
        self.assert_record(user.PKEY2)

        # send active "itest-user2" to preserved
        self.delete_record(user.PKEY2, confirm_btn=None)
        self.check_option('preserve', value='true')
        self.dialog_button_click('ok')

        # try to activate staged "itest-user2" while one is already preserved
        # (should fail)
        self.navigate_to_entity('stageuser')
        self.select_record(user.PKEY2)
        self.button_click('activate')
        self.dialog_button_click('ok')
        self.assert_last_error_dialog(ENTRY_EXIST, details=True)
        self.dialog_button_click('ok')

        # delete preserved "itest-user2" and activate the staged one
        # (should pass)
        self.switch_to_facet('search_preserved')
        self.delete_record(user.PKEY2)
        self.navigate_to_entity('stageuser')
        self.select_record(user.PKEY2)
        self.button_click('activate')
        self.wait()
        self.dialog_button_click('ok')
        self.assert_notification(assert_text='1 user(s) activated')

        # send multiple records to preserved
        self.navigate_to_entity('stageuser')
        self.navigate_to_entity(user.ENTITY)
        self.delete_record([user.PKEY, user.PKEY2],
                           confirm_btn=None)
        self.check_option('preserve', value='true')
        self.dialog_button_click('ok')
        self.assert_notification(assert_text='2 item(s) deleted')

        # restore multiple records
        self.switch_to_facet('search_preserved')
        self.select_multiple_records([user.DATA, user.DATA2])
        self.button_click('undel')
        self.dialog_button_click('ok')
        self.assert_no_error_dialog()
        self.assert_notification(assert_text='2 user(s) restored')
        self.wait()

        # send multiple users to staged (through preserved)
        self.navigate_to_entity(user.ENTITY)
        self.delete_record([user.PKEY, user.PKEY2],
                           confirm_btn=None)
        self.check_option('preserve', value='true')
        self.dialog_button_click('ok')
        self.switch_to_facet('search_preserved')
        self.select_multiple_records([user.DATA, user.DATA2])
        self.button_click('batch_stage')
        self.dialog_button_click('ok')
        self.assert_no_error_dialog()
        self.wait(2)
        self.assert_notification(assert_text='2 users(s) staged')

        # activate multiple users from stage
        self.navigate_to_entity('stageuser')
        self.select_multiple_records([user.DATA, user.DATA2])
        self.button_click('activate')
        self.dialog_button_click('ok')
        self.assert_notification(assert_text='2 user(s) activated')

        # try to disable record from user page
        self.navigate_to_entity(user.ENTITY)
        self.select_record(user.PKEY)
        self.facet_button_click('disable')
        self.dialog_button_click('ok')
        self.assert_record_value('Disabled', user.PKEY,
                                 'nsaccountlock')

        # try to disable same record again (should fail)
        self.select_record(user.PKEY)
        self.facet_button_click('disable')
        self.dialog_button_click('ok')
        self.assert_last_error_dialog(DISABLED, details=True)
        self.dialog_button_click('ok')

        # enable the user again
        self.select_record(user.PKEY)
        self.facet_button_click('enable')
        self.dialog_button_click('ok')
        self.assert_record_value('Enabled', user.PKEY,
                                 'nsaccountlock')

        # same for multiple users (disable, disable again, enable)
        self.select_multiple_records([user.DATA, user.DATA2])
        self.facet_button_click('disable')
        self.dialog_button_click('ok')
        self.assert_record_value('Disabled', [user.PKEY, user.PKEY2],
                                 'nsaccountlock')

        self.select_multiple_records([user.DATA, user.DATA2])
        self.facet_button_click('disable')
        self.dialog_button_click('ok')
        self.assert_last_error_dialog(DISABLED, details=True)
        self.dialog_button_click('ok')

        self.select_multiple_records([user.DATA, user.DATA2])
        self.facet_button_click('enable')
        self.dialog_button_click('ok')
        self.assert_record_value('Enabled', [user.PKEY, user.PKEY2],
                                 'nsaccountlock')

        # cleanup and check for ticket 4245 (select all should not remain
        # checked after delete action). Two "ok" buttons at the end are needed
        # for delete confirmation and acknowledging that "admin" cannot be
        # deleted.
        self.navigate_to_entity(user.ENTITY)
        select_all_btn = self.find('input[title="Select All"]',
                                   By.CSS_SELECTOR)
        select_all_btn.click()
        self.facet_button_click('remove')
        self.dialog_button_click('ok')
        self.dialog_button_click('ok')
        self.assert_value_checked('admin', 'uid', negative=True)


@pytest.mark.tier1
class TestSSHkeys(UI_driver):

    @screenshot
    def test_ssh_keys(self):

        self.init_app()

        # add and undo SSH key
        self.add_sshkey_to_record(user.SSH_RSA, 'admin', save=False,
                                  navigate=True)
        self.assert_num_ssh_keys(1)
        self.undo_ssh_keys()
        self.assert_num_ssh_keys(0)

        # add and undo 2 SSH keys (using undo all)
        ssh_keys = [user.SSH_RSA, user.SSH_DSA]

        self.add_sshkey_to_record(ssh_keys, 'admin', save=False)
        self.assert_num_ssh_keys(2)
        self.undo_ssh_keys(btn_name='undo_all')
        self.assert_num_ssh_keys(0)

        # add SSH key and refresh
        self.add_sshkey_to_record(user.SSH_RSA, 'admin', save=False)
        self.assert_num_ssh_keys(1)
        self.facet_button_click('refresh')
        self.assert_num_ssh_keys(0)

        # add SSH key and revert
        self.add_sshkey_to_record(user.SSH_RSA, 'admin', save=False)
        self.assert_num_ssh_keys(1)
        self.facet_button_click('revert')
        self.assert_num_ssh_keys(0)

        # add SSH key, move elsewhere and cancel.
        self.add_sshkey_to_record(user.SSH_RSA, 'admin', save=False)
        self.assert_num_ssh_keys(1)
        self.switch_to_facet('memberof_group')
        self.dialog_button_click('cancel')
        self.assert_num_ssh_keys(1)
        self.undo_ssh_keys()

        # add SSH key, move elsewhere and click reset button.
        self.add_sshkey_to_record(user.SSH_RSA, 'admin', save=False)
        self.assert_num_ssh_keys(1)
        self.switch_to_facet('memberof_group')
        self.wait_for_request()
        self.dialog_button_click('revert')
        self.wait()
        self.switch_to_facet('details')
        self.assert_num_ssh_keys(0)

        # add SSH key, move elsewhere and click save button.
        self.add_sshkey_to_record(user.SSH_RSA, 'admin', save=False)
        self.assert_num_ssh_keys(1)
        self.switch_to_facet('memberof_group')
        self.wait()
        self.dialog_button_click('save')
        self.wait_for_request(n=4)
        self.switch_to_facet('details')
        self.assert_num_ssh_keys(1)
        self.delete_record_sshkeys('admin')

        # add, save and delete RSA and DSA keys
        keys = [user.SSH_RSA, user.SSH_DSA]

        self.add_sshkey_to_record(keys, 'admin')
        self.assert_num_ssh_keys(2)
        self.delete_record_sshkeys('admin')
        self.assert_num_ssh_keys(0)

        # add RSA SSH keys with trailing space and "=" sign at the end
        keys = [user.SSH_RSA+" ", user.SSH_RSA2+"="]

        self.add_sshkey_to_record(keys, 'admin')
        self.assert_num_ssh_keys(2)
        self.delete_record_sshkeys('admin')
        self.assert_num_ssh_keys(0)

        # lets try to add empty SSH key (should fail)
        self.add_sshkey_to_record('', 'admin')
        self.assert_last_error_dialog(EMPTY_MOD)
        self.dialog_button_click('cancel')
        self.undo_ssh_keys()

        # try to add invalid SSH key
        self.add_sshkey_to_record('invalid_key', 'admin')
        self.assert_last_error_dialog(INVALID_SSH_KEY)
        self.dialog_button_click('cancel')
        self.undo_ssh_keys()

        # add duplicate SSH keys
        self.add_sshkey_to_record(user.SSH_RSA, 'admin')
        self.add_sshkey_to_record(user.SSH_RSA, 'admin', save=False)
        self.facet_button_click('save')
        self.assert_last_error_dialog(EMPTY_MOD)
        self.dialog_button_click('cancel')

        # test SSH key edit when user lacks write rights for related attribute
        # see ticket 3800 (we use DATA_SPECIAL_CHARS just for convenience)
        self.add_record(user.ENTITY, [user.DATA2, user.DATA_SPECIAL_CHARS])
        self.add_sshkey_to_record(user.SSH_RSA, user.PKEY2, navigate=True)

        self.logout()
        self.init_app(user.PKEY_SPECIAL_CHARS, user.PASSWD_SCECIAL_CHARS)

        self.navigate_to_record(user.PKEY2, entity=user.ENTITY)

        show_ssh_key_btn = self.find('div.widget .btn[name="ipasshpubkey-0"]',
                                     By.CSS_SELECTOR)
        show_ssh_key_btn.click()
        ssh_key_e = self.find('textarea', By.CSS_SELECTOR, self.get_dialog())

        assert ssh_key_e.get_attribute('readonly') == 'true'
        self.dialog_button_click('cancel')
        self.logout()
        self.init_app()

        # cleanup
        self.delete(user.ENTITY, [user.DATA2, user.DATA_SPECIAL_CHARS])
        self.delete_record_sshkeys('admin', navigate=True)
