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
except ImportError:
    pass


@pytest.mark.tier1
class user_tasks(UI_driver):
    def load_file(self, path):
        with open(path, 'r') as file_d:
            content = file_d.read()
        return content


@pytest.mark.tier1
class test_user(user_tasks):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: user
        """
        self.init_app()
        self.basic_crud(user.ENTITY, user.DATA)

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

        self.action_list_action('unlock')

        # delete
        self.delete_action(user.ENTITY, user.PKEY, action='delete_active_user')

    @screenshot
    def test_certificates(self):
        """
        Test user certificate actions

        Requires to have CA installed and 'user_csr_path' configuration option
        set.
        """

        if not self.has_ca():
            self.skip('CA is not configured')

        csr_path = self.config.get('user_csr_path')
        if not csr_path:
            self.skip('CSR file is not configured')

        self.init_app()
        # ENHANCEMENT: generate csr dynamically
        csr = self.load_file(csr_path)
        cert_widget_sel = "div.certificate-widget"

        self.add_record(user.ENTITY, user.DATA)
        self.navigate_to_record(user.PKEY)

        # cert request
        self.action_list_action('request_cert', confirm=False)
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
