# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information
"""Tests for FreeIPA system accounts webui functionality"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_sysaccount as sysaccount
import ipatests.test_webui.test_rbac as rbac
import pytest
from ipapython.ipaldap import realm_to_serverid

try:
    from selenium.webdriver.common.by import By
except ImportError:
    pass


@pytest.mark.tier1
class test_sysaccount(UI_driver):
    """
    Web UI test for system accounts.
    """

    def restart_dirsrv(self):
        realm = self.config.get('ipa_realm')
        private_key_path = (
            self.config.get('root_ssh_key_filename')
        )

        if realm:
            dashed_domain = realm_to_serverid(realm)
            restart = f"systemctl restart dirsrv@{dashed_domain}"
            self.run_cmd_on_ui_host(
                restart, auth_method='key',
                private_key_path=private_key_path,
                username='root'
            )

    @screenshot
    def test_privileged_flag(self):
        """
        Test privileged flag in system account
        """
        self.init_app()

        # Add system account with privileged flag
        self.add_record(sysaccount.ENTITY, sysaccount.DATA_PRIVILEGED)

        self.restart_dirsrv()

        # Navigate to details and verify privileged is checked
        self.navigate_to_record(sysaccount.PKEY_PRIVILEGED)
        self.assert_facet(sysaccount.ENTITY, 'details')

        # Verify privileged checkbox is checked
        assert self.get_field_checked('privileged')

        # Modify to uncheck privileged
        self.mod_record(sysaccount.ENTITY, sysaccount.DATA_PRIVILEGED)
        self.restart_dirsrv()

        # Verify privileged checkbox is unchecked
        assert not self.get_field_checked('privileged')

        # Cleanup
        self.delete(sysaccount.ENTITY, [sysaccount.DATA_PRIVILEGED])

    @screenshot
    def test_associations(self):
        """
        System account role associations
        """
        self.init_app()

        # Create system account "test-app"
        test_app_data = {
            'pkey': 'test-app',
            'add': [
                ('textbox', 'uid', 'test-app'),
                ('textbox', 'description', 'system account for role'),
                ('password', 'userpassword', 'Secret123'),
                ('password', 'userpassword2', 'Secret123'),
            ],
        }
        self.add_record(sysaccount.ENTITY, test_app_data)

        # Create role "test_role"
        test_role_data = {
            'pkey': 'test_role',
            'add': [
                ('textbox', 'cn', 'test_role'),
                ('textarea', 'description', 'role for system account'),
            ],
        }
        self.add_record(rbac.ROLE_ENTITY, test_role_data)

        # Navigate to the role
        self.navigate_to_record('test_role', entity=rbac.ROLE_ENTITY)

        # Add system account "test-app" to the role
        # This will: switch to System Accounts tab, click add button,
        # select "test-app" from available, click add button (right arrow),
        # then click add button (confirm)
        self.add_associations(['test-app'], facet='member_sysaccount')

    @screenshot
    def test_enable_disable(self):
        """
        Test enable/disable system account
        """
        self.init_app()

        # Add system account
        self.add_record(sysaccount.ENTITY, sysaccount.DATA)

        # Navigate to details
        self.navigate_to_entity(sysaccount.ENTITY)
        self.navigate_to_record(sysaccount.PKEY)

        # Disable system account
        self.disable_action()

        # Verify it's disabled in search
        self.navigate_to_entity(sysaccount.ENTITY)
        self.assert_record_value('Disabled', sysaccount.PKEY, 'nsaccountlock')

        # Navigate back to details and enable
        self.navigate_to_record(sysaccount.PKEY)
        self.enable_action()

        # Verify it's enabled in search
        self.navigate_to_entity(sysaccount.ENTITY)
        self.assert_record_value('Enabled', sysaccount.PKEY, 'nsaccountlock')

    @screenshot
    def test_password_mismatch(self):
        """
        Test password mismatch validation in add dialog
        """
        self.init_app()

        self.navigate_to_entity(sysaccount.ENTITY)
        self.facet_button_click('add')

        # Fill in system account details
        self.fill_input('uid', 'itest-pwd-mismatch')
        self.fill_textbox('description', 'test password mismatch')
        self.check_option('privileged', 'checked')

        # Fill passwords that don't match
        self.fill_password('userpassword', 'Secret123')
        self.fill_password('userpassword2', 'Different123')

        # Try to add - should fail validation
        self.dialog_button_click('add')

        # Check for password mismatch error
        self.find(
            ".widget[name='userpassword2']", By.CSS_SELECTOR, strict=True
        )
        # The validation should prevent submission
        # Check if dialog is still open (validation failed)
        dialog = self.find(".modal-dialog", By.CSS_SELECTOR, strict=False)
        assert dialog is not None

        self.dialog_button_click('cancel')

    @screenshot
    def test_empty_sysaccount_name(self):
        self.init_app()
        self.navigate_to_entity(sysaccount.ENTITY)
        self.facet_button_click('add')
        self.dialog_button_click('add')
        elem = self.find(".widget[name='uid']")
        self.assert_field_validation_required(elem)
        self.dialog_button_click('cancel')

    @screenshot
    def test_duplicate_sysaccount_name(self):
        # First create a system account
        self.init_app()
        self.add_record(sysaccount.ENTITY, sysaccount.DATA2)

        # Try to create another with same name
        error = f'system account with name "{sysaccount.PKEY2}" already exists'
        self.navigate_to_entity(sysaccount.ENTITY)
        self.facet_button_click('add')
        self.fill_input('uid', sysaccount.PKEY2)
        self.fill_textbox('description', 'duplicate test')
        self.fill_password('userpassword', 'Secret123')
        self.fill_password('userpassword2', 'Secret123')

        def cancel_retry_dialog(expected_error):
            self.dialog_button_click('add')
            dialog = self.get_last_error_dialog()
            assert (expected_error in dialog.text)
            self.wait_for_request()
            self.dialog_button_click('cancel')

        cancel_retry_dialog(error)
