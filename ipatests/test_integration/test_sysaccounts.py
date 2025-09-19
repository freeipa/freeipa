# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information
"""Tests for FreeIPA system accounts functionality"""

import time
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipapython.ipautil import ipa_generate_password


def extract_password_from_result(result):
    # Extract password from creation output
    password_line = [
        line
        for line in result.stdout_text.split("\n")
        if "Random password:" in line
    ][0]
    return password_line.split("Random password:")[1].strip()


class TestSystemAccounts(IntegrationTest):
    """Integration tests for system accounts functionality"""

    topology = "line"
    num_clients = 0
    num_replicas = 0

    def test_system_account_lifecycle(self):
        """Test basic system account lifecycle operations"""
        sysaccount_name = "test-app"
        tasks.kinit_admin(self.master)

        # Test creating a system account with random password
        result = self.master.run_command(
            ["ipa", "sysaccount-add", sysaccount_name, "--random"]
        )
        assert (
            f'Added system account "{sysaccount_name}"' in result.stdout_text
        )
        assert "Random password:" in result.stdout_text

        # Test finding system accounts
        result = self.master.run_command(["ipa", "sysaccount-find"])
        assert sysaccount_name in result.stdout_text

        # Test showing system account details
        result = self.master.run_command(
            ["ipa", "sysaccount-show", sysaccount_name]
        )
        assert f"System account ID: {sysaccount_name}" in result.stdout_text

        # Test disabling system account
        result = self.master.run_command(
            ["ipa", "sysaccount-disable", sysaccount_name]
        )
        assert (
            f'Disabled system account "{sysaccount_name}"'
            in result.stdout_text
        )

        # Test enabling system account
        result = self.master.run_command(
            ["ipa", "sysaccount-enable", sysaccount_name]
        )
        assert (
            f'Enabled system account "{sysaccount_name}"' in result.stdout_text
        )

        # Clean up
        self.master.run_command(["ipa", "sysaccount-del", sysaccount_name])

        # Verify deletion
        result = self.master.run_command(
            ["ipa", "sysaccount-show", sysaccount_name], raiseonerr=False
        )
        assert result.returncode != 0

    def test_system_account_ldap_bind(self):
        """Test LDAP bind functionality with system accounts"""
        sysaccount_name = "ldap-test-app"
        basedn = str(self.master.domain.basedn)
        tasks.kinit_admin(self.master)

        # Create system account
        result = self.master.run_command(
            ["ipa", "sysaccount-add", sysaccount_name, "--random"]
        )

        # Extract password from creation output
        password = extract_password_from_result(result)

        bind_dn = f"uid={sysaccount_name},cn=sysaccounts,cn=etc,{basedn}"

        # Test LDAP bind with the system account
        ldap_uri = f"ldap://{self.master.hostname}"
        result = self.master.run_command(
            [
                "ldapsearch",
                "-D", bind_dn,
                "-w", password,
                "-H", ldap_uri,
                "-b", basedn,
                "-s", "base",
                "(objectclass=*)",
                "dn",
            ]
        )
        assert result.returncode == 0
        assert basedn in result.stdout_text

        # Clean up
        self.master.run_command(["ipa", "sysaccount-del", sysaccount_name])

    def test_system_account_password_management_without_reset(self):
        """Test system account password management without triggering reset"""
        sysaccount_name = "password-mgmt-app"
        test_user = "sysaccount-test-user"
        dashed_domain = self.master.domain.realm.replace(".", "-")
        basedn = str(self.master.domain.basedn)
        tasks.kinit_admin(self.master)

        try:
            # Create test user
            self.master.run_command(
                [
                    "ipa",
                    "user-add", test_user,
                    "--first", "Test",
                    "--last", "User",
                    "--random",
                ]
            )

            # Create system account
            result = self.master.run_command(
                ["ipa", "sysaccount-add", sysaccount_name, "--random"]
            )

            # Extract password from creation output
            sysaccount_password = extract_password_from_result(result)

            # Create privilege for password changes
            privilege_name = f"{sysaccount_name}-password-privilege"
            self.master.run_command(["ipa", "privilege-add", privilege_name])

            # Add permission to privilege
            self.master.run_command(
                [
                    "ipa",
                    "privilege-add-permission", privilege_name,
                    "--permission", "System: Change User password",
                ]
            )

            # Create role
            role_name = f"{sysaccount_name}-role"
            self.master.run_command(["ipa", "role-add", role_name])

            # Add privilege to role
            self.master.run_command(
                [
                    "ipa",
                    "role-add-privilege", role_name,
                    "--privilege", privilege_name,
                ]
            )

            # Add system account to role
            self.master.run_command(
                [
                    "ipa",
                    "role-add-member", role_name,
                    "--sysaccounts", sysaccount_name,
                ]
            )

            # Enable privileged password changes for the system account
            result = self.master.run_command(
                [
                    "ipa",
                    "sysaccount-policy", sysaccount_name,
                    "--privileged=true",
                ]
            )
            assert (
                "Restart the Directory Server services" in result.stderr_text
            )

            # Restart directory server to apply changes
            self.master.run_command(
                ["systemctl", "restart", f"dirsrv@{dashed_domain}"]
            )

            # Wait for the service to restart
            time.sleep(15)

            # Set user password to a known value first
            initial_password = ipa_generate_password()
            self.master.run_command(
                ["ipa", "user-mod", test_user, "--password"],
                stdin_text=f"{initial_password}\n{initial_password}\n",
            )

            # Change user password using system account via ldappasswd
            new_password = ipa_generate_password()
            sysaccount_dn = (
                f"uid={sysaccount_name},cn=sysaccounts,cn=etc,{basedn}"
            )
            user_dn = (
                f"uid={test_user},cn=users,cn=accounts,{basedn}"
            )

            result = self.master.run_command(
                [
                    "ldappasswd",
                    "-D", sysaccount_dn,
                    "-w", sysaccount_password,
                    "-a", initial_password,
                    "-s", new_password,
                    "-x",
                    "-ZZ",
                    "-H",
                    f"ldap://{self.master.hostname}",
                    user_dn,
                ]
            )
            assert result.returncode == 0

            # Verify password was changed and no reset is required
            user_details = self.master.run_command(
                ["ipa", "user-show", test_user, "--all", "--raw"]
            )

            # The key test:
            # verify that krbLastPwdChange != krbPasswordExpiration
            # If they are equal, it means password reset is required
            krb_last_pwd_change = None
            krb_pwd_expiration = None

            for line in user_details.stdout_text.split("\n"):
                if "krbLastPwdChange:" in line:
                    krb_last_pwd_change = line.split(":", 1)[1].strip()
                elif "krbPasswordExpiration:" in line:
                    krb_pwd_expiration = line.split(":", 1)[1].strip()

            # If system account privileged password change worked,
            # these values should be different
            if krb_last_pwd_change and krb_pwd_expiration:
                assert krb_last_pwd_change != krb_pwd_expiration, (
                    "Password reset was not bypassed - "
                    "krbLastPwdChange equals krbPasswordExpiration"
                )

            # Test user can authenticate with new password
            self.master.run_command(["kdestroy", "-A"])
            result = self.master.run_command(
                ["kinit", test_user], stdin_text=f"{new_password}\n"
            )
            assert result.returncode == 0

        finally:
            # Clean up
            self.master.run_command(["kdestroy", "-A"])
            tasks.kinit_admin(self.master)

            # Remove system account policy
            self.master.run_command(
                [
                    "ipa",
                    "sysaccount-policy", sysaccount_name,
                    "--privileged=false",
                ],
                raiseonerr=False,
            )

            # Clean up entities in reverse order
            self.master.run_command(
                ["ipa", "role-del", role_name], raiseonerr=False
            )
            self.master.run_command(
                ["ipa", "privilege-del", privilege_name], raiseonerr=False
            )
            self.master.run_command(
                ["ipa", "sysaccount-del", sysaccount_name], raiseonerr=False
            )
            self.master.run_command(
                ["ipa", "user-del", test_user], raiseonerr=False
            )

            # Restart directory server to apply changes
            self.master.run_command(
                ["systemctl", "restart", f"dirsrv@{dashed_domain}"]
            )

            # Wait for the service to restart
            time.sleep(15)

    def test_system_account_role_membership(self):
        """Test system account membership in roles"""
        sysaccount_name = "role-test-app"
        role_name = "test-sysaccount-role"
        tasks.kinit_admin(self.master)

        try:
            # Create system account
            self.master.run_command(
                ["ipa", "sysaccount-add", sysaccount_name, "--random"]
            )

            # Create a test role
            self.master.run_command(["ipa", "role-add", role_name])

            # Add system account to role
            result = self.master.run_command(
                [
                    "ipa",
                    "role-add-member", role_name,
                    "--sysaccounts", sysaccount_name,
                ]
            )
            assert "Number of members added 1" in result.stdout_text

            # Verify membership
            result = self.master.run_command(["ipa", "role-show", role_name])
            assert sysaccount_name in result.stdout_text

            # Verify from system account perspective
            result = self.master.run_command(
                ["ipa", "sysaccount-show", sysaccount_name]
            )
            assert role_name in result.stdout_text

            # Remove system account from role
            result = self.master.run_command(
                [
                    "ipa",
                    "role-remove-member", role_name,
                    "--sysaccounts", sysaccount_name,
                ]
            )
            assert "Number of members removed 1" in result.stdout_text

        finally:
            # Clean up
            self.master.run_command(
                ["ipa", "role-del", role_name], raiseonerr=False
            )
            self.master.run_command(
                ["ipa", "sysaccount-del", sysaccount_name], raiseonerr=False
            )

    def test_required_system_accounts_protection(self):
        """Test that required system accounts cannot be deleted"""
        required_accounts = ["passsync", "sudo"]
        tasks.kinit_admin(self.master)

        for account in required_accounts:
            # Try to delete a required system account
            result = self.master.run_command(
                ["ipa", "sysaccount-del", account], raiseonerr=False
            )
            assert result.returncode != 0
            assert "is required by the IPA master" in result.stderr_text

    def test_system_account_password_validation(self):
        """Test system account password validation"""
        sysaccount_name = "password-validation-test"
        tasks.kinit_admin(self.master)

        # Test creation with explicit password
        test_password = ipa_generate_password()
        result = self.master.run_command(
            ["ipa", "sysaccount-add", sysaccount_name, "--password"],
            stdin_text=f"{test_password}\n{test_password}\n",
        )
        assert (
            f'Added system account "{sysaccount_name}"' in result.stdout_text
        )

        # Clean up
        self.master.run_command(["ipa", "sysaccount-del", sysaccount_name])

    def test_system_account_implicit_password(self):
        """Test system account password validation"""
        sysaccount_name = "password-implicit-validation-test"
        tasks.kinit_admin(self.master)

        # Test creation with implicitly asked password
        test_password = ipa_generate_password()
        result = self.master.run_command(
            ["ipa", "sysaccount-add", sysaccount_name],
            stdin_text=f"{test_password}\n{test_password}\n",
        )
        assert (
            f'Added system account "{sysaccount_name}"' in result.stdout_text
        )

        # Clean up
        self.master.run_command(["ipa", "sysaccount-del", sysaccount_name])

    def test_system_account_modify_password(self):
        """Test modifying system account password"""
        sysaccount_name = "modify-password-test"
        tasks.kinit_admin(self.master)

        try:
            # Create system account
            self.master.run_command(
                ["ipa", "sysaccount-add", sysaccount_name, "--random"]
            )

            # Modify with new random password
            result = self.master.run_command(
                ["ipa", "sysaccount-mod", sysaccount_name, "--random"]
            )
            assert "Random password:" in result.stdout_text

            # Modify with explicit password
            new_password = ipa_generate_password()
            self.master.run_command(
                ["ipa", "sysaccount-mod", sysaccount_name, "--password"],
                stdin_text=f"{new_password}\n{new_password}\n",
            )

        finally:
            # Clean up
            self.master.run_command(
                ["ipa", "sysaccount-del", sysaccount_name], raiseonerr=False
            )
