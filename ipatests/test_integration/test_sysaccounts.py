# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information
"""Tests for FreeIPA system accounts functionality"""

import contextlib
import textwrap

from ipapython.dn import DN
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


def setup_sysaccout(host, sysaccount_name, privilege_name, permission,
                    role_name, privileged=True,
                    password=None,
                    desc=None):
    tasks.kinit_admin(host)
    cmd = [
        "ipa", "sysaccount-add", sysaccount_name
    ]
    if password is not None:
        cmd.append('--password')
        stdin_text = '{0}\n{0}\n'.format(password)
    else:
        cmd.append('--random')
        stdin_text = None
    if desc is not None:
        cmd.append(f'--desc="{desc}"')

    result = host.run_command(cmd, stdin_text=stdin_text)

    host.run_command(["ipa", "privilege-add", privilege_name])
    host.run_command(
        ["ipa", "privilege-add-permission", privilege_name,
         "--permission", f"{permission}"]
    )
    host.run_command(["ipa", "role-add", role_name])
    host.run_command(["ipa", "role-add-privilege", role_name,
                     "--privilege", privilege_name])
    host.run_command(["ipa", "role-add-member", role_name,
                     "--sysaccounts", sysaccount_name])
    if privileged:
        host.run_command(
            ["ipa", "sysaccount-policy", sysaccount_name,
             f"--privileged={privileged}"
             ]
        )
    tasks.service_control_dirsrv(host)
    if password:
        return None
    else:
        return extract_password_from_result(result)


def cleanup_sysaccount(
        host, role_name, privilege_name, sysaccount_name, user=None):
    tasks.kinit_admin(host)
    # Clean up entities in reverse order
    host.run_command(
        ["ipa", "role-del", role_name], raiseonerr=False
    )
    host.run_command(
        ["ipa", "privilege-del", privilege_name], raiseonerr=False
    )
    host.run_command(
        ["ipa", "sysaccount-del", sysaccount_name], raiseonerr=False
    )
    if user:
        host.run_command(
            ["ipa", "user-del", user], raiseonerr=False
        )

    # Restart directory server to apply changes
    tasks.service_control_dirsrv(host)


class TestSystemAccounts(IntegrationTest):
    """Integration tests for system accounts functionality"""

    topology = "line"
    num_clients = 0
    num_replicas = 1

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
        result = tasks.run_ldapsearch(
            self.master, bind_dn, password, basedn,
            ["(objectclass=*)", "dn"]
        )
        assert result.returncode == 0
        assert basedn in result.stdout_text

        # Clean up
        self.master.run_command(["ipa", "sysaccount-del", sysaccount_name])

    def test_system_account_password_management_without_reset(self):
        """Test system account password management without triggering reset"""
        sysaccount_name = "password-mgmt-app"
        test_user = "sysaccount-test-user"
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
            tasks.service_control_dirsrv(self.master)

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
            tasks.service_control_dirsrv(self.master)

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

    def test_system_account_password_change_verification(self):
        """Test password change and verify it works"""
        sysaccount_name = "pwd-change-verify-test"
        basedn = str(self.master.domain.basedn)
        tasks.kinit_admin(self.master)

        try:
            # Create sysaccount
            result = self.master.run_command(
                ["ipa", "sysaccount-add", sysaccount_name, "--random"]
            )
            original_password = extract_password_from_result(result)
            bind_dn = f"uid={sysaccount_name},cn=sysaccounts,cn=etc,{basedn}"

            # Verify original password works
            result = tasks.run_ldapsearch(
                self.master, bind_dn, original_password, basedn,
                ["(objectclass=*)", "dn"]
            )

            # Change password
            new_password = ipa_generate_password()
            self.master.run_command(
                [
                    "ipa", "sysaccount-mod", sysaccount_name,
                    "--password"
                ],
                stdin_text=f"{new_password}\n{new_password}\n"
            )

            # Verify old password doesn't work
            result = tasks.run_ldapsearch(
                self.master, bind_dn, original_password, basedn,
                ["(objectclass=*)", "dn"], raiseonerr=False
            )
            assert result.returncode != 0

            # Verify new password works
            result = tasks.run_ldapsearch(
                self.master, bind_dn, new_password, basedn,
                ["(objectclass=*)", "dn"]
            )

        finally:
            self.master.run_command(
                ["ipa", "sysaccount-del", sysaccount_name], raiseonerr=False
            )

    def test_system_account_privileged(self):
        """Test system account privilege"""

        sysaccount_name = "test-privilege"
        privilege_name = "test-privilege-password-privilege"
        permission = "System: Change User password"
        role_name = "test-privilege-role"
        test_user = "anna"
        basedn = str(self.master.domain.basedn)
        user_dn = (
            f"uid={test_user},cn=users,cn=accounts,{basedn}"
        )
        sysaccount_dn = (
            f"uid={sysaccount_name},cn=sysaccounts,cn=etc,{basedn}"
        )
        tasks.create_active_user(self.master, login=test_user,
                                 password="Secret123")
        try:
            sysaccount_password = setup_sysaccout(
                self.master, sysaccount_name, privilege_name,
                permission, role_name, privileged=True
            )
            self.master.run_command(
                ['ipa', 'pwpolicy-mod', '--minlife=1', '--minlength=5']
            )
            self.master.run_command(
                ["ipa", "sysaccount-policy", sysaccount_name,
                 "--privileged=True"], raiseonerr=False
            )
            tasks.service_control_dirsrv(self.master)

            ldif_text = textwrap.dedent("""
                dn: {user_dn}
                changetype: modify
                replace: userpassword
                userpassword: {new_password}
            """).format(user_dn=user_dn, new_password='S123')
            result = tasks.run_ldapmodify(
                self.master, sysaccount_dn, sysaccount_password,
                ldif_text, raiseonerr=False
            )
            assert "Too soon to change password" in result.stderr_text

            self.master.run_command(
                ["ipa", "sysaccount-policy", sysaccount_name,
                 "--privileged=False"], raiseonerr=False
            )
            tasks.service_control_dirsrv(self.master)

            ldif_text = textwrap.dedent("""
                dn: {user_dn}
                changetype: modify
                replace: userpassword
                userpassword: {new_password}
            """).format(user_dn=user_dn, new_password='S123')
            result = tasks.run_ldapmodify(
                self.master, sysaccount_dn, sysaccount_password,
                ldif_text
            )
            assert "Too soon to change password" not in result.stderr_text

            self.master.run_command(
                ['ipa', 'pwpolicy-mod', '--minlife=0', '--minlength=5']
            )
            self.master.run_command(
                ["ipa", "sysaccount-policy", sysaccount_name,
                 "--privileged=True"], raiseonerr=False
            )
            tasks.service_control_dirsrv(self.master)

            ldif_text = textwrap.dedent("""
                dn: {user_dn}
                changetype: modify
                replace: userpassword
                userpassword: {new_password}
            """).format(user_dn=user_dn, new_password='S123')
            result = tasks.run_ldapmodify(
                self.master, sysaccount_dn, sysaccount_password,
                ldif_text, raiseonerr=False
            )
            assert "Password is too short" in result.stderr_text

            self.master.run_command(
                ["ipa", "sysaccount-policy", sysaccount_name,
                 "--privileged=False"], raiseonerr=False
            )
            tasks.service_control_dirsrv(self.master)

            ldif_text = textwrap.dedent("""
                dn: {user_dn}
                changetype: modify
                replace: userpassword
                userpassword: {new_password}
            """).format(user_dn=user_dn, new_password='S123')
            result = tasks.run_ldapmodify(
                self.master, sysaccount_dn, sysaccount_password,
                ldif_text
            )
            assert "Password is too short" not in result.stderr_text
        finally:
            tasks.kinit_admin(self.master)
            cleanup_sysaccount(
                self.master, role_name, privilege_name,
                sysaccount_name, test_user
            )
            self.master.run_command(
                ['ipa', 'pwpolicy-mod', '--minlife=1', '--minlength=8'],
                raiseonerr=False
            )

    def test_system_account_privileged_removal_on_replica(self):
        """Test that SysAcctManagersDNs persists after
        sysaccount deletion on replica
        """
        sysaccount_name = "test-privileged-replica"
        basedn = str(self.master.domain.basedn)
        sysaccount_dn = (
            f"uid={sysaccount_name},cn=sysaccounts,cn=etc,{basedn}"
        )
        config_dn = "cn=ipa_pwd_extop,cn=plugins,cn=config"
        tasks.kinit_admin(self.master)

        try:
            # Create sysaccount with --privileged=True on the master
            self.master.run_command(
                ["ipa", "sysaccount-add", sysaccount_name, "--random",
                 "--privileged=True"]
            )
            # Restart directory server to apply changes
            tasks.service_control_dirsrv(self.master)

            # Enable privileged password changes on replica
            tasks.kinit_admin(self.replicas[0])
            self.replicas[0].run_command(
                [
                    "ipa",
                    "sysaccount-policy", sysaccount_name,
                    "--privileged=true",
                ]
            )

            # Verify sysaccount DN is in SysAcctManagersDNs on master/replica
            for host in [self.master, self.replicas[0]]:
                result = tasks.ldapsearch_dm(
                    host,
                    config_dn,
                    ["(objectclass=*)", "sysacctmanagersdns"],
                    scope='base'
                ).stdout_text
                assert f"sysacctmanagersdns: {sysaccount_dn}" in result

            # Remove the sysaccount on the replica
            self.replicas[0].run_command(
                ["ipa", "sysaccount-del", sysaccount_name]
            )

            # Check that SysAcctManagersDNs attribute still contains
            # the sysaccount dn on the master
            result = tasks.ldapsearch_dm(
                self.master,
                config_dn,
                ["(objectclass=*)", "sysacctmanagersdns"],
                scope='base'
            )
            assert f"sysacctmanagersdns: {sysaccount_dn}" in result.stdout_text

            # Check that ldapmodify can remove the value
            entry_ldif = textwrap.dedent("""
                dn: {config_dn}
                changetype: modify
                delete: sysacctmanagersdns
                sysacctmanagersdns: {sysaccount_dn}
            """).format(config_dn=config_dn, sysaccount_dn=sysaccount_dn)

            self.master.run_command(
                [
                    "ldapmodify",
                    "-x",
                    "-D", str(self.master.config.dirman_dn),
                    "-w", self.master.config.dirman_password,
                    "-H", f"ldap://{self.master.hostname}",
                ],
                stdin_text=entry_ldif
            )

            # Verify the value is removed
            result = tasks.ldapsearch_dm(
                self.master,
                config_dn,
                ["(objectclass=*)", "sysacctmanagersdns"],
                scope='base'
            ).stdout_text
            assert f"sysacctmanagersdns: {sysaccount_dn}" not in result
        finally:
            # Clean up - ensure sysaccount is removed if it still exists
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "sysaccount-del", sysaccount_name], raiseonerr=False
            )


@contextlib.contextmanager
def full_backup_restore(host, data_only=False):
    """Context manager for full backup, uninstall, and restore

    :param host: host object
    :param data_only: if True, create data-only backup and tasks.ipa_restore
                      if False, create full backup, uninstall, and restore
    :yields: backup_path
    """
    # Create backup
    backup_path = tasks.get_backup_dir(host, data_only=data_only)

    if data_only:
        # For data-only backup, just yield and let caller handle restore
        yield backup_path
        # Restore from backup
        tasks.ipa_restore(host, backup_path)
    else:
        # For full backup, uninstall and restore
        # Uninstall IPA
        host.run_command(['ipa-server-install', '--uninstall', '-U'])

        # Restore from backup
        dirman_password = host.config.dirman_password
        host.run_command(
            ['ipa-restore', backup_path],
            stdin_text=f'{dirman_password}\nyes'
        )

        yield backup_path

    # Wait for services and re-authenticate
    tasks.wait_for_sssd_domain_status_online(host)
    tasks.kinit_admin(host)


class TestSystemAccountsBackupRestore(IntegrationTest):
    """Integration tests for system accounts with backuprestore"""

    topology = "line"
    num_clients = 0
    num_replicas = 0
    sys_acc1 = "account-1"
    sys_acc2 = "account-2"
    desc1 = "System Account 1"
    desc2 = "System Account 2"
    privilege_name1 = "test-privilege-password-privilege1"
    privilege_name2 = "test-privilege-password-privilege2"
    permission = "System: Change User password"
    role_name1 = "test-privilege-role1"
    role_name2 = "test-privilege-role2"
    password = "Secret123"

    def validate_sysaccount_show_output(
            self, name, expected_desc=None,
            expected_disabled=None,
            expected_password=None, expected_roles=None,
            expected_privileged=None
    ):
        """Validate output of 'ipa sysaccount-show <name> --all' command.

        Validates that output contains all expected fields with their values.

        :param name: System account name to show
        :param expected_desc: Expected description value (None to skip check)
        :param expected_disabled: Expected Account disabled(Bool, None to skip)
        :param expected_password: Expected Password value(Bool, None to skip)
        :param expected_roles: Expected Roles can be str or list(None to skip)
        :param expected_privileged: Expected privileged (Bool, None to skip)
        """
        tasks.kinit_admin(self.master)
        basedn = str(self.master.domain.basedn)

        # Run the command
        result = self.master.run_command(
            ["ipa", "sysaccount-show", name, "--all"]
        ).stdout_text

        # Validate DN
        expected_dn = f"uid={name},cn=sysaccounts,cn=etc,{basedn}"
        assert expected_dn in result

        # Validate System account ID
        assert f"System account ID: {name}" in result

        # Validate Description if provided
        if expected_desc is not None:
            assert f'Description: "{expected_desc}"' in result

        # Validate Account disabled if provided
        if expected_disabled is not None:
            expected_disabled_str = "True" if expected_disabled else "False"
            assert f"Account disabled: {expected_disabled_str}" in result

        # Validate Password if provided
        if expected_password is not None:
            expected_password_str = "True" if expected_password else "False"
            assert f"Password: {expected_password_str}" in result

        # Validate Roles if provided
        if expected_roles is not None:
            if isinstance(expected_roles, list):
                # Multiple roles - check each one is present
                for role in expected_roles:
                    assert role in result
            else:
                # Single role
                assert expected_roles in result

        # Validate objectclass
        val = "account, simplesecurityobject, top, nsMemberOf"
        assert f"objectclass: {val}" in result

        # Validate privileged if provided
        if expected_privileged is not None:
            result_lower = result.lower()
            expected_privileged = "true" if expected_privileged else "false"
            assert f"privileged: {expected_privileged}" in result_lower

    def _validate_accounts_from_config(self, account_configs):
        """Validate all system accounts from a configuration list.

        :param account_configs: List of dicts with account validation params
        """
        for config in account_configs:
            self.validate_sysaccount_show_output(
                name=config['name'],
                expected_desc=config['expected_desc'],
                expected_disabled=config['expected_disabled'],
                expected_password=True,
                expected_roles=config['expected_roles'],
                expected_privileged=config['expected_privileged']
            )

    def test_system_account_full_backup_and_restore(self):
        """
        Test backup/restore preserves default configuration
        """
        tasks.kinit_admin(self.master)
        basedn = str(self.master.domain.basedn)

        # Define account configurations
        account_configs = [
            {
                'name': self.sys_acc1,
                'expected_desc': self.desc1,
                'expected_roles': self.role_name1,
                'expected_privileged': True,
                'expected_disabled': False,
            },
            {
                'name': self.sys_acc2,
                'expected_desc': self.desc2,
                'expected_roles': self.role_name2,
                'expected_privileged': False,
                'expected_disabled': False,
            }
        ]

        # Setup system accounts
        setup_sysaccout(
            self.master, self.sys_acc1, self.privilege_name1,
            self.permission, self.role_name1, privileged=True,
            desc=self.desc1, password=self.password
        )
        setup_sysaccout(
            self.master, self.sys_acc2, self.privilege_name2,
            self.permission, self.role_name2, privileged=False,
            desc=self.desc2, password=self.password
        )

        # Generate bind DNs from account configs
        bind_dns = [
            f"uid={config['name']},cn=sysaccounts,cn=etc,{basedn}"
            for config in account_configs
        ]

        # Verify password works before backup
        for dn in bind_dns:
            tasks.run_ldapsearch(
                self.master, dn, self.password, basedn,
                ["(objectclass=*)", "dn"]
            )

        # Verify sysaccount before restore
        self._validate_accounts_from_config(account_configs)

        # Full backup, uninstall, and restore
        with full_backup_restore(self.master):
            pass

        # Verify sysaccount after restore
        self._validate_accounts_from_config(account_configs)

        # Verify password still works after restore
        for dn in bind_dns:
            tasks.run_ldapsearch(
                self.master, dn, self.password, basedn,
                ["(objectclass=*)", "dn"]
            )

    def test_system_account_data_backup_and_restore(self):
        """Test data-only backup and restore with sysaccounts"""
        sysaccount_name = "data-backup-test"
        tasks.kinit_admin(self.master)

        try:
            # Create data-only backup
            backup_path = tasks.get_backup_dir(self.master, data_only=True)

            # Create sysaccount after backup
            self.master.run_command(
                [
                    "ipa", "sysaccount-add", sysaccount_name,
                    "--desc", "Created after backup",
                    "--random"
                ]
            )
            # Restore from backup
            tasks.ipa_restore(self.master, backup_path)

            # Wait for services
            tasks.wait_for_sssd_domain_status_online(self.master)
            tasks.kinit_admin(self.master)

            # Verify sysaccount created after restore
            result = self.master.run_command(
                ["ipa", "sysaccount-show", sysaccount_name],
                raiseonerr=False
            )
            assert "not found" in result.stderr_text.lower()

        finally:
            # Clean up sysaccount if it still exists
            self.master.run_command(
                ["ipa", "sysaccount-del", sysaccount_name], raiseonerr=False
            )

    def test_system_account_backup_restore_with_roles(self):
        """Test backup/restore preserves role memberships"""
        tasks.kinit_admin(self.master)

        # Verify membership
        result = self.master.run_command(["ipa", "role-show", self.role_name1])
        assert self.sys_acc1 in result.stdout_text

        result = self.master.run_command(
            ["ipa", "sysaccount-show", self.sys_acc1]
        )
        assert self.role_name1 in result.stdout_text

        # Full backup, uninstall, and restore
        with full_backup_restore(self.master):
            pass

        # Verify role membership is preserved
        result = self.master.run_command(["ipa", "role-show", self.role_name1])
        assert self.sys_acc1 in result.stdout_text

        result = self.master.run_command(
            ["ipa", "sysaccount-show", self.sys_acc1]
        )
        assert self.role_name1 in result.stdout_text

    def test_system_account_backup_restore_disabled(self):
        """Test backup/restore preserves disabled state"""

        # Define account configurations
        account_configs = [
            {
                'name': self.sys_acc1,
                'expected_desc': self.desc1,
                'expected_roles': self.role_name1,
                'expected_privileged': True,
                'expected_disabled': True,
            }
        ]
        try:
            # Disable sysaccount
            self.master.run_command(
                ["ipa", "sysaccount-disable", self.sys_acc1]
            )
            # Verify disabled state before backup
            self._validate_accounts_from_config(account_configs)

            # Verify bind fails (disabled account)
            basedn = str(self.master.domain.basedn)
            bind_dn1 = f"uid={self.sys_acc1},cn=sysaccounts,cn=etc,{basedn}"
            result = tasks.run_ldapsearch(
                self.master, bind_dn1, self.password, basedn,
                ["(objectclass=*)", "dn"], raiseonerr=False
            )
            assert result.returncode != 0

            # Full backup, uninstall, and restore
            with full_backup_restore(self.master):
                pass

            # Verify disabled state after restore.
            self._validate_accounts_from_config(account_configs)

            # Verify bind fails (disabled account)
            result = tasks.run_ldapsearch(
                self.master, bind_dn1, self.password, basedn,
                ["(objectclass=*)", "dn"], raiseonerr=False
            )
            assert result.returncode != 0
        finally:
            # Enable sysaccount
            self.master.run_command(
                ["ipa", "sysaccount-enable", self.sys_acc1]
            )

    def test_required_sysaccounts_backup_restore(self):
        """Test that required sysaccounts are preserved during restore"""
        required_accounts = ["sudo"]
        tasks.kinit_admin(self.master)

        # Verify required accounts exist before backup
        for account in required_accounts:
            result = self.master.run_command(
                ["ipa", "sysaccount-show", account]
            )
            assert f"System account ID: {account}" in result.stdout_text

        # Full backup, uninstall, and restore
        with full_backup_restore(self.master):
            pass

        # Verify required accounts still exist after restore
        for account in required_accounts:
            result = self.master.run_command(
                ["ipa", "sysaccount-show", account]
            )
            assert f"System account ID: {account}" in result.stdout_text

            # Verify they still cannot be deleted
            result = self.master.run_command(
                ["ipa", "sysaccount-del", account], raiseonerr=False
            )
            assert result.returncode != 0
            assert "is required by the IPA master" in result.stderr_text

    def test_system_account_groups_backup_restore(self):
        """Test backup/restore of sysaccount groups (adtrust agents, etc.)"""
        tasks.kinit_admin(self.master)

        # Check if adtrust agents group exists
        basedn = str(self.master.domain.basedn)
        ldap = self.master.ldap_connect()
        adtrust_agents_dn = DN(
            ('cn', 'adtrust agents'),
            ('cn', 'sysaccounts'),
            ('cn', 'etc'),
            basedn
        )

        entry = ldap.get_entry(adtrust_agents_dn, ['member'])
        members_before = set(entry.get('member', []))

        # Full backup, uninstall, and restore
        with full_backup_restore(self.master):
            pass

        # Verify sysaccount groups are restored

        ldap = self.master.ldap_connect()
        entry = ldap.get_entry(adtrust_agents_dn, ['member'])
        members_after = set(entry.get('member', []))

        # Verify members are preserved (or at least group exists)
        # Note: Members might change if servers are different
        assert members_before == members_after

    def test_system_account_backup_restore_password_change(self):
        """Test that password changes after backup are not restored"""
        basedn = str(self.master.domain.basedn)
        tasks.kinit_admin(self.master)

        # Create sysaccount
        bind_dn = f"uid={self.sys_acc1},cn=sysaccounts,cn=etc,{basedn}"

        # Create backup
        backup_path = tasks.get_backup_dir(self.master, data_only=True)

        # Change password after backup
        new_password = ipa_generate_password()
        self.master.run_command(
            [
                "ipa", "sysaccount-mod", self.sys_acc1,
                "--password"
            ],
            stdin_text=f"{new_password}\n{new_password}\n"
        )

        # Verify new password works
        tasks.run_ldapsearch(
            self.master, bind_dn, new_password, basedn,
            ["(objectclass=*)", "dn"]
        )

        # Restore from backup
        tasks.ipa_restore(self.master, backup_path)

        # Wait for services
        tasks.wait_for_sssd_domain_status_online(self.master)
        tasks.kinit_admin(self.master)

        # Verify original password works again (restored)
        tasks.run_ldapsearch(
            self.master, bind_dn, self.password, basedn,
            ["(objectclass=*)", "dn"]
        )

        # Verify new password doesn't work
        result = tasks.run_ldapsearch(
            self.master, bind_dn, new_password, basedn,
            ["(objectclass=*)", "dn"], raiseonerr=False
        )
        assert result.returncode != 0
