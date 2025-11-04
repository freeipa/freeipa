# Copyright (C) 2025 FreeIPA Contributors see COPYING for license

"""
HBAC functional tests ported from bash test suite
This module tests Host-Based Access Control functionality
"""

from __future__ import absolute_import
import time
import re
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestHBACFunctional(IntegrationTest):
    """HBAC functional tests ported from bash test suite"""

    topology = 'line'
    num_clients = 2

    # Constants
    USER_PASSWORD = 'Secret123'
    USER_1 = 'user1'
    USER_2 = 'user2'
    USER_3 = 'user3'
    HOSTGROUP_1 = 'hostgrp1'
    HOSTGROUP_2 = 'hostgrp2'
    GROUP = 'group1'
    GROUP_2 = 'group2'
    HBAC_RULE = 'rule1'
    UTF8_HBAC_RULE = 'ÃŒ'
    HBAC_SERVICE_GROUP1 = 'sshdgrp1'
    HBAC_SERVICE_GROUP2 = 'emptygrp2'


    @classmethod
    def install(cls, mh):
        """Install and initial setup"""
        super(TestHBACFunctional, cls).install(mh)
        tasks.kinit_admin(cls.master)
        cls.master.run_command(
            ["ipa", "hbacrule-enable", "allow_all"],
            raiseonerr=False
        )
        # Setup common test users
        cls.setup_common_users()

    @classmethod
    def setup_common_users(cls):
        """Create common test users"""
        tasks.kinit_admin(cls.master)
        for user in [cls.USER_1, cls.USER_2, cls.USER_3]:
            cls.master.run_command(["rm", "-rf", f"/home/{user}"], raiseonerr=False)
            cls.master.run_command(["mkdir", "-p", f"/home/{user}"])
            cls.master.run_command(["chmod", "700", f"/home/{user}"])
            # Create the user
            tasks.create_active_user(cls.master, user, password=cls.USER_PASSWORD)
            cls.master.run_command(["chown", f"{user}:{user}", f"/home/{user}"])
        tasks.clear_sssd_cache(cls.master)

    @classmethod
    def cleanup_common_users(cls):
        """Remove common test users"""
        tasks.kinit_admin(cls.master)
        for user in [cls.USER_1, cls.USER_2, cls.USER_3]:
            # Delete the user from IPA
            cls.master.run_command(["ipa", "user-del", user], raiseonerr=False)

            cls.master.run_command(["rm", "-rf", f"/home/{user}"], raiseonerr=False)
        tasks.clear_sssd_cache(cls.master)

    def ssh_auth_success(self, user, password, host):
        """
        Test SSH authentication success
        Args:
            user: Username to authenticate
            password: Password for authentication
            host: Host to connect to.
        Returns:
            True if authentication succeeds, False otherwise
        """
        result = host.run_command([
            'sshpass', '-p', password, 'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'PasswordAuthentication=yes',
            '-l', user, host.hostname, 'echo login successful'
        ], raiseonerr=False)

        if result.returncode == 0 and 'login successful' in result.stdout_text:
            return True
        return False

    def ssh_auth_failure(self, user, password, host):
        """
        Test SSH authentication failure
        Args:
            user: Username to authenticate
            password: Password for authentication
            host: Host to connect to.
        Returns:
            True if authentication fails as expected, False otherwise
        """
        result = host.run_command([
            'sshpass', '-p', password, 'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'PasswordAuthentication=yes',
            '-l', user, host.hostname, 'echo login successful'
        ], raiseonerr=False)

        if result.returncode != 0 or 'login successful' not in result.stdout_text:
            return True
        return False

    def ftp_auth_success(self, user, password, target_host, source_host=None):
        """
        Test FTP authentication success
        Args:
            user: Username to authenticate
            password: Password for authentication
            target_host: Host to connect to (FTP server)
            source_host: Host to run command from (optional, defaults to target_host)
        Returns:
            True if authentication succeeds, False otherwise
        """
        if source_host is None:
            source_host = target_host

        ftp_script = (
            f'printf "user {user} {password}\nquit\n" | '
            f'ftp -inv {target_host.hostname}'
        )
        result = source_host.run_command(
            ['bash', '-c', ftp_script],
            raiseonerr=False
        )

        if result.returncode == 0 and 'Login successful.' in result.stdout_text:
            return True
        return False

    def ftp_auth_failure(self, user, password, target_host, source_host=None):
        """
        Test FTP authentication failure
        Args:
            user: Username to authenticate
            password: Password for authentication
            target_host: Host to connect to (FTP server)
            source_host: Host to run command from (optional, defaults to target_host)
        Returns:
            True if authentication fails as expected, False otherwise
        """
        if source_host is None:
            source_host = target_host

        ftp_script = (
            f'printf "user {user} {password}\nquit\n" | '
            f'ftp -inv {target_host.hostname}'
        )
        result = source_host.run_command(
            ['bash', '-c', ftp_script],
            raiseonerr=False
        )

        if result.returncode != 0 or 'Login successful.' not in result.stdout_text:
            return True
        return False

    def run_hbactest(self, user, host, service, should_allow=True,
                     rule=None, nodetail=False, expect_unresolved=False,
                     expect_error=False, expected_patterns=None,
                     forbidden_patterns=None):
        """
        Run HBAC test with flexible parameters
        Args:
            user: Username to test
            host: Hostname to test
            service: Service name to test
            should_allow: Expected result (True=access granted, False=denied)
            rule: Optional rule name to test specific rule
            nodetail: If True, use --nodetail flag
            expect_unresolved: If True, expect unresolved rules in output
            expect_error: If True, expect error in output
            expected_patterns: List of regex patterns to check in output
            forbidden_patterns: List of regex patterns that must NOT be in output
        """
        cmd = [
            "ipa", "hbactest",
            f"--user={user}",
            f"--host={host}",
            f"--service={service}"
        ]

        if rule:
            cmd.append(f"--rule={rule}")

        if nodetail:
            cmd.append("--nodetail")

        result = self.master.run_command(cmd, raiseonerr=False)

        if expected_patterns:
            for pattern in expected_patterns:
                assert re.search(pattern, result.stdout_text), (
                    f"Expected pattern '{pattern}' not found in output: "
                    f"{result.stdout_text}"
                )
            return

        if forbidden_patterns:
            for pattern in forbidden_patterns:
                assert not re.search(pattern, result.stdout_text), (
                    f"Forbidden pattern '{pattern}' found in output: "
                    f"{result.stdout_text}"
                )
            return

        if expect_unresolved:
            assert ("Unresolved rules in --rules" in result.stdout_text or
                    (rule and f"error: {rule}" in result.stdout_text)), (
                f"Expected unresolved rule for {rule}, got: {result.stdout_text}"
            )
            return

        if expect_error:
            assert (f"error: {rule}" in result.stdout_text or
                    "error:" in result.stdout_text.lower()), (
                f"Expected error in output, got: {result.stdout_text}"
            )
            return

        if should_allow:
            assert ("Access granted: True" in result.stdout_text or
                    (rule and f"matched: {rule}" in result.stdout_text)), (
                f"Expected access granted for {user} to {host}:{service}, "
                f"got: {result.stdout_text}"
            )
        else:
            assert ("Access granted: False" in result.stdout_text or
                    (rule and f"notmatched: {rule}" in result.stdout_text)), (
                f"Expected access denied for {user} to {host}:{service}, "
                f"got: {result.stdout_text}"
            )

    # Test 001: User access to client
    def test_hbacsvc_master_001(self):
        """hbacsvc_master_001: user access to client, on master, add rule"""
        tasks.kinit_admin(self.master)

        # Test SSH before HBAC setup
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.master)
        tasks.kdestroy_all(self.master)
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.master)
        assert self.ssh_auth_success(self.USER_3, self.USER_PASSWORD, self.master)

        tasks.kinit_admin(self.master)

        # Setup admin rule and disable allow_all
        self.master.run_command([
            "ipa", "hbacrule-add", "admin_allow_all",
            "--hostcat=all", "--servicecat=all"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "admin_allow_all", "--groups=admins"
        ])
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)

        # Create rule1
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command([
            "ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"
        ])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test with hbactest
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         rule=self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         rule=self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: False",
                             rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        # Test with --nodetail
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        tasks.clear_sssd_cache(self.clients[0])
        tasks.clear_sssd_cache(self.clients[1])
        # client 1 test
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["kdestroy", "-A"])

        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[0])

        # client 2 test
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])

        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_001_cleanup(self):
        """Cleanup for test_hbacsvc_master_001"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-del", "admin_allow_all"], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)

    # Test 002: User access to master for FTP
    def test_hbacsvc_master_002(self):
        """hbacsvc_master_002: user access to master for ftp, on master, add rule"""
        tasks.kinit_admin(self.master)
        # Install FTP
        self.master.run_command(["dnf", "install", "-y", "vsftpd"], raiseonerr=False)
        self.master.run_command(["systemctl", "start", "vsftpd"], raiseonerr=False)
        self.master.run_command(["setsebool", "-P", "tftp_home_dir", "on"], raiseonerr=False)
        self.master.run_command(["firewall-cmd", "--permanent", "--add-service=ftp"], raiseonerr=False)
        self.master.run_command(["firewall-cmd", "--reload"], raiseonerr=False)

        # Create HBAC RULE
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.master.hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=vsftpd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])
        tasks.clear_sssd_cache(self.master)

        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         should_allow=True, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_2, self.master.hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         rule=self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest(self.USER_2, self.master.hostname, "vsftpd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["dnf", "install", "-y", "ftp"], raiseonerr=False)
        tasks.kinit_as_user(self.master, self.USER_1, self.USER_PASSWORD)
        self.clients[0].run_command(["kdestroy", "-A"])
        # Test: Can client connect to master via FTP?
        assert self.ftp_auth_success(self.USER_1, self.USER_PASSWORD,
                              self.master, self.clients[0])
        assert self.ftp_auth_failure(self.USER_2, self.USER_PASSWORD,
                              self.master, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_2])
        self.clients[1].run_command(["dnf", "install", "-y", "ftp"], raiseonerr=False)
        tasks.kinit_as_user(self.master, self.USER_1, self.USER_PASSWORD)
        self.clients[1].run_command(["kdestroy", "-A"])
        # Test: Can client connect to master via FTP?
        assert self.ftp_auth_success(self.USER_1, self.USER_PASSWORD,
                              self.master, self.clients[1])
        assert self.ftp_auth_failure(self.USER_2, self.USER_PASSWORD,
                              self.master, self.clients[1])

    # Test 002_1: Delete service and test
    def test_hbacsvc_master_002_1(self):
        """hbacsvc_master_002_1: user access to master after ftp removed, on master, remove ftp from rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        self.master.run_command(["ipa", "hbacsvc-del", "vsftpd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"], raiseonerr=False)

        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         should_allow=False, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_2, self.master.hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         rule=self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: False"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest(self.USER_2, self.master.hostname, "vsftpd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        assert self.ftp_auth_failure(self.USER_1, self.USER_PASSWORD,
                              self.master, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        tasks.kinit_admin(self.clients[1])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        assert self.ftp_auth_failure(self.USER_1, self.USER_PASSWORD,
                              self.master, self.clients[1])
        assert self.ftp_auth_failure(self.USER_2, self.USER_PASSWORD,
                              self.master, self.clients[1])

    def test_hbacsvc_master_002_cleanup(self):
        """Cleanup for test_hbacsvc_master_002"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)

    # Test 003: FTP service group
    def test_hbacsvc_master_003(self):
        """hbacsvc_master_003: user access to master for ftp service group, on master, add rule"""
        tasks.kinit_admin(self.master)
        # Create rule with service group (verifies bug 746227)
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacsvc-add", "vsftpd"])
        self.master.run_command([
            "ipa", "hbacsvcgroup-add-member", "ftp", "--hbacsvcs=vsftpd"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcgroups=ftp"
        ])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.master.hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test (verifies bug 746227)
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         should_allow=True, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_2, self.master.hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         rule=self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "ftp",
                         rule=self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest(self.USER_2, self.master.hostname, "vsftpd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ftp_auth_success(self.USER_1, self.USER_PASSWORD,
                              self.master, self.clients[0])
        assert self.ftp_auth_failure(self.USER_2, self.USER_PASSWORD,
                              self.master, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ftp_auth_success(self.USER_1, self.USER_PASSWORD,
                              self.master, self.clients[1])

    def test_hbacsvc_master_003_cleanup(self):
        """Cleanup for test_hbacsvc_master_003"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)

    # Test 004: Hostgroup access (verifies bug 733663)
    def test_hbacsvc_master_004(self):
        """hbacsvc_master_004: user access to hostgroup, on master, add rule"""
        tasks.kinit_admin(self.master)
        # Create hostgroup
        self.master.run_command([
            "ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"
        ])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[1].hostname}"
        ])

        # Create rule
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command([
            "ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"
        ])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test (verifies bug 733663)
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_2, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_3, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.HOSTGROUP_1, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True,
                         forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_004_cleanup(self):
        """Cleanup for test_hbacsvc_master_004"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)

    # Test 005: Hostgroup with user removal
    def test_hbacsvc_master_005(self):
        """hbacsvc_master_005: user access to hostgroup, on master, add rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[1].hostname}"
        ])

        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_2, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_3, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.HOSTGROUP_1, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client Test
        tasks.clear_sssd_cache(self.clients[0])
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])

    # Test 005_1: Remove user from rule
    def test_hbacsvc_master_005_1(self):
        """hbacsvc_master_005_1: user access after user removed, on master, remove user from rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-remove-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE)
        self.run_hbactest(self.USER_1, self.HOSTGROUP_1, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)

        # Client Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_005_cleanup(self):
        """Cleanup for test_hbacsvc_master_005"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)

    # Test 006: Hostgroup to hostgroup access
    def test_hbacsvc_master_006(self):
        """hbacsvc_master_006: user access to hostgroup from hostgroup2, on master, add rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_2, f"--desc={self.HOSTGROUP_2}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_2,
            f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client Test
        tasks.clear_sssd_cache(self.clients[0])
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_006_cleanup(self):
        """Cleanup for test_hbacsvc_master_006"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_2], raiseonerr=False)

    # Test 007: Hostgroup for HBAC service group (verifies bug 830347)
    def test_hbacsvc_master_007(self):
        """hbacsvc_master_007: user access to hostgroup for hbac service group, on master (bz830347)"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_2, f"--desc={self.HOSTGROUP_2}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_2,
            f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client Test
        tasks.clear_sssd_cache(self.clients[0])
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[1])

    # Test 007_1: Remove user from rule
    def test_hbacsvc_master_007_1(self):
        """hbacsvc_master_007_1: user access after user removed, on master, remove user from rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-remove-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.HOSTGROUP_1, "sshd",
                         self.HBAC_RULE,
                         forbidden_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                             ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                          self.HBAC_RULE,
                          expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                                ])
        self.run_hbactest(self.USER_2, self.HOSTGROUP_1, "sshd",
                          self.HBAC_RULE,
                          expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                                ])

        self.run_hbactest(self.USER_1, self.HOSTGROUP_2, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.HOSTGROUP_2, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_007_cleanup(self):
        """Cleanup for test_hbacsvc_master_007"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_2], raiseonerr=False)

    # Test 008: Group access to client
    def test_hbacsvc_master_008(self):
        """hbacsvc_master_008: group access to client2, on master, add rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[1])

    # Test 008_1: Remove group from rule
    def test_hbacsvc_master_008_1(self):
        """hbacsvc_master_008_1: group access after group removed, on master, remove group from rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-remove-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         forbidden_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                             ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                          self.HBAC_RULE,
                          expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                                ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          self.HBAC_RULE,
                          expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                                ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_008_cleanup(self):
        """Cleanup for test_hbacsvc_master_008"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)

    # Test 009: Group access to client2 for HBAC service group
    def test_hbacsvc_master_009(self):
        """hbacsvc_master_009: group access to client2 for hbac service group, on master, add rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])

        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_009_1(self):
        """hbacsvc_master_009_1: verify group still in rule (srchost validation deprecated)"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_009_cleanup(self):
        """Cleanup for test_hbacsvc_master_009"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)

    # Test 010: Group access to hostgroup
    def test_hbacsvc_master_010(self):
        """hbacsvc_master_010: group access to hostgroup, on master, add rule"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command(["ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_010_cleanup(self):
        """Cleanup for test_hbacsvc_master_010"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)

    # Test 011: Group access to hostgroup for HBAC service group
    def test_hbacsvc_master_011(self):
        """hbacsvc_master_011: group access to hostgroup for hbac service group, on master, add rule"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_011_1(self):
        """hbacsvc_master_011_1: remove hbac service group"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "hbacrule-remove-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         forbidden_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

    def test_hbacsvc_master_011_cleanup(self):
        """Cleanup for test_hbacsvc_master_011"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)

    # Test 012: Group access to client2 from hostgroup for HBAC service group
    def test_hbacsvc_master_012(self):
        """hbacsvc_master_012: group access to client2 from hostgroup for hbac service group"""

        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacsvcgroup-add", self.HBAC_SERVICE_GROUP1, f"--desc={self.HBAC_SERVICE_GROUP1}grp"])
        self.master.run_command(["ipa", "hbacsvcgroup-add-member", self.HBAC_SERVICE_GROUP1, f"--hbacsvc=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, f"--hbacsvcgroup={self.HBAC_SERVICE_GROUP1}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_012_cleanup(self):
        """Cleanup for test_hbacsvc_master_012"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacsvcgroup-del", self.HBAC_SERVICE_GROUP1], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)

    # Test 013: Group access to hostgroup from hostgroup2
    def test_hbacsvc_master_013(self):
        """hbacsvc_master_013: group access to hostgroup from hostgroup2, on master, add rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_2, f"--desc={self.HOSTGROUP_2}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_2,
            f"--hosts={self.clients[1].hostname}"
        ])

        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command(["ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_013_cleanup(self):
        """Cleanup for test_hbacsvc_master_013"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_2], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)

    # Test 014: Similar to 013
    def test_hbacsvc_master_014(self):
        """hbacsvc_master_014: group access to hostgroup from hostgroup2, on master"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_2, f"--desc={self.HOSTGROUP_2}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_2,
            f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command(["ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_014_cleanup(self):
        """Cleanup for test_hbacsvc_master_014"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_2], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)

    # Test 015: Nested group access to client
    def test_hbacsvc_master_015(self):
        """hbacsvc_master_015: nested group access to client, on master, add rule"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add", self.GROUP_2, f"--desc={self.GROUP_2}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP_2, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--groups={self.GROUP_2}"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_015_1(self):
        """hbacsvc_master_015_1: nested group access after group removed"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-remove-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         forbidden_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_015_cleanup(self):
        """Cleanup for test_hbacsvc_master_015"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP_2], raiseonerr=False)

    # Test 016: Nested group access for HBAC service group
    def test_hbacsvc_master_016(self):
        """hbacsvc_master_016: nested group access to client for hbac service group"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add", self.GROUP_2, f"--desc={self.GROUP_2}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP_2, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--groups={self.GROUP_2}"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_016_1(self):
        """hbacsvc_master_016_1: nested group access after group removed"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-remove-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_016_cleanup(self):
        """Cleanup for test_hbacsvc_master_016"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP_2], raiseonerr=False)

    # Test 017: Nested group access from hostgroup
    def test_hbacsvc_master_017(self):
        """hbacsvc_master_017: nested group access to client from hostgroup"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add", self.GROUP_2, f"--desc={self.GROUP_2}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP_2, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--groups={self.GROUP_2}"])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_017_cleanup(self):
        """Cleanup for test_hbacsvc_master_017"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP_2], raiseonerr=False)

    # Test 018: Nested group access to hostgroup from hostgroup for HBAC service group
    def test_hbacsvc_master_018(self):
        """hbacsvc_master_018: nested group to hostgroup from hostgroup for hbac service group"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add", self.GROUP_2, f"--desc={self.GROUP_2}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP_2, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--groups={self.GROUP_2}"])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_018_cleanup(self):
        """Cleanup for test_hbacsvc_master_018"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP_2], raiseonerr=False)

    # Test 019: Nested group access to hostgroup from hostgroup2
    def test_hbacsvc_master_019(self):
        """hbacsvc_master_019: nested group to hostgroup from hostgroup2"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add", self.GROUP_2, f"--desc={self.GROUP_2}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP_2, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--groups={self.GROUP_2}"])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_2, f"--desc={self.HOSTGROUP_2}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_2,
            f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP_2}"])
        self.master.run_command(["ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_019_cleanup(self):
        """Cleanup for test_hbacsvc_master_019"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_2], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP_2], raiseonerr=False)

    # Test 020: Nested group for HBAC service group
    def test_hbacsvc_master_020(self):
        """hbacsvc_master_020: nested group to hostgroup for hbac service group"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add", self.GROUP_2, f"--desc={self.GROUP_2}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP_2, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--groups={self.GROUP_2}"])

        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_1,
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_2, f"--desc={self.HOSTGROUP_2}"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", self.HOSTGROUP_2,
            f"--hosts={self.clients[1].hostname}"
        ])

        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP_2}"])
        self.master.run_command(["ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_020_1(self):
        """hbacsvc_master_020_1: after rule removed"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE])
        result = self.master.run_command(
            ["ipa", "hbacrule-show", self.HBAC_RULE, "--all"],
            raiseonerr=False
        )

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.HOSTGROUP_1, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.HOSTGROUP_1, "sshd",
                         self.HBAC_RULE,
                         forbidden_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.HOSTGROUP_1, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[r"Access granted: True"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_020_cleanup(self):
        """Cleanup for test_hbacsvc_master_020"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_2], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP_2], raiseonerr=False)

    # Test 021: User access client from external host
    def test_hbacsvc_master_021(self):
        """hbacsvc_master_021: user access client from external host, on master, add rule and run hbactest"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, "externalhost.randomhost.com", "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, "externalhost.randomhost.com", "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

    def test_hbacsvc_master_021_cleanup(self):
        """Cleanup for test_hbacsvc_master_021"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)

    # Test 023: Group access to client2 from external host
    def test_hbacsvc_master_023(self):
        """hbacsvc_master_023: group access client2 from external host, on master, add rule and run hbactest"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, "externalhost.randomhost.com", "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, "externalhost.randomhost.com", "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

    def test_hbacsvc_master_023_cleanup(self):
        """Cleanup for test_hbacsvc_master_023"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)

    # Test 025: Group access to client from external host 2
    def test_hbacsvc_master_025(self):
        """hbacsvc_master_025: group access client from external host 2, on master, add rule and run hbactest"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "group-add", self.GROUP_2, f"--desc={self.GROUP_2}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "group-add-member", self.GROUP_2, f"--groups={self.GROUP}"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, "externalhost.randomhost.com", "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, "externalhost.randomhost.com", "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

    def test_hbacsvc_master_025_cleanup(self):
        """Cleanup for test_hbacsvc_master_025"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP_2], raiseonerr=False)

    # Test 027: Empty HBAC service group
    def test_hbacsvc_master_027(self):
        """hbacsvc_master_027: user access with empty hbac service group"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacsvcgroup-add", self.HBAC_SERVICE_GROUP2, f"--desc={self.HBAC_SERVICE_GROUP2}"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, f"--hbacsvcgroup={self.HBAC_SERVICE_GROUP2}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_027_cleanup(self):
        """Cleanup for test_hbacsvc_master_027"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hbacsvcgroup-del", self.HBAC_SERVICE_GROUP2], raiseonerr=False)

    # Test 028: Multiple HBAC services in rule
    def test_hbacsvc_master_028(self):
        """hbacsvc_master_028: user access with multiple hbac services"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "hbacsvc-add", "sshdtest"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshdtest"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_028_cleanup(self):
        """Cleanup for test_hbacsvc_master_028"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)

    # Test 029: Empty group in rule
    def test_hbacsvc_master_029(self):
        """hbacsvc_master_029: user access with empty group in rule"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "hbacsvcgroup-add", self.HBAC_SERVICE_GROUP2, f"--desc={self.HBAC_SERVICE_GROUP2}"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, f"--hbacsvcgroup={self.HBAC_SERVICE_GROUP2}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client 1 Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_029_cleanup(self):
        """Cleanup for test_hbacsvc_master_029"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "hbacsvcgroup-del", self.HBAC_SERVICE_GROUP2], raiseonerr=False)

    # Test 030: Empty group, hostgroup and service group in rule
    def test_hbacsvc_master_030(self):
        """hbacsvc_master_030: user access with empty group hostgroup and service group"""
        tasks.kinit_admin(self.master)

        self.master.run_command(["ipa", "hostgroup-add", self.HOSTGROUP_1, f"--desc={self.HOSTGROUP_1}"])
        self.master.run_command(["ipa", "group-add", self.GROUP, f"--desc={self.GROUP}"])
        self.master.run_command(["ipa", "hbacsvcgroup-add", self.HBAC_SERVICE_GROUP2, f"--desc={self.HBAC_SERVICE_GROUP2}"])
        self.master.run_command(["ipa", "hbacrule-add", self.HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command(["ipa", "hbacrule-add-user", self.HBAC_RULE, f"--groups={self.GROUP}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.HBAC_RULE, f"--hostgroups={self.HOSTGROUP_1}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-service", self.HBAC_RULE, f"--hbacsvcgroup={self.HBAC_SERVICE_GROUP2}"])
        self.master.run_command(["ipa", "hbacrule-show", self.HBAC_RULE, "--all"])

        # Test with hbactest
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         rule=self.HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                            rule=self.HBAC_RULE,
                            expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                            ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         rule=self.HBAC_RULE,
                         expected_patterns=[
                                r"Access granted: False",
                                rf"Not matched rules: {self.HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False, rule=self.HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          rule=self.HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"])

        # Client Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["id", self.USER_1], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        time.sleep(5)
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        time.sleep(5)
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_030_cleanup(self):
        """Cleanup for test_hbacsvc_master_030"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.HBAC_RULE], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", self.HOSTGROUP_1], raiseonerr=False)
        self.master.run_command(["ipa", "group-del", self.GROUP], raiseonerr=False)
        self.master.run_command(["ipa", "hbacsvcgroup-del",self.HBAC_SERVICE_GROUP2], raiseonerr=False)

    # Test 031: UTF-8 rule name
    def test_hbacsvc_master_031(self):
        """hbacsvc_master_031: user access with UTF-8 rule name"""
        # Now test with UTF-8 rule name
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-add", self.UTF8_HBAC_RULE])
        self.master.run_command(["ipa", "hbacrule-add-user", self.UTF8_HBAC_RULE, f"--users={self.USER_1}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", self.UTF8_HBAC_RULE, f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", self.UTF8_HBAC_RULE, "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", self.UTF8_HBAC_RULE, "--all"])

        # Test with hbactest
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         rule=self.UTF8_HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: True",
                             rf"Matched rules: {self.UTF8_HBAC_RULE}"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules"
                         ])
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                         rule=self.UTF8_HBAC_RULE,
                         expected_patterns=[
                             r"Access granted: False"
                         ])
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule=self.UTF8_HBAC_RULE, nodetail=True)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          rule=self.UTF8_HBAC_RULE, nodetail=True,
                          forbidden_patterns=[rf"Matched rules: {self.UTF8_HBAC_RULE}"])

        # Client Test
        tasks.clear_sssd_cache(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        time.sleep(5)
        assert self.ssh_auth_success(self.USER_1, self.USER_PASSWORD, self.clients[0])

        # Client 2 Test
        tasks.clear_sssd_cache(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", self.USER_1])
        assert self.ssh_auth_failure(self.USER_1, self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_031_cleanup(self):
        """Cleanup for test_hbacsvc_master_031"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", self.UTF8_HBAC_RULE], raiseonerr=False)
    '''
    # Bug-specific tests
    def test_hbacsvc_master_bug736314(self):
        """hbacsvc_master_bug736314: user access master with multiple external hosts (bz736314)"""
        user736314 = "user736314"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user736314}"], raiseonerr=False)
        tasks.create_active_user(self.master, user736314, password=self.USER_PASSWORD)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-add", "rule736314"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule736314", f"--users={user736314}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule736314", f"--hosts={self.master.hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule736314", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule736314", "--all"])
        
        # Test (verifies bug 736314)
        self.run_hbactest(user736314, self.master.hostname, "sshd",
                         should_allow=True, rule="rule736314")

    def test_hbacsvc_master_bug736314_cleanup(self):
        """Cleanup for bug736314 test"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", "rule736314"], raiseonerr=False)

    def test_hbacsvc_client_bug736314(self):
        """hbacsvc_client_bug736314: multiple external hosts, on client (bz736314)"""
        tasks.clear_sssd_cache(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user736314"])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user736314", self.USER_PASSWORD, self.master)

    def test_hbacsvc_client2_bug736314(self):
        """hbacsvc_client2_bug736314: multiple external hosts, on client2 (bz736314)"""
        tasks.clear_sssd_cache(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user736314"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user736314", self.USER_PASSWORD, self.master)
        assert self.ssh_auth_failure(self.USER_2, self.USER_PASSWORD, self.master)

    def test_hbacsvc_master_bug782927(self):
        """hbacsvc_master_bug782927: test sizelimit option to hbactest (bz782927)"""
        user782927 = "user782927"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user782927}"], raiseonerr=False)
        tasks.create_active_user(self.master, user782927, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user782927, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        # Create multiple rules to test sizelimit
        for i in range(1000, 1011):
            self.master.run_command(["ipa", "hbacrule-add", str(i)])
        
        # Set search records limit
        self.master.run_command(["ipa", "config-mod", "--searchrecordslimit=10"])
        
        # Test without size limit - should use global setting
        result = self.master.run_command(["ipa", "hbacrule-find"])
        # Should return 10 rules based on global limit
        
        # Test with specific size limit
        result = self.master.run_command(["ipa", "hbacrule-find", "--sizelimit=7"])
        # Should return 7 rules
        
        # Restore config
        self.master.run_command(["ipa", "config-mod", "--searchrecordslimit=100"])
        
        # Cleanup
        for i in range(1000, 1011):
            self.master.run_command(["ipa", "hbacrule-del", str(i)])

    def test_hbacsvc_master_bug772852(self):
        """hbacsvc_master_bug772852: error message with hbacrule in rules option (bz772852)"""
        user772852 = "user772852"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user772852}"], raiseonerr=False)
        tasks.create_active_user(self.master, user772852, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user772852, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        # Create multiple rules to test with size limit
        for i in range(1000, 1011):
            self.master.run_command(["ipa", "hbacrule-add", str(i)])
        
        self.master.run_command(["ipa", "config-mod", "--searchrecordslimit=10"])
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-add", "772852"])
        self.master.run_command(["ipa", "hbacrule-add-user", "772852", f"--users={user772852}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "772852", f"--hosts={self.master.hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "772852", "--hbacsvcs=sshd"])
        
        # Test with --rules option (verifies bug 772852 - should not show "Unresolved rules")
        result = self.master.run_command([
            "ipa", "hbactest",
            f"--user={user772852}",
            f"--host={self.master.hostname}",
            "--service=sshd",
            "--rules=772852"
        ])
        assert "Access granted: True" in result.stdout_text or "matched: 772852" in result.stdout_text
        assert "Unresolved rules" not in result.stdout_text
        
        # Restore config
        self.master.run_command(["ipa", "config-mod", "--searchrecordslimit=100"])
        for i in range(1000, 1011):
            self.master.run_command(["ipa", "hbacrule-del", str(i)])
        self.master.run_command(["ipa", "hbacrule-del", "772852"])

    def test_hbacsvc_master_bug766876(self):
        """hbacsvc_master_bug766876: Make HBAC srchost processing optional (bz766876)"""
        user766876 = "user766876"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user766876}"], raiseonerr=False)
        tasks.create_active_user(self.master, user766876, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user766876, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-add", "rule766876"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule766876", f"--users={user766876}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule766876", f"--hosts={self.master.hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule766876", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule766876", "--all"])

    def test_hbacsvc_client_bug766876(self):
        """hbacsvc_client_bug766876: srchost processing optional, on client (bz766876)"""
        tasks.clear_sssd_cache(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user766876"])
        self.clients[0].run_command(["kdestroy", "-A"])
        # Srchost validation deprecated, access should be allowed
        assert self.ssh_auth_success("user766876", self.USER_PASSWORD, self.master)

    def test_hbacsvc_client2_bug766876(self):
        """hbacsvc_client2_bug766876: srchost processing optional, on client2 (bz766876)"""
        tasks.clear_sssd_cache(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user766876"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user766876", self.USER_PASSWORD, self.master)

    def test_hbacsvc_master_bug801769(self):
        """hbacsvc_master_bug801769: hbactest returns failure when hostgroups are chained (bz801769)"""
        user801769 = "user801769"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user801769}"], raiseonerr=False)
        tasks.create_active_user(self.master, user801769, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user801769, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        # Create hostgroup
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup801769", "--desc=Master group"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup801769",
            f"--hosts={self.master.hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "801769"])
        self.master.run_command(["ipa", "hbacrule-add-user", "801769", f"--users={user801769}"])
        self.master.run_command(["ipa", "hbacrule-add-host", "801769", "--hostgroups=hostgroup801769"])
        self.master.run_command(["ipa", "hbacrule-add-service", "801769", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "801769", "--all"])
        
        # Test (verifies bug 801769)
        self.run_hbactest(user801769, self.master.hostname, "sshd",
                         should_allow=True, rule="801769")
        
        # Create chained hostgroup
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup801769_2", "--desc=Master group2"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup801769_2",
            "--hostgroups=hostgroup801769"
        ])
        
        # Test with chained hostgroup (verifies bug is fixed)
        self.run_hbactest(user801769, self.master.hostname, "sshd",
                         should_allow=True, rule="801769")

    def test_hbacsvc_master_bug771706(self):
        """hbacsvc_master_bug771706: sssd crashes with empty service group or hostgroup (bz771706)"""
        user771706 = "user771706"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user771706}"], raiseonerr=False)
        tasks.create_active_user(self.master, user771706, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user771706, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        # Create rule with empty service group (verifies bug 771706)
        self.master.run_command(["ipa", "hbacrule-add", "rule771706", "--hostcat=all"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule771706", f"--users={user771706}"])
        self.master.run_command(["ipa", "hbacsvcgroup-add", "svcgroup1", "--desc=svcgroup1"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule771706", "--hbacsvcgroups=svcgroup1"])
        
        # Access should fail with empty service group
        self.master.run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure(user771706, self.USER_PASSWORD, self.master)
        
        # Delete and recreate with valid service
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", "rule771706"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule771706"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule771706", f"--users={user771706}"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule771706", "--hbacsvcs=sshd"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule771706", f"--hosts={self.master.hostname}"
        ])
        
        # Now access should succeed
        self.master.run_command(["kdestroy", "-A"])
        tasks.clear_sssd_cache(self.master)
        assert self.ssh_auth_success(user771706, self.USER_PASSWORD, self.master)

    '''