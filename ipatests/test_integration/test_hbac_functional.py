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

    @classmethod
    def install(cls, mh):
        """Install and initial setup"""
        super(TestHBACFunctional, cls).install(mh)
        tasks.kinit_admin(cls.master)
        cls.master.run_command(
            ["ipa", "hbacrule-enable", "allow_all"],
            raiseonerr=False
        )

    def ssh_auth_success(self, user, password, host):
        """
        Test SSH authentication success
        Args:
            user: Username to authenticate
            password: Password for authentication
            host: Host to connect to
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
            host: Host to connect to
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

    def run_hbactest(self, user, host, service, should_allow=True,
                     rule=None, nodetail=False, expect_unresolved=False,
                     expect_error=False, expected_patterns=None):
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

        # Check for specific patterns if provided
        if expected_patterns:
            for pattern in expected_patterns:
                assert re.search(pattern, result.stdout_text), (
                    f"Expected pattern '{pattern}' not found in output: "
                    f"{result.stdout_text}"
                )
            return  # Skip other checks if custom patterns are used

        # Check for unresolved rules
        if expect_unresolved:
            assert ("Unresolved rules in --rules" in result.stdout_text or
                    (rule and f"error: {rule}" in result.stdout_text)), (
                f"Expected unresolved rule for {rule}, got: {result.stdout_text}"
            )
            return

        # Check for errors
        if expect_error:
            assert (f"error: {rule}" in result.stdout_text or
                    "error:" in result.stdout_text.lower()), (
                f"Expected error in output, got: {result.stdout_text}"
            )
            return

        # Standard access granted/denied checks
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
        user1 = "user1"
        user2 = "user2"
        user3 = "user3"

        tasks.kinit_admin(self.master)

        # Create users
        for i in [1, 2, 3]:
            username = f"user{i}"
            self.master.run_command(["rm", "-rf", f"/home/{username}"], raiseonerr=False)
            tasks.create_active_user(self.master, username, password=self.USER_PASSWORD)
            self.master.run_command(["su", "-", username, "-c", "pwd"], raiseonerr=False)
            time.sleep(2)

        # Test SSH before HBAC setup
        assert self.ssh_auth_success(user1, self.USER_PASSWORD, self.master)
        tasks.kdestroy_all(self.master)
        assert self.ssh_auth_success(user1, self.USER_PASSWORD, self.master)
        assert self.ssh_auth_success(user3, self.USER_PASSWORD, self.master)

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
        self.master.run_command(["ipa", "hbacrule-add", "rule1"])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule1", f"--users={user1}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule1",
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule1", "--hbacsvcs=sshd"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule1", "--all"])

        # Test with hbactest
        self.run_hbactest(user1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule1")
        self.run_hbactest(user2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user1, self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule1")
        self.run_hbactest("user1", self.clients[0].hostname, "sshd",
                         rule="rule1",
                         expected_patterns=[
                             r"Access granted: True",
                             r"Matched rules: rule1"
                         ])
        self.run_hbactest("user1", self.clients[0].hostname, "sshd",
                         rule="rule2",
                         expected_patterns=[
                             r"Unresolved rules in --rules",
                             r"Non-existent or invalid rules: rule2"
                         ])
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         rule="rule1",
                         expected_patterns=[
                             r"Access granted: False",
                             r"Not matched rules: rule1"
                         ])
        # Test with --nodetail
        self.run_hbactest(user1, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule1", nodetail=True)
        tasks.clear_sssd_cache(self.clients[0])
        tasks.clear_sssd_cache(self.clients[1])

    def test_hbacsvc_master_001_cleanup(self):
        """Cleanup for test_hbacsvc_master_001"""
        tasks.kinit_admin(self.master)
        for i in [1, 2, 3]:
            self.master.run_command([f"ipa", "user-del", f"user{i}"], raiseonerr=False)
            self.master.run_command(["rm", "-rf", f"/home/user{i}"], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-del", "rule1"], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-del", "admin_allow_all"], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)

    def test_hbacsvc_client_001(self):
        """hbacsvc_client_001: user access to client, on client, allow only user to client"""
        user1 = "user1"
        user2 = "user2"

        self.clients[0].run_command(["getent", "-s", "sss", "passwd", user1])
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["kdestroy", "-A"])

        assert self.ssh_auth_success(user1, self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure(user2, self.USER_PASSWORD, self.clients[0])

        tasks.clear_sssd_cache(self.client)

    def test_hbacsvc_client2_001(self):
        """hbacsvc_client2_001: user access to client, on client2, deny user to client2"""
        user1 = "user1"

        self.clients[1].run_command(["getent", "-s", "sss", "passwd", user1])
        self.clients[1].run_command(["kdestroy", "-A"])

        assert self.ssh_auth_failure(user1, self.USER_PASSWORD, self.clients[1])
        tasks.clear_sssd_cache(self.client1)
    '''
    # Test 002: User access to master for FTP
    def test_hbacsvc_master_002(self):
        """hbacsvc_master_002: user access to master for ftp, on master, add rule"""
        tasks.kinit_admin(self.master)
        
        # Create users
        for i in [1, 2, 3]:
            username = f"user{i}"
            self.master.run_command(["rm", "-rf", f"/home/{username}"], raiseonerr=False)
            self.master.run_command(["mkdir", "-p", f"/home/{username}"])
            self.master.run_command(["chmod", "700", f"/home/{username}"])
            tasks.create_active_user(self.master, username, password=self.USER_PASSWORD)
            self.master.run_command(["chown", f"{username}.{username}", f"/home/{username}"])
            time.sleep(5)
            self.master.run_command(["su", "-", username, "-c", "pwd"], raiseonerr=False)

        tasks.kinit_admin(self.master)
        # Disable allow_all
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)

        # Install FTP
        self.master.run_command(["dnf", "install", "-y", "vsftpd"], raiseonerr=False)
        self.master.run_command(["systemctl", "start", "vsftpd"], raiseonerr=False)
        self.master.run_command(["setsebool", "-P", "tftp_home_dir", "on"], raiseonerr=False)

        # Create rule2
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-add", "rule2"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule2", "--users=user1"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule2", f"--hosts={self.master.hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule2", "--hbacsvcs=vsftpd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule2", "--all"])
        tasks.clear_sssd_cache(self.master)

        # Test with hbactest - Basic tests
        self.run_hbactest("user1", self.master.hostname, "vsftpd",
                         should_allow=True, rule="rule2")
        self.run_hbactest("user2", self.master.hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest("user1", self.clients[0].hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest("user1", self.clients[1].hostname, "vsftpd",
                         should_allow=False)

        # Additional verification tests - checking specific output patterns
        # Test 1: Verify that testing with sshd service against rule2 shows unresolved
        # (rule2 is configured for vsftpd, not sshd)
        self.run_hbactest("user1", self.master.hostname, "sshd",
                         rule="rule2",
                         expected_patterns=[
                             r"Access granted: False,"
                             r"notmatched: rule2"
                         ])

        # Test 2: Create rule1 for user1 with sshd and test that user2 is denied
        self.master.run_command(["ipa", "hbacrule-add", "rule1"], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-add-user", "rule1", "--users=user1"], 
                               raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-add-host", "rule1", 
                               f"--hosts={self.master.hostname}"], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-add-service", "rule1", "--hbacsvcs=sshd"],
                               raiseonerr=False)

        # Verify user2 is explicitly denied access with rule1
        self.run_hbactest("user2", self.master.hostname, "sshd",
                         rule="rule1",
                         expected_patterns=[
                             r"Access granted: False",
                             r"notmatched: rule1"
                         ])

        # Test 3: Test with non-existent rule to verify unresolved error
        self.run_hbactest("user1", self.master.hostname, "sshd",
                         rule="nonexistent_rule",
                         expect_unresolved=True)

        # Cleanup rule1
        self.master.run_command(["ipa", "hbacrule-del", "rule1"], raiseonerr=False)

    def test_hbacsvc_master_002_cleanup(self):
        """Cleanup for test_hbacsvc_master_002"""
        tasks.kinit_admin(self.master)
        for i in [1, 2, 3]:
            self.master.run_command([f"ipa", "user-del", f"user{i}"], raiseonerr=False)
            self.master.run_command(["rm", "-rf", f"/home/user{i}"], raiseonerr=False)
        self.master.run_command(["rm", "-fr", "/tmp/krb5cc_*_*"], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-del", "rule2"], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)

    def test_hbacsvc_client_002(self):
        """hbacsvc_client_002: user access to master for ftp, on client, allow only user to master"""
        self.clients[0].run_command(["systemctl", "stop", "sssd"], raiseonerr=False)
        self.clients[0].run_command(["rm", "-frv", "/var/lib/sss/{db,mc}/*"], raiseonerr=False)
        self.clients[0].run_command(["systemctl", "start", "sssd"], raiseonerr=False)
        self.clients[0].run_command(["id", "user1"], raiseonerr=False)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user1"])
        self.clients[0].run_command(["kdestroy", "-A"])
        self.clients[0].run_command(["dnf", "install", "-y", "ftp"], raiseonerr=False)

    def test_hbacsvc_client2_002(self):
        """hbacsvc_client2_002: user access to master for ftp, on client2, deny user2 to master"""
        self.clients[1].run_command(["systemctl", "stop", "sssd"], raiseonerr=False)
        self.clients[1].run_command(["rm", "-frv", "/var/lib/sss/{db,mc}/*"], raiseonerr=False)
        self.clients[1].run_command(["systemctl", "start", "sssd"], raiseonerr=False)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user1"])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user2"])
        time.sleep(5)
        self.clients[1].run_command(["kdestroy", "-A"])
        self.clients[1].run_command(["dnf", "install", "-y", "ftp"], raiseonerr=False)

    # Test 002_1: Delete service and test
    def test_hbacsvc_master_002_1(self):
        """hbacsvc_master_002_1: user access to master after ftp removed, on master, remove ftp from rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacsvc-del", "vsftpd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule2", "--all"], raiseonerr=False)
        
        # Test access denied
        self.run_hbactest("user1", self.master.hostname, "vsftpd", should_allow=False)
        self.run_hbactest("user2", self.master.hostname, "vsftpd", should_allow=False)
        
        self.master.run_command(["rm", "-fr", "/tmp/krb5cc_*_*"], raiseonerr=False)

    def test_hbacsvc_client_002_1(self):
        """hbacsvc_client_002_1: user access to master after ftp removed, on client, deny access"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user1"])
        self.clients[0].run_command(["rm", "-fr", "/tmp/krb5cc_*_*"], raiseonerr=False)

    def test_hbacsvc_client2_002_1(self):
        """hbacsvc_client2_002_1: user access to master after ftp removed, on client2, deny access"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user1"])
        self.clients[1].run_command(["rm", "-fr", "/tmp/krb5cc_*_*"], raiseonerr=False)

    # Test 003: FTP service group
    def test_hbacsvc_master_003(self):
        """hbacsvc_master_003: user access to master for ftp service group, on master, add rule"""
        tasks.kinit_admin(self.master)
        
        # Create users
        for i in [1, 2, 3]:
            username = f"user{i}"
            self.master.run_command(["rm", "-rf", f"/home/{username}"], raiseonerr=False)
            self.master.run_command(["mkdir", "-p", f"/home/{username}"])
            self.master.run_command(["chmod", "700", f"/home/{username}"])
            tasks.create_active_user(self.master, username, password=self.USER_PASSWORD)
            self.master.run_command(["chown", f"{username}.{username}", f"/home/{username}"])
            self.master.run_command(["su", "-", username, "-c", "pwd"], raiseonerr=False)
            time.sleep(2)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        # Install FTP
        self.master.run_command(["dnf", "install", "-y", "vsftpd"], raiseonerr=False)
        self.master.run_command(["setsebool", "-P", "tftp_home_dir", "on"], raiseonerr=False)
        self.master.run_command(["systemctl", "restart", "vsftpd"], raiseonerr=False)
        
        # Create rule with service group (verifies bug 746227)
        self.master.run_command(["ipa", "hbacrule-add", "rule3"])
        self.master.run_command(["ipa", "hbacsvc-add", "vsftpd"])
        self.master.run_command([
            "ipa", "hbacsvcgroup-add-member", "ftp", "--hbacsvcs=vsftpd"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule3", "--hbacsvcgroups=ftp"
        ])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule3", "--users=user3"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule3", f"--hosts={self.master.hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule3", "--all"])
        
        # Test (verifies bug 746227)
        self.run_hbactest("user3", self.master.hostname, "vsftpd",
                         should_allow=True, rule="rule3")
        self.run_hbactest("user2", self.master.hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest("user3", self.clients[0].hostname, "vsftpd",
                         should_allow=False)
        self.run_hbactest("user3", self.master.hostname, "ftp",
                         should_allow=True, rule="rule3")

    def test_hbacsvc_master_003_cleanup(self):
        """Cleanup for test_hbacsvc_master_003"""
        tasks.kinit_admin(self.master)
        for i in [1, 2, 3]:
            self.master.run_command([f"ipa", "user-del", f"user{i}"], raiseonerr=False)
            self.master.run_command(["rm", "-rf", f"/home/user{i}"], raiseonerr=False)
        self.master.run_command(["rm", "-fr", "/tmp/krb5cc_*_*"], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-del", "rule3"], raiseonerr=False)
        self.master.run_command(["rm", "-rf", "/var/lib/sss/db/*"], raiseonerr=False)
        self.master.run_command(["systemctl", "restart", "sssd"], raiseonerr=False)

    def test_hbacsvc_client_003(self):
        """hbacsvc_client_003: user access to master for ftp service group, on client"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user3"])
        self.clients[0].run_command(["kdestroy", "-A"])
        self.clients[0].run_command(["dnf", "install", "-y", "ftp"], raiseonerr=False)
        self.clients[0].run_command(["rm", "-fr", "/tmp/krb5cc_*_*"], raiseonerr=False)

    def test_hbacsvc_client2_003(self):
        """hbacsvc_client2_003: user access to master for ftp service group, on client2"""
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user3"])
        time.sleep(5)
        self.clients[1].run_command(["kdestroy", "-A"])
        self.clients[1].run_command(["dnf", "install", "-y", "ftp"], raiseonerr=False)
        self.clients[1].run_command(["rm", "-fr", "/tmp/krb5cc_*_*"], raiseonerr=False)

    # Test 004: Hostgroup access (verifies bug 733663)
    def test_hbacsvc_master_004(self):
        """hbacsvc_master_004: user access to hostgroup, on master, add rule"""
        user4 = "user4"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user4}"], raiseonerr=False)
        tasks.create_active_user(self.master, user4, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user4, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        # Create hostgroup
        self.master.run_command([
            "ipa", "hostgroup-add", "hostgrp1", "--desc=hostgrp1"
        ])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgrp1",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        # Create rule
        self.master.run_command(["ipa", "hbacrule-add", "rule4"])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule4", "--hbacsvcs=sshd"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule4", f"--users={user4}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule4", "--hostgroups=hostgrp1"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule4", "--all"])
        
        # Test (verifies bug 733663)
        self.run_hbactest(user4, self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule4")
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user4, self.master.hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_master_004_cleanup(self):
        """Cleanup for test_hbacsvc_master_004"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", "rule4"], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", "hostgrp1"], raiseonerr=False)

    def test_hbacsvc_client_004(self):
        """hbacsvc_client_004: user access to hostgroup, on client"""
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user4"])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user4", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_004(self):
        """hbacsvc_client2_004: user access to hostgroup, on client2"""
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user4"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[1])

        # Test 005: Hostgroup with user removal
    def test_hbacsvc_master_005(self):
        """hbacsvc_master_005: user access to hostgroup, on master, add rule"""
        user5 = "user5"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user5}"], raiseonerr=False)
        tasks.create_active_user(self.master, user5, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user5, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hostgroup-add", "hostgrp5", "--desc=hostgrp5"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgrp5",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule5"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule5", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule5", f"--users={user5}"])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule5", "--hostgroups=hostgrp5"])
        self.master.run_command(["ipa", "hbacrule-show", "rule5", "--all"])
        
        # Test access
        self.run_hbactest(user5, self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule5")
        self.run_hbactest("user2", self.clients[1].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_master_005_cleanup(self):
        """Cleanup for test_hbacsvc_master_005"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", "rule5"], raiseonerr=False)
        self.master.run_command(["ipa", "hostgroup-del", "hostgrp5"], raiseonerr=False)

    def test_hbacsvc_client_005(self):
        """hbacsvc_client_005: user access to hostgroup, on client, allow access"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user5"])
        time.sleep(5)
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user5", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_005(self):
        """hbacsvc_client2_005: user access to hostgroup, on client2, deny access to host not in hostgroup"""
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user5"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user5", self.USER_PASSWORD, self.clients[0])

    # Test 005_1: Remove user from rule
    def test_hbacsvc_master_005_1(self):
        """hbacsvc_master_005_1: user access after user removed, on master, remove user from rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-remove-user", "rule5", "--users=user5"])
        self.master.run_command(["ipa", "hbacrule-show", "rule5", "--all"])
        
        # Test access denied after user removal
        result = self.master.run_command([
            "ipa", "hbactest", "--user=user5",
            f"--host={self.clients[1].hostname}", "--service=sshd"
        ], raiseonerr=False)
        assert "Access granted: True" not in result.stdout_text

    def test_hbacsvc_client_005_1(self):
        """hbacsvc_client_005_1: user access after user removed, on client, deny access"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user5"])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user5", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_005_1(self):
        """hbacsvc_client2_005_1: user access after user removed, on client2, deny access"""
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user5"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user5", self.USER_PASSWORD, self.clients[0])

    # Test 006: Hostgroup to hostgroup access
    def test_hbacsvc_master_006(self):
        """hbacsvc_master_006: user access to hostgroup from hostgroup2, on master, add rule"""
        user6 = "user6"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user6}"], raiseonerr=False)
        tasks.create_active_user(self.master, user6, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user6, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hostgroup-add", "hostgrp6-1", "--desc=hostgrp6-1"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgrp6-1",
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", "hostgrp6-2", "--desc=hostgrp6-2"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgrp6-2",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule6"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule6", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule6", f"--users={user6}"])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule6", "--hostgroups=hostgrp6-1"])
        self.master.run_command(["ipa", "hbacrule-show", "rule6", "--all"])
        
        # Test
        self.run_hbactest(user6, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule6")
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user6, self.clients[1].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_006(self):
        """hbacsvc_client_006: user access to hostgroup from hostgroup2, on client"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user6"])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user6", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_006(self):
        """hbacsvc_client2_006: user access to hostgroup from hostgroup2, on client2"""
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user6"])
        time.sleep(5)
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user6", self.USER_PASSWORD, self.clients[0])

    # Test 007: Hostgroup for HBAC service group (verifies bug 830347)
    def test_hbacsvc_master_007(self):
        """hbacsvc_master_007: user access to hostgroup for hbac service group, on master (bz830347)"""
        user2 = "user7_2"
        user7 = "user7"
        
        tasks.kinit_admin(self.master)
        for username in [user2, user7]:
            self.master.run_command(["rm", "-rf", f"/home/{username}"], raiseonerr=False)
            tasks.create_active_user(self.master, username, password=self.USER_PASSWORD)
            self.master.run_command(["su", "-", username, "-c", "pwd"], raiseonerr=False)
            time.sleep(2)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hostgroup-add", "hostgrp7", "--desc=hostgrp7"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgrp7",
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", "hostgrp7-2", "--desc=hostgrp7-2"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgrp7-2",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule7"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule7", f"--users={user7}"])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule7", "--hostgroups=hostgrp7"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule7", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule7", "--all"])
        
        # Test
        self.run_hbactest(user7, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule7")
        self.run_hbactest(user2, self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user7, self.clients[1].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_007(self):
        """hbacsvc_client_007: user access to hostgroup for hbac service group, on client"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user7"])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user7", self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure("user7_2", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_007(self):
        """hbacsvc_client2_007: user access to hostgroup for hbac service group, on client2 (bz830347)"""
        result = self.clients[1].run_command([
            "ssh", f"root@{self.clients[0].hostname}",
            "getent", "-s", "sss", "passwd", "user7"
        ], raiseonerr=False)
        time.sleep(5)
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user7", self.USER_PASSWORD, self.clients[0])

    # Test 007_1: Remove user from rule
    def test_hbacsvc_master_007_1(self):
        """hbacsvc_master_007_1: user access after user removed, on master, remove user from rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-remove-user", "rule7", "--users=user7"])
        self.master.run_command(["ipa", "hbacrule-show", "rule7", "--all"])
        
        # Test access denied
        result = self.master.run_command([
            "ipa", "hbactest", "--user=user7",
            f"--host={self.clients[0].hostname}", "--service=sshd"
        ], raiseonerr=False)
        assert "Access granted: True" not in result.stdout_text

    def test_hbacsvc_client_007_1(self):
        """hbacsvc_client_007_1: user access after user removed, on client, deny access"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user7"])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user7", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_007_1(self):
        """hbacsvc_client2_007_1: user access after user removed, on client2, deny access"""
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user7"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user7", self.USER_PASSWORD, self.clients[0])

    # Test 008: Group access to client
    def test_hbacsvc_master_008(self):
        """hbacsvc_master_008: group access to client2, on master, add rule"""
        user8 = "user8"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user8}"], raiseonerr=False)
        tasks.create_active_user(self.master, user8, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user8, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group8", "--desc=group8"])
        self.master.run_command(["ipa", "group-add-member", "group8", f"--users={user8}"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule8"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule8", "--groups=group8"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule8", f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule8", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule8", "--all"])
        
        # Test
        self.run_hbactest(user8, self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule8")
        self.run_hbactest("user2", self.clients[1].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_008(self):
        """hbacsvc_client_008: group access to client2, on client"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user8"])
        time.sleep(5)
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user8", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_008(self):
        """hbacsvc_client2_008: group access to client2, on client2, allow only user in group"""
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user8"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user8", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[1])

    # Test 008_1: Remove group from rule
    def test_hbacsvc_master_008_1(self):
        """hbacsvc_master_008_1: group access after group removed, on master, remove group from rule"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-remove-user", "rule8", "--groups=group8"])
        self.master.run_command(["ipa", "hbacrule-show", "rule8", "--all"])
        
        # Test access denied
        result = self.master.run_command([
            "ipa", "hbactest", "--user=user8",
            f"--host={self.clients[1].hostname}", "--service=sshd"
        ], raiseonerr=False)
        assert "Access granted: True" not in result.stdout_text

    def test_hbacsvc_client_008_1(self):
        """hbacsvc_client_008_1: group access after group removed, on client, deny access"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user8"])
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user8", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_008_1(self):
        """hbacsvc_client2_008_1: group access after group removed, on client2, deny access"""
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user8"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_failure("user8", self.USER_PASSWORD, self.clients[1])

    # Test 009: Group access to client2 for HBAC service group
    def test_hbacsvc_master_009(self):
        """hbacsvc_master_009: group access to client2 for hbac service group, on master, add rule"""
        user9 = "user9"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user9}"], raiseonerr=False)
        tasks.create_active_user(self.master, user9, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user9, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group9", "--desc=group9"])
        self.master.run_command(["ipa", "group-add-member", "group9", f"--users={user9}"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule9"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule9", "--groups=group9"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule9", f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule9", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule9", "--all"])
        
        # Test
        self.run_hbactest(user9, self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule9")
        self.run_hbactest("user2", self.clients[1].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_009(self):
        """hbacsvc_client_009: group access to client2 for hbac service group, on client"""
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user9"])
        time.sleep(5)
        self.clients[0].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user9", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_009(self):
        """hbacsvc_client2_009: group access to client2 for hbac service group, on client2"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user9"])
        self.clients[1].run_command(["kdestroy", "-A"])
        assert self.ssh_auth_success("user9", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_009_1(self):
        """hbacsvc_master_009_1: verify group still in rule (srchost validation deprecated)"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-show", "rule9", "--all"])
        
        # Test access still granted (srchost validation deprecated)
        self.run_hbactest("user9", self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule9")

    def test_hbacsvc_client_009_1(self):
        """hbacsvc_client_009_1: access still allowed (srchost validation deprecated)"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user9"])
        assert self.ssh_auth_success("user9", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_009_1(self):
        """hbacsvc_client2_009_1: access still allowed (srchost validation deprecated)"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user9"])
        assert self.ssh_auth_success("user9", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[1])

    # Test 010: Group access to hostgroup
    def test_hbacsvc_master_010(self):
        """hbacsvc_master_010: group access to hostgroup, on master, add rule"""
        user10 = "user10"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user10}"], raiseonerr=False)
        tasks.create_active_user(self.master, user10, password=self.USER_PASSWORD)
        time.sleep(5)
        self.master.run_command(["getent", "-s", "sss", "passwd", user10])
        self.master.run_command(["su", "-", user10, "-c", "pwd"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group10", "--desc=group10"])
        self.master.run_command(["ipa", "group-add-member", "group10", f"--users={user10}"])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup10", "--desc=hostgroup10"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup10",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule10"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule10", "--groups=group10"])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule10", "--hostgroups=hostgroup10"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule10", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule10", "--all"])
        
        # Test
        self.run_hbactest(user10, self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule10")
        self.run_hbactest("user2", self.clients[1].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_010(self):
        """hbacsvc_client_010: group access to hostgroup, on client, allow access"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user10"])
        assert self.ssh_auth_success("user10", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_010(self):
        """hbacsvc_client2_010: group access to hostgroup, on client2, deny access for user not in group"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user10"])
        # Srchost validation deprecated - access should be allowed
        assert self.ssh_auth_success("user10", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[1])

    # Test 011: Group access to hostgroup for HBAC service group
    def test_hbacsvc_master_011(self):
        """hbacsvc_master_011: group access to hostgroup for hbac service group, on master, add rule"""
        user11 = "user11"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user11}"], raiseonerr=False)
        tasks.create_active_user(self.master, user11, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user11, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group11", "--desc=group11"])
        self.master.run_command(["ipa", "group-add-member", "group11", f"--users={user11}"])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup11", "--desc=hostgroup11"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup11",
            f"--hosts={self.clients[0].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule11"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule11", "--groups=group11"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule11", f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule11", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule11", "--all"])
        
        # Test
        self.run_hbactest(user11, self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule11")
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_011(self):
        """hbacsvc_client_011: group access to hostgroup for hbac service group, on client"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user11"])
        assert self.ssh_auth_success("user11", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_011(self):
        """hbacsvc_client2_011: group access to hostgroup for hbac service group, on client2"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user11"])
        # Srchost validation deprecated
        assert self.ssh_auth_success("user11", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_master_011_1(self):
        """hbacsvc_master_011_1: remove hbac service group"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-remove-service", "rule11", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule11", "--all"])
        
        # Test access denied after service removal
        result = self.master.run_command([
            "ipa", "hbactest", "--user=user11",
            f"--host={self.clients[1].hostname}", "--service=sshd"
        ], raiseonerr=False)
        assert "Access granted: True" not in result.stdout_text

    def test_hbacsvc_client_011_1(self):
        """hbacsvc_client_011_1: after hbac service group removed, on client, deny access"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user11"])
        assert self.ssh_auth_failure("user11", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_011_1(self):
        """hbacsvc_client2_011_1: after hbac service group removed, on client2, deny access"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user11"])
        assert self.ssh_auth_failure("user11", self.USER_PASSWORD, self.clients[1])

    # Test 012: Group access to client2 from hostgroup for HBAC service group
    def test_hbacsvc_master_012(self):
        """hbacsvc_master_012: group access to client2 from hostgroup for hbac service group"""
        user12 = "user12"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user12}"], raiseonerr=False)
        tasks.create_active_user(self.master, user12, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user12, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group12", "--desc=group12"])
        self.master.run_command(["ipa", "group-add-member", "group12", f"--users={user12}"])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup12", "--desc=hostgroup12"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup12",
            f"--hosts={self.clients[0].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule12"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule12", "--groups=group12"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule12", f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacsvcgroup-add", "sshd", "--desc=sshdgrp"])
        self.master.run_command(["ipa", "hbacsvcgroup-add-member", "sshd", "--hbacsvc=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule12", "--hbacsvcgroup=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule12", "--all"])
        
        # Test
        self.run_hbactest(user12, self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule12")

    def test_hbacsvc_client_012(self):
        """hbacsvc_client_012: group access to client2 from hostgroup, on client"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user12"])
        assert self.ssh_auth_failure("user12", self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_success("user12", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_012(self):
        """hbacsvc_client2_012: group access to client2 from hostgroup, on client2"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user12"])
        assert self.ssh_auth_failure("user12", self.USER_PASSWORD, self.clients[0])

    # Test 013: Group access to hostgroup from hostgroup2
    def test_hbacsvc_master_013(self):
        """hbacsvc_master_013: group access to hostgroup from hostgroup2, on master, add rule"""
        user13 = "user13"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user13}"], raiseonerr=False)
        tasks.create_active_user(self.master, user13, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user13, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group13", "--desc=group13"])
        self.master.run_command(["ipa", "group-add-member", "group13", f"--users={user13}"])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup13", "--desc=hostgroup13"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup13",
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup13-2", "--desc=hostgroup13-2"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup13-2",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule13"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule13", "--groups=group13"])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule13", "--hostgroups=hostgroup13"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule13", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule13", "--all"])
        
        # Test
        self.run_hbactest(user13, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule13")
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_013(self):
        """hbacsvc_client_013: group access to hostgroup from hostgroup2, on client"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user13"])
        assert self.ssh_auth_failure("user13", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_013(self):
        """hbacsvc_client2_013: group access to hostgroup from hostgroup2, on client2 (bz830347)"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        result = self.clients[1].run_command([
            "ssh", f"root@{self.clients[0].hostname}",
            "getent", "-s", "sss", "passwd", "user13"
        ], raiseonerr=False)
        assert self.ssh_auth_success("user13", self.USER_PASSWORD, self.clients[0])

    # Test 014: Similar to 013
    def test_hbacsvc_master_014(self):
        """hbacsvc_master_014: group access to hostgroup from hostgroup2, on master"""
        user14 = "user14"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user14}"], raiseonerr=False)
        tasks.create_active_user(self.master, user14, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user14, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group14", "--desc=group14"])
        self.master.run_command(["ipa", "group-add-member", "group14", f"--users={user14}"])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup14", "--desc=hostgroup14"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup14",
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup14-2", "--desc=hostgroup14-2"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup14-2",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule14"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule14", "--groups=group14"])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule14", "--hostgroups=hostgroup14"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule14", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule14", "--all"])
        
        # Test
        self.run_hbactest(user14, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule14")
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user14, self.clients[1].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_014(self):
        """hbacsvc_client_014: group access to hostgroup from hostgroup2, on client"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user14"])
        assert self.ssh_auth_failure("user14", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_014(self):
        """hbacsvc_client2_014: group access to hostgroup from hostgroup2, on client2 (bz830347)"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        result = self.clients[1].run_command([
            "ssh", f"root@{self.clients[0].hostname}",
            "getent", "-s", "sss", "passwd", "user14"
        ], raiseonerr=False)
        assert self.ssh_auth_success("user14", self.USER_PASSWORD, self.clients[0])

    # Test 015: Nested group access to client
    def test_hbacsvc_master_015(self):
        """hbacsvc_master_015: nested group access to client, on master, add rule"""
        user15 = "user15"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user15}"], raiseonerr=False)
        tasks.create_active_user(self.master, user15, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user15, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group15", "--desc=group15"])
        self.master.run_command(["ipa", "group-add", "group15-2", "--desc=group15-2"])
        self.master.run_command(["ipa", "group-add-member", "group15-2", f"--users={user15}"])
        self.master.run_command(["ipa", "group-add-member", "group15", "--groups=group15-2"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule15"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule15", "--groups=group15"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule15", f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule15", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule15", "--all"])
        
        # Test
        self.run_hbactest(user15, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule15")
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         should_allow=False)

    def test_hbacsvc_client_015(self):
        """hbacsvc_client_015: nested group access to client, on client"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user15"])
        # Srchost validation deprecated
        assert self.ssh_auth_success("user15", self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_015(self):
        """hbacsvc_client2_015: nested group access to client, on client2"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user15"])
        assert self.ssh_auth_success("user15", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_015_1(self):
        """hbacsvc_master_015_1: nested group access after group removed"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-remove-user", "rule15", "--groups=group15"])
        self.master.run_command(["ipa", "hbacrule-show", "rule15", "--all"])
        
        # Test access denied
        result = self.master.run_command([
            "ipa", "hbactest", "--user=user15",
            f"--host={self.clients[0].hostname}", "--service=sshd"
        ], raiseonerr=False)
        assert "Access granted: True" not in result.stdout_text

    def test_hbacsvc_client_015_1(self):
        """hbacsvc_client_015_1: nested group access after group removed, on client"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user15"])
        assert self.ssh_auth_failure("user15", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_015_1(self):
        """hbacsvc_client2_015_1: nested group access after group removed, on client2"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user15"])
        assert self.ssh_auth_failure("user15", self.USER_PASSWORD, self.clients[0])

    # Test 016: Nested group access for HBAC service group
    def test_hbacsvc_master_016(self):
        """hbacsvc_master_016: nested group access to client for hbac service group"""
        user16 = "user16"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user16}"], raiseonerr=False)
        tasks.create_active_user(self.master, user16, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user16, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group16", "--desc=group16"])
        self.master.run_command(["ipa", "group-add", "group16-2", "--desc=group16-2"])
        self.master.run_command(["ipa", "group-add-member", "group16-2", f"--users={user16}"])
        self.master.run_command(["ipa", "group-add-member", "group16", "--groups=group16-2"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule16"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule16", "--groups=group16"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule16", f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule16", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule16", "--all"])
        
        # Test
        self.run_hbactest(user16, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule16")

    def test_hbacsvc_client_016(self):
        """hbacsvc_client_016: nested group access for hbac service group, on client"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user16"])
        # Srchost validation deprecated
        assert self.ssh_auth_success("user16", self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_016(self):
        """hbacsvc_client2_016: nested group access for hbac service group, on client2"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user16"])
        assert self.ssh_auth_success("user16", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_016_1(self):
        """hbacsvc_master_016_1: nested group access after group removed"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-remove-user", "rule16", "--groups=group16"])
        self.master.run_command(["ipa", "hbacrule-show", "rule16", "--all"])
        
        # Test access denied
        result = self.master.run_command([
            "ipa", "hbactest", "--user=user16",
            f"--host={self.clients[0].hostname}", "--service=sshd",
            "--rule=rule16"
        ], raiseonerr=False)
        assert "Access granted: True" not in result.stdout_text

    def test_hbacsvc_client_016_1(self):
        """hbacsvc_client_016_1: nested group after group removed, on client, deny access"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user16"])
        assert self.ssh_auth_failure("user16", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_016_1(self):
        """hbacsvc_client2_016_1: nested group after group removed, on client2, deny access"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user16"])
        assert self.ssh_auth_failure("user16", self.USER_PASSWORD, self.clients[0])

    # Test 017: Nested group access from hostgroup
    def test_hbacsvc_master_017(self):
        """hbacsvc_master_017: nested group access to client from hostgroup"""
        user17 = "user17"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user17}"], raiseonerr=False)
        tasks.create_active_user(self.master, user17, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user17, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group17", "--desc=group17"])
        self.master.run_command(["ipa", "group-add", "group17-2", "--desc=group17-2"])
        self.master.run_command(["ipa", "group-add-member", "group17-2", f"--users={user17}"])
        self.master.run_command(["ipa", "group-add-member", "group17", "--groups=group17-2"])
        
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup17", "--desc=hostgroup17"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup17",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule17"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule17", "--groups=group17"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule17", f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule17", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule17", "--all"])
        
        # Test
        self.run_hbactest(user17, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule17")

    def test_hbacsvc_client_017(self):
        """hbacsvc_client_017: nested group access from hostgroup, on client"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user17"])
        assert self.ssh_auth_failure("user17", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_017(self):
        """hbacsvc_client2_017: nested group access from hostgroup, on client2"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user17"])
        assert self.ssh_auth_failure("user17", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_success("user17", self.USER_PASSWORD, self.clients[0])

    # Test 018: Nested group access to hostgroup from hostgroup for HBAC service group
    def test_hbacsvc_master_018(self):
        """hbacsvc_master_018: nested group to hostgroup from hostgroup for hbac service group"""
        user18 = "user18"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user18}"], raiseonerr=False)
        tasks.create_active_user(self.master, user18, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user18, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group18", "--desc=group18"])
        self.master.run_command(["ipa", "group-add", "group18-2", "--desc=group18-2"])
        self.master.run_command(["ipa", "group-add-member", "group18-2", f"--users={user18}"])
        self.master.run_command(["ipa", "group-add-member", "group18", "--groups=group18-2"])
        
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup18", "--desc=hostgroup18"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup18",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule18"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule18", "--groups=group18"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule18", f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule18", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule18", "--all"])
        
        # Test
        self.run_hbactest(user18, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule18")

    def test_hbacsvc_client_018(self):
        """hbacsvc_client_018: nested group to hostgroup, on client"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user18"])
        assert self.ssh_auth_failure("user18", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_018(self):
        """hbacsvc_client2_018: nested group to hostgroup, on client2"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user18"])
        assert self.ssh_auth_failure("user18", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_success("user18", self.USER_PASSWORD, self.clients[0])

    # Test 019: Nested group access to hostgroup from hostgroup2
    def test_hbacsvc_master_019(self):
        """hbacsvc_master_019: nested group to hostgroup from hostgroup2"""
        user19 = "user19"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user19}"], raiseonerr=False)
        tasks.create_active_user(self.master, user19, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user19, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group19", "--desc=group19"])
        self.master.run_command(["ipa", "group-add", "group19-2", "--desc=group19-2"])
        self.master.run_command(["ipa", "group-add-member", "group19-2", f"--users={user19}"])
        self.master.run_command(["ipa", "group-add-member", "group19", "--groups=group19-2"])
        
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup19", "--desc=hostgroup19"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup19",
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup19-2", "--desc=hostgroup19-2"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup19-2",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule19"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule19", "--groups=group19-2"])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule19", "--hostgroups=hostgroup19"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule19", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule19", "--all"])
        
        # Test
        self.run_hbactest(user19, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule19")

    def test_hbacsvc_client_019(self):
        """hbacsvc_client_019: nested group to hostgroup from hostgroup2, on client"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user19"])
        assert self.ssh_auth_failure("user19", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_019(self):
        """hbacsvc_client2_019: nested group to hostgroup from hostgroup2, on client2 (bz830347)"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user19"])
        assert self.ssh_auth_failure("user19", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_success("user19", self.USER_PASSWORD, self.clients[0])

    # Test 020: Nested group for HBAC service group
    def test_hbacsvc_master_020(self):
        """hbacsvc_master_020: nested group to hostgroup for hbac service group"""
        user20 = "user20"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user20}"], raiseonerr=False)
        tasks.create_active_user(self.master, user20, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user20, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group20", "--desc=group20"])
        self.master.run_command(["ipa", "group-add", "group20-2", "--desc=group20-2"])
        self.master.run_command(["ipa", "group-add-member", "group20-2", f"--users={user20}"])
        self.master.run_command(["ipa", "group-add-member", "group20", "--groups=group20-2"])
        
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup20", "--desc=hostgroup20"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup20",
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hostgroup-add", "hostgroup20-2", "--desc=hostgroup20-2"])
        self.master.run_command([
            "ipa", "hostgroup-add-member", "hostgroup20-2",
            f"--hosts={self.clients[1].hostname}"
        ])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule20"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule20", "--groups=group20-2"])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule20", "--hostgroups=hostgroup20"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule20", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule20", "--all"])
        
        # Test
        self.run_hbactest(user20, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule20")

    def test_hbacsvc_client_020(self):
        """hbacsvc_client_020: nested group for hbac service group, on client"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user20"])
        assert self.ssh_auth_failure("user20", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_020(self):
        """hbacsvc_client2_020: nested group for hbac service group, on client2 (bz830347)"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user20"])
        assert self.ssh_auth_failure("user20", self.USER_PASSWORD, self.clients[1])
        assert self.ssh_auth_success("user20", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_master_020_1(self):
        """hbacsvc_master_020_1: after rule removed"""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-del", "rule20"])
        result = self.master.run_command(
            ["ipa", "hbacrule-show", "rule20", "--all"],
            raiseonerr=False
        )
        assert result.returncode == 2

    def test_hbacsvc_client_020_1(self):
        """hbacsvc_client_020_1: after rule removed, on client, deny access"""
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user20"])
        assert self.ssh_auth_failure("user20", self.USER_PASSWORD, self.clients[1])

    def test_hbacsvc_client2_020_1(self):
        """hbacsvc_client2_020_1: after rule removed, on client2, deny access"""
        tasks.kinit_admin(self.clients[1])
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user20"])
        assert self.ssh_auth_failure("user20", self.USER_PASSWORD, self.clients[1])

    # Test 021: User access client from external host
    def test_hbacsvc_master_021(self):
        """hbacsvc_master_021: user access client from external host, on master, add rule and run hbactest"""
        user21 = "user21"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user21}"], raiseonerr=False)
        tasks.create_active_user(self.master, user21, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user21, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-add", "rule21"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule21", f"--users={user21}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule21", f"--hosts={self.clients[0].hostname}"
        ])
        # Note: srchost validation deprecated, but keeping for hbactest
        self.master.run_command(["ipa", "hbacrule-add-service", "rule21", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule21", "--all"])
        
        # Test with hbactest (external host won't actually authenticate, but hbactest works)
        self.run_hbactest(user21, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule21")
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user21, "externalhost.randomhost.com", "sshd",
                         should_allow=False)

    # Test 022: User access external host from external host for HBAC service group
    def test_hbacsvc_master_022(self):
        """hbacsvc_master_022: user access external host from external host for hbac service group"""
        user22 = "user22"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user22}"], raiseonerr=False)
        tasks.create_active_user(self.master, user22, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user22, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacrule-add", "rule22"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule22", f"--users={user22}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule22", "--hosts=externalhost.randomhost.com"
        ])
        # Note: srchost is deprecated but command structure preserved for testing
        result = self.master.run_command([
            "ipa", "hbacrule-add-sourcehost", "rule22", "--hosts=externalhost2.randomhost.com"
        ], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-add-service", "rule22", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule22", "--all"])
        
        # Test with hbactest using srchost (deprecated but command still works)
        cmd = [
            "ipa", "hbactest",
            f"--user={user22}",
            "--srchost=externalhost2.randomhost.com",
            "--host=externalhost.randomhost.com",
            "--service=sshd"
        ]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert "Access granted: True" in result.stdout_text or "matched: rule22" in result.stdout_text

    # Test 023: Group access to client2 from external host
    def test_hbacsvc_master_023(self):
        """hbacsvc_master_023: group access client2 from external host, on master, add rule and run hbactest"""
        user23 = "user23"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user23}"], raiseonerr=False)
        tasks.create_active_user(self.master, user23, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user23, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group23", "--desc=group23"])
        self.master.run_command(["ipa", "group-add-member", "group23", f"--users={user23}"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule23"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule23", f"--users={user23}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule23", f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule23", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule23", "--all"])
        
        # Test with hbactest
        self.run_hbactest(user23, self.clients[1].hostname, "sshd",
                         should_allow=True, rule="rule23")
        self.run_hbactest("user2", self.clients[1].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user23, "externalhost2.randomhost.com", "sshd",
                         should_allow=False)

    # Test 024: Group access external_host from external_host_2
    def test_hbacsvc_master_024(self):
        """hbacsvc_master_024: group access external_host from external_host_2, on master, add rule and run hbactest"""
        user24 = "user24"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user24}"], raiseonerr=False)
        tasks.create_active_user(self.master, user24, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user24, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group24", "--desc=group24"])
        self.master.run_command(["ipa", "group-add-member", "group24", f"--users={user24}"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule24"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule24", f"--users={user24}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule24", "--hosts=externalhost.randomhost.com"
        ])
        # Note: srchost is deprecated but command structure preserved
        result = self.master.run_command([
            "ipa", "hbacrule-add-sourcehost", "rule24", "--hosts=externalhost2.randomhost.com"
        ], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-add-service", "rule24", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule24", "--all"])
        
        # Test with hbactest using srchost
        cmd = [
            "ipa", "hbactest",
            f"--user={user24}",
            "--srchost=externalhost2.randomhost.com",
            "--host=externalhost.randomhost.com",
            "--service=sshd",
            "--rule=rule24"
        ]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert "Access granted: True" in result.stdout_text or "matched: rule24" in result.stdout_text

    # Test 025: Group access to client from external host 2
    def test_hbacsvc_master_025(self):
        """hbacsvc_master_025: group access client from external host 2, on master, add rule and run hbactest"""
        user25 = "user25"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user25}"], raiseonerr=False)
        tasks.create_active_user(self.master, user25, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user25, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group25", "--desc=group25"])
        self.master.run_command(["ipa", "group-add", "group25-2", "--desc=group25-2"])
        self.master.run_command(["ipa", "group-add-member", "group25", "--users=user25"])
        self.master.run_command(["ipa", "group-add-member", "group25-2", "--groups=group25"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule25"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule25", "--users=user25"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule25", f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule25", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule25", "--all"])
        
        # Test with hbactest
        self.run_hbactest(user25, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule25")
        self.run_hbactest("user2", self.clients[0].hostname, "sshd",
                         should_allow=False)
        self.run_hbactest(user25, "externalhost2.randomhost.com", "sshd",
                         should_allow=False)

    # Test 026: Group access to external host from external host 2
    def test_hbacsvc_master_026(self):
        """hbacsvc_master_026: group access external host from external host 2, on master, add rule and run hbactest"""
        user26 = "user26"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user26}"], raiseonerr=False)
        tasks.create_active_user(self.master, user26, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user26, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "group-add", "group26", "--desc=group26"])
        self.master.run_command(["ipa", "group-add", "group26-2", "--desc=group26-2"])
        self.master.run_command(["ipa", "group-add-member", "group26", "--user=user26"])
        self.master.run_command(["ipa", "group-add-member", "group26-2", "--groups=group26"])
        
        self.master.run_command(["ipa", "hbacrule-add", "rule26"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule26", f"--users={user26}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule26", "--hosts=externalhost.randomhost.com"
        ])
        # Note: srchost is deprecated but command structure preserved
        result = self.master.run_command([
            "ipa", "hbacrule-add-sourcehost", "rule26", "--hosts=externalhost2.randomhost.com"
        ], raiseonerr=False)
        self.master.run_command(["ipa", "hbacrule-add-service", "rule26", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule26", "--all"])
        
        # Test with hbactest using srchost
        cmd = [
            "ipa", "hbactest",
            f"--user={user26}",
            "--srchost=externalhost2.randomhost.com",
            "--host=externalhost.randomhost.com",
            "--service=sshd",
            "--rule=rule26"
        ]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert "Access granted: True" in result.stdout_text or "matched: rule26" in result.stdout_text

    # Test 027: Empty HBAC service group
    def test_hbacsvc_master_027(self):
        """hbacsvc_master_027: user access with empty hbac service group"""
        user27 = "user27"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user27}"], raiseonerr=False)
        tasks.create_active_user(self.master, user27, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user27, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacsvcgroup-add", "empty", "--desc=empty"])
        self.master.run_command(["ipa", "hbacrule-add", "rule27"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule27", f"--users={user27}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule27", f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule27", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule27", "--hbacsvcgroup=empty"])
        self.master.run_command(["ipa", "hbacrule-show", "rule27", "--all"])
        
        # Test
        self.run_hbactest(user27, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule27")

    def test_hbacsvc_client_027(self):
        """hbacsvc_client_027: empty hbac service group, on client"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user27"])
        # Srchost validation deprecated
        assert self.ssh_auth_success("user27", self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_027(self):
        """hbacsvc_client2_027: empty hbac service group, on client2"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user27"])
        assert self.ssh_auth_success("user27", self.USER_PASSWORD, self.clients[0])

    # Test 028: Multiple HBAC services in rule
    def test_hbacsvc_master_028(self):
        """hbacsvc_master_028: user access with multiple hbac services"""
        user28 = "user28"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user28}"], raiseonerr=False)
        tasks.create_active_user(self.master, user28, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user28, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        self.master.run_command(["ipa", "hbacsvc-add", "sshdtest"])
        self.master.run_command(["ipa", "hbacrule-add", "rule28"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule28", f"--users={user28}"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule28", f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule28", "--hbacsvcs=sshdtest"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule28", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-show", "rule28", "--all"])
        
        # Test
        self.run_hbactest(user28, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule28")

    def test_hbacsvc_client_028(self):
        """hbacsvc_client_028: multiple hbac services, on client"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user28"])
        # Srchost validation deprecated
        assert self.ssh_auth_success("user28", self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_028(self):
        """hbacsvc_client2_028: multiple hbac services, on client2 (bz830347)"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        result = self.clients[1].run_command([
            "ssh", f"root@{self.clients[0].hostname}",
            "getent", "-s", "sss", "passwd", "user28"
        ], raiseonerr=False)
        assert self.ssh_auth_success("user28", self.USER_PASSWORD, self.clients[0])

    # Test 029: Empty group in rule
    def test_hbacsvc_master_029(self):
        """hbacsvc_master_029: user access with empty group in rule"""
        user29 = "user29"
        
        tasks.kinit_admin(self.master)
        self.master.run_command(["rm", "-rf", f"/home/{user29}"], raiseonerr=False)
        tasks.create_active_user(self.master, user29, password=self.USER_PASSWORD)
        self.master.run_command(["su", "-", user29, "-c", "pwd"], raiseonerr=False)
        time.sleep(5)
        
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"], raiseonerr=False)
        
        # Check and delete if exists
        result = self.master.run_command(
            ["ipa", "hbacsvcgroup-show", "empty"],
            raiseonerr=False
        )
        if result.returncode == 0:
            self.master.run_command(["ipa", "hbacsvcgroup-del", "empty"])
        
        self.master.run_command(["ipa", "group-add", "emptygroup", "--desc=emptygroup"])
        self.master.run_command(["ipa", "hbacsvcgroup-add", "empty", "--desc=emptygroup"])
        self.master.run_command(["ipa", "hbacrule-add", "rule29"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule29", f"--users={user29}"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule29", "--groups=emptygroup"])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule29", f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule29", "--hbacsvcs=sshd"])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule29", "--hbacsvcgroup=empty"])
        self.master.run_command(["ipa", "hbacrule-show", "rule29", "--all"])
        
        # Test
        self.run_hbactest(user29, self.clients[0].hostname, "sshd",
                         should_allow=True, rule="rule29")

    def test_hbacsvc_client_029(self):
        """hbacsvc_client_029: empty group in rule, on client"""
        tasks.kinit_admin(self.clients[0])
        time.sleep(5)
        self.clients[0].run_command(["getent", "-s", "sss", "passwd", "user29"])
        # Srchost validation deprecated
        assert self.ssh_auth_success("user29", self.USER_PASSWORD, self.clients[0])
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.clients[0])

    def test_hbacsvc_client2_029(self):
        """hbacsvc_client2_029: empty group in rule, on client2"""
        tasks.kinit_admin(self.clients[1])
        time.sleep(5)
        self.clients[1].run_command(["getent", "-s", "sss", "passwd", "user29"])
        assert self.ssh_auth_success("user29", self.USER_PASSWORD, self.clients[0])

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
        assert self.ssh_auth_failure("user2", self.USER_PASSWORD, self.master)

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