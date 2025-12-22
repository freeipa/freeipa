# Copyright (C) 2025 FreeIPA Contributors see COPYING for license

"""
HBAC functional tests ported from bash test suite
This module tests Host-Based Access Control functionality
"""

from __future__ import absolute_import
import re
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestHBACFunctional(IntegrationTest):
    """HBAC functional tests ported from bash test suite"""

    topology = 'star'
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
        # Install FTP
        tasks.install_packages(cls.master, ['vsftpd'])
        tasks.install_packages(cls.clients[0], ['ftp'])
        tasks.install_packages(cls.clients[1], ['ftp'])
        if cls.domain_level is not None:
            domain_level = cls.domain_level
        else:
            domain_level = cls.master.config.domain_level
        tasks.install_topo(cls.topology,
                           cls.master, [],
                           cls.clients, domain_level,
                           clients_extra_args=('--mkhomedir',))
        tasks.kinit_admin(cls.master)
        # Setup common test users
        cls.setup_common_users()

    @classmethod
    def setup_common_users(cls):
        """Create common test users"""
        tasks.kinit_admin(cls.master)
        for user in [cls.USER_1, cls.USER_2, cls.USER_3]:
            # Create the test active user's
            tasks.create_active_user(
                cls.master, user, password=cls.USER_PASSWORD, extra_args=[
                    '--homedir', '/home/{}'.format(user)]
            )
            # Set home directory ownership and permissions
            home_dir = f'/home/{user}'
            cls.master.run_command(['mkdir', '-p', home_dir])
            cls.master.run_command(['chown', f'{user}:{user}', home_dir])
            cls.master.run_command(['chmod', '755', home_dir])
        tasks.clear_sssd_cache(cls.master)

    def ssh_auth_success(self, user, password, host, source_host=None):
        """
        Test SSH authentication success
        Args:
            user: Username to authenticate
            password: Password for authentication
            host: Host to connect to (target host)
            source_host: Host to run command from (optional,
                         defaults to target host)
        Returns:
            True if authentication succeeds, False otherwise
        """
        if source_host is None:
            source_host = host

        result = source_host.run_command([
            'sshpass', '-p', password, 'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'PasswordAuthentication=yes',
            '-l', user, host.hostname, 'echo login successful'
        ], raiseonerr=False)

        if result.returncode == 0 and 'login successful' in result.stdout_text:
            return True
        return False

    def ssh_auth_failure(self, user, password, host, source_host=None):
        """
        Test SSH authentication failure
        Args:
            user: Username to authenticate
            password: Password for authentication
            host: Host to connect to (target host)
            source_host: Host to run command from (optional,
                         defaults to target host)
        Returns:
            True if authentication fails as expected, False otherwise
        """
        return not self.ssh_auth_success(user, password, host, source_host)

    def ftp_auth_success(self, user, password, target_host, source_host):
        """
        Test FTP authentication success
        Args:
            user: Username to authenticate
            password: Password for authentication
            target_host: Host to connect to (FTP server)
            source_host: Host to run command from
        Returns:
            True if authentication succeeds, False otherwise
        """
        ftp_script = (
            f'printf "user {user} {password}\nquit\n" | '
            f'ftp -inv {target_host.hostname}'
        )
        result = source_host.run_command(
            ['bash', '-c', ftp_script],
            raiseonerr=False
        )

        if (result.returncode == 0
                and 'Login successful.' in result.stdout_text):
            return True
        return False

    def ftp_auth_failure(self, user, password, target_host, source_host):
        """
        Test FTP authentication failure
        Args:
            user: Username to authenticate
            password: Password for authentication
            target_host: Host to connect to (FTP server)
            source_host: Host to run command from
        Returns:
            True if authentication fails as expected, False otherwise
        """
        return not self.ftp_auth_success(
            user, password, target_host, source_host
        )

    def refresh_user_cache(
        self, host, users, kdestroy=True
    ):
        """
        Clear SSSD cache, run id and getent for users, and optionally destroy
        kerberos tickets.
        Args:
            host: The host/client to run commands on
            users: A single username (str) or a list of usernames to process
            kdestroy: If True (default), destroy all kerberos tickets after
                     refreshing cache. Set to False to skip kdestroy.
            kinit_admin: If True, run kinit_admin after clearing cache.
                        Defaults to False.
        """
        # Normalize users to a list
        if isinstance(users, str):
            users = [users]
        # Clear SSSD cache
        tasks.clear_sssd_cache(host)
        # Run id command for each user
        for user in users:
            host.run_command(["id", user], raiseonerr=False)
        # Run getent for each user
        for user in users:
            host.run_command(
                ["getent", "-s", "sss", "passwd", user]
            )
        # Destroy all kerberos tickets if requested
        if kdestroy:
            tasks.kdestroy_all(host)

    def _build_hbactest_cmd(self, user, host, service, **kwargs):
        """Build the hbactest command with given parameters."""
        cmd = [
            "ipa", "hbactest",
            f"--user={user}",
            f"--host={host}",
            f"--service={service}"
        ]
        if kwargs.get('rule'):
            cmd.append(f"--rule={kwargs['rule']}")
        if kwargs.get('nodetail'):
            cmd.append("--nodetail")
        return cmd

    def _run_hbactest_with_patterns(self, user, host, service, **kwargs):
        """Run hbactest and verify expected patterns are present."""
        cmd = self._build_hbactest_cmd(user, host, service, **kwargs)
        result = self.master.run_command(cmd, raiseonerr=False)
        for pattern in kwargs['expected_patterns']:
            assert re.search(pattern, result.stdout_text), (
                f"Expected pattern '{pattern}' not found in "
                f"output: {result.stdout_text}"
            )

    def _run_hbactest_with_forbidden_patterns(self, user, host, service,
                                              **kwargs):
        """Run hbactest and verify forbidden patterns are absent."""
        cmd = self._build_hbactest_cmd(user, host, service, **kwargs)
        result = self.master.run_command(cmd, raiseonerr=False)
        for pattern in kwargs['forbidden_patterns']:
            assert not re.search(pattern, result.stdout_text), (
                f"Forbidden pattern '{pattern}' found in output: "
                f"{result.stdout_text}"
            )

    def _run_hbactest_expect_unresolved(self, user, host, service, **kwargs):
        """Run hbactest expecting unresolved rules."""
        cmd = self._build_hbactest_cmd(user, host, service, **kwargs)
        result = self.master.run_command(cmd, raiseonerr=False)
        rule = kwargs.get('rule')
        assert ("Unresolved rules in --rules" in result.stdout_text
                or (rule and f"error: {rule}" in result.stdout_text)), (
            f"Expected unresolved rule for {rule}, "
            f"got: {result.stdout_text}"
        )

    def _run_hbactest_expect_error(self, user, host, service, **kwargs):
        """Run hbactest expecting an error."""
        cmd = self._build_hbactest_cmd(user, host, service, **kwargs)
        result = self.master.run_command(cmd, raiseonerr=False)
        rule = kwargs.get('rule')
        assert (f"error: {rule}" in result.stdout_text
                or "error:" in result.stdout_text.lower()), (
            f"Expected error in output, got: {result.stdout_text}"
        )

    def _run_hbactest_basic(self, user, host, service, should_allow, **kwargs):
        """Run basic hbactest and verify access granted/denied."""
        cmd = self._build_hbactest_cmd(user, host, service, **kwargs)
        result = self.master.run_command(cmd, raiseonerr=False)
        rule = kwargs.get('rule')
        if should_allow:
            assert ("Access granted: True" in result.stdout_text
                    or (rule and f"matched: {rule}" in
                        result.stdout_text)), (
                f"Expected access granted for {user} to "
                f"{host}:{service}, got: {result.stdout_text}"
            )
        else:
            assert ("Access granted: False" in result.stdout_text
                    or (rule and f"notmatched: {rule}" in
                        result.stdout_text)), (
                f"Expected access denied for {user} to "
                f"{host}:{service}, got: {result.stdout_text}"
            )

    def run_hbactest(self, user, host, service, should_allow=True, **kwargs):
        """
        Run HBAC test with flexible parameters.

        Args:
            user: Username to test
            host: Hostname to test
            service: Service name to test
            should_allow: Expected result (True=access granted,
                          False=denied)

        Kwargs:
            rule: Optional rule name to test specific rule
            nodetail: If True, use --nodetail flag
            expect_unresolved: If True, expect unresolved rules in output
            expect_error: If True, expect error in output
            expected_patterns: List of regex patterns to check in output
            forbidden_patterns: List of regex patterns that must NOT
                                be in output
        """
        if 'expected_patterns' in kwargs:
            self._run_hbactest_with_patterns(user, host, service, **kwargs)
        elif 'forbidden_patterns' in kwargs:
            self._run_hbactest_with_forbidden_patterns(
                user, host, service, **kwargs
            )
        elif kwargs.get('expect_unresolved'):
            self._run_hbactest_expect_unresolved(user, host, service, **kwargs)
        elif kwargs.get('expect_error'):
            self._run_hbactest_expect_error(user, host, service, **kwargs)
        else:
            self._run_hbactest_basic(user, host, service, should_allow,
                                     **kwargs)

    def cleanup_resources(self, users=None, groups=None, hostgroups=None,
                          hbacrules=None, hbacsvcs=None, hbacsvcgroups=None,
                          netgroups=None, clear_cache=True, kinit_admin=True):
        """
        Common cleanup method for HBAC test resources.
        All parameters accept lists of resource names to delete.

        Example:
            self.cleanup_resources(
                hbacrules=['rule1'],
                hostgroups=['hostgrp1'],
                groups=['group1']
            )
        """
        if kinit_admin:
            tasks.kinit_admin(self.master)

        # Define cleanup order (dependencies first - rules before groups)
        cleanup_map = [
            ('hbacrule-del', hbacrules),
            ('hbacsvcgroup-del', hbacsvcgroups),
            ('hbacsvc-del', hbacsvcs),
            ('hostgroup-del', hostgroups),
            ('netgroup-del', netgroups),
            ('group-del', groups),
            ('user-del', users),
        ]

        for cmd, resources in cleanup_map:
            if resources:
                for resource in resources:
                    self.master.run_command(
                        ["ipa", cmd, resource], raiseonerr=False
                    )
                    if cmd == 'user-del':
                        self.master.run_command(
                            ["rm", "-rf", f"/home/{resource}"],
                            raiseonerr=False
                        )

        if clear_cache:
            tasks.clear_sssd_cache(self.master)
            if hasattr(self, 'clients'):
                for client in self.clients:
                    tasks.clear_sssd_cache(client)

    # Test 001: User access to client
    def test_hbacsvc_master_001(self, request):
        """hbacsvc_master_001: user access to client, on master,
        add rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE, "admin_allow_all"]
        ))
        tasks.kinit_admin(self.master)

        # Test SSH before HBAC setup
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.master
        )
        tasks.kdestroy_all(self.master)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.master
        )
        assert self.ssh_auth_success(
            self.USER_3, self.USER_PASSWORD, self.master
        )

        tasks.kinit_admin(self.master)

        # Setup admin rule and disable allow_all
        tasks.hbacrule_add(
            self.master, "admin_allow_all",
            extra_args=["--hostcat=all", "--servicecat=all"]
        )
        tasks.hbacrule_add_user(
            self.master, "admin_allow_all",
            groups="admins"
        )
        tasks.hbacrule_disable(self.master, "allow_all")

        # Create rule1: allow user1 to access client0 with ssh
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test with hbactest
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            should_allow=False
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=False
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule="rule2",
            expected_patterns=[
                r"Unresolved rules in --rules",
                r"Non-existent or invalid rules: rule2"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        # Test with --nodetail
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        # client 1 test
        self.refresh_user_cache(self.clients[0], self.USER_1)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0]
        )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )
        # client 2 test
        self.refresh_user_cache(self.clients[1], self.USER_1)
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1]
        )

    # Test 002: User access to master for FTP
    def test_hbacsvc_master_002(self):
        """hbacsvc_master_002: user access to master for ftp, on master, add
        rule"""
        tasks.kinit_admin(self.master)
        # FTP Configs.
        self.master.run_command(
            ["systemctl", "start", "vsftpd"],
            raiseonerr=False
        )
        self.master.run_command(
            ["setsebool", "-P", "tftp_home_dir", "on"],
            raiseonerr=False
        )
        self.master.run_command(
            ["firewall-cmd", "--permanent", "--add-service=ftp"],
            raiseonerr=False
        )
        self.master.run_command(["firewall-cmd", "--reload"], raiseonerr=False)

        # Create HBAC RULE: allow user1 to access master with service vsftpd
        tasks.kinit_admin(self.master)
        # Create rule: allow user1 to access master with service vsftpd
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.master.hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="vsftpd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])
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
                          should_allow=True, rule=self.HBAC_RULE,
                          nodetail=True)

        # Test both clients
        for client in self.clients:
            self.refresh_user_cache(
                client, [self.USER_1, self.USER_2]
            )
            # Test: Can client connect to master via FTP?
            assert self.ftp_auth_success(
                self.USER_1, self.USER_PASSWORD,
                self.master, client
            )
            assert self.ftp_auth_failure(
                self.USER_2, self.USER_PASSWORD,
                self.master, client
            )

    # Test 002_1: Delete service and test
    def test_hbacsvc_master_002_1(self, request):
        """hbacsvc_master_002_1: user access to master after ftp removed, on
        master, remove ftp from rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_disable(self.master, "allow_all")
        tasks.hbacsvc_del(self.master, "vsftpd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

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
        self.run_hbactest(
            self.USER_1, self.master.hostname, "vsftpd",
            rule="rule2",
            expected_patterns=[
                r"Unresolved rules in --rules",
                r"Non-existent or invalid rules: rule2"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.master.hostname, "vsftpd",
            rule="rule2",
            expected_patterns=[
                r"Unresolved rules in --rules",
                r"Non-existent or invalid rules: rule2"
            ]
        )
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                          should_allow=False, rule=self.HBAC_RULE,
                          nodetail=True)

        # Client 1  and client 2 Test
        for client in self.clients:
            self.refresh_user_cache(
                client, self.USER_1,
                kdestroy=False
            )
            assert self.ftp_auth_failure(
                self.USER_1, self.USER_PASSWORD,
                self.master, client
            )
        assert self.ftp_auth_failure(
            self.USER_2, self.USER_PASSWORD,
            self.master, source_host=self.clients[1]
        )

    # Test 003: FTP service group
    def test_hbacsvc_master_003(self, request):
        """hbacsvc_master_003: user access to master for ftp service group,
        on master, add rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE]
        ))
        tasks.kinit_admin(self.master)
        # Create rule with service group (verifies bug 746227):
        # allow ftp access to user1 on master through a service group
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacsvc_add(self.master, "vsftpd", raiseonerr=False)
        tasks.hbacsvcgroup_add_member(self.master, "ftp", services="vsftpd")
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   extra_args=["--hbacsvcgroups=ftp"])
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.master.hostname)
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

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
        self.run_hbactest(
            self.USER_1, self.master.hostname, "vsftpd",
            rule="rule2",
            expected_patterns=[
                r"Unresolved rules in --rules",
                r"Non-existent or invalid rules: rule2"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.master.hostname, "vsftpd",
            rule="rule2",
            expected_patterns=[
                r"Unresolved rules in --rules",
                r"Non-existent or invalid rules: rule2"
            ]
        )
        self.run_hbactest(self.USER_1, self.master.hostname, "vsftpd",
                          should_allow=True, rule=self.HBAC_RULE,
                          nodetail=True)

        # Client 1 and client 2 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ftp_auth_success(
                self.USER_1, self.USER_PASSWORD,
                self.master, src_client
            )
        assert self.ftp_auth_failure(
            self.USER_2, self.USER_PASSWORD,
            self.master, source_host=self.clients[0]
        )

    # Test 004: Hostgroup access (verifies bug 733663)
    def test_hbacsvc_master_004(self, request):
        """hbacsvc_master_004: user access to hostgroup, on master,
        add rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1]
        ))
        tasks.kinit_admin(self.master)
        # Create hostgroup
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[1].hostname)

        # Create rule: allow ssh access for user1 to hosts member of
        # the hostgroup (=client1)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

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
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_3, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.HOSTGROUP_1, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client Test
        self.refresh_user_cache(self.clients[0], self.USER_1)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[1],
            source_host=self.clients[0]
        )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1],
            source_host=self.clients[1]
        )

    # Test 005: Hostgroup with user removal
    def test_hbacsvc_master_005(self):
        """hbacsvc_master_005: user access to hostgroup, on master,
        add rule"""
        tasks.kinit_admin(self.master)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[1].hostname)

        # Create rule: allow ssh access for user1 to hosts member of
        # the hostgroup (=client1)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

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
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_3, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.HOSTGROUP_1, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client Test
        self.refresh_user_cache(self.clients[0], self.USER_1)
        self.refresh_user_cache(self.clients[1], self.USER_1)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[1],
            source_host=self.clients[0]
        )
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )

    # Test 005_1: Remove user from rule
    def test_hbacsvc_master_005_1(self, request):
        """hbacsvc_master_005_1: user access after user removed, on master,
        remove user from rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_remove_user(
            self.master, self.HBAC_RULE, users=self.USER_1)
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

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
        self.run_hbactest(
            self.USER_1, self.HOSTGROUP_1, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )

        # Client Test
        self.refresh_user_cache(self.clients[0], self.USER_1)
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[0]
        )

    # Test 006: Hostgroup to hostgroup access
    def test_hbacsvc_master_006(self, request):
        """hbacsvc_master_006: user access to hostgroup from hostgroup2,
        on master, add rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1, self.HOSTGROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[0].hostname)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_2)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_2,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for user1 to hosts member of
        # the hostgroup (=client0)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

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
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client Test
        self.refresh_user_cache(self.clients[0], self.USER_1)
        self.refresh_user_cache(self.clients[1], self.USER_1)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1],
            source_host=self.clients[1]
        )

    # Test 007: Hostgroup for HBAC service group (verifies bug 830347)
    def test_hbacsvc_master_007(self):
        """hbacsvc_master_007: user access to hostgroup for hbac service
        group, on master (bz830347)"""
        tasks.kinit_admin(self.master)

        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[0].hostname)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_2)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_2,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for user1 to hosts member of
        # the hostgroup (HOSTGROUP_1) (=client0)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )

    # Test 007_1: Remove user from rule
    def test_hbacsvc_master_007_1(self, request):
        """hbacsvc_master_007_1: user access after user removed, on master,
        remove user from rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1, self.HOSTGROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_remove_user(
            self.master, self.HBAC_RULE, users=self.USER_1)
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

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
        self.run_hbactest(
            self.USER_1, self.HOSTGROUP_1, "sshd",
            self.HBAC_RULE,
            forbidden_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.HOSTGROUP_1, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )

        self.run_hbactest(
            self.USER_1, self.HOSTGROUP_2, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.HOSTGROUP_2, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client Test
        self.refresh_user_cache(self.clients[0], self.USER_1)
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[0]
        )

    # Test 008: Group access to client
    def test_hbacsvc_master_008(self):
        """hbacsvc_master_008: group access to client2, on master,
        add rule"""
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        # Create rule: allow ssh access for users in group (GROUP) to client1
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[1].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2 test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1]
        )

    # Test 008_1: Remove group from rule
    def test_hbacsvc_master_008_1(self, request):
        """hbacsvc_master_008_1: group access after group removed, on
        master, remove group from rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            groups=[self.GROUP]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_remove_user(
            self.master, self.HBAC_RULE,
            extra_args=[f"--groups={self.GROUP}"])
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            forbidden_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client Test
        self.refresh_user_cache(self.clients[1], self.USER_1)
        for src_client in self.clients:
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )

    # Test 009: Group access to client2 for HBAC service group
    def test_hbacsvc_master_009(self):
        """hbacsvc_master_009: group access to client2 for hbac service
        group, on master, add rule"""
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        # Create rule: allow ssh access for users in group (GROUP) to client1
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[1].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1]
        )

    def test_hbacsvc_master_009_1(self, request):
        """hbacsvc_master_009_1: verify group still in rule (srchost
        validation deprecated)"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            groups=[self.GROUP]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1]
        )

    # Test 010: Group access to hostgroup
    def test_hbacsvc_master_010(self, request):
        """hbacsvc_master_010: group access to hostgroup, on master, add
        rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1],
            groups=[self.GROUP]
        ))
        tasks.kinit_admin(self.master)

        tasks.group_add(self.master, self.GROUP)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for users in group (GROUP) to hosts
        # member of the hostgroup (HOSTGROUP_1) (=client1)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1]
        )

    # Test 011: Group access to hostgroup for HBAC service group
    def test_hbacsvc_master_011(self):
        """hbacsvc_master_011: group access to hostgroup for hbac service
        group, on master, add rule"""
        tasks.kinit_admin(self.master)

        tasks.group_add(self.master, self.GROUP)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[0].hostname)
        # Create rule: allow ssh access for users in group to client1
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[1].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1]
        )

    def test_hbacsvc_master_011_1(self, request):
        """hbacsvc_master_011_1: remove hbac service group"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1],
            groups=[self.GROUP]
        ))
        tasks.kinit_admin(self.master)

        tasks.hbacrule_remove_service(self.master, self.HBAC_RULE,
                                      services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            forbidden_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2  Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )

    # Test 012: Group access to client2 from hostgroup for HBAC service group
    def test_hbacsvc_master_012(self, request):
        """hbacsvc_master_012: group access to client2 from hostgroup for
        hbac service group"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hbacsvcgroups=[self.HBAC_SERVICE_GROUP1],
            hostgroups=[self.HOSTGROUP_1],
            groups=[self.GROUP]
        ))
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[0].hostname)
        # Create rule: allow ssh access for users in group to client1 through
        # a service group
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[1].hostname)
        tasks.hbacsvcgroup_add(self.master, self.HBAC_SERVICE_GROUP1)
        tasks.hbacsvcgroup_add_member(
            self.master, self.HBAC_SERVICE_GROUP1,
            services="sshd")
        tasks.hbacrule_add_service(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hbacsvcgroup={self.HBAC_SERVICE_GROUP1}"])
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        self.refresh_user_cache(self.clients[0], self.USER_1)
        self.refresh_user_cache(self.clients[1], self.USER_1)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[1],
            source_host=self.clients[0]
        )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )
        # Client 2 Test
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )

    # Test 013: Group access to hostgroup from hostgroup2
    def test_hbacsvc_master_013(self, request):
        """hbacsvc_master_013: group access to hostgroup from hostgroup2,
        on master, add rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1, self.HOSTGROUP_2],
            groups=[self.GROUP]))
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[0].hostname)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_2)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_2,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for users in group (GROUP) to hosts
        # member of the hostgroup (HOSTGROUP_1) (=client0)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        self.refresh_user_cache(self.clients[0], self.USER_1)

        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1],
            source_host=self.clients[0]
        )
        # Client 2 Test
        self.refresh_user_cache(self.clients[1], self.USER_1)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )

    # Test 014: Similar to 013
    def test_hbacsvc_master_014(self, request):
        """hbacsvc_master_014: group access to hostgroup from hostgroup2,
        on master"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1, self.HOSTGROUP_2],
            groups=[self.GROUP]))
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[0].hostname)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_2)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_2,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for users in group to hosts member of
        # the hostgroup (=client0)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE, groups=self.GROUP)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        self.refresh_user_cache(self.clients[0], self.USER_1)
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1],
            source_host=self.clients[0]
        )
        # Client 2 Test
        self.refresh_user_cache(self.clients[1], self.USER_1)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )

    # Test 015: Nested group access to client
    def test_hbacsvc_master_015(self):
        """hbacsvc_master_015: nested group access to client, on master,
        add rule"""
        tasks.kinit_admin(self.master)

        tasks.group_add(self.master, self.GROUP)
        tasks.group_add(self.master, self.GROUP_2)
        tasks.group_add_member(self.master, self.GROUP_2, users=self.USER_1)
        tasks.group_add_member(
            self.master, self.GROUP,
            extra_args=[f"--groups={self.GROUP_2}"])
        # Create rule: allow ssh access for users in nested group to client0
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )

    def test_hbacsvc_master_015_1(self, request):
        """hbacsvc_master_015_1: nested group access after group removed"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            groups=[self.GROUP, self.GROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_remove_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            forbidden_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Test both clients
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )

    # Test 016: Nested group access for HBAC service group
    def test_hbacsvc_master_016(self):
        """hbacsvc_master_016: nested group access to client for hbac
        service group"""
        tasks.kinit_admin(self.master)

        tasks.group_add(self.master, self.GROUP)
        tasks.group_add(self.master, self.GROUP_2)
        tasks.group_add_member(self.master, self.GROUP_2, users=self.USER_1)
        tasks.group_add_member(
            self.master, self.GROUP,
            extra_args=[f"--groups={self.GROUP_2}"])
        # Create rule: allow ssh access for users in nested group to client0
        # through a service group
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )

    def test_hbacsvc_master_016_1(self, request):
        """hbacsvc_master_016_1: nested group access after group removed"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            groups=[self.GROUP, self.GROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_remove_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Test both clients
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )

    # Test 017: Nested group access from hostgroup
    def test_hbacsvc_master_017(self, request):
        """hbacsvc_master_017: nested group access to client from
        hostgroup"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1],
            groups=[self.GROUP, self.GROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add(self.master, self.GROUP_2)
        tasks.group_add_member(self.master, self.GROUP_2, users=self.USER_1)
        tasks.group_add_member(
            self.master, self.GROUP,
            extra_args=[f"--groups={self.GROUP_2}"])
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for users in nested group to client0
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )

    # Test 018: Nested group access to hostgroup from hostgroup for HBAC
    # service group
    def test_hbacsvc_master_018(self, request):
        """hbacsvc_master_018: nested group to hostgroup from hostgroup
        for hbac service group"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1],
            groups=[self.GROUP, self.GROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add(self.master, self.GROUP_2)
        tasks.group_add_member(self.master, self.GROUP_2, users=self.USER_1)
        tasks.group_add_member(
            self.master, self.GROUP,
            extra_args=[f"--groups={self.GROUP_2}"])
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for users in nested group to client0
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            groups=self.GROUP)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )

    # Test 019: Nested group access to hostgroup from hostgroup2
    def test_hbacsvc_master_019(self, request):
        """hbacsvc_master_019: nested group to hostgroup from
        hostgroup2"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1, self.HOSTGROUP_2],
            groups=[self.GROUP, self.GROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add(self.master, self.GROUP_2)
        tasks.group_add_member(self.master, self.GROUP_2, users=self.USER_1)
        tasks.group_add_member(
            self.master, self.GROUP,
            extra_args=[f"--groups={self.GROUP_2}"])
        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[0].hostname)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_2)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_2,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for users in nested group to hosts
        # member of the hostgroup (=client0)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                groups=self.GROUP_2)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )

    # Test 020: Nested group for HBAC service group
    def test_hbacsvc_master_020(self):
        """hbacsvc_master_020: nested group to hostgroup for hbac
        service group"""
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add(self.master, self.GROUP_2)
        tasks.group_add_member(self.master, self.GROUP_2, users=self.USER_1)
        tasks.group_add_member(
            self.master, self.GROUP,
            extra_args=[f"--groups={self.GROUP_2}"])

        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_1,
                                   hosts=self.clients[0].hostname)
        tasks.hostgroup_add(self.master, self.HOSTGROUP_2)
        tasks.hostgroup_add_member(self.master, self.HOSTGROUP_2,
                                   hosts=self.clients[1].hostname)
        # Create rule: allow ssh access for users in nested group to hosts
        # member of the hostgroup (=client0)
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                groups=self.GROUP_2)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0],
            source_host=self.clients[1]
        )

    def test_hbacsvc_master_020_1(self, request):
        """hbacsvc_master_020_1: after rule removed"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hostgroups=[self.HOSTGROUP_1, self.HOSTGROUP_2],
            groups=[self.GROUP, self.GROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_del(self.master, self.HBAC_RULE)

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.HOSTGROUP_1, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.HOSTGROUP_1, "sshd",
            self.HBAC_RULE,
            forbidden_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.HOSTGROUP_1, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[r"Access granted: True"]
        )

        # Test both clients --> CLIENT 1
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_failure(
                self.USER_1, self.USER_PASSWORD, self.clients[1],
                source_host=src_client
            )

    # Test 021: User access client from external host
    def test_hbacsvc_master_021(self, request):
        """hbacsvc_master_021: user access client from external host,
        on master, add rule and run hbactest"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE]
        ))
        tasks.kinit_admin(self.master)
        # Create rule: allow user1 to access client0 with ssh
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, "externalhost.randomhost.com", "sshd",
            should_allow=False
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, "externalhost.randomhost.com", "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

    # Test 023: Group access to client2 from external host
    def test_hbacsvc_master_023(self, request):
        """hbacsvc_master_023: group access client2 from external host,
        on master, add rule and run hbactest"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            groups=[self.GROUP]
        ))
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        # Create rule: allow ssh access for users in group to client1
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[1].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, "externalhost.randomhost.com", "sshd",
            should_allow=False
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, "externalhost.randomhost.com", "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

    # Test 025: Group access to client from external host 2
    def test_hbacsvc_master_025(self, request):
        """hbacsvc_master_025: group access client from external host 2,
        on master, add rule and run hbactest"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            groups=[self.GROUP, self.GROUP_2]
        ))
        tasks.kinit_admin(self.master)
        tasks.group_add(self.master, self.GROUP)
        tasks.group_add(self.master, self.GROUP_2)
        tasks.group_add_member(self.master, self.GROUP, users=self.USER_1)
        tasks.group_add_member(
            self.master, self.GROUP_2,
            extra_args=[f"--groups={self.GROUP}"])
        # Create rule: allow user1 to access client0 with ssh
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, "externalhost.randomhost.com", "sshd",
            should_allow=False
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, "externalhost.randomhost.com", "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

    # Test 027: Empty HBAC service group
    def test_hbacsvc_master_027(self, request):
        """hbacsvc_master_027: user access with empty hbac service
        group"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hbacsvcgroups=[self.HBAC_SERVICE_GROUP2]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacsvcgroup_add(self.master, self.HBAC_SERVICE_GROUP2)
        # Create rule: allow user1 to access client0 with ssh through a
        # service group
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_add_service(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hbacsvcgroup={self.HBAC_SERVICE_GROUP2}"])
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )

    # Test 028: Multiple HBAC services in rule
    def test_hbacsvc_master_028(self, request):
        """hbacsvc_master_028: user access with multiple hbac
        services"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE]
        ))
        tasks.kinit_admin(self.master)

        tasks.hbacsvc_add(self.master, "sshdtest")
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshdtest")
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )

    # Test 029: Empty group in rule
    def test_hbacsvc_master_029(self, request):
        """hbacsvc_master_029: user access with empty group in rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hbacsvcgroups=[self.HBAC_SERVICE_GROUP2],
            groups=[self.GROUP]
        ))
        tasks.kinit_admin(self.master)

        tasks.group_add(self.master, self.GROUP)
        tasks.hbacsvcgroup_add(self.master, self.HBAC_SERVICE_GROUP2)
        # Create rule: allow user1 and users in group to access client0 with
        # ssh through a service group
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            extra_args=[f"--groups={self.GROUP}"])
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_add_service(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hbacsvcgroup={self.HBAC_SERVICE_GROUP2}"])
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test access
        # Test with hbactest - Basic tests
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )

    # Test 030: Empty group, hostgroup and service group in rule
    def test_hbacsvc_master_030(self, request):
        """hbacsvc_master_030: user access with empty group hostgroup
        and service group"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE],
            hbacsvcgroups=[self.HBAC_SERVICE_GROUP2],
            hostgroups=[self.HOSTGROUP_1],
            groups=[self.GROUP]
        ))
        tasks.kinit_admin(self.master)

        tasks.hostgroup_add(self.master, self.HOSTGROUP_1)
        tasks.group_add(self.master, self.GROUP)
        tasks.hbacsvcgroup_add(self.master, self.HBAC_SERVICE_GROUP2)
        # Create rule: allow user1 and users in group to access client0 and
        # hosts in hostgroup with ssh through a service group
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_user(
            self.master, self.HBAC_RULE,
            extra_args=[f"--groups={self.GROUP}"])
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_host(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hostgroups={self.HOSTGROUP_1}"])
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_add_service(
            self.master, self.HBAC_RULE,
            extra_args=[f"--hbacsvcgroup={self.HBAC_SERVICE_GROUP2}"])
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test with hbactest
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            rule=self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            rule=self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            should_allow=False, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Client 1 and 2 Test
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.clients[0],
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[0]
        )

    # Test 031: UTF-8 rule name
    def test_hbacsvc_master_031(self, request):
        """hbacsvc_master_031: user access with UTF-8 rule name"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.UTF8_HBAC_RULE]
        ))
        # Now test with UTF-8 rule name
        tasks.kinit_admin(self.master)
        # Create rule: allow user1 to access client0 with ssh
        tasks.hbacrule_add(self.master, self.UTF8_HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.UTF8_HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.UTF8_HBAC_RULE,
                                hosts=self.clients[0].hostname)
        tasks.hbacrule_add_service(self.master, self.UTF8_HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(
            self.master, self.UTF8_HBAC_RULE, extra_args=["--all"])

        # Test with hbactest
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.UTF8_HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.UTF8_HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule="rule2",
            expected_patterns=[
                r"Unresolved rules in --rules"
            ]
        )
        self.run_hbactest(
            self.USER_2, self.clients[0].hostname, "sshd",
            rule=self.UTF8_HBAC_RULE,
            expected_patterns=[
                r"Access granted: False"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            should_allow=True, rule=self.UTF8_HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.clients[0].hostname, "sshd",
            rule=self.UTF8_HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.UTF8_HBAC_RULE}"]
        )

        # Client 1  and 2 Test
        for client in self.clients:
            self.refresh_user_cache(client, self.USER_1)

        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[0]
        )
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1]
        )

    # Test 033: Offline client caching for enabled default HBAC rule
    def test_hbacsvc_master_033(self):
        """hbacsvc_master_033: offline caching with allow_all enabled"""
        tasks.kinit_admin(self.master)

        # Enable allow_all
        self.master.run_command(
            ["ipa", "hbacrule-enable", "allow_all"],
            raiseonerr=False
        )

        # Test with hbactest - all should be granted
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.master.hostname, "sshd",
                          should_allow=True)
        # --------------------------------------------------
        # Test SSH access from client0 to client1 and master
        # --------------------------------------------------
        self.refresh_user_cache(
            self.clients[0], [self.USER_1, self.USER_2], kdestroy=False
        )
        for user in [self.USER_1, self.USER_2]:
            assert self.ssh_auth_success(
                user, self.USER_PASSWORD, self.clients[1],
                source_host=self.clients[0]
            )
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.master,
                source_host=self.clients[0]
            )
        tasks.stop_ipa_server(self.master)
        for user in [self.USER_1, self.USER_2]:
            assert self.ssh_auth_success(
                user, self.USER_PASSWORD, self.clients[1],
                source_host=self.clients[0]
            )
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.master,
                source_host=self.clients[0]
            )
        tasks.start_ipa_server(self.master)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])
        # --------------------------------------------------
        # Test SSH access from client1 to client0 and master
        # --------------------------------------------------
        self.refresh_user_cache(
            self.clients[1], [self.USER_1, self.USER_2], kdestroy=False
        )
        for user in [self.USER_1, self.USER_2]:
            assert self.ssh_auth_success(
                user, self.USER_PASSWORD, self.clients[0],
                source_host=self.clients[1]
            )
            assert self.ssh_auth_success(
                user, self.USER_PASSWORD, self.master,
                source_host=self.clients[1]
            )
        tasks.stop_ipa_server(self.master)
        for user in [self.USER_1, self.USER_2]:
            assert self.ssh_auth_success(
                user, self.USER_PASSWORD, self.clients[0],
                source_host=self.clients[1]
            )
            assert self.ssh_auth_success(
                user, self.USER_PASSWORD, self.master,
                source_host=self.clients[1]
            )
        tasks.start_ipa_server(self.master)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[1])

    # Test 034: Offline client caching for disabled default HBAC rule
    def test_hbacsvc_master_034(self):
        """hbacsvc_master_034: offline caching with allow_all disabled"""
        tasks.kinit_admin(self.master)

        # Disable allow_all
        tasks.hbacrule_disable(self.master, "allow_all")

        # Test with hbactest - all should be denied
        self.run_hbactest(self.USER_1, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[0].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_1, self.master.hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(self.USER_2, self.master.hostname, "sshd",
                          should_allow=False)
        # --------------------------------------------------
        # Test SSH access from client0 to client1 and master - should fail
        # --------------------------------------------------
        self.refresh_user_cache(
            self.clients[0], [self.USER_1, self.USER_2], kdestroy=False
        )
        for user in [self.USER_1, self.USER_2]:
            assert self.ssh_auth_failure(
                user, self.USER_PASSWORD, self.clients[1],
                source_host=self.clients[0]
            )
            assert self.ssh_auth_failure(
                user, self.USER_PASSWORD, self.master,
                source_host=self.clients[0]
            )
        tasks.stop_ipa_server(self.master)
        for user in [self.USER_1, self.USER_2]:
            assert self.ssh_auth_failure(
                user, self.USER_PASSWORD, self.clients[1],
                source_host=self.clients[0]
            )
            assert self.ssh_auth_failure(
                user, self.USER_PASSWORD, self.master,
                source_host=self.clients[0]
            )
        tasks.start_ipa_server(self.master)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])
        # --------------------------------------------------
        # Test SSH access from client1 to client0 and master - should fail
        # --------------------------------------------------
        self.refresh_user_cache(
            self.clients[1], [self.USER_1, self.USER_2], kdestroy=False
        )
        for user in [self.USER_1, self.USER_2]:
            assert self.ssh_auth_failure(
                user, self.USER_PASSWORD, self.clients[0],
                source_host=self.clients[1]
            )
            assert self.ssh_auth_failure(
                user, self.USER_PASSWORD, self.master,
                source_host=self.clients[1]
            )
        tasks.stop_ipa_server(self.master)
        for user in [self.USER_1, self.USER_2]:
            assert self.ssh_auth_failure(
                user, self.USER_PASSWORD, self.clients[0],
                source_host=self.clients[1]
            )
            assert self.ssh_auth_failure(
                user, self.USER_PASSWORD, self.master,
                source_host=self.clients[1]
            )
        tasks.start_ipa_server(self.master)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])

    # Test 035: Offline client caching for custom HBAC rule
    def test_hbacsvc_master_035(self, request):
        """hbacsvc_master_035: offline caching with custom HBAC rule"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE]
        ))
        tasks.kinit_admin(self.master)
        # Disable allow_all and create custom rule
        tasks.hbacrule_disable(self.master, "allow_all")

        # Create rule: allow user1 to access client0 with ssh
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.clients[1].hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])

        # Test with hbactest
        self.run_hbactest(self.USER_1, self.clients[1].hostname, "sshd",
                          should_allow=True)
        self.run_hbactest(self.USER_2, self.clients[1].hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, self.clients[1].hostname, "vsftpd",
            should_allow=False
        )
        # --------------------------------------------------
        # Test SSH access from client0 to client1 and master
        # --------------------------------------------------
        tasks.clear_sssd_cache(self.master)
        self.refresh_user_cache(
            self.clients[0], [self.USER_1, self.USER_2], kdestroy=False
        )
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[1], self.clients[0]
        )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1], self.clients[0]
        )
        assert self.ftp_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1], self.clients[0]
        )
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.master, self.clients[0]
        )
        tasks.stop_ipa_server(self.master)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[1], self.clients[0]
        )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1], self.clients[0]
        )
        assert self.ftp_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1], self.clients[1]
        )
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.master, self.clients[0]
        )
        tasks.start_ipa_server(self.master)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])
        # --------------------------------------------------
        # Test SSH access from client1 to client1 and master
        # --------------------------------------------------
        self.refresh_user_cache(
            self.clients[1], [self.USER_1, self.USER_2], kdestroy=False
        )
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[1], self.clients[1]
        )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1], self.clients[1]
        )
        assert self.ftp_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1], self.clients[1]
        )
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.master, self.clients[1]
        )
        tasks.stop_ipa_server(self.master)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.clients[1], self.clients[1]
        )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.clients[1], self.clients[1]
        )
        assert self.ftp_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.clients[1], self.clients[1]
        )
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.master, self.clients[1]
        )
        tasks.start_ipa_server(self.master)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[1])

    # -------------------------------------------------
    # Bug-specific tests
    # -------------------------------------------------
    def test_hbacsvc_master_bug736314(self, request):
        """hbacsvc_master_bug736314: user access master with multiple
        external hosts (bz736314)"""
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[self.HBAC_RULE]
        ))
        tasks.kinit_admin(self.master)
        tasks.hbacrule_disable(self.master, "allow_all")
        # Create rule: allow user1 to access master with ssh
        tasks.hbacrule_add(self.master, self.HBAC_RULE)
        tasks.hbacrule_add_user(self.master, self.HBAC_RULE,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, self.HBAC_RULE,
                                hosts=self.master.hostname)
        tasks.hbacrule_add_service(self.master, self.HBAC_RULE,
                                   services="sshd")
        tasks.hbacrule_show(self.master, self.HBAC_RULE, extra_args=["--all"])
        # Test (verifies bug 736314)
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE
        )
        self.run_hbactest(self.USER_2, self.master.hostname, "sshd",
                          should_allow=False)
        self.run_hbactest(
            self.USER_1, "externalhost2.randomhost.com", "sshd",
            should_allow=False
        )
        self.run_hbactest(
            self.USER_1, "externalhost.randomhost.com", "sshd",
            should_allow=False
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: True",
                rf"Matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_2, "externalhost.randomhost.com", "sshd",
            self.HBAC_RULE,
            expected_patterns=[
                r"Access granted: False",
                rf"Not matched rules: {self.HBAC_RULE}"
            ]
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            should_allow=True, rule=self.HBAC_RULE, nodetail=True
        )
        self.run_hbactest(
            self.USER_1, self.master.hostname, "sshd",
            rule=self.HBAC_RULE, nodetail=True,
            forbidden_patterns=[rf"Matched rules: {self.HBAC_RULE}"]
        )

        # Test SSH access from client to master
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.master,
                source_host=src_client
            )
        assert self.ssh_auth_failure(
            self.USER_2, self.USER_PASSWORD, self.master, self.clients[1]
        )

    def test_hbacsvc_master_bug782927(self):
        """hbacsvc_master_bug782927: test sizelimit option to hbactest
        (bz782927)"""
        tasks.kinit_admin(self.master)
        try:
            # Create multiple rules to test sizelimit
            for i in range(1000, 1011):
                # Create rule: test rule for size limit
                tasks.hbacrule_add(self.master, f"rule_{i}")
            self.master.run_command(
                ["ipa", "config-mod", "--searchrecordslimit=10"]
            )
            self.master.run_command(["ipa", "config-show"])
            # Test without specific size limit
            result = self.master.run_command(["ipa", "hbacrule-find"])
            assert "Number of entries returned" in result.stdout_text
            assert "10" in result.stdout_text
            # Test with specific size limit
            result = self.master.run_command(
                ["ipa", "hbacrule-find", "--sizelimit=7"]
            )
            assert "Number of entries returned" in result.stdout_text
            assert "7" in result.stdout_text
        finally:
            # Restore config
            self.master.run_command(
                ["ipa", "config-mod", "--searchrecordslimit=100"]
            )
            self.master.run_command(["ipa", "config-show"])
            # Cleanup
            for i in range(1000, 1011):
                tasks.hbacrule_del(self.master, f"rule_{i}")

    def test_hbacsvc_master_bug772852(self):
        """hbacsvc_master_bug772852: error message with hbacrule in rules
        option (bz772852)"""
        tasks.kinit_admin(self.master)
        RULE_772852 = "bug772852"
        try:
            # Create multiple rules to test with size limit
            for i in range(1000, 1011):
                # Create rule: test rule for size limit
                tasks.hbacrule_add(self.master, f"rule_{i}")
            self.master.run_command(
                ["ipa", "config-mod", "--searchrecordslimit=15"]
            )
            # Create rule: test rule for bug 772852
            tasks.hbacrule_add(self.master, RULE_772852)
            tasks.hbacrule_add_user(
                self.master, RULE_772852, users=self.USER_1)
            tasks.hbacrule_add_host(self.master, RULE_772852,
                                    hosts=self.master.hostname)
            tasks.hbacrule_add_service(self.master, RULE_772852,
                                       services="sshd")

            # Test with --rules option (verifies bug 772852 - should not
            # show "Unresolved rules")
            self.run_hbactest(
                self.USER_1, self.master.hostname, "sshd",
                RULE_772852,
                expected_patterns=[
                    r"Access granted: True",
                    rf"Matched rules: {RULE_772852}"
                ]
            )
        finally:
            # Restore config
            self.master.run_command(
                ["ipa", "config-mod", "--searchrecordslimit=100"]
            )
            self.master.run_command(["ipa", "config-show"])
            # Cleanup
            for i in range(1000, 1011):
                tasks.hbacrule_del(self.master, f"rule_{i}")
            tasks.hbacrule_del(self.master, RULE_772852)

    def test_hbacsvc_master_bug766876(self):
        """hbacsvc_master_bug766876: Make HBAC srchost processing optional
        (bz766876)"""
        RULE_766876 = "bug766876"

        tasks.kinit_admin(self.master)
        # Create rule: allow user1 to access master with ssh
        tasks.hbacrule_add(self.master, RULE_766876)
        tasks.hbacrule_add_user(self.master, RULE_766876,
                                users=self.USER_1)
        tasks.hbacrule_add_host(self.master, RULE_766876,
                                hosts=self.master.hostname)
        tasks.hbacrule_add_service(self.master, RULE_766876,
                                   services="sshd")
        tasks.hbacrule_show(self.master, RULE_766876, extra_args=["--all"])

        # Test (verifies bug 766876) Client-1
        for src_client in self.clients:
            self.refresh_user_cache(src_client, self.USER_1)
            assert self.ssh_auth_success(
                self.USER_1, self.USER_PASSWORD, self.master,
                source_host=src_client
            )

    def test_hbacsvc_master_bug766876_2(self, request):
        """hbacsvc_master_bug766876_2: Make HBAC srchost processing
        optional Case2, on master, bz766876"""
        RULE_766876 = "bug766876"
        request.addfinalizer(lambda: self.cleanup_resources(
            hbacrules=[RULE_766876]
        ))
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["sed", "-i", "6iipa_hbac_support_srchost = true",
             "/etc/sssd/sssd.conf"]
        )
        tasks.clear_sssd_cache(self.master)
        # Test (verifies bug 766876) Client
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.master
        )

    def test_hbacsvc_master_bug801769(self):
        """hbacsvc_master_bug801769: hbactest returns failure when
        hostgroups are chained (bz801769)"""
        RULE_801769 = "bug801769"
        HOSTGROUP_801769 = "hostgroup801769"
        HOSTGROUP_801769_2 = "hostgroup801769_2"
        tasks.kinit_admin(self.master)
        try:
            # Create hostgroup
            tasks.hostgroup_add(self.master, HOSTGROUP_801769)
            tasks.hostgroup_add_member(self.master, HOSTGROUP_801769,
                                       hosts=self.master.hostname)
            # Create rule: allow user1 to access master with ssh through a
            # hostgroup
            tasks.hbacrule_add(self.master, RULE_801769)
            tasks.hbacrule_add_user(
                self.master, RULE_801769, users=self.USER_1)
            tasks.hbacrule_add_host(
                self.master, RULE_801769,
                extra_args=[f"--hostgroups={HOSTGROUP_801769}"])
            tasks.hbacrule_add_service(self.master, RULE_801769,
                                       services="sshd")
            tasks.hbacrule_show(self.master, RULE_801769, extra_args=["--all"])

            # Test (verifies bug 801769)
            self.run_hbactest(
                self.USER_1, self.master.hostname, "sshd",
                should_allow=True, rule=RULE_801769
            )

            # Create chained hostgroup
            tasks.hostgroup_add(self.master, HOSTGROUP_801769_2)
            tasks.hostgroup_add_member(
                self.master, HOSTGROUP_801769_2,
                extra_args=[f"--hostgroups={HOSTGROUP_801769}"])

            # Test with chained hostgroup (verifies bug is fixed)
            self.run_hbactest(
                self.USER_1, self.master.hostname, "sshd",
                should_allow=True, rule=RULE_801769
            )
        finally:
            tasks.hbacrule_del(self.master, RULE_801769)
            tasks.hostgroup_del(
                self.master, HOSTGROUP_801769_2, raiseonerr=False)
            tasks.hostgroup_del(
                self.master, HOSTGROUP_801769, raiseonerr=False)
            tasks.clear_sssd_cache(self.master)

    def test_hbacsvc_master_bug771706(self):
        """hbacsvc_master_bug771706: sssd crashes with empty service group
        or hostgroup (bz771706)"""
        RULE_771706 = "bug771706"
        SVCGROUP_771706 = "svcgroup771706"

        tasks.kinit_admin(self.master)
        # Create rule with empty service group (verifies bug 771706)
        tasks.hbacrule_add(
            self.master, RULE_771706, extra_args=["--hostcat=all"])
        tasks.hbacrule_add_user(self.master, RULE_771706,
                                users=self.USER_1)
        tasks.hbacsvcgroup_add(self.master, SVCGROUP_771706)
        tasks.hbacrule_add_service(
            self.master, RULE_771706,
            extra_args=[f"--hbacsvcgroups={SVCGROUP_771706}"])

        # Access should fail with empty service group
        tasks.kdestroy_all(self.master)
        assert self.ssh_auth_failure(
            self.USER_1, self.USER_PASSWORD, self.master
        )

        # Delete and recreate with valid service
        tasks.kinit_admin(self.master)
        tasks.hbacrule_del(self.master, RULE_771706)
        # Create rule: allow user1 to access master with ssh
        tasks.hbacrule_add(self.master, RULE_771706)
        tasks.hbacrule_add_user(self.master, RULE_771706,
                                users=self.USER_1)
        tasks.hbacrule_add_service(self.master, RULE_771706,
                                   services="sshd")
        tasks.hbacrule_add_host(self.master, RULE_771706,
                                hosts=self.master.hostname)

        # Now access should succeed
        tasks.kdestroy_all(self.master)
        self.master.run_command(
            ["sed", "-i", "/ipa_hbac_support_srchost/d",
             "/etc/sssd/sssd.conf"]
        )
        tasks.clear_sssd_cache(self.master)
        assert self.ssh_auth_success(
            self.USER_1, self.USER_PASSWORD, self.master
        )
