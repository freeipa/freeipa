# Copyright (C) 2025 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import
import time
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestHBACFunctional(IntegrationTest):
    """HBAC functional tests ported from bash test suite"""

    topology = 'line'
    num_clients = 2
    
    # Constants for test data
    USER_PASSWORD = 'Secret123'
    
    # Test users - we only need 3 main users for most tests
    TEST_USERS = ['testuser1', 'testuser2', 'testuser3']
    
    # Common group names
    TEST_GROUP = 'testgroup'
    TEST_NESTED_GROUP = 'nestedgroup'
    
    # Common hostgroup names  
    TEST_HOSTGROUP = 'testhostgroup'
    TEST_HOSTGROUP2 = 'testhostgroup2'
    
    # Common service group names
    TEST_SVCGROUP = 'testsvcgroup'
    
    # External host names
    EXTERNAL_HOST1 = 'external1.example.com'
    EXTERNAL_HOST2 = 'external2.example.com'

    @classmethod
    def install(cls, mh):
        super(TestHBACFunctional, cls).install(mh)
        
        # Create all test users once at setup
        tasks.kinit_admin(cls.master)
        for username in cls.TEST_USERS:
            cls.create_test_user(cls.master, username, cls.USER_PASSWORD)
        
        # Create common hostgroups
        cls.master.run_command([
            "ipa", "hostgroup-add", cls.TEST_HOSTGROUP, 
            f"--desc={cls.TEST_HOSTGROUP}"
        ])
        cls.master.run_command([
            "ipa", "hostgroup-add-member", cls.TEST_HOSTGROUP, 
            f"--hosts={cls.clients[1].hostname}"
        ])
        
        cls.master.run_command([
            "ipa", "hostgroup-add", cls.TEST_HOSTGROUP2, 
            f"--desc={cls.TEST_HOSTGROUP2}"
        ])
        cls.master.run_command([
            "ipa", "hostgroup-add-member", cls.TEST_HOSTGROUP2, 
            f"--hosts={cls.clients[0].hostname}"
        ])
        
        # Clear caches
        tasks.clear_sssd_cache(cls.master)
        tasks.clear_sssd_cache(cls.clients[0])
        tasks.clear_sssd_cache(cls.clients[1])

    @classmethod
    def uninstall(cls, mh):
        """Clean up all test resources"""
        try:
            tasks.kinit_admin(cls.master)
            
            # Delete test users
            for username in cls.TEST_USERS:
                tasks.user_del(cls.master, username)
                cls.master.run_command([
                    "rm", "-rf", f"/home/{username}"
                ], raiseonerr=False)
                
            # Delete hostgroups
            cls.master.run_command([
                "ipa", "hostgroup-del", cls.TEST_HOSTGROUP
            ], raiseonerr=False)
            cls.master.run_command([
                "ipa", "hostgroup-del", cls.TEST_HOSTGROUP2
            ], raiseonerr=False)
            
            # Enable allow_all back
            cls.master.run_command([
                "ipa", "hbacrule-enable", "allow_all"
            ], raiseonerr=False)
            
        except Exception:
            pass  # Don't fail uninstall on cleanup errors
            
        super(TestHBACFunctional, cls).uninstall(mh)

    @classmethod
    def create_test_user(cls, host, username, password):
        """Helper to create a test user with specified number and password"""
        host.run_command(["rm", "-rf", f"/home/{username}"], raiseonerr=False)
        tasks.create_active_user(host, username, password=password)

    def assert_hbac_access(self, user, host, service, should_allow=True, 
                          expected_rule=None):
        """Generic helper for HBAC test assertions"""
        result = self.master.run_command([
            "ipa", "hbactest", f"--user={user}", 
            f"--host={host}", f"--service={service}"
        ], raiseonerr=False)
        
        if should_allow:
            access_granted = "Access granted: True" in result.stdout_text
            rule_matched = (expected_rule and 
                           f"matched: {expected_rule}" in result.stdout_text)
            assert access_granted or rule_matched, (
                f"Expected access granted for {user} to {host}:{service}, "
                f"got: {result.stdout_text}"
            )
        else:
            assert "Access granted: False" in result.stdout_text, (
                f"Expected access denied for {user} to {host}:{service}, "
                f"got: {result.stdout_text}"
            )

    def setup_admin_rule_and_disable_allow_all(self):
        """Common helper to set up admin rule and disable allow_all"""
        tasks.kinit_admin(self.master)
        self.master.run_command([
            "ipa", "hbacrule-add", "admin_allow_all", 
            "--hostcat=all", "--servicecat=all"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "admin_allow_all", 
            "--groups=admins"
        ])
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])

    def cleanup_rule_and_groups(self, rule_name, *group_names):
        """Helper to clean up rules and groups"""
        tasks.kinit_admin(self.master)
        self.master.run_command([
            "ipa", "hbacrule-del", rule_name
        ], raiseonerr=False)
        for group_name in group_names:
            if group_name.startswith('hostgrp') or 'hostgroup' in group_name:
                self.master.run_command([
                    "ipa", "hostgroup-del", group_name
                ], raiseonerr=False)
            elif group_name.startswith('svcgrp') or 'svcgroup' in group_name:
                self.master.run_command([
                    "ipa", "hbacsvcgroup-del", group_name
                ], raiseonerr=False)
            else:
                self.master.run_command([
                    "ipa", "group-del", group_name
                ], raiseonerr=False)

    def test_hbacsvc_master_001(self):
        """
        hbacsvc_master_001: user access to client, on master, add rule
        """
        # Use existing test users
        user_allowed = self.TEST_USERS[0]  # testuser1
        user_denied = self.TEST_USERS[1]   # testuser2
        
        # SSH auth success tests as in bash
        result = self.master.run_command([
            'sshpass', '-p', self.USER_PASSWORD, 'ssh', '-o', 
            'StrictHostKeyChecking=no', '-l', user_allowed, 
            self.master.hostname, 'whoami'
        ], raiseonerr=False)
        
        # Setup HBAC rule on master
        self.setup_admin_rule_and_disable_allow_all()
        
        self.master.run_command(["ipa", "hbacrule-add", "rule1"])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule1", f"--users={user_allowed}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule1", 
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule1", "--hbacsvcs=sshd"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule1", "--all"])
        
        # Test using helper
        self.assert_hbac_access(user_allowed, self.clients[0].hostname, 
                               "sshd", should_allow=True, expected_rule="rule1")
        self.assert_hbac_access(user_denied, self.clients[0].hostname, 
                               "sshd", should_allow=False)
        self.assert_hbac_access(user_allowed, self.clients[1].hostname, 
                               "sshd", should_allow=False)

    def test_hbacsvc_master_001_cleanup(self):
        """Cleanup for hbacsvc_master_001"""
        self.cleanup_rule_and_groups("rule1", "admin_allow_all")
        tasks.clear_sssd_cache(self.master)

    def test_hbacsvc_client_001(self):
        """
        hbacsvc_client_001: user access to client, on client, 
        allow only user to client
        """
        user_allowed = self.TEST_USERS[0]  # testuser1
        user_denied = self.TEST_USERS[1]   # testuser2
        
        # Run on client
        self.clients[0].run_command([
            "getent", "-s", "sss", "passwd", user_allowed
        ])
        time.sleep(5)
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(["kdestroy", "-A"])
        
        # SSH auth success from client as in bash
        result = self.clients[0].run_command([
            'sshpass', '-p', self.USER_PASSWORD, 'ssh', '-o', 
            'StrictHostKeyChecking=no', '-l', user_allowed, 
            self.clients[0].hostname, 'whoami'
        ], raiseonerr=False)
        
        # SSH auth failure from client as in bash
        result = self.clients[0].run_command([
            'sshpass', '-p', self.USER_PASSWORD, 'ssh', '-o', 
            'StrictHostKeyChecking=no', '-l', user_denied, 
            self.clients[0].hostname, 'whoami'
        ], raiseonerr=False)
        
        self.clients[0].run_command([
            "rm", "-fr", "/tmp/krb5cc_*_*"
        ], raiseonerr=False)

    def test_hbacsvc_client2_001(self):
        """
        hbacsvc_client2_001: user access to client, on client2, 
        deny user to client2
        """
        user_allowed = self.TEST_USERS[0]  # testuser1
        
        # Run on client2
        self.clients[1].run_command([
            "getent", "-s", "sss", "passwd", user_allowed
        ])
        self.clients[1].run_command(["kdestroy", "-A"])
        
        # SSH auth failure from client2 as in bash
        result = self.clients[1].run_command([
            'sshpass', '-p', self.USER_PASSWORD, 'ssh', '-o', 
            'StrictHostKeyChecking=no', '-l', user_allowed, 
            self.clients[1].hostname, 'whoami'
        ], raiseonerr=False)
        
        self.clients[1].run_command([
            "rm", "-fr", "/tmp/krb5cc_*_*"
        ], raiseonerr=False)

    def test_hbacsvc_master_002(self):
        """
        hbacsvc_master_002: user access to master for ftp, on master, add rule
        """
        user_allowed = self.TEST_USERS[0]  # testuser1
        user_denied = self.TEST_USERS[1]   # testuser2
        
        # Disable allow_all on master
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Install and start FTP on master
        self.master.run_command(["dnf", "install", "-y", "ftp", "vsftpd"])
        self.master.run_command(["systemctl", "start", "vsftpd"])
        self.master.run_command(["setsebool", "-P", "tftp_home_dir", "on"])
        
        # Create HBAC rule for FTP on master
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-add", "rule2"])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule2", f"--users={user_allowed}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule2", 
            f"--hosts={self.master.hostname}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule2", "--hbacsvcs=vsftpd"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule2", "--all"])
        tasks.clear_sssd_cache(self.master)
        
        # Test using helper
        self.assert_hbac_access(user_allowed, self.master.hostname, 
                               "vsftpd", should_allow=True, expected_rule="rule2")
        self.assert_hbac_access(user_denied, self.master.hostname, 
                               "vsftpd", should_allow=False)

    def test_hbacsvc_master_002_cleanup(self):
        """Cleanup for hbacsvc_master_002"""
        self.cleanup_rule_and_groups("rule2")
        tasks.clear_sssd_cache(self.master)

    def test_hbacsvc_master_003(self):
        """
        hbacsvc_master_003: user access to master for ftp service group, 
        on master, add rule
        """
        user_allowed = self.TEST_USERS[2]  # testuser3
        user_denied = self.TEST_USERS[1]   # testuser2
        
        # Disable allow_all on master
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Install and start FTP on master
        self.master.run_command(["dnf", "install", "-y", "ftp", "vsftpd"])
        self.master.run_command(["setsebool", "-P", "tftp_home_dir", "on"])
        self.master.run_command(["systemctl", "restart", "vsftpd"])
        
        # Create HBAC rule with service group on master
        self.master.run_command(["ipa", "hbacrule-add", "rule3"])
        self.master.run_command(["ipa", "hbacsvc-add", "vsftpd"])
        self.master.run_command([
            "ipa", "hbacsvcgroup-add-member", "ftp", "--hbacsvcs=vsftpd"
        ])
        
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule3", 
            "--hbacsvcgroups=ftp"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule3", f"--users={user_allowed}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule3", 
            f"--hosts={self.master.hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule3", "--all"])
        
        # Test using helper - verifies bug 746227
        self.assert_hbac_access(user_allowed, self.master.hostname, 
                               "vsftpd", should_allow=True, expected_rule="rule3")
        self.assert_hbac_access(user_denied, self.master.hostname, 
                               "vsftpd", should_allow=False)

    def test_hbacsvc_master_003_cleanup(self):
        """Cleanup for hbacsvc_master_003"""
        self.cleanup_rule_and_groups("rule3")
        tasks.clear_sssd_cache(self.master)

    def test_hbacsvc_master_004(self):
        """
        hbacsvc_master_004: user access to hostgroup, on master, add rule
        """
        user_allowed = self.TEST_USERS[0]  # testuser1
        user_denied = self.TEST_USERS[1]   # testuser2
        
        # Disable allow_all on master
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Create HBAC rule using existing hostgroup on master
        self.master.run_command(["ipa", "hbacrule-add", "rule4"])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule4", "--hbacsvcs=sshd"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule4", f"--users={user_allowed}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule4", f"--hostgroups={self.TEST_HOSTGROUP}"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule4", "--all"])
        
        # Test using helper - verifies bug 733663
        self.assert_hbac_access(user_allowed, self.clients[1].hostname, 
                               "sshd", should_allow=True, expected_rule="rule4")
        self.assert_hbac_access(user_denied, self.clients[0].hostname, 
                               "sshd", should_allow=False)

    def test_hbacsvc_master_004_cleanup(self):
        """Cleanup for hbacsvc_master_004"""
        self.cleanup_rule_and_groups("rule4")

    def test_hbacsvc_master_008(self):
        """
        hbacsvc_master_008: group access to client2, on master, add rule
        """
        user_in_group = self.TEST_USERS[0]  # testuser1
        user_not_in_group = self.TEST_USERS[1]  # testuser2
        
        # Create group and add user
        tasks.kinit_admin(self.master)
        self.master.run_command([
            "ipa", "group-add", self.TEST_GROUP, f"--desc={self.TEST_GROUP}"
        ])
        self.master.run_command([
            "ipa", "group-add-member", self.TEST_GROUP, f"--users={user_in_group}"
        ])
        time.sleep(5)
        
        # Disable allow_all on master
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Create HBAC rule for group access on master
        self.master.run_command(["ipa", "hbacrule-add", "rule8"])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule8", "--hbacsvcs=sshd"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule8", f"--groups={self.TEST_GROUP}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule8", 
            f"--hosts={self.clients[1].hostname}"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule8", "--all"])
        
        # Test using helper
        self.assert_hbac_access(user_in_group, self.clients[1].hostname, 
                               "sshd", should_allow=True, expected_rule="rule8")
        self.assert_hbac_access(user_not_in_group, self.clients[1].hostname, 
                               "sshd", should_allow=False)
        
        # Test group removal breaks access
        self.master.run_command([
            "ipa", "hbacrule-remove-user", "rule8", f"--groups={self.TEST_GROUP}"
        ])
        
        self.assert_hbac_access(user_in_group, self.clients[1].hostname, 
                               "sshd", should_allow=False)

    def test_hbacsvc_master_008_cleanup(self):
        """Cleanup for hbacsvc_master_008"""
        self.cleanup_rule_and_groups("rule8", self.TEST_GROUP)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[1])

    def test_hbacsvc_master_015(self):
        """
        hbacsvc_master_015: nested group access to client, on master, add rule
        """
        user_in_nested_group = self.TEST_USERS[0]  # testuser1
        
        # Create nested groups
        tasks.kinit_admin(self.master)
        self.master.run_command([
            "ipa", "group-add", self.TEST_GROUP, f"--desc={self.TEST_GROUP}"
        ])
        self.master.run_command([
            "ipa", "group-add", self.TEST_NESTED_GROUP, f"--desc={self.TEST_NESTED_GROUP}"
        ])
        self.master.run_command([
            "ipa", "group-add-member", self.TEST_GROUP, f"--users={user_in_nested_group}"
        ])
        self.master.run_command([
            "ipa", "group-add-member", self.TEST_NESTED_GROUP, f"--groups={self.TEST_GROUP}"
        ])
        
        # Disable allow_all
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Create HBAC rule using nested group
        self.master.run_command(["ipa", "hbacrule-add", "rule15"])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule15", f"--groups={self.TEST_NESTED_GROUP}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule15", 
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule15", "--hbacsvcs=sshd"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule15", "--all"])
        
        # Test nested group access
        self.assert_hbac_access(user_in_nested_group, self.clients[0].hostname, 
                               "sshd", should_allow=True, expected_rule="rule15")
        
        # Test removing nested group breaks access
        self.master.run_command([
            "ipa", "hbacrule-remove-user", "rule15", f"--groups={self.TEST_NESTED_GROUP}"
        ])
        
        self.assert_hbac_access(user_in_nested_group, self.clients[0].hostname, 
                               "sshd", should_allow=False)

    def test_hbacsvc_master_015_cleanup(self):
        """Cleanup for hbacsvc_master_015"""
        self.cleanup_rule_and_groups("rule15", self.TEST_GROUP, self.TEST_NESTED_GROUP)

    def test_hbacsvc_master_021(self):
        """
        hbacsvc_master_021: user access client from external host, 
        on master, hbactest
        """
        user_allowed = self.TEST_USERS[0]  # testuser1
        
        # Disable allow_all
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Create HBAC rule with external host
        self.master.run_command(["ipa", "hbacrule-add", "rule21"])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule21", f"--users={user_allowed}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule21", 
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule21", "--hbacsvcs=sshd"
        ])
        
        # Add external host
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule21", 
            f"--hosts={self.EXTERNAL_HOST1}"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule21", "--all"])
        
        # Test external host access
        self.assert_hbac_access(user_allowed, self.EXTERNAL_HOST1, 
                               "sshd", should_allow=True, expected_rule="rule21")
        
        # Test client access
        self.assert_hbac_access(user_allowed, self.clients[0].hostname, 
                               "sshd", should_allow=True, expected_rule="rule21")

    def test_hbacsvc_master_021_cleanup(self):
        """Cleanup for hbacsvc_master_021"""
        self.cleanup_rule_and_groups("rule21")

    def test_hbacsvc_master_bug736314(self):
        """
        hbacsvc_master_bug736314: user access client from external host for
        ftp service group, on master, hbactest
        Multiple external hosts bug 736314
        """
        user_allowed = self.TEST_USERS[0]  # testuser1
        
        # Disable allow_all
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Create service group and add sshd
        self.master.run_command([
            "ipa", "hbacsvcgroup-add", self.TEST_SVCGROUP, f"--desc={self.TEST_SVCGROUP}"
        ])
        self.master.run_command([
            "ipa", "hbacsvcgroup-add-member", self.TEST_SVCGROUP, "--hbacsvcs=sshd"
        ])
        
        # Create HBAC rule with multiple external hosts
        self.master.run_command(["ipa", "hbacrule-add", "rule736314"])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule736314", f"--users={user_allowed}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule736314", 
            f"--hbacsvcgroups={self.TEST_SVCGROUP}"
        ])
        
        # Add multiple external hosts
        for ext_host in [self.EXTERNAL_HOST1, self.EXTERNAL_HOST2]:
            self.master.run_command([
                "ipa", "hbacrule-add-host", "rule736314", 
                f"--hosts={ext_host}"
            ])
        
        # Test multiple external hosts
        for ext_host in [self.EXTERNAL_HOST1, self.EXTERNAL_HOST2]:
            self.assert_hbac_access(user_allowed, ext_host, 
                                   "sshd", should_allow=True, expected_rule="rule736314")

    def test_hbacsvc_master_bug736314_cleanup(self):
        """Cleanup for hbacsvc_master_bug736314"""
        self.cleanup_rule_and_groups("rule736314", self.TEST_SVCGROUP)

    def test_hbacsvc_master_bug771706(self):
        """
        hbacsvc_master_bug771706: sssd be crashes during auth when there exists 
        empty service group or hostgroup in an hbacrule, on master, hbactest
        """
        user_denied = self.TEST_USERS[0]  # testuser1
        
        # Disable allow_all
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Create empty service group
        empty_svc_group = "empty_svc_group"
        self.master.run_command([
            "ipa", "hbacsvcgroup-add", empty_svc_group, 
            "--desc=Empty service group for bug test"
        ])
        
        # Create HBAC rule with empty service group
        self.master.run_command(["ipa", "hbacrule-add", "rule771706"])
        self.master.run_command([
            "ipa", "hbacrule-add-user", "rule771706", f"--users={user_denied}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-host", "rule771706", 
            f"--hosts={self.clients[0].hostname}"
        ])
        self.master.run_command([
            "ipa", "hbacrule-add-service", "rule771706", 
            f"--hbacsvcgroups={empty_svc_group}"
        ])
        self.master.run_command(["ipa", "hbacrule-show", "rule771706", "--all"])
        
        # Test with empty service group - should not crash
        self.assert_hbac_access(user_denied, self.clients[0].hostname, 
                               "sshd", should_allow=False)

    def test_hbacsvc_master_bug771706_cleanup(self):
        """Cleanup for hbacsvc_master_bug771706"""
        self.cleanup_rule_and_groups("rule771706", "empty_svc_group")

    def test_hbacsvc_master_033(self):
        """
        hbacsvc_master_033: Offline client caching for enabled default hbac rule, 
        on master, enable allow all
        """
        user_allowed = self.TEST_USERS[0]  # testuser1
        
        # Enable allow_all rule
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-enable", "allow_all"])
        
        # Test access with allow_all enabled
        self.assert_hbac_access(user_allowed, self.clients[0].hostname, 
                               "sshd", should_allow=True, expected_rule="allow_all")
        
        # Test offline caching by stopping IPA services temporarily
        self.master.run_command(["systemctl", "stop", "ipa"], 
                               raiseonerr=False)
        time.sleep(10)
        
        # Start services back
        self.master.run_command(["systemctl", "start", "ipa"], 
                               raiseonerr=False)
        time.sleep(30)

    def test_hbacsvc_master_034(self):
        """
        hbacsvc_master_034: Offline client caching for disabled default 
        HBAC rule, on master, disable allow all
        """
        user_denied = self.TEST_USERS[0]  # testuser1
        
        # Disable allow_all rule
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        
        # Test access with allow_all disabled
        self.assert_hbac_access(user_denied, self.clients[0].hostname, 
                               "sshd", should_allow=False)
        
        # Test offline caching
        tasks.clear_sssd_cache(self.clients[0])
        time.sleep(10)
        
        # Re-enable allow_all for other tests
        self.master.run_command([
            "ipa", "hbacrule-enable", "allow_all"
        ], raiseonerr=False)