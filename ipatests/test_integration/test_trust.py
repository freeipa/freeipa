# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import textwrap
import time
import functools

import pytest

from ipaplatform.constants import constants as platformconstants
from ipaplatform.paths import paths

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration import fips
from ipatests.util import xfail_context
from ipapython.dn import DN
from collections import namedtuple
from contextlib import contextmanager

TestDataRule = namedtuple('TestDataRule',
                          ['name', 'ruletype', 'user', 'subject'])


def skip_in_fips_mode_due_to_issue_8715(test_method):
    @functools.wraps(test_method)
    def wrapper(instance):
        if fips.is_fips_enabled(instance.master):
            pytest.skip('Skipping in FIPS mode due to '
                        'https://pagure.io/freeipa/issue/8715')
        else:
            test_method(instance)
    return wrapper


class BaseTestTrust(IntegrationTest):
    num_clients = 1
    topology = 'line'
    num_ad_domains = 1
    num_ad_subdomains = 1
    num_ad_treedomains = 1

    upn_suffix = 'UPNsuffix.com'
    upn_username = 'upnuser'
    upn_name = 'UPN User'
    upn_principal = '{}@{}'.format(upn_username, upn_suffix)
    upn_password = 'Secret123456'

    shared_secret = 'qwertyuiopQq!1'
    default_shell = platformconstants.DEFAULT_SHELL

    @classmethod
    def install(cls, mh):
        if not cls.master.transport.file_exists('/usr/bin/rpcclient'):
            raise pytest.skip("Package samba-client not available "
                              "on {}".format(cls.master.hostname))
        super(BaseTestTrust, cls).install(mh)
        cls.ad = cls.ads[0]
        cls.ad_domain = cls.ad.domain.name
        tasks.install_adtrust(cls.master)
        cls.check_sid_generation()
        tasks.sync_time(cls.master, cls.ad)

        if cls.num_ad_subdomains > 0:
            cls.child_ad = cls.ad_subdomains[0]
            cls.ad_subdomain = cls.child_ad.domain.name
        if cls.num_ad_treedomains > 0:
            cls.tree_ad = cls.ad_treedomains[0]
            cls.ad_treedomain = cls.tree_ad.domain.name
        # values used in workaround for
        # https://bugzilla.redhat.com/show_bug.cgi?id=1711958
        cls.srv_gc_record_name = \
            '_ldap._tcp.Default-First-Site-Name._sites.gc._msdcs'
        cls.srv_gc_record_value = '0 100 389 {}.'.format(cls.master.hostname)

    @classmethod
    def check_sid_generation(cls):
        command = ['ipa', 'user-show', 'admin', '--all', '--raw']

        # TODO: remove duplicate definition and import from common module
        _sid_identifier_authority = '(0x[0-9a-f]{1,12}|[0-9]{1,10})'
        sid_regex = 'S-1-5-21-%(idauth)s-%(idauth)s-%(idauth)s'\
                    % dict(idauth=_sid_identifier_authority)
        stdout_re = re.escape('  ipaNTSecurityIdentifier: ') + sid_regex

        tasks.run_repeatedly(cls.master, command,
                             test=lambda x: re.search(stdout_re, x))

    def check_trustdomains(self, realm, expected_ad_domains):
        """Check that ipa trustdomain-find lists all expected domains"""
        result = self.master.run_command(['ipa', 'trustdomain-find', realm])
        for domain in expected_ad_domains:
            expected_text = 'Domain name: %s\n' % domain
            assert expected_text in result.stdout_text
        expected_text = ("Number of entries returned %s\n" %
                         len(expected_ad_domains))
        assert expected_text in result.stdout_text

    def check_range_properties(self, realm, expected_type, expected_size):
        """Check the properties of the created range"""
        range_name = realm.upper() + '_id_range'
        result = self.master.run_command(['ipa', 'idrange-show', range_name,
                                          '--all', '--raw'])
        expected_text = 'ipaidrangesize: %s\n' % expected_size
        assert expected_text in result.stdout_text
        expected_text = 'iparangetype: %s\n' % expected_type
        assert expected_text in result.stdout_text

    def mod_idrange_auto_private_group(
        self, option='false'
    ):
        """
        Set the auto-private-group option of the default trusted
        AD domain range.
        """
        tasks.kinit_admin(self.master)
        rangename = self.ad_domain.upper() + '_id_range'
        error_msg = "ipa: ERROR: no modifications to be performed"
        cmd = ["ipa", "idrange-mod", rangename,
               "--auto-private-groups", option]
        result = self.master.run_command(cmd, raiseonerr=False)
        if result.returncode != 0:
            tasks.assert_error(result, error_msg)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])
        test = self.master.run_command(["ipa", "idrange-show", rangename])
        assert "Auto private groups: {0}".format(option) in test.stdout_text

    def get_user_id(self, host, username):
        """
        User uid gid is parsed from the output of id user command.
        """
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])
        self.master.run_command(["id", username])
        test_id = host.run_command(["id", username])
        regex = r"^uid=(?P<uid>\d+).*gid=(?P<gid>\d+).*groups=(?P<groups>\d+)"
        match = re.match(regex, test_id.stdout_text)
        uid = match.group('uid')
        gid = match.group('gid')
        return uid, gid

    @contextmanager
    def set_idoverrideuser(self, user, uid, gid):
        """
        Fixture to add/remove idoverrideuser for default idview,
        also creates idm group with the provided gid because
        gid overrides requires an existing group.
        """
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])
        tasks.kinit_admin(self.master)
        try:
            args = ["ipa", "idoverrideuser-add", "Default Trust View",
                    "--gid", gid, "--uid", uid, user]
            self.master.run_command(args)
            tasks.group_add(self.master, "idgroup",
                            extra_args=["--gid", gid])
            yield
        finally:
            self.master.run_command([
                "ipa", "idoverrideuser-del", "Default Trust View", user]
            )
            self.master.run_command(["ipa", "group-del", "idgroup"])

    def remove_trust(self, ad):
        tasks.remove_trust_with_ad(self.master,
                                   ad.domain.name, ad.hostname)
        tasks.clear_sssd_cache(self.master)


class TestTrust(BaseTestTrust):

    # Tests for non-posix AD trust

    def test_establish_nonposix_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])

    def test_trustdomains_found_in_nonposix_trust(self):
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain, self.ad_subdomain])

    def test_range_properties_in_nonposix_trust(self):
        self.check_range_properties(self.ad_domain, 'ipa-ad-trust', 200000)

    def test_user_gid_uid_resolution_in_nonposix_trust(self):
        """Check that user has SID-generated UID"""
        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = r"^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         r"Test User:/home/%s/testuser:%s$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain),
                            self.default_shell,
                            )

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

    def test_ipa_commands_run_as_aduser(self):
        """Test if proper error thrown when AD user tries to run IPA commands

        Before fix the error used to implies that the ipa setup is broken.
        Fix is to throw the proper error. This test is to check that the
        error with 'Invalid credentials' thrown when AD user tries to run
        IPA commands.

        related: https://pagure.io/freeipa/issue/8163
        """
        tasks.kdestroy_all(self.master)
        ad_admin = 'Administrator@%s' % self.ad_domain
        tasks.kinit_as_user(self.master, ad_admin,
                            self.master.config.ad_admin_password)
        err_string1 = 'ipa: ERROR: Insufficient access: '
        err_string2 = 'Invalid credentials'
        result = self.master.run_command(['ipa', 'ping'], raiseonerr=False)
        assert err_string1 in result.stderr_text
        assert err_string2 in result.stderr_text

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

    def test_ipa_management_run_as_aduser(self):
        """Test if adding AD user to a role makes it an administrator"""
        ipauser = u'tuser'
        ad_admin = 'Administrator@%s' % self.ad_domain

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'idoverrideuser-add',
                                 'Default Trust View', ad_admin])

        self.master.run_command(['ipa', 'role-add-member',
                                 'User Administrator',
                                 '--idoverrideusers', ad_admin])
        tasks.kdestroy_all(self.master)
        tasks.kinit_as_user(self.master, ad_admin,
                            self.master.config.ad_admin_password)
        # Create a user in IPA as Active Directory administrator
        self.test_ipauser_authentication_with_nonposix_trust()

        tasks.kdestroy_all(self.master)
        tasks.kinit_as_user(self.master, ad_admin,
                            self.master.config.ad_admin_password)
        self.master.run_command(['ipa', 'user-del', ipauser], raiseonerr=False)
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

    def test_password_login_as_aduser(self):
        """Test if AD user can login with password to Web UI"""
        ad_admin = 'Administrator@%s' % self.ad_domain

        tasks.kdestroy_all(self.master)
        user_and_password = ('user=%s&password=%s' %
                             (ad_admin, self.master.config.ad_admin_password))
        host = self.master.hostname
        cmd_args = [
            paths.BIN_CURL,
            '-v',
            '-H', 'referer:https://{}/ipa'.format(host),
            '-H', 'Content-Type:application/x-www-form-urlencoded',
            '-H', 'Accept:text/plain',
            '--cacert', paths.IPA_CA_CRT,
            '--data', user_and_password,
            'https://{}/ipa/session/login_password'.format(host)]
        result = self.master.run_command(cmd_args)
        assert "Set-Cookie: ipa_session=MagBearerToken" in result.stderr_text
        tasks.kinit_admin(self.master)

    def test_ipauser_authentication_with_nonposix_trust(self):
        ipauser = u'tuser'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'

        # create an ipauser for this test
        self.master.run_command(['ipa', 'user-add', ipauser, '--first=Test',
                                 '--last=User', '--password'],
                                stdin_text=original_passwd)

        # change password for the user to be able to kinit
        tasks.ldappasswd_user_change(ipauser, original_passwd, new_passwd,
                                     self.master)

        # try to kinit as ipauser
        self.master.run_command([
            'kinit', '-E', '{0}@{1}'.format(ipauser, self.master.domain.name)],
            stdin_text=new_passwd)

    # Tests for UPN suffixes

    def test_upn_in_nonposix_trust(self):
        """Check that UPN is listed as trust attribute"""
        result = self.master.run_command(['ipa', 'trust-show', self.ad_domain,
                                          '--all', '--raw'])

        assert ("ipantadditionalsuffixes: {}".format(self.upn_suffix) in
                result.stdout_text)

    def test_upn_user_resolution_in_nonposix_trust(self):
        """Check that user with UPN can be resolved"""
        result = self.master.run_command(['getent', 'passwd',
                                          self.upn_principal])

        # result will contain AD domain, not UPN
        upnuser_regex = (
            r"^{}@{}:\*:(\d+):(\d+):{}:/home/{}/{}:{}$".format(
                self.upn_username, self.ad_domain, self.upn_name,
                self.ad_domain, self.upn_username,
                self.default_shell,
            )
        )
        assert re.search(upnuser_regex, result.stdout_text), result.stdout_text

    def test_upn_user_authentication_in_nonposix_trust(self):
        """ Check that AD user with UPN can authenticate in IPA """
        self.master.run_command(['kinit', '-C', '-E', self.upn_principal],
                                stdin_text=self.upn_password)

    @contextmanager
    def check_sudorules_for(self, object_type, object_name,
                            testuser, expected):
        """Verify trusted domain objects can be added to sudorules"""

        # Create a SUDO rule that allows test user
        # to run any command on any host as root without password
        # and check that it is indeed possible to do so with sudo -l
        hbacrule = 'hbacsudoers-' + object_type
        sudorule = 'testrule-' + object_type
        commands = [['ipa', 'hbacrule-add', hbacrule,
                     '--usercat=all', '--hostcat=all'],
                    ['ipa', 'hbacrule-add-service', hbacrule,
                     '--hbacsvcs=sudo'],
                    ['ipa', 'sudocmd-add', 'ALL'],
                    ['ipa', 'sudorule-add', sudorule, '--hostcat=all'],
                    ['ipa', 'sudorule-add-user', sudorule,
                     '--users', object_name],
                    ['ipa', 'sudorule-add-option', sudorule,
                     '--sudooption', '!authenticate'],
                    ['ipa', 'sudorule-add-allow-command', sudorule,
                     '--sudocmds', 'ALL']]
        for c in commands:
            self.master.run_command(c)

        # allow additional configuration
        yield TestDataRule(sudorule, 'sudo', object_name, testuser)

        # Modify refresh_expired_interval to reduce time for refreshing
        # expired entries in SSSD cache in order to avoid waiting at least
        # 30 seconds before SSSD updates SUDO rules and undertermined time
        # that takes to refresh the rules.
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        try:
            with tasks.remote_sssd_config(self.master) as sssd_conf:
                sssd_conf.edit_domain(
                    self.master.domain, 'refresh_expired_interval', 1)
                sssd_conf.edit_domain(
                    self.master.domain, 'entry_cache_timeout', 1)
            tasks.clear_sssd_cache(self.master)

            # Sleep some time so that SSSD settles down
            # cache updates
            time.sleep(10)
            result = self.master.run_command(
                ['su', '-', testuser, '-c', 'sudo -l'])
            if isinstance(expected, (tuple, list)):
                assert any(x for x in expected if x in result.stdout_text)
            else:
                assert expected in result.stdout_text
        finally:
            sssd_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)

        commands = [['ipa', 'sudorule-del', sudorule],
                    ['ipa', 'sudocmd-del', 'ALL'],
                    ['ipa', 'hbacrule-del', hbacrule]]
        for c in commands:
            self.master.run_command(c)

    def test_sudorules_ad_users(self):
        """Verify trusted domain users can be added to sudorules"""

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

        testuser = '%s@%s' % (self.master.config.ad_admin_name, self.ad_domain)
        expected = "(root) NOPASSWD: ALL"

        with self.check_sudorules_for("user", testuser, testuser, expected):
            # no additional configuration
            pass

    def test_sudorules_ad_groups(self):
        """Verify trusted domain groups can be added to sudorules"""

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

        testuser = '%s@%s' % (self.master.config.ad_admin_name, self.ad_domain)
        testgroup = 'Enterprise Admins@%s' % self.ad_domain
        expected = "(root) NOPASSWD: ALL"
        with self.check_sudorules_for("group", testuser, testuser,
                                      expected) as sudorule:
            # Remove the user and instead add a group
            self.master.run_command(['ipa',
                                     'sudorule-remove-user', sudorule.name,
                                     '--users', sudorule.user])
            self.master.run_command(['ipa', 'sudorule-add-user', sudorule.name,
                                     '--groups', testgroup])

    def test_sudorules_ad_runasuser(self):
        """Verify trusted domain users can be added to runAsUser"""

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

        testuser = '%s@%s' % (self.master.config.ad_admin_name, self.ad_domain)
        expected = "(%s) NOPASSWD: ALL" % (testuser.lower())

        with self.check_sudorules_for("user", testuser, testuser,
                                      expected) as sudorule:
            # Add runAsUser with the same user
            self.master.run_command(['ipa',
                                     'sudorule-add-runasuser', sudorule.name,
                                     '--users', sudorule.subject])

    def test_sudorules_ad_runasuser_group(self):
        """Verify trusted domain groups can be added to runAsUser"""

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

        testuser = '%s@%s' % (self.master.config.ad_admin_name, self.ad_domain)
        testgroup = 'Enterprise Admins@%s' % self.ad_domain
        expected1 = '("%%%s") NOPASSWD: ALL' % testgroup.lower()
        expected2 = '("%%%%%s") NOPASSWD: ALL' % testgroup.lower()

        with self.check_sudorules_for("group", testuser, testuser,
                                      [expected1, expected2]) as sudorule:
            # Add runAsUser with the same user
            self.master.run_command(['ipa',
                                     'sudorule-add-runasuser',
                                     sudorule.name,
                                     '--groups', testgroup])

    def test_sudorules_ad_runasgroup(self):
        """Verify trusted domain groups can be added to runAsGroup"""

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

        testuser = '%s@%s' % (self.master.config.ad_admin_name, self.ad_domain)
        testgroup = 'Enterprise Admins@%s' % self.ad_domain
        expected = '(%s : "%%%s") NOPASSWD: ALL' % (testuser.lower(),
                                                    testgroup.lower())
        with self.check_sudorules_for("group", testuser, testuser,
                                      expected) as sudorule:
            # Add runAsGroup with the same user
            self.master.run_command(['ipa',
                                     'sudorule-add-runasgroup',
                                     sudorule.name,
                                     '--groups', testgroup])

    # Test with AD trust defining subordinate suffixes
    def test_subordinate_suffix(self):
        """Test subordinate UPN suffixes routing.

        Given an AD domain ad.test with additional UPN suffix suffix.ad.test
        check that requests from IPA for suffix.ad.test
        are properly routed to ad.test.

        This is a regression test for https://pagure.io/freeipa/issue/8554
        """

        # Create subordinate UPN suffix
        subordinate_suffix = 'test_subdomain.' + self.ad_domain
        self.ad.run_command([
            'powershell', '-c',
            'Set-ADForest -Identity {} -UPNSuffixes @{{add="{}"}}'.format(
                self.ad_domain, subordinate_suffix)])
        try:
            # Verify UPN suffix is created
            cmd = ('Get-ADForest -Identity {} '
                   '| Select-Object -Property UPNSuffixes'
                   .format(self.ad_domain))
            res = self.ad.run_command(['powershell', '-c', cmd])
            assert subordinate_suffix in res.stdout_text

            # Verify IPA does not receive subordinate suffix from AD
            self.master.run_command(
                ['ipa', 'trust-fetch-domains', self.ad_domain],
                ok_returncode=1)
            res = self.master.run_command(
                ['ipa', 'trust-show', self.ad_domain])
            assert subordinate_suffix not in res.stdout_text

            # Set UPN for the AD user
            upn = 'testuser@' + subordinate_suffix
            cmd = 'Set-Aduser -UserPrincipalName {} -Identity testuser'.format(
                upn)
            self.ad.run_command(['powershell', '-c', cmd])

            # Check user resolution
            res = self.master.run_command(['getent', 'passwd', upn])
            expected_regex = (
                r'^testuser@{domain}:\*:(\d+):(\d+):'
                r'Test User:/home/{domain}/testuser:{shell}$'
                .format(domain=re.escape(self.ad_domain),
                        shell=self.default_shell))
            assert re.search(expected_regex, res.stdout_text)

            # Check user authentication
            self.master.run_command(
                ['kinit', '-E', upn], stdin_text='Secret123')
        finally:
            # cleanup
            tasks.kdestroy_all(self.master)
            cmd = ('Set-ADForest -Identity {} -UPNSuffixes @{{Remove="{}"}}'
                   .format(self.ad_domain, subordinate_suffix))
            self.ad.run_command(['powershell', '-c', cmd])

    def test_ssh_aduser(self):
        """Test ssh with GSSAPI is working with aduser

        When kerberos ticket is obtained for child domain user
        and ssh with this ticket should be successful
        with no password prompt.

        Related : https://pagure.io/freeipa/issue/9316
        """
        testuser = 'testuser@{0}'.format(self.ad_domain)
        testusersub = 'subdomaintestuser@{0}'.format(self.ad_subdomain)

        def sshuser(host, user):
            tasks.kdestroy_all(host)
            try:
                tasks.kinit_as_user(host, user,
                                    host.config.ad_admin_password
                                    )
                ssh_cmd = "ssh -q -K -l {user} {host} hostname"
                valid_ssh = host.run_command(
                    ssh_cmd.format(user=user, host=host.hostname)
                )
                assert host.hostname in valid_ssh.stdout_text
            finally:
                tasks.kdestroy_all(host)

        sshuser(self.master, testuser)
        sshuser(self.master, testusersub)

    def test_remove_nonposix_trust(self):
        self.remove_trust(self.ad)
        tasks.unconfigure_dns_for_trust(self.master, self.ad)

    # Tests for posix AD trust

    def test_establish_posix_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust-posix'])

    def test_trustdomains_found_in_posix_trust(self):
        """Tests that all trustdomains can be found."""
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain, self.ad_subdomain])

    def test_range_properties_in_posix_trust(self):
        """Check the properties of the created range"""
        self.check_range_properties(self.ad_domain, 'ipa-ad-trust-posix',
                                    200000)

    def test_user_uid_gid_resolution_in_posix_trust(self):
        """Check that user has AD-defined UID"""

        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        testuser_stdout = "testuser@%s:*:10042:10047:"\
                          "Test User:/home/%s/testuser:%s"\
                          % (self.ad_domain, self.ad_domain,
                             self.default_shell,
                             )

        assert testuser_stdout in result.stdout_text

    def test_user_without_posix_attributes_not_visible(self):
        """Check that user has AD-defined UID"""

        # Using domain name since it is lowercased realm name for AD domains
        nonposixuser = 'nonposixuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', nonposixuser],
                                         raiseonerr=False)

        # Getent exits with 2 for non-existent user
        assert result.returncode == 2

    def test_override_homedir(self):
        """POSIX attributes should not be overwritten or missing.

        Regression test for bug https://pagure.io/SSSD/sssd/issue/2474

        When there is IPA-AD trust with POSIX attributes,
        including the home directory set in the AD LDAP and in sssd.conf
        subdomain_homedir = %o is added after initgroup call home directory
        should be correct and do not report in logs like,
        'get_subdomain_homedir_of_user failed: * [Home directory is NULL]'
        """
        tasks.backup_file(self.master, paths.SSSD_CONF)
        log_file = '{0}/sssd_{1}.log' .format(paths.VAR_LOG_SSSD_DIR,
                                              self.master.domain.name)

        logsize = len(self.master.get_file_contents(log_file))

        try:
            testuser = 'testuser@%s' % self.ad_domain
            with tasks.remote_sssd_config(self.master) as sssd_conf:
                sssd_conf.edit_domain(self.master.domain,
                                      'subdomain_homedir', '%o')

            tasks.clear_sssd_cache(self.master)
            # The initgroups operation now uses the LDAP connection because
            # the LDAP AD DS server contains the POSIX attributes
            self.master.run_command(['getent', 'initgroups', '-s', 'sss',
                                     testuser])

            result = self.master.run_command(['getent', 'passwd', testuser])
            assert '/home/testuser' in result.stdout_text

            sssd_log2 = self.master.get_file_contents(log_file)[logsize:]

            assert b'get_subdomain_homedir_of_user failed' not in sssd_log2
        finally:
            tasks.restore_files(self.master)
            tasks.clear_sssd_cache(self.master)

    def test_extdom_plugin(self):
        """Extdom plugin should not return error (32)/'No such object'

        Regression test for https://pagure.io/freeipa/issue/8044

        If there is a timeout during a request to SSSD the extdom plugin
        should not return error 'No such object' and the existing user should
        not be added to negative cache on the client.
        """
        extdom_dn = DN(
            ('cn', 'ipa_extdom_extop'), ('cn', 'plugins'),
            ('cn', 'config')
        )

        client = self.clients[0]
        tasks.backup_file(self.master, paths.SSSD_CONF)
        res = self.master.run_command(['pidof', 'sssd_be'])
        pid = res.stdout_text.strip()
        test_id = 'id testuser@%s' % self.ad_domain
        client.run_command(test_id)

        conn = self.master.ldap_connect()
        entry = conn.get_entry(extdom_dn)
        orig_extdom_timeout = entry.single_value.get('ipaextdommaxnsstimeout')

        # set the extdom plugin timeout to 1s (1000)
        entry.single_value['ipaextdommaxnsstimeout'] = 1000
        conn.update_entry(entry)
        self.master.run_command(['ipactl', 'restart'])

        with tasks.remote_sssd_config(self.master) as sssd_conf:
            sssd_conf.edit_domain(self.master.domain, 'timeout', '999999')

        remove_cache = 'sss_cache -E'
        self.master.run_command(remove_cache)
        client.run_command(remove_cache)

        log_file = '{0}/sssd_{1}.log'.format(paths.VAR_LOG_SSSD_DIR,
                                             client.domain.name)
        logsize = len(client.get_file_contents(log_file))

        try:
            # stop sssd_be, needed to simulate a timeout in the extdom plugin.
            self.master.run_command('kill -STOP %s' % pid)
            try:
                client.run_command(test_id)
                error = 'ldap_extended_operation result: No such object(32)'
                sssd_log2 = client.get_file_contents(log_file)[logsize:]
                assert error.encode() not in sssd_log2
            finally:
                self.master.run_command('kill -CONT %s' % pid)
        finally:
            # reconnect and set back to default extdom plugin
            conn = self.master.ldap_connect()
            entry = conn.get_entry(extdom_dn)
            entry.single_value['ipaextdommaxnsstimeout'] = orig_extdom_timeout
            conn.update_entry(entry)
            tasks.restore_files(self.master)
            self.master.run_command(['ipactl', 'restart'])

    def test_remove_posix_trust(self):
        self.remove_trust(self.ad)
        tasks.unconfigure_dns_for_trust(self.master, self.ad)

    # Tests for handling invalid trust types

    def test_invalid_range_types(self):

        invalid_range_types = ['ipa-local',
                               'ipa-ad-winsync',
                               'ipa-ipa-trust',
                               'random-invalid',
                               're@ll%ybad12!']

        tasks.configure_dns_for_trust(self.master, self.ad)
        try:
            for range_type in invalid_range_types:
                tasks.kinit_admin(self.master)

                result = self.master.run_command(
                    ['ipa', 'trust-add', '--type', 'ad', self.ad_domain,
                     '--admin', 'Administrator@' + self.ad_domain,
                     '--range-type', range_type, '--password'],
                    raiseonerr=False,
                    stdin_text=self.master.config.ad_admin_password)

                # The trust-add command is supposed to fail
                assert result.returncode == 1
                assert "ERROR: invalid 'range_type'" in result.stderr_text
        finally:
            tasks.unconfigure_dns_for_trust(self.master, self.ad)

    # Tests for external trust with AD subdomain

    def test_establish_external_subdomain_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_subdomain,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    def test_trustdomains_found_in_external_subdomain_trust(self):
        self.check_trustdomains(
            self.ad_subdomain, [self.ad_subdomain])

    def test_user_gid_uid_resolution_in_external_subdomain_trust(self):
        """Check that user has SID-generated UID"""
        testuser = 'subdomaintestuser@{0}'.format(self.ad_subdomain)
        result = self.master.run_command(['getent', 'passwd', testuser])

        testuser_regex = (r"^subdomaintestuser@{0}:\*:(?!10142)(\d+):"
                          r"(?!10147)(\d+):Subdomaintest User:"
                          r"/home/{1}/subdomaintestuser:{2}$".format(
                              re.escape(self.ad_subdomain),
                              re.escape(self.ad_subdomain),
                              self.default_shell,
                          ))

        assert re.search(testuser_regex, result.stdout_text)

    def test_remove_external_subdomain_trust(self):
        self.remove_trust(self.child_ad)
        tasks.unconfigure_dns_for_trust(self.master, self.ad)

    # Tests for non-external trust with AD subdomain

    def test_establish_nonexternal_subdomain_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        try:
            tasks.kinit_admin(self.master)

            result = self.master.run_command([
                'ipa', 'trust-add', '--type', 'ad', self.ad_subdomain,
                '--admin', 'Administrator@' + self.ad_subdomain,
                '--password', '--range-type', 'ipa-ad-trust'
            ], stdin_text=self.master.config.ad_admin_password,
                raiseonerr=False)

            assert result != 0
            assert ("Domain '{0}' is not a root domain".format(
                self.ad_subdomain) in result.stderr_text)
        finally:
            tasks.unconfigure_dns_for_trust(self.master, self.ad)

    # Tests for external trust with tree domain

    def test_establish_external_treedomain_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad, self.tree_ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_treedomain,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    def test_trustdomains_found_in_external_treedomain_trust(self):
        self.check_trustdomains(
            self.ad_treedomain, [self.ad_treedomain])

    def test_user_gid_uid_resolution_in_external_treedomain_trust(self):
        """Check that user has SID-generated UID"""
        testuser = 'treetestuser@{0}'.format(self.ad_treedomain)
        result = self.master.run_command(['getent', 'passwd', testuser])

        testuser_regex = (r"^treetestuser@{0}:\*:(?!10242)(\d+):"
                          r"(?!10247)(\d+):TreeTest User:"
                          r"/home/{1}/treetestuser:{2}$".format(
                              re.escape(self.ad_treedomain),
                              re.escape(self.ad_treedomain),
                              self.default_shell,
                          ))

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

    def test_ssh_adtreeuser(self):
        testuser = 'treetestuser@{0}'.format(self.ad_treedomain)
        self.master.run_command(["id", testuser])
        tasks.clear_sssd_cache(self.master)
        tasks.kdestroy_all(self.master)
        try:
            tasks.kinit_as_user(self.master, testuser,
                                password="Secret123456"
                                )
            ssh_cmd = "ssh -q -K -l {user} {host} hostname"
            valid_ssh = self.master.run_command(
                ssh_cmd.format(user=testuser, host=self.master.hostname)
            )
            assert self.master.hostname in valid_ssh.stdout_text
        finally:
            tasks.kdestroy_all(self.master)

    def test_remove_external_treedomain_trust(self):
        self.remove_trust(self.tree_ad)
        tasks.unconfigure_dns_for_trust(self.master, self.ad, self.tree_ad)

    # Test for non-external trust with tree domain

    def test_establish_nonexternal_treedomain_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad, self.tree_ad)
        try:
            tasks.kinit_admin(self.master)

            result = self.master.run_command([
                'ipa', 'trust-add', '--type', 'ad', self.ad_treedomain,
                '--admin', 'Administrator@' + self.ad_treedomain,
                '--password', '--range-type', 'ipa-ad-trust'
            ], stdin_text=self.master.config.ad_admin_password,
                raiseonerr=False)

            assert result != 0
            assert ("Domain '{0}' is not a root domain".format(
                self.ad_treedomain) in result.stderr_text)
        finally:
            tasks.unconfigure_dns_for_trust(self.master, self.ad, self.tree_ad)

    # Tests for external trust with root domain

    def test_establish_external_rootdomain_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    def test_trustdomains_found_in_external_rootdomain_trust(self):
        self.check_trustdomains(self.ad_domain, [self.ad_domain])

    def test_remove_external_rootdomain_trust(self):
        self.remove_trust(self.ad)
        tasks.unconfigure_dns_for_trust(self.master, self.ad)

    # Test for one-way forest trust with shared secret

    @skip_in_fips_mode_due_to_issue_8715
    def test_establish_forest_trust_with_shared_secret(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.configure_windows_dns_for_trust(self.ad, self.master)

        # this is a workaround for
        # https://bugzilla.redhat.com/show_bug.cgi?id=1711958
        self.master.run_command(
            ['ipa', 'dnsrecord-add', self.master.domain.name,
             self.srv_gc_record_name,
             '--srv-rec', self.srv_gc_record_value])

        # create windows side of trust using powershell bindings
        # to .Net functions
        ps_cmd = (
            '[System.DirectoryServices.ActiveDirectory.Forest]'
            '::getCurrentForest()'
            '.CreateLocalSideOfTrustRelationship("{}", 1, "{}")'.format(
                self.master.domain.name, self.shared_secret))
        self.ad.run_command(['powershell', '-c', ps_cmd])

        # create ipa side of trust
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain, shared_secret=self.shared_secret)

    @skip_in_fips_mode_due_to_issue_8715
    def test_trustdomains_found_in_forest_trust_with_shared_secret(self):
        result = self.master.run_command(
            ['ipa', 'trust-fetch-domains', self.ad.domain.name],
            raiseonerr=False)
        assert result.returncode == 1
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain, self.ad_subdomain])

    @skip_in_fips_mode_due_to_issue_8715
    def test_user_gid_uid_resolution_in_forest_trust_with_shared_secret(self):
        """Check that user has SID-generated UID"""
        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = r"^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         r"Test User:/home/%s/testuser:%s$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain),
                            self.default_shell,
                            )

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

    @skip_in_fips_mode_due_to_issue_8715
    def test_remove_forest_trust_with_shared_secret(self):
        ps_cmd = (
            '[System.DirectoryServices.ActiveDirectory.Forest]'
            '::getCurrentForest()'
            '.DeleteLocalSideOfTrustRelationship("{}")'.format(
                self.master.domain.name))
        self.ad.run_command(['powershell', '-c', ps_cmd])

        self.remove_trust(self.ad)

        # this is cleanup for workaround for
        # https://bugzilla.redhat.com/show_bug.cgi?id=1711958
        self.master.run_command(
            ['ipa', 'dnsrecord-del', self.master.domain.name,
             self.srv_gc_record_name, '--srv-rec',
             self.srv_gc_record_value])

        tasks.unconfigure_windows_dns_for_trust(self.ad, self.master)
        tasks.unconfigure_dns_for_trust(self.master, self.ad)

    # Test for one-way external trust with shared secret

    @skip_in_fips_mode_due_to_issue_8715
    def test_establish_external_trust_with_shared_secret(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.configure_windows_dns_for_trust(self.ad, self.master)

        # create windows side of trust using netdom.exe utility
        self.ad.run_command(
            ['netdom.exe', 'trust', self.master.domain.name,
             '/d:' + self.ad.domain.name,
             '/passwordt:' + self.shared_secret, '/add', '/oneside:TRUSTED'])

        # create ipa side of trust
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain, shared_secret=self.shared_secret,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    @skip_in_fips_mode_due_to_issue_8715
    def test_trustdomains_found_in_external_trust_with_shared_secret(self):
        result = self.master.run_command(
            ['ipa', 'trust-fetch-domains', self.ad.domain.name],
            raiseonerr=False)
        assert result.returncode == 1
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain])

    @skip_in_fips_mode_due_to_issue_8715
    def test_user_uid_resolution_in_external_trust_with_shared_secret(self):
        """Check that user has SID-generated UID"""
        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = r"^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         r"Test User:/home/%s/testuser:%s$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain),
                            self.default_shell,
                            )

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

    @skip_in_fips_mode_due_to_issue_8715
    def test_remove_external_trust_with_shared_secret(self):
        self.ad.run_command(
            ['netdom.exe', 'trust', self.master.domain.name,
             '/d:' + self.ad.domain.name, '/remove', '/oneside:TRUSTED']
        )
        self.remove_trust(self.ad)
        tasks.unconfigure_windows_dns_for_trust(self.ad, self.master)
        tasks.unconfigure_dns_for_trust(self.master, self.ad)

    def test_server_option_with_unreachable_ad(self):
        """
        Check trust can be established with partially unreachable AD topology

        The SRV records for AD services can point to hosts unreachable for
        ipa master. In this case we must be able to establish trust and
        fetch domains list by using "--server" option.
        This is the regression test for https://pagure.io/freeipa/issue/7895.
        """
        # To simulate Windows Server advertising unreachable hosts in SRV
        # records we create specially crafted zone file for BIND DNS server
        tasks.backup_file(self.master, paths.NAMED_CONF)
        ad_zone = textwrap.dedent('''
            $ORIGIN {ad_dom}.
            $TTL 86400
            @  IN A {ad_ip}
               IN NS {ad_host}.
               IN SOA {ad_host}. hostmaster.{ad_dom}. 39 900 600 86400 3600
            _msdcs IN NS {ad_host}.
            _gc._tcp.Default-First-Site-Name._sites IN SRV 0 100 3268 unreachable.{ad_dom}.
            _kerberos._tcp.Default-First-Site-Name._sites IN SRV 0 100 88 unreachable.{ad_dom}.
            _ldap._tcp.Default-First-Site-Name._sites IN SRV 0 100 389 unreachable.{ad_dom}.
            _gc._tcp IN SRV 0 100 3268 unreachable.{ad_dom}.
            _kerberos._tcp IN SRV 0 100 88 unreachable.{ad_dom}.
            _kpasswd._tcp IN SRV 0 100 464 unreachable.{ad_dom}.
            _ldap._tcp IN SRV 0 100 389 unreachable.{ad_dom}.
            _kerberos._udp IN SRV 0 100 88 unreachable.{ad_dom}.
            _kpasswd._udp IN SRV 0 100 464 unreachable.{ad_dom}.
            {ad_short} IN A {ad_ip}
            unreachable IN A {unreachable}
            DomainDnsZones IN A {ad_ip}
            _ldap._tcp.Default-First-Site-Name._sites.DomainDnsZones IN SRV 0 100 389 unreachable.{ad_dom}.
            _ldap._tcp.DomainDnsZones IN SRV 0 100 389 unreachable.{ad_dom}.
            ForestDnsZones IN A {ad_ip}
            _ldap._tcp.Default-First-Site-Name._sites.ForestDnsZones IN SRV 0 100 389 unreachable.{ad_dom}.
            _ldap._tcp.ForestDnsZones IN SRV 0 100 389 unreachable.{ad_dom}.
        '''.format(  # noqa: E501
            ad_ip=self.ad.ip, unreachable='192.168.254.254',
            ad_host=self.ad.hostname, ad_dom=self.ad.domain.name,
            ad_short=self.ad.shortname))
        ad_zone_file = tasks.create_temp_file(self.master, directory='/etc')
        self.master.put_file_contents(ad_zone_file, ad_zone)
        self.master.run_command(
            ['chmod', '--reference', paths.NAMED_CONF, ad_zone_file])
        self.master.run_command(
            ['chown', '--reference', paths.NAMED_CONF, ad_zone_file])
        named_conf = self.master.get_file_contents(paths.NAMED_CONF,
                                                   encoding='utf-8')
        named_conf += textwrap.dedent(f'''
            zone "{self.ad.domain.name}" {{
                type master;
                file "{ad_zone_file}";
            }};
        ''')
        self.master.put_file_contents(paths.NAMED_CONF, named_conf)
        tasks.restart_named(self.master)
        try:
            # Check that trust can not be established without --server option
            # This checks that our setup is correct
            result = self.master.run_command(
                ['ipa', 'trust-add', self.ad_domain,
                 '--admin', 'Administrator@' + self.ad_domain, '--password'],
                raiseonerr=False,
                stdin_text=self.master.config.ad_admin_password)
            assert result.returncode == 1
            assert 'Unable to read domain information' in result.stderr_text
            httpd_error_log = self.master.get_file_contents(
                paths.VAR_LOG_HTTPD_ERROR,
                encoding='utf-8'
            )
            assert 'CIFS server communication error: code "3221225653", ' \
                   'message "{Device Timeout}' in httpd_error_log

            # Check that trust is successfully established with --server option
            tasks.establish_trust_with_ad(
                self.master, self.ad_domain,
                extra_args=['--server', self.ad.hostname])

            # Check domains can not be fetched without --server option
            # This checks that our setup is correct
            result = self.master.run_command(
                ['ipa', 'trust-fetch-domains', self.ad.domain.name],
                raiseonerr=False)
            assert result.returncode == 1
            assert ('Fetching domains from trusted forest failed'
                    in result.stderr_text)

            # Check that domains can be fetched with --server option
            result = self.master.run_command(
                ['ipa', 'trust-fetch-domains', self.ad.domain.name,
                 '--server', self.ad.hostname],
                raiseonerr=False)
            assert result.returncode == 1
            assert ('List of trust domains successfully refreshed'
                    in result.stdout_text)
        finally:
            tasks.restore_files(self.master)
            tasks.restart_named(self.master)
            tasks.clear_sssd_cache(self.master)
            self.master.run_command(['rm', '-f', ad_zone_file])
            tasks.configure_dns_for_trust(self.master, self.ad)
            self.remove_trust(self.ad)


class TestNonPosixAutoPrivateGroup(BaseTestTrust):
    """
    Tests for auto-private-groups option with non posix AD trust
    Related : https://pagure.io/freeipa/issue/8807
    """
    topology = 'line'
    num_ad_domains = 1
    num_clients = 1
    num_ad_subdomains = 0
    num_ad_treedomains = 0
    uid_override = "99999999"
    gid_override = "78878787"

    def test_add_nonposix_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])

    @pytest.mark.parametrize('type', ['hybrid', 'true', "false"])
    def test_auto_private_groups_default_trusted_range(self, type):
        """
        Modify existing range for default trusted AD domain range
        with auto-private-groups set as true/hybrid/false and test
        user with no posix attributes.
        """
        self.mod_idrange_auto_private_group(type)
        nonposixuser = "nonposixuser@%s" % self.ad_domain
        (uid, gid) = self.get_user_id(self.clients[0], nonposixuser)
        if type == "true":
            assert uid == gid
        else:
            test_group = self.clients[0].run_command(["id", nonposixuser])
            gid_str = "gid={0}(domain users@{1})".format(gid, self.ad_domain)
            grp_str = "groups={0}(domain users@{1})".format(gid,
                                                            self.ad_domain)
            assert gid_str in test_group.stdout_text
            assert grp_str in test_group.stdout_text
            assert uid != gid

    @pytest.mark.parametrize('type', ['hybrid', 'true', "false"])
    def test_idoverride_with_auto_private_group(self, type):
        """
        Override ad trusted user in default trust view
        and set auto-private-groups=[hybrid,true,false]
        and ensure that overridden values takes effect.
        """
        nonposixuser = "nonposixuser@%s" % self.ad_domain
        with self.set_idoverrideuser(nonposixuser,
                                     self.uid_override,
                                     self.gid_override
                                     ):
            self.mod_idrange_auto_private_group(type)
            sssd_version = tasks.get_sssd_version(self.clients[0])
            bad_version = (tasks.parse_version("2.8.2") <= sssd_version
                           < tasks.parse_version("2.9.4"))
            cond = (type == 'hybrid') and bad_version
            with xfail_context(condition=cond,
                               reason="https://pagure.io/freeipa/issue/9295"):
                (uid, gid) = self.get_user_id(self.clients[0], nonposixuser)
                assert (uid == self.uid_override and gid == self.gid_override)
            test_group = self.clients[0].run_command(
                ["id", nonposixuser]).stdout_text
            cond2 = ((type == 'false'
                      and sssd_version >= tasks.parse_version("2.9.4"))
                     or type == 'hybrid')
            with xfail_context(cond2,
                               'https://github.com/SSSD/sssd/issues/5989 '
                               'and 7169'):
                assert "domain users@{0}".format(self.ad_domain) in test_group

    @pytest.mark.parametrize('type', ['hybrid', 'true', "false"])
    def test_nonposixuser_nondefault_primary_group(self, type):
        """
        Test for non default primary group.
        For hybrid/false gid corresponds to the group testgroup1.
        """
        nonposixuser1 = "nonposixuser1@%s" % self.ad_domain
        self.mod_idrange_auto_private_group(type)
        (uid, gid) = self.get_user_id(self.clients[0], nonposixuser1)
        if type == "true":
            assert uid == gid
        else:
            test_group = self.clients[0].run_command(["id", nonposixuser1])
            gid_str = "gid={0}(testgroup1@{1})".format(gid, self.ad_domain)
            group = "groups={0}(testgroup1@{1})".format(gid, self.ad_domain)
            assert (gid_str in test_group.stdout_text
                    and group in test_group.stdout_text)


class TestPosixAutoPrivateGroup(BaseTestTrust):
    """
    Tests for auto-private-groups option with posix AD trust
    Related : https://pagure.io/freeipa/issue/8807
    """
    topology = 'line'
    num_ad_domains = 1
    num_clients = 1
    num_ad_subdomains = 0
    num_ad_treedomains = 0
    uid_override = "99999999"
    gid_override = "78878787"

    def test_add_posix_trust(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust-posix'])

    @pytest.mark.parametrize('type', ['hybrid', 'true', "false"])
    def test_gidnumber_not_corresponding_existing_group(self, type):
        """
        Test checks that sssd can resolve AD users which
        contain posix attributes (uidNumber and gidNumber)
        but there is no group with the corresponding gidNumber.
        """
        posixuser = "testuser2@%s" % self.ad_domain
        self.mod_idrange_auto_private_group(type)
        if type != "true":
            result = self.clients[0].run_command(['id', posixuser],
                                                 raiseonerr=False)
            tasks.assert_error(result, "no such user")
        else:
            # sssd_version = tasks.get_sssd_version(self.clients[0])
            with xfail_context(True,
                               'https://github.com/SSSD/sssd/issues/5988'):
                (uid, gid) = self.get_user_id(self.clients[0], posixuser)
                assert uid == gid
                assert uid == '10060'

    @pytest.mark.parametrize('type', ['hybrid', 'true', "false"])
    def test_only_uid_number_auto_private_group_default(self, type):
        """
        Test checks that posix user with only uidNumber defined
        and gidNumber not set, auto-private-group
        is set to false/true/hybrid
        """
        posixuser = "testuser1@%s" % self.ad_domain
        self.mod_idrange_auto_private_group(type)
        if type == "true":
            sssd_version = tasks.get_sssd_version(self.clients[0])
            bad_version = (tasks.parse_version("2.8.2") <= sssd_version
                           < tasks.parse_version("2.9.4"))
            with xfail_context(bad_version,
                 "https://pagure.io/freeipa/issue/9295"):
                (uid, gid) = self.get_user_id(self.clients[0], posixuser)
                assert uid == gid
        else:
            for host in [self.master, self.clients[0]]:
                result = host.run_command(['id', posixuser], raiseonerr=False)
                tasks.assert_error(result, "no such user")

    @pytest.mark.parametrize('type', ['hybrid', 'true', "false"])
    def test_auto_private_group_primary_group(self, type):
        """
        Test checks that AD users which contain posix attributes
        (uidNumber and gidNumber) and there is primary group
        with gid number defined.
        """
        posixuser = "testuser@%s" % self.ad_domain
        self.mod_idrange_auto_private_group(type)
        (uid, gid) = self.get_user_id(self.clients[0], posixuser)
        test_grp = self.clients[0].run_command(["id", posixuser])
        assert uid == '10042'
        if type == "true":
            assert uid == gid
            groups = "groups=10042(testuser@{0}),10047(testgroup@{1})".format(
                self.ad_domain, self.ad_domain)
            assert groups in test_grp.stdout_text
        else:
            assert gid == '10047'
            groups = "10047(testgroup@{0})".format(self.ad_domain)
            assert groups in test_grp.stdout_text

    @pytest.mark.parametrize('type', ['hybrid', 'true', "false"])
    def test_idoverride_with_auto_private_group(self, type):
        """
        Override ad trusted user in default trust view
        and set auto-private-groups=[hybrid,true,false]
        and ensure that overridden values takes effect.
        """
        posixuser = "testuser@%s" % self.ad_domain
        with self.set_idoverrideuser(posixuser,
                                     self.uid_override,
                                     self.gid_override):
            self.mod_idrange_auto_private_group(type)
            (uid, gid) = self.get_user_id(self.clients[0], posixuser)
            assert(uid == self.uid_override
                   and gid == self.gid_override)
            result = self.clients[0].run_command(['id', posixuser])
            sssd_version = tasks.get_sssd_version(self.clients[0])
            bad_version = sssd_version >= tasks.parse_version("2.9.4")
            with xfail_context(bad_version and type in ('false', 'hybrid'),
                 "https://github.com/SSSD/sssd/issues/7169"):
                assert "10047(testgroup@{0})".format(
                    self.ad_domain) in result.stdout_text
