# Copyright (C) 2019  FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import unittest
import textwrap

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipapython.dn import DN


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

    @classmethod
    def install(cls, mh):
        if not cls.master.transport.file_exists('/usr/bin/rpcclient'):
            raise unittest.SkipTest("Package samba-client not available "
                                    "on {}".format(cls.master.hostname))
        super(BaseTestTrust, cls).install(mh)
        cls.ad = cls.ads[0]  # pylint: disable=no-member
        cls.ad_domain = cls.ad.domain.name
        tasks.install_adtrust(cls.master)
        cls.check_sid_generation()
        tasks.sync_time(cls.master, cls.ad)

        cls.child_ad = cls.ad_subdomains[0]  # pylint: disable=no-member
        cls.ad_subdomain = cls.child_ad.domain.name
        cls.tree_ad = cls.ad_treedomains[0]  # pylint: disable=no-member
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

    def remove_trust(self, ad):
        tasks.remove_trust_with_ad(self.master, ad.domain.name)
        tasks.clear_sssd_cache(self.master)

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
                         r"Test User:/home/%s/testuser:/bin/sh$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain))

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

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
            r"^{}@{}:\*:(\d+):(\d+):{}:/home/{}/{}:/bin/sh$".format(
                self.upn_username, self.ad_domain, self.upn_name,
                self.ad_domain, self.upn_username)
        )
        assert re.search(upnuser_regex, result.stdout_text), result.stdout_text

    def test_upn_user_authentication_in_nonposix_trust(self):
        """ Check that AD user with UPN can authenticate in IPA """
        self.master.run_command(['kinit', '-C', '-E', self.upn_principal],
                                stdin_text=self.upn_password)

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
                          "Test User:/home/%s/testuser:/bin/sh"\
                          % (self.ad_domain, self.ad_domain)

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
            domain = self.master.domain
            tasks.modify_sssd_conf(
                self.master,
                domain.name,
                {
                    'subdomain_homedir': '%o'
                }
            )

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
        log_file = '{0}/sssd_{1}.log'.format(paths.VAR_LOG_SSSD_DIR,
                                             client.domain.name)
        logsize = len(client.get_file_contents(log_file))
        res = self.master.run_command(['pidof', 'sssd_be'])
        pid = res.stdout_text.strip()
        test_id = 'id testuser@%s' % self.ad_domain
        client.run_command(test_id)

        conn = self.master.ldap_connect()
        entry = conn.get_entry(extdom_dn)  # pylint: disable=no-member
        orig_extdom_timeout = entry.single_value.get('ipaextdommaxnsstimeout')

        # set the extdom plugin timeout to 1s (1000)
        entry.single_value['ipaextdommaxnsstimeout'] = 1000
        conn.update_entry(entry)  # pylint: disable=no-member
        self.master.run_command(['ipactl', 'restart'])

        domain = self.master.domain
        tasks.modify_sssd_conf(
            self.master,
            domain.name,
            {
                'timeout': '999999'
            }
        )
        remove_cache = 'sss_cache -E'
        self.master.run_command(remove_cache)
        client.run_command(remove_cache)

        try:
            # stop sssd_be, needed to simulate a timeout in the extdom plugin.
            stop_sssdbe = self.master.run_command('kill -STOP %s' % pid)
            client.run_command(test_id)
            error = 'ldap_extended_operation result: No such object(32)'
            sssd_log2 = client.get_file_contents(log_file)[logsize:]
            assert error.encode() not in sssd_log2
        finally:
            if stop_sssdbe.returncode == 0:
                self.master.run_command('kill -CONT %s' % pid)
            # reconnect and set back to default extdom plugin
            conn = self.master.ldap_connect()
            entry = conn.get_entry(extdom_dn)  # pylint: disable=no-member
            entry.single_value['ipaextdommaxnsstimeout'] = orig_extdom_timeout
            conn.update_entry(entry)  # pylint: disable=no-member
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
                     '--admin', 'Administrator',
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
                          r"/home/{1}/subdomaintestuser:/bin/sh$".format(
                              re.escape(self.ad_subdomain),
                              re.escape(self.ad_subdomain)))

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
                '--admin',
                'Administrator', '--password', '--range-type', 'ipa-ad-trust'
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
                          r"/home/{1}/treetestuser:/bin/sh$".format(
                              re.escape(self.ad_treedomain),
                              re.escape(self.ad_treedomain)))

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

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
                '--admin',
                'Administrator', '--password', '--range-type', 'ipa-ad-trust'
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

    def test_trustdomains_found_in_forest_trust_with_shared_secret(self):
        result = self.master.run_command(
            ['ipa', 'trust-fetch-domains', self.ad.domain.name],
            raiseonerr=False)
        assert result.returncode == 1
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain, self.ad_subdomain])

    def test_user_gid_uid_resolution_in_forest_trust_with_shared_secret(self):
        """Check that user has SID-generated UID"""
        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = r"^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         r"Test User:/home/%s/testuser:/bin/sh$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain))

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

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

    def test_trustdomains_found_in_external_trust_with_shared_secret(self):
        result = self.master.run_command(
            ['ipa', 'trust-fetch-domains', self.ad.domain.name],
            raiseonerr=False)
        assert result.returncode == 1
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain])

    def test_user_uid_resolution_in_external_trust_with_shared_secret(self):
        """Check that user has SID-generated UID"""
        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = r"^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         r"Test User:/home/%s/testuser:/bin/sh$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain))

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

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
        named_conf += textwrap.dedent('''
            zone "ad.test" {{
                type master;
                file "{}";
            }};
        '''.format(ad_zone_file))
        self.master.put_file_contents(paths.NAMED_CONF, named_conf)
        tasks.restart_named(self.master)
        try:
            # Check that trust can not be established without --server option
            # This checks that our setup is correct
            result = self.master.run_command(
                ['ipa', 'trust-add', self.ad.domain.name,
                 '--admin', 'Administrator', '--password'], raiseonerr=False)
            assert result.returncode == 1
            assert 'CIFS server communication error: code "3221225653", ' \
                   'message "{Device Timeout}' in result.stderr_text

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
            self.remove_trust(self.ad)
            tasks.restore_files(self.master)
            self.master.run_command(['rm', '-f', ad_zone_file])
            tasks.restart_named(self.master)
