# Authors:
#   Tomas Babej <tbabej@redhat.com>
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

from __future__ import absolute_import

import nose
import re

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths


class ADTrustBase(IntegrationTest):
    """Provides common checks for the AD trust integration testing."""

    topology = 'line'
    num_ad_domains = 1
    num_ad_subdomains = 1
    num_ad_treedomains = 1

    @classmethod
    def install(cls, mh):
        if not cls.master.transport.file_exists('/usr/bin/rpcclient'):
            raise nose.SkipTest("Package samba-client not available "
                                "on {}".format(cls.master.hostname))
        super(ADTrustBase, cls).install(mh)
        cls.ad = cls.ads[0]
        cls.ad_domain = cls.ad.domain.name
        cls.install_adtrust()
        cls.check_sid_generation()

        cls.child_ad = cls.ad_subdomains[0]
        cls.ad_subdomain = cls.child_ad.domain.name
        cls.tree_ad = cls.ad_treedomains[0]
        cls.ad_treedomain = cls.tree_ad.domain.name

        cls.configure_dns_and_time()

    @classmethod
    def install_adtrust(cls):
        """Test adtrust support installation"""

        tasks.install_adtrust(cls.master)

    @classmethod
    def check_sid_generation(cls):
        """Test SID generation"""

        command = ['ipa', 'user-show', 'admin', '--all', '--raw']

        # TODO: remove duplicate definition and import from common module
        _sid_identifier_authority = '(0x[0-9a-f]{1,12}|[0-9]{1,10})'
        sid_regex = 'S-1-5-21-%(idauth)s-%(idauth)s-%(idauth)s'\
                    % dict(idauth=_sid_identifier_authority)
        stdout_re = re.escape('  ipaNTSecurityIdentifier: ') + sid_regex

        tasks.run_repeatedly(cls.master, command,
                             test=lambda x: re.search(stdout_re, x))

    @classmethod
    def configure_dns_and_time(cls):
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.sync_time(cls.master, cls.ad)

    def test_establish_trust(self):
        """Tests establishing trust with Active Directory"""

        tasks.establish_trust_with_ad(self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])

    def test_all_trustdomains_found(self):
        """
        Tests that all trustdomains can be found.
        """
        result = self.master.run_command(['ipa',
                                          'trustdomain-find',
                                          self.ad_domain])

        # Check that all trustdomains appear in the result
        assert self.ad_domain in result.stdout_text
        assert self.ad_subdomain in result.stdout_text
        assert "Number of entries returned 2" in result.stdout_text


class ADTrustSubdomainBase(ADTrustBase):
    """
    Base class for tests involving subdomains of trusted forests
    """

    @classmethod
    def configure_dns_and_time(cls):
        tasks.configure_dns_for_trust(cls.master, cls.child_ad)
        tasks.sync_time(cls.master, cls.child_ad)


class ADTrustTreedomainBase(ADTrustBase):
    """
    Base class for tests involving tree root domains of trusted forests
    """

    @classmethod
    def configure_dns_and_time(cls):
        tasks.configure_dns_for_trust(cls.master, cls.tree_ad)
        tasks.sync_time(cls.master, cls.tree_ad)


class TestBasicADTrust(ADTrustBase):
    """Basic Integration test for Active Directory"""

    def test_range_properties_in_nonposix_trust(self):
        """Check the properties of the created range"""

        range_name = self.ad_domain.upper() + '_id_range'
        result = self.master.run_command(['ipa', 'idrange-show', range_name,
                                          '--all', '--raw'])

        iparangetype_regex = r'ipaRangeType: ipa-ad-trust'
        iparangesize_regex = r'ipaIDRangeSize: 200000'

        assert re.search(iparangetype_regex, result.stdout_text, re.IGNORECASE)
        assert re.search(iparangesize_regex, result.stdout_text, re.IGNORECASE)

    def test_user_gid_uid_resolution_in_nonposix_trust(self):
        """Check that user has SID-generated UID"""

        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = "^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         "Test User:/home/%s/testuser:/bin/sh$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain))

        assert re.search(testuser_regex, result.stdout_text)

    def test_ipauser_authentication(self):
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
        self.master.run_command(
            ['kinit', '-E', '{0}@{1}'.format(ipauser,
                                             self.master.domain.name)],
            stdin_text=new_passwd)

    def test_remove_nonposix_trust(self):
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.clear_sssd_cache(self.master)


class TestPosixADTrust(ADTrustBase):
    """Integration test for Active Directory with POSIX support"""

    def test_establish_trust(self):
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust-posix']
        )

    def test_range_properties_in_posix_trust(self):
        # Check the properties of the created range

        range_name = self.ad_domain.upper() + '_id_range'

        result = self.master.run_command(['ipa', 'idrange-show', range_name,
                                          '--all', '--raw'])

        # Check the range type and size
        iparangetype_regex = r'ipaRangeType: ipa-ad-trust-posix'
        iparangesize_regex = r'ipaIDRangeSize: 200000'

        assert re.search(iparangetype_regex, result.stdout_text, re.IGNORECASE)
        assert re.search(iparangesize_regex, result.stdout_text, re.IGNORECASE)

    def test_user_uid_gid_resolution_in_posix_trust(self):
        # Check that user has AD-defined UID

        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        testuser_stdout = "testuser@%s:*:10042:10047:"\
                          "Test User:/home/%s/testuser:/bin/sh"\
                          % (self.ad_domain, self.ad_domain)

        assert testuser_stdout in result.stdout_text

    def test_user_without_posix_attributes_not_visible(self):
        # Check that user has AD-defined UID

        # Using domain name since it is lowercased realm name for AD domains
        nonposixuser = 'nonposixuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', nonposixuser],
                                         raiseonerr=False)

        # Getent exits with 2 for non-existent user
        assert result.returncode == 2

    def test_remove_trust_with_posix_attributes(self):
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.clear_sssd_cache(self.master)


class TestEnforcedPosixADTrust(TestPosixADTrust):
    """
    This test is intented to copycat PosixADTrust, since enforcing the POSIX
    trust type should not make a difference.
    """
    """Re-difene method from test_establish_trust_with_posix_attributes
    to test_establish_trust. win server 2016 no more have support for MFU/NIS,
    so autodetection doesn't work"""

    def test_establish_trust(self):
        tasks.establish_trust_with_ad(self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust-posix'])


class TestInvalidRangeTypes(ADTrustBase):
    """
    Tests invalid values being put into trust-add command.
    """

    def test_invalid_range_types(self):

        invalid_range_types = ['ipa-local',
                               'ipa-ad-winsync',
                               'ipa-ipa-trust',
                               'random-invalid',
                               're@ll%ybad12!']

        for range_type in invalid_range_types:
            tasks.kinit_admin(self.master)

            result = self.master.run_command(
                ['ipa', 'trust-add', '--type', 'ad', self.ad_domain, '--admin',
                 'Administrator', '--range-type', range_type, '--password'],
                raiseonerr=False,
                stdin_text=self.master.config.ad_admin_password)

            # The trust-add command is supposed to fail
            assert result.returncode == 1


class TestExternalTrustWithSubdomain(ADTrustSubdomainBase):
    """
    Test establishing external trust with subdomain
    """

    def test_establish_trust(self):
        """ Tests establishing external trust with Active Directory """
        tasks.establish_trust_with_ad(
            self.master, self.ad_subdomain,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    def test_all_trustdomains_found(self):
        """ Test that only one trustdomain is found """
        result = self.master.run_command(['ipa', 'trustdomain-find',
                                          self.ad_subdomain])

        assert self.ad_subdomain in result.stdout_text
        assert "Number of entries returned 1" in result.stdout_text

    def test_user_gid_uid_resolution_in_nonposix_trust(self):
        """ Check that user has SID-generated UID """
        testuser = 'subdomaintestuser@{0}'.format(self.ad_subdomain)
        result = self.master.run_command(['getent', 'passwd', testuser])

        testuser_regex = ("^subdomaintestuser@{0}:\*:(?!10142)(\d+):"
                          "(?!10147)(\d+):Subdomaintest User:"
                          "/home/{1}/subdomaintestuser:/bin/sh$".format(
                              re.escape(self.ad_subdomain),
                              re.escape(self.ad_subdomain)))

        assert re.search(testuser_regex, result.stdout_text)

    def test_remove_nonposix_trust(self):
        tasks.remove_trust_with_ad(self.master, self.ad_subdomain)
        tasks.clear_sssd_cache(self.master)


class TestNonexternalTrustWithSubdomain(ADTrustSubdomainBase):
    """
    Tests that a non-external trust to a subdomain cannot be established
    """
    def test_establish_trust(self):
        """ Tests establishing non-external trust with Active Directory """
        self.master.run_command(['kinit', '-kt', paths.HTTP_KEYTAB,
                                 'HTTP/%s' % self.master.hostname])
        self.master.run_command(['systemctl', 'restart', 'krb5kdc.service'])
        self.master.run_command(['kdestroy', '-A'])

        tasks.kinit_admin(self.master)
        self.master.run_command(['klist'])
        self.master.run_command(['smbcontrol', 'all', 'debug', '100'])

        result = self.master.run_command([
            'ipa', 'trust-add', '--type', 'ad', self.ad_subdomain, '--admin',
            'Administrator', '--password', '--range-type', 'ipa-ad-trust'
            ], stdin_text=self.master.config.ad_admin_password,
            raiseonerr=False)

        assert result != 0
        assert ("Domain '{0}' is not a root domain".format(
            self.ad_subdomain) in result.stderr_text)

    def test_all_trustdomains_found(self):
        raise nose.SkipTest(
            'Test case unapplicable, present for inheritance reason only')


class TestExternalTrustWithTreedomain(ADTrustTreedomainBase):
    """
    Test establishing external trust with tree root domain
    """

    def test_establish_trust(self):
        """ Tests establishing external trust with Active Directory """
        tasks.establish_trust_with_ad(
            self.master, self.ad_treedomain,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    def test_all_trustdomains_found(self):
        """ Test that only one trustdomain is found """
        result = self.master.run_command(['ipa', 'trustdomain-find',
                                          self.ad_treedomain])

        assert self.ad_treedomain in result.stdout_text
        assert "Number of entries returned 1" in result.stdout_text

    def test_user_gid_uid_resolution_in_nonposix_trust(self):
        """ Check that user has SID-generated UID """
        testuser = 'treetestuser@{0}'.format(self.ad_treedomain)
        result = self.master.run_command(['getent', 'passwd', testuser])

        testuser_regex = ("^treetestuser@{0}:\*:(?!10242)(\d+):"
                          "(?!10247)(\d+):TreeTest User:"
                          "/home/{1}/treetestuser:/bin/sh$".format(
                              re.escape(self.ad_treedomain),
                              re.escape(self.ad_treedomain)))

        assert re.search(testuser_regex, result.stdout_text)

    def test_remove_nonposix_trust(self):
        tasks.remove_trust_with_ad(self.master, self.ad_treedomain)
        tasks.clear_sssd_cache(self.master)


class TestNonexternalTrustWithTreedomain(ADTrustTreedomainBase):
    """
    Tests that a non-external trust to a tree root domain cannot be established
    """
    def test_establish_trust(self):
        """ Tests establishing non-external trust with Active Directory """
        self.master.run_command(['kinit', '-kt', paths.HTTP_KEYTAB,
                                 'HTTP/%s' % self.master.hostname])
        self.master.run_command(['systemctl', 'restart', 'krb5kdc.service'])
        self.master.run_command(['kdestroy', '-A'])

        tasks.kinit_admin(self.master)
        self.master.run_command(['klist'])
        self.master.run_command(['smbcontrol', 'all', 'debug', '100'])

        result = self.master.run_command([
            'ipa', 'trust-add', '--type', 'ad', self.ad_treedomain, '--admin',
            'Administrator', '--password', '--range-type', 'ipa-ad-trust'
            ], stdin_text=self.master.config.ad_admin_password,
            raiseonerr=False)

        assert result != 0
        assert ("Domain '{0}' is not a root domain".format(
            self.ad_treedomain) in result.stderr_text)

    def test_all_trustdomains_found(self):
        raise nose.SkipTest(
            'Test case unapplicable, present for inheritance reason only')


class TestExternalTrustWithRootDomain(ADTrustBase):
    """
    Test establishing external trust with root domain
    Main purpose of this test is to verify that subdomains are not
    associated with the external trust, hence all tests are skipped
    if no subdomain is specified.
    """

    def test_establish_trust(self):
        """ Tests establishing external trust with Active Directory """
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    def test_all_trustdomains_found(self):
        """ Test that only one trustdomain is found """
        result = self.master.run_command(['ipa', 'trustdomain-find',
                                          self.ad_domain])

        assert self.ad_domain in result.stdout_text
        assert "Number of entries returned 1" in result.stdout_text

    def test_remove_nonposix_trust(self):
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.clear_sssd_cache(self.master)


class TestTrustWithUPN(ADTrustBase):
    """
    Test support of UPN for trusted domains
    """

    upn_suffix = 'UPNsuffix.com'
    upn_username = 'upnuser'
    upn_name = 'UPN User'
    upn_principal = '{}@{}'.format(upn_username, upn_suffix)
    upn_password = 'Secret123456'

    def test_upn_in_nonposix_trust(self):
        """ Check that UPN is listed as trust attribute """
        result = self.master.run_command(['ipa', 'trust-show', self.ad_domain,
                                          '--all', '--raw'])

        assert ("ipantadditionalsuffixes: {}".format(self.upn_suffix) in
                result.stdout_text)

    def test_upn_user_resolution_in_nonposix_trust(self):
        """ Check that user with UPN can be resolved """
        result = self.master.run_command(['getent', 'passwd',
                                          self.upn_principal])

        # result will contain AD domain, not UPN
        upnuser_regex = "^{}@{}:\*:(\d+):(\d+):{}:/home/{}/{}:/bin/sh$".format(
            self.upn_username, self.ad_domain, self.upn_name,
            self.ad_domain, self.upn_username)
        assert re.search(upnuser_regex, result.stdout_text)

    def test_upn_user_authentication(self):
        """ Check that AD user with UPN can authenticate in IPA """
        self.master.run_command(['kinit', '-C', '-E', self.upn_principal],
                                stdin_text=self.upn_password)

    def test_remove_nonposix_trust(self):
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.clear_sssd_cache(self.master)
