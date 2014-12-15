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

import nose
import re

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration import tasks
from ipatests.test_integration import util


class ADTrustBase(IntegrationTest):
    """Provides common checks for the AD trust integration testing."""

    topology = 'line'
    num_ad_domains = 1
    optional_extra_roles = ['ad_subdomain']

    @classmethod
    def install(cls, mh):
        super(ADTrustBase, cls).install(mh)
        cls.ad = cls.ad_domains[0].ads[0]
        cls.install_adtrust()
        cls.check_sid_generation()
        cls.configure_dns_and_time()

        # Determine whether the subdomain AD is available
        try:
            child_ad = cls.host_by_role(cls.optional_extra_roles[0])
            cls.ad_subdomain = '.'.join(
                                   child_ad.hostname.split('.')[1:])
        except LookupError:
            cls.ad_subdomain = None

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

        util.run_repeatedly(cls.master, command,
                            test=lambda x: re.search(stdout_re, x))

    @classmethod
    def configure_dns_and_time(cls):
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.sync_time(cls.master, cls.ad)

    def test_establish_trust(self):
        """Tests establishing trust with Active Directory"""

        tasks.establish_trust_with_ad(self.master, self.ad,
            extra_args=['--range-type', 'ipa-ad-trust'])

    def test_all_trustdomains_found(self):
        """
        Tests that all trustdomains can be found.
        """

        if self.ad_subdomain is None:
            raise nose.SkipTest('AD subdomain is not available.')

        result = self.master.run_command(['ipa',
                                          'trustdomain-find',
                                           self.ad.domain.name])

        # Check that both trustdomains appear in the result
        assert self.ad.domain.name in result.stdout_text
        assert self.ad_subdomain in result.stdout_text


class TestBasicADTrust(ADTrustBase):
    """Basic Integration test for Active Directory"""

    def test_range_properties_in_nonposix_trust(self):
        """Check the properties of the created range"""

        range_name = self.ad.domain.name.upper() + '_id_range'
        result = self.master.run_command(['ipa', 'idrange-show', range_name,
                                          '--all', '--raw'])

        iparangetype_regex = r'ipaRangeType: ipa-ad-trust'
        iparangesize_regex = r'ipaIDRangeSize: 200000'

        assert re.search(iparangetype_regex, result.stdout_text, re.IGNORECASE)
        assert re.search(iparangesize_regex, result.stdout_text, re.IGNORECASE)

    def test_user_gid_uid_resolution_in_nonposix_trust(self):
        """Check that user has SID-generated UID"""

        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad.domain.name
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = "^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         "Test User:/home/%s/testuser:/bin/sh$"\
                         % (re.escape(self.ad.domain.name),
                            re.escape(self.ad.domain.name))

        assert re.search(testuser_regex, result.stdout_text)

    def test_remove_nonposix_trust(self):
        tasks.remove_trust_with_ad(self.master, self.ad)
        tasks.clear_sssd_cache(self.master)


class TestPosixADTrust(ADTrustBase):
    """Integration test for Active Directory with POSIX support"""

    def test_establish_trust(self):
        # Not specifying the --range-type directly, it should be detected
        tasks.establish_trust_with_ad(self.master, self.ad)

    def test_range_properties_in_posix_trust(self):
        # Check the properties of the created range

        range_name = self.ad.domain.name.upper() + '_id_range'

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
        testuser = 'testuser@%s' % self.ad.domain.name
        result = self.master.run_command(['getent', 'passwd', testuser])

        testuser_stdout = "testuser@%s:*:10042:10047:"\
                          "Test User:/home/%s/testuser:/bin/sh"\
                          % (self.ad.domain.name,
                             self.ad.domain.name)

        assert testuser_stdout in result.stdout_text

    def test_user_without_posix_attributes_not_visible(self):
        # Check that user has AD-defined UID

        # Using domain name since it is lowercased realm name for AD domains
        nonposixuser = 'nonposixuser@%s' % self.ad.domain.name
        result = self.master.run_command(['getent', 'passwd', nonposixuser],
                                         raiseonerr=False)

        # Getent exits with 2 for non-existent user
        assert result.returncode == 2

    def test_remove_trust_with_posix_attributes(self):
        tasks.remove_trust_with_ad(self.master, self.ad)
        tasks.clear_sssd_cache(self.master)


class TestEnforcedPosixADTrust(TestPosixADTrust):
    """
    This test is intented to copycat PosixADTrust, since enforcing the POSIX
    trust type should not make a difference.
    """

    def test_establish_trust_with_posix_attributes(self):
        tasks.establish_trust_with_ad(self.master, self.ad,
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
                               ['ipa', 'trust-add',
                               '--type', 'ad', self.ad.domain.name,
                               '--admin', 'Administrator',
                               '--range-type', range_type,
                               '--password'],
                               raiseonerr=False,
                               stdin_text=self.master.config.ad_admin_password)

            # The trust-add command is supposed to fail
            assert result.returncode == 1
