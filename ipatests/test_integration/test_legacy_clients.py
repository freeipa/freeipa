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

# FIXME: Pylint errors
# pylint: disable=no-member

from __future__ import absolute_import

import os
import re
import unittest

from ipaplatform.paths import paths

from ipatests.pytest_ipa.integration import tasks

# importing test_trust under different name to avoid nose executing the test
# base class imported from this module
from ipatests.test_integration import test_trust as trust_tests


class BaseTestLegacyClient:
    """
    Tests legacy client support.
    """

    advice_id = None
    backup_files = ['/etc/sysconfig/authconfig',
                    '/etc/pam.d',
                    '/etc/openldap/cacerts',
                    '/etc/openldap/ldap.conf',
                    '/etc/nsswitch.conf',
                    paths.SSSD_CONF]

    homedir_template = "/home/{domain}/{username}"
    required_extra_roles = ()
    optional_extra_roles = ()

    # Actual test classes need to override these attributes to set the expected
    # values on the UID and GID results, since this varies with the usage of the
    # POSIX and non-POSIX ID ranges

    testuser_uid_regex = None
    testuser_gid_regex = None
    subdomain_testuser_uid_regex = None
    subdomain_testuser_gid_regex = None
    treedomain_testuser_uid_regex = None
    treedomain_testuser_gid_regex = None

    # To allow custom validation dependent on the trust type
    posix_trust = False

    def test_apply_advice(self):
        # Obtain the advice from the server
        tasks.kinit_admin(self.master)
        result = self.master.run_command(['ipa-advise', self.advice_id])
        advice = result.stdout_text

        # Apply the advice on the legacy client
        advice_path = os.path.join(self.legacy_client.config.test_dir,
                                   'advice.sh')
        self.legacy_client.put_file_contents(advice_path, advice)
        result = self.legacy_client.run_command(['bash', '-x', '-e',
                                                 advice_path])

        # Restart SSHD to load new PAM configuration
        self.legacy_client.run_command([paths.SBIN_SERVICE, 'sshd', 'restart'])

    def clear_sssd_caches(self):
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.legacy_client)

    def test_getent_ipa_user(self):
        self.clear_sssd_caches()
        result = self.legacy_client.run_command(['getent', 'passwd', 'admin'])

        admin_regex = r"admin:\*:(\d+):(\d+):"\
                      r"Administrator:/home/admin:/bin/bash"

        assert re.search(admin_regex, result.stdout_text)

    def test_getent_ipa_group(self):
        self.clear_sssd_caches()
        result = self.legacy_client.run_command(['getent', 'group', 'admins'])

        admin_group_regex = r"admins:\*:(\d+):admin"

        assert re.search(admin_group_regex, result.stdout_text)

    def test_id_ipa_user(self):
        self.clear_sssd_caches()
        result = self.legacy_client.run_command(['id', 'admin'])

        uid_regex = r"uid=(\d+)\(admin\)"
        gid_regex = r"gid=(\d+)\(admins\)"
        groups_regex = r"groups=(\d+)\(admins\)"

        assert re.search(uid_regex, result.stdout_text)
        assert re.search(gid_regex, result.stdout_text)
        assert re.search(groups_regex, result.stdout_text)

    def test_getent_ad_user(self):
        self.clear_sssd_caches()
        testuser = 'testuser@%s' % self.ad.domain.name
        result = self.legacy_client.run_command(['getent', 'passwd', testuser])

        testuser_regex = r"testuser@%s:\*:%s:%s:"\
                         r"Test User:%s:/bin/sh"\
                         % (re.escape(self.ad.domain.name),
                            self.testuser_uid_regex,
                            self.testuser_gid_regex,
                            self.homedir_template.format(
                                username='testuser',
                                domain=re.escape(self.ad.domain.name))
                            )

        assert re.search(testuser_regex, result.stdout_text)

    def test_getent_ad_group(self):
        self.clear_sssd_caches()
        testgroup = 'testgroup@%s' % self.ad.domain.name
        result = self.legacy_client.run_command(['getent', 'group', testgroup])

        testgroup_regex = r"%s:\*:%s:" % (testgroup, self.testuser_gid_regex)
        assert re.search(testgroup_regex, result.stdout_text)

    def test_id_ad_user(self):
        self.clear_sssd_caches()
        testuser = 'testuser@%s' % self.ad.domain.name
        testgroup = 'testgroup@%s' % self.ad.domain.name

        result = self.legacy_client.run_command(['id', testuser])

        # Only for POSIX trust testing does the testuser belong to the
        # testgroup
        group_name = '\(%s\)' % testgroup if self.posix_trust else ''

        uid_regex = "uid=%s\(%s\)" % (self.testuser_uid_regex, testuser)
        gid_regex = "gid=%s%s" % (self.testuser_gid_regex, group_name)
        groups_regex = "groups=%s%s" % (self.testuser_gid_regex, group_name)

        assert re.search(uid_regex, result.stdout_text)
        assert re.search(gid_regex, result.stdout_text)
        assert re.search(groups_regex, result.stdout_text)

    def test_login_ipa_user(self):
        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise unittest.SkipTest('Package sshpass not available on %s'
                                 % self.master.hostname)

        result = self.master.run_command(
            'sshpass -p %s '
            'ssh '
            '-o StrictHostKeyChecking=no '
            '-l admin '
            '%s '
            '"echo test"' %
            (self.legacy_client.config.admin_password,
             self.legacy_client.hostname))

        assert "test" in result.stdout_text

    def test_login_ad_user(self):
        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise unittest.SkipTest('Package sshpass not available on %s'
                                 % self.master.hostname)

        testuser = 'testuser@%s' % self.ad.domain.name
        result = self.master.run_command(
            'sshpass -p Secret123 '
            'ssh '
            '-o StrictHostKeyChecking=no '
            '-l %s '
            '%s '
            '"echo test"' %
             (testuser, self.legacy_client.hostname))

        assert "test" in result.stdout_text

    def test_login_disabled_ipa_user(self):
        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise unittest.SkipTest('Package sshpass not available on %s'
                                 % self.master.hostname)

        self.clear_sssd_caches()

        result = self.master.run_command(
            'sshpass -p %s '
            'ssh '
            '-o StrictHostKeyChecking=no '
            '-l disabledipauser '
            '%s '
            '"echo test"'
            % (self.legacy_client.config.admin_password,
               self.legacy_client.external_hostname),
            raiseonerr=False)

        assert result.returncode != 0

    def test_login_disabled_ad_user(self):
        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise unittest.SkipTest('Package sshpass not available on %s'
                                 % self.master.hostname)

        testuser = 'disabledaduser@%s' % self.ad.domain.name
        result = self.master.run_command(
            'sshpass -p Secret123 '
            'ssh '
            '-o StrictHostKeyChecking=no '
            '-l %s '
            '%s '
            '"echo test"' %
            (testuser, self.legacy_client.external_hostname),
            raiseonerr=False)

        assert result.returncode != 0

    def test_getent_subdomain_ad_user(self):
        if not self.ad_subdomain:
            raise unittest.SkipTest('AD for the subdomain is not available.')

        self.clear_sssd_caches()
        testuser = 'subdomaintestuser@%s' % self.ad_subdomain
        result = self.legacy_client.run_command(['getent', 'passwd', testuser])

        testuser_regex = r"subdomaintestuser@%s:\*:%s:%s:"\
                         r"Subdomaintest User:%s:"\
                         r"/bin/sh"\
                         % (re.escape(self.ad_subdomain),
                            self.subdomain_testuser_uid_regex,
                            self.subdomain_testuser_gid_regex,
                            self.homedir_template.format(
                                username='subdomaintestuser',
                                domain=re.escape(self.ad_subdomain))
                            )

        assert re.search(testuser_regex, result.stdout_text)

    def test_getent_subdomain_ad_group(self):
        if not self.ad_subdomain:
            raise unittest.SkipTest('AD for the subdomain is not available.')

        self.clear_sssd_caches()
        testgroup = 'subdomaintestgroup@%s' % self.ad_subdomain
        result = self.legacy_client.run_command(['getent', 'group', testgroup])

        testgroup_stdout = r"%s:\*:%s:" % (testgroup,
                                          self.subdomain_testuser_gid_regex)
        assert re.search(testgroup_stdout, result.stdout_text)

    def test_id_subdomain_ad_user(self):
        if not self.ad_subdomain:
            raise unittest.SkipTest('AD for the subdomain is not available.')

        self.clear_sssd_caches()
        testuser = 'subdomaintestuser@%s' % self.ad_subdomain
        testgroup = 'subdomaintestgroup@%s' % self.ad_subdomain

        result = self.legacy_client.run_command(['id', testuser])

        # Only for POSIX trust testing does the testuser belong to the
        # testgroup
        group_name = '\(%s\)' % testgroup if self.posix_trust else ''

        uid_regex = "uid=%s\(%s\)" % (self.subdomain_testuser_uid_regex,
                                      testuser)
        gid_regex = "gid=%s%s" % (self.subdomain_testuser_gid_regex,
                                  group_name)
        groups_regex = "groups=%s%s" % (self.subdomain_testuser_gid_regex,
                                        group_name)

        assert re.search(uid_regex, result.stdout_text)
        assert re.search(gid_regex, result.stdout_text)
        assert re.search(groups_regex, result.stdout_text)

    def test_login_subdomain_ad_user(self):
        if not self.ad_subdomain:
            raise unittest.SkipTest('AD for the subdomain is not available.')

        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise unittest.SkipTest('Package sshpass not available on %s'
                                 % self.master.hostname)

        testuser = 'subdomaintestuser@%s' % self.ad_subdomain
        result = self.master.run_command(
            'sshpass -p Secret123 '
            'ssh '
            '-o StrictHostKeyChecking=no '
            '-l %s '
            '%s '
            '"echo test"' %
             (testuser, self.legacy_client.external_hostname))

        assert "test" in result.stdout_text

    def test_login_disabled_subdomain_ad_user(self):
        if not self.ad_subdomain:
            raise unittest.SkipTest('AD for the subdomain is not available.')

        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise unittest.SkipTest('Package sshpass not available on %s'
                                 % self.master.hostname)

        testuser = 'subdomaindisabledaduser@%s' % self.ad_subdomain
        result = self.master.run_command(
            'sshpass -p Secret123 '
            'ssh '
            '-o StrictHostKeyChecking=no '
            '-l %s '
            '%s '
            '"echo test"' %
            (testuser, self.legacy_client.external_hostname),
            raiseonerr=False)

        assert result.returncode != 0

    def test_getent_treedomain_ad_user(self):
        if not self.ad_treedomain:
            raise unittest.SkipTest('AD tree root domain is not available.')

        self.clear_sssd_caches()
        testuser = 'treetestuser@{0}'.format(self.ad_treedomain)
        result = self.legacy_client.run_command(['getent', 'passwd', testuser])

        testuser_regex = (r"treetestuser@{0}:\*:{1}:{2}:TreeTest User:"
                          r"/home/{0}/treetestuser:/bin/sh".format(
                              re.escape(self.ad_treedomain),
                              self.treedomain_testuser_uid_regex,
                              self.treedomain_testuser_gid_regex))

        assert re.search(testuser_regex, result.stdout_text)

    def test_getent_treedomain_ad_group(self):
        if not self.ad_treedomain:
            raise unittest.SkipTest('AD tree root domain is not available')

        self.clear_sssd_caches()
        testgroup = 'treetestgroup@{0}'.format(self.ad_treedomain)
        result = self.legacy_client.run_command(['getent', 'group', testgroup])

        testgroup_stdout = r"{0}:\*:{1}:".format(
                           testgroup, self.treedomain_testuser_gid_regex)

        assert re.search(testgroup_stdout, result.stdout_text)

    def test_id_treedomain_ad_user(self):
        if not self.ad_treedomain:
            raise unittest.SkipTest('AD tree root domain is not available')

        self.clear_sssd_caches()

        testuser = 'treetestuser@{0}'.format(self.ad_treedomain)
        testgroup = 'treetestgroup@{0}'.format(self.ad_treedomain)

        result = self.legacy_client.run_command(['id', testuser])

        # Only for POSIX trust testing does the testuser belong to the
        # testgroup

        group_name = '\({}\)'.format(testgroup) if self.posix_trust else ''

        uid_regex = "uid={0}\({1}\)".format(
                    self.treedomain_testuser_uid_regex, testuser)

        gid_regex = "gid={0}{1}".format(
                    self.treedomain_testuser_gid_regex, group_name)

        group_regex = "groups={0}{1}".format(
                      self.treedomain_testuser_gid_regex, group_name)

        assert re.search(uid_regex, result.stdout_text)
        assert re.search(gid_regex, result.stdout_text)
        assert re.search(group_regex, result.stdout_text)

    def test_login_treedomain_ad_user(self):
        if not self.ad_treedomain:
            raise unittest.SkipTest('AD tree root domain is not available.')

        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise unittest.SkipTest(
                'Package sshpass not available on {}'.format(
                    self.master.hostname)
            )

        result = self.master.run_command(
            'sshpass -p {0} ssh -o StrictHostKeyChecking=no '
            '-l admin {1} "echo test"'.format(
                self.legacy_client.config.admin_password,
                self.legacy_client.external_hostname))

        assert "test" in result.stdout_text


    @classmethod
    def install(cls, mh):
        super(BaseTestLegacyClient, cls).install(mh)

        tasks.kinit_admin(cls.master)

        password_confirmation = (
            cls.master.config.admin_password +
            '\n' +
            cls.master.config.admin_password
            )

        cls.master.run_command(['ipa', 'user-add', 'disabledipauser',
                                        '--first', 'disabled',
                                        '--last', 'ipauser',
                                        '--password'],
                                 stdin_text=password_confirmation)

        cls.master.run_command(['ipa', 'user-disable', 'disabledipauser'])

        cls.ad = cls.ad_domains[0].ads[0]

        cls.legacy_client = cls.host_by_role(cls.required_extra_roles[0])

        # Determine whether the subdomain AD is available
        try:
            child_ad = cls.host_by_role(cls.optional_extra_roles[0])
            cls.ad_subdomain = '.'.join(
                child_ad.hostname.split('.')[1:])
        except LookupError:
            cls.ad_subdomain = None

        # Determine whether the tree domain AD is available
        try:
            cls.tree_ad = cls.host_by_role(cls.optional_extra_roles[1])
            cls.ad_treedomain = '.'.join(
                cls.tree_ad.hostname.split('.')[1:])
        except LookupError:
            cls.ad_treedomain = None

        tasks.apply_common_fixes(cls.legacy_client)

        for f in cls.backup_files:
            tasks.backup_file(cls.legacy_client, f)

    @classmethod
    def uninstall(cls, mh):
        cls.master.run_command(['ipa', 'user-del', 'disabledipauser'],
                                raiseonerr=False)

        # Remove information about trust from AD, if domain was defined
        if hasattr(cls, 'ad_domain'):
            tasks.remove_trust_info_from_ad(cls.master, cls.ad_domain)

        # Also unapply fixes on the legacy client, if defined
        if hasattr(cls, 'legacy_client'):
            tasks.unapply_fixes(cls.legacy_client)

        super(BaseTestLegacyClient, cls).uninstall(mh)


# Base classes with attributes that are specific for each legacy client test

class BaseTestLegacySSSDBefore19RedHat:

    advice_id = 'config-redhat-sssd-before-1-9'
    required_extra_roles = ['legacy_client_sssd_redhat']
    optional_extra_roles = ['ad_subdomain', 'ad_treedomain']


class BaseTestLegacyNssPamLdapdRedHat:

    advice_id = 'config-redhat-nss-pam-ldapd'
    required_extra_roles = ['legacy_client_nss_pam_ldapd_redhat']
    optional_extra_roles = ['ad_subdomain', 'ad_treedomain']

    def clear_sssd_caches(self):
        tasks.clear_sssd_cache(self.master)


class BaseTestLegacyNssLdapRedHat:

    advice_id = 'config-redhat-nss-ldap'
    required_extra_roles = ['legacy_client_nss_ldap_redhat']
    optional_extra_roles = ['ad_subdomain', 'ad_treedomain']

    def clear_sssd_caches(self):
        tasks.clear_sssd_cache(self.master)


# Base classes that join legacy client specific steps with steps required
# to setup IPA with trust (both with and without using the POSIX attributes)

class BaseTestLegacyClientPosix(trust_tests.BaseTestTrust,
                                BaseTestLegacyClient):

    testuser_uid_regex = '10042'
    testuser_gid_regex = '10047'
    subdomain_testuser_uid_regex = '10142'
    subdomain_testuser_gid_regex = '10147'
    treedomain_testuser_uid_regex = '10242'
    treedomain_testuser_gid_regex = '10247'
    posix_trust = True

    def test_remove_trust_with_posix_attributes(self):
        pass


class BaseTestLegacyClientNonPosix(trust_tests.BaseTestTrust,
                                   BaseTestLegacyClient):

    testuser_uid_regex = r'(?!10042)(\d+)'
    testuser_gid_regex = r'(?!10047)(\d+)'
    subdomain_testuser_uid_regex = r'(?!10142)(\d+)'
    subdomain_testuser_gid_regex = r'(?!10147)(\d+)'
    treedomain_testuser_uid_regex = r'(?!10242)(\d+)'
    treedomain_testuser_gid_regex = r'(?!10247)(\d+)'

    def test_remove_nonposix_trust(self):
        pass


class BaseTestSSSDMixin:

    def test_apply_advice(self):
        super(BaseTestSSSDMixin, self).test_apply_advice()
        tasks.setup_sssd_debugging(self.legacy_client)


# Tests definitions themselves. Beauty. Just pure beauty.

class TestLegacySSSDBefore19RedHatNonPosix(BaseTestSSSDMixin,
                                           BaseTestLegacySSSDBefore19RedHat,
                                           BaseTestLegacyClientNonPosix):
    pass


class TestLegacyNssPamLdapdRedHatNonPosix(BaseTestLegacyNssPamLdapdRedHat,
                                          BaseTestLegacyClientNonPosix):
    pass


class TestLegacyNssLdapRedHatNonPosix(BaseTestLegacyNssLdapRedHat,
                                      BaseTestLegacyClientNonPosix):
    pass


class TestLegacySSSDBefore19RedHatPosix(BaseTestSSSDMixin,
                                        BaseTestLegacySSSDBefore19RedHat,
                                        BaseTestLegacyClientPosix):
    pass


class TestLegacyNssPamLdapdRedHatPosix(BaseTestLegacyNssPamLdapdRedHat,
                                       BaseTestLegacyClientPosix):
    pass


class TestLegacyNssLdapRedHatPosix(BaseTestLegacyNssLdapRedHat,
                                   BaseTestLegacyClientPosix):
    pass
