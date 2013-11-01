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

import os
import re

import nose

from ipatests.test_integration import tasks

# importing test_trust under different name to avoid nose executing the test
# base class imported from this module
from ipatests.test_integration import test_trust as trust_tests


class BaseTestLegacyClient(trust_tests.TestEnforcedPosixADTrust):
    """
    Tests legacy client support.
    """

    advice_id = None
    backup_files = ['/etc/sysconfig/authconfig',
                    '/etc/pam.d',
                    '/etc/openldap/cacerts',
                    '/etc/openldap/ldap.conf',
                    '/etc/nsswitch.conf',
                    '/etc/sssd/sssd.conf']

    @classmethod
    def setup_class(cls):
        super(BaseTestLegacyClient, cls).setup_class()
        cls.ad = cls.ad_domains[0].ads[0]

        cls.legacy_client = cls.host_by_role(cls.required_extra_roles[0])
        tasks.apply_common_fixes(cls.legacy_client)

        for f in cls.backup_files:
            tasks.backup_file(cls.legacy_client, f)

    def test_remove_trust_with_posix_attributes(self):
        pass

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
        self.legacy_client.run_command(['/sbin/service', 'sshd', 'restart'])

    def clear_sssd_caches(self):
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.legacy_client)

    def test_getent_ipa_user(self):
        self.clear_sssd_caches()
        result = self.legacy_client.run_command(['getent', 'passwd', 'admin'])

        admin_regex = "^admin:\*:(\d+):(\d+):"\
                      "Administrator:/home/admin:/bin/bash$"

        assert re.search(admin_regex, result.stdout_text)

    def test_getent_ipa_group(self):
        self.clear_sssd_caches()
        result = self.legacy_client.run_command(['getent', 'group', 'admins'])

        admin_group_regex = "^admins:\*:(\d+):admin"

        assert re.search(admin_group_regex, result.stdout_text)

    def test_id_ipa_user(self):
        self.clear_sssd_caches()
        result = self.legacy_client.run_command(['id', 'admin'])

        uid_regex = "uid=(\d+)\(admin\)"
        gid_regex = "gid=(\d+)\(admins\)"
        groups_regex = "groups=(\d+)\(admins\)"

        assert re.search(uid_regex, result.stdout_text)
        assert re.search(gid_regex, result.stdout_text)
        assert re.search(groups_regex, result.stdout_text)

    def test_getent_ad_user(self):
        self.clear_sssd_caches()
        testuser = 'testuser@%s' % self.ad.domain.name
        result = self.legacy_client.run_command(['getent', 'passwd', testuser])

        testuser_stdout = "testuser@%s:*:10042:10047:"\
                          "Test User:/home/testuser:/bin/sh"\
                          % self.ad.domain.name

        assert testuser_stdout in result.stdout_text

    def test_getent_ad_group(self):
        self.clear_sssd_caches()
        testgroup = 'test group@%s' % self.ad.domain.name
        result = self.legacy_client.run_command(['getent', 'group', testgroup])

        testgroup_stdout = "%s:\*:10047:" % testgroup
        assert re.search(testgroup_stdout, result.stdout_text)

    def test_id_ad_user(self):
        self.clear_sssd_caches()
        testuser = 'testuser@%s' % self.ad.domain.name
        testgroup = 'test group@%s' % self.ad.domain.name

        result = self.legacy_client.run_command(['id', testuser])

        uid_regex = "uid=10042\(%s\)" % testuser
        gid_regex = "gid=10047\(%s\)" % testgroup
        groups_regex = "groups=10047\(%s\)" % testgroup

        assert re.search(uid_regex, result.stdout_text)
        assert re.search(gid_regex, result.stdout_text)
        assert re.search(groups_regex, result.stdout_text)

    def test_login_ipa_user(self):
        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise nose.SkipTest('Package sshpass not available on %s'
                                 % self.master.hostname)

        result = self.master.run_command(
            'sshpass -p %s '
            'ssh '
            '-o StrictHostKeyChecking=no '
            '-l admin '
            '%s '
            '"echo test"' %
            (self.legacy_client.config.admin_password,
             self.legacy_client.external_hostname))

        assert "test" in result.stdout_text

    def test_login_ad_user(self):
        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise nose.SkipTest('Package sshpass not available on %s'
                                 % self.master.hostname)

        testuser = 'testuser@%s' % self.ad.domain.name
        result = self.master.run_command(
            'sshpass -p Secret123 '
            'ssh '
            '-o StrictHostKeyChecking=no '
            '-l %s '
            '%s '
            '"echo test"' %
             (testuser, self.legacy_client.external_hostname))

        assert "test" in result.stdout_text

    def test_login_disabled_ipa_user(self):
        if not self.master.transport.file_exists('/usr/bin/sshpass'):
            raise nose.SkipTest('Package sshpass not available on %s'
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
            raise nose.SkipTest('Package sshpass not available on %s'
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

    @classmethod
    def install(cls):
        super(BaseTestLegacyClient, cls).install()

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

    @classmethod
    def uninstall(cls):
        cls.master.run_command(['ipa', 'user-del', 'disabledipauser'],
                                raiseonerr=False)
        tasks.unapply_fixes(cls.legacy_client)
        super(BaseTestLegacyClient, cls).uninstall()


class TestLegacySSSDBefore19RedHat(BaseTestLegacyClient):

    advice_id = 'config-redhat-sssd-before-1-9'
    required_extra_roles = ['legacy_client_sssd_redhat']


class TestLegacyNssPamLdapdRedHat(BaseTestLegacyClient):

    advice_id = 'config-redhat-nss-pam-ldapd'
    required_extra_roles = ['legacy_client_nss_pam_ldapd_redhat']

    def clear_sssd_caches(self):
        tasks.clear_sssd_cache(self.master)


class TestLegacyNssLdapRedHat(BaseTestLegacyClient):

    advice_id = 'config-redhat-nss-ldap'
    required_extra_roles = ['legacy_client_nss_ldap_redhat']

    def clear_sssd_caches(self):
        tasks.clear_sssd_cache(self.master)
