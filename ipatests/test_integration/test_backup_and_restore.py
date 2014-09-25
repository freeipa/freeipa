# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2014  Red Hat
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
import contextlib

from ipapython.ipa_log_manager import log_mgr
from ipapython.dn import DN
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration import tasks
from ipatests.util import assert_deepequal

log = log_mgr.get_logger(__name__)


def assert_entries_equal(a, b):
    assert_deepequal(a.dn, b.dn)
    assert_deepequal(dict(a), dict(b))


def assert_results_equal(a, b):
    def to_dict(r):
        return {
            'stdout': r.stdout_text,
            'stderr': r.stderr_text,
            'returncode': r.returncode,
        }
    assert_deepequal(to_dict(a), to_dict(b))


def check_admin_in_ldap(host):
    ldap = host.ldap_connect()
    basedn = host.domain.basedn
    user_dn = DN(('uid', 'admin'), ('cn', 'users'), ('cn', 'accounts'), basedn)
    entry = ldap.get_entry(user_dn)
    print entry
    assert entry.dn == user_dn
    assert entry['uid'] == ['admin']

    del entry['krbLastSuccessfulAuth']

    return entry


def check_admin_in_cli(host):
    result = host.run_command(['ipa', 'user-show', 'admin'])
    assert 'User login: admin' in result.stdout_text, result.stdout_text
    return result


def check_admin_in_id(host):
    result = host.run_command(['id', 'admin'])
    assert 'admin' in result.stdout_text, result.stdout_text
    return result


def check_certs(host):
    result = host.run_command(['ipa', 'cert-find'])
    assert re.search('^Number of entries returned [1-9]\d*$',
                     result.stdout_text, re.MULTILINE), result.stdout_text
    return result


def check_dns(host):
    result = host.run_command(['host', host.hostname, 'localhost'])
    return result


def check_kinit(host):
    result = host.run_command(['kinit', 'admin'],
                              stdin_text=host.config.admin_password)
    return result


CHECKS = [
    (check_admin_in_ldap, assert_entries_equal),
    (check_admin_in_cli, assert_results_equal),
    (check_admin_in_id, assert_results_equal),
    (check_certs, assert_results_equal),
    (check_dns, assert_results_equal),
    (check_kinit, assert_results_equal),
]


@contextlib.contextmanager
def restore_checker(host):
    """Check that the IPA at host works the same at context enter and exit"""
    tasks.kinit_admin(host)

    results = []
    for check, assert_func in CHECKS:
        log.info('Storing result for %s', check)
        results.append(check(host))

    yield

    for (check, assert_func), expected in zip(CHECKS, results):
        log.info('Checking result for %s', check)
        got = check(host)
        assert_func(expected, got)


def backup(host):
    """Run backup on host, return the path to the backup directory"""
    result = host.run_command(['ipa-backup', '-v'])

    # Get the backup location from the command's output
    for line in result.stderr_text.splitlines():
        prefix = ('ipa.ipaserver.install.ipa_backup.Backup: '
                  'INFO: Backed up to ')
        if line.startswith(prefix):
            backup_path = line[len(prefix):].strip()
            log.info('Backup path for %s is %s', host, backup_path)
            return backup_path
    else:
        raise AssertionError('Backup directory not found in output')



class TestBackupAndRestore(IntegrationTest):
    topology = 'star'

    def test_full_backup_and_restore(self):
        """backup, uninstall, restore"""
        with restore_checker(self.master):
            backup_path = backup(self.master)

            self.master.run_command(['ipa-server-install',
                                     '--uninstall',
                                     '-U'])

            dirman_password = self.master.config.dirman_password
            self.master.run_command(['ipa-restore', backup_path],
                                    stdin_text=dirman_password + '\nyes')

    def test_full_backup_and_restore_with_removed_users(self):
        """regression test for https://fedorahosted.org/freeipa/ticket/3866"""
        with restore_checker(self.master):
            backup_path = backup(self.master)

            self.log.info('Backup path for %s is %s', self.master, backup_path)

            self.master.run_command(['ipa-server-install',
                                     '--uninstall',
                                     '-U'])

            self.master.run_command(['userdel', 'dirsrv'])
            self.master.run_command(['userdel', 'pkiuser'])

            homedir = os.path.join(self.master.config.test_dir,
                                   'testuser_homedir')
            self.master.run_command(['useradd', 'ipatest_user1',
                                     '--system',
                                     '-d', homedir])
            try:
                dirman_password = self.master.config.dirman_password
                self.master.run_command(['ipa-restore', backup_path],
                                        stdin_text=dirman_password + '\nyes')
            finally:
                self.master.run_command(['userdel', 'ipatest_user1'])

    def test_full_backup_and_restore_with_selinux_booleans_off(self):
        """regression test for https://fedorahosted.org/freeipa/ticket/4157"""
        with restore_checker(self.master):
            backup_path = backup(self.master)

            self.log.info('Backup path for %s is %s', self.master, backup_path)

            self.master.run_command(['ipa-server-install',
                                     '--uninstall',
                                     '-U'])

            self.master.run_command([
                'setsebool', '-P',
                'httpd_can_network_connect=off',
                'httpd_manage_ipa=off',
            ])

            dirman_password = self.master.config.dirman_password
            self.master.run_command(['ipa-restore', backup_path],
                                    stdin_text=dirman_password + '\nyes')

        result = self.master.run_command([
            'getsebool',
            'httpd_can_network_connect',
            'httpd_manage_ipa',
        ])
        assert 'httpd_can_network_connect --> on' in result.stdout_text
        assert 'httpd_manage_ipa --> on' in result.stdout_text
