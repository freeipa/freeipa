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

from __future__ import print_function, absolute_import

import logging
import os
import re
import contextlib
from tempfile import NamedTemporaryFile

from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks as platformtasks
from ipapython.dn import DN
from ipapython import ipautil
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_dnssec import wait_until_record_is_signed
from ipatests.test_integration.test_simple_replication import check_replication
from ipatests.util import assert_deepequal
from ldap.dn import escape_dn_chars

logger = logging.getLogger(__name__)

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
    print(entry)
    assert entry.dn == user_dn
    assert entry['uid'] == ['admin']

    entry.pop('krbLastSuccessfulAuth', None)

    return entry


def check_admin_in_cli(host):
    result = host.run_command(['ipa', 'user-show', 'admin'])
    assert 'User login: admin' in result.stdout_text, result.stdout_text

    # LDAP do not guarantee any order, so the test cannot assume it. Based on
    # that, the code bellow order the 'Member of groups' field to able to
    # assert it latter.
    data = dict(re.findall("\W*(.+):\W*(.+)\W*", result.stdout_text))
    data["Member of groups"] = ', '.join(sorted(data["Member of groups"]
                                                .split(", ")))
    result.stdout_text = ''.join([' {}: {}\n'.format(k, v)
                                  for k, v in data.items()])
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
        logger.info('Storing result for %s', check)
        results.append(check(host))

    yield

    for (check, assert_func), expected in zip(CHECKS, results):
        logger.info('Checking result for %s', check)
        got = check(host)
        assert_func(expected, got)


def backup(host):
    """Run backup on host, return the path to the backup directory"""
    result = host.run_command(['ipa-backup', '-v'])

    # Test for ticket 7632: check that services are restarted
    # before the backup is compressed
    pattern = r'.*gzip.*Starting IPA service.*'
    if (re.match(pattern, result.stderr_text, re.DOTALL)):
        raise AssertionError('IPA Services are started after compression')

    # Get the backup location from the command's output
    for line in result.stderr_text.splitlines():
        prefix = 'ipaserver.install.ipa_backup: INFO: Backed up to '
        if line.startswith(prefix):
            backup_path = line[len(prefix):].strip()
            logger.info('Backup path for %s is %s', host, backup_path)
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

            logger.info('Backup path for %s is %s', self.master, backup_path)

            self.master.run_command(['ipa-server-install',
                                     '--uninstall',
                                     '-U'])

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

    @pytest.mark.skipif(
        not platformtasks.is_selinux_enabled(),
        reason="Test needs SELinux enabled")
    def test_full_backup_and_restore_with_selinux_booleans_off(self):
        """regression test for https://fedorahosted.org/freeipa/ticket/4157"""
        with restore_checker(self.master):
            backup_path = backup(self.master)

            logger.info('Backup path for %s is %s', self.master, backup_path)

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


class BaseBackupAndRestoreWithDNS(IntegrationTest):
    """
    Abstract class for DNS restore tests
    """
    topology = 'star'

    example_test_zone = "example.test."
    example2_test_zone = "example2.test."

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def _full_backup_restore_with_DNS_zone(self, reinstall=False):
        """backup, uninstall, restore"""
        with restore_checker(self.master):
            self.master.run_command([
                'ipa', 'dnszone-add',
                self.example_test_zone,
            ])

            tasks.resolve_record(self.master.ip, self.example_test_zone)

            backup_path = backup(self.master)

            self.master.run_command(['ipa-server-install',
                                     '--uninstall',
                                     '-U'])

            if reinstall:
                tasks.install_master(self.master, setup_dns=True)

            dirman_password = self.master.config.dirman_password
            self.master.run_command(['ipa-restore', backup_path],
                                    stdin_text=dirman_password + '\nyes')

            tasks.resolve_record(self.master.ip, self.example_test_zone)

            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'dnszone-add',
                self.example2_test_zone,
            ])

            tasks.resolve_record(self.master.ip, self.example2_test_zone)


class TestBackupAndRestoreWithDNS(BaseBackupAndRestoreWithDNS):
    def test_full_backup_and_restore_with_DNS_zone(self):
        """backup, uninstall, restore"""
        self._full_backup_restore_with_DNS_zone(reinstall=False)


class TestBackupReinstallRestoreWithDNS(BaseBackupAndRestoreWithDNS):
    def test_full_backup_reinstall_restore_with_DNS_zone(self):
        """backup, uninstall, reinstall, restore"""
        self._full_backup_restore_with_DNS_zone(reinstall=True)


class BaseBackupAndRestoreWithDNSSEC(IntegrationTest):
    """
    Abstract class for DNSSEC restore tests
    """
    topology = 'star'

    example_test_zone = "example.test."
    example2_test_zone = "example2.test."

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        args = [
            "ipa-dns-install",
            "--dnssec-master",
            "--forwarder", cls.master.config.dns_forwarder,
            "-U",
        ]
        cls.master.run_command(args)

    def _full_backup_and_restore_with_DNSSEC_zone(self, reinstall=False):
        with restore_checker(self.master):
            self.master.run_command([
                'ipa', 'dnszone-add',
                self.example_test_zone,
                '--dnssec', 'true',
            ])

            assert (
                wait_until_record_is_signed(
                    self.master.ip, self.example_test_zone)
            ), "Zone is not signed"

            backup_path = backup(self.master)

            self.master.run_command(['ipa-server-install',
                                     '--uninstall',
                                     '-U'])

            if reinstall:
                tasks.install_master(self.master, setup_dns=True)

            dirman_password = self.master.config.dirman_password
            self.master.run_command(['ipa-restore', backup_path],
                                    stdin_text=dirman_password + '\nyes')

            assert (
                wait_until_record_is_signed(
                    self.master.ip, self.example_test_zone)
            ), "Zone is not signed after restore"

            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'dnszone-add',
                self.example2_test_zone,
                '--dnssec', 'true',
            ])

            assert (
                wait_until_record_is_signed(
                    self.master.ip, self.example2_test_zone)
            ), "A new zone is not signed"


class TestBackupAndRestoreWithDNSSEC(BaseBackupAndRestoreWithDNSSEC):
    def test_full_backup_and_restore_with_DNSSEC_zone(self):
        """backup, uninstall, restore"""
        self._full_backup_and_restore_with_DNSSEC_zone(reinstall=False)


class TestBackupReinstallRestoreWithDNSSEC(BaseBackupAndRestoreWithDNSSEC):
    def test_full_backup_reinstall_restore_with_DNSSEC_zone(self):
        """backup, uninstall, install, restore"""
        self._full_backup_and_restore_with_DNSSEC_zone(reinstall=True)


class BaseBackupAndRestoreWithKRA(IntegrationTest):
    """
    Abstract class for KRA restore tests
    """
    topology = 'star'

    vault_name = "ci_test_vault"
    vault_password = "password"
    vault_data = "SSBsb3ZlIENJIHRlc3RzCg=="

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)

    def _full_backup_restore_with_vault(self, reinstall=False):
        with restore_checker(self.master):
            # create vault
            self.master.run_command([
                "ipa", "vault-add",
                self.vault_name,
                "--password", self.vault_password,
                "--type", "symmetric",
            ])

            # archive secret
            self.master.run_command([
                "ipa", "vault-archive",
                self.vault_name,
                "--password", self.vault_password,
                "--data", self.vault_data,
            ])

            # retrieve secret
            self.master.run_command([
                "ipa", "vault-retrieve",
                self.vault_name,
                "--password", self.vault_password,
            ])

            backup_path = backup(self.master)

            self.master.run_command(['ipa-server-install',
                                     '--uninstall',
                                     '-U'])

            if reinstall:
                tasks.install_master(self.master, setup_dns=True)

            dirman_password = self.master.config.dirman_password
            self.master.run_command(['ipa-restore', backup_path],
                                    stdin_text=dirman_password + '\nyes')

            tasks.kinit_admin(self.master)
            # retrieve secret after restore
            self.master.run_command([
                "ipa", "vault-retrieve",
                self.vault_name,
                "--password", self.vault_password,
            ])


class TestBackupAndRestoreWithKRA(BaseBackupAndRestoreWithKRA):
    def test_full_backup_restore_with_vault(self):
        """backup, uninstall, restore"""
        self._full_backup_restore_with_vault(reinstall=False)


class TestBackupReinstallRestoreWithKRA(BaseBackupAndRestoreWithKRA):
    def test_full_backup_reinstall_restore_with_vault(self):
        """backup, uninstall, reinstall, restore"""
        self._full_backup_restore_with_vault(reinstall=True)


class TestBackupAndRestoreWithReplica(IntegrationTest):
    """Regression test for https://pagure.io/freeipa/issue/7234"""
    num_replicas = 1
    topology = "star"

    @classmethod
    def install(cls, mh):
        if cls.domain_level is None:
            domain_level = cls.master.config.domain_level
        else:
            domain_level = cls.domain_level

        if cls.topology is None:
            return
        else:
            tasks.install_topo(
                cls.topology, cls.master, [],
                cls.clients, domain_level
            )

    def test_full_backup_and_restore_with_replica(self):
        replica = self.replicas[0]

        with restore_checker(self.master):
            backup_path = backup(self.master)

            logger.info("Backup path for %s is %s", self.master, backup_path)

            self.master.run_command([
                "ipa-server-install", "--uninstall", "-U"
            ])

            logger.info("Stopping and disabling oddjobd service")
            self.master.run_command([
                "systemctl", "stop", "oddjobd"
            ])
            self.master.run_command([
                "systemctl", "disable", "oddjobd"
            ])

            self.master.run_command(
                ["ipa-restore", backup_path],
                stdin_text='yes'
            )

            status = self.master.run_command([
                "systemctl", "status", "oddjobd"
            ])
            assert "active (running)" in status.stdout_text

        tasks.install_replica(self.master, replica)
        check_replication(self.master, replica, "testuser1")


class TestUserRootFilesOwnershipPermission(IntegrationTest):
    """Test to check if userroot.ldif have proper ownership.

    Before the fix, when ipa-backup was called for the first time,
    the LDAP database exported to
    /var/lib/dirsrv/slapd-<instance>/ldif/<instance>-userRoot.ldif.
    db2ldif is called for this and it runs under root, hence files
    were owned by root.

    When ipa-backup called the next time, the db2ldif fails,
    because the tool does not have permissions to write to the ldif
    file which was owned by root (instead of dirsrv).

    This test check if files are owned by dirsrv and db2ldif doesn't
    fail

    related ticket: https://pagure.io/freeipa/issue/7010

    This test also checks if the access rights for user/group
    are set and umask 0022 set while restoring.

    related ticket: https://pagure.io/freeipa/issue/6844
    """

    @classmethod
    def install(cls, mh):
        super(TestUserRootFilesOwnershipPermission, cls).install(mh)
        cls.bashrc_file = cls.master.get_file_contents('/root/.bashrc')

    def test_userroot_ldif_files_ownership_and_permission(self):
        """backup, uninstall, restore, backup"""
        tasks.install_master(self.master)
        backup_path = backup(self.master)

        self.master.run_command(['ipa-server-install',
                                 '--uninstall',
                                 '-U'])

        # set umask to 077 just to check if restore success.
        self.master.run_command('echo "umask 0077" >> /root/.bashrc')
        result = self.master.run_command(['umask'])
        assert '0077' in result.stdout_text

        dirman_password = self.master.config.dirman_password
        result = self.master.run_command(['ipa-restore', backup_path],
                                         stdin_text=dirman_password + '\nyes')
        assert 'Temporary setting umask to 022' in result.stderr_text

        # check if umask reset to 077 after restore.
        result = self.master.run_command(['umask'])
        assert '0077' in result.stdout_text

        # check if files have proper owner and group.
        dashed_domain = self.master.domain.realm.replace(".", '-')
        arg = ['stat',
               '-c', '%U:%G',
               '{}/ldif/'.format(
                   paths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE %
                   dashed_domain)]
        cmd = self.master.run_command(arg)
        expected = '{}:{}'.format(constants.DS_USER, constants.DS_GROUP)
        assert expected in cmd.stdout_text

        # also check of access rights are set to 644.
        arg = ['stat',
               '-c', '%U:%G:%a',
               '{}/ldif/{}-ipaca.ldif'.format(
                   paths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE %
                   dashed_domain, dashed_domain)]
        cmd = self.master.run_command(arg)
        assert '{}:644'.format(expected) in cmd.stdout_text

        arg = ['stat',
               '-c', '%U:%G:%a',
               '{}/ldif/{}-userRoot.ldif'.format(
                   paths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE %
                   dashed_domain, dashed_domain)]
        cmd = self.master.run_command(arg)
        assert '{}:644'.format(expected) in cmd.stdout_text

        cmd = self.master.run_command(['ipa-backup', '-d'])
        unexp_str = "CRITICAL: db2ldif failed:"
        assert cmd.returncode == 0
        assert unexp_str not in cmd.stdout_text

    def test_files_ownership_and_permission_teardown(self):
        """ Method to restore the default bashrc contents"""
        if self.bashrc_file is not None:
            self.master.put_file_contents('/root/.bashrc', self.bashrc_file)


class TestReplicaInstallAfterRestore(IntegrationTest):
    """Test to check second replica installation after master restore

    When master is restored from backup and replica1 is re-initialize,
    second replica installation was failing. The issue was with ipa-backup
    tool which was not backing up the /etc/ipa/custodia/custodia.conf and
    /etc/ipa/custodia/server.keys.

    related ticket: https://pagure.io/freeipa/issue/7247
    """

    num_replicas = 2

    def test_replica_install_after_restore(self):
        master = self.master
        replica1 = self.replicas[0]
        replica2 = self.replicas[1]

        tasks.install_master(master)
        tasks.install_replica(master, replica1)
        check_replication(master, replica1, "testuser1")

        # backup master.
        backup_path = backup(master)

        suffix = ipautil.realm_to_suffix(master.domain.realm)
        suffix = escape_dn_chars(str(suffix))
        tf = NamedTemporaryFile()
        ldif_file = tf.name
        entry_ldif = (
            "dn: cn=meTo{hostname},cn=replica,"
            "cn={suffix},"
            "cn=mapping tree,cn=config\n"
            "changetype: modify\n"
            "replace: nsds5ReplicaEnabled\n"
            "nsds5ReplicaEnabled: off\n\n"

            "dn: cn=caTo{hostname},cn=replica,"
            "cn=o\\3Dipaca,cn=mapping tree,cn=config\n"
            "changetype: modify\n"
            "replace: nsds5ReplicaEnabled\n"
            "nsds5ReplicaEnabled: off").format(
            hostname=replica1.hostname,
            suffix=suffix)
        master.put_file_contents(ldif_file, entry_ldif)

        # disable replication agreement
        arg = ['ldapmodify',
               '-h', master.hostname,
               '-p', '389', '-D',
               str(master.config.dirman_dn),  # pylint: disable=no-member
               '-w', master.config.dirman_password,
               '-f', ldif_file]
        master.run_command(arg)

        # uninstall master.
        tasks.uninstall_master(master)

        # master restore.
        dirman_password = master.config.dirman_password
        master.run_command(['ipa-restore', backup_path],
                           stdin_text=dirman_password + '\nyes')

        # re-initialize topology after restore.
        topo_name = "{}-to-{}".format(master.hostname, replica1.hostname)
        for topo_suffix in 'domain', 'ca':
            arg = ['ipa',
                   'topologysegment-reinitialize',
                   topo_suffix,
                   topo_name,
                   '--left']
            replica1.run_command(arg)

        # wait sometime for re-initialization
        tasks.wait_for_replication(replica1.ldap_connect())

        # install second replica after restore
        tasks.install_replica(master, replica2)
        check_replication(master, replica2, "testuser2")


class TestBackupAndRestoreDMPassword(IntegrationTest):
    """Negative tests for incorrect DM password"""
    topology = 'star'

    def test_restore_bad_dm_password(self):
        """backup, uninstall, restore, wrong DM password (expect failure)"""
        with restore_checker(self.master):
            backup_path = backup(self.master)

            # No uninstall, just pure restore, the only case where
            # prompting for the DM password matters.
            result = self.master.run_command(['ipa-restore', backup_path],
                                             stdin_text='badpass\nyes',
                                             raiseonerr=False)
            assert result.returncode == 1

    def test_restore_dirsrv_not_running(self):
        """backup, restore, dirsrv not running (expect failure)"""

        # Flying blind without the restore_checker so we can have
        # an error thrown when dirsrv is down.
        backup_path = backup(self.master)

        self.master.run_command(['ipactl', 'stop'])

        dirman_password = self.master.config.dirman_password
        result = self.master.run_command(
            ['ipa-restore', backup_path],
            stdin_text=dirman_password + '\nyes',
            raiseonerr=False)
        assert result.returncode == 1
