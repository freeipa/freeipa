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
import pytest

from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks as platformtasks
from ipapython.ipaldap import realm_to_serverid
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
    data = dict(re.findall(r"\W*(.+):\W*(.+)\W*", result.stdout_text))
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
    assert re.search(r'^Number of entries returned [1-9]\d*$',
                     result.stdout_text, re.MULTILINE), result.stdout_text
    return result


def check_dns(host):
    result = host.run_command(['host', host.hostname, 'localhost'])
    return result


def check_kinit(host):
    result = host.run_command(['kinit', 'admin'],
                              stdin_text=host.config.admin_password)
    return result


def check_custodia_files(host):
    """regression test for https://pagure.io/freeipa/issue/7247"""
    assert host.transport.file_exists(paths.IPA_CUSTODIA_KEYS)
    assert host.transport.file_exists(paths.IPA_CUSTODIA_CONF)
    return True


def check_pkcs11_modules(host):
    """regression test for https://pagure.io/freeipa/issue/8073"""
    # Return a dictionary with key = filename, value = file content
    # containing all the PKCS11 modules modified by the installer
    result = dict()
    for filename in platformtasks.get_pkcs11_modules():
        assert host.transport.file_exists(filename)
        result[filename] = host.get_file_contents(filename)
    return result


CHECKS = [
    (check_admin_in_ldap, assert_entries_equal),
    (check_admin_in_cli, assert_results_equal),
    (check_admin_in_id, assert_results_equal),
    (check_certs, assert_results_equal),
    (check_dns, assert_results_equal),
    (check_kinit, assert_results_equal),
    (check_custodia_files, assert_deepequal),
    (check_pkcs11_modules, assert_deepequal)
]


@contextlib.contextmanager
def restore_checker(host):
    """Check that the IPA at host works the same at context enter and exit"""
    tasks.kinit_admin(host)

    results = []
    for check, assert_func in CHECKS:
        logger.info('Storing result for %s', check.__name__)
        results.append(check(host))

    yield

    tasks.kinit_admin(host)

    for (check, assert_func), expected in zip(CHECKS, results):
        logger.info('Checking result for %s', check.__name__)
        got = check(host)
        assert_func(expected, got)


def backup(host):
    """Run backup on host, return the path to the backup directory"""
    result = host.run_command(['ipa-backup', '-v'])

    # Test for ticket 7632: check that services are restarted
    # before the backup is compressed
    pattern = r'.*{}.*Starting IPA service.*'.format(paths.GZIP)
    if (re.match(pattern, result.stderr_text, re.DOTALL)):
        raise AssertionError('IPA Services are started after compression')

    # Get the backup location from the command's output
    for line in result.stderr_text.splitlines():
        prefix = 'ipaserver.install.ipa_backup: INFO: Backed up to '
        if line.startswith(prefix):
            backup_path = line[len(prefix):].strip()
            logger.info('Backup path for %s is %s', host.hostname, backup_path)
            return backup_path
    else:
        raise AssertionError('Backup directory not found in output')


@pytest.yield_fixture(scope="function")
def cert_sign_request(request):
    master = request.instance.master
    hosts = [master] + request.instance.replicas
    csrs = {}
    for host in hosts:
        request_path = host.run_command(['mktemp']).stdout_text.strip()
        openssl_command = [
            'openssl', 'req', '-new', '-nodes', '-out', request_path,
            '-subj', '/CN=' + master.hostname
        ]
        host.run_command(openssl_command)
        csrs[host.hostname] = request_path
    yield csrs
    for host in hosts:
        host.run_command(['rm', csrs[host.hostname]])


class TestBackupAndRestore(IntegrationTest):
    topology = 'star'

    def test_full_backup_and_restore(self):
        """backup, uninstall, restore"""
        with restore_checker(self.master):
            backup_path = backup(self.master)

            self.master.run_command(['ipa-server-install',
                                     '--uninstall',
                                     '-U'])
            assert not self.master.transport.file_exists(
                paths.IPA_CUSTODIA_KEYS)
            assert not self.master.transport.file_exists(
                paths.IPA_CUSTODIA_CONF)

            dirman_password = self.master.config.dirman_password
            self.master.run_command(['ipa-restore', backup_path],
                                    stdin_text=dirman_password + '\nyes')

            # check the file permssion and ownership is set to 770 and
            # dirsrv:dirsrv after restore on /var/log/dirsrv/slapd-<instance>
            # related ticket : https://pagure.io/freeipa/issue/7725
            instance = realm_to_serverid(self.master.domain.realm)
            log_path = paths.VAR_LOG_DIRSRV_INSTANCE_TEMPLATE % instance
            cmd = self.master.run_command(['stat', '-c',
                                           '"%a %G:%U"', log_path])
            assert "770 dirsrv:dirsrv" in cmd.stdout_text

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
    """Regression tests for issues 7234 and 7455

    https://pagure.io/freeipa/issue/7234
        - check that oddjobd service is started after restore
        - check new replica  setup after restore
    https://pagure.io/freeipa/issue/7455
        check that after restore and replication reinitialization
            - users and CA data are at state before backup
            - CA can be installed on existing replica
            - new replica with CA can be setup
    """
    num_replicas = 2
    topology = "star"

    @classmethod
    def install(cls, mh):
        cls.replica1 = cls.replicas[0]
        cls.replica2 = cls.replicas[1]
        if cls.domain_level is None:
            domain_level = cls.master.config.domain_level
        else:
            domain_level = cls.domain_level
        # Configure /etc/resolv.conf on each replica to use the master as DNS
        # Otherwise ipa-replica-manage re-initialize is unable to
        # resolve the master name
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.replica1
        )
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.replica2
        )
        # Configure only master and one replica.
        # Replica is configured without CA
        tasks.install_topo(
            cls.topology, cls.master, [cls.replica1],
            cls.clients, domain_level,
            setup_replica_cas=False
        )

    def get_users(self, host):
        res = host.run_command(['ipa', 'user-find'])
        users = set()
        for line in res.stdout_text.splitlines():
            k, _unused, v = line.strip().partition(': ')
            if k == 'User login':
                users.add(v)
        return users

    def check_replication_error(self, host):
        status = r'Error \(19\) Replication error acquiring replica: ' \
                 'Replica has different database generation ID'
        tasks.wait_for_replication(
            host.ldap_connect(), target_status_re=status,
            raise_on_timeout=True)

    def check_replication_success(self, host):
        status = r'Error \(0\) Replica acquired successfully: ' \
                 'Incremental update succeeded'
        tasks.wait_for_replication(
            host.ldap_connect(), target_status_re=status,
            raise_on_timeout=True)

    def request_test_service_cert(self, host, request_path,
                                  expect_connection_error=False):
        res = host.run_command([
            'ipa', 'cert-request', '--principal=TEST/' + self.master.hostname,
            request_path
        ], raiseonerr=not expect_connection_error)
        if expect_connection_error:
            assert (1 == res.returncode and
                    '[Errno 111] Connection refused' in res.stderr_text)

    def test_full_backup_and_restore_with_replica(self, cert_sign_request):
        # check prerequisites
        self.check_replication_success(self.master)
        self.check_replication_success(self.replica1)

        self.master.run_command(
            ['ipa', 'service-add', 'TEST/' + self.master.hostname])

        tasks.user_add(self.master, 'test1_master')
        tasks.user_add(self.replica1, 'test1_replica')

        with restore_checker(self.master):
            backup_path = backup(self.master)

            # change data after backup
            self.master.run_command(['ipa', 'user-del', 'test1_master'])
            self.replica1.run_command(['ipa', 'user-del', 'test1_replica'])
            tasks.user_add(self.master, 'test2_master')
            tasks.user_add(self.replica1, 'test2_replica')

            # simulate master crash
            self.master.run_command(['ipactl', 'stop'])
            tasks.uninstall_master(self.master, clean=False)

            logger.info("Stopping and disabling oddjobd service")
            self.master.run_command([
                "systemctl", "stop", "oddjobd"
            ])
            self.master.run_command([
                "systemctl", "disable", "oddjobd"
            ])

            self.master.run_command(['ipa-restore', '-U', backup_path])

        status = self.master.run_command([
            "systemctl", "status", "oddjobd"
        ])
        assert "active (running)" in status.stdout_text

        # replication should not work after restoration
        # create users to force master and replica to try to replicate
        tasks.user_add(self.master, 'test3_master')
        tasks.user_add(self.replica1, 'test3_replica')
        self.check_replication_error(self.master)
        self.check_replication_error(self.replica1)
        assert {'admin', 'test1_master', 'test1_replica', 'test3_master'} == \
            self.get_users(self.master)
        assert {'admin', 'test2_master', 'test2_replica', 'test3_replica'} == \
            self.get_users(self.replica1)

        # reestablish and check replication
        self.replica1.run_command(['ipa-replica-manage', 're-initialize',
                                  '--from', self.master.hostname])
        # create users to force master and replica to try to replicate
        tasks.user_add(self.master, 'test4_master')
        tasks.user_add(self.replica1, 'test4_replica')
        self.check_replication_success(self.master)
        self.check_replication_success(self.replica1)
        assert {'admin', 'test1_master', 'test1_replica',
                'test3_master', 'test4_master', 'test4_replica'} == \
            self.get_users(self.master)
        assert {'admin', 'test1_master', 'test1_replica',
                'test3_master', 'test4_master', 'test4_replica'} == \
            self.get_users(self.replica1)

        # CA on master should be accesible from master and replica
        self.request_test_service_cert(
            self.master, cert_sign_request[self.master.hostname])
        self.request_test_service_cert(
            self.replica1, cert_sign_request[self.replica1.hostname])

        # replica should not be able to sign certificates without CA on master
        self.master.run_command(['ipactl', 'stop'])
        try:
            self.request_test_service_cert(
                self.replica1, cert_sign_request[self.replica1.hostname],
                expect_connection_error=True)
        finally:
            self.master.run_command(['ipactl', 'start'])

        tasks.install_ca(self.replica1)

        # now replica should be able to sign certificates without CA on master
        self.master.run_command(['ipactl', 'stop'])
        self.request_test_service_cert(
            self.replica1, cert_sign_request[self.replica1.hostname])
        self.master.run_command(['ipactl', 'start'])

        # check installation of new replica
        tasks.install_replica(self.master, self.replica2, setup_ca=True)
        check_replication(self.master, self.replica2, "testuser")

        # new replica should be able to sign certificates without CA on master
        # and old replica
        self.master.run_command(['ipactl', 'stop'])
        self.replica1.run_command(['ipactl', 'stop'])
        try:
            self.request_test_service_cert(
                self.replica2, cert_sign_request[self.replica2.hostname])
        finally:
            self.replica1.run_command(['ipactl', 'start'])
            self.master.run_command(['ipactl', 'start'])


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
        # disable replication agreement
        tasks.ldapmodify_dm(master, entry_ldif)

        # uninstall master.
        tasks.uninstall_master(master, clean=False)

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
