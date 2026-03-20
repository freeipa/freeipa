#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

"""Tests for NFS automount access by AD trusted users.

This module verifies that AD trusted users (from both a top-level AD domain
and a child subdomain) can access Kerberized NFS mounts configured via IPA
automount. It covers allow/deny scenarios for read-only and read-write NFS
exports, ownership-based access control, and a BZ1028422 regression test
for SSSD autofs map retrieval with default_domain_suffix.
"""

from __future__ import absolute_import

import time

import pytest

from ipatests.test_integration.test_trust import BaseTestTrust
from ipatests.pytest_ipa.integration import tasks

AD_USER1 = 'aduser1'
AD_USER2 = 'aduser2'
AD_PASSWORD = 'Secret123'

AUTOMOUNT_LOCATION = 'trust_location'
AUTOMOUNT_INDIRECT_MAP = 'auto.share'
AUTOMOUNT_INDIRECT_MOUNTPOINT = '/automnt.d'
AUTOMOUNT_DIRECT_KEY = '/automnt2.d/aduser2'
EXPORT_RW_DIR = '/export'
EXPORT_RO_DIR = '/export2/aduser2'

WAIT_AFTER_SSSD_RESTART = 10
WAIT_AFTER_AUTOMOUNT_LOCATION = 5


def run_as_ad_user(host, user, domain, command, **kwargs):
    """Run a shell command on host as user@domain via su -l."""
    return tasks.run_command_as_user(
        host, f'{user}@{domain}', command, **kwargs
    )


def kinit_ad_user(host, user, domain, realm, password=AD_PASSWORD):
    """Obtain a Kerberos ticket for an AD user via su -l."""
    run_as_ad_user(
        host, user, domain,
        f'echo {password} | kinit {user}@{realm}'
    )


def umount_and_restart_autofs(host, mountpoint):
    """Unmount a stale NFS mount and restart autofs."""
    host.run_command(['umount', mountpoint], raiseonerr=False)
    host.run_command(['systemctl', 'restart', 'autofs'])


class TestTrustAutomount(BaseTestTrust):
    """Tests for NFS automount access by AD top-domain trusted users."""

    num_ad_subdomains = 0
    num_ad_treedomains = 0

    @classmethod
    def install(cls, mh):
        super(TestTrustAutomount, cls).install(mh)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(
            cls.master, cls.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.clear_sssd_cache(cls.master)

        cls.nfs_ad_domain = cls.ad_domain
        cls.nfs_ad_realm = cls.ad_domain.upper()

    @classmethod
    def uninstall(cls, mh):
        tasks.kinit_admin(cls.master, raiseonerr=False)
        cls.master.run_command(
            ['ipa', 'automountlocation-del', AUTOMOUNT_LOCATION],
            raiseonerr=False)
        cls.master.run_command(
            ['rm', '-rf', EXPORT_RW_DIR, '/export2'],
            raiseonerr=False)
        cls.clients[0].run_command(
            ['ipa-client-automount', '--uninstall', '-U'],
            raiseonerr=False)
        cls.master.run_command(
            ['systemctl', 'stop', 'nfs-server'], raiseonerr=False)
        cls.master.run_command(
            ['systemctl', 'stop', 'rpc-gssd.service'],
            raiseonerr=False)
        cls.master.run_command(
            ['systemctl', 'restart', 'gssproxy'], raiseonerr=False)
        tasks.clear_sssd_cache(cls.master)
        tasks.unconfigure_dns_for_trust(cls.master, cls.ad)
        super(TestTrustAutomount, cls).uninstall(mh)

    def test_bug_1028422_automount_default_domain_suffix(self):
        """SSSD retrieves auto.master with default_domain_suffix.

        Regression test for https://bugzilla.redhat.com/show_bug.cgi?id=1028422
        and https://bugzilla.redhat.com/show_bug.cgi?id=1036157.
        Verifies that SSSD can retrieve autofs maps when
        default_domain_suffix is set in sssd.conf.
        """
        master = self.master
        client = self.clients[0]
        sssd_conf = '/etc/sssd/sssd.conf'
        nsswitch_conf = '/etc/nsswitch.conf'

        result = master.run_command(['ipa', 'trust-find'])
        assert self.nfs_ad_domain in result.stdout_text

        tasks.clear_sssd_cache(master)
        time.sleep(WAIT_AFTER_SSSD_RESTART)

        tasks.clear_sssd_cache(client)
        time.sleep(WAIT_AFTER_SSSD_RESTART)

        client.run_command(
            ['getent', 'passwd', f'{AD_USER1}@{self.nfs_ad_domain}'])

        with tasks.FileBackup(client, sssd_conf), \
             tasks.FileBackup(client, nsswitch_conf):
            client.run_command([
                'sed', '-i',
                f'/\\[sssd\\]/ a default_domain_suffix = '
                f'{self.nfs_ad_domain}',
                sssd_conf
            ])
            client.run_command([
                'sed', '-i', 's/services.*/&, autofs/g', sssd_conf
            ])
            client.run_command([
                'sed', '-i', 's/automount:.*/automount:  sss files/',
                nsswitch_conf
            ])

            result = client.run_command(
                ['grep', '-A3', '\\[sssd\\]', sssd_conf])
            assert 'default_domain_suffix' in result.stdout_text

            tasks.clear_sssd_cache(client)
            time.sleep(WAIT_AFTER_SSSD_RESTART)
            client.run_command(['systemctl', 'restart', 'autofs'])

            client.run_command(['getent', 'passwd', AD_USER1])

            result = client.run_command(['automount', '-m'])
            assert ('setautomntent' not in result.stdout_text
                    or 'No such file or directory'
                    not in result.stdout_text)
            assert 'autofs dump map information' in result.stdout_text
            assert 'Mount point: /-' in result.stdout_text

            log_result = client.run_command(
                ['cat', '/var/log/sssd/sssd_autofs.log'],
                raiseonerr=False)
            if log_result.returncode == 0:
                assert 'failed' not in log_result.stdout_text.lower()

        client.run_command(['systemctl', 'restart', 'sssd'])
        client.run_command(['systemctl', 'restart', 'autofs'])

    def test_automount_nfs_setup(self):
        """Set up NFS server on master and automount on client."""
        master = self.master
        client = self.clients[0]
        domain = self.nfs_ad_domain
        ad_user1 = f'{AD_USER1}@{domain}'
        ad_user2 = f'{AD_USER2}@{domain}'

        master.run_command(
            ['dnf', '-y', 'install', 'gssproxy'], raiseonerr=False)

        tasks.kinit_admin(master)

        nfs_principal = f'nfs/{master.hostname}'

        result = master.run_command(
            ['ipa', 'service-show', nfs_principal], raiseonerr=False)
        if result.returncode != 0:
            master.run_command(['ipa', 'service-add', nfs_principal])

        result = master.run_command(
            ['klist', '-ket', '/etc/krb5.keytab'], raiseonerr=False)
        if nfs_principal not in result.stdout_text:
            master.run_command([
                'ipa-getkeytab', '-k', '/etc/krb5.keytab',
                '-s', master.hostname, '-p', nfs_principal
            ])

        master.run_command([
            'sh', '-c',
            'echo \'SECURE_NFS="yes"\' >> /etc/sysconfig/nfs'
        ], raiseonerr=False)

        # RW export for aduser1
        master.run_command(['mkdir', '-p', '/export/aduser1'])
        master.run_command(['chmod', '770', '/export/aduser1'])
        master.run_command(
            ['chown', f'{ad_user1}:{ad_user1}', '/export/aduser1'])
        master.run_command([
            'sh', '-c',
            'echo "/export  *(rw,sec=krb5:krb5i:krb5p)" > /etc/exports'
        ])
        master.run_command([
            'sh', '-c',
            'echo "Read-Write-Test" > /export/aduser1/rw_test'
        ])
        master.run_command(
            ['chown', f'{ad_user1}:{ad_user1}', '/export/aduser1/rw_test'])
        master.run_command(['chmod', '664', '/export/aduser1/rw_test'])

        # RO export for aduser2
        master.run_command(['mkdir', '-p', '/export2/aduser2'])
        master.run_command(['chmod', '770', '/export2/aduser2'])
        master.run_command(
            ['chown', f'{ad_user2}:{ad_user2}', '/export2/aduser2'])
        master.run_command([
            'sh', '-c',
            'echo "/export2/aduser2  *(ro,sec=krb5:krb5i:krb5p)"'
            ' >> /etc/exports'
        ])
        master.run_command([
            'sh', '-c',
            'echo "Read-Only-Test" > /export2/aduser2/ro_test'
        ])
        master.run_command(
            ['chown', f'{ad_user2}:{ad_user2}', '/export2/aduser2/ro_test'])
        master.run_command(['chmod', '664', '/export2/aduser2/ro_test'])

        master.run_command(['systemctl', 'restart', 'nfs-server'])
        master.run_command(['systemctl', 'restart', 'rpc-gssd.service'])
        master.run_command(['systemctl', 'restart', 'gssproxy'])
        master.run_command(['exportfs', '-a'])

        # IPA automount location and maps
        master.run_command(
            ['ipa', 'automountlocation-add', AUTOMOUNT_LOCATION])
        master.run_command([
            'ipa', 'automountmap-add-indirect', AUTOMOUNT_LOCATION,
            AUTOMOUNT_INDIRECT_MAP,
            f'--mount={AUTOMOUNT_INDIRECT_MOUNTPOINT}',
            '--parentmap=auto.master'
        ])
        master.run_command([
            'ipa', 'automountkey-add', AUTOMOUNT_LOCATION,
            AUTOMOUNT_INDIRECT_MAP,
            '--key=*',
            f'--info=-rw,soft,fstype=nfs4,sec=krb5 '
            f'{master.hostname}:{EXPORT_RW_DIR}/&'
        ])
        master.run_command([
            'ipa', 'automountkey-add', AUTOMOUNT_LOCATION, 'auto.direct',
            f'--key={AUTOMOUNT_DIRECT_KEY}',
            f'--info=-rw,fstype=nfs4,sec=krb5 '
            f'{master.hostname}:{EXPORT_RO_DIR}'
        ])

        time.sleep(WAIT_AFTER_AUTOMOUNT_LOCATION)

        client.run_command([
            'ipa-client-automount',
            f'--server={master.hostname}',
            f'--location={AUTOMOUNT_LOCATION}', '-U'
        ])

    def test_allow_ad_user_nfs_mount(self):
        """AD user with valid Kerberos ticket can write and read NFS mount."""
        client = self.clients[0]
        master = self.master
        domain = self.nfs_ad_domain
        realm = self.nfs_ad_realm
        marker = 'mytest.allow_ad_user_nfs_mount'

        client.run_command(
            ['umount', f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1'],
            raiseonerr=False)

        kinit_ad_user(client, AD_USER1, domain, realm)

        run_as_ad_user(
            client, AD_USER1, domain,
            f'cd {AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1; ls -ltra')

        run_as_ad_user(
            client, AD_USER1, domain,
            f'echo {marker} > {AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1/tfile')

        result = run_as_ad_user(
            client, AD_USER1, domain,
            f'cat {AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1/tfile')
        assert marker in result.stdout_text

        result = master.run_command(['cat', '/export/aduser1/tfile'])
        assert marker in result.stdout_text

    def test_deny_ad_user_nfs_mount_no_ticket(self):
        """AD user without Kerberos ticket is denied NFS access."""
        client = self.clients[0]
        domain = self.nfs_ad_domain

        umount_and_restart_autofs(client, AUTOMOUNT_DIRECT_KEY)

        run_as_ad_user(client, AD_USER1, domain, 'kdestroy -A')

        result = run_as_ad_user(
            client, AD_USER1, domain,
            f'cd {AUTOMOUNT_DIRECT_KEY}',
            raiseonerr=False)
        assert result.returncode != 0
        output = result.stdout_text + result.stderr_text
        assert 'Permission denied' in output

        result = client.run_command(['mount'])
        assert f'{self.master.hostname}:{EXPORT_RO_DIR}' in result.stdout_text

    def test_allow_ad_user_read_ro_nfs(self):
        """AD user can read files on read-only NFS mount."""
        client = self.clients[0]
        domain = self.nfs_ad_domain
        realm = self.nfs_ad_realm

        umount_and_restart_autofs(client, AUTOMOUNT_DIRECT_KEY)

        kinit_ad_user(client, AD_USER2, domain, realm)

        result = run_as_ad_user(
            client, AD_USER2, domain,
            f'cat {AUTOMOUNT_DIRECT_KEY}/ro_test')
        assert 'Read-Only-Test' in result.stdout_text

    def test_deny_ad_user_write_ro_nfs(self):
        """AD user cannot write to read-only NFS mount."""
        client = self.clients[0]
        domain = self.nfs_ad_domain
        realm = self.nfs_ad_realm

        umount_and_restart_autofs(client, AUTOMOUNT_DIRECT_KEY)

        kinit_ad_user(client, AD_USER2, domain, realm)

        result = run_as_ad_user(
            client, AD_USER2, domain,
            f'date >> {AUTOMOUNT_DIRECT_KEY}/ro_test',
            raiseonerr=False)
        assert result.returncode != 0
        output = result.stdout_text + result.stderr_text
        assert 'Read-only file system' in output

    def test_allow_ad_user_read_rw_nfs(self):
        """AD user can read files on read-write NFS mount."""
        client = self.clients[0]
        domain = self.nfs_ad_domain
        realm = self.nfs_ad_realm

        umount_and_restart_autofs(
            client, f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1')

        kinit_ad_user(client, AD_USER1, domain, realm)

        result = run_as_ad_user(
            client, AD_USER1, domain,
            f'cat {AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1/rw_test')
        assert 'Read-Write-Test' in result.stdout_text

    def test_write_rw_nfs_ownership(self):
        """Different AD user cannot write to another user's rw directory.

        aduser2 attempts to write to aduser1's directory and is denied.
        """
        client = self.clients[0]
        domain = self.nfs_ad_domain
        realm = self.nfs_ad_realm

        umount_and_restart_autofs(
            client, f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1')

        run_as_ad_user(client, AD_USER2, domain, 'kdestroy -A')
        kinit_ad_user(client, AD_USER2, domain, realm)

        result = run_as_ad_user(
            client, AD_USER2, domain,
            f'echo New-RW-Test >> '
            f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1/rw_test',
            raiseonerr=False)
        assert result.returncode != 0
        output = result.stdout_text + result.stderr_text
        assert 'Permission denied' in output

        result = run_as_ad_user(
            client, AD_USER2, domain,
            f'cat {AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1/rw_test',
            raiseonerr=False)
        assert result.returncode != 0
        output = result.stdout_text + result.stderr_text
        assert 'Permission denied' in output


class TestTrustAutomountSubdomain(TestTrustAutomount):
    """Tests for NFS automount access by AD subdomain trusted users.

    Inherits all test methods from TestTrustAutomount but targets the
    AD child subdomain instead of the top-level domain.

    test_write_rw_nfs_ownership has intentionally DIFFERENT behavior:
    in the subdomain variant, aduser1 CAN write to its own rw mount
    (asserts success), unlike the top-domain variant where aduser2 is
    denied.
    """

    num_ad_subdomains = 1

    @classmethod
    def install(cls, mh):
        super(TestTrustAutomountSubdomain, cls).install(mh)
        cls.nfs_ad_domain = cls.ad_subdomain
        cls.nfs_ad_realm = cls.ad_subdomain.upper()

    def test_bug_1028422_automount_default_domain_suffix(self):
        """Skip BZ1028422 test for subdomain -- already covered by
        TestTrustAutomount."""
        pytest.skip('BZ1028422 already tested with top-level AD domain')

    def test_write_rw_nfs_ownership(self):
        """Subdomain aduser1 CAN write to its own rw directory.

        Unlike the top-domain variant, this test verifies that aduser1
        from the subdomain can append to its own rw mount successfully.
        """
        client = self.clients[0]
        domain = self.nfs_ad_domain
        realm = self.nfs_ad_realm

        umount_and_restart_autofs(
            client, f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1')

        run_as_ad_user(client, AD_USER1, domain, 'kdestroy -A')
        kinit_ad_user(client, AD_USER1, domain, realm)

        run_as_ad_user(
            client, AD_USER1, domain,
            f'echo New-RW-Test >> '
            f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1/rw_test')

        result = run_as_ad_user(
            client, AD_USER1, domain,
            f'cat {AUTOMOUNT_INDIRECT_MOUNTPOINT}/aduser1/rw_test')
        assert 'New-RW-Test' in result.stdout_text
