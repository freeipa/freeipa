#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests that uninstallation is successful.

It is important not to leave the remote system in an inconsistent
state. Every failed uninstall should successfully remove remaining
pieces if possible.
"""

from __future__ import absolute_import

from difflib import unified_diff
import os

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths
from ipapython.ipaldap import realm_to_serverid

# from ipaserver.install.dsinstance
DS_INSTANCE_PREFIX = 'slapd-'


class TestUninstallBase(IntegrationTest):

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_uninstall_client_invalid_hostname(self):

        # using replica as client just for convenience
        client = self.replicas[0]
        client_inv_hostname = '{}.nonexistent'.format(client.hostname)
        tasks.install_client(self.master, client,
                             extra_args=['--hostname', client_inv_hostname],
                             nameservers=None)

        client.run_command(['ipa-client-install', '--uninstall', '-U'])
        client_uninstall_log = client.get_file_contents(
            paths.IPACLIENT_UNINSTALL_LOG, encoding='utf-8'
        )
        assert "exception: ScriptError:" not in client_uninstall_log

        restore_state_path = os.path.join(paths.IPA_CLIENT_SYSRESTORE,
                                          'sysrestore.state')
        result = client.run_command(
            ['ls', restore_state_path], raiseonerr=False)
        assert 'No such file or directory' in result.stderr_text

    def test_install_uninstall_replica(self):
        # Test that the sequence install replica / uninstall replica
        # properly removes the line
        # Include /etc/httpd/conf.d/ipa-rewrite.conf
        # from ssl.conf on the replica
        tasks.install_replica(self.master, self.replicas[0],
                              extra_args=['--force-join'], nameservers=None)
        tasks.uninstall_replica(self.master, self.replicas[0])
        errline = b'Include /etc/httpd/conf.d/ipa-rewrite.conf'
        ssl_conf = self.replicas[0].get_file_contents(paths.HTTPD_SSL_CONF)
        assert errline not in ssl_conf

    def test_failed_uninstall(self):
        self.master.run_command(['ipactl', 'stop'])

        serverid = realm_to_serverid(self.master.domain.realm)
        instance_name = ''.join([DS_INSTANCE_PREFIX, serverid])

        try:
            # Moving the DS instance out of the way will cause the
            # uninstaller to raise an exception and return with a
            # non-zero return code.
            self.master.run_command([
                '/bin/mv',
                '%s/%s' % (paths.ETC_DIRSRV, instance_name),
                '%s/%s.test' % (paths.ETC_DIRSRV, instance_name)
            ])

            cmd = self.master.run_command([
                'ipa-server-install',
                '--uninstall', '-U'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
        finally:
            # Be paranoid. If something really went wrong then DS may
            # be marked as uninstalled so server cert will still be
            # tracked and the instances may remain. This can cause
            # subsequent installations to fail so be thorough.
            dashed_domain = self.master.domain.realm.replace(".", '-')
            dirsrv_service = "dirsrv@%s.service" % dashed_domain
            self.master.run_command(['systemctl', 'stop', dirsrv_service])

            # Moving it back should allow the uninstall to finish
            # successfully.
            self.master.run_command([
                '/bin/mv',
                '%s/%s.test' % (paths.ETC_DIRSRV, instance_name),
                '%s/%s' % (paths.ETC_DIRSRV, instance_name)
            ])

            cmd = self.master.run_command([
                'ipa-server-install',
                '--uninstall', '-U'],
                raiseonerr=False
            )
            assert cmd.returncode == 0

            self.master.run_command([
                paths.IPA_GETCERT,
                'stop-tracking',
                '-d', '%s/%s' % (paths.ETC_DIRSRV, instance_name),
                '-n', 'Server-Cert',
            ])

            self.master.run_command([
                paths.DSCTL, serverid, 'remove', '--do-it'
            ])


class TestUninstallWithoutDNS(IntegrationTest):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_uninstall_server_without_dns(self):
        """Test if server setup without dns uninstall properly

        IPA server uninstall was failing if dns was not setup.
        This test check if it uninstalls properly.

        related: https://pagure.io/freeipa/issue/8630
        """
        tasks.uninstall_master(self.master)


class TestUninstallCleanup(IntegrationTest):
    """Test installer hostname validator."""

    num_replicas = 0
    before = None
    after = None

    @classmethod
    def install(cls, mh):
        # These create files on first start
        for svc in ('certmonger', 'sssd',):
            cls.master.run_command(['systemctl', 'start', svc])
        cls.before = cls.master.run_command(
            "find /etc/ /run/ /var/ /root/ -mount | sort"
        ).stdout_text.split('\n')
        tasks.install_master(cls.master, setup_dns=True,
                             setup_kra=True)
        tasks.install_dns(
            cls.master,
            extra_args=['--dnssec-master', '--no-dnssec-validation']
        )

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_clean_uninstall(self):
        tasks.uninstall_master(self.master)
        self.after = self.master.run_command(
            "find /etc/ /run/ /var/ /root/ -mount | sort"
        ).stdout_text.split('\n')

        diff = unified_diff(self.before, self.after,
                            fromfile='before', tofile='after')
        ALLOW_LIST = [
            '/var/log',
            '/var/tmp/systemd-private',
            '/run/systemd',
            '/run/log/journal',
            '/var/lib/authselect/backups/pre_ipaclient',
            '/var/named/data/named.run',
            paths.DNSSEC_SOFTHSM_PIN_SO,  # See commit eb54814741
            '/etc/selinux/targeted/contexts/files/file_contexts.local.bin',
            paths.SSSD_CONF_DELETED,  # See commit dd72ed6212
            '/root/.cache',
            '/root/.dogtag',
            '/root/.local',
            '/run/dirsrv',
            '/run/lock/dirsrv',
            '/var/lib/authselect/backups',
            '/var/lib/gssproxy/rcache/krb5_0.rcache2',
            '/var/lib/ipa/ipa-kasp.db.backup',
            '/var/lib/selinux/targeted/active/booleans.local',
            '/var/lib/selinux/targeted/active/file_contexts.local',
            '/var/lib/sss/pubconf/krb5.include.d/krb5_libdefaults',
            '/var/lib/sss/pubconf/krb5.include.d/localauth_plugin',
            '/var/named/dynamic/managed-keys.bind',
            '/var/named/dynamic/managed-keys.bind.jnl',
            '/var/lib/systemd/coredump/',
        ]

        leftovers = []
        for line in diff:
            line = line.strip()
            if line.startswith('+'):
                if line.endswith('log'):
                    continue
                if line.startswith('+++ after'):
                    continue
                found = False
                for s in ALLOW_LIST:
                    if s in line:
                        found = True
                        break
                if found:
                    continue
                leftovers.append(line)

        assert len(leftovers) == 0


class TestUninstallReinstall(IntegrationTest):
    """Test install, uninstall, re-install.

       Reinstall with PKI 11.6.0 was failing
       https://pagure.io/freeipa/issue/9673
    """

    num_replicas = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_uninstall_server(self):
        tasks.uninstall_master(self.master)

    def test_reinstall_server(self):
        tasks.install_master(self.master, setup_dns=False)
