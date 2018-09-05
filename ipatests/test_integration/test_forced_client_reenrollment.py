# Authors:
#   Ana Krivokapic <akrivoka@redhat.com>
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

import logging
import os
import subprocess
from ipaplatform.paths import paths
import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

logger = logging.getLogger(__name__)

CLIENT_KEYTAB = paths.KRB5_KEYTAB


class TestForcedClientReenrollment(IntegrationTest):
    """
    Forced client re-enrollment
    http://www.freeipa.org/page/V3/Forced_client_re-enrollment#Test_Plan
    """
    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        super(TestForcedClientReenrollment, cls).install(mh)
        tasks.install_master(cls.master)

        cls.client_dom = cls.clients[0].hostname.split('.', 1)[1]
        if cls.client_dom != cls.master.domain.name:
            # In cases where client is managed by upstream DNS server we
            # overlap its zone so we can save DNS records (e.g. SSHFP) for
            # comparison.
            servers = [cls.master] + cls.replicas
            tasks.add_dns_zone(cls.master, cls.client_dom,
                               skip_overlap_check=True,
                               dynamic_update=True,
                               add_a_record_hosts=servers
                               )

        tasks.install_replica(cls.master, cls.replicas[0], setup_ca=False)
        cls.BACKUP_KEYTAB = os.path.join(
            cls.master.config.test_dir,
            'krb5.keytab'
        )

    def test_reenroll_with_force_join(self, client):
        """
        Client re-enrollment using admin credentials (--force-join)
        """
        sshfp_record_pre = self.get_sshfp_record()
        self.restore_client()
        self.check_client_host_entry()
        self.reenroll_client(force_join=True)
        sshfp_record_post = self.get_sshfp_record()
        assert sshfp_record_pre == sshfp_record_post

    def test_reenroll_with_keytab(self, client):
        """
        Client re-enrollment using keytab
        """
        self.backup_keytab()
        sshfp_record_pre = self.get_sshfp_record()
        self.restore_client()
        self.check_client_host_entry()
        self.restore_keytab()
        self.reenroll_client(keytab=self.BACKUP_KEYTAB)
        sshfp_record_post = self.get_sshfp_record()
        assert sshfp_record_pre == sshfp_record_post

    def test_reenroll_with_both_force_join_and_keytab(self, client):
        """
        Client re-enrollment using both --force-join and --keytab options
        """
        self.backup_keytab()
        sshfp_record_pre = self.get_sshfp_record()
        self.restore_client()
        self.check_client_host_entry()
        self.restore_keytab()
        self.reenroll_client(force_join=True, keytab=self.BACKUP_KEYTAB)
        sshfp_record_post = self.get_sshfp_record()
        assert sshfp_record_pre == sshfp_record_post

    def test_reenroll_to_replica(self, client):
        """
        Client re-enrollment using keytab, to a replica
        """
        self.backup_keytab()
        sshfp_record_pre = self.get_sshfp_record()
        self.restore_client()
        self.check_client_host_entry()
        self.restore_keytab()
        self.reenroll_client(keytab=self.BACKUP_KEYTAB, to_replica=True)
        sshfp_record_post = self.get_sshfp_record()
        assert sshfp_record_pre == sshfp_record_post

    def test_try_to_reenroll_with_disabled_host(self, client):
        """
        Client re-enrollment using keytab, with disabled host
        """
        self.backup_keytab()
        self.disable_client_host_entry()
        self.restore_client()
        self.check_client_host_entry(enabled=False)
        self.restore_keytab()
        self.reenroll_client(keytab=self.BACKUP_KEYTAB, expect_fail=True)

    def test_try_to_reenroll_with_uninstalled_host(self, client):
        """
        Client re-enrollment using keytab, with uninstalled host
        """
        self.backup_keytab()
        self.uninstall_client()
        self.restore_client()
        self.check_client_host_entry(enabled=False)
        self.restore_keytab()
        self.reenroll_client(keytab=self.BACKUP_KEYTAB, expect_fail=True)

    def test_try_to_reenroll_with_deleted_host(self, client):
        """
        Client re-enrollment using keytab, with deleted host
        """
        self.backup_keytab()
        self.delete_client_host_entry()
        self.restore_client()
        self.check_client_host_entry(not_found=True)
        self.restore_keytab()
        self.reenroll_client(keytab=self.BACKUP_KEYTAB, expect_fail=True)

    def test_try_to_reenroll_with_incorrect_keytab(self, client):
        """
        Client re-enrollment using keytab, with incorrect keytab file
        """
        EMPTY_KEYTAB = os.path.join(
            self.clients[0].config.test_dir,
            'empty.keytab'
        )
        self.restore_client()
        self.check_client_host_entry()
        self.clients[0].run_command(['touch', EMPTY_KEYTAB])
        self.reenroll_client(keytab=EMPTY_KEYTAB, expect_fail=True)

    def test_try_to_reenroll_with_empty_keytab(self, client):
        """
        Client re-enrollment with invalid (empty) client keytab file
        """
        self.restore_client()
        self.check_client_host_entry()
        try:
            os.remove(CLIENT_KEYTAB)
        except OSError:
            pass
        self.clients[0].run_command(['touch', CLIENT_KEYTAB])
        self.reenroll_client(force_join=True)

    def uninstall_client(self):
        self.clients[0].run_command(
            ['ipa-client-install', '--uninstall', '-U'],
            set_env=False,
            raiseonerr=False
        )

    def restore_client(self):
        client = self.clients[0]

        client.run_command([
            'iptables',
            '-A', 'INPUT',
            '-j', 'ACCEPT',
            '-p', 'tcp',
            '--dport', '22'
        ])
        for host in [self.master] + self.replicas:
            client.run_command([
                'iptables',
                '-A', 'INPUT',
                '-j', 'REJECT',
                '-p', 'all',
                '--source', host.ip
            ])
        self.uninstall_client()
        client.run_command(['iptables', '-F'])

    def reenroll_client(self, keytab=None, to_replica=False, force_join=False,
                        expect_fail=False):
        server = self.replicas[0] if to_replica else self.master
        client = self.clients[0]

        self.fix_resolv_conf(client, server)

        args = [
            'ipa-client-install', '-U',
            '--server', server.hostname,
            '--domain', server.domain.name
        ]
        if force_join:
            args.append('--force-join')
        if keytab:
            args.extend(['--keytab', keytab])
        else:
            args.extend([
                '-p', client.config.admin_name,
                '-w', client.config.admin_password
            ])

        result = client.run_command(
            args,
            set_env=False,
            raiseonerr=not expect_fail
        )
        assert 'IPA Server: %s' % server.hostname in result.stderr_text

        if expect_fail:
            err_msg = "Kerberos authentication failed: "
            assert result.returncode == 1
            assert err_msg in result.stderr_text
        elif force_join and keytab:
            warn_msg = ("Option 'force-join' has no additional effect "
                        "when used with together with option 'keytab'.")
            assert warn_msg in result.stderr_text

    def check_client_host_entry(self, enabled=True, not_found=False):
        result = self.master.run_command(
            ['ipa', 'host-show', self.clients[0].hostname],
            raiseonerr=not not_found
        )

        if not_found:
            assert result.returncode == 2
            assert 'host not found' in result.stderr_text
        elif enabled:
            assert 'Certificate:' not in result.stdout_text
            assert 'Keytab: True' in result.stdout_text
        else:
            assert 'Certificate:' not in result.stdout_text
            assert 'Keytab: False' in result.stdout_text

    def disable_client_host_entry(self):
        self.master.run_command(
            ['ipa', 'host-disable', self.clients[0].hostname]
        )

    @classmethod
    def delete_client_host_entry(cls):
        try:
            cls.master.run_command(
                ['ipa', 'host-del', cls.clients[0].hostname]
            )
        except subprocess.CalledProcessError as e:
            if e.returncode != 2:
                raise

    def get_sshfp_record(self):
        sshfp_record = ''
        client_host = self.clients[0].hostname.split('.')[0]

        result = self.master.run_command(
            ['ipa', 'dnsrecord-show', self.client_dom, client_host]
        )

        lines = result.stdout_text.splitlines()
        for line in lines:
            if 'SSHFP record:' in line:
                sshfp_record = line.replace('SSHFP record:', '').strip()

        assert sshfp_record, 'SSHFP record not found'

        sshfp_record = set(sshfp_record.split(', '))
        logger.debug("SSHFP record for host %s: %s",
                     client_host, str(sshfp_record))

        return sshfp_record

    def backup_keytab(self):
        contents = self.clients[0].get_file_contents(CLIENT_KEYTAB)
        self.master.put_file_contents(self.BACKUP_KEYTAB, contents)

    def restore_keytab(self):
        contents = self.master.get_file_contents(self.BACKUP_KEYTAB)
        self.clients[0].put_file_contents(self.BACKUP_KEYTAB, contents)

    @classmethod
    def fix_resolv_conf(cls, client, server):
        """
        Put server's ip address at the top of resolv.conf
        """
        contents = client.get_file_contents(paths.RESOLV_CONF,
                                            encoding='utf-8')
        nameserver = 'nameserver %s\n' % server.ip

        if not contents.startswith(nameserver):
            contents = nameserver + contents.replace(nameserver, '')
            client.put_file_contents(paths.RESOLV_CONF, contents)


@pytest.fixture()
def client(request):
    # Here we call "fix_resolv_conf" method before every ipa-client-install so
    # we get the client pointing to ipa master as DNS server.
    request.cls.fix_resolv_conf(request.cls.clients[0], request.cls.master)
    tasks.install_client(request.cls.master, request.cls.clients[0])

    def teardown_client():
        tasks.uninstall_client(request.cls.clients[0])
        request.cls.delete_client_host_entry()
    request.addfinalizer(teardown_client)
