#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths


class TestNTPoptions(IntegrationTest):
    """
    Test NTP Options:
    --no-ntp / -N
    --ntp-server
    --ntp-pool
    """
    num_clients = 1
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        cls.client = cls.clients[0]
        cls.replica = cls.replicas[0]

    def install_client(self, *args):
        cmd = ['ipa-client-install', '-U',
               '--domain', self.client.domain.name,
               '--realm', self.client.domain.realm,
               '-p', self.client.config.admin_name,
               '-w', self.client.config.admin_password,
               '--server', self.master.hostname, *args]
        return self.client.run_command(cmd, raiseonerr=False)

    def install_replica(self, *args):
        cmd = ['ipa-replica-install', '-w', self.master.config.admin_password,
               '-n', self.master.domain.name, '-r', self.master.domain.realm,
               '--server', self.master.hostname, '-U', *args]
        return self.replica.run_command(cmd, raiseonerr=False)

    def test_server_client_install_without_options(self):
        """
        test to verify that ipa-server and ipa-client install uses
        default chrony configuration without any NTP options specified
        """
        expected_msg1 = "No SRV records of NTP servers found and " \
                        "no NTP server or pool address was provided."
        expected_msg2 = "Using default chrony configuration."

        server_install = tasks.install_master(self.master, setup_dns=False)
        assert expected_msg1 in server_install.stderr_text
        assert expected_msg2 in server_install.stdout_text

        client_install = self.install_client()
        assert expected_msg1 in client_install.stderr_text
        assert expected_msg2 in client_install.stdout_text

        self.cleanup()

    def test_server_client_install_no_ntp(self):
        """
        test to verify that ipa-server and ipa-client install invoked with
        option -N uses system defined NTP daemon configuration
        """
        expected_msg1 = "Excluded by options:"
        expected_msg2 = "Using default chrony configuration."

        server_install = tasks.install_master(self.master, setup_dns=False,
                                              extra_args=['-N'])
        assert expected_msg1 in server_install.stdout_text
        assert expected_msg2 not in server_install.stdout_text

        client_install = self.install_client('--no-ntp')
        assert expected_msg2 not in client_install.stdout_text

        self.cleanup()

    def test_server_client_install_with_multiple_ntp_srv(self):
        """
        test to verify that ipa-server-install passes with multiple
        --ntp-server option used
        """
        ntp_server1 = "1.pool.ntp.org"
        ntp_server2 = "2.pool.ntp.org"
        expected_msg = "Configuration of chrony was changed by installer."

        server_install = tasks.install_master(
            self.master, setup_dns=False,
            extra_args=['--ntp-server=%s' % ntp_server1,
                        '--ntp-server=%s' % ntp_server2])
        assert expected_msg in server_install.stderr_text
        cmd = self.master.run_command(['cat', paths.CHRONY_CONF])
        assert ntp_server1 in cmd.stdout_text
        assert ntp_server2 in cmd.stdout_text

        client_install = self.install_client('--ntp-server=%s' % ntp_server1,
                                             '--ntp-server=%s' % ntp_server2)
        assert expected_msg in client_install.stderr_text
        cmd = self.client.run_command(['cat', paths.CHRONY_CONF])
        assert ntp_server1 in cmd.stdout_text
        assert ntp_server2 in cmd.stdout_text

        self.cleanup()

    def test_server_replica_client_install_with_pool_and_srv(self):
        """
        test to verify that ipa-server, ipa-replica and ipa-client install
        passes with options --ntp-pool and --ntp-server together
        """
        ntp_pool = "pool.ntp.org"
        ntp_server = "1.pool.ntp.org"
        expected_msg = "Configuration of chrony was changed by installer."

        server_install = tasks.install_master(
            self.master, setup_dns=False,
            extra_args=['--ntp-pool=%s' % ntp_pool,
                        '--ntp-server=%s' % ntp_server])
        assert expected_msg in server_install.stderr_text
        cmd = self.master.run_command(['cat', paths.CHRONY_CONF])
        assert ntp_pool in cmd.stdout_text
        assert ntp_server in cmd.stdout_text

        replica_install = self.install_replica('--ntp-pool=%s' % ntp_pool,
                                               '--ntp-server=%s' % ntp_server)
        assert expected_msg in replica_install.stderr_text
        cmd = self.replica.run_command(['cat', paths.CHRONY_CONF])
        assert ntp_pool in cmd.stdout_text
        assert ntp_server in cmd.stdout_text

        client_install = self.install_client('--ntp-pool=%s' % ntp_pool,
                                             '--ntp-server=%s' % ntp_server)
        assert expected_msg in client_install.stderr_text
        cmd = self.client.run_command(['cat', paths.CHRONY_CONF])
        assert ntp_pool in cmd.stdout_text
        assert ntp_server in cmd.stdout_text
        tasks.uninstall_master(self.replica)

        self.cleanup()

    def test_server_client_install_mixed_options(self):
        """
        test to verify that ipa-server and ipa-client install with
         --ntp-server and -N options would fail
        """
        ntp_server = "1.pool.ntp.org"
        exp_str = ("error: --ntp-server cannot be used"
                   " together with --no-ntp")
        exp_pool_str = ("error: --ntp-pool cannot be used"
                        " together with --no-ntp")

        args1 = ['ipa-server-install', '-N', '--ntp-server=%s' % ntp_server]
        server_install = self.master.run_command(args1, raiseonerr=False)
        assert server_install.returncode == 2
        assert exp_str in server_install.stderr_text

        args2 = ['ipa-client-install', '-N', '--ntp-server=%s' % ntp_server]
        client_install = self.client.run_command(args2, raiseonerr=False)
        assert client_install.returncode == 2
        assert exp_str in client_install.stderr_text

        args3 = ['ipa-client-install', '-N',
                 '--ntp-pool=%s' % ntp_server.lstrip('1.')]
        client_install = self.client.run_command(args3, raiseonerr=False)
        assert client_install.returncode == 2
        assert exp_pool_str in client_install.stderr_text

    def test_replica_promotion_with_ntp_options(self):
        """
        test to verify that replica promotion with ntp --ntp-server,
         --ntp-pool and -N or --no-ntp option would fail
        """
        ntp_server = "1.pool.ntp.org"
        ntp_pool = "pool.ntp.org"
        exp_str = "NTP configuration cannot be updated during promotion"

        tasks.install_master(self.master, setup_dns=False)
        tasks.install_client(self.master, self.replica)

        try:
            replica_install = self.replica.run_command(
                ['ipa-replica-install', '-N'], raiseonerr=False)
            assert replica_install.returncode == 1
            assert exp_str in replica_install.stderr_text

            replica_install = self.replica.run_command(
                ['ipa-replica-install', '--ntp-server=%s' % ntp_server],
                raiseonerr=False)
            assert replica_install.returncode == 1
            assert exp_str in replica_install.stderr_text

            replica_install = self.replica.run_command(
                ['ipa-replica-install', '--ntp-pool=%s' % ntp_pool],
                raiseonerr=False)
            assert replica_install.returncode == 1
            assert exp_str in replica_install.stderr_text

        finally:
            tasks.uninstall_master(self.replica)
            self.cleanup()

    @pytest.mark.xfail(reason='freeipa ticket 7719', strict=True)
    def test_replica_promotion_without_ntp(self):
        """
        test to verify that replica promotion without ntp options
         - ipa-client install with ntp option
         - ipa-replica without ntp option
        will be successful
        """
        ntp_pool = "pool.ntp.org"
        exp_str = "ipa-replica-install command was successful"

        tasks.install_master(self.master, setup_dns=False)
        tasks.install_client(self.master, self.replica,
                             extra_args=['--ntp-pool=%s' % ntp_pool])

        replica_install = self.replica.run_command(
            ['ipa-replica-install'], raiseonerr=False)
        assert exp_str in replica_install.stderr_text
        cmd = self.replica.run_command(['cat', paths.CHRONY_CONF])
        assert ntp_pool in cmd.stdout_text

        tasks.uninstall_master(self.replica)

    def cleanup(self):
        """
        Uninstall ipa-server and ipa-client
        """
        tasks.uninstall_client(self.client)
        tasks.uninstall_master(self.master)
