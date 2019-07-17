#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
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

    ntp_pool = "pool.ntp.org"
    ntp_server1 = "1.pool.ntp.org"
    ntp_server2 = "2.pool.ntp.org"

    print_chrony_conf = ['cat', paths.CHRONY_CONF]

    exp_records_msg = "No SRV records of NTP servers found and " \
                      "no NTP server or pool address was provided."
    exp_chrony_msg = "Using default chrony configuration."

    @classmethod
    def install(cls, mh):
        cls.client = cls.clients[0]
        cls.replica = cls.replicas[0]

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

        client_install = tasks.install_client(self.master, self.client)

        assert expected_msg1 in client_install.stderr_text
        assert expected_msg2 in client_install.stdout_text

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

        client_install = tasks.install_client(self.master, self.client,
                                              extra_args=['--no-ntp'])
        assert expected_msg2 not in client_install.stdout_text

    def test_server_client_install_with_multiple_ntp_srv(self):
        """
        test to verify that ipa-server-install passes with multiple
        --ntp-server option used
        """
        expected_msg = "Configuration of chrony was changed by installer."
        args = ['--ntp-server=%s' % self.ntp_server1,
                '--ntp-server=%s' % self.ntp_server2]

        server_install = tasks.install_master(self.master, setup_dns=False,
                                              extra_args=args)
        assert expected_msg in server_install.stderr_text
        cmd = self.master.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_server1 in cmd.stdout_text
        assert self.ntp_server2 in cmd.stdout_text

        client_install = tasks.install_client(self.master, self.client,
                                              extra_args=args)
        assert expected_msg in client_install.stderr_text
        cmd = self.client.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_server1 in cmd.stdout_text
        assert self.ntp_server2 in cmd.stdout_text

    def test_server_replica_client_install_with_pool_and_srv(self):
        """
        test to verify that ipa-server, ipa-replica and ipa-client install
        passes with options --ntp-pool and --ntp-server together
        """
        expected_msg = "Configuration of chrony was changed by installer."
        args = ['--ntp-pool=%s' % self.ntp_pool,
                '--ntp-server=%s' % self.ntp_server1]

        server_install = tasks.install_master(self.master, setup_dns=False,
                                              extra_args=args)
        assert expected_msg in server_install.stderr_text
        cmd = self.master.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_pool in cmd.stdout_text
        assert self.ntp_server1 in cmd.stdout_text

        replica_install = tasks.install_replica(self.master, self.replica,
                                                extra_args=args,
                                                promote=False)
        assert expected_msg in replica_install.stderr_text

        cmd = self.replica.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_pool in cmd.stdout_text
        assert self.ntp_server1 in cmd.stdout_text

        client_install = tasks.install_client(self.master, self.client,
                                              extra_args=args)
        assert expected_msg in client_install.stderr_text
        cmd = self.client.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_pool in cmd.stdout_text
        assert self.ntp_server1 in cmd.stdout_text

    def test_server_promoted_replica_client_install_with_srv(self):
        """
        test to verify that ipa-server, promotion of ipa-replica and
        ipa-client install passes with options --ntp-server
        """
        expected_msg = "Configuration of chrony was changed by installer."
        args = ['--ntp-server=%s' % self.ntp_server1]

        server_install = tasks.install_master(self.master, setup_dns=False,
                                              extra_args=args)
        assert expected_msg in server_install.stderr_text
        cmd = self.master.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_server1 in cmd.stdout_text

        replica_install = tasks.install_replica(self.master, self.replica,
                                                extra_args=args,
                                                promote=True)
        # while promoting with tasks expected_msg will not be in output
        assert expected_msg not in replica_install.stderr_text

        cmd = self.replica.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_server1 in cmd.stdout_text

        client_install = tasks.install_client(self.master, self.client,
                                              extra_args=args)
        assert expected_msg in client_install.stderr_text
        cmd = self.client.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_server1 in cmd.stdout_text

    def test_server_client_install_mixed_options(self):
        """
        test to verify that ipa-server and ipa-client install with
        --ntp-server and -N options would fail
        """
        exp_str = ("error: --ntp-server cannot be used"
                   " together with --no-ntp")
        exp_pool_str = ("error: --ntp-pool cannot be used"
                        " together with --no-ntp")

        args1 = ['ipa-server-install', '-N',
                 '--ntp-server=%s' % self.ntp_server1]
        server_install = self.master.run_command(args1, raiseonerr=False)
        assert server_install.returncode == 2
        assert exp_str in server_install.stderr_text

        args2 = ['ipa-client-install', '--no-ntp',
                 '--ntp-server=%s' % self.ntp_server2]
        client_install = self.client.run_command(args2, raiseonerr=False)
        assert client_install.returncode == 2
        assert exp_str in client_install.stderr_text

        args3 = ['ipa-client-install', '-N',
                 '--ntp-pool=%s' % self.ntp_pool]
        client_install = self.client.run_command(args3, raiseonerr=False)
        assert client_install.returncode == 2
        assert exp_pool_str in client_install.stderr_text

    def test_replica_promotion_with_ntp_options(self):
        """
        test to verify that replica promotion with ntp --ntp-server,
        --ntp-pool and -N or --no-ntp option would fail
        """
        exp_str = "NTP configuration cannot be updated during promotion"

        tasks.install_master(self.master, setup_dns=False)
        tasks.install_client(self.master, self.replica)

        replica_install = self.replica.run_command(
            ['ipa-replica-install', '--no-ntp'],
            raiseonerr=False)
        assert replica_install.returncode == 1
        assert exp_str in replica_install.stderr_text

        replica_install = self.replica.run_command(
            ['ipa-replica-install', '--ntp-server=%s' % self.ntp_server1],
            raiseonerr=False)
        assert replica_install.returncode == 1
        assert exp_str in replica_install.stderr_text

        replica_install = self.replica.run_command(
            ['ipa-replica-install', '--ntp-pool=%s' % self.ntp_pool],
            raiseonerr=False)
        assert replica_install.returncode == 1
        assert exp_str in replica_install.stderr_text

    def test_replica_promotion_without_ntp(self):
        """
        test to verify that replica promotion without ntp options
        - ipa-client-install with ntp option
        - ipa-replica-install without ntp option
        will be successful
        """
        exp_str = "ipa-replica-install command was successful"
        expected_msg = "Configuration of chrony was changed by installer."
        ntp_args = ['--ntp-pool=%s' % self.ntp_pool]

        server_install = tasks.install_master(self.master, setup_dns=False,
                                              extra_args=ntp_args)
        assert expected_msg in server_install.stderr_text

        client_install = tasks.install_client(self.master, self.replica,
                                              extra_args=ntp_args)
        assert expected_msg in client_install.stderr_text

        replica_install = tasks.install_replica(self.master, self.replica,
                                                promote=False)
        assert exp_str in replica_install.stderr_text

        cmd = self.replica.run_command(['cat', paths.CHRONY_CONF])
        assert self.ntp_pool in cmd.stdout_text

    def test_interactive_ntp_set_opt(self):
        """
        Test to verify that ipa installations with ntp options passed
        interactively (without -U/--nattended) will be successful
        - ipa-server-install
        - ipa-client-install
        Both NTP servers and pool passed interactively to options.
        """
        server_input = (
            # Do you want to configure integrated DNS (BIND)? [no]:
            "No\n"
            # Server host name [hostname]:
            "\n"
            # Do you want to configure chrony with NTP server
            #   or pool address? [no]:
            "Yes\n"
            # Enter NTP source server addresses separated by comma,
            #   or press Enter to skip:
            "{},{}\n".format(self.ntp_server2, self.ntp_server1) +
            # Enter a NTP source pool address, or press Enter to skip:
            "{}\n".format(self.ntp_pool) +
            # Continue to configure the system with these values? [no]:
            "Yes"
        )

        client_input = (
            # Proceed with fixed values and no DNS discovery? [no]:
            "Yes\n"
            # Do you want to configure chrony with NTP server
            #   or pool address? [no]:
            "Yes\n"
            # Enter NTP source server addresses separated by comma,
            #   or press Enter to skip:
            "{},{}\n".format(self.ntp_server2, self.ntp_server1) +
            # Enter a NTP source pool address, or press Enter to skip:
            "{}\n".format(self.ntp_pool) +
            # Continue to configure the system with these values? [no]:
            "Yes"
        )

        server_install = tasks.install_master(self.master,
                                              setup_dns=False,
                                              unattended=False,
                                              stdin_text=server_input)

        assert server_install.returncode == 0
        assert self.ntp_pool in server_install.stdout_text
        assert self.ntp_server1 in server_install.stdout_text
        assert self.ntp_server2 in server_install.stdout_text

        cmd = self.master.run_command(self.print_chrony_conf)
        assert self.ntp_pool in cmd.stdout_text
        assert self.ntp_server1 in cmd.stdout_text
        assert self.ntp_server2 in cmd.stdout_text

        client_install = tasks.install_client(self.master,
                                              self.client,
                                              unattended=False,
                                              stdin_text=client_input)

        assert client_install.returncode == 0

        cmd = self.client.run_command(self.print_chrony_conf)
        assert self.ntp_pool in cmd.stdout_text
        assert self.ntp_server1 in cmd.stdout_text
        assert self.ntp_server2 in cmd.stdout_text

    def test_interactive_ntp_no_opt(self):
        """
        Test to verify that ipa installations without ntp options passed
        interactively (without -U/--nattended) will be successful
        - ipa-server-install
        - ipa-client-install
        Both NTP servers and pool configuration skipped interactively.
        """

        server_input = (
            "No\n"
            "\n"
            "Yes\n"
            "\n"
            "\n"
            "Yes"
        )

        client_input = (
            "Yes\n"
            "Yes\n"
            "\n"
            "\n"
            "Yes"
        )

        server_install = tasks.install_master(self.master,
                                              setup_dns=False,
                                              unattended=False,
                                              stdin_text=server_input)

        assert server_install.returncode == 0
        assert self.exp_records_msg in server_install.stderr_text
        assert self.exp_chrony_msg in server_install.stdout_text

        client_install = tasks.install_client(self.master,
                                              self.client,
                                              unattended=False,
                                              stdin_text=client_input)

        assert client_install.returncode == 0
        assert self.exp_records_msg in client_install.stderr_text
        assert self.exp_chrony_msg in client_install.stdout_text

    def test_interactive_ntp_no_conf(self):
        """
        Test to verify that ipa installations without selecting
        to configure ntp options interactively (without -U/--nattended)
        will be successful
        - ipa-server-install
        - ipa-client-install
        """

        server_input = (
            "\n" +
            "\n"
            "No\n"
            "Yes"
        )

        client_input = (
            "Yes\n"
            "No\n"
            "Yes"
        )

        server_install = tasks.install_master(self.master,
                                              setup_dns=False,
                                              unattended=False,
                                              stdin_text=server_input)

        assert server_install.returncode == 0
        assert self.exp_records_msg in server_install.stderr_text
        assert self.exp_chrony_msg in server_install.stdout_text

        client_install = tasks.install_client(self.master,
                                              self.client,
                                              unattended=False,
                                              stdin_text=client_input)

        assert client_install.returncode == 0
        assert self.exp_records_msg in client_install.stderr_text
        assert self.exp_chrony_msg in client_install.stdout_text

    def teardown_method(self, method):
        """
        Uninstall ipa-server, ipa-replica and ipa-client
        """
        tasks.uninstall_client(self.client)
        tasks.uninstall_master(self.replica)
        tasks.uninstall_master(self.master)
