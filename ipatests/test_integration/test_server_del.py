#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from itertools import permutations

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipalib.constants import DOMAIN_LEVEL_1, DOMAIN_SUFFIX_NAME, CA_SUFFIX_NAME

REMOVAL_ERR_TEMPLATE = ("Removal of '{hostname}' leads to disconnected "
                        "topology in suffix '{suffix}'")


def check_master_removal(host, hostname_to_remove,
                         force=False,
                         ignore_topology_disconnect=False,
                         ignore_last_of_role=False):
    result = tasks.run_server_del(
        host,
        hostname_to_remove,
        force=force,
        ignore_topology_disconnect=ignore_topology_disconnect,
        ignore_last_of_role=ignore_last_of_role)

    assert result.returncode == 0
    if force:
        assert ("Forcing removal of {hostname}".format(
            hostname=hostname_to_remove) in result.stderr_text)

    if ignore_topology_disconnect:
        assert "Ignoring topology connectivity errors." in result.stderr_text

    if ignore_last_of_role:
        assert ("Ignoring these warnings and proceeding with removal" in
                result.stderr_text)

    tasks.assert_error(
        host.run_command(
            ['ipa', 'server-show', hostname_to_remove], raiseonerr=False
        ),
        "{}: server not found".format(hostname_to_remove),
        returncode=2
    )


def check_removal_disconnects_topology(
        host, hostname_to_remove,
        affected_suffixes=(DOMAIN_SUFFIX_NAME,)):
    result = tasks.run_server_del(host, hostname_to_remove)
    assert len(affected_suffixes) <= 2

    err_messages_by_suffix = {
        CA_SUFFIX_NAME: REMOVAL_ERR_TEMPLATE.format(
            hostname=hostname_to_remove,
            suffix=CA_SUFFIX_NAME
        ),
        DOMAIN_SUFFIX_NAME: REMOVAL_ERR_TEMPLATE.format(
            hostname=hostname_to_remove,
            suffix=DOMAIN_SUFFIX_NAME
        )
    }

    for suffix in err_messages_by_suffix:
        if suffix in affected_suffixes:
            tasks.assert_error(
                result, err_messages_by_suffix[suffix], returncode=1)
        else:
            assert err_messages_by_suffix[suffix] not in result.stderr_text


class ServerDelBase(IntegrationTest):
    num_replicas = 2
    num_clients = 1
    domain_level = DOMAIN_LEVEL_1
    topology = 'star'

    @classmethod
    def install(cls, mh):
        super(ServerDelBase, cls).install(mh)

        cls.client = cls.clients[0]
        cls.replica1 = cls.replicas[0]
        cls.replica2 = cls.replicas[1]


class TestServerDel(ServerDelBase):

    # avoid 'Deleting this server will leave your installation without DNS'
    setup_replica_dns = True

    @classmethod
    def install(cls, mh):
        super(TestServerDel, cls).install(mh)
        # prepare topologysegments for negative test cases
        # it should look like this for DOMAIN_SUFFIX_NAME:
        #             master
        #            /
        #           /
        #          /
        #   replica1------- replica2
        # and like this for CA_SUFFIX_NAME
        #             master
        #                  \
        #                   \
        #                    \
        #   replica1------- replica2

        tasks.create_segment(cls.client, cls.replica1, cls.replica2)
        tasks.create_segment(cls.client, cls.replica1, cls.replica2,
                             suffix=CA_SUFFIX_NAME)

        # try to delete all relevant segment connecting master and replica1/2
        segment_name_fmt = '{p[0].hostname}-to-{p[1].hostname}'
        for domain_pair in permutations((cls.master, cls.replica2)):
            tasks.destroy_segment(
                cls.client, segment_name_fmt.format(p=domain_pair))

        for ca_pair in permutations((cls.master, cls.replica1)):
            tasks.destroy_segment(
                cls.client, segment_name_fmt.format(p=ca_pair),
                suffix=CA_SUFFIX_NAME)

    def test_removal_of_nonexistent_master_raises_error(self):
        """
        tests that removal of non-existent master raises an error
        """
        hostname = u'bogus-master.bogus.domain'
        err_message = "{}: server not found".format(hostname)
        tasks.assert_error(
            tasks.run_server_del(self.client, hostname),
            err_message,
            returncode=2
        )

    def test_forced_removal_of_nonexistent_master(self):
        """
        tests that removal of non-existent master with '--force' does not raise
        an error
        """
        hostname = u'bogus-master.bogus.domain'
        result = tasks.run_server_del(self.client, hostname, force=True)
        assert result.returncode == 0
        assert ('Deleted IPA server "{}"'.format(hostname) in
                result.stdout_text)

        assert ("Server has already been deleted" in result.stderr_text)

    def test_removal_of_replica1_disconnects_domain_topology(self):
        """
        tests that given the used topology, attempted removal of replica1 fails
        with disconnected DOMAIN topology but not CA
        """

        check_removal_disconnects_topology(
            self.client,
            self.replica1.hostname,
            affected_suffixes=(DOMAIN_SUFFIX_NAME,)
        )

    def test_removal_of_replica2_disconnects_ca_topology(self):
        """
        tests that given the used topology, attempted removal of replica2 fails
        with disconnected CA topology but not DOMAIN
        """

        check_removal_disconnects_topology(
            self.client,
            self.replica2.hostname,
            affected_suffixes=(CA_SUFFIX_NAME,)
        )

    def test_ignore_topology_disconnect_replica1(self):
        """
        tests that removal of replica1 with '--ignore-topology-disconnect'
        destroys master for good
        """
        check_master_removal(
            self.client,
            self.replica1.hostname,
            ignore_topology_disconnect=True
        )

        # reinstall the replica
        tasks.uninstall_master(self.replica1)
        tasks.install_replica(self.master, self.replica1, setup_ca=True)

    def test_ignore_topology_disconnect_replica2(self):
        """
        tests that removal of replica2 with '--ignore-topology-disconnect'
        destroys master for good with verbose option for uninstallation
        """
        check_master_removal(
            self.client,
            self.replica2.hostname,
            ignore_topology_disconnect=True
        )

        # reinstall the replica
        tasks.uninstall_master(self.replica2, verbose=True)
        tasks.install_replica(self.master, self.replica2, setup_ca=True)

    def test_removal_of_master_disconnects_both_topologies(self):
        """
        tests that master removal will now raise errors in both suffixes.
        """
        check_removal_disconnects_topology(
            self.client,
            self.master.hostname,
            affected_suffixes=(CA_SUFFIX_NAME, DOMAIN_SUFFIX_NAME)
        )

    def test_removal_of_replica1(self):
        """
        tests the removal of replica1 which should now pass without errors
        """
        check_master_removal(
            self.client,
            self.replica1.hostname
        )

    def test_removal_of_replica2(self):
        """
        tests the removal of replica2 which should now pass without errors
        """
        check_master_removal(
            self.client,
            self.replica2.hostname
        )


class TestLastServices(ServerDelBase):
    """
    Test the checks for last services during server-del and their bypassing
    using when forcing the removal
    """
    num_replicas = 1
    domain_level = DOMAIN_LEVEL_1
    topology = 'line'

    setup_replica_cas = False

    def test_removal_of_master_raises_error_about_last_dns(self):
        """
        Now server-del should complain about the removal of last DNS server
        """
        tasks.assert_error(
            tasks.run_server_del(self.replicas[0], self.master.hostname),
            "Deleting this server will leave your installation "
            "without a DNS.",
            1
        )

    def test_install_dns_on_replica1_and_dnssec_on_master(self):
        """
        install DNS server on replica and DNSSec on master
        """
        tasks.install_dns(self.replicas[0])
        args = [
            "ipa-dns-install",
            "--dnssec-master",
            "--forwarder", self.master.config.dns_forwarder,
            "-U",
        ]
        self.master.run_command(args)
        Firewall(self.master).enable_service("dns")

    def test_removal_of_master_raises_error_about_dnssec(self):
        tasks.assert_error(
            tasks.run_server_del(self.replicas[0], self.master.hostname),
            "Replica is active DNSSEC key master. Uninstall "
            "could break your DNS system. Please disable or replace "
            "DNSSEC key master first.",
            1
        )

    def test_disable_dnssec_on_master(self):
        """
        Disable DNSSec master so that it is not tested anymore. Normal way
        would be to move the DNSSec master to replica, but that is tested in
        DNSSec tests.
        """
        args = [
            "ipa-dns-install",
            "--disable-dnssec-master",
            "--forwarder", self.master.config.dns_forwarder,
            "--force",
            "-U",
        ]
        self.master.run_command(args)

    def test_removal_of_master_raises_error_about_last_ca(self):
        """
        test that removal of master fails on the last
        """
        tasks.assert_error(
            tasks.run_server_del(self.replicas[0], self.master.hostname),
            "Deleting this server is not allowed as it would leave your "
            "installation without a CA.",
            1
        )

    def test_forced_removal_of_master(self):
        """
        Tests that we can still force remove the master using
        '--ignore-last-of-role'
        """
        check_master_removal(
            self.replicas[0], self.master.hostname,
            ignore_last_of_role=True
        )
