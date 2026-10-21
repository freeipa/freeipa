#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Tests covering replica re-add (remove then install again) scenarios.

The existing integration suite removes replicas and separately installs
fresh ones, but it does not exercise what happens when a previously
removed replica is added back. This module covers four such gaps:

* ``TestReaddCAReplicaRoles`` - a re-added CA replica must not reclaim the
  CA renewal master / CRL generation master roles (IDM-7204).
* ``TestReaddKRAReplicaVaultData`` - a re-added KRA replica must still be
  able to retrieve vault data created before its removal.
* ``TestReaddReplicaDNSHygiene`` - a same-hostname re-add must recreate the
  server SRV/A records exactly once (no duplicates, no stale entries).
* ``TestReaddReplicaFromDifferentServer`` - a replica can be re-added from
  a surviving peer after its original install source has been removed.
"""

from __future__ import absolute_import

import re

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_ipahealthcheck import run_healthcheck
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.env_config import get_global_config

config = get_global_config()
reasoning = "Topology plugin disabled due to domain level 0"


def assert_healthcheck_ok(host):
    """Assert ipa-healthcheck reports no failures on the given host."""
    returncode, _data = run_healthcheck(host, failures_only=True)
    assert returncode == 0, (
        "ipa-healthcheck reported failures on %s" % host.hostname
    )


@pytest.mark.skipif(config.domain_level == 0, reason=reasoning)
class TestReaddCAReplicaRoles(IntegrationTest):
    """A re-added CA replica must not grab the renewal/CRL master roles.

    The master owns the CA renewal master and CRL generation master roles.
    Removing a CA replica and installing it again must leave those roles on
    the master; the re-added replica must come back as a plain CA server.
    """
    num_replicas = 1
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_ca=True)

    def assert_sole_renewal_master(self, host):
        """Master is the only CA renewal master, replica is not."""
        result = host.run_command(["ipa", "config-show"]).stdout_text
        matches = re.findall('IPA CA renewal master: (.*)', result)
        assert matches == [self.master.hostname], (
            "Unexpected CA renewal master(s): %s" % matches
        )

    def test_master_owns_roles_before_readd(self):
        self.assert_sole_renewal_master(self.master)
        # CRL generation is enabled on the master and disabled on the replica
        result = self.master.run_command(['ipa-crlgen-manage', 'status'])
        assert 'CRL generation: enabled' in result.stdout_text
        result = self.replicas[0].run_command(['ipa-crlgen-manage', 'status'])
        assert 'CRL generation: disabled' in result.stdout_text

    def test_readd_ca_replica_does_not_reclaim_roles(self):
        master = self.master
        replica = self.replicas[0]

        # Remove the CA replica cleanly.
        tasks.run_server_del(
            master, replica.hostname, force=True,
            ignore_topology_disconnect=True, ignore_last_of_role=True)
        tasks.uninstall_master(replica)

        # Re-add it as a CA replica.
        tasks.install_replica(master, replica, setup_ca=True)

        # The master must remain the sole renewal master.
        self.assert_sole_renewal_master(master)
        tasks.wait_for_replication(replica.ldap_connect())
        self.assert_sole_renewal_master(replica)

        # The re-added replica must not have become the CRL master.
        result = replica.run_command(['ipa-crlgen-manage', 'status'])
        assert 'CRL generation: disabled' in result.stdout_text
        result = master.run_command(['ipa-crlgen-manage', 'status'])
        assert 'CRL generation: enabled' in result.stdout_text

        # Certificate tracking is functional on the re-added replica.
        replica.run_command(['getcert', 'list'])

    def test_healthcheck_clean_after_readd(self):
        assert_healthcheck_ok(self.master)
        assert_healthcheck_ok(self.replicas[0])


@pytest.mark.skipif(config.domain_level == 0, reason=reasoning)
class TestReaddKRAReplicaVaultData(IntegrationTest):
    """A re-added KRA replica must still serve pre-existing vault data."""
    num_replicas = 1
    topology = 'star'

    vault_name = "readd_vault"
    vault_password = "SomeVAULTpassword123"
    vault_data = "Super secret vault data"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_ca=True)
        tasks.install_kra(cls.replicas[0])

    def test_vault_created_and_served_by_replica(self):
        master = self.master
        replica = self.replicas[0]
        tasks.kinit_admin(master)
        master.run_command([
            "ipa", "vault-add", self.vault_name,
            "--password", self.vault_password, "--type", "symmetric",
        ])
        master.run_command([
            "ipa", "vault-archive", self.vault_name,
            "--password", self.vault_password, "--data", self.vault_data,
        ])
        # The KRA replica can retrieve the secret before being re-added.
        tasks.kinit_admin(replica)
        result = replica.run_command([
            "ipa", "vault-retrieve", self.vault_name,
            "--password", self.vault_password,
        ])
        assert self.vault_data in result.stdout_text

    def test_readd_kra_replica_preserves_vault_data(self):
        master = self.master
        replica = self.replicas[0]

        # Remove the KRA replica cleanly.
        tasks.run_server_del(
            master, replica.hostname, force=True,
            ignore_topology_disconnect=True, ignore_last_of_role=True)
        tasks.uninstall_master(replica)

        # Re-add the replica and reinstall KRA on it.
        tasks.install_replica(master, replica, setup_ca=True)
        tasks.install_kra(replica)
        tasks.wait_for_replication(replica.ldap_connect())

        # The secret archived before removal is still retrievable from the
        # re-added KRA replica, proving KRA replication was re-established.
        tasks.kinit_admin(replica)
        result = replica.run_command([
            "ipa", "vault-retrieve", self.vault_name,
            "--password", self.vault_password,
        ])
        assert self.vault_data in result.stdout_text

    def test_healthcheck_clean_after_readd(self):
        assert_healthcheck_ok(self.master)
        assert_healthcheck_ok(self.replicas[0])


@pytest.mark.skipif(config.domain_level == 0, reason=reasoning)
class TestReaddReplicaDNSHygiene(IntegrationTest):
    """Same-hostname re-add must recreate server DNS records exactly once."""
    num_replicas = 1
    topology = 'star'

    # SRV record owner names that should reference every IPA server.
    SRV_OWNERS = (
        '_ldap._tcp',
        '_kerberos._tcp',
        '_kerberos._udp',
        '_kerberos-master._tcp',
        '_kerberos-master._udp',
    )

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(
            cls.master, cls.replicas[0], setup_ca=True, setup_dns=True)

    def _count_srv(self, owner):
        """Return how many SRV records point at the replica hostname."""
        zone = self.master.domain.name
        result = self.master.run_command(
            ["ipa", "dnsrecord-show", zone, owner]).stdout_text
        # SRV targets are printed as "0 100 389 replica.example.test."
        return len(re.findall(
            re.escape(self.replicas[0].hostname) + r'\.?',
            result))

    def _assert_records_once(self):
        tasks.kinit_admin(self.master)
        for owner in self.SRV_OWNERS:
            count = self._count_srv(owner)
            assert count == 1, (
                "Expected exactly one %s SRV record for %s, found %d"
                % (owner, self.replicas[0].hostname, count))
        # The A record for the replica exists exactly once.
        zone = self.master.domain.name
        shortname = self.replicas[0].hostname[:-(len(zone) + 1)]
        result = self.master.run_command(
            ["ipa", "dnsrecord-show", zone, shortname]).stdout_text
        assert result.count('A record:') == 1

    def test_dns_records_present_before_readd(self):
        self._assert_records_once()

    def test_dns_records_recreated_once_after_readd(self):
        master = self.master
        replica = self.replicas[0]

        tasks.run_server_del(
            master, replica.hostname, force=True,
            ignore_topology_disconnect=True, ignore_last_of_role=True)
        tasks.uninstall_master(replica)

        # Re-add with the same hostname and DNS enabled.
        tasks.install_replica(master, replica, setup_ca=True, setup_dns=True)
        tasks.wait_for_replication(replica.ldap_connect())

        # Records must be recreated exactly once - no duplicates, no leftover
        # entries from the removed instance.
        self._assert_records_once()

    def test_healthcheck_clean_after_readd(self):
        assert_healthcheck_ok(self.master)
        assert_healthcheck_ok(self.replicas[0])


@pytest.mark.skipif(config.domain_level == 0, reason=reasoning)
class TestReaddReplicaFromDifferentServer(IntegrationTest):
    """Re-add a replica from a surviving peer after the original master is
    removed.

    ``replicas[0]`` is removed and re-added; ``replicas[1]`` is the surviving
    CA peer that becomes the new install source. The original master (the
    first install source) is decommissioned so it cannot be used, proving the
    re-add does not depend on it and leaves no reference to it.
    """
    num_replicas = 2
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        # replicas[0] will be removed and re-added.
        tasks.install_replica(cls.master, cls.replicas[0], setup_ca=True)
        # replicas[1] is the surviving CA + DNS peer, the future source.
        tasks.install_replica(
            cls.master, cls.replicas[1], setup_ca=True, setup_dns=True)

    def test_readd_replica_from_surviving_peer(self):
        master = self.master
        readd = self.replicas[0]
        peer = self.replicas[1]

        # Move the CA renewal master role to the peer so that removing the
        # master does not leave the cluster without one.
        tasks.kinit_admin(peer)
        peer.run_command([
            'ipa', 'config-mod',
            '--ca-renewal-master-server', peer.hostname])
        tasks.wait_for_replication(peer.ldap_connect())

        # Remove the replica we will re-add.
        tasks.run_server_del(
            master, readd.hostname, force=True,
            ignore_topology_disconnect=True, ignore_last_of_role=True)
        tasks.uninstall_master(readd)

        # Decommission the original install source (the master), driven from
        # the peer. From now on only the peer can serve as a source.
        tasks.run_server_del(
            peer, master.hostname, force=True,
            ignore_topology_disconnect=True, ignore_last_of_role=True)
        tasks.wait_for_cleanallruv_tasks(peer.ldap_connect())
        tasks.uninstall_master(master)

        # Re-add the replica against the peer, resolving DNS via the peer.
        tasks.install_replica(
            peer, readd, setup_ca=True, nameservers=peer.ip)
        tasks.wait_for_replication(readd.ldap_connect())

        # The new replication topology is between peer and the re-added
        # replica, with no reference to the removed master.
        segments = peer.run_command(
            ['ipa', 'topologysegment-find', 'domain']).stdout_text
        assert readd.hostname in segments
        assert master.hostname not in segments

        # No stale RUV for the removed master remains.
        ruv = peer.run_command(['ipa-replica-manage', 'list-ruv']).stdout_text
        assert master.hostname not in ruv

        # Two-way replication between peer and re-added replica works.
        tasks.kinit_admin(peer)
        tasks.user_add(peer, 'readduser')
        tasks.wait_for_replication(readd.ldap_connect())
        tasks.kinit_admin(readd)
        readd.run_command(['ipa', 'user-show', 'readduser'])

        # CA is functional on the re-added replica.
        readd.run_command(['getcert', 'list'])

    def test_healthcheck_clean_after_readd(self):
        assert_healthcheck_ok(self.replicas[1])
        assert_healthcheck_ok(self.replicas[0])
