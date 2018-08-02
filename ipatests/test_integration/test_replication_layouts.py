#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import time
import pytest
from ipalib.constants import DOMAIN_LEVEL_0
from ipatests.pytest_ipa.integration.env_config import get_global_config
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

config = get_global_config()

class LayoutsBaseTest(IntegrationTest):

    @classmethod
    def install(cls, mh):
        # tests use custom installation
        pass

    def replication_is_working(self):
        test_user = 'replication-testuser'
        self.master.run_command(
            ['ipa', 'user-add', test_user, '--first', 'test', '--last', 'user']
        )

        time.sleep(60)  # make sure the replication of user is done

        for r in self.replicas:
            r.run_command(['ipa', 'user-show', test_user])


@pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                    reason='does not work on DOMAIN_LEVEL_0 by design')
class TestLineTopologyWithoutCA(LayoutsBaseTest):

    num_replicas = 3

    def test_line_topology_without_ca(self):
        tasks.install_topo('line', self.master, self.replicas, [],
                           setup_replica_cas=False)
        self.replication_is_working()


class TestLineTopologyWithCA(LayoutsBaseTest):

    num_replicas = 3

    def test_line_topology_with_ca(self):
        tasks.install_topo('line', self.master, self.replicas, [],
                           setup_replica_cas=True)
        self.replication_is_working()


class TestLineTopologyWithCAKRA(LayoutsBaseTest):

    num_replicas = 3

    def test_line_topology_with_ca_kra(self):
        tasks.install_topo('line', self.master, self.replicas, [],
                           setup_replica_cas=True, setup_replica_kras=True)
        self.replication_is_working()


class TestStarTopologyWithoutCA(LayoutsBaseTest):

    num_replicas = 3

    def test_star_topology_without_ca(self):
        tasks.install_topo('star', self.master, self.replicas, [],
                           setup_replica_cas=False)
        self.replication_is_working()


class TestStarTopologyWithCA(LayoutsBaseTest):

    num_replicas = 3

    def test_star_topology_with_ca(self):
        tasks.install_topo('star', self.master, self.replicas, [],
                           setup_replica_cas=True)
        self.replication_is_working()


class TestStarTopologyWithCAKRA(LayoutsBaseTest):

    num_replicas = 3

    def test_star_topology_with_ca_kra(self):
        tasks.install_topo('star', self.master, self.replicas, [],
                           setup_replica_cas=True, setup_replica_kras=True)
        self.replication_is_working()


class TestCompleteTopologyWithoutCA(LayoutsBaseTest):

    num_replicas = 3

    def test_complete_topology_without_ca(self):
        tasks.install_topo('complete', self.master, self.replicas, [],
                           setup_replica_cas=False)
        self.replication_is_working()


class TestCompleteTopologyWithCA(LayoutsBaseTest):

    num_replicas = 3

    def test_complete_topology_with_ca(self):
        tasks.install_topo('complete', self.master, self.replicas, [],
                           setup_replica_cas=True)
        self.replication_is_working()


class TestCompleteTopologyWithCAKRA(LayoutsBaseTest):

    num_replicas = 3

    def test_complete_topology_with_ca_kra(self):
        tasks.install_topo('complete', self.master, self.replicas, [],
                           setup_replica_cas=True, setup_replica_kras=True)
        self.replication_is_working()


@pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                    reason='does not work on DOMAIN_LEVEL_0 by design')
class Test2ConnectedTopologyWithoutCA(LayoutsBaseTest):
    num_replicas = 33

    def test_2_connected_topology_without_ca(self):
        tasks.install_topo('2-connected', self.master, self.replicas, [],
                           setup_replica_cas=False)
        self.replication_is_working()


class Test2ConnectedTopologyWithCA(LayoutsBaseTest):
    num_replicas = 33

    def test_2_connected_topology_with_ca(self):
        tasks.install_topo('2-connected', self.master, self.replicas, [],
                           setup_replica_cas=True)
        self.replication_is_working()


class Test2ConnectedTopologyWithCAKRA(LayoutsBaseTest):
    num_replicas = 33

    def test_2_connected_topology_with_ca_kra(self):
        tasks.install_topo('2-connected', self.master, self.replicas, [],
                           setup_replica_cas=True, setup_replica_kras=True)
        self.replication_is_working()


@pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                    reason='does not work on DOMAIN_LEVEL_0 by design')
class TestDoubleCircleTopologyWithoutCA(LayoutsBaseTest):
    num_replicas = 29

    def test_2_connected_topology_with_ca(self):
        tasks.install_topo('double-circle', self.master, self.replicas, [],
                           setup_replica_cas=False)
        self.replication_is_working()


class TestDoubleCircleTopologyWithCA(LayoutsBaseTest):
    num_replicas = 29

    def test_2_connected_topology_with_ca(self):
        tasks.install_topo('double-circle', self.master, self.replicas, [],
                           setup_replica_cas=True)
        self.replication_is_working()


class TestDoubleCircleTopologyWithCAKRA(LayoutsBaseTest):
    num_replicas = 29

    def test_2_connected_topology_with_ca_kra(self):
        tasks.install_topo('double-circle', self.master, self.replicas, [],
                           setup_replica_cas=True, setup_replica_kras=True)
        self.replication_is_working()
