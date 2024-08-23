from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import MultiDomainIntegrationTest


class TestMultidomain(MultiDomainIntegrationTest):
    num_clients = 1
    num_replicas = 1
    num_trusted_clients = 1
    num_trusted_replicas = 1
    topology = 'line'

    def test_multidomain_setup(self):
        """
        Test services on multidomain topology.
        """

        for host in (self.master, self.replicas[0],
                     self.trusted_master, self.trusted_replicas[0]
                     ):
            tasks.start_ipa_server(host)

        for host in (self.master, self.replicas[0],
                     self.trusted_master, self.trusted_replicas[0],
                     self.clients[0], self.trusted_clients[0]
                     ):
            tasks.kinit_admin(host)
