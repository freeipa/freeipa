from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestMultidomain(IntegrationTest):
    num_trusted_domains = 1
    num_clients = 1
    num_replicas = 1
    num_trusted_clients = 1
    num_trusted_replicas = 1

    @classmethod
    def install(cls, mh):
        pass

    def test_multidomain_setup(self):
        tasks.install_master(self.master)
        tasks.install_master(self.trusted_master)

        tasks.install_replica(self.master, self.replicas[0])
        tasks.install_replica(self.trusted_master, self.trusted_replicas[0])

        tasks.install_client(self.master, self.clients[0])
        tasks.install_client(self.trusted_master, self.trusted_clients[0])

        for host in (self.master, self.replicas[0],
                     self.trusted_master, self.trusted_replicas[0]
                     ):
            tasks.start_ipa_server(host)

        for host in (self.master, self.replicas[0],
                     self.trusted_master, self.trusted_replicas[0],
                     self.clients[0], self.trusted_clients[0]
                     ):
            tasks.kinit_admin(host)
