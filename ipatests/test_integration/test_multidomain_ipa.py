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

        # Add DNS forwarder to trusted domain on ipa domain
        self.master.run_cmd([
            "ipa", "dnsforwardzone-add", self.trusted_master.domain.name,
            "--forwarder", self.trusted_master.ip,
            "--forward-policy=only"
        ])
        self.trusted_master.run_cmd([
            "ipa", "dnsforwardzone-add", self.master.domain.name,
            "--forwarder", self.master.ip,
            "--forward-policy=only"
        ])
        
        # Establish trust
        self.master.run_cmd([
            "ipa", "trust-add", "--type=ipa",
            "--admin", "admin@{}".format(self.trusted_master.domain.realm),
            "--range-type=ipa-ad-trust-posix",
            "--password", "--two-way=true",
            self.trusted_master.domain.name
        ], stdin_text=self.trusted_master.config.admin_password)
