from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import MultiDomainIntegrationTest


class TestMultidomain(MultiDomainIntegrationTest):
    num_clients = 1
    num_replicas = 1
    num_trusted_clients = 1
    num_trusted_replicas = 1
    topology = 'line'

    def test_multidomain_trust(self):
        """
        Test services on multidomain topology.
        """

        for host in (self.master, self.replicas[0],
                     self.trusted_master, self.trusted_replicas[0]
                     ):
            tasks.start_ipa_server(host)

        for host in (self.master, self.trusted_master):
            tasks.disable_dnssec_validation(host)
            tasks.restart_named(host)

        for host in (self.master, self.replicas[0],
                     self.trusted_master, self.trusted_replicas[0],
                     self.clients[0], self.trusted_clients[0]
                     ):
            tasks.kinit_admin(host)

        # Add DNS forwarder to trusted domain on ipa domain
        self.master.run_command([
            "ipa", "dnsforwardzone-add", self.trusted_master.domain.name,
            "--forwarder", self.trusted_master.ip,
            "--forward-policy=only"
        ])
        self.trusted_master.run_command([
            "ipa", "dnsforwardzone-add", self.master.domain.name,
            "--forwarder", self.master.ip,
            "--forward-policy=only"
        ])

        tasks.install_adtrust(self.master)
        tasks.install_adtrust(self.trusted_master)

        #  Establish trust
        # self.master.run_command([
        #     "ipa", "trust-add", "--type=ipa",
        #     "--admin", "admin@{}".format(self.trusted_master.domain.realm),
        #     "--range-type=ipa-ad-trust-posix",
        #     "--password", "--two-way=true",
        #     self.trusted_master.domain.name
        # ], stdin_text=self.trusted_master.config.admin_password)
