#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for various options of ipa-client-install.
"""

from __future__ import absolute_import

import shlex

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestInstallClient(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])

    def check_dns_lookup_kdc(self, client):
        """Check that dns_lookup_kdc is never set to false.

        https://pagure.io/freeipa/issue/6523

        Setting dns_lookup_kdc to False would result in a hardcoded
        configuration which is less reliable in the long run.
        For instance, adding a trust to an Active Directory forest
        after clients are enrolled would result in clients not being
        able to authenticate AD users. Recycling FreeIPA servers
        could prove problematic if the original hostnames are not
        reused too.
        """

        result = client.run_command(
            shlex.split("grep dns_lookup_kdc /etc/krb5.conf")
        )
        assert 'false' not in result.stdout_text.lower()
        assert 'true' in result.stdout_text.lower()

    def test_dns_lookup_kdc_is_true_with_default_enrollment_options(self):
        self.check_dns_lookup_kdc(self.clients[0])
        tasks.uninstall_client(self.clients[0])

    def test_dns_lookup_kdc_is_true_with_ipa_server_on_cli(self):
        tasks.install_client(
            self.master,
            self.clients[0],
            extra_args=["--server", self.master.hostname]
        )
        self.check_dns_lookup_kdc(self.clients[0])
        tasks.uninstall_client(self.clients[0])

    def test_client_install_with_ssh_trust_dns(self):
        """no host key verification if ssh-trust-dns option is used

        There will be no prompt of host key verificaiton during ssh
        to IPA enrolled machines if ssh-trust-dns option is used during
        ipa-client-install. This was broken for FIPS env which got fixed.
        Test checks for non-existence of param HostKeyAlgorithms in
        ssh_config after client-install.

        related: https://pagure.io/freeipa/issue/8082
        """
        tasks.install_client(self.master, self.clients[0],
                             extra_args=['--ssh-trust-dns'])
        result = self.clients[0].run_command(['cat', '/etc/ssh/ssh_config'])
        assert 'HostKeyAlgorithms' not in result.stdout_text
