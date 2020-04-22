#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for various options of ipa-client-install.
"""

from __future__ import absolute_import

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestInstallClient(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

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
