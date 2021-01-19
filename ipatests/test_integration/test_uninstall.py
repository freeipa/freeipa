#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module for ipa uninstall related scenarios.
"""

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestUninstallWithoutDNS(IntegrationTest):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_uninstall_server_without_dns(self):
        """Test if server setup without dns uninstall properly

        IPA server uninstall was failing if dns was not setup.
        This test check if it uninstalls propelry.

        related: https://pagure.io/freeipa/issue/8630
        """
        tasks.uninstall_master(self.master)
