#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for the automount location feature.
"""

from __future__ import absolute_import

import time
import re

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

# give some time for units to stabilize
# otherwise we get transient errors
WAIT_AFTER_INSTALL = 5
WAIT_AFTER_UNINSTALL = WAIT_AFTER_INSTALL


class TestAutomountInstallUninstall(IntegrationTest):
    """
    Test if ipa-client-automount behaves as expected
    """

    num_replicas = 1
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)
        client = cls.replicas[0]
        tasks.install_client(cls.master, client)

    def test_use_automount_location(self):

        client = self.replicas[0]

        self.master.run_command([
            "ipa", "automountlocation-add", "baltimore"
        ])

        self.master.run_command([
            "ipa", "host-mod", client.hostname,
            "--location", "baltimore"
        ])

        # systemctl non-fatal errors will only be displayed
        # if ipa-client-automount is launched with --debug
        result1 = client.run_command([
            'ipa-client-automount', '--location', 'baltimore',
            '-U', '--debug'
        ])

        # systemctl non-fatal errors will show up like this:
        # stderr=Failed to restart nfs-secure.service: \
        #        Unit nfs-secure.service not found.
        # normal output:
        # stderr=
        m1 = re.search(r'(?<=stderr\=Failed).+', result1.stderr_text)
        # maybe re-use m1.group(0) if it exists.
        assert m1 is None

        time.sleep(WAIT_AFTER_INSTALL)

        result2 = client.run_command([
            'ipa-client-automount', '--uninstall',
            '-U', '--debug'
        ])

        m2 = re.search(r'(?<=stderr\=Failed).+', result2.stderr_text)
        assert m2 is None

        time.sleep(WAIT_AFTER_UNINSTALL)

        self.master.run_command([
            "ipa", "host-mod", client.hostname,
            "--location", "''"
        ])

        self.master.run_command([
            "ipa", "automountlocation-del", "baltimore"
        ])
