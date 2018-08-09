#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests to verify that the upgrade script works.
"""

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestUpgrade(IntegrationTest):
    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_invoke_upgrader(self):
        cmd = self.master.run_command(['ipa-server-upgrade'],
                                      raiseonerr=False)
        assert ("DN: cn=Schema Compatibility,cn=plugins,cn=config does not \
                exists or haven't been updated" not in cmd.stdout_text)
        assert cmd.returncode == 0
