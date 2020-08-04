#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""This covers tests for dns related feature"""

from __future__ import absolute_import

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestDNS(IntegrationTest):
    """Tests for DNS feature.

    This test class covers the tests for DNS feature.
    """
    topology = 'line'
    num_replicas = 0

    def test_fake_mname_param(self):
        """Test that fake_mname param is set using dnsserver-mod option.

        Test for BZ 1488732 which checks that  --soa-mname-override option
        from dnsserver-mod sets the fake_mname.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'dnsserver-mod', self.master.hostname,
                                 '--soa-mname-override', 'fake'])
        tasks.restart_named(self.master)
        cmd = self.master.run_command(['dig', '+short', '-t', 'SOA',
                                       self.master.domain.name])
        assert 'fake' in cmd.stdout_text

        # reverting the fake_mname change to check it is reverted correctly
        self.master.run_command(['ipa', 'dnsserver-mod', self.master.hostname,
                                 '--soa-mname-override', ''])
        tasks.restart_named(self.master)
        cmd = self.master.run_command(['dig', '+short', '-t', 'SOA',
                                       self.master.domain.name])
        assert 'fake' not in cmd.stdout_text
