#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""This covers tests for dns related feature"""

from __future__ import absolute_import

import pytest

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

    external_hosts = ['fedoraproject.org', 'debian.org', 'gentoo.org']

    @pytest.mark.parametrize('hostname', external_hosts)
    def test_request_ipa_dns(self, hostname):
        """External names should be resolvable by IPA nameserver via forwarder.
        """
        res = self.master.run_command(
            ['dig', '@127.0.0.1', '+short', hostname])
        assert res.stdout_text.strip()

    @pytest.mark.parametrize('hostname', external_hosts)
    def test_request_forwarder(self, hostname):
        """Verify that hosts used in test_request_ipa_dns are resolvable."""
        forwarder = self.master.config.dns_forwarder
        res = self.master.run_command(
            ['dig', '@%s' % forwarder, '+short', hostname])
        assert res.stdout_text.strip()

    def test_debug(self):
        import time
        time.sleep(10000)
