from ipatests.test_integration.base import IntegrationTest

import pytest

hosts = ['fedoraproject.org', 'debian.org', 'gentoo.org']
class TestForwarder(IntegrationTest):
    topology = 'line'

    @pytest.mark.parametrize('hostname', hosts)
    def test_request_via_ipa_dns(self, hostname):
        res = self.master.run_command(
            ['dig', '@127.0.0.1', '+short', hostname])
        assert res.stdout_text.strip()

    @pytest.mark.parametrize('hostname', hosts)
    def test_request_forwarder(self, hostname):
        forwarder = self.master.config.dns_forwarder
        res = self.master.run_command(
            ['dig', '@%s' % forwarder, '+short', hostname])
        assert res.stdout_text.strip()
