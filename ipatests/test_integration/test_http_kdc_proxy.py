#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import six
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipatests.test_integration.base import IntegrationTest
from ipaplatform.paths import paths


if six.PY3:
    unicode = str


class TestHttpKdcProxy(IntegrationTest):
    topology = "line"
    num_clients = 1
    # Firewall rules without --append/-A, --delete/-D, .. First entry of
    # each rule is the chain name, the argument to add or delete the rule
    # will be added by the used Firewall method. See firewall.py for more
    # information.
    fw_rules = [['OUTPUT', '-p', 'tcp', '--dport', '88', '-j', 'DROP'],
                ['OUTPUT', '-p', 'udp', '--dport', '88', '-j', 'DROP']]

    @classmethod
    def install(cls, mh):
        super(TestHttpKdcProxy, cls).install(mh)
        # Block access from client to master's port 88
        Firewall(cls.clients[0]).prepend_passthrough_rules(cls.fw_rules)
        # configure client
        cls.clients[0].run_command(
            r"sed -i 's/ kdc = .*$/ kdc = https:\/\/%s\/KdcProxy/' %s" % (
                cls.master.hostname, paths.KRB5_CONF)
            )
        cls.clients[0].run_command(
            r"sed -i 's/master_kdc = .*$/master_kdc"
            r" = https:\/\/%s\/KdcProxy/' %s" % (
                cls.master.hostname, paths.KRB5_CONF)
            )
        # Workaround for https://fedorahosted.org/freeipa/ticket/6443
        cls.clients[0].run_command(['systemctl', 'restart', 'sssd.service'])
        # End of workaround

    @classmethod
    def uninstall(cls, mh):
        super(TestHttpKdcProxy, cls).uninstall(mh)
        Firewall(cls.clients[0]).remove_passthrough_rules(cls.fw_rules)

    def test_http_kdc_proxy_works(self):
        result = tasks.kinit_admin(self.clients[0], raiseonerr=False)
        assert(result.returncode == 0), (
            "Unable to kinit using KdcProxy: %s" % result.stderr_text
            )
