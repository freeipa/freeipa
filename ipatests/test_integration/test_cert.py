#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various certificate
related scenarios.
"""

from __future__ import absolute_import

import re

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestInstallMasterClient(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_client(cls.master, cls.clients[0])

    def test_cacert_file_appear_with_option_F(self):
        """Test if getcert creates cacert file with -F option

        It took longer to create the cacert file in older version.
        restarting the certmonger service creates the file at the location
        specified by -F option. This fix is to check that cacert file
        creates immediately after certificate goes into MONITORING state.

        related: https://pagure.io/freeipa/issue/8105
        """
        cmd_arg = ['ipa-getcert', 'request',
                   '-f', '/etc/pki/tls/certs/test.pem',
                   '-k', '/etc/pki/tls/private/test.key',
                   '-K', 'test/%s' % self.clients[0].hostname,
                   '-F', '/etc/pki/tls/test.CA']
        result = self.clients[0].run_command(cmd_arg)
        request_id = re.findall(r'\d+', result.stdout_text)

        # check if certificate is in MONITORING state
        status = tasks.wait_for_request(self.clients[0], request_id[0], 50)
        assert status == "MONITORING"

        self.clients[0].run_command(['ls', '-l', '/etc/pki/tls/test.CA'])
