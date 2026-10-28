#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import time
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipaplatform.paths import paths


class TestCockpitIntegration(IntegrationTest):
    topology = "line"
    reqcert = '/etc/cockpit/ws-certs.d/99-cockpit.cert'
    reqkey = '/etc/cockpit/ws-certs.d/99-cockpit.key'
    symlink = '/etc/cockpit/krb5.keytab'

    @classmethod
    def uninstall(cls, mh):
        cls.master.run_command(['ipa-getcert', 'stop-tracking', '-f',
                                cls.reqcert], raiseonerr=False)
        cls.master.run_command(['rm', '-f', cls.symlink], raiseonerr=False)
        cls.master.run_command(['systemctl', 'disable', '--now',
                                'cockpit.socket'])
        super(TestCockpitIntegration, cls).uninstall(mh)

    @classmethod
    def install(cls, mh):
        master = cls.master

        # Install Cockpit and configure it to use IPA certificate and keytab
        master.run_command(['dnf', 'install', '-y', 'cockpit', 'curl'],
                           raiseonerr=False)

        super(TestCockpitIntegration, cls).install(mh)

        master.run_command(['ipa-getcert', 'request', '-f', cls.reqcert, '-k',
                            cls.reqkey, '-D', cls.master.hostname, '-K',
                            'host/' + cls.master.hostname, '-m', '0640', '-o',
                            'root:cockpit-ws', '-O', 'root:root', '-M',
                            '0644'], raiseonerr=False)

        master.run_command(['ln', '-s', paths.HTTP_KEYTAB, cls.symlink],
                           raiseonerr=False)

        time.sleep(5)
        master.run_command(['systemctl', 'enable', '--now', 'cockpit.socket'])

    def test_login_with_kerberos(self):
        """
        Login to Cockpit using GSSAPI authentication
        """
        master = self.master
        tasks.kinit_admin(master)

        cockpit_login = f'https://{master.hostname}:9090/cockpit/login'
        result = master.run_command([paths.BIN_CURL, '-u:', '--negotiate',
                                     '--cacert', paths.IPA_CA_CRT,
                                     cockpit_login])
        assert ("csrf-token" in result.stdout_text)
