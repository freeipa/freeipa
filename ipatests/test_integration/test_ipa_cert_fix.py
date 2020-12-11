#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for ipa-cert-fix CLI.
"""
import pytest
import time

from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestIpaCertFix(IntegrationTest):
    @classmethod
    def uninstall(cls, mh):
        # Uninstall method is empty as the uninstallation is done in
        # the fixture
        pass

    @pytest.fixture
    def expire_cert_critical(self):
        """
        Fixture to expire the certs by moving the system date using
        date -s command and revert it back
        """
        # Do not install NTP as the test plays with the date
        tasks.install_master(self.master, setup_dns=False,
                             extra_args=['--no-ntp'])
        self.master.run_command(['systemctl', 'stop', 'chronyd'])
        self.master.run_command(['date','-s', '+3Years+1day'])
        yield
        tasks.uninstall_master(self.master)
        self.master.run_command(['date','-s', '-3Years-1day'])
        self.master.run_command(['systemctl', 'start', 'chronyd'])

    def test_missing_csr(self, expire_cert_critical):
        """
        Test that ipa-cert-fix succeeds when CSR is missing from CS.cfg

        Test case for https://pagure.io/freeipa/issue/8618
        Scenario:
        - move the date so that ServerCert cert-pki-ca is expired
        - remove the ca.sslserver.certreq directive from CS.cfg
        - call getcert resubmit in order to create the CSR in certmonger file
        - use ipa-cert-fix, no issue should be seen
        """
        # pki must be stopped in order to edit CS.cfg
        self.master.run_command(['ipactl', 'stop'])
        self.master.run_command(['sed', '-i', r'/ca\.sslserver\.certreq=/d',
                                 paths.CA_CS_CFG_PATH])
        # dirsrv needs to be up in order to run ipa-cert-fix
        self.master.run_command(['ipactl', 'start',
                                 '--ignore-service-failures'])

        # It's the call to getcert resubmit that creates the CSR in certmonger.
        # In normal operations it would be launched automatically when the
        # expiration date is near but in the test we force the CSR creation.
        self.master.run_command(['getcert', 'resubmit',
                                 '-n', 'Server-Cert cert-pki-ca',
                                 '-d', paths.PKI_TOMCAT_ALIAS_DIR])
        # Wait a few secs
        time.sleep(3)

        # Now the real test, call ipa-cert-fix and ensure it doesn't
        # complain about missing sslserver.crt
        result = self.master.run_command(['ipa-cert-fix', '-v'],
                                         stdin_text='yes\n',
                                         raiseonerr=False)
        msg = ("No such file or directory: "
               "'/etc/pki/pki-tomcat/certs/sslserver.crt'")
        assert msg not in result.stderr_text

        # Because of BZ 1897120, pki-cert-fix fails on pki-core 10.10.0
        # https://bugzilla.redhat.com/show_bug.cgi?id=1897120
        if tasks.get_pki_version(self.master) != tasks.parse_version('10.10.0'):
            assert result.returncode == 0

            # get the number of certs track by certmonger
            cmd = self.master.run_command(['getcert', 'list'])
            certs = cmd.stdout_text.count('Request ID')
            timeout = 600
            renewed = 0
            start = time.time()
            # wait up to 10 min for all certs to renew
            while time.time() - start < timeout:
                cmd = self.master.run_command(['getcert', 'list'])
                renewed = cmd.stdout_text.count('status: MONITORING')
                if renewed == certs:
                    break
                time.sleep(100)
            else:
                # timeout
                raise AssertionError('Timeout: Failed to renew all the certs')
