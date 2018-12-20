#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for the ipa-pkinit-manage command.
"""

from __future__ import absolute_import

from ipalib import x509
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


SELFSIGNED_CA_HELPER = 'SelfSign'
IPA_CA_HELPER = 'IPA'
PKINIT_STATUS_ENABLED = 'enabled'
PKINIT_STATUS_DISABLED = 'disabled'


def check_pkinit_status(host, status):
    """Ensures that ipa-pkinit-manage status returns the expected state"""
    result = host.run_command(['ipa-pkinit-manage', 'status'],
                              raiseonerr=False)
    assert result.returncode == 0
    assert 'PKINIT is {}'.format(status) in result.stdout_text


def check_pkinit_tracking(host, ca_helper):
    """Ensures that the PKINIT cert is tracked by the expected helper"""
    result = host.run_command(['getcert', 'list', '-f', paths.KDC_CERT],
                              raiseonerr=False)
    assert result.returncode == 0
    # Make sure that only one request exists
    assert result.stdout_text.count('Request ID') == 1
    # Make sure that the right CA helper is used to track the cert
    assert 'CA: {}'.format(ca_helper) in result.stdout_text


def check_pkinit_cert_issuer(host, issuer):
    """Ensures that the PKINIT cert is signed by the expected issuer"""
    data = host.get_file_contents(paths.KDC_CERT)
    pkinit_cert = x509.load_pem_x509_certificate(data)
    # Make sure that the issuer is the expected one
    assert DN(pkinit_cert.issuer) == DN(issuer)


def check_pkinit(host, enabled=True):
    """Checks that PKINIT is configured as expected

    If enabled:
    ipa-pkinit-manage status must return 'PKINIT is enabled'
    the certificate must be tracked by IPA CA helper
    the certificate must be signed by IPA CA
    If disabled:
    ipa-pkinit-manage status must return 'PKINIT is disabled'
    the certificate must be tracked by SelfSign CA helper
    the certificate must be self-signed
    """
    if enabled:
        # When pkinit is enabled:
        # cert is tracked by IPA CA helper
        # cert is signed by IPA CA
        check_pkinit_status(host, PKINIT_STATUS_ENABLED)
        check_pkinit_tracking(host, IPA_CA_HELPER)
        check_pkinit_cert_issuer(
            host,
            'CN=Certificate Authority,O={}'.format(host.domain.realm))
    else:
        # When pkinit is disabled
        # cert is tracked by 'SelfSign' CA helper
        # cert is self-signed
        check_pkinit_status(host, PKINIT_STATUS_DISABLED)
        check_pkinit_tracking(host, SELFSIGNED_CA_HELPER)
        check_pkinit_cert_issuer(
            host,
            'CN={},O={}'.format(host.hostname, host.domain.realm))


class TestPkinitManage(IntegrationTest):
    """Tests the ipa-pkinit-manage command.

    ipa-pkinit-manage can be used to enable, disable or check
    the status of PKINIT.
    When pkinit is enabled, the kerberos server is using a certificate
    signed either externally or by IPA CA. In the latter case, certmonger
    is tracking the cert with IPA helper.
    When pkinit is disabled, the kerberos server is using a self-signed
    certificate that is tracked by certmonger with the SelfSigned helper.
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        # Install the master with PKINIT disabled
        tasks.install_master(cls.master, extra_args=['--no-pkinit'])
        check_pkinit(cls.master, enabled=False)

    def test_pkinit_enable(self):
        self.master.run_command(['ipa-pkinit-manage', 'enable'])
        check_pkinit(self.master, enabled=True)

    def test_pkinit_disable(self):
        self.master.run_command(['ipa-pkinit-manage', 'disable'])
        check_pkinit(self.master, enabled=False)

    def test_pkinit_reenable(self):
        self.master.run_command(['ipa-pkinit-manage', 'enable'])
        check_pkinit(self.master, enabled=True)

    def test_pkinit_on_replica(self):
        """Test pkinit enable on a replica without CA

        Test case for ticket 7795.
        Install a replica with --no-pkinit (without CA)
        then call ipa-pkinit-manage enable. The replica must contact
        a master with a CA instance to get its KDC cert.
        """
        tasks.install_replica(self.master, self.replicas[0], setup_ca=False,
                              extra_args=['--no-pkinit'])
        check_pkinit(self.replicas[0], enabled=False)

        self.replicas[0].run_command(['ipa-pkinit-manage', 'enable'])
        check_pkinit(self.replicas[0], enabled=True)
