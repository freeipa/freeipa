#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for ipa-cert-fix CLI.
"""
import pytest
import time

import logging
from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_caless import CALessBase, ipa_certs_cleanup


logger = logging.getLogger(__name__)


def server_install_teardown(func):
    def wrapped(*args):
        master = args[0].master
        try:
            func(*args)
        finally:
            ipa_certs_cleanup(master)
    return wrapped


def check_status(host, cert_count, state, timeout=600):
    """Helper method to check that if all the certs are in given state
    :param host: the host
    :param cert_count: no of cert to look for
    :param state: state to check for
    :param timeout: max time in seconds to wait for the state
    """
    for _i in range(0, timeout, 10):
        result = host.run_command(['getcert', 'list'])
        count = result.stdout_text.count(f"status: {state}")
        logger.info("cert count in %s state : %s", state, count)
        if int(count) == cert_count:
            break
        time.sleep(10)
    else:
        raise RuntimeError("request timed out")

    return count


@pytest.fixture
def expire_cert_critical():
    """
    Fixture to expire the certs by moving the system date using
    date -s command and revert it back
    """

    hosts = dict()

    def _expire_cert_critical(host, setup_kra=False):
        hosts['host'] = host
        # Do not install NTP as the test plays with the date
        tasks.install_master(host, setup_dns=False,
                             extra_args=['--no-ntp'])
        if setup_kra:
            tasks.install_kra(host)
        host.run_command(['systemctl', 'stop', 'chronyd'])
        host.run_command(['date', '-s', '+3Years+1day'])

    yield _expire_cert_critical

    host = hosts.pop('host')
    tasks.uninstall_master(host)
    host.run_command(['date', '-s', '-3Years-1day'])
    host.run_command(['systemctl', 'start', 'chronyd'])


class TestIpaCertFix(IntegrationTest):
    @classmethod
    def uninstall(cls, mh):
        # Uninstall method is empty as the uninstallation is done in
        # the fixture
        pass

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
        expire_cert_critical(self.master)
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

    def test_renew_expired_cert_on_master(self, expire_cert_critical):
        """Test if ipa-cert-fix renews expired certs

        Test moves system date to expire certs. Then calls ipa-cert-fix
        to renew them. This certs include subsystem, audit-signing,
        OCSP signing, Dogtag HTTPS, IPA RA agent, LDAP and KDC certs.

        related: https://pagure.io/freeipa/issue/7885
        """
        expire_cert_critical(self.master)

        # wait for cert expiry
        check_status(self.master, 8, "CA_UNREACHABLE")

        self.master.run_command(['ipa-cert-fix', '-v'], stdin_text='yes\n')

        check_status(self.master, 9, "MONITORING")

        # second iteration of ipa-cert-fix
        result = self.master.run_command(
            ['ipa-cert-fix', '-v'],
            stdin_text='yes\n'
        )
        assert "Nothing to do" in result.stdout_text
        check_status(self.master, 9, "MONITORING")

    def test_ipa_cert_fix_non_ipa(self):
        """Test ipa-cert-fix doesn't work on non ipa system

        ipa-cert-fix tool should not work on non ipa system.

        related: https://pagure.io/freeipa/issue/7885
        """
        result = self.master.run_command(['ipa-cert-fix', '-v'],
                                         stdin_text='yes\n',
                                         raiseonerr=False)
        assert result.returncode == 2


class TestIpaCertFixThirdParty(CALessBase):
    """
    Test that ipa-cert-fix works with an installation with custom certs.
    """

    @classmethod
    def install(cls, mh):
        cls.nickname = 'ca1/server'

        super(TestIpaCertFixThirdParty, cls).install(mh)
        tasks.install_master(cls.master, setup_dns=True)

    @server_install_teardown
    def test_third_party_certs(self):
        self.create_pkcs12(self.nickname,
                           password=self.cert_password,
                           filename='server.p12')
        self.prepare_cacert('ca1')

        # We have a chain length of one. If this is extended then the
        # additional cert names will need to be calculated.
        nick_chain = self.nickname.split('/')
        ca_cert = '%s.crt' % nick_chain[0]

        # Add the CA to the IPA store
        self.copy_cert(self.master, ca_cert)
        self.master.run_command(['ipa-cacert-manage', 'install', ca_cert])

        # Apply the new cert chain otherwise ipa-server-certinstall will fail
        self.master.run_command(['ipa-certupdate'])

        # Install the updated certs and restart the world
        self.copy_cert(self.master, 'server.p12')
        args = ['ipa-server-certinstall',
                '-p', self.master.config.dirman_password,
                '--pin', self.master.config.admin_password,
                '-d', 'server.p12']
        self.master.run_command(args)
        self.master.run_command(['ipactl', 'restart',])

        # Run ipa-cert-fix. This is basically a no-op but tests that
        # the DS nickname is used and not a hardcoded value.
        result = self.master.run_command(['ipa-cert-fix', '-v'],)
        assert self.nickname in result.stderr_text
