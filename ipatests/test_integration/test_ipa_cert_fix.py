#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for ipa-cert-fix CLI.
"""
from datetime import datetime, date
import pytest
import time

import logging
from ipalib import x509
from ipaplatform.paths import paths
from ipapython.ipaldap import realm_to_serverid
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_caless import CALessBase, ipa_certs_cleanup
from ipatests.test_integration.test_cert import get_certmonger_fs_id

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


def needs_resubmit(host, req_id):
    """Helper method to identify if cert request needs to be resubmitted
    :param host: the host
    :param req_id: request id to perform operation for

    Returns True if resubmit needed else False
    """
    # check if cert is in monitoring state
    tasks.wait_for_certmonger_status(
        host, ('MONITORING'), req_id, timeout=600
    )

    # check if cert is valid and not expired
    cmd = host.run_command(
        'getcert list -i {} | grep expires'.format(req_id)
    )
    cert_expiry = cmd.stdout_text.split(' ')
    cert_expiry = datetime.strptime(cert_expiry[1], '%Y-%m-%d').date()
    if cert_expiry > date.today():
        return False
    else:
        return True


def get_cert_expiry(host, nssdb_path, cert_nick):
    """Method to get cert expiry date of given certificate

    :param host: the host
    :param nssdb_path: nssdb path of certificate
    :param cert_nick: certificate nick name for extracting cert from nssdb
    """
    # get initial expiry date to compare later with renewed cert
    host.run_command([
        'certutil', '-L', '-a',
        '-d', nssdb_path,
        '-n', cert_nick,
        '-o', '/root/cert.pem'
    ])
    data = host.get_file_contents('/root/cert.pem')
    cert = x509.load_pem_x509_certificate(data)
    return cert.not_valid_after_utc


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

        # move date to expire certs
        tasks.move_date(host, 'stop', '+3Years+1day')

    yield _expire_cert_critical

    host = hosts.pop('host')
    # Prior to uninstall remove all the cert tracking to prevent
    # errors from certmonger trying to check the status of certs
    # that don't matter because we are uninstalling.
    host.run_command(['systemctl', 'stop', 'certmonger'])
    # Important: run_command with a str argument is able to
    # perform shell expansion but run_command with a list of
    # arguments is not
    host.run_command('rm -fv ' + paths.CERTMONGER_REQUESTS_DIR + '*')
    tasks.uninstall_master(host)
    tasks.move_date(host, 'start', '-3Years-1day')


class TestIpaCertFix(IntegrationTest):
    @classmethod
    def uninstall(cls, mh):
        # Uninstall method is empty as the uninstallation is done in
        # the fixture
        pass

    @pytest.fixture
    def expire_ca_cert(self):
        tasks.install_master(self.master, setup_dns=False,
                             extra_args=['--no-ntp'])
        tasks.move_date(self.master, 'stop', '+20Years+1day')

        yield

        tasks.uninstall_master(self.master)
        tasks.move_date(self.master, 'start', '-20Years-1day')

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
        if (tasks.get_pki_version(self.master)
           != tasks.parse_version('10.10.0')):
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

    def test_missing_startup(self, expire_cert_critical):
        """
        Test ipa-cert-fix fails/warns when startup directive is missing

        This test checks that if 'selftests.container.order.startup' directive
        is missing from CS.cfg, ipa-cert-fix fails and throw proper error
        message. It also checks that underlying command 'pki-server cert-fix'
        should fail to renew the cert.

        related: https://pagure.io/freeipa/issue/8721

        With https://github.com/dogtagpki/pki/pull/3466, it changed to display
        a warning than failing.

        This test also checks that if 'selftests.container.order.startup'
        directive is missing from CS.cfg, ipa-cert-fix dsplay proper warning
        (depending on pki version)

        related: https://pagure.io/freeipa/issue/8890
        """
        expire_cert_critical(self.master)
        # pki must be stopped in order to edit CS.cfg
        self.master.run_command(['ipactl', 'stop'])
        self.master.run_command([
            'sed', '-i', r'/selftests\.container\.order\.startup/d',
            paths.CA_CS_CFG_PATH
        ])
        # dirsrv needs to be up in order to run ipa-cert-fix
        self.master.run_command(['ipactl', 'start',
                                 '--ignore-service-failures'])

        result = self.master.run_command(['ipa-cert-fix', '-v'],
                                         stdin_text='yes\n',
                                         raiseonerr=False)

        err_msg1 = "ERROR: 'selftests.container.order.startup'"
        # check that pki-server cert-fix command fails
        err_msg2 = ("ERROR: CalledProcessError(Command "
                    "['pki-server', 'cert-fix'")
        warn_msg = "WARNING: No selftests configured in"

        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('10.11.0')):
            assert (err_msg1 in result.stderr_text
                    and err_msg2 in result.stderr_text)
        else:
            assert warn_msg in result.stderr_text

    def test_expired_CA_cert(self, expire_ca_cert):
        """Test to check ipa-cert-fix when CA certificate is expired

        In order to fix expired certs using ipa-cert-fix, CA cert should be
        valid. If CA cert expired, ipa-cert-fix won't work.

        related: https://pagure.io/freeipa/issue/8721
        """
        result = self.master.run_command(['ipa-cert-fix', '-v'],
                                         stdin_text='yes\n',
                                         raiseonerr=False)
        # check that pki-server cert-fix command fails
        err_msg = ("ERROR: CalledProcessError(Command "
                   "['pki-server', 'cert-fix'")
        assert err_msg in result.stderr_text


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
        self.master.run_command(['ipactl', 'restart'])

        # Run ipa-cert-fix. This is basically a no-op but tests that
        # the DS nickname is used and not a hardcoded value.
        result = self.master.run_command(['ipa-cert-fix', '-v'],)
        assert self.nickname in result.stderr_text


class TestCertFixKRA(IntegrationTest):
    @classmethod
    def uninstall(cls, mh):
        # Uninstall method is empty as the uninstallation is done in
        # the fixture
        pass

    def test_renew_expired_cert_with_kra(self, expire_cert_critical):
        """Test if ipa-cert-fix renews expired certs with kra installed

        This test check if ipa-cert-fix renews certs with kra
        certificate installed.

        related: https://pagure.io/freeipa/issue/7885
        """
        expire_cert_critical(self.master, setup_kra=True)

        # check if all subsystem cert expired
        check_status(self.master, 11, "CA_UNREACHABLE")

        self.master.run_command(['ipa-cert-fix', '-v'], stdin_text='yes\n')

        check_status(self.master, 12, "MONITORING")


class TestCertFixReplica(IntegrationTest):

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            mh.master, setup_dns=False, extra_args=['--no-ntp']
        )
        # Important: this test is date-sensitive and may fail if executed
        # around Feb 28 or Feb 29 on a leap year.
        # The previous tests are playing with the date by jumping in the
        # future and back to the (expected) current date but calling
        # date -s +3Years+1day and then date -s -3Years-1day doesn't
        # bring the date back to the original value if called around Feb 29.
        # As a consequence, client and server are not synchronized any more
        # and client installation may fail with the following error:
        # Joining realm failed: JSON-RPC call failed:
        # SSL peer certificate or SSH remote key was not OK
        # If you see this failure, just ignore and relaunch on March 1.
        tasks.install_replica(
            mh.master, mh.replicas[0],
            setup_dns=False, extra_args=['--no-ntp']
        )

    @classmethod
    def uninstall(cls, mh):
        # Uninstall method is empty as the uninstallation is done in
        # the fixture
        pass

    @pytest.fixture
    def expire_certs(self):
        # move system date to expire certs
        for host in self.master, self.replicas[0]:
            tasks.move_date(host, 'stop', '+3years+1days')
            host.run_command(
                ['ipactl', 'restart', '--ignore-service-failures']
            )

        yield

        # move date back on replica and master
        for host in self.replicas[0], self.master:
            tasks.uninstall_master(host)
            tasks.move_date(host, 'start', '-3years-1days')

    def test_renew_expired_cert_replica(self, expire_certs):
        """Test renewal of certificates on replica with ipa-cert-fix

        This is to check that ipa-cert-fix renews the certificates
        on replica

        related: https://pagure.io/freeipa/issue/7885
        """
        # wait for cert expiry
        check_status(self.master, 8, "CA_UNREACHABLE")

        self.master.run_command(['ipa-cert-fix', '-v'], stdin_text='yes\n')

        check_status(self.master, 9, "MONITORING")

        # replica operations
        # 'Server-Cert cert-pki-ca' cert will be in CA_UNREACHABLE state
        cmd = self.replicas[0].run_command(
            ['getcert', 'list',
             '-d', paths.PKI_TOMCAT_ALIAS_DIR,
             '-n', 'Server-Cert cert-pki-ca']
        )
        req_id = get_certmonger_fs_id(cmd.stdout_text)
        tasks.wait_for_certmonger_status(
            self.replicas[0], ('CA_UNREACHABLE'), req_id, timeout=600
        )
        # get initial expiry date to compare later with renewed cert
        initial_expiry = get_cert_expiry(
            self.replicas[0],
            paths.PKI_TOMCAT_ALIAS_DIR,
            'Server-Cert cert-pki-ca'
        )

        # check that HTTP,LDAP,PKINIT are renewed and in MONITORING state
        instance = realm_to_serverid(self.master.domain.realm)
        dirsrv_cert = paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
        for cert in (paths.KDC_CERT, paths.HTTPD_CERT_FILE):
            cmd = self.replicas[0].run_command(
                ['getcert', 'list', '-f', cert]
            )
            req_id = get_certmonger_fs_id(cmd.stdout_text)
            tasks.wait_for_certmonger_status(
                self.replicas[0], ('MONITORING'), req_id, timeout=600
            )

        cmd = self.replicas[0].run_command(
            ['getcert', 'list', '-d', dirsrv_cert]
        )
        req_id = get_certmonger_fs_id(cmd.stdout_text)
        tasks.wait_for_certmonger_status(
            self.replicas[0], ('MONITORING'), req_id, timeout=600
        )

        # check if replication working fine
        testuser = 'testuser1'
        password = 'Secret@123'
        stdin = (f"{self.master.config.admin_password}\n"
                 f"{self.master.config.admin_password}\n"
                 f"{self.master.config.admin_password}\n")
        self.master.run_command(['kinit', 'admin'], stdin_text=stdin)
        tasks.user_add(self.master, testuser, password=password)
        self.replicas[0].run_command(['kinit', 'admin'], stdin_text=stdin)
        self.replicas[0].run_command(['ipa', 'user-show', testuser])

        # renew shared certificates by resubmitting to certmonger
        cmd = self.replicas[0].run_command(
            ['getcert', 'list', '-f', paths.RA_AGENT_PEM]
        )
        req_id = get_certmonger_fs_id(cmd.stdout_text)
        if needs_resubmit(self.replicas[0], req_id):
            self.replicas[0].run_command(
                ['getcert', 'resubmit', '-i', req_id]
            )
            tasks.wait_for_certmonger_status(
                self.replicas[0], ('MONITORING'), req_id, timeout=600
            )
        for cert_nick in ('auditSigningCert cert-pki-ca',
                          'ocspSigningCert cert-pki-ca',
                          'subsystemCert cert-pki-ca'):
            cmd = self.replicas[0].run_command(
                ['getcert', 'list',
                 '-d', paths.PKI_TOMCAT_ALIAS_DIR,
                 '-n', cert_nick]
            )
            req_id = get_certmonger_fs_id(cmd.stdout_text)
            if needs_resubmit(self.replicas[0], req_id):
                self.replicas[0].run_command(
                    ['getcert', 'resubmit', '-i', req_id]
                )
                tasks.wait_for_certmonger_status(
                    self.replicas[0], ('MONITORING'), req_id, timeout=600
                )

        self.replicas[0].run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )

        check_status(self.replicas[0], 9, "MONITORING")

        # Sometimes certmonger takes time to update the cert status
        # So check in nssdb instead of relying on getcert command
        renewed_expiry = get_cert_expiry(
            self.replicas[0],
            paths.PKI_TOMCAT_ALIAS_DIR,
            'Server-Cert cert-pki-ca'
        )
        assert renewed_expiry > initial_expiry
