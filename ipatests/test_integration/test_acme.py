#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import time

from cryptography.hazmat.backends import default_backend
from cryptography import x509
import pytest

from ipalib.constants import IPA_CA_RECORD
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_caless import CALessBase, ipa_certs_cleanup
from ipaplatform.osinfo import osinfo
from ipaplatform.paths import paths
from ipatests.test_integration.test_external_ca import (
    install_server_external_ca_step1,
    install_server_external_ca_step2,
)


IPA_CA = "ipa_ca.crt"
ROOT_CA = "root_ca.crt"

# RHEL does not have certbot.  EPEL's version is broken with
# python-cryptography-2.3; likewise recent PyPI releases.
# So for now, on RHEL we suppress tests that use certbot.
skip_certbot_tests = osinfo.id not in ['fedora', ]

# Fedora mod_md package needs some patches before it will work.
# RHEL version has the patches.
skip_mod_md_tests = osinfo.id not in ['rhel', 'fedora', ]

CERTBOT_DNS_IPA_SCRIPT = '/usr/libexec/ipa/acme/certbot-dns-ipa'


def check_acme_status(host, exp_status, timeout=60):
    """Helper method to check the status of acme server"""
    for _i in range(0, timeout, 5):
        result = host.run_command(['ipa-acme-manage', 'status'])
        status = result.stdout_text.split(" ")[2].strip()
        print("ACME status: %s" % status)
        if status == exp_status:
            break
        time.sleep(5)
    else:
        raise RuntimeError("request timed out")

    return status


def server_install_teardown(func):
    def wrapped(*args):
        master = args[0].master
        try:
            func(*args)
        finally:
            ipa_certs_cleanup(master)
    return wrapped


class TestACME(CALessBase):
    """
    Test the FreeIPA ACME service by using ACME clients on a FreeIPA client.

    We currently test:

        * service enable/disable (using Curl)
        * http-01 challenge with Certbot's standalone HTTP server
        * dns-01 challenge with Certbot and FreeIPA DNS via hook scripts
        * revocation with Certbot
        * http-01 challenge with mod_md

    Tests we should add:

        * dns-01 challenge with mod_md (see
          https://httpd.apache.org/docs/current/mod/mod_md.html#mdchallengedns01)

    Things that are not implmented/supported yet, but may be in future:

        * IP address SAN
        * tls-alpn-01 challenge
        * Other clients or service scenarios

    """
    num_replicas = 1
    num_clients = 1

    @classmethod
    def prepare_acme_client(cls):
        # cache the acme service uri
        acme_host = f'{IPA_CA_RECORD}.{cls.master.domain.name}'
        cls.acme_server = f'https://{acme_host}/acme/directory'

        # install acme client packages
        if not skip_certbot_tests:
            tasks.install_packages(cls.clients[0], ['certbot'])
        if not skip_mod_md_tests:
            tasks.install_packages(cls.clients[0], ['mod_md'])

    @classmethod
    def install(cls, mh):
        super(TestACME, cls).install(mh)

        # install packages before client install in case of IPA DNS problems
        cls.prepare_acme_client()

        # Each subclass handles its own server installation procedure
        if cls.__name__ != 'TestACME':
            return

        tasks.install_master(cls.master, setup_dns=True)

        tasks.install_client(cls.master, cls.clients[0])
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.clients[0]
        )
        tasks.install_replica(cls.master, cls.replicas[0])
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.replicas[0]
        )

    def certinstall(self, certfile=None, keyfile=None,
                    pin=None):
        """Small wrapper around ipa-server-certinstall

           We are always replacing only the web server with a fixed
           pre-generated value and returning the result for the caller
           to figure out.
        """
        self.create_pkcs12('ca1/server', password=None, filename='server.p12')
        self.copy_cert(self.master, 'server.p12')
        if pin is None:
            pin = self.cert_password
        args = ['ipa-server-certinstall',
                '-p', self.master.config.dirman_password,
                '--pin', pin,
                '-w']
        if certfile:  # implies keyfile
            args.append(certfile)
            args.append(keyfile)
        else:
            args.append('server.p12')

        return self.master.run_command(args,
                                       raiseonerr=False)

    #######
    # kinit
    #######

    def test_kinit_master(self):
        # Some tests require executing ipa commands, e.g. to
        # check revocation status or add/remove DNS entries.
        # Preemptively kinit as admin on the master.
        tasks.kinit_admin(self.master)

    #####################
    # Enable ACME service
    #####################

    def test_acme_service_not_yet_enabled(self):
        # --fail makes curl exit code 22 when response status >= 400.
        # ACME service should return 503 because it was not enabled yet.
        self.clients[0].run_command(
            ['curl', '--fail', self.acme_server],
            ok_returncode=22,
        )
        result = self.master.run_command(['ipa-acme-manage', 'status'])
        assert 'disabled' in result.stdout_text

    def test_enable_acme_service(self):
        self.master.run_command(['ipa-acme-manage', 'enable'])

        # wait a short time for Dogtag ACME service to observe config
        # change and reconfigure itself to service requests
        exc = None
        for _i in range(5):
            time.sleep(2)
            try:
                self.clients[0].run_command(
                    ['curl', '--fail', self.acme_server])
                break
            except Exception as e:
                exc = e
        else:
            raise exc

    def test_centralize_acme_enable(self):
        """Test if ACME enable on replica if enabled on master"""
        status = check_acme_status(self.replicas[0], 'enabled')
        assert status == 'enabled'

    ###############
    # Certbot tests
    ###############

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_certbot_register(self):
        # clean up any existing registration and certificates
        self.clients[0].run_command(
            [
                'rm', '-rf',
                '/etc/letsencrypt/accounts',
                '/etc/letsencrypt/archive',
                '/etc/letsencrypt/csr',
                '/etc/letsencrypt/keys',
                '/etc/letsencrypt/live',
                '/etc/letsencrypt/renewal',
                '/etc/letsencrypt/renewal-hooks'
            ]
        )
        # service is enabled; registration should succeed
        self.clients[0].run_command(
            [
                'certbot',
                '--server', self.acme_server,
                'register',
                '-m', 'nobody@example.test',
                '--agree-tos',
                '--no-eff-email',
            ],
        )

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_certbot_certonly_standalone(self):
        # Get a cert from ACME service using HTTP challenge and Certbot's
        # standalone HTTP server mode
        self.clients[0].run_command(['systemctl', 'stop', 'httpd'])
        self.clients[0].run_command(
            [
                'certbot',
                '--server', self.acme_server,
                'certonly',
                '--domain', self.clients[0].hostname,
                '--standalone',
            ],
        )

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_certbot_revoke(self):
        # Assume previous certonly operation succeeded.
        # Read certificate to learn serial number.
        cert_path = \
            f'/etc/letsencrypt/live/{self.clients[0].hostname}/cert.pem'
        data = self.clients[0].get_file_contents(cert_path)
        cert = x509.load_pem_x509_certificate(data, backend=default_backend())

        # revoke cert via ACME
        self.clients[0].run_command(
            [
                'certbot',
                '--server', self.acme_server,
                'revoke',
                '--cert-name', self.clients[0].hostname,
                '--delete-after-revoke',
            ],
        )

        # check cert is revoked (kinit already performed)
        result = self.master.run_command(
            ['ipa', 'cert-show', str(cert.serial_number), '--raw']
        )
        assert 'revocation_reason:' in result.stdout_text

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_certbot_dns(self):
        # Assume previous revoke operation succeeded and cert was deleted.
        # We can now request a new certificate.

        # Get a cert from ACME service using dns-01 challenge and Certbot's
        # standalone HTTP server mode
        self.clients[0].run_command([
            'certbot',
            '--server', self.acme_server,
            'certonly',
            '--non-interactive',
            '--domain', self.clients[0].hostname,
            '--preferred-challenges', 'dns',
            '--manual',
            '--manual-public-ip-logging-ok',
            '--manual-auth-hook', CERTBOT_DNS_IPA_SCRIPT,
            '--manual-cleanup-hook', CERTBOT_DNS_IPA_SCRIPT,
        ])

    ##############
    # mod_md tests
    ##############

    @pytest.mark.skipif(skip_mod_md_tests, reason='mod_md not available')
    def test_mod_md(self):
        # write config
        self.clients[0].run_command(['mkdir', '-p', '/etc/httpd/conf.d'])
        self.clients[0].run_command(['mkdir', '-p', '/etc/httpd/md'])
        self.clients[0].put_file_contents(
            '/etc/httpd/conf.d/md.conf',
            '\n'.join([
                f'MDCertificateAuthority {self.acme_server}',
                'MDCertificateAgreement accepted',
                'MDStoreDir  /etc/httpd/md',
                f'MDomain {self.clients[0].hostname}',
                '<VirtualHost *:443>',
                f'    ServerName {self.clients[0].hostname}',
                '    SSLEngine on',
                '</VirtualHost>\n',
            ]),
        )

        # To check for successful cert issuance means knowing how mod_md
        # stores certificates, or looking for specific log messages.
        # If the thing we are inspecting changes, the test will break.
        # So I prefer a conservative sleep.
        #
        self.clients[0].run_command(['systemctl', 'restart', 'httpd'])
        time.sleep(15)

        # We expect mod_md has acquired the certificate by now.
        # Perform a graceful restart to begin using the cert.
        # (If mod_md ever learns to start using newly acquired
        # certificates /without/ the second restart, then both
        # of these sleeps can be replaced by "loop until good".)
        #
        self.clients[0].run_command(['systemctl', 'reload', 'httpd'])
        time.sleep(3)

        # HTTPS request from server to client (should succeed)
        self.master.run_command(
            ['curl', f'https://{self.clients[0].hostname}'])

        # clean-up
        self.clients[0].run_command(['rm', '-rf', '/etc/httpd/md'])
        self.clients[0].run_command(['rm', '-f', '/etc/httpd/conf.d/md.conf'])

    ######################
    # Disable ACME service
    ######################

    def test_disable_acme_service(self):
        """
        Disable ACME service again, and observe that it no longer services
        requests.

        """
        self.master.run_command(['ipa-acme-manage', 'disable'])

        # wait a short time for Dogtag ACME service to observe config
        # change and reconfigure itself to no longer service requests
        time.sleep(3)

        # should fail now
        self.clients[0].run_command(
            ['curl', '--fail', self.acme_server],
            ok_returncode=22,
        )

    def test_centralize_acme_disable(self):
        """Test if ACME disable on replica if disabled on master"""
        status = check_acme_status(self.replicas[0], 'disabled')
        assert status == 'disabled'

    @server_install_teardown
    def test_third_party_certs(self):
        """Require ipa-ca SAN on replacement web certificates"""

        self.master.run_command(['ipa-acme-manage', 'enable'])

        self.create_pkcs12('ca1/server')
        self.prepare_cacert('ca1')

        # Re-install the existing Apache certificate that has a SAN to
        # verify that it will be accepted.
        pin = self.master.get_file_contents(
            paths.HTTPD_PASSWD_FILE_FMT.format(host=self.master.hostname)
        )
        result = self.certinstall(
            certfile=paths.HTTPD_CERT_FILE,
            keyfile=paths.HTTPD_KEY_FILE,
            pin=pin
        )
        assert result.returncode == 0

        # Install using a 3rd party cert with a missing SAN for ipa-ca
        # which should be rejected.
        result = self.certinstall()
        assert result.returncode == 1

        self.master.run_command(['ipa-acme-manage', 'disable'])

        # Install using a 3rd party cert with a missing SAN for ipa-ca
        # which should be ok since ACME is disabled.
        result = self.certinstall()
        assert result.returncode == 0

        # Enable ACME which should fail since the Apache cert lacks the SAN
        result = self.master.run_command(['ipa-acme-manage', 'enable'],
                                         raiseonerr=False)
        assert result.returncode == 1
        assert "invalid 'certificate'" in result.stderr_text


class TestACMECALess(IntegrationTest):
    """Test to check the CA less replica setup"""
    num_replicas = 1
    num_clients = 0

    @pytest.fixture
    def test_setup_teardown(self):
        tasks.install_master(self.master, setup_dns=True)

        tasks.install_replica(self.master, self.replicas[0], setup_ca=False)
        tasks.config_host_resolvconf_with_master_data(
            self.master, self.replicas[0]
        )

        yield

        tasks.uninstall_replica(self.master, self.replicas[0])
        tasks.uninstall_master(self.master)

    def test_caless_to_cafull_replica(self, test_setup_teardown):
        """Test ACME is enabled on CA-less replica when converted to CA-full

        Deployment where one server is deployed as CA-less, when converted
        to CA full, should have ACME enabled by default.

        related: https://pagure.io/freeipa/issue/8524
        """
        tasks.kinit_admin(self.master)
        # enable acme on master
        self.master.run_command(['ipa-acme-manage', 'enable'])

        # check status of acme server on master
        status = check_acme_status(self.master, 'enabled')
        assert status == 'enabled'

        tasks.kinit_admin(self.replicas[0])
        # check status of acme on replica, result: CA is not installed
        result = self.replicas[0].run_command(['ipa-acme-manage', 'status'],
                                              raiseonerr=False)
        assert result.returncode == 3

        # Install CA on replica
        tasks.install_ca(self.replicas[0])

        # check acme status, should be enabled now
        status = check_acme_status(self.replicas[0], 'enabled')
        assert status == 'enabled'

        # disable acme on replica
        self.replicas[0].run_command(['ipa-acme-manage', 'disable'])

        # check acme status on master, should be disabled
        status = check_acme_status(self.master, 'disabled')
        assert status == 'disabled'

    def test_enable_caless_to_cafull_replica(self, test_setup_teardown):
        """Test ACME with CA-less replica when converted to CA-full

        Deployment have one ca-less replica and ACME is not enabled.
        After converting ca-less replica to ca-full, ACME can be
        enabled or disabled.

        related: https://pagure.io/freeipa/issue/8524
        """
        tasks.kinit_admin(self.master)

        # check status of acme server on master
        status = check_acme_status(self.master, 'disabled')
        assert status == 'disabled'

        tasks.kinit_admin(self.replicas[0])
        # check status of acme on replica, result: CA is not installed
        result = self.replicas[0].run_command(['ipa-acme-manage', 'status'],
                                              raiseonerr=False)
        assert result.returncode == 3

        # Install CA on replica
        tasks.install_ca(self.replicas[0])

        # check acme status on replica, should not throw error
        status = check_acme_status(self.replicas[0], 'disabled')
        assert status == 'disabled'

        # enable acme on replica
        self.replicas[0].run_command(['ipa-acme-manage', 'enable'])

        # check acme status on master
        status = check_acme_status(self.master, 'enabled')
        assert status == 'enabled'

        # check acme status on replica
        status = check_acme_status(self.replicas[0], 'enabled')
        assert status == 'enabled'

        # disable acme on master
        self.master.run_command(['ipa-acme-manage', 'disable'])

        # check acme status on replica, should be disabled
        status = check_acme_status(self.replicas[0], 'disabled')
        assert status == 'disabled'


class TestACMEwithExternalCA(TestACME):
    """Test the FreeIPA ACME service with external CA"""

    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        super(TestACMEwithExternalCA, cls).install(mh)

        # install master with external-ca
        result = install_server_external_ca_step1(cls.master)
        assert result.returncode == 0
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            cls.master, paths.ROOT_IPA_CSR, ROOT_CA, IPA_CA
        )

        install_server_external_ca_step2(
            cls.master, ipa_ca_fname, root_ca_fname
        )
        tasks.kinit_admin(cls.master)

        tasks.install_client(cls.master, cls.clients[0])
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.clients[0]
        )
        tasks.install_replica(cls.master, cls.replicas[0])
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.replicas[0]
        )
