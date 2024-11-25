#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import time

import pytest

from ipalib.constants import IPA_CA_RECORD
from ipalib import x509
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_caless import CALessBase, ipa_certs_cleanup
from ipatests.test_integration.test_random_serial_numbers import (
    pki_supports_RSNv3
)
from ipaplatform.osinfo import osinfo
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipatests.test_integration.test_external_ca import (
    install_server_external_ca_step1,
    install_server_external_ca_step2,
)


IPA_CA = "ipa_ca.crt"
ROOT_CA = "root_ca.crt"

# RHEL does not have certbot.  EPEL's version is broken with
# python-cryptography-2.3; likewise recent PyPI releases.
# So for now, on RHEL we suppress tests that use certbot.
skip_certbot_tests = osinfo.id not in ['fedora', 'rhel']

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


def get_selinux_status(host):
    """
    Return the SELinux enforcing status.

    Return True if enabled and enforcing, otherwise False
    """
    result = host.run_command(['/usr/sbin/selinuxenabled'], raiseonerr=False)
    if result.returncode != 0:
        return False

    result = host.run_command(['/usr/sbin/getenforce'], raiseonerr=False)
    if 'Enforcing' in result.stdout_text:
        return True

    return False


def server_install_teardown(func):
    def wrapped(*args):
        master = args[0].master
        try:
            func(*args)
        finally:
            ipa_certs_cleanup(master)
    return wrapped


def prepare_acme_client(master, client):
    # cache the acme service uri
    acme_host = f'{IPA_CA_RECORD}.{master.domain.name}'
    acme_server = f'https://{acme_host}/acme/directory'

    # enable firewall rule on client
    Firewall(client).enable_services(["http", "https"])

    # install acme client packages
    if not skip_certbot_tests:
        tasks.install_packages(client, ['certbot'])
    if not skip_mod_md_tests:
        tasks.install_packages(client, ['mod_md'])

    return acme_server


def certbot_register(host, acme_server):
    """method to register the host to acme server"""
    # clean up any existing registration and certificates
    host.run_command(
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
    host.run_command(
        [
            'certbot',
            '--server', acme_server,
            'register',
            '-m', 'nobody@example.test',
            '--agree-tos',
            '--no-eff-email',
        ],
    )


def certbot_standalone_cert(host, acme_server, no_of_cert=1):
    """method to issue a certbot's certonly standalone cert"""
    # Get a cert from ACME service using HTTP challenge and Certbot's
    # standalone HTTP server mode
    host.run_command(['systemctl', 'stop', 'httpd'])
    for _i in range(0, no_of_cert):
        host.run_command(
            [
                'certbot',
                '--server', acme_server,
                'certonly',
                '--domain', host.hostname,
                '--standalone',
                '--key-type', 'rsa',
                '--force-renewal'
            ]
        )


def get_389ds_backend(host):
    """ Return the backend type used by 389ds (either 'bdb' or 'lmdb')"""
    conn = host.ldap_connect()
    entry = conn.get_entry(
        DN('cn=config,cn=ldbm database,cn=plugins,cn=config'))
    backend = entry.single_value.get('nsslapd-backend-implement')
    return backend


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
    def install(cls, mh):
        super(TestACME, cls).install(mh)

        # install packages before client install in case of IPA DNS problems
        cls.acme_server = prepare_acme_client(cls.master, cls.clients[0])

        # Each subclass handles its own server installation procedure
        if cls.__name__ != 'TestACME':
            return

        tasks.install_master(cls.master, setup_dns=True)

        tasks.install_client(cls.master, cls.clients[0])
        tasks.install_replica(cls.master, cls.replicas[0])

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
        certbot_register(self.clients[0], self.acme_server)

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_certbot_certonly_standalone(self):
        certbot_standalone_cert(self.clients[0], self.acme_server)

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_certbot_revoke(self):
        # Assume previous certonly operation succeeded.
        # Read certificate to learn serial number.
        cert_path = \
            f'/etc/letsencrypt/live/{self.clients[0].hostname}/cert.pem'
        data = self.clients[0].get_file_contents(cert_path)
        cert = x509.load_pem_x509_certificate(data)

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
            '--key-type', 'rsa',
        ])

    ##############
    # mod_md tests
    ##############

    @pytest.mark.skipif(skip_mod_md_tests, reason='mod_md not available')
    def test_mod_md(self):
        if get_selinux_status(self.clients[0]):
            # mod_md requires its own SELinux policy to grant perms to
            # maintaining ACME registration and cert state.
            raise pytest.skip("SELinux is enabled, this will fail")
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

    def test_acme_pruning_no_random_serial(self):
        """BDB install is configured without random serial
           numbers. Verify that we can't enable pruning on it.
        """
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")
        self.master.run_command(['ipa-acme-manage', 'enable'])

        # This test is only relevant with BDB backend
        # as with LMDB, the installer now enable RSNv3 and cert pruning
        if get_389ds_backend(self.master) == 'bdb':
            result = self.master.run_command(
                ['ipa-acme-manage', 'pruning', '--enable'],
                raiseonerr=False)
            assert result.returncode == 1
            assert "requires random serial numbers" in result.stderr_text

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
        tasks.install_replica(cls.master, cls.replicas[0])


@pytest.fixture
def issue_and_expire_acme_cert():
    """Fixture to expire cert by moving date past expiry of acme cert"""
    hosts = []

    def _issue_and_expire_acme_cert(
        master, client,
        acme_server_url, no_of_cert=1
    ):

        hosts.append(master)
        hosts.append(client)

        # enable the ACME service on master
        master.run_command(['ipa-acme-manage', 'enable'])

        # register the account with certbot
        certbot_register(client, acme_server_url)

        # request a standalone acme cert
        certbot_standalone_cert(client, acme_server_url, no_of_cert)

        # move system date to expire acme cert
        for host in hosts:
            tasks.kdestroy_all(host)
            tasks.move_date(host, 'stop', '+90days+2hours')

        # restart ipa services as date moved and wait to get things settle
        time.sleep(10)
        master.run_command(['ipactl', 'restart'])
        time.sleep(10)

        tasks.get_kdcinfo(master)
        # Note raiseonerr=False:
        # the assert is located after kdcinfo retrieval.
        # run kinit command repeatedly until sssd gets settle
        # after date change
        tasks.run_repeatedly(
            master, "KRB5_TRACE=/dev/stdout kinit admin",
            stdin_text='{0}\n{0}\n{0}\n'.format(
                master.config.admin_password
            )
        )
        # Retrieve kdc.$REALM after the password change, just in case SSSD
        # domain status flipped to online during the password change.
        tasks.get_kdcinfo(master)

    yield _issue_and_expire_acme_cert

    # move back date
    for host in hosts:
        tasks.move_date(host, 'start', '-90days-2hours')

    # restart ipa services as date moved and wait to get things settle
    # if the internal fixture was not called (for instance because the test
    # was skipped), hosts = [] and hosts[0] would produce an IndexError
    # exception.
    if hosts:
        time.sleep(10)
        hosts[0].run_command(['ipactl', 'restart'])
        time.sleep(10)


class TestACMERenew(IntegrationTest):

    num_clients = 1

    @classmethod
    def install(cls, mh):

        # install packages before client install in case of IPA DNS problems
        cls.acme_server = prepare_acme_client(cls.master, cls.clients[0])

        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_renew(self, issue_and_expire_acme_cert):
        """Test if ACME renews the issued cert with cerbot

        This test is to check if ACME certificate renews upon
        reaching expiry

        related: https://pagure.io/freeipa/issue/4751
        """
        issue_and_expire_acme_cert(
            self.master, self.clients[0], self.acme_server)
        data = self.clients[0].get_file_contents(
            f'/etc/letsencrypt/live/{self.clients[0].hostname}/cert.pem'
        )
        cert = x509.load_pem_x509_certificate(data)
        initial_expiry = cert.not_valid_after_utc

        self.clients[0].run_command(['certbot', 'renew'])

        data = self.clients[0].get_file_contents(
            f'/etc/letsencrypt/live/{self.clients[0].hostname}/cert.pem'
        )
        cert = x509.load_pem_x509_certificate(data)
        renewed_expiry = cert.not_valid_after_utc

        assert initial_expiry != renewed_expiry


class TestACMEPrune(IntegrationTest):
    """Validate that ipa-acme-manage configures dogtag for pruning"""

    random_serial = True
    num_clients = 1

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        tasks.install_master(cls.master, setup_dns=True,
                             random_serial=True)
        cls.acme_server = prepare_acme_client(cls.master, cls.clients[0])
        tasks.install_client(cls.master, cls.clients[0])

    @classmethod
    def uninstall(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RSNv3 not supported")
        super(TestACMEPrune, cls).uninstall(mh)

    def test_enable_pruning(self):
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")

        # Pruning is enabled by default when the host supports lmdb
        if get_389ds_backend(self.master) == 'bdb':
            cs_cfg = self.master.get_file_contents(paths.CA_CS_CFG_PATH)
            assert "jobsScheduler.job.pruning.enabled=false".encode() in cs_cfg
            self.master.run_command(['ipa-acme-manage', 'pruning', '--enable'])

        cs_cfg = self.master.get_file_contents(paths.CA_CS_CFG_PATH)
        assert "jobsScheduler.enabled=true".encode() in cs_cfg
        assert "jobsScheduler.job.pruning.enabled=true".encode() in cs_cfg
        assert "jobsScheduler.job.pruning.owner=ipara".encode() in cs_cfg

    def test_pruning_options(self):
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")

        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--certretention=60',
             '--certretentionunit=minute',
             '--certsearchsizelimit=2000',
             '--certsearchtimelimit=5',]
        )
        cs_cfg = self.master.get_file_contents(paths.CA_CS_CFG_PATH)
        assert (
            "jobsScheduler.job.pruning.certRetentionTime=60".encode()
            in cs_cfg
        )
        assert (
            "jobsScheduler.job.pruning.certRetentionUnit=minute".encode()
            in cs_cfg
        )
        assert (
            "jobsScheduler.job.pruning.certSearchSizeLimit=2000".encode()
            in cs_cfg
        )
        assert (
            "jobsScheduler.job.pruning.certSearchTimeLimit=5".encode()
            in cs_cfg
        )

        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--requestretention=60',
             '--requestretentionunit=minute',
             '--requestsearchsizelimit=2000',
             '--requestsearchtimelimit=5',]
        )
        cs_cfg = self.master.get_file_contents(paths.CA_CS_CFG_PATH)
        assert (
            "jobsScheduler.job.pruning.requestRetentionTime=60".encode()
            in cs_cfg
        )
        assert (
            "jobsScheduler.job.pruning.requestRetentionUnit=minute".encode()
            in cs_cfg
        )
        assert (
            "jobsScheduler.job.pruning.requestSearchSizeLimit=2000".encode()
            in cs_cfg
        )
        assert (
            "jobsScheduler.job.pruning.requestSearchTimeLimit=5".encode()
            in cs_cfg
        )

        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--cron=0 23 1 * *',]
        )
        cs_cfg = self.master.get_file_contents(paths.CA_CS_CFG_PATH)
        assert (
            "jobsScheduler.job.pruning.cron=0 23 1 * *".encode()
            in cs_cfg
        )

    def test_pruning_negative_options(self):
        """Negative option testing for things we directly cover"""
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")

        result = self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--enable', '--disable'],
            raiseonerr=False
        )
        assert result.returncode == 2
        assert "Cannot both enable and disable" in result.stderr_text

        for cmd in ('--config-show', '--run'):
            result = self.master.run_command(
                ['ipa-acme-manage', 'pruning',
                 cmd, '--enable'],
                raiseonerr=False
            )
            assert result.returncode == 2
            assert "Cannot change and show config" in result.stderr_text

        result = self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--cron=* *'],
            raiseonerr=False
        )
        assert result.returncode == 2
        assert "Invalid format for --cron" in result.stderr_text

        result = self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--cron=100 * * * *'],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert "100 not within the range 0-59" in result.stderr_text

        result = self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--cron=10 1-5 * * *'],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert "1-5 ranges are not supported" in result.stderr_text

    def test_prune_cert_manual(self, issue_and_expire_acme_cert):
        """Test to prune expired certificate by manual run"""
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")

        issue_and_expire_acme_cert(
            self.master, self.clients[0], self.acme_server)

        # check that the certificate issued for the client
        result = self.master.run_command(
            ['ipa', 'cert-find', '--subject', self.clients[0].hostname]
        )
        assert f'CN={self.clients[0].hostname}' in result.stdout_text

        # run prune command manually
        self.master.run_command(['ipa-acme-manage', 'pruning', '--enable'])
        self.master.run_command(['ipactl', 'restart'])
        self.master.run_command(['ipa-acme-manage', 'pruning', '--run'])
        # wait for cert to get prune
        time.sleep(50)

        # check if client cert is removed
        result = self.master.run_command(
            ['ipa', 'cert-find', '--subject', self.clients[0].hostname],
            raiseonerr=False
        )
        assert f'CN={self.clients[0].hostname}' not in result.stdout_text

    def test_prune_cert_cron(self, issue_and_expire_acme_cert):
        """Test to prune expired certificate by cron job"""
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")

        issue_and_expire_acme_cert(
            self.master, self.clients[0], self.acme_server)

        # check that the certificate issued for the client
        result = self.master.run_command(
            ['ipa', 'cert-find', '--subject', self.clients[0].hostname]
        )
        assert f'CN={self.clients[0].hostname}' in result.stdout_text

        # enable pruning
        self.master.run_command(['ipa-acme-manage', 'pruning', '--enable'])

        # cron would be set to run the next minute
        cron_minute = self.master.run_command(
            [
                "python3",
                "-c",
                (
                    "from datetime import datetime, timedelta; "
                    "print(int((datetime.now() + "
                    "timedelta(minutes=5)).strftime('%M')))"
                ),
            ]
        ).stdout_text.strip()
        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             f'--cron={cron_minute} * * * *']
        )
        self.master.run_command(['ipactl', 'restart'])
        # wait for 5 minutes to cron to execute and 20 sec for just in case
        time.sleep(320)

        # check if client cert is removed
        result = self.master.run_command(
            ['ipa', 'cert-find', '--subject', self.clients[0].hostname],
            raiseonerr=False
        )
        assert f'CN={self.clients[0].hostname}' not in result.stdout_text

    def test_prune_cert_retention_unit(self, issue_and_expire_acme_cert):
        """Test to prune expired certificate with retention unit option"""
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")
        issue_and_expire_acme_cert(
            self.master, self.clients[0], self.acme_server)

        # check that the certificate issued for the client
        result = self.master.run_command(
            ['ipa', 'cert-find', '--subject', self.clients[0].hostname]
        )
        assert f'CN={self.clients[0].hostname}' in result.stdout_text

        # enable pruning
        self.master.run_command(['ipa-acme-manage', 'pruning', '--enable'])

        # certretention set to 5 min
        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--certretention=5', '--certretentionunit=minute']
        )
        self.master.run_command(['ipactl', 'restart'])

        # wait for 5 min and check if expired cert is removed
        time.sleep(310)
        self.master.run_command(['ipa-acme-manage', 'pruning', '--run'])
        result = self.master.run_command(
            ['ipa', 'cert-find', '--subject', self.clients[0].hostname],
            raiseonerr=False
        )
        assert f'CN={self.clients[0].hostname}' not in result.stdout_text

    def test_prune_cert_search_size_limit(self, issue_and_expire_acme_cert):
        """Test to prune expired certificate with search size limit option"""
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")
        no_of_cert = 10
        search_size_limit = 5
        issue_and_expire_acme_cert(
            self.master, self.clients[0], self.acme_server, no_of_cert)

        # check that the certificate issued for the client
        result = self.master.run_command(
            ['ipa', 'cert-find', '--subject', self.clients[0].hostname]
        )
        assert f'CN={self.clients[0].hostname}' in result.stdout_text
        assert f'Number of entries returned {no_of_cert}'

        # enable pruning
        self.master.run_command(['ipa-acme-manage', 'pruning', '--enable'])

        # certretention set to 5 min
        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             f'--certsearchsizelimit={search_size_limit}',
             '--certsearchtimelimit=100']
        )
        self.master.run_command(['ipactl', 'restart'])

        # prune the certificates
        self.master.run_command(['ipa-acme-manage', 'pruning', '--run'])

        # check if 5 expired cert is removed
        result = self.master.run_command(
            ['ipa', 'cert-find', '--subject', self.clients[0].hostname]
        )
        assert f'Number of entries returned {no_of_cert - search_size_limit}'

    def test_prune_config_show(self):
        """Test to check config-show command shows set param"""
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")

        self.master.run_command(['ipa-acme-manage', 'pruning', '--enable'])
        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--cron=0 0 1 * *']
        )
        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--certretention=30', '--certretentionunit=day']
        )
        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--certsearchsizelimit=1000', '--certsearchtimelimit=0']
        )
        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--requestretention=30', '--requestretentionunit=day']
        )
        self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--requestsearchsizelimit=1000', '--requestsearchtimelimit=0']
        )
        result = self.master.run_command(
            ['ipa-acme-manage', 'pruning', '--config-show']
        )
        assert 'Status: enabled' in result.stdout_text
        assert 'Certificate Retention Time: 30' in result.stdout_text
        assert 'Certificate Retention Unit: day' in result.stdout_text
        assert 'Certificate Search Size Limit: 1000' in result.stdout_text
        assert 'Certificate Search Time Limit: 0' in result.stdout_text
        assert 'Request Retention Time: 30' in result.stdout_text
        assert 'Request Retention Unit: day' in result.stdout_text
        assert 'Request Search Size Limit: 1000' in result.stdout_text
        assert 'Request Search Time Limit: 0' in result.stdout_text
        assert 'cron Schedule: 0 0 1 * *' in result.stdout_text

    def test_prune_disable(self):
        """Test prune command throw error after disabling the pruning"""
        if (tasks.get_pki_version(self.master)
           < tasks.parse_version('11.3.0')):
            raise pytest.skip("Certificate pruning is not available")

        self.master.run_command(['ipa-acme-manage', 'pruning', '--disable'])
        result = self.master.run_command(
            ['ipa-acme-manage', 'pruning',
             '--cron=0 0 1 * *']
        )
        assert 'Status: disabled' in result.stdout_text
