#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various certificate
related scenarios.
"""
import ipaddress
import pytest
import re

from ipaplatform.paths import paths
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

DEFAULT_RA_AGENT_SUBMITTED_VAL = '19700101000000'


def get_certmonger_fs_id(input_str):
    """Get certmonger FS ID
    from the `getcert list -f /var/lib/ipa/ra-agent.pem` output
    command output

    :return request ID string
    """
    request_id = re.findall(r'\d+', input_str)
    return request_id[1]


def get_certmonger_request_value(host, requestid, state):
    """Get certmonger submitted value from
    /var/lib/certmonger/requests/<timestamp>

    :return submitted timestamp value
    """
    result = host.run_command(
        ['grep', '-rl', 'id={0}'.format(requestid),
         paths.CERTMONGER_REQUESTS_DIR]
    )
    assert result.stdout_text is not None
    filename = result.stdout_text.strip()
    request_file = host.get_file_contents(filename, encoding='utf-8')
    val = None
    for line in request_file.split('\n'):
        if line.startswith('%s=' % state):
            _unused, val = line.partition("=")[::2]
            break
    return val


class TestInstallMasterClient(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        # use master's DNS so nsupdate adds correct IP address for client
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.clients[0]
        )
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

    def test_ipa_getcert_san_aci(self):
        """Test for DNS and IP SAN extensions + ACIs
        """
        hostname = self.clients[0].hostname
        certfile = '/etc/pki/tls/certs/test2.pem'

        tasks.kinit_admin(self.master)
        name, zone = hostname.split('.', 1)
        self.master.run_command(['ipa', 'dnsrecord-show', zone, name])
        tasks.kdestroy_all(self.master)

        cmd_arg = [
            'ipa-getcert', 'request', '-v', '-w',
            '-f', certfile,
            '-k', '/etc/pki/tls/private/test2.key',
            '-K', f'test/{hostname}',
            '-D', hostname,
            '-A', self.clients[0].ip,
        ]
        result = self.clients[0].run_command(cmd_arg)
        request_id = re.findall(r'\d+', result.stdout_text)

        # check if certificate is in MONITORING state
        status = tasks.wait_for_request(self.clients[0], request_id[0], 50)
        assert status == "MONITORING"

        certdata = self.clients[0].get_file_contents(certfile)
        cert = x509.load_pem_x509_certificate(
            certdata, default_backend()
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        dnsnames = ext.value.get_values_for_type(x509.DNSName)
        assert dnsnames == [self.clients[0].hostname]
        ipaddrs = ext.value.get_values_for_type(x509.IPAddress)
        assert ipaddrs == [ipaddress.ip_address(self.clients[0].ip)]

    def test_getcert_list_profile(self):
        """
        Test that getcert list command displays the profile
        for the cert
        """
        result = self.master.run_command(
            ["getcert", "list", "-f", paths.HTTPD_CERT_FILE]
        )
        assert "profile: caIPAserviceCert" in result.stdout_text
        result = self.master.run_command(
            ["getcert", "list", "-n", "Server-Cert cert-pki-ca"]
        )
        assert "profile: caServerCert" in result.stdout_text

    @pytest.fixture
    def test_subca_certs(self):
        """
        Fixture to add subca, stop tracking request,
        followed by removing SUB CA along with
        cert keys
        """
        sub_name = "CN=SUBCA"
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "ca-add", "mysubca", "--subject={}".format(sub_name)]
        )
        self.master.run_command(
            [
                "ipa",
                "caacl-add-ca",
                "hosts_services_caIPAserviceCert",
                "--cas=mysubca",
            ]
        )
        yield
        self.master.run_command(
            ["getcert", "stop-tracking", "-i", "test-request"]
        )
        self.master.run_command(["ipa", "ca-disable", "mysubca"])
        self.master.run_command(["ipa", "ca-del", "mysubca"])
        self.master.run_command(
            ["rm", "-fv", "/etc/pki/tls/private/test.key"]
        )
        self.master.run_command(["rm", "-fv", "/etc/pki/tls/certs/test.pem"])

    def test_getcert_list_profile_using_subca(self, test_subca_certs):
        """
        Test that getcert list command displays the profile
        for the cert requests generated, with a SubCA configured
        on the IPA server.
        """
        cmd_arg = [
            "getcert",
            "request",
            "-c",
            "ipa",
            "-I",
            "test-request",
            "-k",
            "/etc/pki/tls/private/test.key",
            "-f",
            "/etc/pki/tls/certs/test.pem",
            "-D",
            self.master.hostname,
            "-K",
            "host/%s" % self.master.hostname,
            "-N",
            "CN={}".format(self.master.hostname),
            "-U",
            "id-kp-clientAuth",
            "-X",
            "mysubca",
            "-T",
            "caIPAserviceCert",
        ]
        result = self.master.run_command(cmd_arg)
        assert (
            'New signing request "test-request" added.\n' in result.stdout_text
        )
        status = tasks.wait_for_request(self.master, "test-request", 300)
        if status == "MONITORING":
            result = self.master.run_command(
                ["getcert", "list", "-i", "test-request"]
            )
            assert "profile: caIPAserviceCert" in result.stdout_text
        else:
            raise AssertionError("certmonger request is "
                                 "in state {}". format(status))

    def test_certmonger_rekey_option(self):
        """Test certmonger rekey command works fine

        Certmonger's rekey command was throwing an error as
        unrecognized command. Test is to check if it is working fine.

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1249165
        """
        result = self.master.run_command([
            'ipa-getcert', 'request',
            '-f', '/etc/pki/tls/certs/test_rekey.pem',
            '-k', '/etc/pki/tls/private/test.key',
            '-K', 'test/{}'.format(self.master.hostname)])
        request_id = re.findall(r'\d+', result.stdout_text)

        status = tasks.wait_for_request(self.master, request_id[0], 50)
        assert status == "MONITORING"

        certdata = self.master.get_file_contents(
            '/etc/pki/tls/certs/test_rekey.pem'
        )
        cert = x509.load_pem_x509_certificate(
            certdata, default_backend()
        )
        assert cert.public_key().key_size == 2048

        # rekey with key size 3072
        self.master.run_command(['getcert', 'rekey',
                                 '-i', request_id[0],
                                 '-g', '3072'])

        status = tasks.wait_for_request(self.master, request_id[0], 50)
        assert status == "MONITORING"

        certdata = self.master.get_file_contents(
            '/etc/pki/tls/certs/test_rekey.pem'
        )
        cert = x509.load_pem_x509_certificate(
            certdata, default_backend()
        )
        # check if rekey command updated the key size
        assert cert.public_key().key_size == 3072

        self.master.run_command(['getcert', 'stop-tracking'
                                 '-i', request_id[0]])


class TestCertmongerInterruption(IntegrationTest):
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_replica(cls.master, cls.replicas[0])

    def test_certmomger_tracks_renewed_certs_during_interruptions(self):
        """Test that CA renewal handles early CA_WORKING and restarts

        A non-renewal master CA might submit a renewal request before
        the renewal master actually updating the certs. This is expected.
        The tracking request will result in CA_WORKING.

        This would trigger a different path within the IPA renewal
        scripts which differentiate between a SUBMIT (new request) and
        a POLL (resume request). The script was requiring a cookie
        value for POLL requests which wasn't available and was
        erroring out unrecoverably without restarting certmonger.

        Submit a request for renewal early and wait for it to go into
        CA_WORKING. Resubmit the request to ensure that the request
        remains in CA_WORKING without reporting any ca_error like
        Invalid cookie: ''

        Use the submitted value in the certmonger request to validate
        that the request was resubmitted and not rely on catching
        the states directly.

        Pagure Issue: https://pagure.io/freeipa/issue/8164
        """
        cmd = ['getcert', 'list', '-f', paths.RA_AGENT_PEM]
        result = self.replicas[0].run_command(cmd)

        # Get Request ID and Submitted Values
        request_id = get_certmonger_fs_id(result.stdout_text)
        start_val = get_certmonger_request_value(self.replicas[0],
                                                 request_id, "submitted")

        # at this point submitted value for RA agent cert should be
        # 19700101000000 since it has never been submitted for renewal.
        assert start_val == DEFAULT_RA_AGENT_SUBMITTED_VAL

        cmd = ['getcert', 'resubmit', '-f', paths.RA_AGENT_PEM]
        self.replicas[0].run_command(cmd)

        tasks.wait_for_certmonger_status(self.replicas[0],
                                         ('CA_WORKING', 'MONITORING'),
                                         request_id)

        resubmit_val = get_certmonger_request_value(self.replicas[0],
                                                    request_id,
                                                    "submitted")

        if resubmit_val == DEFAULT_RA_AGENT_SUBMITTED_VAL:
            pytest.fail("Request was not resubmitted")

        ca_error = get_certmonger_request_value(self.replicas[0],
                                                request_id, "ca_error")
        state = get_certmonger_request_value(self.replicas[0],
                                             request_id, "state")

        assert ca_error is None
        assert state == 'CA_WORKING'

        cmd = ['getcert', 'resubmit', '-f', paths.RA_AGENT_PEM]
        self.replicas[0].run_command(cmd)

        tasks.wait_for_certmonger_status(self.replicas[0],
                                         ('CA_WORKING', 'MONITORING'),
                                         request_id)

        resubmit2_val = get_certmonger_request_value(self.replicas[0],
                                                     request_id,
                                                     "submitted")

        if resubmit_val == DEFAULT_RA_AGENT_SUBMITTED_VAL:
            pytest.fail("Request was not resubmitted")

        assert resubmit2_val > resubmit_val

        ca_error = get_certmonger_request_value(self.replicas[0],
                                                request_id, "ca_error")
        state = get_certmonger_request_value(self.replicas[0],
                                             request_id, "state")

        assert ca_error is None
        assert state == 'CA_WORKING'
