#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various certificate
related scenarios.
"""
import os

import ipaddress
import pytest
import random
import re
import string
import time

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
    topology = 'line'

    @classmethod
    def install(cls, mh):
        super().install(mh)

        # time to look into journal logs in
        # test_certmonger_ipa_responder_jsonrpc
        cls.since = time.strftime('%H:%M:%S')

    def test_cacert_file_appear_with_option_F(self):
        """Test if getcert creates cacert file with -F option

        It took longer to create the cacert file in older version.
        restarting the certmonger service creates the file at the location
        specified by -F option. This fix is to check that cacert file
        creates immediately after certificate goes into MONITORING state.

        related: https://pagure.io/freeipa/issue/8105
        """
        cmd_arg = [
            "ipa-getcert", "request",
            "-f", os.path.join(paths.OPENSSL_CERTS_DIR, "test.pem"),
            "-k", os.path.join(paths.OPENSSL_PRIVATE_DIR, "test.key"),
            "-K", "test/%s" % self.clients[0].hostname,
            "-F", os.path.join(paths.OPENSSL_DIR, "test.CA"),
        ]
        result = self.clients[0].run_command(cmd_arg)
        request_id = re.findall(r'\d+', result.stdout_text)

        # check if certificate is in MONITORING state
        status = tasks.wait_for_request(self.clients[0], request_id[0], 50)
        assert status == "MONITORING"

        self.clients[0].run_command(
            ["ls", "-l", os.path.join(paths.OPENSSL_DIR, "test.CA")]
        )

    def test_certmonger_ipa_responder_jsonrpc(self):
        """Test certmonger IPA responder switched to JSONRPC

        This is to test if certmonger IPA responder swithed to JSONRPC
        from XMLRPC

        This test utilizes the cert request made in previous test.
        (test_cacert_file_appear_with_option_F)

        related: https://pagure.io/freeipa/issue/3299
        """
        # check that request is made against /ipa/json so that
        # IPA enforce json data type
        exp_str = 'Submitting request to "https://{}/ipa/json"'.format(
            self.master.hostname
        )
        result = self.clients[0].run_command([
            'journalctl', '-u', 'certmonger', '--since={}'.format(self.since)
        ])
        assert exp_str in result.stdout_text

    def test_ipa_getcert_san_aci(self):
        """Test for DNS and IP SAN extensions + ACIs
        """
        hostname = self.clients[0].hostname
        certfile = os.path.join(paths.OPENSSL_CERTS_DIR, "test2.pem")

        tasks.kinit_admin(self.master)

        zone = tasks.prepare_reverse_zone(self.master, self.clients[0].ip)[0]

        # add PTR dns record for cert request with SAN extention
        rec = str(self.clients[0].ip).split('.')[3]
        result = self.master.run_command(
            ['ipa', 'dnsrecord-add', zone, rec, '--ptr-rec', hostname]
        )
        assert 'Record name: {}'.format(rec) in result.stdout_text
        assert 'PTR record: {}'.format(hostname) in result.stdout_text

        name, zone = hostname.split('.', 1)
        self.master.run_command(['ipa', 'dnsrecord-show', zone, name])
        tasks.kdestroy_all(self.master)

        cmd_arg = [
            'ipa-getcert', 'request', '-v', '-w',
            '-f', certfile,
            '-k', os.path.join(paths.OPENSSL_PRIVATE_DIR, "test2.key"),
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
            ["rm", "-fv", os.path.join(paths.OPENSSL_PRIVATE_DIR, "test.key")]
        )
        self.master.run_command(
            ["rm", "-fv", os.path.join(paths.OPENSSL_CERTS_DIR, "test.pem")]
        )

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
            "-k", os.path.join(paths.OPENSSL_PRIVATE_DIR, "test.key"),
            "-f", os.path.join(paths.OPENSSL_CERTS_DIR, "test.pem"),
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


class TestCertmongerRekey(IntegrationTest):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    @pytest.fixture
    def request_cert(self):
        """Fixture to request and remove a certificate"""
        self.request_id = ''.join(
            random.choice(
                string.ascii_lowercase
            ) for i in range(10)
        )
        self.master.run_command(
            [
                'ipa-getcert', 'request',
                '-f',
                os.path.join(
                    paths.OPENSSL_CERTS_DIR, f"{self.request_id}.pem",
                ),
                '-k',
                os.path.join(
                    paths.OPENSSL_PRIVATE_DIR, f"{self.request_id}.key"
                ),
                '-I', self.request_id,
                '-K', 'test/{}'.format(self.master.hostname)
            ]
        )
        status = tasks.wait_for_request(self.master, self.request_id, 100)
        assert status == "MONITORING"

        yield

        self.master.run_command(['getcert', 'stop-tracking',
                                 '-i', self.request_id])
        self.master.run_command(
            [
                "rm",
                "-rf",
                os.path.join(
                    paths.OPENSSL_CERTS_DIR, f"{self.request_id}.pem"
                ),
            ]
        )
        self.master.run_command(
            [
                "rm",
                "-rf",
                os.path.join(
                    paths.OPENSSL_PRIVATE_DIR, f"{self.request_id}.key"
                ),
            ]
        )

    def test_certmonger_rekey_keysize(self, request_cert):
        """Test certmonger rekey command works fine

        Certmonger's rekey command was throwing an error as
        unrecognized command. Test is to check if -g (keysize)
        option is working fine.

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1249165
        """
        certdata = self.master.get_file_contents(
            os.path.join(paths.OPENSSL_CERTS_DIR, f"{self.request_id}.pem")
        )
        cert = x509.load_pem_x509_certificate(
            certdata, default_backend()
        )
        assert cert.public_key().key_size == 2048

        # rekey with key size 3072
        self.master.run_command(['getcert', 'rekey',
                                 '-i', self.request_id,
                                 '-g', '3072'])

        status = tasks.wait_for_request(self.master, self.request_id, 100)
        assert status == "MONITORING"

        certdata = self.master.get_file_contents(
            os.path.join(paths.OPENSSL_CERTS_DIR, f"{self.request_id}.pem")
        )
        cert = x509.load_pem_x509_certificate(
            certdata, default_backend()
        )
        # check if rekey command updated the key size
        assert cert.public_key().key_size == 3072

    def test_rekey_keytype_RSA(self, request_cert):
        """Test certmonger rekey command works fine

        Certmonger's rekey command was throwing an error as
        unrecognized command. Test is to check if -G (keytype)
        option is working fine. Currently only RSA type is supported

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1249165
        """
        # rekey with RSA key type
        self.master.run_command(['getcert', 'rekey',
                                 '-i', self.request_id,
                                 '-g', '3072',
                                 '-G', 'RSA'])
        status = tasks.wait_for_request(self.master, self.request_id, 100)
        assert status == "MONITORING"

    def test_rekey_request_id(self, request_cert):
        """Test certmonger rekey command works fine

        Test is to check if -I (request id name) option is working fine.

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1249165
        """
        new_req_id = 'newtest'
        # rekey with -I option
        result = self.master.run_command(['getcert', 'rekey',
                                          '-i', self.request_id,
                                          '-I', new_req_id])
        # above command output: Resubmitting "newtest" to "IPA".
        assert new_req_id in result.stdout_text

        # rename back the request id for fixture to delete it
        result = self.master.run_command(['getcert', 'rekey',
                                          '-i', new_req_id,
                                          '-I', self.request_id])
        assert self.request_id in result.stdout_text

    def test_rekey_keytype_DSA(self):
        """Test certmonger rekey command works fine

        Test is to check if -G (keytype) with DSA fails

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1249165
        """
        result = self.master.run_command(
            [
                'ipa-getcert', 'request',
                '-f', os.path.join(paths.OPENSSL_CERTS_DIR, "test_dsa.pem"),
                '-k', os.path.join(paths.OPENSSL_PRIVATE_DIR, "test_dsa.key"),
                '-K', 'test/{}'.format(self.master.hostname),
            ]
        )
        req_id = re.findall(r'\d+', result.stdout_text)
        status = tasks.wait_for_request(self.master, req_id[0], 100)
        assert status == "MONITORING"

        # rekey with RSA key type
        self.master.run_command(['getcert', 'rekey',
                                 '-i', req_id[0],
                                 '-g', '3072',
                                 '-G', 'DSA'])
        time.sleep(100)
        # look for keytpe as DSA in request file
        self.master.run_command([
            'grep',
            'DSA',
            os.path.join(paths.CERTMONGER_REQUESTS_DIR, req_id[0]),
        ])

        err_msg = 'Unable to create enrollment request: Invalid Request'
        result = self.master.run_command(['getcert', 'list', '-i', req_id[0]])
        assert err_msg in result.stdout_text


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
