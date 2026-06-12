#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various feature
under PQC enabled installs.
"""

import os
import re

import pytest
from ipaplatform.paths import paths

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestPQCMasterClientCerts(IntegrationTest):
    """
    Install with an ML-DSA CA and run basic post-install checks.

    These tests validate that:
    - installation succeeds with ML-DSA CA options
    - certmonger tracks the expected installed certificates and shows profiles
    - user cert request with ML-DSA CSR is successful [expected-fail] IDM-6497
    - client host cert request with ML-DSA key is successful
      [expected-fail] IDM-6498
    """

    num_clients = 1
    topology = "line"

    ipa_key_type = "mldsa"
    ca_key_type = "mldsa"

    @classmethod
    def install(cls, mh):
        """Install master+client using ML-DSA IPA keys and ML-DSA CA."""
        extra_args = [
            "--key-type-size", cls.ipa_key_type,
            "--ca-key-type", cls.ca_key_type,
        ]
        tasks.install_master(cls.master, setup_dns=True, extra_args=extra_args)
        tasks.add_a_records_for_hosts_in_master_domain(cls.master)
        tasks.install_clients([cls.master], cls.clients)

    def test_getcert_list_profile_installed_certs(self):
        """Verify install-time certs are tracked with correct profiles."""
        result = self.master.run_command(
            ["getcert", "list", "-f", paths.HTTPD_CERT_FILE]
        )
        assert "profile: caIPAserviceCert" in result.stdout_text

        result = self.master.run_command(
            ["getcert", "list", "-n", "Server-Cert cert-pki-ca"]
        )
        assert "profile: caServerCert" in result.stdout_text

    def test_user_cert_request_mldsa_csr(self):
        """Request a user cert with an ML-DSA CSR (expected-fail for now)."""
        user = "pqcuser1"
        csr = "/tmp/pqcuser1.csr"
        key = "/tmp/pqcuser1.key"
        crt = "/tmp/pqcuser1.crt"

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, user)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

        algo = "ML-DSA-65"
        probe = os.path.join(paths.OPENSSL_PRIVATE_DIR, ".mldsa-probe.key")
        try:
            gen = self.master.run_command(
                ["openssl", "genpkey", "-algorithm", algo, "-out", probe],
                raiseonerr=False,
            )
            if gen.returncode != 0:
                pytest.skip(
                    "OpenSSL cannot generate %s keys on %s"
                    % (algo, self.master.hostname)
                )
        finally:
            self.master.run_command(["rm", "-f", probe], raiseonerr=False)

        self.master.run_command(
            ["openssl", "genpkey", "-algorithm", algo, "-out", key]
        )
        self.master.run_command(
            [
                "openssl", "req", "-new", "-key", key, "-out", csr,
                "-subj", f"/CN={user}",
            ]
        )

        res = self.master.run_command(
            [
                "ipa", "cert-request", "--principal", user,
                "--certificate-out", crt, csr,
            ],
            raiseonerr=False,
        )
        if res.returncode != 0:
            if "400 Client Error: Bad Request" in res.stderr_text:
                pytest.xfail(
                    "Known ML-DSA CA limitation: IPA cert-request fails "
                    "(Dogtag 400)"
                )
            pytest.fail(res.stderr_text)

        # If it starts working, ensure we got a PEM cert back.
        pem = self.master.get_file_contents(crt)
        assert "BEGIN CERTIFICATE" in pem

        tasks.kdestroy_all(self.master)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

    def test_client_host_cert_request_certmonger(self):
        """Request client host cert with ML-DSA key (expected-fail for now)."""
        host = self.clients[0]
        certfile = os.path.join(paths.OPENSSL_CERTS_DIR, "pqc-client.pem")
        keyfile = os.path.join(paths.OPENSSL_PRIVATE_DIR, "pqc-client.key")

        host.run_command(["rm", "-f", certfile, keyfile], raiseonerr=False)
        out = host.run_command(
            ["ipa-getcert", "request",
             "-f", certfile,
             "-k", keyfile,
             "-K", "test/%s" % host.hostname,
             "-G", "ML-DSA-65"],
            raiseonerr=False,
        )
        if out.returncode != 0:
            # Some environments may not yet support certmonger ML-DSA keygen.
            if "unsupported" in out.stderr_text.lower():
                pytest.skip(
                    "certmonger does not support ML-DSA keygen on this host"
                )
            if "400 Client Error: Bad Request" in out.stderr_text:
                pytest.xfail(
                    "Known ML-DSA CA limitation: ipa-getcert request fails "
                    "(Dogtag 400)"
                )
            pytest.fail(out.stderr_text)

        request_id = re.findall(r"\d+", out.stdout_text)
        if not request_id:
            pytest.fail(
                "Could not parse request id from output:\n"
                f"{out.stdout_text}\n{out.stderr_text}"
            )

        state = tasks.wait_for_request(host, request_id[0], 60)
        if state != "MONITORING":
            if state == "CA_UNREACHABLE":
                pytest.xfail(
                    "Known ML-DSA CA limitation: certmonger reaches "
                    "CA_UNREACHABLE"
                )
            pytest.fail(f"Unexpected request state: {state}")

        pk_out = host.run_command(
            "openssl x509 -in %s -noout -text | grep Public-Key" % certfile,
            raiseonerr=False,
        ).stdout_text
        assert "ML-DSA-65" in pk_out

        host.run_command(
            ["getcert", "stop-tracking", "-i", request_id[0]],
            raiseonerr=False,
        )
        host.run_command(["rm", "-f", certfile, keyfile], raiseonerr=False)
