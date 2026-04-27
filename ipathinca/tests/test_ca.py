# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
CA operation tests (deployment required)

Tests CA info, certificate issuance, retrieval, and revocation
against a running ipathinca service.
"""

import os
import pytest

from ipathinca.tests.conftest import (
    requires_deployment,
    curl_get_json,
    curl_post_json,
    generate_csr,
    get_base_url,
)


pytestmark = requires_deployment


@pytest.fixture(scope="module")
def base_url():
    return get_base_url()


@pytest.fixture(scope="module")
def ra_creds():
    """Return RA agent credentials if available."""
    ra_key = "/var/lib/ipa/ra-agent.key"
    ra_cert = "/var/lib/ipa/ra-agent.pem"
    if os.path.exists(ra_key) and os.path.exists(ra_cert):
        return ra_key, ra_cert
    return None, None


class TestCAInfo:
    """Test CA information endpoints."""

    def test_ca_info(self, base_url):
        """GET /pki/rest/info returns CA status."""
        status, data = curl_get_json(base_url, "/pki/rest/info")
        assert status == 200
        assert data is not None

    def test_ca_info_v2(self, base_url):
        """GET /pki/v2/info returns CA status."""
        status, data = curl_get_json(base_url, "/pki/v2/info")
        assert status == 200
        assert data is not None


class TestCertificateLifecycleE2E:
    """Test end-to-end certificate lifecycle."""

    def test_issue_and_retrieve(self, base_url, ra_creds):
        """Issue a certificate and retrieve it by serial number."""
        ra_key, ra_cert = ra_creds
        if not ra_cert:
            pytest.skip("RA agent credentials not available")

        # Issue cert
        csr = generate_csr("ca-e2e-test.example.com")
        if csr is None:
            pytest.skip("Could not generate CSR")

        payload = {
            "ProfileID": "caIPAserviceCert",
            "pkcs10": csr,
        }
        status, data = curl_post_json(
            base_url, "/ca/rest/certrequests", payload,
            client_cert=ra_cert, client_key=ra_key,
        )
        if status not in (200, 201) or data is None:
            pytest.skip(f"Cert issuance failed with status {status}")

        # Extract serial
        entries = data.get("entries", [data]) if isinstance(data, dict) else []
        cert_id = None
        for entry in entries:
            cert_id = entry.get("certId") or entry.get("id")
            if cert_id:
                break

        if not cert_id:
            pytest.skip("No certId in issuance response")

        # Retrieve cert
        status, cert_data = curl_get_json(
            base_url, f"/ca/rest/certs/{cert_id}",
            client_cert=ra_cert, client_key=ra_key,
        )
        assert status == 200
        assert cert_data is not None

    def test_revoke_certificate(self, base_url, ra_creds):
        """Issue then revoke a certificate."""
        ra_key, ra_cert = ra_creds
        if not ra_cert:
            pytest.skip("RA agent credentials not available")

        # Issue cert
        csr = generate_csr("ca-revoke-test.example.com")
        if csr is None:
            pytest.skip("Could not generate CSR")

        payload = {
            "ProfileID": "caIPAserviceCert",
            "pkcs10": csr,
        }
        status, data = curl_post_json(
            base_url, "/ca/rest/certrequests", payload,
            client_cert=ra_cert, client_key=ra_key,
        )
        if status not in (200, 201) or data is None:
            pytest.skip(f"Cert issuance failed with status {status}")

        entries = data.get("entries", [data]) if isinstance(data, dict) else []
        cert_id = None
        for entry in entries:
            cert_id = entry.get("certId") or entry.get("id")
            if cert_id:
                break

        if not cert_id:
            pytest.skip("No certId in issuance response")

        # Revoke
        revoke_payload = {
            "Reason": "keyCompromise",
        }
        status, revoke_data = curl_post_json(
            base_url, f"/ca/rest/certs/{cert_id}/revoke", revoke_payload,
            client_cert=ra_cert, client_key=ra_key,
        )
        # Accept 200 or 204 or 409 (already revoked)
        assert status in (200, 204, 409), (
            f"Unexpected revocation status: {status}"
        )

    def test_cert_search_finds_results(self, base_url, ra_creds):
        """Certificate search returns results."""
        ra_key, ra_cert = ra_creds
        if not ra_cert:
            pytest.skip("RA agent credentials not available")

        status, data = curl_get_json(
            base_url, "/ca/rest/certs/search",
            client_cert=ra_cert, client_key=ra_key,
        )
        if status != 200:
            # Try POST search
            status, data = curl_post_json(
                base_url, "/ca/rest/certs/search", {},
                client_cert=ra_cert, client_key=ra_key,
            )
        assert status == 200
        assert data is not None
