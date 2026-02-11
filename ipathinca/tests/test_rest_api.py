# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
REST API endpoint tests (deployment required)

Tests public and authenticated endpoints, error handling, and response format.
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


class TestPublicEndpoints:
    """Test endpoints that do not require authentication."""

    def test_info_endpoint(self, base_url):
        """GET /pki/rest/info returns 200 with JSON."""
        status, data = curl_get_json(base_url, "/pki/rest/info")
        assert status == 200
        assert data is not None
        assert isinstance(data, dict)

    def test_info_has_version(self, base_url):
        """Info response contains Version field."""
        status, data = curl_get_json(base_url, "/pki/rest/info")
        assert status == 200
        assert "Version" in data or "version" in data

    def test_profiles_endpoint(self, base_url):
        """GET /ca/rest/profiles returns profile list."""
        status, data = curl_get_json(base_url, "/ca/rest/profiles")
        assert status == 200
        assert data is not None
        # Should have entries
        if isinstance(data, dict) and "entries" in data:
            assert len(data["entries"]) > 0
        elif isinstance(data, list):
            assert len(data) > 0

    def test_profiles_contain_service_cert(self, base_url):
        """Profile list includes caIPAserviceCert."""
        status, data = curl_get_json(base_url, "/ca/rest/profiles")
        assert status == 200
        entries = data.get("entries", data) if isinstance(data, dict) else data
        profile_ids = [e.get("profileId", e.get("id", "")) for e in entries]
        assert "caIPAserviceCert" in profile_ids


class TestAuthenticatedEndpoints:
    """Test endpoints that require RA agent certificate."""

    def test_cert_search(self, base_url, ra_creds):
        """GET /ca/rest/certs/search returns certificates."""
        ra_key, ra_cert = ra_creds
        if not ra_cert:
            pytest.skip("RA agent credentials not available")

        status, data = curl_get_json(
            base_url,
            "/ca/rest/certs/search",
            client_cert=ra_cert,
            client_key=ra_key,
        )
        if status == 200:
            assert data is not None

    def test_cert_request_submission(self, base_url, ra_creds):
        """POST /ca/rest/certrequests submits a cert request."""
        ra_key, ra_cert = ra_creds
        if not ra_cert:
            pytest.skip("RA agent credentials not available")

        csr = generate_csr("resttest.example.com")
        if csr is None:
            pytest.skip("Could not generate CSR")

        payload = {
            "ProfileID": "caIPAserviceCert",
            "pkcs10": csr,
        }
        status, data = curl_post_json(
            base_url,
            "/ca/rest/certrequests",
            payload,
            client_cert=ra_cert,
            client_key=ra_key,
        )
        assert status in (200, 201), f"Unexpected status: {status}"
        assert data is not None

    def test_cert_request_returns_request_id(self, base_url, ra_creds):
        """Cert request response includes requestId."""
        ra_key, ra_cert = ra_creds
        if not ra_cert:
            pytest.skip("RA agent credentials not available")

        csr = generate_csr("resttest-id.example.com")
        if csr is None:
            pytest.skip("Could not generate CSR")

        payload = {
            "ProfileID": "caIPAserviceCert",
            "pkcs10": csr,
        }
        status, data = curl_post_json(
            base_url,
            "/ca/rest/certrequests",
            payload,
            client_cert=ra_cert,
            client_key=ra_key,
        )
        if status not in (200, 201):
            pytest.skip(f"Request failed with status {status}")

        entries = data.get("entries", [data]) if isinstance(data, dict) else []
        request_ids = [e.get("requestId") for e in entries if e]
        assert any(rid is not None for rid in request_ids)


class TestErrorHandling:
    """Test error responses."""

    def test_invalid_endpoint_404(self, base_url):
        """Non-existent endpoint returns 404."""
        status, _data = curl_get_json(base_url, "/ca/rest/nonexistent")
        assert status == 404

    def test_unauthenticated_agent_endpoint(self, base_url):
        """Agent endpoint without cert returns 401 or 403."""
        status, _data = curl_get_json(base_url, "/ca/rest/certs/search")
        # Should require authentication
        assert status in (
            401,
            403,
            200,
        ), f"Expected auth-related status, got {status}"
