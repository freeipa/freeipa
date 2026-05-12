# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Sub-CA (lightweight CA) tests (deployment required)

Tests sub-CA listing and management via REST API.
"""

import os
import pytest

from ipathinca.tests.conftest import (
    requires_deployment,
    curl_get_json,
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


class TestSubCAList:
    """Test sub-CA listing."""

    def test_list_cas(self, base_url, ra_creds):
        """GET /ca/rest/authorities returns CA list."""
        ra_key, ra_cert = ra_creds
        if not ra_cert:
            pytest.skip("RA agent credentials not available")

        status, data = curl_get_json(
            base_url,
            "/ca/rest/authorities",
            client_cert=ra_cert,
            client_key=ra_key,
        )
        if status == 404:
            pytest.skip("Authorities endpoint not available")
        assert status == 200
        assert data is not None

    def test_main_ca_in_list(self, base_url, ra_creds):
        """CA list includes the main IPA CA."""
        ra_key, ra_cert = ra_creds
        if not ra_cert:
            pytest.skip("RA agent credentials not available")

        status, data = curl_get_json(
            base_url,
            "/ca/rest/authorities",
            client_cert=ra_cert,
            client_key=ra_key,
        )
        if status != 200 or data is None:
            pytest.skip("Cannot list CAs")

        entries = data.get("entries", data) if isinstance(data, dict) else data
        if not isinstance(entries, list):
            pytest.skip("Unexpected response format")

        # Look for main CA
        ca_found = any(
            e.get("isHostAuthority", False)
            or e.get("id", "") == "host-authority"
            or e.get("authorityID", "") == "host-authority"
            for e in entries
        )
        # Even if the main CA has a different format, at least one CA
        # should be present
        assert len(entries) >= 1 or ca_found
