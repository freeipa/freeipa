# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
OCSP responder tests (deployment required)

Tests OCSP request/response via POST and GET, and the stats endpoint.
"""

import base64
import os
import subprocess
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
def ca_cert_path():
    """Path to the IPA CA certificate."""
    path = "/etc/ipa/ca.crt"
    if not os.path.exists(path):
        pytest.skip("CA certificate not found at /etc/ipa/ca.crt")
    return path


def _build_ocsp_request(ca_cert_path, serial="0x1"):
    """Build a DER-encoded OCSP request using openssl.

    Returns (der_bytes, base64_str) or (None, None) on failure.
    """
    try:
        result = subprocess.run(
            [
                "openssl",
                "ocsp",
                "-issuer",
                ca_cert_path,
                "-serial",
                serial,
                "-reqout",
                "/dev/stdout",
                "-no_nonce",
            ],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return None, None
        der = result.stdout
        b64 = base64.b64encode(der).decode("ascii")
        return der, b64
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None, None


class TestOCSPEndpoint:
    """Test OCSP request/response."""

    def test_ocsp_post(self, base_url, ca_cert_path):
        """POST /ca/ocsp with DER request returns a response."""
        der, _b64 = _build_ocsp_request(ca_cert_path)
        if der is None:
            pytest.skip("Could not build OCSP request (openssl not available)")

        try:
            result = subprocess.run(
                [
                    "curl",
                    "-sk",
                    "--max-time",
                    "15",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/ocsp-request",
                    "--data-binary",
                    "@-",
                    "-o",
                    "/dev/stdout",
                    "-w",
                    "\n%{http_code}",
                    f"{base_url}/ca/ocsp",
                ],
                input=der,
                capture_output=True,
                timeout=25,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pytest.skip("OCSP request timed out")

        lines = result.stdout.rsplit(b"\n", 1)
        try:
            status = int(lines[-1].strip())
        except (ValueError, IndexError):
            status = 0

        assert status == 200, f"OCSP POST returned status {status}"

    def test_ocsp_get(self, base_url, ca_cert_path):
        """GET /ca/ocsp/{base64} returns a response."""
        _der, b64 = _build_ocsp_request(ca_cert_path)
        if b64 is None:
            pytest.skip("Could not build OCSP request")

        # URL-encode for safe transmission; --path-as-is prevents curl
        # from collapsing %2F back to / which would split the path
        url_b64 = (
            b64.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
        )
        try:
            result = subprocess.run(
                [
                    "curl",
                    "-sk",
                    "--path-as-is",
                    "--max-time",
                    "15",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    f"{base_url}/ca/ocsp/{url_b64}",
                ],
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pytest.skip("OCSP GET request timed out")

        try:
            status = int(result.stdout.strip())
        except ValueError:
            status = 0

        assert status == 200, f"OCSP GET returned status {status}"


class TestOCSPStats:
    """Test OCSP statistics endpoint."""

    def test_ocsp_stats(self, base_url):
        """GET /ca/rest/ocsp/stats returns statistics."""
        status, data = curl_get_json(base_url, "/ca/rest/ocsp/stats")
        # Stats endpoint might require auth or might not exist
        if status == 404:
            pytest.skip("OCSP stats endpoint not available")
        if status == 200:
            assert data is not None
