# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Shared test infrastructure for ipathinca tests

Provides common fixtures, helpers, and markers used across all test modules.
"""

import configparser
import json
import os
import subprocess

import pytest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes


def _service_is_active():
    """Check if ipathinca.service is running."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "ipathinca.service"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "active"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


requires_deployment = pytest.mark.skipif(
    not _service_is_active(),
    reason="ipathinca.service not active",
)


@pytest.fixture(scope="module")
def ipathinca_config():
    """Initialize ipathinca global config for tests that need it.

    Reads /etc/ipa/ipathinca.conf if available, otherwise builds a
    minimal config from defaults.
    """
    import ipathinca

    conf_path = Path("/etc/ipa/ipathinca.conf")
    cfg = configparser.RawConfigParser()

    if conf_path.exists():
        cfg.read(str(conf_path))
    else:
        cfg.add_section("global")
        cfg.set("global", "realm", "IPA.TEST")
        cfg.set("global", "domain", "ipa.test")
        cfg.set("global", "basedn", "dc=ipa,dc=test")
        cfg.add_section("ca")

    ipathinca.set_global_config(cfg)
    return cfg


@pytest.fixture
def variable_context(ipathinca_config):
    """Provide variable substitution context for profile parsing."""
    realm = ipathinca_config.get("global", "realm")
    domain = ipathinca_config.get("global", "domain")
    return {
        "DOMAIN": domain,
        "IPA_CA_RECORD": f"ipa-ca.{domain}",
        "SUBJECT_DN_O": realm,
        "CRL_ISSUER": f"CN=Certificate Authority,O={realm}",
        "REALM": realm,
    }


@pytest.fixture
def sample_key():
    """Generate a sample RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@pytest.fixture
def sample_csr(ipathinca_config, sample_key):
    """Generate a sample CSR with proper DN ordering."""
    realm = ipathinca_config.get("global", "realm")
    domain = ipathinca_config.get("global", "domain")

    subject = x509.Name(
        [
            x509.NameAttribute(
                x509.oid.NameOID.ORGANIZATION_NAME, realm
            ),
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, f"server.{domain}"
            ),
        ]
    )

    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(sample_key, hashes.SHA256())
    )


@pytest.fixture(scope="module")
def ra_credentials():
    """Return RA agent certificate/key paths if available."""
    ra_key = "/var/lib/ipa/ra-agent.key"
    ra_cert = "/var/lib/ipa/ra-agent.pem"
    if os.path.exists(ra_key) and os.path.exists(ra_cert):
        return ra_key, ra_cert
    return None, None


# ======================================================================
# HTTP helpers for deployment tests
# ======================================================================


def curl_get_json(base_url, path, timeout=30, client_cert=None,
                  client_key=None):
    """Make an HTTPS GET request and return (status_code, json_body).

    Returns (0, None) if the connection failed.
    """
    cmd = [
        "curl", "-sk", "--max-time", str(timeout),
        "-H", "Accept: application/json",
        "-w", "\n%{http_code}",
    ]
    if client_cert:
        cmd.extend(["--cert", client_cert])
    if client_key:
        cmd.extend(["--key", client_key])
    cmd.append(f"{base_url}{path}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired:
        return 0, None
    lines = result.stdout.rsplit("\n", 1)
    body = lines[0] if len(lines) > 1 else ""
    try:
        status = int(lines[-1].strip()) if lines[-1].strip() else 0
    except ValueError:
        status = 0
    try:
        data = json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        data = None
    return status, data


def curl_post_json(base_url, path, payload, timeout=30, client_cert=None,
                   client_key=None):
    """Make an HTTPS POST request with JSON body, return (status, json).

    Returns (0, None) if the connection failed.
    """
    cmd = [
        "curl", "-sk", "--max-time", str(timeout),
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "-H", "Accept: application/json",
        "-d", json.dumps(payload),
        "-w", "\n%{http_code}",
    ]
    if client_cert:
        cmd.extend(["--cert", client_cert])
    if client_key:
        cmd.extend(["--key", client_key])
    cmd.append(f"{base_url}{path}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired:
        return 0, None
    lines = result.stdout.rsplit("\n", 1)
    body = lines[0] if len(lines) > 1 else ""
    try:
        status = int(lines[-1].strip()) if lines[-1].strip() else 0
    except ValueError:
        status = 0
    try:
        data = json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        data = None
    return status, data


def generate_csr(cn="test.example.com"):
    """Generate a fresh CSR using openssl."""
    result = subprocess.run(
        [
            "openssl", "req", "-new", "-newkey", "rsa:2048",
            "-nodes", "-keyout", "/dev/null",
            "-subj", f"/CN={cn}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def get_base_url():
    """Get the ipathinca service base URL from config."""
    cfg = configparser.ConfigParser()
    cfg.read("/etc/ipa/ipathinca.conf")
    port = cfg.get("server", "https_port", fallback="8443")
    return f"https://localhost:{port}"
