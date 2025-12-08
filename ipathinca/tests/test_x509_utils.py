# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Tests for X.509 utility functions

Tests DN conversion, OID mappings, signature algorithm parsing,
key usage extensions, and build_x509_name.
"""

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from ipapython.dn import DN

from ipathinca.x509_utils import (
    OID_TO_SHORTNAME,
    SHORTNAME_TO_OID,
    cert_name_to_ipa_dn,
    ipa_dn_to_x509_name,
    build_x509_name,
    get_dn_components,
    decode_ldap_attribute,
    parse_signature_algorithm,
    get_default_algorithm_for_key,
    get_ca_key_usage_extension,
    get_service_key_usage_extension,
    get_ocsp_key_usage_extension,
    get_subsystem_key_usage_extension,
    get_audit_key_usage_extension,
    get_server_extended_key_usage,
    get_ocsp_extended_key_usage,
    get_subsystem_extended_key_usage,
    get_pkinit_extended_key_usage,
)


# ======================================================================
# OID mappings
# ======================================================================


class TestOIDMappings:
    """Test OID_TO_SHORTNAME and SHORTNAME_TO_OID."""

    def test_common_oids_present(self):
        """Common OIDs are mapped."""
        assert NameOID.COMMON_NAME in OID_TO_SHORTNAME
        assert NameOID.ORGANIZATION_NAME in OID_TO_SHORTNAME
        assert NameOID.COUNTRY_NAME in OID_TO_SHORTNAME
        assert NameOID.DOMAIN_COMPONENT in OID_TO_SHORTNAME

    def test_shortname_to_oid_cn(self):
        """CN maps to COMMON_NAME OID."""
        assert SHORTNAME_TO_OID["CN"] == NameOID.COMMON_NAME

    def test_shortname_to_oid_email_variants(self):
        """emailAddress has case variants."""
        assert SHORTNAME_TO_OID["emailAddress"] == NameOID.EMAIL_ADDRESS
        assert SHORTNAME_TO_OID["EMAILADDRESS"] == NameOID.EMAIL_ADDRESS
        assert SHORTNAME_TO_OID["email"] == NameOID.EMAIL_ADDRESS

    def test_bidirectional_consistency(self):
        """Every OID_TO_SHORTNAME entry has a reverse mapping."""
        for oid, shortname in OID_TO_SHORTNAME.items():
            assert shortname in SHORTNAME_TO_OID, (
                f"Missing reverse mapping for {shortname}"
            )
            assert SHORTNAME_TO_OID[shortname] == oid


# ======================================================================
# DN conversion
# ======================================================================


class TestDNConversion:
    """Test DN conversion functions."""

    def test_cert_name_to_ipa_dn_simple(self):
        """Convert simple x509.Name to IPA DN."""
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EXAMPLE.COM"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
        ])
        dn = cert_name_to_ipa_dn(name)
        dn_str = str(dn)
        assert "CN=Test User" in dn_str
        assert "O=EXAMPLE.COM" in dn_str

    def test_cert_name_to_ipa_dn_reverse_default(self):
        """Default reverse=True reverses order for IPA format."""
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EXAMPLE.COM"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
        ])
        dn = cert_name_to_ipa_dn(name, reverse=True)
        dn_str = str(dn)
        # CN should come first in IPA DN format
        assert dn_str.startswith("CN=")

    def test_ipa_dn_to_x509_name(self):
        """Convert IPA DN string to x509.Name."""
        name = ipa_dn_to_x509_name("CN=Test,O=EXAMPLE.COM")
        components = list(name)
        # x509.Name stores in reverse, so check by attribute
        cn_found = any(
            attr.oid == NameOID.COMMON_NAME and attr.value == "Test"
            for attr in components
        )
        o_found = any(
            attr.oid == NameOID.ORGANIZATION_NAME
            and attr.value == "EXAMPLE.COM"
            for attr in components
        )
        assert cn_found
        assert o_found

    def test_get_dn_components(self):
        """get_dn_components returns correct tuples."""
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EXAMPLE.COM"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
        ])
        components = get_dn_components(name)
        # Most-specific-first
        assert components[0] == ("CN", "Test")
        assert components[1] == ("O", "EXAMPLE.COM")


# ======================================================================
# build_x509_name
# ======================================================================


class TestBuildX509Name:
    """Test build_x509_name utility."""

    def test_from_list_of_tuples(self):
        """Build from list of tuples."""
        name = build_x509_name([("CN", "Test"), ("O", "Example")])
        components = get_dn_components(name)
        assert ("CN", "Test") in components
        assert ("O", "Example") in components

    def test_from_dict(self):
        """Build from dict."""
        name = build_x509_name({"CN": "Test", "O": "Example"})
        components = get_dn_components(name)
        assert ("CN", "Test") in components
        assert ("O", "Example") in components

    def test_standard_dn_ordering_applied(self):
        """Attributes are reordered by STANDARD_DN_ORDER internally."""
        # Input in non-standard order
        name = build_x509_name([
            ("O", "Org"),
            ("C", "US"),
            ("CN", "Test"),
        ])
        # x509.Name stores in STANDARD_DN_ORDER: [CN, O, C]
        # rfc4514_string reverses: "C=US,O=Org,CN=Test"
        rfc4514 = name.rfc4514_string()
        assert "CN=Test" in rfc4514
        assert "O=Org" in rfc4514
        assert "C=US" in rfc4514

    def test_reverse_gives_display_order(self):
        """reverse=True produces CN-first RFC 4514 display."""
        name = build_x509_name(
            [("O", "Example"), ("CN", "Test")], reverse=True
        )
        rfc4514 = name.rfc4514_string()
        assert rfc4514.startswith("CN=")


# ======================================================================
# decode_ldap_attribute
# ======================================================================


class TestDecodeLdapAttribute:
    """Test LDAP attribute decoding."""

    def test_bytes_to_str(self):
        """Decode bytes to str."""
        assert decode_ldap_attribute(b"hello") == "hello"

    def test_str_passthrough(self):
        """str passes through unchanged."""
        assert decode_ldap_attribute("hello") == "hello"

    def test_bytes_to_int(self):
        """Decode bytes to int."""
        assert decode_ldap_attribute(b"42", int) == 42

    def test_str_to_int(self):
        """Decode str to int."""
        assert decode_ldap_attribute("42", int) == 42

    def test_bytes_to_bool_true(self):
        """Decode bytes to bool (TRUE)."""
        assert decode_ldap_attribute(b"TRUE", bool) is True
        assert decode_ldap_attribute(b"1", bool) is True
        assert decode_ldap_attribute(b"YES", bool) is True

    def test_bytes_to_bool_false(self):
        """Decode bytes to bool (FALSE)."""
        assert decode_ldap_attribute(b"FALSE", bool) is False
        assert decode_ldap_attribute(b"no", bool) is False

    def test_none(self):
        """None returns None."""
        assert decode_ldap_attribute(None) is None


# ======================================================================
# Signature algorithm parsing
# ======================================================================


class TestParseSignatureAlgorithm:
    """Test parse_signature_algorithm."""

    def test_sha256_with_rsa(self):
        """SHA256withRSA returns SHA256."""
        alg = parse_signature_algorithm("SHA256withRSA")
        assert isinstance(alg, hashes.SHA256)

    def test_sha384_with_rsa(self):
        """SHA384withRSA returns SHA384."""
        alg = parse_signature_algorithm("SHA384withRSA")
        assert isinstance(alg, hashes.SHA384)

    def test_sha512_with_rsa(self):
        """SHA512withRSA returns SHA512."""
        alg = parse_signature_algorithm("SHA512withRSA")
        assert isinstance(alg, hashes.SHA512)

    def test_sha1_with_rsa(self):
        """SHA1withRSA returns SHA1."""
        alg = parse_signature_algorithm("SHA1withRSA")
        assert isinstance(alg, hashes.SHA1)

    def test_sha256_with_ec(self):
        """SHA256withEC returns SHA256."""
        alg = parse_signature_algorithm("SHA256withEC")
        assert isinstance(alg, hashes.SHA256)

    def test_case_insensitive(self):
        """Algorithm parsing is case-insensitive."""
        alg = parse_signature_algorithm("sha256withRSA")
        assert isinstance(alg, hashes.SHA256)

    def test_unknown_raises(self):
        """Unknown algorithm raises ValueError."""
        with pytest.raises(ValueError):
            parse_signature_algorithm("UnknownAlgorithm")


# ======================================================================
# get_default_algorithm_for_key
# ======================================================================


class TestDefaultAlgorithmForKey:
    """Test get_default_algorithm_for_key."""

    def test_rsa_key(self):
        """RSA key returns SHA256withRSA."""
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        assert get_default_algorithm_for_key(key.public_key()) == \
            "SHA256withRSA"

    def test_ec_key(self):
        """EC key returns SHA256withEC."""
        key = ec.generate_private_key(ec.SECP256R1())
        assert get_default_algorithm_for_key(key.public_key()) == \
            "SHA256withEC"


# ======================================================================
# KeyUsage extensions
# ======================================================================


class TestKeyUsageExtensions:
    """Test KeyUsage extension builders."""

    def test_ca_key_usage(self):
        """CA KeyUsage allows cert signing, CRL signing, digital sig."""
        ku = get_ca_key_usage_extension()
        assert ku.digital_signature
        assert ku.key_cert_sign
        assert ku.crl_sign
        assert not ku.key_encipherment

    def test_service_key_usage(self):
        """Service KeyUsage allows digital sig and key encipherment."""
        ku = get_service_key_usage_extension()
        assert ku.digital_signature
        assert ku.key_encipherment
        assert not ku.key_cert_sign
        assert not ku.crl_sign

    def test_ocsp_key_usage(self):
        """OCSP KeyUsage allows digital sig, key and data encipherment."""
        ku = get_ocsp_key_usage_extension()
        assert ku.digital_signature
        assert ku.key_encipherment
        assert ku.data_encipherment

    def test_audit_key_usage(self):
        """Audit KeyUsage includes content_commitment (non-repudiation)."""
        ku = get_audit_key_usage_extension()
        assert ku.digital_signature
        assert ku.content_commitment
        assert not ku.key_encipherment

    def test_subsystem_key_usage(self):
        """Subsystem KeyUsage allows digital sig and key encipherment."""
        ku = get_subsystem_key_usage_extension()
        assert ku.digital_signature
        assert ku.key_encipherment


# ======================================================================
# ExtendedKeyUsage extensions
# ======================================================================


class TestExtendedKeyUsageExtensions:
    """Test ExtendedKeyUsage extension builders."""

    def test_server_eku(self):
        """Server EKU includes server and client auth."""
        eku = get_server_extended_key_usage()
        oids = list(eku)
        assert ExtendedKeyUsageOID.SERVER_AUTH in oids
        assert ExtendedKeyUsageOID.CLIENT_AUTH in oids

    def test_ocsp_eku(self):
        """OCSP EKU includes OCSP signing."""
        eku = get_ocsp_extended_key_usage()
        oids = list(eku)
        assert ExtendedKeyUsageOID.OCSP_SIGNING in oids

    def test_subsystem_eku(self):
        """Subsystem EKU includes client and server auth."""
        eku = get_subsystem_extended_key_usage()
        oids = list(eku)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in oids
        assert ExtendedKeyUsageOID.SERVER_AUTH in oids

    def test_pkinit_eku(self):
        """PKINIT EKU includes KDC OID."""
        eku = get_pkinit_extended_key_usage()
        oids = [str(oid.dotted_string) for oid in eku]
        assert "1.3.6.1.5.2.3.5" in oids
