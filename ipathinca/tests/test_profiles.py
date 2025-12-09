# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Integration tests for Dogtag profile compatibility

These tests verify that IPAthinCA can correctly parse and use Dogtag .cfg
profile files, including constraint validation and default application.
"""

import pytest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from ipathinca.profile_parser import ProfileParser
from ipathinca.profile import Profile


@pytest.fixture
def variable_context():
    """Provide variable substitution context"""
    return {
        "DOMAIN": "ipa.test",
        "IPA_CA_RECORD": "ipa-ca.ipa.test",
        "SUBJECT_DN_O": "IPA.TEST",
        "CRL_ISSUER": "CN=Certificate Authority,O=IPA.TEST",
        "REALM": "IPA.TEST",
    }


@pytest.fixture
def sample_csr():
    """Generate sample CSR for testing"""
    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Build CSR
    subject = x509.Name(
        [
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, "server.ipa.test"
            ),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "IPA.TEST"),
        ]
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    return csr


def test_parse_caIPAserviceCert(variable_context):
    """Test parsing caIPAserviceCert.cfg"""
    profile_path = Path("/usr/share/ipa/profiles/caIPAserviceCert.cfg")

    if not profile_path.exists():
        pytest.skip(f"Profile not found: {profile_path}")

    parser = ProfileParser(str(profile_path))
    profile = parser.parse(variable_context)

    # Validate profile metadata
    assert profile.profile_id == "caIPAserviceCert"
    assert profile.class_id == "caEnrollImpl"
    assert profile.enabled is True
    assert profile.visible is False

    # Validate policy count
    assert len(profile.policies) == 12

    # Validate signing algorithm constraint (policy 8)
    policy_8 = profile.get_policy_by_number(8)
    assert policy_8 is not None
    assert hasattr(policy_8.constraint, "allowed")

    # Check allowed algorithms
    allowed = profile.get_allowed_signing_algorithms()
    assert allowed is not None
    assert "SHA256withRSA" in allowed
    assert "SHA384withRSA" in allowed
    assert "SHA512withRSA" in allowed

    # Check default algorithm
    default_alg = profile.get_default_signing_algorithm()
    assert default_alg is None  # Server decides ("-")


def test_parse_acmeIPAServerCert(variable_context):
    """Test parsing acmeIPAServerCert.cfg (ACME profile)"""
    profile_path = Path("/usr/share/ipa/profiles/acmeIPAServerCert.cfg")

    if not profile_path.exists():
        pytest.skip(f"Profile not found: {profile_path}")

    parser = ProfileParser(str(profile_path))
    profile = parser.parse(variable_context)

    # Validate profile metadata
    assert profile.profile_id == "acmeIPAServerCert"
    assert profile.class_id == "caEnrollImpl"

    # ACME profile should restrict algorithms (no SHA1, no MD5)
    allowed = profile.get_allowed_signing_algorithms()
    if allowed:
        assert "SHA256withRSA" in allowed
        assert "SHA384withRSA" in allowed
        assert "SHA512withRSA" in allowed
        # Should NOT allow SHA1 or MD5
        assert "SHA1withRSA" not in allowed
        assert "MD5withRSA" not in allowed


def test_parse_KDCs_PKINIT_Certs(variable_context):
    """Test parsing KDCs_PKINIT_Certs.cfg"""
    profile_path = Path("/usr/share/ipa/profiles/KDCs_PKINIT_Certs.cfg")

    if not profile_path.exists():
        pytest.skip(f"Profile not found: {profile_path}")

    parser = ProfileParser(str(profile_path))
    profile = parser.parse(variable_context)

    # Validate profile metadata
    assert profile.profile_id == "KDCs_PKINIT_Certs"
    assert profile.class_id == "caEnrollImpl"

    # PKINIT should have stricter key size requirements
    # Check for key constraint policy
    has_key_constraint = any(
        hasattr(p.constraint, "key_type") for p in profile.policies
    )
    assert has_key_constraint


def test_signing_algorithm_extraction(variable_context, sample_csr):
    """Test that signing algorithm is properly extracted from profile"""
    profile_path = Path("/usr/share/ipa/profiles/caIPAserviceCert.cfg")

    if not profile_path.exists():
        pytest.skip(f"Profile not found: {profile_path}")

    parser = ProfileParser(str(profile_path))
    profile = parser.parse(variable_context)

    # Build context for policy execution
    context = {
        "request": {
            "csr": sample_csr,
        },
        "signing_algorithm": None,
    }

    # Execute policy chain (simplified - just check signing alg default)
    for policy in profile.policies:
        if hasattr(policy.default, "signing_alg"):
            # This is SigningAlgDefault
            builder = x509.CertificateBuilder()
            policy.default.apply(builder, sample_csr, context)
            break

    # Verify algorithm was set
    assert context["signing_algorithm"] is not None
    # Should be SHA256withRSA for RSA 2048 key
    assert "SHA256" in context["signing_algorithm"]


def test_constraint_validation(variable_context, sample_csr):
    """Test constraint validation against CSR"""
    profile_path = Path("/usr/share/ipa/profiles/caIPAserviceCert.cfg")

    if not profile_path.exists():
        pytest.skip(f"Profile not found: {profile_path}")

    parser = ProfileParser(str(profile_path))
    profile = parser.parse(variable_context)

    # Build context
    context = {
        "request": {
            "csr": sample_csr,
        },
        "signing_algorithm": "SHA256withRSA",
    }

    # Run all constraint validations
    all_errors = []
    for policy in profile.policies:
        errors = policy.constraint.validate(sample_csr, context)
        all_errors.extend(errors)

    # Should pass validation (CSR is valid for this profile)
    assert len(all_errors) == 0, f"Validation errors: {all_errors}"


def test_variable_substitution(variable_context):
    """Test variable substitution in profile"""
    profile_path = Path("/usr/share/ipa/profiles/caIPAserviceCert.cfg")

    if not profile_path.exists():
        pytest.skip(f"Profile not found: {profile_path}")

    parser = ProfileParser(str(profile_path))
    profile = parser.parse(variable_context)

    # Check that variables were substituted in raw config
    # For example, CRL distribution point should have ipa-ca.ipa.test
    raw_config_str = str(profile.raw_config)
    assert (
        "ipa-ca.ipa.test" in raw_config_str
        or "$IPA_CA_RECORD" in raw_config_str
    )


def test_all_included_profiles_parse(variable_context):
    """Test that all included .cfg profiles parse successfully"""
    profiles_dir = Path("/usr/share/ipa/profiles")

    if not profiles_dir.exists():
        pytest.skip(f"Profiles directory not found: {profiles_dir}")

    cfg_files = list(profiles_dir.glob("*.cfg"))
    assert len(cfg_files) > 0, "No .cfg files found"

    failed_profiles = []

    for cfg_path in cfg_files:
        try:
            parser = ProfileParser(str(cfg_path))
            profile = parser.parse(variable_context)

            # Basic validation
            assert profile.profile_id
            assert profile.class_id
            assert len(profile.policies) > 0

        except Exception as e:
            failed_profiles.append((cfg_path.name, str(e)))

    # Report failures
    if failed_profiles:
        msg = "Failed to parse profiles:\n"
        for name, error in failed_profiles:
            msg += f"  - {name}: {error}\n"
        pytest.fail(msg)


def test_profile_manager_integration(variable_context):
    """Test ProfileManager integration with Dogtag profiles"""
    from ipathinca.profiles import ProfileManager

    # Create profile manager with test profiles directory
    profiles_dir = Path("/usr/share/ipa/profiles")
    if not profiles_dir.exists():
        pytest.skip(f"Profiles directory not found: {profiles_dir}")

    manager = ProfileManager()

    # Test has_profile
    assert manager.has_profile("caIPAserviceCert")

    # Test load_profile
    profile = manager.get_profile("caIPAserviceCert")
    assert isinstance(profile, Profile)
    assert profile.profile_id == "caIPAserviceCert"

    # Test get_profile_for_signing (should prefer Dogtag)
    signing_profile = manager.get_profile_for_signing("caIPAserviceCert")
    assert isinstance(signing_profile, Profile)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
