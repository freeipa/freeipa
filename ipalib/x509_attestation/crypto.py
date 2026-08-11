#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""
HKDF key derivation and binding signature for S4U2Self attestation.

Mirrors derive_attestation_key() / derive_p256_key() in gss-s4u-x509-crypto.c
and derive_attestation_key() / derive_p256_attestation_key() in
ipa_kdb_s4u_x509.c.

All numeric constants and the HKDF info format must remain byte-for-byte
identical between this module, the OpenSSH client, and the IPA KDB plugin.

The HKDF salt and binding label are derived from the service type for
cryptographic domain separation between services:
  salt  = "{service_type}-attestation-v1"   (UTF-8 encoded)
  label = "{service_type}-attestation-binding-v1"

For SSH (service_type="ssh") these evaluate to the fixed strings used in
gss-s4u-x509-crypto.c and ipa_kdb_s4u_x509.c.
"""

import hashlib
import struct
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# P-256 group order n  (FIPS 186-4 §D.1.2.3 / SEC2 §2.4.2).
# Hardcoded to match the P256_ORDER constant in ipa_kdb_s4u_x509.c and
# the P256_ORDER array in gss-s4u-x509-crypto.c.  This value is defined by
# the curve specification and will never change.
P256_ORDER = int.from_bytes(bytes([
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
]), 'big')

SigningKey = Union[ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey]


def _build_hkdf_info(hostname: str, realm: str, kvno: int) -> bytes:
    """HKDF info field: hostname || NUL || realm || NUL || kvno_be32."""
    return (
        hostname.encode() + b'\x00'
        + realm.encode() + b'\x00'
        + struct.pack('>I', kvno)
    )


def _derive_p256_key(seed48: bytes) -> ec.EllipticCurvePrivateKey:
    """
    Derive a P-256 private key from 48 bytes of HKDF output.

    NIST SP 800-56A Rev 3 §5.6.1.2.2 "extra random bits" method:
        scalar = (OS2IP(seed48) mod (n_P256 − 1)) + 1

    48 bytes = 384 bits; the 128 extra bits above the 256-bit curve order
    keep the bias below 2^{−128}.

    ec.derive_private_key() computes Q = scalar·G internally, producing a
    full keypair.  This sidesteps the OpenSSL 3.x EVP_PKEY_fromdata issue
    where the EC public key is not auto-derived from the private scalar
    (documented in doc/designs/krb-s4u-x509-assertion.md §FIPS
    Considerations).
    """
    raw = int.from_bytes(seed48, 'big')
    scalar = (raw % (P256_ORDER - 1)) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def derive_signing_key(
    ikm: bytes,
    hostname: str,
    realm: str,
    kvno: int,
    fips_mode: bool,
    service_type: str = "ssh",
) -> SigningKey:
    """
    Derive the attestation signing key from raw keytab key material (IKM).

    The HKDF salt "{service_type}-attestation-v1" provides cryptographic
    domain separation so the same keytab key produces distinct signing
    keys for each service type (ssh, oidc, pam, ...).

    Non-FIPS: Ed25519 from 32-byte HKDF-SHA256 output.
    FIPS:     ECDSA P-256 from 48-byte HKDF-SHA256 output, scalar-reduced
              via NIST SP 800-56A Rev 3 §5.6.1.2.2.

    The seed is zeroed after use as a best-effort mitigation (CPython does
    not guarantee that bytes objects are immediately reclaimed).
    """
    salt = f"{service_type}-attestation-v1".encode()
    seed_len = 48 if fips_mode else 32
    seed = HKDF(
        algorithm=hashes.SHA256(),
        length=seed_len,
        salt=salt,
        info=_build_hkdf_info(hostname, realm, kvno),
    ).derive(ikm)

    try:
        if fips_mode:
            return _derive_p256_key(seed)
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    finally:
        seed = b'\x00' * len(seed)   # best-effort zero


def signing_key_is_fips(key: SigningKey) -> bool:
    """Return True if the key is ECDSA P-256 (FIPS path)."""
    return isinstance(key, ec.EllipticCurvePrivateKey)


def compute_binding_signature(
    signing_key: SigningKey,
    host_spki_der: bytes,
    principal: str,
    kvno: int,
    service_type: str = "ssh",
) -> bytes:
    """
    Compute the issuer binding signature.

    Pre-image:
        label  = "{service_type}-attestation-binding-v1"
        digest = SHA256(serviceKey_DER || label
                        || principal || kvno_be32)

    For Ed25519:
        sig = Ed25519.sign(key, message=digest)
        Ed25519 applies its internal SHA-512 to the 32-byte message.

    For ECDSA P-256:
        sig = ECDSA.sign(key, SHA256(digest))
        Matches OpenSSL EVP_DigestSign(EVP_sha256, key, digest, 32)
        behaviour, which hashes the supplied message before signing.

    The result is:
        Ed25519  — 64-byte raw signature
        ECDSA    — DER-encoded SEQUENCE { INTEGER r, INTEGER s }
    """
    label = f"{service_type}-attestation-binding-v1".encode()
    digest = hashlib.sha256(
        host_spki_der
        + label
        + principal.encode()
        + struct.pack('>I', kvno)
    ).digest()

    if isinstance(signing_key, ed25519.Ed25519PrivateKey):
        return signing_key.sign(digest)
    else:
        return signing_key.sign(digest, ec.ECDSA(hashes.SHA256()))


def generate_ephemeral_subject_key(fips_mode: bool):
    """
    Generate an ephemeral subject public key for non-publickey auth methods.

    Non-FIPS: Ed25519
    FIPS:     ECDSA P-256
    """
    if fips_mode:
        return ec.generate_private_key(ec.SECP256R1()).public_key()
    return ed25519.Ed25519PrivateKey.generate().public_key()
