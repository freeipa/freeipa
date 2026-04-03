#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""
X.509 attestation certificate assembly for SSH S4U2Self.

Mirrors ssh_gssapi_s4u_x509_build_cert() in gss-s4u-x509.c.

Design: doc/designs/krb-s4u-x509-assertion.md
"""

import os
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .asn1 import (
    OID_KERBEROS_SERVICE_ISSUER_BINDING, OID_SSH_AUTHN_CONTEXT,
    OID_PKINIT_SAN, OID_PKINIT_KP_CLIENTAUTH,
    encode_issuer_binding, encode_authn_context, encode_pkinit_san_value,
)
from .crypto import (
    derive_signing_key, signing_key_is_fips,
    compute_binding_signature, generate_ephemeral_subject_key,
)
from .keytab import KeytabEntry

# Mirrors SSH_S4U_CERT_LIFETIME_MAX in gss-s4u-x509-internal.h
CERT_LIFETIME_MAX = 300  # seconds


def build_attestation_cert(
    user: str,
    realm: str,
    auth_method: str,
    session_id: bytes,
    host_pubkey,                       # cryptography public key object
    keytab_entry: KeytabEntry,
    *,
    subject_pubkey=None,               # user's public key (pubkey auth) or None
    key_fingerprint: str | None = None,
    client_address: str | None = None,
    cert_lifetime: int = 300,
) -> bytes:
    """
    Build a DER-encoded SSH S4U2Self attestation X.509 certificate.

    Parameters
    ----------
    user:            SSH username (cert Subject CN, PKINIT SAN principal).
    realm:           Kerberos realm.
    auth_method:     "publickey", "password", or "keyboard-interactive".
    session_id:      SSH session ID bytes (random 32 bytes for non-SSH use).
    host_pubkey:     SSH host public key as a cryptography public key object.
    keytab_entry:    Best keytab entry from get_host_keytab_key().
    subject_pubkey:  User's public key for publickey auth; None → ephemeral key.
    key_fingerprint: "SHA256:…" key fingerprint string, or None.
    client_address:  "ip:port" string, or None.
    cert_lifetime:   Validity window in seconds (capped at 300).

    Returns
    -------
    DER-encoded X.509 certificate bytes.
    """
    if cert_lifetime > CERT_LIFETIME_MAX:
        cert_lifetime = CERT_LIFETIME_MAX

    fips_mode = _is_fips_mode()

    # In FIPS mode, Ed25519 subject keys cannot appear in a SPKI.
    if fips_mode and isinstance(subject_pubkey, ed25519.Ed25519PublicKey):
        raise ValueError(
            "Ed25519 subject keys are not usable in FIPS mode; "
            "pass subject_pubkey=None to use an ephemeral P-256 key"
        )

    # Extract hostname from "host/<hostname>@<realm>"
    hostname = keytab_entry.principal.split('/')[1].split('@')[0]
    principal = keytab_entry.principal

    # Derive the attestation signing key from keytab IKM.
    signing_key = derive_signing_key(
        keytab_entry.key, hostname, realm,
        keytab_entry.kvno, fips_mode,
    )
    fips = signing_key_is_fips(signing_key)

    # Get the SPKI DER of the host key for the binding digest.
    host_spki_der = host_pubkey.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Compute the issuer binding signature.
    binding_sig = compute_binding_signature(
        signing_key, host_spki_der, principal, keytab_entry.kvno,
    )

    # Build the two custom extension payloads.
    issuer_binding_der = encode_issuer_binding(
        service_type="ssh",
        principal=principal,
        enctype=keytab_entry.enctype,
        kvno=keytab_entry.kvno,
        fips_mode=fips,
        host_spki_der=host_spki_der,
        binding_sig=binding_sig,
    )
    authn_context_der = encode_authn_context(
        auth_method=auth_method,
        session_id=session_id,
        key_fingerprint=key_fingerprint,
        client_address=client_address,
    )

    # Choose the subject public key.
    if subject_pubkey is not None:
        actual_subject_key = subject_pubkey
    else:
        actual_subject_key = generate_ephemeral_subject_key(fips_mode)

    now = datetime.now(tz=timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(seconds=cert_lifetime))
        .issuer_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, principal),
        ]))
        .subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, user),
        ]))
        .public_key(actual_subject_key)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            # id-pkinit-KPClientAuth: required by RFC 4556
            x509.ExtendedKeyUsage([
                x509.ObjectIdentifier(OID_PKINIT_KP_CLIENTAUTH),
            ]),
            critical=False,
        )
        .add_extension(
            # id-pkinit-san: critical — KDC identifies the principal by this
            x509.SubjectAlternativeName([
                x509.OtherName(
                    type_id=x509.ObjectIdentifier(OID_PKINIT_SAN),
                    value=encode_pkinit_san_value(user, realm),
                ),
            ]),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(OID_KERBEROS_SERVICE_ISSUER_BINDING),
                issuer_binding_der,
            ),
            critical=False,
        )
        .add_extension(
            # id-ce-sshAuthnContext: SSH auth details for the KDB plugin
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(OID_SSH_AUTHN_CONTEXT),
                authn_context_der,
            ),
            critical=False,
        )
        .sign(
            signing_key,
            # Ed25519 does not accept a separate hash algorithm parameter.
            algorithm=(
                None
                if isinstance(signing_key, ed25519.Ed25519PrivateKey)
                else hashes.SHA256()
            ),
        )
    )

    return cert.public_bytes(serialization.Encoding.DER)


def _is_fips_mode() -> bool:
    """
    Detect whether the system is running in FIPS mode.

    Checks the Linux kernel sysctl first; falls back to the ssl module's
    EVP_default_properties_is_fips_enabled() wrapper.
    """
    try:
        with open('/proc/sys/crypto/fips_enabled') as f:
            return f.read().strip() == '1'
    except OSError:
        pass
    try:
        import ssl
        return bool(ssl.FIPS_mode())
    except AttributeError:
        return False
