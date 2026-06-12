#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""
X.509 attestation certificate assembly for S4U2Self protocol transition.

Provides a generic builder (_build_cert_core) and two public entry points:

  build_attestation_cert()         — SSH-specific wrapper (backward compat)
  build_service_attestation_cert() — generic, any service type

Design: doc/designs/krb-s4u-x509-assertion.md
"""

from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .asn1 import (
    OID_KERBEROS_SERVICE_ISSUER_BINDING,
    OID_SSH_AUTHN_CONTEXT, OID_OIDC_AUTHN_CONTEXT,
    OID_PKINIT_SAN, OID_PKINIT_KP_CLIENTAUTH,
    encode_issuer_binding,
    encode_authn_context, encode_oidc_authn_context,
    encode_pkinit_san_value,
)
from .crypto import (
    derive_signing_key, signing_key_is_fips,
    compute_binding_signature, generate_ephemeral_subject_key,
)
from .keytab import KeytabEntry

# Mirrors SSH_S4U_CERT_LIFETIME_MAX in gss-s4u-x509-internal.h
CERT_LIFETIME_MAX = 300  # seconds


def _build_cert_core(
    user: str,
    realm: str,
    service_type: str,
    host_pubkey,
    keytab_entry: KeytabEntry,
    *,
    subject_pubkey=None,
    authn_context_ext: tuple[str, bytes] | None = None,
    cert_lifetime: int = 300,
) -> bytes:
    """
    Build a DER-encoded S4U2Self attestation certificate.

    Parameters
    ----------
    user:              Kerberos principal name (cert Subject CN, PKINIT SAN).
    realm:             Kerberos realm.
    service_type:      Service identifier: "ssh", "oidc", "pam", etc.
                       Used as HKDF salt prefix and stored in the
                       id-ce-kerberosServiceIssuerBinding extension.
    host_pubkey:       Service host public key (cryptography public key).
    keytab_entry:      Best keytab entry from get_host_keytab_key().
    subject_pubkey:    Subject public key; None generates an ephemeral key.
    authn_context_ext: Optional (OID_string, DER_bytes) tuple for a
                       service-specific authentication context extension.
                       Pass None to omit the extension entirely.
    cert_lifetime:     Validity window in seconds (capped at 300).

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
        keytab_entry.kvno, fips_mode, service_type,
    )
    fips = signing_key_is_fips(signing_key)

    # Get the SPKI DER of the host key for the binding digest.
    host_spki_der = host_pubkey.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Compute the issuer binding signature.
    binding_sig = compute_binding_signature(
        signing_key, host_spki_der, principal,
        keytab_entry.kvno, service_type,
    )

    # Build the issuer binding extension.
    issuer_binding_der = encode_issuer_binding(
        service_type=service_type,
        principal=principal,
        enctype=keytab_entry.enctype,
        kvno=keytab_entry.kvno,
        fips_mode=fips,
        host_spki_der=host_spki_der,
        binding_sig=binding_sig,
    )

    # Choose the subject public key.
    if subject_pubkey is not None:
        actual_subject_key = subject_pubkey
    else:
        actual_subject_key = generate_ephemeral_subject_key(fips_mode)

    now = datetime.now(tz=timezone.utc)

    builder = (
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
                x509.ObjectIdentifier(
                    OID_KERBEROS_SERVICE_ISSUER_BINDING
                ),
                issuer_binding_der,
            ),
            critical=False,
        )
    )

    if authn_context_ext is not None:
        oid_str, ext_der = authn_context_ext
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(oid_str),
                ext_der,
            ),
            critical=False,
        )

    cert = builder.sign(
        signing_key,
        # Ed25519 does not accept a separate hash algorithm parameter.
        algorithm=(
            None
            if isinstance(signing_key, ed25519.Ed25519PrivateKey)
            else hashes.SHA256()
        ),
    )

    return cert.public_bytes(serialization.Encoding.DER)


def build_attestation_cert(
    user: str,
    realm: str,
    auth_method: str,
    session_id: bytes,
    host_pubkey,                       # cryptography public key object
    keytab_entry: KeytabEntry,
    *,
    subject_pubkey=None,         # user's public key (pubkey auth) or None
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
    subject_pubkey:  User's public key for publickey auth; None → ephemeral.
    key_fingerprint: "SHA256:…" key fingerprint string, or None.
    client_address:  "ip:port" string, or None.
    cert_lifetime:   Validity window in seconds (capped at 300).

    Returns
    -------
    DER-encoded X.509 certificate bytes.
    """
    authn_context_der = encode_authn_context(
        auth_method=auth_method,
        session_id=session_id,
        key_fingerprint=key_fingerprint,
        client_address=client_address,
    )
    return _build_cert_core(
        user=user,
        realm=realm,
        service_type="ssh",
        host_pubkey=host_pubkey,
        keytab_entry=keytab_entry,
        subject_pubkey=subject_pubkey,
        authn_context_ext=(OID_SSH_AUTHN_CONTEXT, authn_context_der),
        cert_lifetime=cert_lifetime,
    )


def build_oidc_attestation_cert(
    user: str,
    realm: str,
    issuer: str,
    access_token_hash: bytes,
    host_pubkey,                    # cryptography public key object
    keytab_entry: KeytabEntry,
    *,
    amr: list[str] | None = None,
    client_id: str | None = None,
    client_address: str | None = None,
    cert_lifetime: int = 300,
) -> bytes:
    """
    Build a DER-encoded OIDC S4U2Self attestation X.509 certificate.

    Parameters
    ----------
    user:               Kerberos principal name (Subject CN, PKINIT SAN).
    realm:              Kerberos realm.
    issuer:             OIDC issuer URL (e.g. "https://idp.example.com").
    access_token_hash:  SHA-256 digest of the OIDC access token (32 bytes).
    host_pubkey:        Service host public key (cryptography public key).
    keytab_entry:       Best keytab entry from get_host_keytab_key().
    amr:                List of RFC 8176 authentication method references
                        (e.g. ["mfa", "otp"]), or None to omit.
    client_id:          OAuth 2.0 client ID string, or None to omit.
    client_address:     "ip:port" string of the OIDC client, or None.
    cert_lifetime:      Validity window in seconds (capped at 300).

    Returns
    -------
    DER-encoded X.509 certificate bytes.
    """
    authn_context_der = encode_oidc_authn_context(
        issuer=issuer,
        access_token_hash=access_token_hash,
        amr=amr,
        client_id=client_id,
        client_address=client_address,
    )
    return _build_cert_core(
        user=user,
        realm=realm,
        service_type="oidc",
        host_pubkey=host_pubkey,
        keytab_entry=keytab_entry,
        authn_context_ext=(OID_OIDC_AUTHN_CONTEXT, authn_context_der),
        cert_lifetime=cert_lifetime,
    )


def build_service_attestation_cert(
    user: str,
    realm: str,
    service_type: str,
    host_pubkey,
    keytab_entry: KeytabEntry,
    *,
    subject_pubkey=None,
    authn_context_ext: tuple[str, bytes] | None = None,
    cert_lifetime: int = 300,
) -> bytes:
    """
    Build a DER-encoded S4U2Self attestation certificate for any service.

    This is the generic entry point for service types without a dedicated
    builder (PAM, etc.).  The service_type string is stored in the
    id-ce-kerberosServiceIssuerBinding extension and used by the IPA KDB
    plugin to select the appropriate handler and auth indicator prefix.

    Parameters
    ----------
    user:              Kerberos principal name (Subject CN, PKINIT SAN).
    realm:             Kerberos realm.
    service_type:      Service identifier, e.g. "pam".
                       Determines the HKDF salt, binding label, and the
                       serviceType field in the issuer binding extension.
    host_pubkey:       Service host public key (cryptography public key).
    keytab_entry:      Best keytab entry from get_host_keytab_key().
    subject_pubkey:    Subject public key; None generates an ephemeral key.
    authn_context_ext: Optional (OID_string, DER_bytes) for a
                       service-specific authentication context extension.
                       Callers are responsible for encoding the value.
                       Pass None to omit the extension.
    cert_lifetime:     Validity window in seconds (capped at 300).

    Returns
    -------
    DER-encoded X.509 certificate bytes.
    """
    return _build_cert_core(
        user=user,
        realm=realm,
        service_type=service_type,
        host_pubkey=host_pubkey,
        keytab_entry=keytab_entry,
        subject_pubkey=subject_pubkey,
        authn_context_ext=authn_context_ext,
        cert_lifetime=cert_lifetime,
    )


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
