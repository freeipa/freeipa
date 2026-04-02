"""
asn1.py — DER-encoding of SSH attestation and PKINIT ASN.1 structures.

All structures are encoded with minimal hand-written DER helpers to avoid
version-specific dependencies on cryptography.hazmat.asn1 (the declarative
codec API has changed across releases).

All structures must be byte-for-byte compatible with the C implementations in
gss-s4u-x509-asn1.c (OpenSSH client) and ipa_kdb_s4u_x509.c (IPA KDB plugin).
"""

# OIDs — must match gss-s4u-x509-internal.h
OID_KERBEROS_SERVICE_ISSUER_BINDING = "2.16.840.1.113730.3.8.15.3.1"
OID_SSH_AUTHN_CONTEXT = "2.16.840.1.113730.3.8.15.3.2"
OID_PKINIT_SAN = "1.3.6.1.5.2.2"
OID_PKINIT_KP_CLIENTAUTH = "1.3.6.1.5.2.3.4"

# KRB_NT_PRINCIPAL from RFC 4120 §6.2
KRB_NT_PRINCIPAL = 1


# ---------------------------------------------------------------------------
# SshAuthnContext — manual DER
#
# id-ce-sshAuthnContext (OID 2.16.840.1.113730.3.8.15.3.2) ::= SEQUENCE {
#     version         INTEGER (0),
#     authMethod      UTF8String,
#     sessionId       OCTET STRING,
#     keyFingerprint  [0] EXPLICIT UTF8String OPTIONAL,
#     clientAddress   [1] EXPLICIT UTF8String OPTIONAL
# }
#
# Matches SSH_AUTHN_CONTEXT in gss-s4u-x509-asn1.c:
#   ASN1_SIMPLE(version, ASN1_INTEGER)
#   ASN1_SIMPLE(auth_method, ASN1_UTF8STRING)
#   ASN1_SIMPLE(session_id, ASN1_OCTET_STRING)
#   ASN1_EXP_OPT(key_fingerprint, ASN1_UTF8STRING, 0)
#   ASN1_EXP_OPT(client_address,  ASN1_UTF8STRING, 1)
# ---------------------------------------------------------------------------

def encode_authn_context(
    auth_method: str,
    session_id: bytes,
    key_fingerprint: str | None = None,
    client_address: str | None = None,
) -> bytes:
    """DER-encode the id-ce-sshAuthnContext extension value."""
    body = (
        _int_der(0)              # version = 0
        + _utf8str(auth_method)  # authMethod
        + _octstr(session_id)    # sessionId
    )
    if key_fingerprint is not None:
        body += _explicit(0, _utf8str(key_fingerprint))  # [0] EXPLICIT UTF8String
    if client_address is not None:
        body += _explicit(1, _utf8str(client_address))   # [1] EXPLICIT UTF8String
    return _seq(body)


# ---------------------------------------------------------------------------
# Minimal DER primitives
#
# Used only where cryptography.hazmat.asn1 cannot represent the required
# type (AlgorithmIdentifier with OID, SubjectPublicKeyInfo, GeneralString).
# ---------------------------------------------------------------------------

def _len_der(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, n >> 8, n & 0xff])


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len_der(len(content)) + content


def _seq(content: bytes) -> bytes:
    return _tlv(0x30, content)


def _int_der(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b'\x00')
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big')
    if b[0] & 0x80:        # prepend zero byte to avoid negative interpretation
        b = b'\x00' + b
    return _tlv(0x02, b)


def _utf8str(s: str) -> bytes:
    return _tlv(0x0c, s.encode())


def _octstr(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _genstr(s: str) -> bytes:
    """GeneralString (universal tag 0x1B) — ASCII/IA5 subset (RFC 4120)."""
    return _tlv(0x1b, s.encode('ascii'))


def _explicit(tag: int, content: bytes) -> bytes:
    """Context-specific constructed explicit tag [tag] EXPLICIT."""
    return _tlv(0xa0 | tag, content)


# AlgorithmIdentifier DER for the two key types used in this protocol.
# V_ASN1_UNDEF parameters: no parameters field at all (not even NULL),
# matching X509_ALGOR_set0(..., V_ASN1_UNDEF, NULL) in gss-s4u-x509.c.
#
# Ed25519:        OID 1.3.101.112  → 06 03 2b 65 70
# ECDSA-SHA256:   OID 1.2.840.10045.4.3.2 → 06 08 2a 86 48 ce 3d 04 03 02
_ALG_ED25519 = _seq(
    bytes([0x06, 0x03, 0x2b, 0x65, 0x70])
)
_ALG_ECDSA_SHA256 = _seq(
    bytes([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])
)


# ---------------------------------------------------------------------------
# KerberosServiceIssuerBinding — manual DER
#
# id-ce-kerberosServiceIssuerBinding (OID 2.16.840.1.113730.3.8.15.3.1):
#   SEQUENCE {
#     version     INTEGER (0),
#     serviceType UTF8String,          -- "ssh", "oidc", "radius", "pam", ...
#     principal   UTF8String,          -- "host/<hostname>@<REALM>"
#     enctype     INTEGER,             -- Kerberos enctype (17–20)
#     kvno        INTEGER,
#     sigAlg      AlgorithmIdentifier, -- Ed25519 or ecdsa-with-SHA256
#     serviceKey  SubjectPublicKeyInfo, -- DER-encoded service public key
#     binding     OCTET STRING         -- raw signature bytes
#   }
#
# Manual encoding is required because AlgorithmIdentifier contains an OID
# and SubjectPublicKeyInfo is an opaque SEQUENCE — neither maps to any type
# that cryptography.hazmat.asn1 supports as a field directly.
# ---------------------------------------------------------------------------

def encode_issuer_binding(
    service_type: str,
    principal: str,
    enctype: int,
    kvno: int,
    fips_mode: bool,
    host_spki_der: bytes,
    binding_sig: bytes,
) -> bytes:
    """DER-encode the id-ce-kerberosServiceIssuerBinding extension value."""
    alg = _ALG_ECDSA_SHA256 if fips_mode else _ALG_ED25519
    return _seq(
        _int_der(0)               # version = 0
        + _utf8str(service_type)  # serviceType
        + _utf8str(principal)     # principal
        + _int_der(enctype)       # enctype
        + _int_der(kvno)          # kvno
        + alg                     # sigAlg (AlgorithmIdentifier)
        + host_spki_der           # serviceKey (SubjectPublicKeyInfo DER)
        + _octstr(binding_sig)    # binding
    )


# ---------------------------------------------------------------------------
# KRB5PrincipalName — manual DER (RFC 4120 §5.2.2 / RFC 4556 §3.1)
#
# KRB5PrincipalName ::= SEQUENCE {
#     realm         [0] EXPLICIT GeneralString,
#     principalName [1] EXPLICIT PrincipalName
# }
# PrincipalName ::= SEQUENCE {
#     name-type   [0] EXPLICIT INTEGER,          -- KRB_NT_PRINCIPAL = 1
#     name-string [1] EXPLICIT SEQUENCE OF GeneralString
# }
#
# Manual encoding is required because GeneralString (universal tag 0x1B) is
# not supported by cryptography.hazmat.asn1 (str maps to UTF8String 0x0C;
# Implicit(0x1B) yields context-specific tag 0x9B, not universal 0x1B).
# ---------------------------------------------------------------------------

def encode_pkinit_san_value(username: str, realm: str) -> bytes:
    """
    Return the DER of KRB5PrincipalName for a single KRB_NT_PRINCIPAL name.

    Pass the result directly to x509.OtherName(OID_PKINIT_SAN, value=...).
    Matches the i2d_KRB5_PRINCIPAL_NAME() output in gss-s4u-x509-asn1.c.
    """
    # SEQUENCE OF GeneralString (name-string list; single component)
    name_string_seq = _seq(_genstr(username))

    # PrincipalName ::= SEQUENCE {
    #     name-type [0] INTEGER, name-string [1] SEQ OF }
    princ_name = _seq(
        _explicit(0, _int_der(KRB_NT_PRINCIPAL))
        + _explicit(1, name_string_seq)
    )

    # KRB5PrincipalName ::= SEQUENCE {
    #     realm [0] GeneralString, principalName [1] }
    return _seq(
        _explicit(0, _genstr(realm))
        + _explicit(1, princ_name)
    )
