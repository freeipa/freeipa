# Kerberos S4U2Self Service Attestation via X.509 Certificate

## Overview

S4U2Self (protocol transition) lets a Kerberos service request a service ticket
on behalf of a user without the user's active participation.  The KDC has no
visibility into *how* the user authenticated to the requesting service —
password, public key, hardware token, OIDC, etc.  Auth indicators, the
mechanism Kerberos uses to communicate authentication strength, are therefore
absent from protocol-transition tickets, which prevents downstream services from
enforcing auth-method policy.

This design describes a general framework for Kerberos services to carry a
verifiable authentication context through S4U2Self by presenting a short-lived
X.509 attestation certificate alongside the `PA-FOR-X509-USER` padata (type
130, RFC 6112).  The certificate is issued by the requesting service itself,
signed with a key derived deterministically from its Kerberos keytab, and bound
to an independent per-service public key registered in the IPA LDAP directory.
The KDC's KDB plugin verifies the certificate and injects auth indicators into
the resulting service ticket.

SSH and OIDC are the two service types implemented.  The IPA KDB plugin verifies
the certificate via the `get_s4u_x509_principal` KDB vtable hook and injects
authentication indicators into the issued service ticket via the DAL v9
`issue_pac` hook.  The design is intentionally extensible to other service types
(PAM, etc.) without changes to the common verification path in the KDC plugin.

The PKINIT kdcpreauth module and the certauth plugin (`ipa_kdb_certauth.c`) are
**not** involved.  They handle AS-REQ pre-authentication only.  S4U2Self
travels as a TGS-REQ and uses an entirely separate code path in MIT Kerberos.

References: [MS-SFU] Microsoft Services for User; [RFC 6112] Anonymity Support
for Kerberos; [RFC 4556] PKINIT; [RFC 4120] Kerberos 5.

### What this gains over plain S4U2Self

| Property | Plain S4U2Self | Attested S4U2Self |
|----------|----------------|-------------------|
| Auth method visible to KDC | No | Yes — via `authMethod` in service context |
| Auth credential visible to KDC | No | Yes — public key fingerprint in cert |
| KDC can set auth indicators | No | Yes — per `authMethod` policy |
| Audit trail (key → TGT → service) | No | Yes |
| Anomaly detection at KDC | No | Yes — `clientAddress`, `sessionId` |

## Use Cases

### UC1 — SSH public-key login with Kerberos service access

A user authenticates to an IPA-enrolled SSH server with their SSH public key.
The SSH server performs S4U2Self to obtain a Kerberos service ticket on the
user's behalf, then uses S4U2Proxy to obtain a ticket to a backend service
(e.g., an NFS mount or an internal web API) on the user's behalf.

With plain S4U2Self the backend service has no way to distinguish this from a
password-based login or from an impersonation performed by a compromised host.
With attested S4U2Self, the backend service policy engine can require the
`ssh-authn:publickey` Kerberos authentication indicator on the forwarded ticket,
ensuring that access is granted only to users who authenticated with a
registered SSH key.

### UC2 — SSH password authentication with audit requirements

A compliance policy requires recording the original authentication method for
all Kerberos service accesses that originated from SSH sessions.  Attested
S4U2Self causes the SSH server to embed the `authMethod` and `clientAddress` in
the attestation certificate, and the KDC to emit `ssh-authn:password` as an
authentication indicator in the service ticket.  The indicator is visible in KDC
audit logs and in the PAC presented to the service.

### UC3 — FIPS-compliant SSH deployment

On RHEL systems with FIPS mode enabled, Ed25519 operations are unavailable from
the OpenSSL FIPS module.  The design transparently substitutes ECDSA P-256 for
all signing and key derivation operations, with no change to the protocol
structure or to the administrator workflow.

### UC4 — OIDC broker attests authentication method

An IPA-enrolled OIDC / OpenID Connect identity provider authenticates a user
and records the authentication methods in the `amr` claim (RFC 8176).  The
broker performs S4U2Self and presents an attestation certificate with service
type `oidc` and an `OidcAuthnContext` extension carrying the `amrValues` list.
The KDC injects one `oidc-authn:<amr>` indicator per RFC 8176 AMR value — for
example `oidc-authn:pwd` and `oidc-authn:otp` for password+OTP authentication,
or `oidc-authn:mfa` for a composite multi-factor claim.  Downstream services
that require MFA can enforce `oidc-authn:mfa` without knowing anything about
OIDC.

## How to Use

### SSH server side (Phase 1)

The SSH server change is limited to `ssh_gssapi_s4u2self()` in
`sshd-session.c`.  After a non-GSSAPI authentication succeeds, the server
constructs an attestation certificate (see
[Attestation Certificate Structure](#attestation-certificate-structure)) and
imports it as a GSSAPI name using the `GSS_KRB5_NT_X509_CERT` name type (MIT
Kerberos ≥ 1.19):

```c
/* DER-encoded attestation certificate */
major = gss_import_name(&minor, &cert_gssbuf,
                         GSS_KRB5_NT_X509_CERT, &user_name);
major = gss_acquire_cred_impersonate_name(&minor,
    host_creds, user_name, lifetime,
    oidset, GSS_C_INITIATE,
    &impersonated_creds, NULL, NULL);
/* Results in a TGS-REQ with PA-FOR-X509-USER carrying the attestation cert */
```

For cross-realm users (`user@FOREIGN_REALM` on an IPA host), the MIT KDC does
not call `get_s4u_x509_principal` (realm mismatch prevents it), so the SSH
server falls back to the existing plain PA-FOR-USER path for those users:

```c
if (user_realm_matches_server_realm)
    gss_import_name(&minor, &cert_buf, GSS_KRB5_NT_X509_CERT, &user_name);
else
    gss_import_name(&minor, &user_buf, GSS_C_NT_USER_NAME, &user_name);
```

### KDC / FreeIPA server side (Phase 1)

No administrator action is required on the KDC.  The `ipa_kdb_s4u_x509.c`
plugin module is compiled in when both OpenSSL (libssl/libcrypto) and the DAL
v9 `issue_pac` hook are available at build time, controlled by the
`BUILD_IPA_S4U_X509` autoconf conditional.  The vtable slot is wired
automatically; no `ipa` CLI command or LDAP entry is needed to activate it.

Host SSH public keys must be registered in the host's IPA LDAP entry under the
`ipaSshPubKey` attribute.  This is populated automatically during
`ipa-client-install` and managed via `ipa host-mod --sshpubkey`.

### Python service library (`ipalib.x509_attestation`)

The `ipalib.x509_attestation` package provides the complete host-side
attestation pipeline as an importable Python library.  Any service running
with a Kerberos keytab — SSH server, OIDC broker, PAM module, etc. — can use
it to build an attestation certificate, exchange it for a S4U2Self service
ticket, and optionally perform S4U2Proxy.  All keytab access uses direct
`libkrb5` ctypes bindings via `ipapython.kerberos`; no external `python-krb5`
package is required.

A full working CLI demonstrating the pipeline is in `doc/examples/s4u-x509/`.

#### Public API

| Symbol | Description |
|--------|-------------|
| `KeytabEntry` | Dataclass: `principal`, `kvno`, `enctype`, `key` (raw bytes) |
| `get_host_keytab_key(hostname, realm, keytab_path=None, fips_mode=False, service_type="host")` | Open keytab; select the highest-preference AES entry for `<service_type>/<hostname>@<realm>`; return `KeytabEntry`.  Pass `service_type="service"` (or any other Kerberos service name prefix) when the keytab holds a non-host principal. |
| `build_attestation_cert(user, realm, auth_method, session_id, host_pubkey, keytab_entry, ...)` | SSH-specific pipeline.  Encodes `SshAuthnContext`, derives signing key with salt `"ssh-attestation-v1"`, and builds the certificate.  Keyword args: `subject_pubkey`, `key_fingerprint`, `client_address`, `cert_lifetime`. |
| `build_oidc_attestation_cert(user, realm, issuer, access_token_hash, host_pubkey, keytab_entry, ...)` | OIDC-specific pipeline.  Encodes `OidcAuthnContext` with `issuer`, `access_token_hash`, and optional RFC 8176 `amr` list.  Derives signing key with salt `"oidc-attestation-v1"`.  Keyword args: `amr`, `client_id`, `client_address`, `cert_lifetime`. |
| `build_service_attestation_cert(user, realm, service_type, host_pubkey, keytab_entry, ...)` | Generic pipeline for any service type.  Salt `"{service_type}-attestation-v1"` provides cryptographic domain separation.  Keyword args: `subject_pubkey`, `authn_context_ext`, `cert_lifetime`. |
| `acquire_s4u_creds(cert_der, host_principal, keytab_path=None)` | Import `cert_der` as a `GSS_KRB5_NT_X509_CERT` GSSAPI name; call `gss_acquire_cred_impersonate_name`; return the resulting impersonated `gssapi.Credentials`. |
| `request_s4u_proxy(s4u_creds, proxy_target)` | Initiate a GSSAPI security context with the S4U2Self credentials toward `proxy_target`; triggers S4U2Proxy TGS-REQ internally; return the initial AP-REQ token bytes. |

Both certificate builders cap `cert_lifetime` at 300 seconds
(`CERT_LIFETIME_MAX`).  FIPS mode is detected automatically from
`/proc/sys/crypto/fips_enabled`; in FIPS mode Ed25519 is replaced by ECDSA
P-256 throughout and AES-128 keytab entries (enctypes 17 and 19) are rejected.

#### SSH service flow

```python
import os
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from ipapython.ssh import SSHPublicKey
from ipalib.x509_attestation import (
    get_host_keytab_key, build_attestation_cert, acquire_s4u_creds,
)

# 1. Select the best keytab entry for the host principal.
keytab_entry = get_host_keytab_key(hostname="srv.example.com",
                                   realm="EXAMPLE.COM")

# 2. Load the SSH host public key (for the issuer binding).
with open("/etc/ssh/ssh_host_ed25519_key.pub", "rb") as f:
    raw = f.read()
host_pubkey = load_ssh_public_key(raw)

# 3. Optionally load the user's SSH public key (publickey auth).
with open(user_pubkey_path, "rb") as f:
    raw = f.read()
ssh_key = SSHPublicKey(raw)
key_fingerprint = ssh_key.fingerprint_hex_sha256()   # "SHA256:..."
user_pubkey = load_ssh_public_key(raw)

# 4. Build the attestation certificate.
cert_der = build_attestation_cert(
    user="alice",
    realm="EXAMPLE.COM",
    auth_method="publickey",
    session_id=os.urandom(32),          # SSH session_id or random nonce
    host_pubkey=host_pubkey,
    keytab_entry=keytab_entry,
    subject_pubkey=user_pubkey,         # None → ephemeral key
    key_fingerprint=key_fingerprint,    # None → omit from SshAuthnContext
    client_address="192.0.2.1:22",      # None → omit
)

# 5. Acquire S4U2Self credentials.
s4u_creds = acquire_s4u_creds(cert_der, keytab_entry.principal)
```

#### OIDC service flow

```python
import hashlib
from ipalib.x509_attestation import (
    get_host_keytab_key, build_oidc_attestation_cert, acquire_s4u_creds,
)

# 1. Select the best keytab entry (keytab holds the service principal key).
keytab_entry = get_host_keytab_key(
    hostname="broker.example.com",
    realm="EXAMPLE.COM",
    keytab_path="/etc/oidc-broker/krb5.keytab",
)

# 2. Load the service's registered attestation public key
#    (ipaKrbServiceAttestationKey on the oidc/ service principal entry).
with open("/etc/oidc-broker/service.pub", "rb") as f:
    service_pubkey = load_public_key(f.read())

# 3. Build the attestation certificate.
#    amr values follow RFC 8176 §2; one auth indicator is emitted per value.
cert_der = build_oidc_attestation_cert(
    user="alice",
    realm="EXAMPLE.COM",
    issuer="https://broker.example.com",
    access_token_hash=hashlib.sha256(access_token_bytes).digest(),
    host_pubkey=service_pubkey,
    keytab_entry=keytab_entry,
    amr=["pwd", "otp"],   # → oidc-authn:pwd and oidc-authn:otp in ticket
)

# 4. Acquire S4U2Self credentials.
s4u_creds = acquire_s4u_creds(cert_der, keytab_entry.principal,
                               keytab_path="/etc/oidc-broker/krb5.keytab")

# 5. Optionally delegate to a backend service via S4U2Proxy.
from ipalib.x509_attestation import request_s4u_proxy
token = request_s4u_proxy(s4u_creds, "HTTP/api.example.com@EXAMPLE.COM")
```

#### Generic service flow

For service types without a dedicated builder, the caller encodes a
service-specific context extension (or passes `None` to omit it) and supplies
the appropriate `service_type` string.  The HKDF salt and binding label are
derived automatically.

```python
from ipalib.x509_attestation import (
    get_host_keytab_key, build_service_attestation_cert, acquire_s4u_creds,
)

keytab_entry = get_host_keytab_key(
    hostname="pam-service.example.com",
    realm="EXAMPLE.COM",
    keytab_path="/etc/pam-service/krb5.keytab",
)

with open("/etc/pam-service/service.pub", "rb") as f:
    service_pubkey = load_public_key(f.read())

cert_der = build_service_attestation_cert(
    user="alice",
    realm="EXAMPLE.COM",
    service_type="pam",
    host_pubkey=service_pubkey,
    keytab_entry=keytab_entry,
    authn_context_ext=None,   # omit — emits "pam-authn:unknown"
)

s4u_creds = acquire_s4u_creds(cert_der, keytab_entry.principal,
                               keytab_path="/etc/pam-service/krb5.keytab")
```

When `authn_context_ext=None` the certificate contains only the mandatory
`id-ce-kerberosServiceIssuerBinding` extension.  The IPA KDB generic handler
still accepts such a certificate and emits `"<service_type>-authn:unknown"` as
the auth indicator, which allows experimentation before a named service context
extension OID is finalised.

#### Dependencies

| Package | Role |
|---------|------|
| `cryptography` | X.509 builder, HKDF, key generation |
| `python-gssapi` | S4U2Self / S4U2Proxy via `gss_acquire_cred_impersonate_name` |
| `ipapython` | Keytab enumeration (ctypes bindings in `ipapython.kerberos`) and `SSHPublicKey` for fingerprinting |

### Enrolling other services for attestation (future)

Non-SSH Kerberos services register an attestation public key against their
service principal entry using `ipa service-add-attestation-key`:

```bash
# Generate a key pair (example: ECDSA P-256)
openssl ecparam -name prime256v1 -genkey -noout -out broker-attest.key
openssl ec -in broker-attest.key -pubout -out broker-attest-pub.pem

# Register the public key for the OIDC service principal
ipa service-add-attestation-key \
    "oidc/broker.example.com@EXAMPLE.COM" \
    --type=oidc \
    --pub-key-file=broker-attest-pub.pem
```

Multiple keys can be registered simultaneously to support key rollover without
downtime.  Remove a key when rotation is complete:

```bash
ipa service-remove-attestation-key \
    "oidc/broker.example.com@EXAMPLE.COM" \
    --pub-key-file=broker-attest-old-pub.pem
```

### Using authentication indicators in policy

Once attestation is in place, service access policies can require specific
authentication indicators using the IPA ticket policy framework.
Indicator strings follow the pattern `<serviceType>-authn:<detail>`:

```
ssh-authn:publickey
ssh-authn:password
ssh-authn:keyboard-interactive
oidc-authn:pwd
oidc-authn:otp
oidc-authn:mfa
```

#### Ticket lifetime limits per attestation method

The IPA Kerberos ticket policy (`ipa krbtpolicy-mod`) supports per-indicator
maximum ticket lifetime and renewable age for S4U2Self attestation indicators.
These limits are stored as LDAP attribute subtypes on the policy object:

```
krbAuthIndMaxTicketLife;ssh-authn: 28800
krbAuthIndMaxRenewableAge;ssh-authn: 86400
krbAuthIndMaxTicketLife;oidc-authn: 43200
krbAuthIndMaxRenewableAge;oidc-authn: 172800
```

They are managed via the IPA CLI:

```bash
# Cap SSH-attested delegated tickets to 8 hours
ipa krbtpolicy-mod --ssh-authn-maxlife=28800 --ssh-authn-maxrenew=86400

# Cap OIDC-attested delegated tickets to 12 hours
ipa krbtpolicy-mod --oidc-authn-maxlife=43200 --oidc-authn-maxrenew=172800
```

The `ipa_kdcpolicy_check_tgs()` KDC policy hook enforces these limits during
TGS-REQ processing.  When a delegated (S4U2Proxy) ticket is requested using a
service ticket that carries `ssh-authn:*` or `oidc-authn:*` indicators, the
hook prefix-matches each indicator against the target service's policy and
applies the smallest configured non-zero `max_life` found.  This allows
administrators to bound the lifetime of delegated tickets independently from
ordinary Kerberos tickets.

Unlike AS-REQ indicator limits (`otp`, `pkinit`, etc.) — which are gated by
the user's `ipaUserAuthType` configuration and enforced at TGT issuance —
the S4U2Self indicator limits apply unconditionally and come from the **target
service's** policy, not the impersonated user's.

## Design

### Trust Model

Two independent secrets are required to forge a trusted attestation cert for a
given service instance:

```
service keytab key  →  HKDF  →  ephemeral derived signing key pair
                                  (recomputed per keytab KVNO)

service-specific public key  registered in IPA LDAP
     (SSH host key, TLS server key, dedicated attestation key, …)
```

The derived key proves: *the keytab holder issued this cert at this KVNO*.  The
binding signature (signing the registered service key with the derived key)
proves: *the keytab holder endorses this specific service instance key*.  Both
must verify for the cert to be accepted.

For services without an independent key the two-factor property is absent: the
keytab alone is sufficient to forge.  This is explicitly noted in the threat
model for each such service type.

### Key Derivation

Both the service and the KDC plugin independently compute the same signing key
from the keytab entry selected by `(principal, enctype, kvno)`.

**Non-FIPS (Ed25519):**

```
ikm    = keytab key bytes for (service_principal@REALM, enctype, kvno)
salt   = "<serviceType>-attestation-v1"   e.g. "ssh-attestation-v1"
info   = hostname || "\x00" || realm || "\x00" || uint32_be(kvno)
length = 32 bytes

derived_seed = HKDF-SHA256(ikm, salt, info)
key pair     = Ed25519(seed = derived_seed)
```

**FIPS mode (ECDSA P-256):**

Ed25519 is not listed in FIPS 186-4 and is therefore unavailable in FIPS mode.
The FIPS path uses the NIST SP 800-56A Rev 3 §5.6.1.2.2 extra-random-bits
method for P-256:

```
length = 48 bytes   (32 + 16 extra bits to keep bias < 2^{-128})

raw    = HKDF-SHA256(ikm, salt, info, length=48)
scalar = (OS2IP(raw) mod (n_P256 - 1)) + 1
key pair = EC-P256(privkey = scalar)
```

The `salt` encodes the service type so that two services sharing a keytab
(unusual but valid) derive different signing keys even when `info` is identical.
The KVNO in `info` ensures re-keying rotates the derived key automatically.

The choice of derivation algorithm is recorded in the `sigAlg` field of the
`id-ce-kerberosServiceIssuerBinding` extension so the KDC plugin knows which
path to use for verification.

### Attestation Certificate Structure

The service issues a short-lived (≤ 300 s) X.509 v3 certificate signed by the
derived key.  The KDC establishes trust by re-deriving the public key from the
keytab — no CA hierarchy is involved.

- Issuer: `CN = <service Kerberos principal>` (e.g. `host/hostname@REALM`)
- Subject: `CN = <username>`
- SubjectPublicKeyInfo: user's public key (publickey auth) or ephemeral key

#### Standard extensions

```text
subjectAltName (critical)
    otherName id-pkinit-san (1.3.6.1.5.2.2):
        KRB5PrincipalName { realm, principalName [username] }

keyUsage (critical)         digitalSignature
extKeyUsage                 id-pkinit-KPClientAuth (1.3.6.1.5.2.3.4)
basicConstraints (critical) cA=FALSE
```

#### Generic service issuer binding (`id-ce-kerberosServiceIssuerBinding`)

OID: `2.16.840.1.113730.3.8.15.3.1`

This extension is present in every attestation cert regardless of service type.
The `serviceType` field is the sole dispatch tag the KDC reads to select the
per-service verification handler; no further extension OID scanning is needed.

```text
KerberosServiceIssuerBinding ::= SEQUENCE {
    version     INTEGER (0),
    serviceType UTF8String,             -- "ssh", "oidc", "pam", ...
    principal   UTF8String,             -- issuing Kerberos principal (full name@REALM)
    enctype     INTEGER,                -- keytab enctype used as HKDF IKM
    kvno        INTEGER,                -- keytab key version number
    sigAlg      AlgorithmIdentifier,    -- id-Ed25519 or ecdsa-with-SHA256
    serviceKey  SubjectPublicKeyInfo,   -- service's registered public key
    binding     OCTET STRING            -- Sign(derived_key,
                                        --   SHA256(serviceKey_DER
                                        --          || "<serviceType>-attestation-binding-v1"
                                        --          || principal_utf8
                                        --          || uint32_be(kvno)))
}
```

The binding label embeds the service type (`"ssh-attestation-binding-v1"`,
`"oidc-attestation-binding-v1"`, …).  A binding crafted for one service type is
cryptographically invalid for another even if the derived key were somehow
shared.  The `binding` field proves that the keytab holder endorses the specific
service key embedded in the extension.

#### Service-specific authentication context extensions

Each service type owns one context extension OID.  The KDC's handler for a
given service type looks up its context extension; other handlers ignore it.
OIDs are allocated under `2.16.840.1.113730.3.8.15.3.*`:

| OID | Name | Service type |
|-----|------|-------------|
| `...3.1` | `id-ce-kerberosServiceIssuerBinding` | all |
| `...3.2` | `id-ce-sshAuthnContext` | `ssh` |
| `...3.3` | `id-ce-oidcAuthnContext` | `oidc` |
| `...3.4` | (reserved) | — |
| `...3.5` | `id-ce-pamAuthnContext` | `pam` (future) |

SSH authentication context (`id-ce-sshAuthnContext`, OID `...3.2`):

```text
SshAuthnContext ::= SEQUENCE {
    version         INTEGER (0),
    authMethod      UTF8String,                       -- "publickey" | "password" | "keyboard-interactive"
    sessionId       OCTET STRING,                     -- SSH session_id from key exchange
    keyFingerprint  [0] EXPLICIT UTF8String OPTIONAL, -- "SHA256:..." (publickey auth only)
    clientAddress   [1] EXPLICIT UTF8String OPTIONAL  -- "ip:port"
}
```

OIDC authentication context (`id-ce-oidcAuthnContext`, OID `...3.3`):

```text
OidcAuthnContext ::= SEQUENCE {
    version          INTEGER (0),
    issuer           UTF8String,
    clientId         UTF8String OPTIONAL,
    accessTokenHash  OCTET STRING,                    -- SHA256(access_token)
    amrValues        SEQUENCE OF UTF8String OPTIONAL, -- RFC 8176 §2 "amr" values
    clientAddress    [0] EXPLICIT UTF8String OPTIONAL
}
```

### KDC Processing Sequence

The MIT Kerberos KDC treats the attestation certificate as **opaque binary
data** throughout.  No X.509 parsing, no chain validation, no revocation
checking, and no CA trust anchor validation are performed by the KDC.  The
certificate blob is passed verbatim to the KDB plugin.  The only cryptographic
operation the KDC performs on the PA-S4U-X509-USER payload is the checksum
verification described below.

The GSSAPI layer (`import_name.c`, `s4u_gss_glue.c`) is equally opaque:
`gss_import_name()` with `GSS_KRB5_NT_X509_CERT` stores the raw DER bytes as
principal data components and sets `is_cert = 1` — it does not parse the cert,
extract the PKINIT SAN, or perform any X.509 processing.
`gss_acquire_cred_impersonate_name()` forwards those bytes verbatim as
`subject_cert` in PA-S4U-X509-USER.

The `id-pkinit-san` OtherName in the certificate is placed there for the KDB
plugin to read (`s4u_lookup_user_by_cn()` in `ipa_kdb_s4u_x509.c`).  PKINIT
SAN processing in the MIT Kerberos source tree occurs only in
`src/plugins/preauth/pkinit/` (`pkinit_crypto_openssl.c`, `pkinit_srv.c`) —
exclusively on the KDC side during a PKINIT AS-REQ, which is an entirely
separate code path from S4U2Self.

```
TGS-REQ received with PA-S4U-X509-USER (padata type 130)
  │
  ├─ gather_tgs_req_info()
  │    └─ kdc_process_s4u2self_req()          (do_tgs_req.c)
  │         └─ kdc_process_s4u_x509_user()    (kdc_util.c)
  │              ├─ ASN.1 decode PA-S4U-X509-USER padata
  │              ├─ verify checksum over krb5_s4u_userid struct
  │              │   using the TGS session key / subkey
  │              │   (only KDC-level cryptographic check)
  │              ├─ validate nonce matches KDC request nonce
  │              └─ if subject_cert.length > 0:
  │                   krb5_db_get_s4u_x509_principal(cert_blob, hint_princ,
  │                                                  KRB5_KDB_FLAG_CLIENT)
  │                   ← KDB vtable: ipadb_get_s4u_x509_principal
  │                     all X.509 interpretation happens here
  │                     (parse, verify, lookup, populate e_data)
  │
  ├─ check_tgs_req() / check_kdcpolicy_tgs()
  │
  └─ issue_reply()
       └─ handle_authdata() → handle_pac()
            └─ krb5_db_issue_pac()            ← KDB vtable: ipadb_v9_issue_pac
                 reads e_data->s4u, emits auth indicators
                 indicators embedded in service ticket enc-part
```

The security property enforced at the KDC level is that the service presenting
the S4U2Self request already holds a valid TGT (it can compute the checksum
using its TGS session key).  All certificate-level security — signature
verification, service key binding, auth indicator gating — is enforced
exclusively by the KDB plugin.

### `get_s4u_x509_principal` KDB Plugin Verification Pipeline

`ipadb_get_s4u_x509_principal` receives the raw certificate blob from the KDC
and performs all X.509 interpretation itself.  The KDC has done nothing with the
cert other than pass it through.

The hook is called in two contexts, distinguished by flags (see `kdb.h:1393`):

- **AS context** (`KRB5_KDB_FLAG_REFERRAL_OK` set, `do_as_req.c:145`): the
  certificate arrived in an AS-REQ.  `princ->realm` is the request realm; its
  data components carry no useful hint and must be ignored.  The plugin maps the
  cert to a principal and may return an out-of-realm client referral — a thin
  `krb5_db_entry` with only `->princ` set and all other fields NULL, the same
  convention used by `ipadb_get_principal()` referrals.

- **TGS/S4U2Self context** (`KRB5_KDB_FLAG_CLIENT` set, `kdc_util.c:1592`):
  the certificate arrived in a TGS-REQ via PA-FOR-X509-USER.  No referral must
  be returned.  `princ` may have data components — if so, the plugin must verify
  that the principal resolved from the cert matches `princ`.

Both paths perform the same certificate verification sequence inside the plugin:

1. Find `id-ce-kerberosServiceIssuerBinding` (OID `...3.1`) in the cert.
   If absent: `KRB5KDC_ERR_PREAUTH_FAILED`.
2. Read `serviceType`.  Look up handler `h = find_handler(serviceType)`.
   `find_handler()` always returns a handler: named service types (currently
   only `"ssh"`) return their dedicated handler; all others return the generic
   fallback handler (see [KDB Plugin Handler Interface](#kdb-plugin-handler-interface)).
3. Extract `(principal, enctype, kvno, sigAlg, serviceKey, binding)`.
4. In FIPS mode, reject any cert whose `sigAlg` indicates Ed25519.
   Reject weak enctype values (< 17 unconditionally; 17 and 19 in FIPS mode).
5. Look up the service principal named in the extension in the KDB; decrypt the
   keytab key matching `(enctype, kvno)` using `krb5_dbe_decrypt_key_data`.
6. Re-derive the signing key pair via HKDF-SHA256 from the keytab key.
7. Verify the outer certificate signature with the derived public key.
8. Compare the cert's `serviceKey` against registered key values pre-fetched at
   `ipadb_get_principal()` time into the host entry's `ipadb_s4u_data`:
   - Generic handler: cert `serviceKey` (DER SPKI) vs `s4u->keys[]`
     (`ipaKrbServiceAttestationKey`); also verify `serviceType` is listed in
     `s4u->types[]` (`ipaKrbServiceAttestationType`).
   - SSH handler: cert `serviceKey` (OpenSSH wire format) vs
     `s4u->ssh_pubkeys[]` (`ipasshpubkey`).
   No second LDAP round-trip is performed for either path.
   Mismatch: `KRB5KDC_ERR_CERTIFICATE_MISMATCH`.
9. Verify the `binding` signature over
   `SHA256(serviceKey_DER || h->binding_label || principal_utf8 || uint32_be(kvno))`.
   For the generic handler, `binding_label` is derived dynamically as
   `"<stype>-attestation-binding-v1"`.
10. If `h->context_ext_oid` is non-NULL, locate that extension in the cert and
    call `h->verify_context(kctx, h, cert, hint_princ, flags, svc_context, entry_out)`.
    The handler resolves the user principal (see step 11) and stores attestation
    result in `user_entry->e_data->s4u` for later use in `issue_pac`.
11. User principal resolution (inside `verify_context` via `s4u_lookup_user_by_cn()`):
    prefer the `id-pkinit-san` OtherName (RFC 4556 §3.1) in the cert's SAN;
    fall back to the Subject CN when the PKINIT SAN is absent.  The resolved
    username is looked up in two passes:

    - **Pass 1 — IPA principal lookup:** look up `username@REALM` as a local IPA
      Kerberos principal.  If found, the returned `krb5_db_entry` provides
      `ipasshpubkey` values for the publickey strong assertion check.

    - **Pass 2 — Default Trust View fallback:** if Pass 1 returns
      `KRB5_KDB_NOENTRY`, search the Default Trust View
      (`cn=Default Trust View,cn=views,cn=accounts,$SUFFIX`) with LDAP filter
      `(ipaOriginalUid=<username>)`.  This handles users from trusted realms
      (e.g. AD users) and any user absent from the KDB who has an ID override
      registered in IPA.  The ID override entry may carry `ipaSshPubKey` and
      `userCertificate;binary` values, which are matched against the cert's
      SubjectPublicKeyInfo for the publickey strong assertion check (see
      [Default Trust View ID Override Fallback](#default-trust-view-id-override-fallback)).

    In the TGS/S4U2Self context (`KRB5_KDB_FLAG_CLIENT` set), if `princ` has data
    components (`princ->length > 0`), verify the resolved principal matches the
    `princ` hint passed by the KDC.

Steps 1–9 are identical for all service types; only step 10 calls into the
per-service handler.

**Error codes:**

| Condition | Return code |
|-----------|-------------|
| No certificate data in request | `KRB5_PLUGIN_NO_HANDLE` |
| IPA context not initialised | `KRB5_KDB_DBNOTINITED` |
| Cert parse failure | `KRB5KDC_ERR_PREAUTH_FAILED` |
| Missing required extension | `KRB5KDC_ERR_PREAUTH_FAILED` |
| Unknown service type | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Host/service principal not found | `KRB5_KDB_NOENTRY` |
| Keytab key not found or enctype rejected | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Cert signature invalid | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Service key not in LDAP | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Binding signature invalid | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Subject CN / principal mismatch | `KRB5KDC_ERR_CLIENT_NAME_MISMATCH` |
| User principal not found | `KRB5_KDB_NOENTRY` |

### Auth Indicator Injection

`ipadb_v9_issue_pac()` (DAL v9 only) checks `ied->s4u->attested` on the client
entry.  When set and the request is a protocol transition
(`KRB5_KDB_FLAG_PROTOCOL_TRANSITION`), it iterates over `ied->s4u->auth_methods`
(a NULL-terminated array of RFC 8176 AMR strings) and emits one
`"<serviceType>-authn:<method>"` indicator per entry, appending each to
`*auth_indicators` via `realloc`.  An empty or absent `auth_methods` falls back
to a single `"<serviceType>-authn:unknown"` indicator.  MIT Kerberos's
`add_auth_indicators()` picks up the array and embeds each string in
`AD_KDC_ISSUED` authdata in the issued service ticket.

Auth indicator naming follows the pattern `<serviceType>-authn:<detail>`:

| Indicator | Meaning |
|-----------|---------|
| `ssh-authn:publickey` | SSH public-key authentication |
| `ssh-authn:password` | SSH password authentication |
| `ssh-authn:keyboard-interactive` | SSH keyboard-interactive |
| `oidc-authn:<amr>` | OIDC; one indicator per RFC 8176 §2 AMR value (e.g. `oidc-authn:pwd`, `oidc-authn:otp`, `oidc-authn:mfa`) |
| `oidc-authn:sso` | OIDC; fallback when `amrValues` is absent from the context extension |

### Cross-Realm Scope

MIT Kerberos calls `krb5_db_get_s4u_x509_principal` only when the user's realm
matches the server's realm.  For cross-realm users (e.g., `user@AD_DOMAIN` on
an IPA server) the attestation certificate is silently bypassed and the existing
code path is unchanged.  No cert is verified, no indicators are emitted.

Auth indicators emitted by `issue_pac` travel with the service ticket as
`AD_KDC_ISSUED` authdata for as long as the ticket remains within the same
Kerberos realm.  When a ticket crosses realm boundaries in a subsequent
S4U2Proxy step, foreign KDCs (including Active Directory) do not recognise RFC
6711 `AD_KDC_ISSUED` auth indicators and treat them as unknown authdata.

**IPA-AD trust summary:**

| User origin | Attestation |
|-------------|-------------|
| IPA user (`user@IPA_REALM`) | Full — `get_s4u_x509_principal` + `issue_pac` emits auth indicators |
| AD user with IPA ID override carrying matching `ipaSshPubKey` or `userCertificate` | Partial — publickey strong assertion succeeds via Default Trust View fallback; `ssh-authn:publickey` emitted |
| AD user without IPA ID override, or ID override has no matching key | None — IPA principal not found, Default Trust View match absent or unverified; no auth indicator emitted; existing PAC synthesis is unchanged |

### KDB Plugin Handler Interface

The handler table is a static array in the plugin; new service types require
adding a new entry (recompile; not a runtime plugin mechanism).  Service types
not present in `s4u_handlers[]` automatically fall through to the
`generic_s4u_handler`.

```c
struct ipa_s4u_cert_handler {
    const char  *service_type;   /* NULL for generic fallback */
    const char  *hkdf_salt;      /* NULL → derived as "<stype>-attestation-v1" */
    const char  *binding_label;  /* NULL → derived as "<stype>-attestation-binding-v1" */
    const char  *context_ext_oid; /* OID string of context extension; NULL = none */
    const char  *ldap_pubkey_attr; /* LDAP attr name used in legacy/debug paths */
    EVP_PKEY   *(*parse_pubkey)(const unsigned char *data, size_t len);

    /* Resolve user entry; populate user_entry->e_data->s4u runtime fields.
     * svc_context points to the parsed context extension (may be NULL).
     * entry_out receives the user db entry. */
    krb5_error_code (*verify_context)(
        krb5_context                       kctx,
        const struct ipa_s4u_cert_handler *h,
        X509                              *cert,
        krb5_const_principal               hint_princ,
        unsigned int                       flags,
        const void                        *svc_context,
        krb5_db_entry                    **entry_out
    );
};

/* Named handlers (dispatched by serviceType string) */
static const struct ipa_s4u_cert_handler s4u_handlers[] = {
    {
        .service_type     = "ssh",
        .hkdf_salt        = "ssh-attestation-v1",
        .binding_label    = "ssh-attestation-binding-v1",
        .context_ext_oid  = "2.16.840.1.113730.3.8.15.3.2",
        .ldap_pubkey_attr = "ipaSshPubKey",
        .parse_pubkey     = parse_openssh_pubkey,
        .verify_context   = ssh_s4u_verify_context,
    },
    {
        .service_type     = "oidc",
        .hkdf_salt        = "oidc-attestation-v1",
        .binding_label    = "oidc-attestation-binding-v1",
        .context_ext_oid  = "2.16.840.1.113730.3.8.15.3.3",
        .ldap_pubkey_attr = "ipaKrbServiceAttestationKey",
        .parse_pubkey     = parse_der_spki_pubkey,
        .verify_context   = oidc_s4u_verify_context,
    },
    /* pam, … */
};

/* Generic fallback: any service type registered via ipaKrbServiceAttestationKey */
static const struct ipa_s4u_cert_handler generic_s4u_handler = {
    .service_type     = NULL,
    .hkdf_salt        = NULL,   /* derived as "<stype>-attestation-v1" */
    .binding_label    = NULL,   /* derived as "<stype>-attestation-binding-v1" */
    .context_ext_oid  = NULL,   /* no context extension */
    .ldap_pubkey_attr = "ipaKrbServiceAttestationKey",
    .parse_pubkey     = parse_der_spki_pubkey,
    .verify_context   = svc_s4u_verify_context,
};
```

Auth indicator emission is **not** a handler callback.  `ipadb_v9_issue_pac()`
reads `ied->s4u->service_type` and iterates `ied->s4u->auth_methods`, calling
`asprintf("%s-authn:%s", svctype, method)` for each entry and appending the
result to `*auth_indicators`.  This means all service types, including future
ones using the generic handler, automatically emit well-formed indicators with
no handler code change.  The OIDC handler populates `auth_methods` with every
RFC 8176 AMR value extracted from `OidcAuthnContext.amrValues`, so the number
of indicators in the ticket equals the number of AMR values in the token.

### LDAP Schema

SSH host principals use the existing `ipasshpubkey` attribute on host entries;
no schema change is needed for the SSH service type.  The same attribute is
also read from **user** entries (where it stores the user's registered SSH
public keys) to implement the SSH publickey strong assertion check.

For all other service types, two new attributes are added to Kerberos service
principal entries:

```
attributeTypes: ( 2.16.840.1.113730.3.8.15.2.4
    NAME 'ipaKrbServiceAttestationKey'
    DESC 'DER-encoded SubjectPublicKeyInfo for Kerberos S4U2Self attestation'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40
    X-ORIGIN 'IPA v4' )

attributeTypes: ( 2.16.840.1.113730.3.8.15.2.5
    NAME 'ipaKrbServiceAttestationType'
    DESC 'Service type allowed for S4U2Self attestation (e.g. oidc, pam, ssh)'
    EQUALITY caseExactIA5Match
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
    X-ORIGIN 'IPA v4' )

objectClasses: ( 2.16.840.1.113730.3.8.24.11
    NAME 'ipaKrbServiceAttestation'
    DESC 'Mixin for Kerberos services that participate in S4U2Self attestation'
    SUP top AUXILIARY
    MAY ( ipaKrbServiceAttestationKey $ ipaKrbServiceAttestationType ) )
```

`ipaKrbServiceAttestationKey` is multi-valued to support key rollover without
downtime.  `ipaKrbServiceAttestationType` is multi-valued to allow a single
service principal to act as an issuer for multiple service types; at least one
registered type must match the `serviceType` in the cert for the generic
handler to accept the request.

Both attributes are pre-fetched into `s4u->keys[]` and `s4u->types[]` at
`ipadb_get_principal()` time by `ipadb_parse_s4u_data()` — no second LDAP
round-trip is performed during cert verification.

## Implementation

### New Source File: `daemons/ipa-kdb/ipa_kdb_s4u_x509.c`

The entire KDC-side verification logic lives in this new file, compiled only
when `BUILD_IPA_S4U_X509` is defined.  It uses OpenSSL's declarative ASN.1
macro API (`ASN1_SEQUENCE` / `IMPLEMENT_ASN1_FUNCTIONS` /
`DECLARE_ASN1_FUNCTIONS`) with built-in OpenSSL types (`X509_ALGOR`,
`X509_PUBKEY`, `ASN1_INTEGER`, `ASN1_UTF8STRING`, `ASN1_OCTET_STRING`) to
define and generate parsers for both extension structures.  No manual DER byte
manipulation is required.

HKDF key derivation uses the OpenSSL 3.x `EVP_KDF` API (`EVP_KDF_fetch` /
`EVP_KDF_CTX_new` / `EVP_KDF_derive`).  OpenSSH public key parsing from LDAP
values is handled by decoding the SSH wire format (uint32-length-prefixed
fields) and constructing `EVP_PKEY` objects via `EVP_PKEY_new_raw_public_key`
(Ed25519) or `EVP_PKEY_fromdata` (ECDSA, RSA).  Supported SSH key types:
`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`.

FIPS mode is detected at runtime via `EVP_default_properties_is_fips_enabled(NULL)`
at the start of `ipadb_get_s4u_x509_principal`.  Both the Ed25519 and ECDSA
P-256 derivation paths are compiled unconditionally; only the runtime branch
differs.

### New `ipadb_s4u_data` structure and `ipadb_e_data` pointer (`daemons/ipa-kdb/ipa_kdb.h`)

All S4U2Self attestation state for a service or user principal entry is
consolidated in a single `struct ipadb_s4u_data`, allocated at
`ipadb_get_principal()` time and stored in `ipadb_e_data` via a new pointer:

```c
struct ipadb_s4u_data {
    /* LDAP-derived fields — populated by ipadb_parse_s4u_data() */
    krb5_data *keys;        /* ipaKrbServiceAttestationKey: DER SPKI (service entries) */
    int        n_keys;
    char **types;           /* ipaKrbServiceAttestationType: NULL-terminated list */
    krb5_data *ssh_pubkeys; /* ipasshpubkey: OpenSSH text (user & host entries) */
    int        n_ssh_pubkeys;
    /* Runtime fields — set by ipadb_get_s4u_x509_principal() */
    bool  attested;
    char *service_type;        /* "ssh", "oidc", "pam", etc. */
    char **auth_methods;       /* NULL-terminated RFC 8176 AMR list, e.g. {"pwd","otp",NULL} */
    char *ssh_key_fingerprint; /* "SHA256:..." (publickey auth only, NULL otherwise) */
    char *ssh_client_address;  /* "ip:port" (NULL if not provided) */
};

struct ipadb_e_data {
    /* ... existing fields ... */
    struct ipadb_s4u_data *s4u;  /* NULL for entries that never participate in S4U */
};
```

`ipadb_s4u_data` is heap-allocated for every entry returned by
`ipadb_parse_ldap_entry()` (since any entry may be a cert issuer or user
target).  The three arrays (`keys`, `types`, `ssh_pubkeys`) are populated from
LDAP at parse time; the runtime fields are zero-initialised and filled later.
`ipadb_free_principal_e_data()` frees all members, using
`krb5_free_data_contents()` for `krb5_data` array elements.

### `ipadb_parse_s4u_data()` helper (`daemons/ipa-kdb/ipa_kdb_principals.c`)

A static helper `ipadb_parse_s4u_data()` is called from
`ipadb_parse_ldap_entry()` for every entry fetched from LDAP.  It allocates an
`ipadb_s4u_data` and pre-fetches three LDAP attributes in a single pass
(all included in `std_principal_attrs[]` so they arrive in the same LDAP
response, incurring no extra round-trip):

| Attribute | Target field | Entry type |
|-----------|-------------|------------|
| `ipaKrbServiceAttestationKey` | `s4u->keys[]` / `n_keys` | service principal |
| `ipaKrbServiceAttestationType` | `s4u->types[]` | service principal |
| `ipasshpubkey` | `s4u->ssh_pubkeys[]` / `n_ssh_pubkeys` | host & user entries |

`keys[]` elements hold raw binary DER data (`krb5_data`).
`ssh_pubkeys[]` elements hold OpenSSH authorized_keys lines (`krb5_data`).
Both arrays are freed via `krb5_free_data_contents()` in
`ipadb_free_principal_e_data()`.

### SSH publickey strong assertion

When a user authenticates to the SSH server with an SSH public key
(`authMethod == "publickey"`), the cert's SubjectPublicKeyInfo carries the
user's actual SSH public key (not an ephemeral key).  `ssh_s4u_verify_context()`
exploits this to perform a strong assertion:

1. Extract the cert's SubjectPublicKeyInfo via `X509_get_pubkey()`.
2. For each OpenSSH key line in `ied->s4u->ssh_pubkeys[]` (fetched from the
   user's `ipasshpubkey` LDAP attribute at `get_principal()` time), parse it
   with `parse_openssh_pubkey()` and compare with `EVP_PKEY_eq()`.
3. If any registered key matches: `ied->s4u->attested = true`.
4. If no key matches: log at `LOG_INFO` and leave `attested = false`; the
   `issue_pac` call emits no auth indicator for this request.

For all other auth methods (password, keyboard-interactive, MFA, etc.) the
cert subject is sufficient evidence — `attested` is set unconditionally.  The
SubjectPublicKeyInfo for those methods holds an ephemeral key (not
user-registered) so no LDAP key comparison is needed or useful.

### Default Trust View ID Override Fallback

When `s4u_lookup_user_by_cn()` cannot resolve the username as a local IPA
Kerberos principal (`KRB5_KDB_NOENTRY`), it performs a second LDAP search
against the Default Trust View:

```
Base:       cn=Default Trust View,cn=views,cn=accounts,$SUFFIX
Filter:     (ipaOriginalUid=<username>)
Attributes: ipaSshPubKey, userCertificate;binary
```

The Default Trust View stores ID overrides for users from trusted realms
(e.g. Active Directory) that have been given a local IPA identity.  An ID
override entry may carry SSH public keys (`ipaSshPubKey`, OpenSSH text format)
and/or X.509 certificates (`userCertificate;binary`, DER format) for the
external user.

**Publickey strong assertion with an ID override:**

If `authMethod == "publickey"` and a matching ID override is found:

1. Parse each `ipaSshPubKey` value into an `EVP_PKEY` and compare against the
   cert's SubjectPublicKeyInfo via `EVP_PKEY_eq()`.
2. Also extract the SubjectPublicKeyInfo from each `userCertificate;binary`
   DER certificate and compare via `EVP_PKEY_eq()`.
3. If any value matches: `ied->s4u->attested = true`.
4. If no value matches: `attested` remains false; no auth indicator is emitted.
   The S4U2Self itself still succeeds.

For non-publickey auth methods, finding a matching ID override entry is
sufficient to set `attested = true` — the same rule as for local IPA
principals.  No key comparison is performed.

**LDAP attribute mapping:**

| LDAP attribute | Source type | Purpose |
|----------------|-------------|---------|
| `ipaOriginalUid` | `ipaNTUserAttrs` / ID override | maps external username to override entry |
| `ipaSshPubKey` | `ipaSshGroupOfPubKeys` | SSH public keys in OpenSSH text format |
| `userCertificate;binary` | `person` | X.509 certificates in DER format |

### Changes to `ipadb_v9_issue_pac()` (`daemons/ipa-kdb/ipa_kdb_mspac_v9.c`)

After the existing PAC building code, a new block checks `ied->s4u->attested` on
the client db entry.  When set and the request is a protocol transition
(`KRB5_KDB_FLAG_PROTOCOL_TRANSITION`), it iterates `ied->s4u->auth_methods` and
appends one `krb5_data` indicator string per entry, formatted as
`"<serviceType>-authn:<method>"` via `asprintf`.  If `auth_methods` is empty or
absent the loop uses a synthetic `{"unknown", NULL}` fallback.  Each indicator is
appended to `*auth_indicators` via `realloc` rather than overwriting, so
indicators set by earlier stages (e.g. PKINIT) are preserved.  No per-handler
callback is invoked; all fields are read directly from `ied->s4u`.

### KDB Vtable Registration (`daemons/ipa-kdb/ipa_kdb.c`)

The `get_s4u_x509_principal` slot in both the DAL v8 and DAL v9 `kdb_vftabl`
instances is set to `ipadb_get_s4u_x509_principal` when `BUILD_IPA_S4U_X509` is
defined, and `NULL` otherwise.  Auth indicator emission is only reachable via
the DAL v9 `issue_pac` path; the DAL v8 slot is wired for completeness.

### Build System

`server.m4` detects OpenSSL via `PKG_CHECK_MODULES([OPENSSL], [libssl libcrypto])`.

`configure.ac` defines the `BUILD_IPA_S4U_X509` automake conditional and the
`BUILD_IPA_S4U_X509` C preprocessor macro (`AC_DEFINE`) when both OpenSSL and
the DAL v9 `issue_pac` hook (`have_kdb_issue_pac`) are available.  Tying the
feature to `have_kdb_issue_pac` ensures auth indicator emission is never
silently disabled on older KDC versions.

`daemons/ipa-kdb/Makefile.am` adds:
- `$(OPENSSL_CFLAGS)` to `AM_CPPFLAGS` and `$(OPENSSL_LIBS)` to
  `ipadb_la_LIBADD` (always, since OpenSSL may be used elsewhere in future)
- `ipa_kdb_s4u_x509.c` to `ipadb_la_SOURCES` conditionally on
  `BUILD_IPA_S4U_X509`
- A dedicated `ipa_kdb_s4u_x509_tests` cmocka binary (see [Test Plan](#test-plan))

### Adding New Service Types

| Component | Required change |
|-----------|----------------|
| KDB plugin (`ipa_kdb_s4u_x509.c`) | Add entry to `s4u_handlers[]`; implement `parse_pubkey` and `verify_context`; add context extension OID |
| IPA API (`ipalib/plugins/service.py`) | Extend `service-add-attestation-key` / `service-remove-attestation-key` to validate the new type string |
| IPA LDAP schema | Assign OID for new context extension; add to schema file |
| Service client library | Implement HKDF, context extension encoding, GSSAPI delivery |

The generic verification path (steps 1–9) does not change when new service
types are added.

### Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| OpenSSL | ≥ 3.0 (RHEL 9) | ASN.1 parsing, HKDF, EVP key operations |
| MIT Kerberos | ≥ 1.21 (RHEL 9) | DAL v9 `issue_pac`, `krb5_dbe_decrypt_key_data` |
| MIT Kerberos (client) | ≥ 1.19 | `GSS_KRB5_NT_X509_CERT` name type (SSH server side) |

OpenSSL is already present on IPA servers.  No new RPM dependency is introduced
for the ipa-server package.  The SSH server side requires MIT Kerberos ≥ 1.19;
RHEL 8 (ships 1.18.2) must fall back to plain PA-FOR-USER.

### FIPS 140-2/140-3 Considerations

| Operation | Non-FIPS | FIPS mode |
|-----------|----------|-----------|
| Derived key pair | Ed25519 | ECDSA P-256 |
| Cert outer signature | id-Ed25519 | ecdsa-with-SHA256 |
| Binding signature | id-Ed25519 | ecdsa-with-SHA256 |
| HKDF | SHA-256 | SHA-256 (approved) |
| Keytab enctype | Any ≥ 17 | AES-256 only (enctypes 18, 20); enctypes 17, 19 rejected |
| Client Ed25519 key | Allowed in SPKI | Reject cert / fall back to plain S4U2Self |

FIPS detection is runtime-only: both algorithm paths are compiled into the binary.

### Post-Quantum Cryptography Roadmap

The design accommodates future post-quantum algorithm migration with no
structural changes to the extension format.

**Phase 1 (current):** Ed25519 / ECDSA P-256.

**Phase 2 (transition):** Composite signatures — ECDSA-P384 + ML-DSA-65
(draft-ietf-lamps-pq-composite-sigs).  The `sigAlg AlgorithmIdentifier` field
already accommodates composite OIDs.  HKDF-SHA384 upgrade for level-3 PQ
security headroom.

**Phase 3 (PQ-only):** ML-DSA-65 (FIPS 204), or SLH-DSA-SHA2-128s (FIPS 205)
if a no-lattice requirement is imposed.  ML-DSA key generation takes a 32-byte
seed deterministically, identical in structure to Ed25519 — the HKDF output
feeds directly into `ML-DSA.KeyGen_internal`.  The primary blocker is MIT
Kerberos PKINIT not yet supporting ML-DSA X.509 certificates.

### Thread Safety

MIT Kerberos dispatches each TGS-REQ on a single thread for the lifetime of
that request.  `get_s4u_x509_principal` and `issue_pac` are called sequentially
on the same thread within one request dispatch (`do_tgs_req.c`).  No concurrent
access to `user_entry->e_data` occurs within a single request.  The
`ipadb_context` and LDAP connection structures are read-only after module
initialisation and require no additional locking.

## Feature Management

### UI

No Web UI changes are required.  SSH public keys registered via
`ipa host-mod --sshpubkey` are automatically used by the KDC plugin.

### CLI

No new CLI commands are introduced for the Phase 1 SSH service type.  The
feature activates automatically when the host has SSH public keys registered
and the build system enables `BUILD_IPA_S4U_X509`.

For future non-SSH service types, two commands extend the existing Kerberos
service management:

| Command | Options | Purpose |
|---------|---------|---------|
| `ipa service-add-attestation-key <principal>` | `--type=TYPE`, `--pub-key-file=FILE` | Register a service attestation public key |
| `ipa service-remove-attestation-key <principal>` | `--pub-key-file=FILE` | Remove a registered attestation key |
| `ipa service-show <principal>` | — | Lists registered keys in output |

Auth indicator ticket lifetime policy is configured via `ipa krbtpolicy-mod`:

```bash
ipa krbtpolicy-mod --ssh-authn-maxlife=28800 --ssh-authn-maxrenew=86400
ipa krbtpolicy-mod --oidc-authn-maxlife=43200 --oidc-authn-maxrenew=172800
```

Service access control (requiring a specific indicator to access a service) is
configured via `ipa service-mod --auth-ind`:

```bash
# Allow only SSH public-key attested tickets to access a sensitive service
ipa service-mod http/internal.example.com@REALM \
    --auth-ind ssh-authn:publickey

# Require any OIDC MFA attestation
ipa service-mod http/api.example.com@REALM \
    --auth-ind oidc-authn:mfa

# Mix AS-REQ and S4U2Self indicators on the same service
ipa service-mod http/api.example.com@REALM \
    --auth-ind otp --auth-ind oidc-authn:mfa
```

The `--auth-ind` parameter accepts both the fixed AS-REQ indicator set and any
`<service>-authn:<detail>` S4U2Self attestation indicator, validated by
`validate_auth_indicator_value()` in `ipaserver/plugins/service.py`.

### Configuration

The feature is enabled at build time when both OpenSSL and DAL v9 are available.
No runtime configuration knob is provided in Phase 1.  No new `krb5.conf` or
`ipaserver.conf` options are required.  Policy (which indicators are required
for which services) is expressed via existing IPA HBAC rules and Kerberos ticket
policy.

## Upgrade

The `KerberosServiceIssuerBinding` extension (OID `2.16.840.1.113730.3.8.15.3.1`)
is a renamed and extended version of the earlier SSH-specific
`id-ce-sshKerberosIssuerBinding` used during initial development.  The ASN.1
gains a `serviceType` field as the second element and `sshHostKey` is renamed to
`serviceKey`.  Because neither the OpenSSH client implementation nor the IPA KDB
plugin has been released publicly, no compatibility concern with deployed
instances applies.

The KDB plugin change is backward-compatible.  `ipadb_s4u_data` is
zero-initialised at allocation time; the `attested` gate flag defaults to
`false`, so `ipadb_v9_issue_pac` behaviour is unchanged for any request that
does not present a valid attestation certificate.  Downgrading the ipa-kdb
plugin to a version without this feature reverts to plain S4U2Self silently.

No new LDAP schema is required for Phase 1 (SSH).  The `ipasshpubkey` attribute
used to cross-check the SSH host public key (and, for the strong assertion, the
user's registered keys) is already present on enrolled hosts and users.  No
data migration is needed.

## Test Plan

### Unit Tests (`daemons/ipa-kdb/tests/ipa_kdb_s4u_x509_tests.c`)

A dedicated cmocka test binary links against cmocka, krb5, LDAP, OpenSSL, and
kdb5.  It includes `ipa_kdb_s4u_x509.c` directly to access static functions.
Stubs for `ipadb_get_context`, `ipadb_get_principal`, `ipadb_simple_search` use
the cmocka `will_return` / `mock()` mechanism.

| Area | Tests |
|------|-------|
| `d2i_KERBEROS_SERVICE_ISSUER_BINDING` | Valid DER round-trip; bad version field; truncated input |
| `d2i_SSH_AUTHN_CONTEXT` | Full fields including optionals; absent optionals; bad version |
| `d2i_OIDC_AUTHN_CONTEXT` | Full fields; absent optionals; multiple `amrValues`; bad version |
| `parse_openssh_pubkey` | Ed25519 round-trip; ECDSA P-256; RSA; unknown key type |
| `parse_der_spki_pubkey` | Ed25519 and ECDSA DER SPKI round-trip |
| `hkdf_sha256` | Determinism; different `info` → different output |
| `derive_attestation_key` | Ed25519 determinism; FIPS/P-256 path; different kvno → different key |
| `verify_binding_signature` | Valid signature; corrupted signature; wrong kvno |
| `ipadb_get_s4u_x509_principal_impl` | Null/empty cert; null context; garbage DER; missing extension; full pipeline (SSH, OIDC, generic); FIPS mode; publickey strong assertion (cert SPKI vs registered `ipasshpubkey`) |
| `oidc_auth_methods` | Single AMR value; multiple AMR values; empty `amrValues` → "sso" fallback; absent context → "sso" fallback |

### Integration Tests

| Scenario | Expected result |
|----------|----------------|
| SSH publickey auth; user key in `ipasshpubkey` | Ticket carries `ssh-authn:publickey` |
| SSH publickey auth; user key NOT in `ipasshpubkey` | S4U2Self succeeds; no `ssh-authn:*` indicator |
| SSH password auth (host ECDSA key; ephemeral subject key) | Ticket carries `ssh-authn:password` |
| SSH keyboard-interactive auth | Ticket carries `ssh-authn:keyboard-interactive` |
| SSH + FIPS mode (P-256 derived key) | Attestation accepted; `ssh-authn:*` injected |
| OIDC; `amr=["pwd","otp"]` | Ticket carries both `oidc-authn:pwd` and `oidc-authn:otp` |
| OIDC; `amr=["mfa"]` | Ticket carries `oidc-authn:mfa` |
| OIDC; `amrValues` absent from context | Ticket carries `oidc-authn:sso` |
| OIDC; unregistered attestation key | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Generic service type registered via `ipaKrbServiceAttestationKey` | Ticket carries `<stype>-authn:unknown` |
| Generic handler: `serviceType` not in `ipaKrbServiceAttestationType` | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Cert `serviceKey` (host) not in `ipasshpubkey` | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Cert with invalid binding signature | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Cert with invalid outer signature | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Cert with wrong KVNO | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Cert outside validity period | `KRB5KDC_ERR_CERTIFICATE_MISMATCH` |
| Keytab re-keying (KVNO bump) | New certs accepted; old in-flight certs rejected after cert expiry |
| Two keys registered for rollover; cert matches second key | Attestation accepted |
| Cross-realm user | Cert not verified (MIT Kerberos realm-check precondition); plain S4U2Self |
| FIPS: Ed25519-signed cert | Rejected |
| FIPS: ECDSA P-256-signed cert | Accepted |

## Troubleshooting and Debugging

### KDC logs

All verification failures are logged via `krb5_klog_syslog` at `LOG_ERR` or
`LOG_WARNING` level with the prefix `"S4U X.509:"`.  Check
`/var/log/krb5kdc.log` or `journalctl -u krb5kdc` for messages such as:

```
S4U X.509: cert missing kerberosServiceIssuerBinding extension
S4U X.509: binding signature invalid for 'host/srv.example.com@EXAMPLE.COM'
S4U X.509: service key not registered for 'host/srv.example.com@EXAMPLE.COM'
S4U X.509: no SSH public keys registered for 'host/srv.example.com@EXAMPLE.COM'
S4U X.509: service type 'oidc' not registered for 'oidc/broker.example.com@EXAMPLE.COM'
S4U X.509: Ed25519 cert rejected in FIPS mode
```

When the user's SSH public key is not registered (publickey auth, strong
assertion check fails), an `LOG_INFO` message is emitted and no indicator is
injected; the S4U2Self itself still succeeds:

```
S4U X.509: SSH public key not registered for user; no attestation indicator emitted
```

### Verifying SSH host key registration

```
ipa host-show srv.example.com --all | grep -i sshpubkey
```

If no `ipasshpubkey` values are present on the host entry, the plugin will
reject the host key cross-check.  Re-run `ipa-client-install` or add keys
manually:

```
ipa host-mod srv.example.com --sshpubkey="$(cat /etc/ssh/ssh_host_ed25519_key.pub)"
```

For the SSH publickey strong assertion to work, the **user**'s entry must also
have `ipasshpubkey` values matching the key the user used to authenticate.
These are managed via `ipa user-mod --sshpubkey` or added automatically when
the user first authenticates if the IPA client is configured to upload keys.

### Checking whether the feature is compiled in

```
nm -D /usr/lib64/krb5/plugins/kdb/ipadb.so | grep ipadb_get_s4u_x509_principal
```

If the symbol is absent, the build did not enable `BUILD_IPA_S4U_X509`.  Verify
that OpenSSL development headers were present at build time.

### Inspecting the attestation certificate

```bash
openssl x509 -in cert.der -inform DER -text -noout
# Look for:
#   id-ce-kerberosServiceIssuerBinding  2.16.840.1.113730.3.8.15.3.1
#   id-ce-sshAuthnContext               2.16.840.1.113730.3.8.15.3.2
```

### Checking registered keys in LDAP (future non-SSH services)

```bash
ldapsearch -Y GSSAPI -b "cn=services,cn=accounts,$SUFFIX" \
    "(&(objectClass=ipaKrbServiceAttestation)(krbPrincipalName=oidc/broker.example.com@*))" \
    ipaKrbServiceAttestationKey
```

### Auth indicators not appearing in service ticket

1. Confirm the service ticket was obtained via S4U2Self (PA-FOR-X509-USER
   padata present in the TGS-REQ).
2. Confirm `krb5_klog_syslog` shows the `"attested S4U2Self"` success message.

Auth indicators live in the service ticket's `enc-part`, protected by the
service key; they are not readable from the client side alone.  To inspect them,
decrypt the ticket via a loopback GSSAPI security context that uses both the
ccache (initiator) and the service keytab (acceptor), then query the RFC 6680
naming attribute `urn:ietf:params:gss:krb5:authentication-indicator`.

Auth indicators are not present in cross-realm tickets — this is by design.

Example — querying the indicator via a loopback GSSAPI context:

```python
import gssapi
from gssapi._utils import import_gssapi_extension
rfc6680 = import_gssapi_extension('rfc6680')

creds = gssapi.Credentials(usage='initiate')
acc_creds = gssapi.Credentials(usage='accept',
                               store={'keytab': '/etc/krb5.keytab'})
target = gssapi.Name('host@srv.example.com',
                     gssapi.NameType.hostbased_service)
init_ctx = gssapi.SecurityContext(name=target, creds=creds,
                                  mech=gssapi.MechType.kerberos,
                                  usage='initiate')
acc_ctx  = gssapi.SecurityContext(creds=acc_creds, usage='accept')
in_tok = None
while not acc_ctx.complete:
    out_tok = init_ctx.step(in_tok)
    in_tok  = acc_ctx.step(out_tok) if out_tok else None
    if not init_ctx.complete and in_tok:
        init_ctx.step(in_tok); in_tok = None

attr = b'urn:ietf:params:gss:krb5:authentication-indicator'
result = rfc6680.get_name_attribute(acc_ctx.initiator_name, attr)
print([v.decode() for v in result.values])
# e.g. ['ssh-authn:publickey']
```

### Open Questions (as of initial implementation)

- **OID registration:** All OIDs are registered — LDAP attributes
  `ipaKrbServiceAttestationKey` (`2.16.840.1.113730.3.8.15.2.4`),
  `ipaKrbServiceAttestationType` (`2.16.840.1.113730.3.8.15.2.5`), objectClass
  `ipaKrbServiceAttestation` (`2.16.840.1.113730.3.8.24.11`), X.509 extensions
  `id-ce-kerberosServiceIssuerBinding` (`2.16.840.1.113730.3.8.15.3.1`),
  `id-ce-sshAuthnContext` (`2.16.840.1.113730.3.8.15.3.2`), and
  `id-ce-oidcAuthnContext` (`2.16.840.1.113730.3.8.15.3.3`).
  OID `2.16.840.1.113730.3.8.15.3.4` is reserved (previously planned for RADIUS,
  now unallocated).
- `id-pkinit-KPClientAuth` EKU: Confirm the MIT KDC does not attempt PKINIT
  processing on a cert bearing this EKU when it arrives via PA-FOR-X509-USER
  (type 130) rather than PKINIT padata.  If ambiguous, define a dedicated EKU
  OID (`2.16.840.1.113730.3.8.15.3.6`).
- **Auth indicator namespace:** The `<serviceType>-authn:<detail>` format is
  established and fully implemented.  The IPA ticket policy layer
  (`krbtpolicy.py`, `ipa_kdb_kdcpolicy.c`) supports `ssh-authn` and
  `oidc-authn` as LDAP attribute subtypes and as prefix-matched indicator
  strings in `check_tgs()`.  The IPA service and host plugins
  (`ipaserver/plugins/service.py`, `ipaserver/plugins/host.py`) accept
  `<service>-authn:<detail>` values via `ipa service-mod --auth-ind` and
  `ipa host-mod --auth-ind`, validated by `validate_auth_indicator_value()`.
  The change from `StrEnum` to `Str`+validator is backward-compatible: all
  previously accepted fixed indicator values remain valid.
- **Keytab re-keying overlap:** The key lookup matches on both `enctype` and
  `kvno`; old certs continue to verify against old key entries as long as they
  remain in the KDB.  Short cert validity makes the overlap window small.
- **RHEL 8 SSH server:** `GSS_KRB5_NT_X509_CERT` requires MIT Kerberos ≥ 1.19;
  RHEL 8 (ships 1.18.2) must always use the plain PA-FOR-USER fallback.
- **Ed25519 SSH client keys in FIPS mode:** If the client authenticated with an
  Ed25519 public key the SubjectPublicKeyInfo cannot be placed in the cert in
  FIPS mode.  Phase 1 falls back to plain S4U2Self in this case.
- **KDB entry for ID-override-only users:** When the user is resolved exclusively
  via a Default Trust View ID override (Pass 2 in step 11) and has no local IPA
  Kerberos principal, `get_s4u_x509_principal` must still return a
  `krb5_db_entry` to the MIT KDC.  The exact entry to return — a synthetic
  minimal entry built from ID override attributes, the associated IPA user object
  (if any), or the AD principal fetched via the trust infrastructure — is an open
  design question for Phase 2.  Phase 1 returns `KRB5_KDB_NOENTRY` for this case
  (no attestation for users without a local IPA principal entry).
