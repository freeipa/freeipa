# SSH S4U2Self/S4U2Proxy X.509 attestation — Python example client

Reference implementation of the SSH host-side attestation pipeline described
in `doc/designs/krb-s4u-x509-assertion.md`.

Demonstrates how an SSH server (or a tool running with its keytab) can build
a short-lived X.509 certificate that attests an SSH authentication event,
exchange it for a Kerberos service ticket via S4U2Self (protocol transition),
and optionally use that ticket to perform S4U2Proxy (constrained delegation)
toward a target service such as `HTTP/ipa.example.com`.

## Background

When a user authenticates to an SSH server that is enrolled in FreeIPA, the
server can obtain a Kerberos service ticket on the user's behalf without
requiring the user to have a TGT.  With the attestation extension, the TGS-REQ
carries a signed X.509 certificate (PA-FOR-X509-USER, RFC 6112) that lets the
IPA KDB plugin inject SSH authentication indicators into the resulting service
ticket.  Indicator format: `<serviceType>-authn:<method>` (e.g.
`ssh-authn:publickey`, `ssh-authn:password`).

The certificate is signed with a key derived from the host Kerberos keytab, so
no additional credentials or PKI infrastructure are required.

## File layout

| File | Mirrors C source | Purpose |
|------|-----------------|---------|
| `keytab.py` | `gss-s4u-x509-keytab.c` | Keytab enumeration and key selection |
| `crypto.py` | `gss-s4u-x509-crypto.c` / `ipa_kdb_s4u_x509.c` | HKDF key derivation and binding signature |
| `asn1.py` | `gss-s4u-x509-asn1.c` | DER encoding of the custom X.509 extensions and PKINIT SAN |
| `cert.py` | `gss-s4u-x509.c` | X.509 certificate assembly |
| `gss.py` | *(GSSAPI call site in sshd)* | GSSAPI S4U2Self acquisition |
| `__main__.py` | *(integration)* | CLI entry point |

## Requirements

```
pip install cryptography gssapi python-krb5
```

- `cryptography` — any version with X.509 builder support (DER encoding is hand-written)
- `gssapi` — python-gssapi with MIT Kerberos backend
- `python-krb5` — python bindings for libkrb5 (keytab access)
- `ipapython` — for `SSHPublicKey` (SSH key parsing and `SHA256:` fingerprinting)
- MIT Kerberos >= 1.19 — for `GSS_KRB5_NT_X509_CERT` / PA-FOR-X509-USER
- FreeIPA >= 4.11 — for the KDB plugin that verifies the attestation cert

## Usage

```sh
python __main__.py \
    --user alice \
    --realm EXAMPLE.COM \
    --hostname server.example.com \
    [--keytab /etc/krb5.keytab] \
    [--host-pubkey /etc/ssh/ssh_host_ed25519_key.pub] \
    [--auth-method publickey] \
    [--user-pubkey /home/alice/.ssh/id_ed25519.pub] \
    [--session-id <hex>] \
    [--client-address 192.0.2.1:22] \
    [--output-cert cert.der] \
    [--ipa-server ipa.example.com]
```

`--keytab` and `--host-pubkey` default to the system locations.  `--session-id`
defaults to 32 random bytes (sufficient for non-SSH testing).

`--user-pubkey` specifies the user's SSH public key file.  When provided, the
key is embedded as the certificate's subject public key and its `SHA256:`
fingerprint is included in `id-ce-sshAuthnContext`.  Use with
`--auth-method publickey` so the KDB plugin verifies the key against the
user's registered `ipasshpubkey` values.

`--ipa-server` triggers S4U2Proxy after S4U2Self: the host requests a service
ticket for `HTTP/<ipa-server>@<realm>` on behalf of the impersonated user.
This requires the IPA server to have the host in its constrained-delegation
policy (`ipa service-add-delegation` or equivalent).

To inspect the generated certificate:

```sh
openssl x509 -in cert.der -inform DER -text -noout
```

## Protocol walk-through

1. **Keytab** (`keytab.py`) — Open the host keytab and select the best AES
   entry for `host/<hostname>@<REALM>` (preference: enctype 20 > 19 > 18 > 17;
   AES-128 enctypes 17 and 19 are rejected in FIPS mode).

2. **Key derivation** (`crypto.py`) — Derive an attestation signing key from
   the raw keytab key material using HKDF-SHA256:
   - IKM: raw keytab key bytes
   - Salt: `ssh-attestation-v1`
   - Info: `hostname || NUL || realm || NUL || kvno_be32`
   - Non-FIPS: 32-byte output → Ed25519 private key
   - FIPS: 48-byte output → P-256 scalar via NIST SP 800-56A Rev 3 §5.6.1.2.2

3. **Binding signature** (`crypto.py`) — Sign a digest binding the host key to
   the principal and KVNO:
   ```
   digest = SHA256(host_SPKI_DER || "ssh-attestation-binding-v1" || principal || kvno_be32)
   sig    = Ed25519.sign(key, digest)           # non-FIPS
          | ECDSA-SHA256.sign(key, digest)      # FIPS
   ```

4. **Certificate** (`cert.py`) — Build a short-lived (≤ 300 s) X.509 v3
   certificate signed by the derived attestation key:
   - Subject CN: SSH username
   - Issuer CN: `host/<hostname>@<REALM>`
   - SubjectPublicKeyInfo: user's SSH public key (publickey auth) or an
     ephemeral key for other authentication methods
   - Extensions:
     - `basicConstraints`: CA:FALSE (critical)
     - `keyUsage`: digitalSignature (critical)
     - `extKeyUsage`: id-pkinit-KPClientAuth
     - `subjectAltName`: id-pkinit-san OtherName with KRB5PrincipalName (critical)
     - `id-ce-kerberosServiceIssuerBinding` — version, serviceType, principal,
       enctype, kvno, AlgorithmIdentifier, host SPKI, binding signature
     - `id-ce-sshAuthnContext` — version, auth method, session ID,
       key fingerprint (optional), client address (optional)

5. **S4U2Self** (`gss.py`) — Import the DER certificate as a GSSAPI name
   using `GSS_KRB5_NT_X509_CERT` (OID 1.2.840.113554.1.2.2.7).  The GSSAPI
   mechanism has no SAN awareness — it stores the raw cert bytes opaquely
   (`is_cert = 1`) and forwards them verbatim into the PA-S4U-X509-USER
   `subject_cert` field.  The KDC in turn passes the blob unchanged to the IPA
   KDB plugin, which performs all X.509 interpretation and injects SSH
   authentication indicators into the resulting service ticket.

6. **S4U2Proxy** (`gss.py`, optional) — After S4U2Self, the host can request
   a proxy ticket for a target service (e.g. `HTTP/ipa.example.com`) on
   behalf of the impersonated user.  `gss_init_sec_context()` with the
   S4U2Self credentials triggers a TGS-REQ with `KDC_OPT_CNAME_IN_ADDL_TKT`
   and the S4U2Self service ticket in `additional-tickets`.  The KDC verifies
   the host's constrained-delegation policy and, if permitted, issues a proxy
   service ticket.  The resulting AP-REQ token can be sent to the target
   service to authenticate the impersonated user.

## KDB plugin verification sequence

The IPA KDB plugin (`ipa_kdb_s4u_x509.c`) receives the raw certificate blob
from the KDC and does all X.509 work itself.  The KDC performs no certificate
parsing, no PKINIT processing, and no chain validation — it only verifies the
checksum over the PA-S4U-X509-USER payload using the TGS session key.

1. Parse `id-ce-kerberosServiceIssuerBinding`; read `serviceType` → select
   handler (`"ssh"` → SSH handler; unknown types → generic handler).
2. Reject FIPS-invalid `sigAlg` or weak enctype.
3. Look up the host principal in the KDB; decrypt keytab key `(enctype, kvno)`.
4. Re-derive the signing key via HKDF-SHA256; verify the cert's outer signature.
5. Compare the cert's `serviceKey` against the host's registered keys:
   - SSH handler: cert SPKI vs `ipasshpubkey` values (OpenSSH text, pre-fetched
     from the host LDAP entry — no second LDAP round-trip).
6. Verify the binding signature.
7. Parse `id-ce-sshAuthnContext`; resolve the user principal from the PKINIT SAN
   (preferred) or Subject CN (fallback).
8. For `authMethod == "publickey"`: compare cert SPKI against the user's
   registered `ipasshpubkey` values; set `attested = true` only on match.
   For all other methods: set `attested = true` unconditionally.
9. `issue_pac` emits `"ssh-authn:<authMethod>"` as an auth indicator into the
   service ticket when `attested` is true.

## ASN.1 encoding notes

All three structures (`SshAuthnContext`, `KerberosServiceIssuerBinding`,
`KRB5PrincipalName`) are encoded with minimal hand-written DER helpers in
`asn1.py` to avoid version-specific dependencies on `cryptography.hazmat.asn1`
(the declarative codec API has changed across releases).

- `KerberosServiceIssuerBinding` embeds an `AlgorithmIdentifier` (SEQUENCE + OID)
  and a `SubjectPublicKeyInfo` — neither maps to a type the declarative codec
  can represent directly (no OID type; `bytes` maps to OCTET STRING).
- `KRB5PrincipalName` uses `GeneralString` (universal tag 0x1B), which the
  declarative codec cannot produce (`str` maps to UTF8String 0x0C).
- `SshAuthnContext` has `[0]/[1] EXPLICIT OPTIONAL` fields; the `Explicit`
  wrapper was not available in all `cryptography` releases.

## OIDs

| OID | Name |
|-----|------|
| `2.16.840.1.113730.3.8.15.3.1` | id-ce-kerberosServiceIssuerBinding |
| `2.16.840.1.113730.3.8.15.3.2` | id-ce-sshAuthnContext |
| `1.3.6.1.5.2.2` | id-pkinit-san |
| `1.3.6.1.5.2.3.4` | id-pkinit-KPClientAuth |
| `1.2.840.113554.1.2.2.7` | GSS_KRB5_NT_X509_CERT |

## FIPS mode

FIPS mode is detected automatically from `/proc/sys/crypto/fips_enabled` (with
fallback to `ssl.FIPS_mode()`).  In FIPS mode:

- Ed25519 keys are replaced by ECDSA P-256 throughout (signing key and
  ephemeral subject key)
- AES-128 keytab entries (enctypes 17 and 19) are rejected; only AES-256
  enctypes (18 and 20) are accepted as IKM
- Ed25519 subject public keys from `--auth-method publickey` are rejected;
  pass `--auth-method password` to use an ephemeral P-256 key instead

## See also

- Design document: `doc/designs/krb-s4u-x509-assertion.md`
- OpenSSH client implementation: `gss-s4u-x509-{asn1,crypto,keytab}.c` and `gss-s4u-x509.c`
- IPA KDB plugin: `daemons/ipa-kdb/ipa_kdb_s4u_x509.c`
