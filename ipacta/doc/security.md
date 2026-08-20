# Security Features

This document covers ipacta's audit logging, hardware security module
integration, key encryption, and key escrow subsystems.

## Audit Logging (`audit.py`)

ipacta maintains a signed, tamper-evident audit log for compliance and
forensics. The audit system is Dogtag-compatible in format.

### Audit Events

| Event | Constant | Description |
|-------|----------|-------------|
| Authentication success | `AUTH_SUCCESS` | Successful client auth |
| Authentication failure | `AUTH_FAIL` | Failed client auth |
| Authorization success | `AUTHZ_SUCCESS` | Access granted |
| Authorization failure | `AUTHZ_FAIL` | Access denied |
| Certificate request | `CERT_REQUEST` | CSR submitted |
| Certificate issued | `CERT_REQUEST_PROCESSED` | Certificate signed |
| Status change request | `CERT_STATUS_CHANGE_REQUEST` | Revoke/unrevoke requested |
| Status change complete | `CERT_STATUS_CHANGE_REQUEST_PROCESSED` | Revocation applied |
| Profile request | `PROFILE_CERT_REQUEST` | Profile-based issuance |
| Profile config | `CONFIG_CERT_PROFILE` | Profile created/modified/deleted |
| CRL generation | `CRL_GENERATION` | CRL generated |
| CRL retrieval | `CRL_RETRIEVAL` | CRL downloaded |
| Key generation | `KEY_GEN_ASYMMETRIC` | RSA/EC key pair generated |
| Key recovery request | `KEY_RECOVERY_REQUEST` | Key recovery initiated |
| Key recovery complete | `KEY_RECOVERY_REQUEST_PROCESSED` | Key recovered |
| CA signing | `CA_SIGNING` | CA key used for signing |
| OCSP generation | `OCSP_GENERATION` | OCSP response generated |
| Security domain | `SECURITY_DOMAIN_UPDATE` | Domain membership changed |
| Sub-CA creation | `SUBCA_CREATION` | Lightweight CA created |
| Sub-CA deletion | `SUBCA_DELETION` | Lightweight CA deleted |
| Serial config | `CONFIG_SERIAL_NUMBER` | Serial range allocated |
| Log signing | `LOG_SIGNING` | Audit log signed |
| Audit startup | `AUDIT_LOG_STARTUP` | Audit subsystem started |
| Audit shutdown | `AUDIT_LOG_SHUTDOWN` | Audit subsystem stopped |

### Audit Outcomes

- `AuditOutcome.SUCCESS` -- Operation completed successfully.
- `AuditOutcome.FAILURE` -- Operation failed.

### AuditLogger

```python
AuditLogger(
    log_file: str = None,
    max_size: int = 52428800,     # 50 MB
    backup_count: int = 50,
    enable_signing: bool = True,
    audit_cert_nickname: str = "auditSigningCert cert-pki-ca",
)
```

**Log signing:** Each log record is signed with RSA-SHA256 (or the
algorithm from `ca.audit_signing_algorithm`). The signing key is
extracted from the NSS database using the audit signing certificate
nickname. A hash chain links each record to the previous one, enabling
tamper detection.

**Log format:** Dogtag-compatible key=value pairs with the signature
appended as `[signature=base64_encoded_sig]`.

**Log rotation:** `RotatingFileHandler` with configurable max size and
backup count.

### Convenience Methods

| Method | Parameters | Description |
|--------|-----------|-------------|
| `log_certificate_request` | principal, request_id, profile, subject | CSR submitted |
| `log_certificate_issued` | principal, request_id, serial, subject, profile, signing_algorithm | Certificate signed |
| `log_certificate_revoked` | principal, serial, reason | Certificate revoked |
| `log_certificate_unrevoked` | principal, serial | Certificate taken off hold |
| `log_authentication` | principal, auth_method | Authentication event |
| `log_authorization` | principal, permission, resource | Authorization decision |
| `log_profile_operation` | principal, operation, profile_id | Profile CRUD |
| `log_crl_generation` | principal, crl_number, num_revoked | CRL generated |
| `log_subca_operation` | principal, operation, ca_id, subject | Sub-CA lifecycle |

All methods accept optional `source_ip` and `outcome` parameters.

### Log Integrity Verification

```python
AuditLogger.verify_log_integrity(log_file)
```

Re-verifies each log line's RSA signature individually against the
audit signing certificate's public key. Returns `True` if every signed
line's signature is valid (unsigned lines are logged as a warning but
do not fail verification).

Note: this only checks per-line signatures. It does **not** recompute
or cross-check the `prev_hash` hash-chain field against neighboring
records, so it cannot detect whole lines being deleted or reordered as
long as each remaining line's own signature still verifies.

### Global Access

```python
from ipacta.audit import get_audit_logger, log_audit_event

logger = get_audit_logger()         # Thread-safe singleton
log_audit_event("CERT_REQUEST", principal="admin", ...)  # Convenience
```

The singleton is lazy-initialized via a proxy (`_LazyAuditLogger`) to
avoid import-time side effects.

### Audit Logging Enhancements

- Audit log file ownership is corrected when created by root during
  installation.
- The audit logger fails fast on log-open failure and uses a sentinel
  for signing failure to avoid silent data loss.

## HSM Integration (`hsm.py`)

ipacta supports Hardware Security Modules via PKCS#11 for CA private
key protection. When enabled, the CA signing key never leaves the HSM.

### HSMConfig

```python
HSMConfig(config_dict={
    "pkcs11_library": "/usr/lib64/pkcs11/libsofthsm2.so",
    "slot_id": None,
    "slot_label": "IPA-CA",
    "token_pin": "secret",
    "key_label_prefix": "ipa-ca",
    "max_sessions": 10,
    "session_timeout": 300,
    "failover_enabled": False,
    "failover_library": None,
    "failover_slot_id": None,
})
```

`validate()` checks that required fields are set and the PKCS#11 library
exists.

### HSMKeyBackend

The main HSM operations class.

```python
backend = HSMKeyBackend(config)
```

**Key Generation:**

```python
pub, priv = backend.generate_key_pair(
    key_label="ipa-ca-signing",
    key_size=3072,
    key_type="RSA",   # or "EC"
)
```

- RSA: 2048+ bits, public exponent 65537.
- EC: P-256 (secp256r1) only for key **generation** -- `generate_key_pair()`
  hardcodes the P-256 curve parameters (a simplified implementation, per
  the code comment). Reading/parsing an *existing* EC key via
  `get_public_key()` supports P-256, P-384, and P-521.
- Keys are created as persistent token objects with appropriate PKCS#11
  attributes (CKA_TOKEN, CKA_SENSITIVE, CKA_EXTRACTABLE=False for private
  keys).

**Key Operations:**

| Method | Description |
|--------|-------------|
| `find_key(label)` | Find private key by label |
| `get_public_key(label)` | Extract public key (RSA or EC) |
| `sign(label, data, hash_algorithm)` | Sign data with the key |
| `delete_key(label)` | Delete both private and public keys |
| `list_keys()` | List all key labels on the token |

Signing mechanisms: `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`,
`CKM_SHA512_RSA_PKCS`.

### HSMPrivateKeyProxy

A proxy that implements the `cryptography` library's private key interface,
allowing HSM keys to be used transparently wherever a `cryptography`
private key is expected:

```python
proxy = HSMPrivateKeyProxy(hsm_backend, key_label)
proxy.sign(data, padding, algorithm)  # Signs via HSM
proxy.public_key()                    # Returns public key
proxy.key_size                        # Key size in bits
```

This proxy is used by `PythonCA` when HSM is enabled, so the signing code
does not need to know whether the key is in software or hardware.

### Session Management

`HSMSession` wraps a PKCS#11 session with context manager support:

```python
with HSMSession(pkcs11_lib, slot_id, pin) as session:
    # Perform operations
```

Sessions are opened with user login and closed with logout.

### Utility Functions

| Function | Description |
|----------|-------------|
| `get_hsm_backend(config)` | Get singleton HSM backend |
| `is_hsm_available()` | Check if PyKCS11 is installed |
| `list_pkcs11_slots(library)` | List all slots with details |
| `get_hsm_info(library, slot_id, slot_label)` | Detailed HSM/token info |

## Key Encryption (`key_encryption.py`)

Provides AES-256-GCM encryption for private keys stored on disk. Its
only current consumer is `key_escrow.py`'s `PythonKeyEscrowBackend`,
which uses it to encrypt the on-disk JSON files backing IPA Vault's
key escrow store (see "Key Escrow (`key_escrow.py`)" below). Sub-CA
keys do **not** go through this module -- they are stored in NSSDB or
an HSM (see `subca.py`).

### Cryptographic Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Algorithm | AES-256-GCM | Authenticated encryption |
| Key derivation | HKDF-Extract (HMAC-SHA256) | RFC 5869 section 2.2 |
| Key size | 256 bits | AES-256 |
| IV size | 96 bits | GCM standard |
| Salt size | 256 bits | Unique per encryption |

The master key is `os.urandom(32)` -- already full-entropy, so
PBKDF2 iteration cost is unnecessary. HKDF-Extract is the correct
primitive for deriving per-encryption keys from a high-entropy master
key: `PRK = HMAC-SHA256(salt, master_key)`.

Raises `KeyEncryptionError` on any encryption/decryption failure.

### KeyEncryption

```python
encryptor = KeyEncryption(master_key_path="/path/to/master.key")
```

**Master Key:** A 32-byte random key stored on disk with permissions
0o400 (owner read-only). Generated on first use if it does not exist.

**Encryption:**

```python
encrypted = encryptor.encrypt_key(private_key_pem)
```

Produces: `[salt (32B)][iv (12B)][ciphertext + GCM auth tag]`.

Each encryption uses a unique random salt and IV.

**Decryption:**

```python
pem = encryptor.decrypt_key(encrypted_data)
```

Extracts salt and IV from the header, derives the key via HKDF-Extract,
and decrypts. The GCM authentication tag detects any tampering.

### Convenience Functions

```python
from ipacta.key_encryption import encrypt_private_key, decrypt_private_key

encrypted = encrypt_private_key(pem_bytes)
pem_bytes = decrypt_private_key(encrypted)
```

Use a global singleton `KeyEncryption` instance.

## Key Escrow (`key_escrow.py`)

Provides a Python-native replacement for Dogtag's KRA key escrow
functionality, used by IPA Vault.

### PythonKeyEscrowBackend

```python
backend = PythonKeyEscrowBackend(storage_path="/var/lib/ipa/key_escrow")
```

**Transport Certificate:** A self-signed RSA-3072 certificate (SHA256,
2-year validity) generated on first use. RSA-3072 meets NIST
SP 800-131A Rev 2 security strength requirements. The short 2-year
validity stays within NIST key-lifetime limits. Used to wrap session
keys during key archival.

**Operations:**

| Method | Description |
|--------|-------------|
| `archive_encrypted_data(client_key_id, key_type, wrapped_data, wrapped_session_key, ...)` | Archive encrypted key material |
| `retrieve_key(key_id, wrapped_session_key)` | Retrieve archived key |
| `list_keys(client_key_id, status)` | List keys for a client |
| `modify_key_status(key_id, new_status)` | Change key status |
| `get_transport_cert()` | Get the transport certificate |

**Storage format:** JSON records encrypted at rest with AES-256-GCM via
`KeyEncryption`. Files on disk start with a magic header identifying the
encrypted format. Plaintext JSON is accepted as a migration path for
pre-encryption files.
Each record contains: `key_id`, `client_key_id`, `key_type`, `status`,
`wrapped_vault_data`, `wrapped_session_key`, `algorithm_oid`,
`nonce_iv`, timestamps.

**Key statuses:** `active`, `inactive`.

### PythonKeyEscrowClient

A client wrapper around `PythonKeyEscrowBackend` that provides the same
interface as Dogtag's key client:

```python
client = get_python_key_escrow_client()
client.archive_encrypted_data(...)
client.retrieve_key(key_id, wrapped_session_key)
```

Includes PKI compatibility stubs (`AccountClient.login()`/`logout()` are
no-ops) for code that expects the Dogtag client API.

### Algorithm OIDs

| OID | Algorithm |
|-----|-----------|
| `1.2.840.113549.3.7` | DES-EDE3-CBC (3DES) |
| `2.16.840.1.101.3.4.1.2` | AES-128-CBC |

## Key Recovery Authority (`kra.py`)

The KRA module provides a Python-native replacement for Dogtag's Key
Recovery Authority, coordinating transport key, storage key, and
key archival/recovery operations with HSM support.

### TransportKey

Manages the KRA transport certificate used to wrap/unwrap secrets
during archival and recovery.

```python
TransportKey(key_size=4096, storage_backend=None, kra_id="kra")
```

- The certificate is always stored in / loaded from NSSDB.
- Private key storage depends on HSM configuration (checked via LDAP):
  when HSM is enabled, the private key stays in the HSM and is accessed
  transparently through `HSMPrivateKeyProxy`; when HSM is disabled, the
  private key is generated in and extracted from NSSDB. In neither case
  is the private key ever written to disk as a PEM file -- it always
  stays in NSSDB or the HSM.

### StorageKey

Manages the KRA storage key used to encrypt secrets before storing
them in LDAP, providing defense-in-depth against LDAP compromise.

```python
StorageKey(key_size=4096, storage_backend=None, kra_id="kra")
```

Uses RSA asymmetric encryption (matching Dogtag KRA storage
certificate pattern). Supports HSM for key protection.

### KRA

The main orchestrator class.

```python
kra = KRA(ca_key=None, ca_cert=None, storage_backend=None, kra_id="kra")
```

| Method | Description |
|--------|-------------|
| `initialize(ca_key, ca_cert, storage_backend, force=False)` | Initialize transport and storage keys, generate certs |
| `archive_secret(encrypted_secret, owner, algorithm="AES", key_size=256)` | Archive a secret (encrypt with storage + transport keys) |
| `retrieve_secret(key_id, requester)` | Retrieve and decrypt an archived secret |
| `list_keys(owner=None, status=None)` | List keys with filters |
| `modify_key_status(key_id, status)` | Change key status (`active`, `inactive`, `archived`) |

**Singleton access:**

```python
from ipacta.kra import get_kra
kra = get_kra()
```
