# CA Engine

The CA engine is a three-layer stack: `PythonCA` provides the core
signing logic, `InternalCA` adds audit logging and principal tracking,
and `PythonCABackend` exposes the Dogtag-compatible interface that the
REST API and `ipaserver/plugins/dogtag.py` call.

## PythonCA (`ca.py`)

The minimal CA engine. Handles certificate signing, revocation, and CRL
generation with LDAP persistence but no audit logging.

### Construction

```python
PythonCA(
    ca_cert_path: str,
    ca_key_path: str,
    ca_id: str = "ipa",
    random_serial_numbers: bool = False,
    config=None,
)
```

On construction, `PythonCA` creates:
- A `CAStorageBackend` via the storage factory
- A `ProfileManager` for certificate profile handling
- A thread-safe request cache (`TTLCache` with maxsize=1000, ttl=3600s;
  falls back to unbounded dict if `cachetools` is not installed)

The CA certificate and private key are loaded lazily on first use via
double-checked locking (`_ensure_ca_loaded`). A public
`ensure_ca_loaded()` method is also available for callers that need to
preload the CA before making requests.

### Key Loading

Private key loading is conditional on HSM configuration:

- **HSM enabled:** Uses `HSMPrivateKeyProxy` with the configured PKCS#11
  backend. The token must be an external hardware token (not the internal
  NSS software token). The key label is `"{ca_id}_signing"`.
- **HSM disabled:** Extracts the private key from the NSS database using
  `NSSDatabase().extract_private_key()`. The nickname is
  `"caSigningCert cert-pki-ca"` for the main CA, or
  `"caSigningCert cert-pki-ca {ca_id}"` for sub-CAs.

### Certificate Issuance

Issuance is a two-step process:

**Step 1: Submit** (`submit_certificate_request`)

```python
request_id = ca.submit_certificate_request(csr_pem, profile="caIPAserviceCert")
```

- Parses and validates the CSR signature.
- Creates a `CertificateRequest` with an auto-generated request ID.
- Stores the request in the in-memory cache and persists to LDAP.

**Step 2: Sign** (`sign_certificate_request`)

```python
serial_number = ca.sign_certificate_request(request_id)
```

- Retrieves the request from cache or LDAP.
- Loads and validates the profile.
- Enters a retry loop (max 10 attempts) for serial number collisions:
  1. Allocates the next serial number from LDAP.
  2. Builds the certificate:
     - Subject from CSR
     - Issuer from CA certificate
     - Validity from profile (clamped to CA's `notAfter` per RFC 5280)
     - Extensions from profile (simplified plugin-based application --
       see InternalCA for full policy chain execution)
  3. Signs with the CA private key (algorithm matching the CA certificate).
  4. Stores in LDAP with `allow_update=False`.
  5. On `DuplicateEntry` or `MidairCollision`, retries with a new serial.
- Updates the request status to `complete` with the serial number.

### Revocation

| Method | Effect |
|--------|--------|
| `revoke_certificate(serial, reason)` | Revoke with the given reason |
| `put_certificate_on_hold(serial)` | Temporary suspension (Certificate Hold) |
| `take_certificate_off_hold(serial)` | Release from hold back to VALID |

All methods retrieve the `CertificateRecord` from LDAP, update its
lifecycle, and store it back. After each status change,
`_invalidate_ocsp_cache(serial_number)` is called to remove stale
OCSP cache entries for the affected serial number. The OCSP manager is
imported lazily to avoid circular imports.

> **Note:** OCSP cache invalidation is specific to the base `PythonCA`
> implementation. `InternalCA` overrides `revoke_certificate` and
> `take_certificate_off_hold` with audit-logging versions that do
> **not** call `_invalidate_ocsp_cache`. `InternalCA` has no override
> of `put_certificate_on_hold` at all -- it inherits the base
> `PythonCA` version verbatim (see the InternalCA section below).

### CRL Generation

```python
crl = ca.generate_crl()
```

1. Ensures the CA is loaded.
2. Gets the next CRL number from LDAP.
3. Builds the CRL:
   - Issuer from CA certificate subject.
   - `lastUpdate` = now.
   - `nextUpdate` = now + `crl_update_interval` + `crl_next_update_grace_period`.
   - CRL Number extension (RFC 5280 section 5.2.3).
   - Authority Key Identifier extension (RFC 5280 section 5.2.1).
4. Retrieves revoked certificates via `storage.get_revoked_for_crl()`,
   which returns a generator of lightweight `(serial_number, revoked_at,
   reason_int)` tuples -- no full certificate DER is loaded, avoiding
   memory pressure on large deployments.
5. Adds each revoked certificate with revocation date and reason flags.
6. Signs with the CA private key.

CRL timing parameters are cached via `_get_crl_timing()` (thread-safe
with double-checked locking) to avoid re-reading config on every CRL
generation.

**CRL timing configuration:**

| Config Key | Default | Description |
|------------|---------|-------------|
| `ca.crl_update_interval` | `240` | Update interval in minutes |
| `ca.crl_next_update_grace_period` | `0` | Grace period in minutes |
| `ca.crl_include_expired_certs` | `false` | Include expired certs in CRL |

### Other Operations

| Method | Description |
|--------|-------------|
| `get_certificate(serial)` | Retrieve certificate from LDAP |
| `find_certificates(criteria)` | Search certificates with filters |
| `get_request_status(request_id)` | Get request (cache then LDAP fallback) |
| `shutdown()` | Stop profile monitor, cleanup resources |

## InternalCA (`ca_internal.py`)

Extends `PythonCA` for production use. Adds audit logging, principal
tracking, and sub-CA delegation.

### Construction

Same parameters as `PythonCA`. Additionally:

1. Calls `storage.initialize_schema()` to create the LDAP directory
   structure.
2. Creates a `SubCAManager` for lightweight CA delegation.
3. Starts the profile change monitor for multi-master hot-reload.

### Audit Integration

Most certificate operations log to the `AuditLogger`:

| Operation | Audit Method | Extra Fields |
|-----------|-------------|--------------|
| Submit request | `log_certificate_request` | request_id, profile, subject |
| Sign certificate | `log_certificate_issued` | request_id, serial, subject, signing_algorithm |
| Revoke | `log_certificate_revoked` | serial, reason |
| Unrevoke | `log_certificate_unrevoked` | serial |
| Generate CRL | `log_crl_generation` | crl_number, num_revoked |

All audit methods receive `principal` (defaults to `"System"`) and
`outcome` (`SUCCESS` or `FAILURE`).

**Exception:** `put_certificate_on_hold()` is not overridden by
`InternalCA` -- it uses the base `PythonCA` implementation, which does
no audit logging at all.

### Principal Tracking

Most mutating methods accept an additional `principal` parameter:

```python
ca.submit_certificate_request(csr_pem, profile, principal="admin@EXAMPLE.COM")
ca.sign_certificate_request(request_id, principal="admin@EXAMPLE.COM")
ca.revoke_certificate(serial, reason, principal="admin@EXAMPLE.COM")
```

The principal is recorded in audit logs and in the certificate lifecycle
state transition history.

**Exception:** `put_certificate_on_hold(serial_number)` has no
`principal` parameter -- it inherits the base `PythonCA` signature
unchanged, since `InternalCA` does not override this method.

### Sub-CA Delegation

When signing a certificate request that targets a sub-CA:

1. The `ca_id` stored on the request is checked via `is_main_ca_id()`.
2. If not the main CA, `subca_manager.get_subca(ca_id)` loads the sub-CA's
   certificate and key.
3. The sub-CA's cert and key are used for signing instead of the main CA's.
4. Signing never falls back to the main CA on error -- it always aborts
   by re-raising: `NotFound` if the sub-CA does not exist,
   `CertificateOperationError` if the sub-CA has no certificate/key, and
   any other exception (e.g. an LDAP timeout or key decryption failure)
   is wrapped in `CertificateOperationError` and raised. This is
   intentional: a certificate must never be issued under the wrong
   issuer.

### Profile Policy Chain

For profiles that parse as `Profile` objects (Dogtag-format `.cfg` files),
`InternalCA` executes the full policy chain via `_execute_policy_chain()`:

1. For each `PolicyRule` in the profile (sorted by number):
   a. Apply the default (populates the certificate builder and context).
   b. Validate with the constraint (checks the result).
2. If any constraint returns errors, signing is rejected with a
   `ValueError`.
3. The signing algorithm is taken from the context (set by
   `SigningAlgDefault`) or from the config default.

## PythonCABackend (`backend.py`)

The top-level entry point that `dogtag.py` and the REST API call.
Implements a Dogtag-compatible interface with dict-based return values.

### Construction

```python
PythonCABackend(config=None)
```

1. Loads config if not provided (`load_config()`).
2. Sets the global config singleton (`set_global_config()`).
3. Validates the configured hostname against the system FQDN (warning on
   mismatch, not fatal).
4. Creates an `InternalCA` instance.
5. Creates a `ProfileManager`.

### Singleton Access

```python
backend = get_python_ca_backend()
```

Thread-safe singleton (lock-protected): the lock is acquired
unconditionally, then the singleton is created if not already set.

### Lazy-Initialized Subsystems

| Property | Type | Created With |
|----------|------|-------------|
| `acme_server` | `ACMEServer` | `ACMEServer(ca, base_url, config)` |
| `acme_state` | `ACMEStateManager` | `ACMEStateManager(config)` |
| `pruning_manager` | `PruningManager` | `PruningManager(config, ca.storage)` |

All initialized under a thread lock on first access.

### Backend Interface

**Certificate Request and Issuance:**

```python
result = backend.request_certificate(csr, profile_id="caIPAserviceCert", ca_id="ipa")
```

Submits the CSR, immediately signs it, retrieves the certificate, and
returns a dict:

```python
{
    "request_id": "42",
    "serial_number": "0x2a",       # Dogtag hex format
    "status": "complete",
    "certificate": "MIIBxjCC...",  # base64 DER
    "subject": "CN=ipa.example.com,O=EXAMPLE.COM",
    "issuer": "CN=Certificate Authority,O=EXAMPLE.COM",
}
```

**Certificate Retrieval:**

```python
result = backend.get_certificate(serial_number)  # accepts int, decimal str, or "0x..." hex
```

Returns PEM with CRLF line endings (Dogtag compatibility).

**Certificate Search:**

```python
result = backend.find_certificates(criteria)
```

Returns entries with both ipacta and Dogtag field names (`SubjectDN`,
`IssuerDN`, `Status`, `NotValidBefore`, `NotValidAfter` in millisecond
timestamps).

**Revocation:**

```python
backend.revoke_certificate(serial_number, revocation_reason=0)
backend.take_certificate_off_hold(serial_number)
```

**CRL Publishing:**

```python
backend.update_crl()
```

1. Calls `ca.generate_crl()`.
2. Writes DER to `{IPACTA_CERTS_DIR}/ca_crl.der`.
3. Publishes to `{IPA_PKI_PUBLISH_DIR}` with a timestamped filename
   (`MasterCRL-YYYYMMDD-HHMMSS-microseconds.der`) and an atomic symlink
   `MasterCRL.bin`.
4. Sets file permissions to 0o644.

**CA Bootstrap:**

```python
result = backend.create_ca_certificate(subject, algorithm="SHA256withRSA")
```

Generates a self-signed CA certificate and RSA private key:
- Key size from config (`ca.ca_signing_key_size`, default 3072).
- Validity: 10 years.
- Extensions: BasicConstraints (CA=true), CA KeyUsage, SKI, AKI.
- Returns PEM certificate, PEM private key (PKCS8 unencrypted), serial.

**System Information:**

```python
backend.get_ca_info()          # CA status, subject, serial, validity
backend.get_certificate_chain() # PEM certificate chain
```

Both return placeholder values during installation when the CA is not yet
configured.

### Dogtag Compatibility

The backend ensures compatibility with `ipaserver/plugins/dogtag.py`:

- Serial numbers are formatted as `"0x{hex}"` (lowercase, 0x prefix).
- PEM certificates use CRLF line endings.
- Search results include both ipacta names (`subject`, `status`) and
  Dogtag names (`SubjectDN`, `Status`, `NotValidBefore`).
- Timestamps in search results include millisecond epoch format.

## Serial Number Allocation

All layers delegate to `storage.get_next_serial_number()`:

- **Sequential:** Monotonically incrementing counter in LDAP.
- **Random (RSNv3):** 128-bit random numbers with MSB set, up to 100
  collision recovery attempts.

Allocation is thread-safe (`threading.Lock` in the storage backend).
The signing retry loop (max 10 attempts) handles the race condition where
two concurrent requests allocate the same serial.
