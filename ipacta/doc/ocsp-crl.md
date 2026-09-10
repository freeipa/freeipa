# OCSP Responder and CRL Generation

ipacta provides an Online Certificate Status Protocol (OCSP) responder
and Certificate Revocation List (CRL) generation for certificate
validation.

## OCSP Responder (`ocsp.py`)

The OCSP responder answers real-time certificate status queries per
RFC 6960. It generates and caches signed OCSP responses.

### OCSPResponder

```python
OCSPResponder(
    ca,
    ocsp_cert_path: str = None,
    ocsp_key_path: str = None,
    cache_timeout: int = 300,    # 5 minutes
)
```

The responder uses a dedicated OCSP signing certificate (separate from
the CA signing key) for response signing.

### OCSP Signing Certificate

On initialization, the responder loads or generates an OCSP signing
certificate:

- **Loading:** Reads the certificate and key from the configured paths.
- **Generation:** If no certificate exists, generates one:
  - RSA key with size from config (`ocsp_signing_key_size`, default 3072).
  - Subject: `"OCSP Responder - {CA_CN}"`.
  - Validity: 1 year.
  - Extensions:
    - Extended Key Usage: OCSP Signing (critical).
    - Subject Key Identifier.
    - Authority Key Identifier.
  - Signed with the OCSP signing key (dedicated key, not the CA key).

The OCSP certificate and key are stored on the filesystem only (never in
LDAP).

### Response Generation

```python
response_der = responder.create_response(request_der)
```

Processing flow:

1. Parse the DER-encoded OCSP request.
2. Extract the certificate serial number from the request.
3. Extract the nonce extension if present (replay protection).
4. Check the response cache (keyed on serial + nonce hash).
5. On cache miss:
   a. Look up the certificate status from the CA:
      - `GOOD` -- certificate is valid.
      - `REVOKED` -- certificate is revoked (includes revocation time and
        reason).
      - `UNKNOWN` -- certificate not found.
   b. Build the OCSP response:
      - `thisUpdate` = now for `GOOD`/`UNKNOWN` status; for `REVOKED`
        status, `thisUpdate` = the certificate's recorded revocation
        time if available, otherwise now.
      - `nextUpdate` = now + cache_timeout.
      - Echo the nonce back if present.
   c. Sign with the OCSP signing key.
   d. Cache the response.
6. Return the DER-encoded response.

### Response Cache

The cache is a `cachetools.TTLCache` (`self.response_cache`) protected
by a thread lock:

| Parameter | Value |
|-----------|-------|
| Max size | 1000 entries |
| TTL | Configurable (default 300s / 5 minutes) |
| Key | `SHA256("{serial}")`, or `SHA256("{serial}:{nonce_hex}")` when the request carries a nonce |
| Eviction | Handled internally by `TTLCache`: entries expire once their TTL elapses, and once `maxsize` is reached the least-recently-used entry is evicted to make room |

A secondary index (`_serial_to_keys` dict) maps serial numbers to cache
keys, enabling efficient per-serial invalidation without scanning the
full cache.

**Cache operations:**

| Method | Description |
|--------|-------------|
| `clear_cache()` | Clear all cached responses and the secondary index |
| `invalidate_serial(serial_number)` | Remove all cache entries for a specific serial (via `_serial_to_keys`) |
| `get_cache_stats()` | Return `total_entries`, `cache_maxsize`, `cache_timeout` |
| `_create_error_response(status)` | Generate an RFC 6960 error response (internal error, try later, etc.) |

### OCSPResponderManager

Singleton manager for multiple OCSP responders (one per CA/sub-CA):

```python
manager = get_ocsp_manager()
responder = manager.get_responder(ca, ca_id="ipa")
```

Thread-safe creation and retrieval of per-CA responders.

| Method | Description |
|--------|-------------|
| `get_responder(ca, ca_id)` | Get or create responder for a CA |
| `invalidate_serial(serial_number)` | Propagate serial invalidation to all responders |
| `clear_all_caches()` | Clear caches for all responders |
| `get_all_stats()` | Aggregate stats for all responders |

### REST API Integration

The OCSP responder is accessed through these REST endpoints:

- `POST /ca/ocsp` -- DER-encoded OCSP request in body.
- `GET /ca/ocsp/{base64_request}` -- Base64-encoded request in URL
  (max 8192 bytes).
- `POST /ca/ee/ca/ocsp` -- Legacy endpoint (same behavior).

Response content type: `application/ocsp-response`.

Additional management endpoints:

- `GET /ca/rest/ocsp/stats` -- Cache and request statistics.
- `POST /ca/rest/ocsp/cache/clear` -- Clear the response cache.
- `GET /ca/rest/ocsp/cert` -- Get the OCSP signing certificate.
- `POST /ca/rest/ocsp/cert/renew` -- Regenerate the OCSP certificate.
- `GET /ca/rest/ocsp/responders` -- List all responders.

## CRL Generation

CRL generation is handled by `PythonCA.generate_crl()` (see
[CA Engine](ca-engine.md) for full details) and published by
`PythonCABackend.update_crl()`.

### Generation Process

1. Get the next CRL number from LDAP (monotonically incrementing).
2. Build the CRL with:
   - Issuer from CA certificate subject.
   - `lastUpdate` = current time.
   - `nextUpdate` = current time + update interval + grace period.
   - CRL Number extension (RFC 5280 section 5.2.3).
   - Authority Key Identifier extension (RFC 5280 section 5.2.1).
3. Query revoked certificates from LDAP via `get_revoked_for_crl()`,
   which returns a generator of lightweight `(serial_number, revoked_at,
   reason_int)` tuples (no full certificate DER loaded).
4. Add each revoked certificate with:
   - Serial number.
   - Revocation date.
   - CRL Reason extension (if reason is not UNSPECIFIED).
5. Sign the CRL with the CA's private key.
6. Store in LDAP via `CRLStorage`.

### Publishing

`PythonCABackend.update_crl()` publishes the generated CRL:

1. Writes the DER-encoded CRL to `{IPACTA_CERTS_DIR}/ca_crl.der`.
2. Creates a timestamped copy in the IPA publish directory:
   `{IPA_PKI_PUBLISH_DIR}/MasterCRL-{YYYYMMDD}-{HHMMSS}-{us}.der`.
3. Creates an atomic symlink `MasterCRL.bin` pointing to the timestamped
   file (temp symlink + rename for atomicity).
4. Sets file permissions to 0o644 (world-readable for HTTP serving).

The published CRL is served by Apache at the URL configured in the
CRL Distribution Points extension of issued certificates (typically
`http://ipa-ca.{domain}/ipa/crl/MasterCRL.bin`).

### CRL Configuration

| Config Key | Default | Description |
|------------|---------|-------------|
| `ca.crl_update_interval` | `240` | Update interval in minutes (4 hours) |
| `ca.crl_next_update_grace_period` | `0` | Grace period added to nextUpdate |

There is no scheduled/daily CRL regeneration mechanism, no separate
CRL signing algorithm setting, and no config option to include expired
certificates:

- CRL signature algorithm is not configurable — it is derived from
  the CA certificate's own signature algorithm via
  `x509_utils.get_certificate_signature_algorithm()`.
- `generate_crl()` was refactored to use a lightweight generator
  (`get_revoked_for_crl()`) that does not have certificate expiry data
  available, so there is no expired-certificate inclusion option.

### CRL Storage

CRLs are stored in LDAP under `ou=crlIssuingPoints,ou=ca,o=ipaca`.
The `CRLStorage` module provides:

| Method | Description |
|--------|-------------|
| `store_crl(name, data, number, this_update, next_update, size)` | Store CRL |
| `get_crl(name)` | Retrieve DER-encoded CRL |
| `get_crl_info(name)` | Get CRL metadata (cached, TTL=300s) |
| `list_crl_issuing_points()` | List CRL names |
| `delete_crl_issuing_point(name)` | Delete a CRL issuing point |

### REST API Endpoints

- `GET /ca/ee/ca/getCRL` -- Download the current CRL (DER,
  `application/pkix-crl`).
- `POST /ca/rest/agent/crl` -- Force CRL regeneration (agent auth).
- `GET /ca/rest/crl/issuingpoints` -- List CRL issuing points.
- `GET /ca/rest/crl/issuingpoints/{name}` -- Get issuing point info.
- `GET /ca/rest/certs/chain` -- Get the CA certificate chain.

### Initial CRL

During installation, `ServiceMgmt._generate_initial_crl()` generates the
first CRL immediately after the CA service starts, ensuring a valid CRL
is available from the moment the CA is operational.
