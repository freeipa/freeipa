# ipacta REST API Reference

ipacta exposes a Dogtag-compatible REST API over HTTPS. FreeIPA's existing
`ipaserver/plugins/dogtag.py` client works without modification.

The API is served by Flask with automatic blueprint discovery. All endpoints
support both the `/ca/rest/` (v1) and `/ca/v2/` (v2) URL prefixes unless
noted otherwise.

## Authentication

### Client Certificate (mTLS)

Endpoints marked **Agent auth** require a client certificate with
`CN=IPA RA` in the subject DN. The certificate is extracted from the
WSGI environment variables set by the Apache reverse proxy:

- `SSL_CLIENT_VERIFY` -- must be `SUCCESS`
- `SSL_CLIENT_S_DN` -- must contain `CN=IPA RA`

**Security:** Only the bare `SSL_*` environment keys are trusted. The
`HTTP_SSL_*` variants (which come from client-supplied HTTP headers) are
explicitly ignored to prevent header injection attacks. There is no
localhost trust exception -- same security model as Dogtag PKI.

### Session Cookies

After a successful `/account/login`, a `JSESSIONID` cookie is issued
(HTTPOnly, Secure, SameSite=Strict, 30-minute expiry). This is provided
for legacy Dogtag client compatibility.

### ACME Authentication

ACME endpoints use JWS nonce-based authentication per RFC 8555. A
`Replay-Nonce` header is included in all ACME responses.

## Error Responses

All errors follow the PKI exception format:

```json
{
  "ClassName": "com.netscape.certsrv.base.PKIException",
  "Code": 400,
  "Message": "Error description",
  "Attributes": {
    "Attribute": [
      {"name": "error", "value": "ErrorType"}
    ]
  }
}
```

Standard HTTP status codes: 200 OK, 201 Created, 204 No Content,
400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found,
429 Too Many Requests, 501 Not Implemented, 503 Service Unavailable.

---

## 1. Health and Status

### GET /pki/rest/info

Get PKI version information (Dogtag compatibility).

- **Auth:** None
- **Response:**
  ```json
  {"Version": "11.5.0", "Attributes": {...}}
  ```

Also available at `/pki/v2/info`.

### GET /ca/rest/info

Get CA information and status.

- **Auth:** None
- **Response:** CA ID, subject DN, serial number, validity dates, status.

### GET /ca/admin/ca/getStatus

Get CA status (plain text).

- **Auth:** None
- **Response:** `text/plain` -- `status=running`

Also available at `/ca/ee/ca/getStatus`.

---

## 2. Account Management

### GET|POST /ca/rest/account/login

Authenticate with client certificate and obtain a session cookie.

- **Auth:** Client certificate (CN=IPA RA)
- **Response:**
  ```json
  {"Status": "success"}
  ```
  Sets `JSESSIONID` cookie (30-minute expiry).

Also available at `/ca/v2/account/login`.

### GET|POST /ca/rest/account/logout

Clear session cookie.

- **Auth:** None
- **Response:** v1: `{"Status": "success"}`, v2: 204 No Content.

### KRA Account Endpoints

Same login/logout pattern at `/kra/rest/account/login` and
`/kra/rest/account/logout`.

---

## 3. Security Domain

### GET /ca/rest/securityDomain/domainInfo

Get security domain information including all subsystems and hosts.

- **Auth:** None
- **Response:** Domain info with subsystem details (hostname, ports, etc.).

### DELETE /ca/rest/securityDomain/hosts/{host_id}

Remove a host from the security domain.

- **Auth:** Agent auth
- **Path:** `host_id` -- format `"SUBSYSTEM HOSTNAME PORT"` (URL-encoded).
  Subsystem must be one of: CA, KRA, OCSP, TKS, TPS.
- **Response:**
  ```json
  {"Status": "SUCCESS", "Message": "..."}
  ```

---

## 4. Certificate Requests

### POST /ca/rest/certrequests

Submit a certificate signing request.

- **Auth:** None
- **Request Body:**
  ```json
  {
    "ProfileID": "caIPAserviceCert",
    "AuthorityID": "host-authority",
    "Input": [
      {
        "id": "i1",
        "ClassID": "certReqInputImpl",
        "Attribute": [
          {"name": "cert_request_type", "value": "pkcs10"},
          {"name": "cert_request", "value": "-----BEGIN CERTIFICATE REQUEST-----\n..."}
        ]
      }
    ]
  }
  ```
  The CSR can also be passed as a top-level `pkcs10` field. PEM and
  raw base64 formats are both accepted.
- **Response (201):**
  ```json
  {
    "entries": [
      {
        "requestId": "42",
        "requestURL": "/ca/rest/certrequests/42",
        "requestStatus": "complete",
        "certId": "0x2a",
        "certificate": "-----BEGIN CERTIFICATE-----\n..."
      }
    ]
  }
  ```

Also available at `/ca/rest/agent/certrequests`.

### GET /ca/rest/certrequests/{request_id}

Get the status of a certificate request.

- **Auth:** None
- **Path:** `request_id` -- integer or string.
- **Response:** Request status, type, and associated certificate ID.

### DELETE /ca/rest/certrequests/{request_id}

Delete a completed or rejected request (used by the pruning job).

- **Auth:** Agent auth

### GET /ca/rest/certrequests/profiles/{profile_id}

Get the enrollment template for a profile.

- **Auth:** None
- **Path:** `profile_id` -- alphanumeric, hyphens, underscores.
- **Response:** Enrollment template with input fields and configuration.

---

## 5. Certificate Management

### GET /ca/rest/certs/{serial_number}

Get a certificate by serial number.

- **Auth:** None
- **Path:** `serial_number` -- hex (`0x1a2b`) or decimal.
- **Response:**
  ```json
  {
    "id": "0x1a2b",
    "SerialNumber": "0x1a2b",
    "Status": "VALID",
    "SubjectDN": "CN=ipa.example.com,O=EXAMPLE.COM",
    "IssuerDN": "CN=Certificate Authority,O=EXAMPLE.COM",
    "Encoded": "-----BEGIN CERTIFICATE-----\n...",
    "RevokedAt": null,
    "RevocationReason": null
  }
  ```

Agent-only variant at `/ca/rest/agent/certs/{serial_number}`.

### GET|POST /ca/rest/certs/search

Search certificates with filters.

- **Auth:** None (public) or Agent auth (agent search endpoint)
- **Query Parameters:**

  | Parameter | Description |
  |-----------|-------------|
  | `size`, `start` | Pagination |
  | `maxResults`, `maxTime` | Search limits |
  | `serialFrom`, `serialTo` | Serial number range |
  | `commonName` | Subject CN filter |
  | `eMail` | Email filter |
  | `userID` | User ID filter |
  | `orgUnit`, `org`, `locality`, `state`, `country` | Subject DN components |
  | `issuerDN` | Issuer DN filter |
  | `status` | Certificate status |
  | `revocationReason` | Revocation reason filter |
  | `matchExactly` | Exact match mode |
  | `issuedOnFrom`, `issuedOnTo` | Issuance date range |
  | `revokedOnFrom`, `revokedOnTo` | Revocation date range |
  | `validNotBeforeFrom`, `validNotBeforeTo` | NotBefore date range |
  | `validNotAfterFrom`, `validNotAfterTo` | NotAfter date range |
  | `certTypeSSLServer`, `certTypeSSLClient`, `certTypeSecureEmail` | Certificate type filters |

- **Response:**
  ```json
  {"entries": [...], "total": 42}
  ```

Also available at `/ca/rest/certs` (GET/POST) and
`/ca/v2/agent/certs/search`.

### POST /ca/rest/agent/certs/{serial_number}/revoke

Revoke a certificate.

- **Auth:** Agent auth
- **Path:** `serial_number`
- **Request Body:**
  ```json
  {"Reason": "Key_Compromise"}
  ```
  Reason can be a string name or integer code:

  | Code | Name |
  |------|------|
  | 0 | Unspecified |
  | 1 | Key_Compromise |
  | 2 | CA_Compromise |
  | 3 | Affiliation_Changed |
  | 4 | Superseded |
  | 5 | Cessation_of_Operation |
  | 6 | Certificate_Hold |
  | 8 | Remove_from_CRL |
  | 9 | Privilege_Withdrawn |
  | 10 | AA_Compromise |

- **Response:** Dogtag-compatible CertRequestInfo.

Also available at `/ca/rest/certs/{serial_number}/revoke`.

### POST /ca/rest/agent/certs/{serial_number}/unrevoke

Remove a certificate from hold (unrevoke).

- **Auth:** Agent auth
- **Response:** Success with request URL.

Also available at `/ca/rest/agent/certs/{serial_number}/revoke-ca`.

### POST /ca/rest/certs/bulk-revoke

Revoke multiple certificates in a single request.

- **Auth:** Agent auth
- **Request Body:**
  ```json
  {
    "serial_numbers": [1, 2, 3],
    "revocation_reason": 0
  }
  ```
- **Response:**
  ```json
  {
    "successful": [...],
    "failed": [...],
    "total": 3,
    "success_count": 2,
    "failure_count": 1
  }
  ```

### GET /ca/rest/certs/revoked

List revoked certificates.

- **Auth:** None
- **Query:** `limit` (default 1000), `offset` (default 0).
- **Response:** `{"entries": [...], "limit": N, "offset": N}`

### GET /ca/ee/ca/displayBySerial

Display certificate by serial (legacy endpoint).

- **Auth:** None
- **Query:** `serialNumber` (hex, e.g. `0x0F4242`).
- **Response:** PEM-encoded certificate (`text/plain`).

### GET /ca/rest/certs/chain

Get the CA certificate chain.

- **Auth:** None
- **Query:** `format=pem` (default).
- **Response:** PEM certificate chain (`application/x-pem-file`).

Also available at `/ca/ee/ca/getCertChain`.

---

## 6. Certificate Profiles

### GET /ca/rest/profiles

List all certificate profiles.

- **Auth:** None
- **Response:** `{"entries": [...], "total": N}`

Legacy XML: `GET /ca/ee/ca/profileList?xml=true`.

### GET /ca/rest/profiles/{profile_id}

Get profile details.

- **Auth:** None
- **Response:** Profile object with id, name, enabled status, description.

### POST /ca/rest/profiles

Create a new profile.

- **Auth:** Agent auth
- **Request Body (JSON):**
  ```json
  {"profileId": "myProfile", "profileData": "..."}
  ```
  Or raw `text/plain` with .cfg file content (at `/ca/rest/profiles/raw`).
- **Response (201):** Created profile object.

### POST|PUT /ca/rest/profiles/{profile_id}

Update a profile.

- **Auth:** Agent auth
- **Query:** `action=enable` or `action=disable` (optional).
- **Request:** JSON or raw .cfg content.
- **Response:** Updated profile object.

### DELETE /ca/rest/profiles/{profile_id}

Delete a profile.

- **Auth:** Agent auth
- **Response:** Success message.

### POST /ca/rest/profiles/{profile_id}/enable

Enable a profile.

- **Auth:** Agent auth
- **Response:** Full profile object.

### POST /ca/rest/profiles/{profile_id}/disable

Disable a profile.

- **Auth:** Agent auth
- **Response:** Full profile object.

### GET /ca/rest/profiles/{profile_id}/raw

Get profile in .cfg format.

- **Auth:** None
- **Response:** `text/plain` -- profile .cfg file content.

### PUT /ca/rest/profiles/{profile_id}/raw

Update profile from .cfg format.

- **Auth:** Agent auth
- **Request:** `text/plain` with .cfg content.
- **Response:** Updated .cfg content.

### Legacy Profile Submission

```
POST /ca/ee/ca/profileSubmitSSLClient
GET  /ca/ee/ca/profileSubmitSSLClient
```

For certmonger compatibility. Accepts form parameters:

| Parameter | Description |
|-----------|-------------|
| `cert_request` | PEM-encoded CSR |
| `cert_request_type` | Accepted for Dogtag client compatibility but currently ignored -- the request type is not read or validated by the current implementation |
| `profileId` | Profile to use (default: `caIPAserviceCert`) |
| `xmlOutput` | `true` for XML response (default) |

---

## 7. CRL and OCSP

### GET /ca/ee/ca/getCRL

Get the current Certificate Revocation List.

- **Auth:** None
- **Response:** DER-encoded CRL (`application/pkix-crl`).

Also available at `/ca/rest/crl`.

### POST /ca/rest/agent/crl

Force CRL regeneration.

- **Auth:** Agent auth
- **Response:** Success message.

Legacy: `GET /ca/agent/ca/updateCRL?crlIssuingPoint=MasterCRL&xml=true`.

### GET /ca/rest/crl/issuingpoints

List CRL issuing points.

- **Auth:** None
- **Response:** `{"entries": [...], "total": N}`

### GET /ca/rest/crl/issuingpoints/{crl_name}

Get CRL issuing point info.

- **Auth:** None
- **Response:** CRL metadata (number, size, issue/update times).

### DELETE /ca/rest/crl/issuingpoints/{crl_name}

Delete a CRL issuing point.

- **Auth:** Agent auth

### POST /ca/ocsp

OCSP request (POST).

- **Auth:** None
- **Request:** DER-encoded OCSP request body.
- **Response:** DER-encoded OCSP response (`application/ocsp-response`).

### GET /ca/ocsp/{ocsp_data}

OCSP request (GET).

- **Auth:** None
- **Path:** Base64-encoded OCSP request (max 8192 bytes).
- **Response:** DER-encoded OCSP response.

Also available at `/ca/ee/ca/ocsp` (GET/POST).

### GET /ca/rest/ocsp/stats

Get OCSP statistics (request counts, cache info).

- **Auth:** Agent auth

### POST /ca/rest/ocsp/cache/clear

Clear the OCSP response cache.

- **Auth:** Agent auth

### GET /ca/rest/ocsp/cert

Get the OCSP signing certificate.

- **Auth:** None
- **Query:** `ca_id` (default: `ipa`).
- **Response:** Certificate metadata and PEM.

### POST /ca/rest/ocsp/cert/renew

Renew the OCSP signing certificate.

- **Auth:** Agent auth
- **Query:** `ca_id` (default: `ipa`).

### GET /ca/rest/ocsp/responders

List OCSP responders.

- **Auth:** Agent auth
- **Response:** List of responders with CA IDs and status.

---

## 8. Pruning

### GET /ca/rest/pruning/config

Get pruning configuration.

- **Auth:** None
- **Response:** Retention times, search limits, enabled status.

### POST|PUT /ca/rest/pruning/config

Update pruning configuration.

- **Auth:** Agent auth
- **Request Body:**
  ```json
  {
    "certRetentionTime": 30,
    "certRetentionUnit": "day",
    "certSearchSizeLimit": 1000,
    "certSearchTimeLimit": 0,
    "requestRetentionTime": 30,
    "requestRetentionUnit": "day",
    "requestSearchSizeLimit": 1000,
    "requestSearchTimeLimit": 0,
    "cronSchedule": "0 1 * * *"
  }
  ```
  Valid retention units: `minute`, `hour`, `day`, `year`.

### POST /ca/rest/pruning/enable

Enable automatic pruning.

- **Auth:** Agent auth

### POST /ca/rest/pruning/disable

Disable automatic pruning.

- **Auth:** Agent auth

### POST /ca/rest/pruning/run

Trigger an immediate pruning job.

- **Auth:** Agent auth
- **Response:**
  ```json
  {
    "certificates_deleted": 5,
    "requests_deleted": 3,
    "errors": []
  }
  ```

---

## 9. Lightweight CAs (Authorities)

### GET /ca/rest/authorities

List all certificate authorities.

- **Auth:** None
- **Response:** Array of authority objects with id, dn, issuerDN, enabled,
  isHostAuthority, serial.

Also available at `/ca/rest/ca/authorities`.

### GET /ca/rest/authorities/{authority_id}

Get authority details.

- **Auth:** None
- **Path:** `authority_id` -- `"host-authority"` for the root CA, or a sub-CA ID.
- **Response:** Authority details including certificate validity dates.

### POST /ca/rest/authorities

Create a lightweight CA.

- **Auth:** Agent auth
- **Request Body:**
  ```json
  {
    "dn": "CN=SubCA,O=EXAMPLE.COM",
    "id": "subca-1",
    "description": "Sub-CA for department X",
    "parentID": "host-authority"
  }
  ```
- **Response (201):** Created authority object.

### GET /ca/rest/authorities/{authority_id}/cert

Get the authority's certificate.

- **Auth:** None
- **Response:** PEM-encoded certificate.

### GET /ca/rest/authorities/{authority_id}/chain

Get the authority's certificate chain.

- **Auth:** None
- **Response:** PKCS#7 chain in PEM format.

### POST /ca/rest/authorities/{authority_id}/enable

Enable an authority.

- **Auth:** Agent auth

### POST /ca/rest/authorities/{authority_id}/disable

Disable an authority. Cannot disable `host-authority`.

- **Auth:** Agent auth

### DELETE /ca/rest/authorities/{authority_id}

Delete an authority. Cannot delete `host-authority`.

- **Auth:** Agent auth

---

## 10. ACME (RFC 8555)

### GET /acme/directory

ACME server directory.

- **Auth:** None
- **Response:** Directory object with endpoint URLs.
- **Status:** 503 if ACME is disabled.

### HEAD|GET /acme/new-nonce

Generate an ACME nonce for replay protection.

- **Auth:** None
- **Response:** `Replay-Nonce` header.

### POST /acme/{endpoint}

Generic ACME endpoint handler.

- **Auth:** JWS nonce-based (RFC 8555)
- **Path:** `endpoint` -- `new-account`, `new-order`, `finalize`, etc.
- **Request:** JWS in flattened format:
  ```json
  {
    "protected": "base64url-encoded-header",
    "payload": "base64url-encoded-payload",
    "signature": "base64url-signature"
  }
  ```
- **Response:** 200 (existing account) or 201 (new resource). `Location`
  header with resource URL.

### POST /acme/enable

Enable the ACME service (Dogtag compatibility).

- **Auth:** Agent auth

### POST /acme/disable

Disable the ACME service.

- **Auth:** Agent auth

---

## 11. Key Recovery Authority (KRA)

### GET /kra/rest/info

Get KRA version and status.

- **Auth:** None

### GET /kra/admin/kra/getStatus

Get KRA status (plain text).

- **Auth:** None
- **Response:** `text/plain` -- `status=running`

### POST /kra/rest/agent/keyrequests

Submit a key archival or recovery request.

- **Auth:** Agent auth
- **Request Body:** ResourceMessage with ClassName and Attributes.

  For archival:
  ```json
  {
    "ClassName": "com.netscape.certsrv.key.KeyArchivalRequest",
    "Attributes": {
      "Attribute": [
        {"name": "clientKeyID", "value": "vault-name"},
        {"name": "wrappedPrivateData", "value": "base64-encrypted-data"},
        {"name": "transWrappedSessionKey", "value": "base64-session-key"},
        {"name": "symmetricAlgorithmParams", "value": "base64-params"}
      ]
    }
  }
  ```

  For recovery:
  ```json
  {
    "ClassName": "com.netscape.certsrv.key.KeyRecoveryRequest",
    "Attributes": {
      "Attribute": [
        {"name": "keyId", "value": "0x1a"},
        {"name": "requestId", "value": "42"},
        {"name": "transWrappedSessionKey", "value": "base64-session-key"}
      ]
    }
  }
  ```

- **Response:** RequestInfo with requestType, requestStatus, requestURL, keyURL.

### GET /kra/rest/agent/keyrequests

List key requests.

- **Auth:** Agent auth
- **Query:** `requestState`, `requestType`, `clientKeyID`.
- **Response:** `{"entries": [...], "total": N}`

### GET /kra/rest/agent/keyrequests/{request_id}

Get key request info.

- **Auth:** Agent auth

### POST /kra/rest/agent/keyrequests/{request_id}/approve

Approve a key request.

- **Auth:** Agent auth

### POST /kra/rest/agent/keyrequests/{request_id}/reject

Reject a key request.

- **Auth:** Agent auth

### POST /kra/rest/agent/keyrequests/{request_id}/cancel

Cancel a key request.

- **Auth:** Agent auth

### POST /kra/rest/agent/keys/archive

Archive a key.

- **Auth:** Agent auth
- **Request Body:**
  ```json
  {
    "wrappedPrivateData": "base64-encrypted-secret",
    "clientKeyId": "vault-name-or-id",
    "dataType": "symmetricKey",
    "keyAlgorithm": "AES",
    "keySize": 256
  }
  ```
  Valid `dataType`: `symmetricKey`, `passPhrase`, `asymmetricKey`.
- **Response:**
  ```json
  {"KeyId": "0x1a", "Status": "complete", "RequestId": "42"}
  ```

### POST /kra/rest/agent/keys/retrieve

Retrieve an archived key.

- **Auth:** Agent auth
- **Request Body:** KeyRecoveryRequest with keyId or requestId, plus
  transWrappedSessionKey.
- **Response:**
  ```json
  {
    "wrappedPrivateData": "base64-encrypted-data",
    "algorithm": "AES",
    "size": 256
  }
  ```

### GET /kra/rest/agent/keys

List archived keys.

- **Auth:** Agent auth
- **Query:** `owner`, `status`, `size` (default 100).
- **Response:** `{"entries": [...], "total": N}`

### GET /kra/rest/agent/keys/{key_id}

Get key metadata.

- **Auth:** Agent auth
- **Response:** Owner, status, algorithm, size, creation date.

### POST /kra/rest/agent/keys/{key_id}

Modify key status.

- **Auth:** Agent auth
- **Query:** `status` -- must be `active`, `inactive`, or `archived`.

### GET /kra/rest/agent/keys/active/{client_key_id}

Get the most recent active key for a client.

- **Auth:** Agent auth

### GET /kra/rest/agent/keys/transportCert

Get the KRA transport certificate (PEM).

- **Auth:** None

Also available as JSON at `/kra/rest/config/cert/transport`.

### GET /kra/rest/stats

Get KRA statistics.

- **Auth:** None

---

## 12. HSM (Hardware Security Module)

### GET /ca/rest/hsm/config

Get HSM configuration.

- **Auth:** Agent auth
- **Query:** `ca_id` (default: `ipa`).
- **Response:** Configuration (token_pin excluded).

### PUT|POST /ca/rest/hsm/config

Update HSM configuration.

- **Auth:** Agent auth
- **Request Body:**
  ```json
  {
    "ca_id": "ipa",
    "enabled": true,
    "pkcs11_library": "/usr/lib64/libsofthsm2.so",
    "token_label": "ipa-ca",
    "token_pin": "secret"
  }
  ```

### DELETE /ca/rest/hsm/config

Delete HSM configuration.

- **Auth:** Agent auth
- **Query:** `ca_id` (default: `ipa`).

### POST /ca/rest/hsm/test

Test HSM connectivity.

- **Query:** `ca_id` (default: `ipa`).
- **Response:** Connection status and key count.

### GET /ca/rest/hsm/slots

List HSM token slots.

- **Query:** `library` (required) -- PKCS#11 library path.
- **Response:** `{"library": "...", "total": N, "entries": [...]}`

### GET /ca/rest/hsm/info

Get HSM device and token information.

- **Query:** `ca_id` (default: `ipa`).

### GET /ca/rest/hsm/keys

List keys stored in the HSM.

- **Query:** `ca_id` (default: `ipa`).
- **Response:** `{"total": N, "entries": [{"label": "..."}]}`

### POST /ca/rest/hsm/keys/generate

Generate a new key pair in the HSM.

- **Request Body:**
  ```json
  {
    "ca_id": "ipa",
    "key_label": "ipa-ca-signing-2025",
    "key_size": 3072,
    "key_type": "RSA"
  }
  ```
  RSA key_size must be 2048, 3072, or 4096.
- **Response (201):** Key generation status with handles.

### DELETE /ca/rest/hsm/keys/{key_label}

Delete a key from the HSM.

- **Query:** `ca_id` (default: `ipa`), `confirm=true` (required).

---

## 13. Serial Number Ranges

Serial number ranges support multi-master replication by partitioning the
serial number space across replicas.

### GET /ca/rest/ranges

List all allocated serial ranges.

- **Auth:** None
- **Response:** `{"entries": [...], "total": N}`

### GET /ca/rest/ranges/replica/{replica_id}

Get serial ranges for a specific replica.

- **Auth:** None
- **Response:** `{"replica_id": "...", "ranges": [...], "total": N}`

### POST /ca/rest/ranges/allocate

Allocate a new serial range for a replica.

- **Auth:** Agent auth
- **Request Body:**
  ```json
  {
    "replica_id": "replica1.example.com",
    "range_size": 10000
  }
  ```
- **Response (201):**
  ```json
  {
    "replica_id": "replica1.example.com",
    "begin_range": 1000001,
    "end_range": 1010000,
    "range_size": 10000
  }
  ```

### PUT /ca/rest/ranges/replica/{replica_id}/{begin_range}

Update the end of a serial range.

- **Auth:** Agent auth
- **Path:** `begin_range` -- integer.
- **Request Body:** `{"new_end_range": 1020000}`

### DELETE /ca/rest/ranges/replica/{replica_id}/{begin_range}

Delete a specific serial range.

- **Auth:** Agent auth

### DELETE /ca/rest/ranges/replica/{replica_id}

Delete all serial ranges for a replica.

- **Auth:** Agent auth

---

## 14. Debug / Diagnostics

### GET /ca/rest/debug/resources

Get a current resource-usage snapshot (RSS, VMS, FDs, threads, GC,
LDAP pool stats, tracemalloc top sites).

- **Auth:** Agent auth
- **Response:**
  ```json
  {
    "timestamp": 1716700000.0,
    "memory": {"rss_mb": 42.5, "vms_mb": 120.0},
    "open_fds": 23,
    "threads": 8,
    "gc": {"gen0": 100, "gen1": 5, "gen2": 1},
    "ldap_pool": {"created": 10, "idle": 3, "max": 10, "min": 2}
  }
  ```

### POST /ca/rest/debug/gc

Force a full garbage-collection cycle and return before/after object
counts.

- **Auth:** Agent auth
- **Response:**
  ```json
  {
    "collected_unreachable": 42,
    "gc_counts_before": {"gen0": 100, "gen1": 5, "gen2": 1},
    "gc_counts_after": {"gen0": 0, "gen1": 0, "gen2": 0}
  }
  ```

---

## Rate Limiting

ACME and OCSP endpoints are protected by per-IP sliding-window rate
limiters. When a limit is exceeded, HTTP 429 is returned with a
`Retry-After` header and an ACME-compatible JSON error body.

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/acme/new-account` | 20 | 1 hour |
| `/acme/new-order` | 60 | 1 minute |
| `/acme/revoke-cert` | 10 | 1 minute |
| Other ACME POST | 120 | 1 minute |
| `/ca/ocsp` | 600 | 1 minute |
