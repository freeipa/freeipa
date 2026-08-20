# ACME Server

ipacta includes a full RFC 8555 ACME (Automatic Certificate Management
Environment) server for automated certificate issuance. The implementation
consists of `ACMEServer` (protocol logic), `ACMEStateManager`
(enable/disable), and `JWK` (JSON Web Key support).

## Architecture

```
REST API (/acme/*)
    |
    v
ACMEServer (acme.py)
    |
    |-- ACMEStateManager (acme_state.py)  -- enable/disable
    |-- JWK / JWS (jwk.py, acme.py)      -- key + signature handling
    |-- PythonCA (ca.py)                  -- certificate signing
    |-- ACMEStorageBackend (storage/acme.py) -- LDAP persistence
    v
LDAP (ou=acme,o=ipaca)
```

All ACME state (accounts, orders, authorizations, challenges, nonces,
certificates) is persisted in LDAP under `ou=acme,o=ipaca`.

## ACME Order Lifecycle

The standard RFC 8555 flow:

```
Client                         Server
  |                              |
  |--- GET /acme/directory ----->|  (1) Discover endpoints
  |<-- directory JSON -----------|
  |                              |
  |--- HEAD /acme/new-nonce ---->|  (2) Get replay nonce
  |<-- Replay-Nonce header ------|
  |                              |
  |--- POST /acme/new-account -->|  (3) Create account
  |<-- 201 + Location header ----|      (or 200 if exists)
  |                              |
  |--- POST /acme/new-order ---->|  (4) Create order
  |<-- 201 + order JSON ---------|      with authorization URLs
  |                              |
  |--- POST /acme/authz/{id} --->|  (5) Get authorization
  |<-- authorization JSON -------|      with challenge list
  |                              |
  |--- POST /acme/chall/{tok} -->|  (6) Respond to challenge
  |<-- challenge JSON -----------|      (http-01 or dns-01)
  |                              |
  |--- POST /order/{id}/final -->|  (7) Finalize with CSR
  |<-- order JSON (status=valid)-|      certificate issued
  |                              |
  |--- POST /acme/cert/{id} ---->|  (8) Download certificate
  |<-- PEM certificate chain ----|
```

## ACMEServer

### Construction

```python
ACMEServer(ca: PythonCA, base_url: str, config)
```

- `ca` -- The CA instance for signing.
- `base_url` -- Server URL (e.g. `https://ipa.example.com`).
- `config` -- ipacta configuration.

Creates an `ACMEStorageBackend` for LDAP persistence.

### Directory

```python
server.get_directory()
```

Returns the RFC 8555 directory object:

```python
{
    "newNonce": "{base_url}/acme/new-nonce",
    "newAccount": "{base_url}/acme/new-account",
    "newOrder": "{base_url}/acme/new-order",
    "revokeCert": "{base_url}/acme/revoke-cert",
    "keyChange": "{base_url}/acme/key-change",
    "meta": {
        "termsOfService": "...",
        "website": "...",
        "caaIdentities": ["..."],
    },
}
```

### Nonce Management

- `generate_nonce()` -- Creates a random nonce, stores in LDAP with
  30-minute expiration. Returns the nonce string.
- `_verify_nonce(nonce)` -- Validates and consumes the nonce from LDAP
  (one-time use).

### Account Management

```python
account, is_new = server.create_account(payload, account_key)
```

- If an account with the same JWK thumbprint exists, returns it with
  `is_new=False`.
- Otherwise creates a new `ACMEAccount` (status=`valid`) and stores in
  LDAP.
- Account ID is derived from the JWK thumbprint (SHA256 hash).
- Supports `onlyReturnExisting` (RFC 8555 section 7.3.1): if set and
  no account exists, returns HTTP 400 `accountDoesNotExist`.

### Order Creation

```python
order = server.create_order(account_id, {"identifiers": [{"type": "dns", "value": "example.com"}]})
```

For each identifier:
1. Creates an `ACMEAuthorization` (status=`pending`, expires in 24 hours).
2. Creates two `ACMEChallenge` objects per authorization:
   - `http-01` -- HTTP validation
   - `dns-01` -- DNS TXT record validation
3. Stores everything in LDAP.
4. Returns the order with authorization URLs.

### Challenge Validation

```python
challenge = server.respond_to_challenge(token, account_id, account_key)
```

Validates the challenge with retry logic (3 attempts):

**HTTP-01:** Before fetching the challenge, `_validate_acme_fqdn()` is
called on the identifier to prevent SSRF via the outbound HTTP request:
it rejects bare IP literals and optionally blocks private/loopback
addresses (when `acme.allow_private_ips = false` in `ipacta.conf`;
default is `true`). This check is specific to HTTP-01 -- DNS-01
validation does not make an outbound HTTP fetch, so it does not call
`_validate_acme_fqdn()`. Once validated, HTTP-01 fetches
`http://{identifier}/.well-known/acme-challenge/{token}` and verifies
the response matches `{token}.{thumbprint}`.

**DNS-01:** Resolves `_acme-challenge.{identifier}` TXT record and
verifies it matches `base64url(SHA256({token}.{thumbprint}))`.

On success, updates the challenge and authorization status to `valid`
in LDAP.

### Order Finalization

```python
order = server.finalize_order(order_id, account_id, csr_der)
```

1. Verifies all authorizations are `valid`.
2. Parses the CSR and validates that its SANs match the order identifiers.
3. Submits the CSR to the CA with the `acmeIPAServerCert` profile.
4. Signs the certificate.
5. Stores the certificate in LDAP.
6. Updates the order status to `valid` with a certificate URL.

### Certificate Download

```python
cert_pem = server.get_certificate(order_id, account_id)
```

Returns the PEM certificate with the full chain.

### Certificate Revocation

```python
server.revoke_certificate(certificate_der, reason=0, account_id=None)
```

Revokes the certificate via the CA with the given reason code.

- `account_id` -- The authenticated account ID making the revocation
  request. When provided, enforces the RFC 8555 §7.6 ownership check:
  the certificate's original order must belong to `account_id`, or an
  `ACMEError("unauthorized", ...)` is raised (also raised if no order
  can be found for the certificate). If `account_id` is `None`, the
  ownership check is skipped (used for legacy/internal revocation
  paths).

### JWS Request Processing

```python
protected_header, payload, account_id = server.process_jws_request(jws_token, expected_url)
```

Validates JWS-signed ACME requests:
1. Decodes the JWS token (protected header, payload, signature).
2. Extracts the public key from the `jwk` field or looks up the account
   by `kid`.
3. Verifies the signature (supports RS256, PS256, ES256, ES384, ES512).
4. Validates the nonce and URL in the protected header.
5. Returns the decoded payload and account ID.

### Maintenance

```python
server.run_maintenance()
```

Removes expired nonces, orders, and authorizations from LDAP. Returns
counts of removed items.

A background maintenance timer can be started with
`start_maintenance_timer(interval_minutes=30)` and stopped with
`stop_maintenance_timer()`.

### Rate Limiting

ACME endpoints are protected by per-IP sliding-window rate limiters
(`rate_limit.py`):

| Endpoint | Limit | Window |
|----------|-------|--------|
| `new-account` | 20 | 1 hour |
| `new-order` | 60 | 1 minute |
| `revoke-cert` | 10 | 1 minute |
| All other POST | 120 | 1 minute |

When a limit is exceeded, the endpoint returns HTTP 429 with an
ACME-compatible JSON error body (`urn:ietf:params:acme:error:rateLimited`)
and a `Retry-After` header.

### ACME Enable/Disable Authentication

The `POST /acme/enable` and `POST /acme/disable` endpoints require
agent authentication (`@require_agent_auth`). This ensures only
authorized RA agents can control the ACME service state.

## ACMEStateManager (`acme_state.py`)

Controls whether the ACME service is enabled or disabled.

```python
manager = ACMEStateManager(config)
manager.is_enabled()        # Check status from LDAP
manager.set_enabled(True)   # Enable ACME
manager.set_enabled(False)  # Disable ACME
```

State is stored in LDAP at `ou=config,ou=acme,o=ipaca` with the
`acmeEnabled` attribute. ACME is disabled by default (secure-by-default).

When ACME is disabled, the `/acme/directory` endpoint returns 503
Service Unavailable.

## JWK Support (`jwk.py`)

### Key Conversion

```python
jwk_dict = JWK.from_cryptography_key(public_key)
```

Converts a `cryptography` public key to JWK format:
- **RSA:** `{"kty": "RSA", "n": "...", "e": "..."}`
- **EC:** `{"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}`

Supported curves: P-256, P-384, P-521.

### JWK Thumbprint (RFC 7638)

```python
thumbprint = JWK.thumbprint(jwk_dict)
```

Calculates the thumbprint by:
1. Serializing the JWK in canonical order:
   - RSA: `{e, kty, n}`
   - EC: `{crv, kty, x, y}`
2. Computing SHA-256 of the JSON.
3. Base64url-encoding the hash.

The thumbprint is used as the account identifier and for challenge
validation tokens.

## Data Model

### ACMEAccount

| Field | Type | Description |
|-------|------|-------------|
| `account_id` | str | Derived from JWK thumbprint |
| `key` | dict | JWK public key |
| `contact` | list | Contact URLs (e.g. `mailto:admin@example.com`) |
| `status` | str | `valid` |
| `created_at` | datetime | Account creation time |

### ACMEOrder

| Field | Type | Description |
|-------|------|-------------|
| `order_id` | str | Random identifier |
| `account_id` | str | Owning account |
| `identifiers` | list | `[{"type": "dns", "value": "example.com"}]` |
| `status` | str | `pending` -> `ready` -> `valid` |
| `authorizations` | list | Authorization IDs |
| `expires` | datetime | 24 hours from creation |
| `certificate_url` | str | Set after finalization |

### ACMEAuthorization

| Field | Type | Description |
|-------|------|-------------|
| `auth_id` | str | Random identifier |
| `account_id` | str | Owning account |
| `identifier` | dict | `{"type": "dns", "value": "example.com"}` |
| `status` | str | `pending` -> `valid` or `invalid` |
| `challenges` | list | `ACMEChallenge` objects (http-01 and dns-01) |
| `expires` | datetime | 24 hours from creation |

### ACMEChallenge

| Field | Type | Description |
|-------|------|-------------|
| `challenge_type` | str | `http-01` or `dns-01` |
| `token` | str | Random URL-safe base64 token |
| `status` | str | `pending` -> `valid` or `invalid` |
| `validated` | datetime | Validation timestamp (if valid) |
