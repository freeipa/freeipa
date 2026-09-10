# Storage Backend

ipacta persists all state in LDAP under the `o=ipaca` base DN, using
a Dogtag-compatible schema. The storage layer provides connection pooling,
per-entity modules, caching, and thread-safe serial number allocation.

## Architecture

The storage layer is composed via multiple inheritance:

```
CAStorageBackend
  ├── CertificateStorage
  ├── ProfileStorage
  ├── CRLStorage
  ├── MaintenanceStorage
  ├── SubCAStorage
  ├── RangeStorage
  ├── HSMStorage
  └── BaseStorageBackend
        └── LDAPStorageMixin
```

`CAStorageBackend` (`storage/ca.py`) is the single entry point used by the
rest of the system. It inherits all storage modules, each of which inherits
from `BaseStorageBackend` for shared infrastructure.

Separate from the inheritance chain, `ACMEStorageBackend` and
`KRAStorageBackend` are standalone classes that use `LDAPStorageMixin`
directly.

### Factory

`get_storage_backend()` (`storage/factory.py`) creates a
`CAStorageBackend` with configuration loaded from `ipacta.conf`:

```python
backend = get_storage_backend(
    ca_id="ipa",
    random_serial_numbers=True,
    config=config,
)
```

## LDAP Connection Management

### Connection Pool

`LDAPConnectionPool` (`ldap_utils.py`) manages a pool of reusable LDAP
connections:

| Parameter | Default | Config Key |
|-----------|---------|------------|
| Min connections | 2 | `[ldap] pool_min_connections` |
| Max connections | 10 | `[ldap] pool_max_connections` |
| Get timeout | 5s | (hardcoded, doubled to 10s when pool exhausted) |

**Behavior:**
- Pre-creates `min_connections` on initialization.
- Health checks use the LDAP `whoami_s()` extended operation, run on
  *every* checkout from and return to the pool (not throttled by any
  interval).
- Unhealthy connections are discarded and replaced.
- Thread-safe via `threading.Lock` and `queue.Queue`.

**Usage:**

```python
with get_ldap_connection() as conn:
    entries = conn.get_entries(
        base_dn, scope=conn.SCOPE_ONELEVEL, filter=filter_str
    )
```

Pooling can be disabled by setting the environment variable
`IPACTA_USE_LDAP_POOL=0`, which falls back to a legacy singleton
connection.

### LDAPStorageMixin

All storage classes inherit `LDAPStorageMixin` (`storage/base.py`),
which provides:

- `_get_ldap_connection()` -- context manager that wraps
  `get_ldap_connection()` with error translation (LDAP errors become
  `StorageConnectionError` or `StoragePermissionError`).
- `_create_ou_if_not_exists(ldap, dn, ou_name)` -- idempotent OU creation
  with race-condition handling (ignores `ALREADY_EXISTS`).

## LDAP Schema

### Directory Tree

```
o=ipaca
├── ou=ca
│   ├── ou=certificateRepository      # Certificate entries
│   │   └── cn={serial}               # objectClass: certificateRecord
│   ├── ou=crlIssuingPoints           # CRL entries
│   │   └── cn={crl_name}             # objectClass: crlIssuingPointRecord
│   ├── ou=authorities                # Sub-CA entries
│   │   └── cn={uuid}                 # objectClass: authority
│   ├── ou=certificateProfiles        # Profile entries
│   │   └── cn={profile_id}           # objectClass: certProfile
│   └── cn=CAConfig                   # CA configuration
│
├── ou=requests
│   └── ou=ca                         # Certificate request entries
│       └── cn={request_id}           # objectClass: request
│
├── ou=ranges
│   ├── ou=replica                    # Serial range allocations
│   │   └── cn={replica_id}-{begin}   # objectClass: extensibleObject
│   ├── ou=certificateRepository      # Certificate range tracking
│   └── ou=requests                   # Request range tracking
│
├── ou=acme                           # ACME protocol state
│   ├── ou=nonces                     # objectClass: acmeNonce
│   ├── ou=accounts                   # objectClass: acmeAccount
│   ├── ou=orders                     # objectClass: acmeOrder
│   ├── ou=authorizations             # objectClass: acmeAuthorization
│   ├── ou=challenges                 # objectClass: acmeChallenge*
│   ├── ou=certificates               # objectClass: acmeCertificate
│   └── ou=config
│
├── ou=Security Domain
│   └── ou=sessions
│
├── ou=replica
├── ou=people
├── ou=groups
│
└── o=kra                             # Key Recovery Authority
    ├── ou=kra
    │   └── cn=KRAConfig
    ├── ou=requests
    │   └── cn={request_id}           # objectClass: request
    ├── ou=people
    ├── ou=groups
    └── ou=ranges
        ├── ou=keyRepository
        ├── ou=replica
        └── ou=requests
```

Key entries under `o=kra` use DN pattern `cn={key_id},o=kra,o=ipaca`
with `objectClass: keyRecord`.

### Serial Number Encoding

ipacta uses Dogtag's length-prefixed encoding for serial numbers in
LDAP (`serialno` attribute), enabling correct lexicographic ordering of
variable-length integers:

```python
biginteger_to_db(serial_number: int) -> str
biginteger_from_db(encoded_serial: str) -> int
```

The encoding prepends the hex digit count as a zero-padded prefix,
allowing LDAP range filters to work correctly on serial numbers of
different lengths.

## Storage Modules

### CertificateStorage (`storage/certificates.py`)

Manages certificate and request persistence.

**Certificate Operations:**

| Method | Description |
|--------|-------------|
| `store_certificate(record, allow_update)` | Store or update a certificate |
| `get_certificate(serial_number)` | Retrieve by serial number |
| `find_certificates(criteria)` | Search with filters |
| `get_revoked_certificates(offset, limit)` | List revoked certificates (supports pagination) |
| `get_revoked_for_crl()` | Generator yielding `(serial, revoked_at, reason_int)` tuples (lightweight, no DER) |
| `bulk_store_certificates(records)` | Store multiple certificates |
| `bulk_revoke_certificates(serials, reason)` | Revoke multiple certificates |

**Search criteria** (dict keys for `find_certificates`):

| Key | Description |
|-----|-------------|
| `subject` | Subject DN substring match |
| `status` | Certificate status filter |
| `serial_number` | Exact serial number |
| `min_serial_number` | Range lower bound |
| `max_serial_number` | Range upper bound |

**Request Operations:**

| Method | Description |
|--------|-------------|
| `store_request(request)` | Store a certificate request |
| `get_request(request_id)` | Retrieve request by ID |
| `delete_request(request_id)` | Delete a request |

**Serial Number Allocation:**

| Method | Description |
|--------|-------------|
| `get_next_serial_number()` | Allocate next serial (sequential or random) |
| `get_next_crl_number()` | Allocate next CRL sequence number |

Serial allocation is thread-safe (`threading.Lock`). When
`random_serial_numbers` is enabled, 128-bit random serials are generated
(matching Dogtag RSNv3), with up to 100 collision recovery attempts.

**Certificate LDAP Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `cn` | str | Serial number (decimal) |
| `serialno` | str | Encoded serial (Dogtag format) |
| `subjectName` | str | Subject DN |
| `issuerName` | str | Issuer DN |
| `notBefore` | str | ISO 8601 validity start |
| `notAfter` | str | ISO 8601 validity end |
| `certStatus` | str | VALID, REVOKED, EXPIRED |
| `userCertificate;binary` | bytes | DER-encoded certificate |
| `dateOfCreate` | str | Creation timestamp |
| `revokedOn` | str | Revocation timestamp |
| `revInfo` | str | Revocation reason code |

**Request LDAP Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `cn` | str | Request ID |
| `requestState` | str | pending, complete, rejected, canceled |
| `extdata-cert-request` | str | PEM-encoded CSR |
| `extdata-profile-id` | str | Profile identifier |
| `extdata-cert-serial-number` | str | Associated certificate serial |
| `dateOfCreate` | str | Creation timestamp |

**Status Mapping (ipacta to Dogtag):**

| ipacta | Dogtag |
|-----------|--------|
| VALID | VALID |
| REVOKED | REVOKED |
| EXPIRED | EXPIRED |
| ON_HOLD | REVOKED |
| PENDING | VALID |

### ProfileStorage (`storage/profiles.py`)

Manages certificate profile persistence in LDAP.

| Method | Description |
|--------|-------------|
| `store_profile(profile_data)` | Store profile to LDAP |
| `get_profile(profile_id)` | Retrieve profile metadata |
| `delete_profile(profile_id)` | Delete profile |
| `list_profiles()` | List all profile IDs |
| `list_profile_ids()` | Alias for `list_profiles()` |
| `get_profile_cfg(profile_id)` | Get raw .cfg file content |
| `update_profile_cfg(profile_id, cfg_content)` | Update profile config |
| `create_profile(profile_id, cfg_content, description)` | Create new profile |

**LDAP Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `cn` | str | Profile identifier |
| `classId` | str | Profile class (e.g. `caEnrollImpl`) |
| `certProfileConfig` | str/bytes | Profile .cfg content |

### CRLStorage (`storage/crl.py`)

Manages Certificate Revocation List persistence.

| Method | Description |
|--------|-------------|
| `store_crl(name, data, number, this_update, next_update, size)` | Store CRL |
| `get_crl(name)` | Retrieve DER-encoded CRL |
| `get_crl_info(name)` | Get CRL metadata (cached, TTL=300s) |
| `list_crl_issuing_points()` | List CRL names |
| `delete_crl_issuing_point(name)` | Delete a CRL issuing point |

**LDAP Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `cn` | str | CRL name (e.g. `MasterCRL`) |
| `crlNumber` | int | Sequence number |
| `thisUpdate` | str | Issue timestamp |
| `nextUpdate` | str | Next update timestamp |
| `certificateRevocationList;binary` | bytes | DER-encoded CRL |
| `crlSize` | int | Number of entries |
| `dateOfCreate` | str | Creation timestamp |
| `dateOfModify` | str | Last modification timestamp |

### SubCAStorage (`storage/subca.py`)

Manages lightweight (subordinate) CA metadata.

| Method | Description |
|--------|-------------|
| `store_authority(authority_data)` | Store sub-CA authority |
| `get_authority(authority_id)` | Retrieve authority details |
| `list_authorities()` | List all authorities |
| `update_authority_status(authority_id, enabled)` | Toggle enabled flag |
| `enable_authority(authority_id)` | Enable sub-CA |
| `disable_authority(authority_id)` | Disable sub-CA |
| `delete_authority(authority_id)` | Delete sub-CA |

**LDAP Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `cn` | str | Authority UUID |
| `authorityID` | str | Authority identifier |
| `authorityDN` | str | Subject DN |
| `authorityKeyNickname` | str | NSS key nickname |
| `authorityEnabled` | str | TRUE or FALSE |
| `authorityParentID` | str | Parent authority UUID |
| `authorityParentDN` | str | Parent subject DN |
| `authoritySerial` | str | Certificate serial number |
| `authorityKeyHost` | list | Key host FQDNs |
| `description` | str | Human-readable description |

### RangeStorage (`storage/ranges.py`)

Manages serial number range allocation for multi-master replication.

| Method | Description |
|--------|-------------|
| `allocate_serial_range(replica_id, range_size)` | Allocate a new range |
| `get_replica_ranges(replica_id)` | Get ranges for a replica |
| `list_all_ranges()` | List all allocated ranges |
| `update_range(replica_id, old_begin, new_end)` | Extend a range |
| `get_range_info(replica_id, begin_range)` | Get range details |
| `delete_range(replica_id, begin_range)` | Delete specific range |
| `delete_replica_ranges(replica_id)` | Delete all ranges for replica |

The global serial counter is stored in `cn=CAConfig,ou=ca,o=ipaca`
(attribute `nextRange`).

### HSMStorage (`storage/hsm.py`)

Manages Hardware Security Module configuration.

| Method | Description |
|--------|-------------|
| `store_hsm_config(ca_id, config)` | Store HSM configuration |
| `get_hsm_config(ca_id)` | Retrieve HSM configuration |
| `delete_hsm_config(ca_id)` | Delete HSM configuration |

HSM configuration is stored on the CA entry
`cn={ca_id},cn=cas,cn=ca,o=ipaca` using:
- `ipaCaHSMConfiguration` -- token name and library path
  (format: `token_name;library_path`)
- `ipaCaHSMMetadata` -- JSON with `enabled`, `slot_label`, `token_pin`

### MaintenanceStorage (`storage/maintenance.py`)

Provides pruning and statistics operations.

| Method | Description |
|--------|-------------|
| `get_statistics()` | Get CA statistics (cached, TTL=60s) |
| `cleanup_old_requests(days)` | Delete requests older than N days |
| `delete_old_certificates(cutoff, size_limit, time_limit)` | Delete old certificates |
| `delete_old_requests(cutoff, size_limit, time_limit)` | Delete old requests |

**Statistics dict:**

| Key | Description |
|-----|-------------|
| `total_certificates` | Total certificate count |
| `valid_certificates` | Valid count |
| `revoked_certificates` | Revoked count |
| `expired_certificates` | Expired count |
| `total_requests` | Total request count |
| `pending_requests` | Pending request count |

### ACMEStorageBackend (`storage/acme.py`)

Standalone storage for ACME protocol state. All ACME data lives under
`ou=acme,o=ipaca`.

**Nonce Operations:**

| Method | Description |
|--------|-------------|
| `create_nonce(nonce_id, expires)` | Create nonce with expiration |
| `validate_nonce(nonce_id)` | Validate and consume (one-time use) |
| `remove_expired_nonces()` | Cleanup expired nonces |

**Account Operations:**

| Method | Description |
|--------|-------------|
| `create_account(account_id, jwk, contacts)` | Create ACME account |
| `get_account(account_id)` | Retrieve account |
| `get_account_by_jwk(jwk)` | Find account by JWK thumbprint |
| `update_account(account_id, contacts, status)` | Update account |

**Order Operations:**

| Method | Description |
|--------|-------------|
| `create_order(order_id, account_id, identifiers, authz_ids, expires)` | Create order |
| `get_order(order_id)` | Retrieve order |
| `update_order_status(order_id, status, cert_id)` | Update order |
| `remove_expired_orders()` | Cleanup expired orders |

**Authorization Operations:**

| Method | Description |
|--------|-------------|
| `create_authorization(authz_id, account_id, identifier, wildcard, expires)` | Create authorization |
| `get_authorization(authz_id)` | Retrieve authorization |
| `update_authorization_status(authz_id, status)` | Update authorization |
| `remove_expired_authorizations()` | Cleanup expired authorizations |

**Challenge Operations:**

| Method | Description |
|--------|-------------|
| `create_challenge(challenge_id, authz_id, account_id, challenge_type, token)` | Create challenge |
| `get_challenge(challenge_id)` | Retrieve challenge |
| `update_challenge_status(challenge_id, status, validated_at)` | Update challenge |

**Certificate Operations:**

| Method | Description |
|--------|-------------|
| `store_certificate(cert_id, certificate_pem)` | Store issued certificate |
| `get_certificate(cert_id)` | Retrieve certificate PEM |

Time values use LDAP GeneralizedTime format (`YYYYMMDDHHMMSSZ`).

### KRAStorageBackend (`storage/kra.py`)

Standalone storage for Key Recovery Authority data under `o=kra,o=ipaca`.

**Key Operations:**

| Method | Description |
|--------|-------------|
| `store_key(encrypted_data, owner, algorithm, key_size, status)` | Store encrypted key |
| `get_key(key_id)` | Retrieve key metadata |
| `list_keys(owner, status, limit)` | List keys with filters |
| `update_key_status(key_id, status)` | Change key status |
| `delete_key(key_id)` | Delete key |

**Request Operations:**

| Method | Description |
|--------|-------------|
| `store_key_request(request_type, owner, status)` | Store key request |
| `get_key_request(request_id)` | Retrieve request |

**Statistics:**

| Method | Description |
|--------|-------------|
| `get_statistics()` | Total keys, active/inactive/archived counts |

Key IDs use hex format (`0x1a`). Key serials are allocated with a
thread-safe lock.

**Key LDAP Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `cn` | str | Key ID (hex) |
| `serialno` | str | Serial number |
| `privateKeyData` | bytes | Encrypted key material |
| `ownerName` | str | Key owner |
| `algorithm` | str | Encryption algorithm |
| `keySize` | int | Key size in bits |
| `keyState` | str | active, inactive, archived |
| `dateOfCreate` | str | Creation timestamp |
| `dateOfModify` | str | Modification timestamp |

## Schema Initialization

`BaseStorageBackend.initialize_schema()` creates the complete LDAP
directory structure on first startup:

1. Creates all `ou=*` container entries under `o=ipaca`.
2. Creates the certificate repository and request containers.
3. Creates range allocation containers.
4. Creates `cn=CAConfig` with initial serial number counters.
5. Creates LDAP indexes for query optimization on frequently searched
   attributes (`serialno`, `certStatus`, `subjectName`, `requestState`,
   `dateOfCreate`).

The schema creation is idempotent -- existing entries are silently skipped.

## Caching

Two TTL caches reduce LDAP load:

| Cache | TTL | Max Size | Data |
|-------|-----|----------|------|
| Statistics | 60s | 1 | Certificate/request counts |
| CRL info | 300s | 10 | CRL metadata per issuing point |

When `cachetools` is available it is used directly. Otherwise, a fallback
`TTLCache` with FIFO eviction is provided.

## Utility Functions

`ldap_utils.py` provides additional helpers:

| Function | Description |
|----------|-------------|
| `init_connection_pool(min, max)` | Initialize the global pool |
| `get_ldap_connection(force_reconnect, use_pool)` | Get a connection |
| `close_ldap_connection()` | Close legacy singleton connection |
| `close_ldap_pool()` | Close all pooled connections |
| `is_main_ca_id(ca_id, ca_name, config)` | Check if ca_id is the main IPA CA |
| `is_internal_token(token_name)` | Check if token is software (not HSM) |

`is_main_ca_id()` first checks by name (fast path: `ca_id == "ipa"`),
then falls back to an LDAP lookup of the `ipaCaId` attribute on
`cn=ipa,cn=cas,cn=ca,{basedn}`.

`is_internal_token()` returns `True` for `None`, empty string,
`"internal"`, and `"Internal Key Storage Token"`.
