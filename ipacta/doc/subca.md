# Sub-CA Management

ipacta supports lightweight (subordinate) Certificate Authorities
for issuing certificates under different CA identities. Sub-CAs share
the same LDAP infrastructure and serial number space as the main CA.

## Architecture

```
Main CA (ca_id="ipa")
  |
  |-- SubCAManager (subca.py)
  |     |-- SubCA (ca_id="dept-a")
  |     |-- SubCA (ca_id="dept-b")
  |     └-- ...
  |
  |-- LDAP: ou=authorities,ou=ca,o=ipaca
  |-- Filesystem: subcas/{ca_id}/ca.crt (certificate only)
  |-- NSSDB: "caSigningCert cert-pki-ca {ca_id}" (private key)
  └-- Dogtag schema: cn={uuid},ou=authorities,...
```

## SubCA

Represents a single subordinate CA with its own certificate and key.

### Construction

```python
SubCA(
    ca_id: str,
    subject_dn: str,
    parent_ca: Optional[SubCA] = None,
    ca_cert: x509.Certificate = None,
    ca_key: rsa.RSAPrivateKey = None,
)
```

### Creation

```python
cert = subca.create(
    key_size=2048,
    validity_days=3650,
    path_length=0,
)
```

1. Generates an RSA private key.
2. Parses the subject DN.
3. Generates a random serial number.
4. Sets the issuer to the parent CA (or self for self-signed).
5. Adds extensions:
   - `BasicConstraints(ca=True, path_length=path_length)` (critical).
   - CA Key Usage (`keyCertSign`, `crlSign`, `digitalSignature`)
     (critical).
   - Subject Key Identifier.
   - Authority Key Identifier (from parent).
6. Signs with the parent CA's key (or self-signs).
7. Saves the certificate to disk and imports the key+certificate into
   NSSDB (`_save_to_nssdb()`).
8. Initializes a `PythonCA` instance for the sub-CA.

### Key Storage

- **Certificate:** Written to disk as PEM at `subcas/{ca_id}/ca.crt`
  (directory mode 0o750, certificate file mode 0o644). This is a
  read cache used by `load_from_disk()`; it is not the authoritative
  copy (see Sub-CA Retrieval, which loads the certificate from the
  LDAP certificate repository instead).
- **Private key:** Never written to disk. `_save_to_nssdb()` always
  imports the key and certificate into NSSDB via
  `NSSDatabase.import_key_and_cert()`, using the Dogtag-compatible
  nickname `caSigningCert cert-pki-ca {ca_id}` (trust flags `u,u,u`).

### Loading

```python
subca.load_from_disk(storage_backend=None)
```

1. Loads the certificate from disk (PEM, from `cert_path`); raises
   `NotFound` if the file does not exist.
2. Looks up HSM configuration for this sub-CA (via the provided
   `storage_backend`, or by walking up the parent chain to find one).
3. Loads the private key based on that configuration:
   - **HSM enabled:** Validates the configured `token_name` (must not
     be `"internal"`), then wraps the key in an `HSMPrivateKeyProxy`
     using key label `{ca_id}_signing`. The key material is never
     read into process memory as a plain key object.
   - **HSM disabled (default):** Loads the private key from NSSDB via
     `NSSDatabase().extract_private_key(nickname)`, using the same
     `caSigningCert cert-pki-ca {ca_id}` nickname used at creation
     time.
4. Initializes a `PythonCA` instance.

### Chain and Metadata

| Method | Description |
|--------|-------------|
| `get_certificate_chain()` | Return chain from leaf to root |
| `to_dict()` | Serialize: ca_id, subject_dn, parent_ca_id, enabled, serial_number, not_before, not_after |

## SubCAManager

Manages the lifecycle of all sub-CAs with LDAP persistence and caching.

### Construction

```python
SubCAManager(
    main_ca=None,
    cache_maxsize=100,
    cache_ttl=300,      # 5 minutes
)
```

Uses `TTLCache` (maxsize=100, ttl=300s) if `cachetools` is available,
otherwise an unbounded dict.

### LDAP Schema

```python
manager.initialize_ldap_schema()
```

Creates the `cn=cas,cn=ca,{basedn}` container with an ACI allowing the
`ipacasrv` account to manage sub-CA entries.

### Sub-CA Creation

```python
subca = manager.create_subca(
    ca_id="dept-a",
    subject_dn="CN=Department A CA,O=EXAMPLE.COM",
    parent_ca_id=None,     # defaults to main CA
    key_size=2048,
    validity_days=3650,
)
```

1. Resolves the parent CA (defaults to main CA).
2. Extracts `path_length` from the parent certificate's
   `BasicConstraints`.
3. Creates the sub-CA certificate and key via `SubCA.create()`, which
   also imports the private key into NSSDB (see Key Storage above).
4. Stores in LDAP using the Dogtag schema (`_store_subca_in_ldap()`):
   - Certificate in `ou=certificateRepository,ou=ca,o=ipaca`.
   - Authority metadata (including the NSSDB `key_nickname`) in
     `ou=authorities,ou=ca,o=ipaca`.
5. Caches the sub-CA with the LDAP modification timestamp.

### Sub-CA Retrieval

```python
subca = manager.get_subca(ca_id, force_reload=False)
```

Uses timestamp-based cache validation:

1. Checks the in-memory cache (unless `force_reload=True`).
2. Compares the cached timestamp against the LDAP `modifyTimestamp`.
3. If the cache is stale or missing, loads from LDAP
   (`_load_subca_dogtag()`):
   a. Gets authority metadata from `ou=authorities`.
   b. Gets the certificate from the certificate repository (by
      serial number).
   c. Loads the private key from NSSDB via
      `_load_subca_key_from_nssdb()` (nickname
      `caSigningCert cert-pki-ca {ca_id}`); if the key is not present
      in NSSDB, the sub-CA is loaded without a private key
      (read-only mode) rather than failing.
   d. Determines the parent CA.
   e. Creates a `SubCA` instance.
4. Returns the `SubCA` or `None` if not found.

### Sub-CA Listing

```python
subcas = manager.list_subcas()
```

Queries LDAP for all entries matching
`(&(objectClass=ipaca)(objectClass=ipactaca))` and returns `SubCA`
instances.

### Sub-CA Deletion

```python
manager.delete_subca(ca_id)
```

Removes the sub-CA from:
1. LDAP authority metadata: `_delete_subca_from_ldap()` calls
   `storage.delete_authority(ca_id)`, which deletes only the
   authority entry under `ou=authorities,ou=ca,o=ipaca`. The
   certificate record previously stored in
   `ou=certificateRepository,ou=ca,o=ipaca` is **not** deleted.
2. In-memory cache.
3. Filesystem: the on-disk certificate cache (`subcas/{ca_id}/`) is
   removed via `shutil.rmtree()`.

Note: the NSSDB key entry (nickname
`caSigningCert cert-pki-ca {ca_id}`) is **not** removed by deletion,
nor is the certificate repository record. This is current behavior,
not by design — deleting and recreating a sub-CA with the same
`ca_id` will leave orphaned data in NSSDB and the certificate
repository.

### Status Management

```python
manager.update_subca_status(ca_id, enabled=False)
```

Updates the `authorityEnabled` attribute in LDAP and invalidates the
cache entry.

### Dogtag LDAP Schema

Sub-CAs are stored using the Dogtag authority schema:

**Authority entry** (`cn={uuid},ou=authorities,ou=ca,o=ipaca`):

| Attribute | Description |
|-----------|-------------|
| `authorityID` | Authority identifier (UUID) |
| `authorityDN` | Subject DN |
| `authorityKeyNickname` | NSS key nickname |
| `authorityEnabled` | `TRUE` or `FALSE` |
| `authorityParentID` | Parent authority UUID |
| `authorityParentDN` | Parent subject DN |
| `authoritySerial` | Certificate serial number |
| `authorityKeyHost` | List of key host FQDNs |
| `description` | Human-readable description |

## Integration with InternalCA

When `InternalCA` signs a certificate request with a `ca_id` that is not
the main CA:

1. `is_main_ca_id(ca_id)` returns `False`.
2. `subca_manager.get_subca(ca_id)` loads the sub-CA.
3. The sub-CA's certificate and key are used for signing.
4. The issued certificate has the sub-CA as its issuer.
5. On any error loading the sub-CA, falls back to the main CA with a
   warning log.

## REST API

Sub-CAs are managed through the Authorities REST API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ca/rest/authorities` | List all authorities |
| GET | `/ca/rest/authorities/{id}` | Get authority details |
| POST | `/ca/rest/authorities` | Create lightweight CA |
| GET | `/ca/rest/authorities/{id}/cert` | Get authority certificate |
| GET | `/ca/rest/authorities/{id}/chain` | Get certificate chain |
| POST | `/ca/rest/authorities/{id}/enable` | Enable authority |
| POST | `/ca/rest/authorities/{id}/disable` | Disable authority |
| DELETE | `/ca/rest/authorities/{id}` | Delete authority |

The special authority ID `"host-authority"` refers to the main CA and
cannot be disabled or deleted.
