# Utilities

This document covers ipacta's X.509 utilities, NSS database
operations, and the certificate pruning manager.

## X.509 Utilities (`x509_utils.py`)

A collection of functions for DN conversion, extension building, algorithm
parsing, and certificate loading. Used throughout the codebase.

### DN Conversion

ipacta must convert between three DN representations:
- `x509.Name` (python-cryptography, least-specific-first RDN order)
- `DN` (IPA, most-specific-first)
- String (`"CN=foo,O=BAR"`)

| Function | From | To | Notes |
|----------|------|----|-------|
| `cert_name_to_ipa_dn(x509_name, reverse=True)` | x509.Name | DN | Reverses RDN order by default |
| `ipa_dn_to_x509_name(dn_string)` | str | x509.Name | Each attribute in its own RDN |
| `get_subject_dn_str(cert)` | Certificate | str | Subject as IPA-format string |
| `get_issuer_dn_str(cert)` | Certificate | str | Issuer as IPA-format string |
| `get_subject_dn(cert)` | Certificate | DN | Subject as DN object |
| `get_issuer_dn(cert)` | Certificate | DN | Issuer as DN object |
| `get_dn_components(x509_name)` | x509.Name | list[tuple] | `[("CN", "foo"), ("O", "BAR")]` |
| `build_x509_name(attributes, reverse=False)` | dict/list | x509.Name | Standard DN ordering |

**OID mappings:** The module maintains bidirectional mappings between
`NameOID` values and short names:

| Short Name | OID |
|-----------|-----|
| CN | 2.5.4.3 |
| O | 2.5.4.10 |
| OU | 2.5.4.11 |
| C | 2.5.4.6 |
| L | 2.5.4.7 |
| ST | 2.5.4.8 |
| emailAddress | 1.2.840.113549.1.9.1 |
| street | 2.5.4.9 |
| DC | 0.9.2342.19200300.100.1.25 |
| UID | 0.9.2342.19200300.100.1.1 |
| serialNumber | 2.5.4.5 |
| SN | 2.5.4.4 |
| givenName | 2.5.4.42 |
| title | 2.5.4.12 |

### KeyUsage Extensions

Pre-built Key Usage extensions for common certificate types:

| Function | Usage Bits |
|----------|-----------|
| `get_ca_key_usage_extension()` | keyCertSign, crlSign, digitalSignature, contentCommitment |
| `get_service_key_usage_extension()` | digitalSignature, keyEncipherment |
| `get_ocsp_key_usage_extension()` | digitalSignature only |
| `get_subsystem_key_usage_extension()` | digitalSignature, keyEncipherment |
| `get_audit_key_usage_extension()` | digitalSignature, contentCommitment (non-repudiation) |

`get_ocsp_key_usage_extension()` sets only `digital_signature`; per its
docstring, RFC 5280 §4.2.1.3 and RFC 6960 §4.2.2.2 allow only
digitalSignature for OCSP responder certificates.

### ExtendedKeyUsage Extensions

| Function | OIDs |
|----------|------|
| `get_server_extended_key_usage()` | serverAuth + clientAuth |
| `get_ocsp_extended_key_usage()` | OCSPSigning |
| `get_subsystem_extended_key_usage()` | clientAuth + serverAuth |
| `get_pkinit_extended_key_usage()` | PKINIT KDC (1.3.6.1.5.2.3.5) |

### Signature Algorithm Handling

| Function | Description |
|----------|-------------|
| `parse_signature_algorithm(alg_string)` | Parse Dogtag strings (e.g. `"SHA256withRSA"`) to hash algorithm |
| `get_default_algorithm_for_key(public_key)` | Infer algorithm from key type (RSA->SHA256withRSA, EC->SHA256withEC) |
| `get_certificate_signature_algorithm(cert)` | Extract algorithm from certificate as Dogtag string |

Supported algorithms: SHA1, SHA256, SHA384, SHA512 (with RSA, EC, or DSA),
plus post-quantum ML-DSA-44/65/87 (no pre-hash algorithm; handled
separately throughout `parse_signature_algorithm()`,
`get_default_algorithm_for_key()`, and
`get_certificate_signature_algorithm()`).
MD5 and MD2 are accepted for parsing legacy certificates but should not be
used for new signatures.

### Certificate Loading

```python
cert = load_certificate_from_ldap_data(cert_data)
```

Handles multiple input formats: DER bytes, PEM string, PEM bytes,
`IPACertificate` objects.

### LDAP Attribute Handling

```python
value = decode_ldap_attribute(raw_value, expected_type=str)
```

Converts LDAP attribute values between types: bytes to str, str to int,
str to bool. Handles the common case where python-ldap returns `bytes`
for string attributes.

## NSS Database Utilities (`nss_utils.py`)

Wraps NSS `certutil`, `pk12util`, and `openssl` commands for certificate
and key management in the NSS database.

### NSSDatabase

```python
NSSDatabase(
    nssdb_dir: Path = None,          # default: /etc/pki/pki-tomcat/alias
    nssdb_password: str = None,
    password_file: Path = None,      # default: /etc/pki/pki-tomcat/password.conf
)
```

The password is loaded from the password file (`internal=password` format)
if not provided directly.

### Operations

| Method | Description |
|--------|-------------|
| `generate_key_pair(nickname, key_size=4096, signing_alg="SHA256withRSA", ec_curve="P-256")` | Generate a key pair (in-memory, imported to NSSDB later); supports RSA, EC, and ML-DSA depending on `signing_alg` |
| `extract_private_key(nickname)` | Extract private key from NSSDB |
| `extract_certificate(nickname)` | Extract certificate from NSSDB |
| `import_key_and_cert(nickname, private_key, certificate, trust_flags="u,u,u")` | Import key+cert to NSSDB |
| `import_certificate(nickname, certificate, trust_flags="u,u,u")` | Import cert only |
| `cert_exists(nickname)` | Check if nickname exists in NSSDB |

### Key Extraction Flow

`extract_private_key(nickname)`:

1. Export from NSSDB to PKCS#12 via `pk12util -o` (60-second timeout).
2. Convert PKCS#12 to PEM via `openssl pkcs12 -nocerts -passin file:...`
   (60-second timeout; password passed via file, never on command line).
3. Parse PEM to `cryptography` RSA key object.
4. Clean up all temporary files.

On timeout, `CertificateOperationError` is raised with a message about
possible NSSDB lock contention.

### Key Import Flow

`import_key_and_cert(nickname, private_key, certificate, trust_flags)`:

1. Serialize the in-memory key and cert to temporary PEM files.
2. Create PKCS#12 via `openssl pkcs12 -export`.
3. Import PKCS#12 to NSSDB via `pk12util -i`.
4. Set trust flags via `certutil -M`.
5. Clean up all temporary files.

### Security

- Temporary PKCS#12 and key files are created with 0o600 permissions at
  creation time via `os.fchmod()` (no world-readable window between
  creation and chmod).
- All temp files are cleaned up in `finally` blocks.
- NSSDB passwords are passed via file (never on command line).
- OpenSSL passwords use `passin file:` / `passout file:` -- never via
  command-line arguments.
- `extract_private_key()` invokes `pk12util` and `openssl pkcs12` via
  `subprocess.run(..., timeout=60)` to prevent indefinite hangs from
  NSSDB lock contention; on timeout, `CertificateOperationError` is
  raised.
- `import_key_and_cert()` (and `import_certificate()`) instead use
  `ipapython.ipautil.run()`, which has no `timeout` parameter -- these
  subprocess calls (`openssl pkcs12 -export`, `pk12util -i`,
  `certutil -M`/`-A`) can block indefinitely if the NSSDB is locked.

### External Commands

| Command | Usage |
|---------|-------|
| `certutil` | List, export, import, modify certificates in NSSDB |
| `pk12util` | Export/import PKCS#12 files |
| `openssl pkcs12` | Convert between PKCS#12 and PEM (passwords via file) |

## Pruning Manager (`pruning.py`)

Manages automatic cleanup of expired certificates and old requests.

### PruningManager

```python
PruningManager(config, storage_backend)
```

State is stored in LDAP under `ou=pruning,o=ipaca`.

### Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `certRetentionTime` | `30` | Certificate retention period |
| `certRetentionUnit` | `day` | Unit: `minute`, `hour`, `day`, `year` |
| `certSearchSizeLimit` | `1000` | Max certs to delete per run |
| `certSearchTimeLimit` | `0` | Search time limit (0 = unlimited) |
| `requestRetentionTime` | `30` | Request retention period |
| `requestRetentionUnit` | `day` | Unit: `minute`, `hour`, `day`, `year` |
| `requestSearchSizeLimit` | `1000` | Max requests to delete per run |
| `requestSearchTimeLimit` | `0` | Search time limit |
| `cronSchedule` | (empty) | Cron schedule expression |
| `enabled` | `FALSE` | Enable automatic pruning |

### Operations

| Method | Description |
|--------|-------------|
| `get_config()` | Get configuration from LDAP |
| `update_config(updates)` | Update configuration in LDAP |
| `is_enabled()` | Check if pruning is enabled |
| `set_enabled(enabled)` | Enable or disable pruning |
| `run_pruning()` | Execute a pruning job |

### Pruning Execution

`run_pruning()`:

1. Calculates the cutoff date from retention time and unit.
2. Calls `storage.delete_old_certificates(cutoff, size_limit, time_limit)`.
3. Calls `storage.delete_old_requests(cutoff, size_limit, time_limit)`.
4. Returns:
   ```python
   {
       "certificates_deleted": 5,
       "requests_deleted": 3,
       "errors": [],
   }
   ```

### Retention Time Units

| Unit | Conversion |
|------|-----------|
| `minute` | `timedelta(minutes=value)` |
| `hour` | `timedelta(hours=value)` |
| `day` | `timedelta(days=value)` |
| `year` | `timedelta(days=value * 365)` |

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ca/rest/pruning/config` | Get configuration |
| POST | `/ca/rest/pruning/config` | Update configuration |
| POST | `/ca/rest/pruning/enable` | Enable pruning |
| POST | `/ca/rest/pruning/disable` | Disable pruning |
| POST | `/ca/rest/pruning/run` | Run pruning job |

Enable, disable, and run require agent authentication.
