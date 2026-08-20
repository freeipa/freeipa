# ipacta Configuration Reference

ipacta is configured through a single INI-style configuration file,
`/etc/ipa/ipacta.conf`. The file is generated from a template during
installation and read at service startup.

## Configuration Lifecycle

### Install Time

During `ipa-server-install` or `ipa-replica-install`, the installer creates
the configuration via:

```python
config = IpactaConfig.from_install_params(
    realm="EXAMPLE.COM",
    host="ipa.example.com",
    basedn="o=ipaca",
    ca_signing_algorithm="SHA256withRSA",
    ca_signing_key_size="3072",
    ...
)
config.write_to_file("/etc/ipa/ipacta.conf")
```

`write_to_file()` substitutes template variables from
`/usr/share/ipa/ipacta.conf.template` and writes the result.

### Runtime

At service startup, the configuration is loaded via:

```python
config = IpactaConfig.from_file("/etc/ipa/ipacta.conf")
```

The loaded config object provides a `RawConfigParser`-compatible interface
(`get()`, `has_option()`, `getboolean()`, `getint()`, `options()`).

## Configuration Sections

### [global]

Core IPA realm and identity settings.

| Option | Description | Example |
|--------|-------------|---------|
| `realm` | Kerberos realm name | `EXAMPLE.COM` |
| `domain` | DNS domain name (lowercase) | `example.com` |
| `host` | FQDN of this CA server | `ipa.example.com` |
| `basedn` | LDAP base DN for CA data | `o=ipaca` |

### [ca]

Certificate Authority signing, validation, and operational parameters.

#### Signing Algorithms

| Option | Default | Description |
|--------|---------|-------------|
| `default_signing_algorithm` | `SHA256withRSA` | Default algorithm when a profile specifies `"-"` |
| `allowed_signing_algorithms` | `SHA256withRSA,SHA384withRSA,SHA512withRSA,SHA256withEC,SHA384withEC,SHA512withEC,ML-DSA-44,ML-DSA-65,ML-DSA-87` | Comma-separated list of permitted algorithms |
| `crl_signing_algorithm` | `SHA256withRSA` | Algorithm for CRL signing |
| `audit_signing_algorithm` | `SHA256withRSA` | Algorithm for audit log signing |
| `ocsp_signing_algorithm` | `SHA256withRSA` | Algorithm for OCSP response signing |

#### Key Parameters

| Option | Default | Description |
|--------|---------|-------------|
| `default_rsa_key_size` | `3072` | Default RSA key size in bits (2048, 3072, 4096) |
| `default_ecc_curve` | `nistp256` | Default ECC curve (nistp256, nistp384, nistp521) |
| `ocsp_signing_key_size` | `3072` | OCSP signing key size in bits |
| `min_rsa_key_size` | `2048` | Minimum allowed RSA key size |
| `max_rsa_key_size` | `8192` | Maximum allowed RSA key size |
| `allowed_rsa_exponents` | `65537` | Comma-separated allowed RSA public exponents |

#### Serial Numbers

| Option | Default | Description |
|--------|---------|-------------|
| `random_serial_numbers` | `true` | Use random serial numbers (128-bit, matching Dogtag RSNv3) |
| `serial_number_bits` | `128` | Bit length of random serial numbers |
| `collision_recovery_attempts` | `100` | Max retries on serial number collision |

#### CRL Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `crl_update_interval` | `240` | CRL update interval in minutes (4 hours) |
| `crl_enable_daily_updates` | `true` | Enable scheduled daily CRL generation |
| `crl_daily_update_time` | `01:00` | Daily CRL update time (HH:MM, 24-hour) |
| `crl_include_expired_certs` | `false` | Include expired certificates in the CRL |
| `crl_next_update_grace_period` | `0` | Grace period in minutes added to CRL nextUpdate |

#### OCSP

| Option | Default | Description |
|--------|---------|-------------|
| `default_ocsp_uri` | `http://ipa-ca.DOMAIN/ca/ocsp` | Default OCSP responder URI for AIA extension |

#### CA Certificate

| Option | Default | Description |
|--------|---------|-------------|
| `ca_cert` | (set at install) | Path to the CA certificate file |

#### Search Limits

| Option | Default | Description |
|--------|---------|-------------|
| `max_search_returns` | `1000` | Maximum number of certificates returned by search queries |

### [ldap]

LDAP connection pool configuration.

| Option | Default | Description |
|--------|---------|-------------|
| `pool_min_connections` | `2` | Minimum connections in the pool |
| `pool_max_connections` | `10` | Maximum connections in the pool |

### [server]

WSGI/HTTP server configuration. Read by the `ipacta` gunicorn launcher
(`install/tools/ipacta.in`) and by `ipacta/wsgi.py`.

| Option | Default | Description |
|--------|---------|-------------|
| `bind_host` | `0.0.0.0` | IP address to bind to |
| `https_port` | `8443` | HTTPS port |
| `workers` | `1` | Number of Gunicorn worker processes |
| `threads` | `4` | Threads per worker |
| `ssl_cert` | `${IPACTA_CERTS_DIR}server.crt` | Server TLS certificate path |
| `ssl_key` | `${IPACTA_PRIVATE_DIR}server.key` | Server TLS private key path |
| `pid_file` | `/run/ipacta/ipacta.pid` | PID file path |
| `user` | `ipaca` | System user to run as |
| `group` | `ipaca` | System group to run as |

### [logging]

Log file configuration.

| Option | Default | Description |
|--------|---------|-------------|
| `level` | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL |
| `log_file` | `/var/log/ipacta/ipacta.log` | Main log file path |
| `access_log` | `/var/log/ipacta/access.log` | HTTP access log path |
| `gunicorn_log` | `/var/log/ipacta/gunicorn.log` | Gunicorn error log path |
| `max_log_size` | `10485760` | Max log file size in bytes (10 MB) |
| `backup_count` | `10` | Number of rotated log files to keep |

### [acme]

ACME protocol configuration.

| Option | Default | Description |
|--------|---------|-------------|
| `allow_private_ips` | `true` | Allow HTTP-01 challenge validation to private/loopback IPs. Set to `false` to enable SSRF protection. |

### [debug]

Diagnostic and resource tracking configuration.

| Option | Default | Description |
|--------|---------|-------------|
| `resource_log_interval` | `0` | Interval in seconds for periodic resource usage logging (0 = disabled) |
| `tracemalloc` | `false` | Enable `tracemalloc` allocation tracing for memory-leak analysis |

The environment variable `IPACTA_TRACEMALLOC=1` can also be used to
enable tracemalloc without a config change.

## WSGI Runtime Defaults

The `WSGI_DEFAULTS` dict in `config.py` provides defaults for the
`[server]`, `[ssl]`, and `[logging]` sections. These are applied before
reading the config file, so file values take precedence.

Note: the `[server]`/`[ssl]` keys in `WSGI_DEFAULTS` below (`host`,
`port`, `ssl_port`, `timeout`, `max_request_size`, and the whole `ssl`
sub-dict) are currently unused fallback defaults left over from an
earlier design -- they do not correspond to the real `[server]` options
documented above (`bind_host`, `https_port`, `ssl_cert`, `ssl_key`,
etc.), which are read directly by `install/tools/ipacta.in` without
going through `WSGI_DEFAULTS`.

```python
WSGI_DEFAULTS = {
    "server": {
        "host": "127.0.0.1",
        "port": "8080",
        "ssl_port": "8443",
        "workers": "1",
        "threads": "4",
        "timeout": "120",
        "max_request_size": "10",
    },
    "ssl": {
        "enabled": "true",
        "cert_file": paths.IPA_CA_CRT,
        "key_file": paths.IPACTA_SIGNING_KEY,
        "ssl_version": "TLSv1_2",
        "ssl_ciphers": "HIGH:!aNULL:!MD5:!3DES",
    },
    "logging": {
        "level": "INFO",
        "log_file": "{paths.IPACTA_LOG_DIR}/ipacta.log",
        "max_log_size": "10485760",
        "backup_count": "10",
    },
}
```

## Install-Time Defaults

When `from_install_params()` is called without explicit values, these
defaults apply:

```python
IPACTA_DEFAULTS = {
    "random_serial_numbers": True,
    "ca_key_type": "rsa",
    "ca_signing_algorithm": "SHA256withRSA",
    "ca_signing_key_size": "3072",
    "ocsp_signing_algorithm": "SHA256withRSA",
    "ocsp_signing_key_size": "3072",
    "audit_signing_algorithm": "SHA256withRSA",
    "ecc_curve": "nistp256",
}
```

## Template Variables

The configuration template (`ipacta.conf.template`) uses these
substitution variables:

| Variable | Source |
|----------|--------|
| `$REALM` | Kerberos realm |
| `$DOMAIN` | DNS domain (lowercase) |
| `$FQDN` | Fully qualified hostname |
| `$BASEDN` | LDAP base DN |
| `$IPA_CA_CRT` | CA certificate path |
| `$RANDOM_SERIAL_NUMBERS` | `true` or `false` |
| `$CA_SIGNING_ALGORITHM` | CA signing algorithm |
| `$DEFAULT_SIGNING_ALGORITHM` | Default signing algorithm |
| `$CRL_SIGNING_ALGORITHM` | CRL signing algorithm |
| `$AUDIT_SIGNING_ALGORITHM` | Audit signing algorithm |
| `$OCSP_SIGNING_ALGORITHM` | OCSP signing algorithm |
| `$DEFAULT_RSA_KEY_SIZE` | Default RSA key size |
| `$DEFAULT_ECC_CURVE` | Default ECC curve |
| `$OCSP_SIGNING_KEY_SIZE` | OCSP signing key size |
| `$IPACTA_PID` | PID file path |
| `$IPACTA_CERTS_DIR` | Certificates directory |
| `$IPACTA_PRIVATE_DIR` | Private keys directory |
| `$IPACTA_LOG_DIR` | Log directory |

## Certificate Profiles

Certificate profiles control what kind of certificate ipacta issues.
Profiles are `.cfg` files in Java properties format (for Dogtag compatibility).

### Profile Locations

Profiles are loaded from two directories, with the first taking priority:

1. `/usr/share/ipa/profiles/` -- IPA-customized profiles
2. `/usr/share/pki/ca/profiles/ca/` -- Standard PKI profiles (fallback)

At runtime, profiles are stored in LDAP under
`ou=certificateProfiles,ou=ca,o=ipaca` and cached in memory.

### Profile File Format

```ini
profileId=caIPAserviceCert
classId=caEnrollImpl
name=IPA Service Certificate Enrollment
desc=Certificate for IPA services
enabled=true
visible=false
auth.instance_id=raCertAuth

# Inputs
input.list=i1,i2
input.i1.class_id=certReqInputImpl
input.i2.class_id=submitterInfoInputImpl

# Outputs
output.list=o1
output.o1.class_id=certOutputImpl

# Policy set
policyset.list=serverCertSet
policyset.serverCertSet.list=1,2,3,4,5,6,7,8,9,10,11,12

# Each policy has a default (value provider) and constraint (validator):
policyset.serverCertSet.1.constraint.class_id=subjectNameConstraintImpl
policyset.serverCertSet.1.constraint.name=Subject Name Constraint
policyset.serverCertSet.1.constraint.params.pattern=.*
policyset.serverCertSet.1.constraint.params.accept=true
policyset.serverCertSet.1.default.class_id=subjectNameDefaultImpl
policyset.serverCertSet.1.default.name=Subject Name Default
policyset.serverCertSet.1.default.params.name=CN=$request.req_subject_name.cn$,O=$REALM
```

### Variable Substitution

Profiles support two types of variables:

**Configuration variables** (substituted at profile load time):
- `$REALM` -- Kerberos realm
- `$DOMAIN` -- DNS domain
- `$SUBJECT_DN_O` -- `O={realm}`
- `$CRL_ISSUER` -- `CN=Certificate Authority,O={realm}`
- `$IPA_CA_RECORD` -- `ipa-ca.{domain}`

**Request variables** (substituted at signing time):
- `$$request.req_subject_name.cn$$` -- Subject CN from the CSR
- `$$request.field$$` -- Generic request field extraction

### Constraint Plugins

Constraints validate CSR and certificate parameters during issuance.

| Class ID | Purpose | Key Parameters |
|----------|---------|----------------|
| `noConstraintImpl` | No validation | -- |
| `subjectNameConstraintImpl` | Subject DN pattern match | `pattern` (regex), `accept` |
| `validityConstraintImpl` | Validity period limits | `range` (max days), `notBeforeCheck`, `notAfterCheck` |
| `keyConstraintImpl` | Key type and size | `keyType` (RSA/EC), `keyParameters` (comma-separated sizes) |
| `signingAlgConstraintImpl` | Signing algorithm | `signingAlgsAllowed` (comma-separated) |
| `keyUsageExtConstraintImpl` | Key Usage bits | `keyUsageCritical`, `keyUsageDigitalSignature`, etc. |
| `extendedKeyUsageExtConstraintImpl` | Extended Key Usage OIDs | `exKeyUsageOIDs` (comma-separated) |
| `extensionConstraintImpl` | Allowed extensions | `extnIds` (allowed OIDs) |

### Default Plugins

Defaults provide values for certificate fields during issuance.

| Class ID | Purpose | Key Parameters |
|----------|---------|----------------|
| `userKeyDefaultImpl` | Public key from CSR | -- |
| `subjectNameDefaultImpl` | Subject DN with variable substitution | `name` (DN template) |
| `validityDefaultImpl` | Validity period | `range` (days), `startTime` (offset) |
| `signingAlgDefaultImpl` | Signing algorithm | `signingAlg` (`"-"` = config default) |
| `authorityKeyIdentifierExtDefaultImpl` | AKI extension | -- |
| `subjectKeyIdentifierExtDefaultImpl` | SKI extension | `critical` |
| `keyUsageExtDefaultImpl` | Key Usage extension | `keyUsageCritical`, `keyUsageDigitalSignature`, etc. |
| `extendedKeyUsageExtDefaultImpl` | Extended Key Usage | `exKeyUsageCritical`, `exKeyUsageOIDs` |
| `crlDistributionPointsExtDefaultImpl` | CRL Distribution Points | `crlDistPointsCritical`, `crlDistPointsNum`, etc. |
| `authInfoAccessExtDefaultImpl` | Authority Info Access | `authInfoAccessNumADs`, `authInfoAccessADMethod_N`, etc. |
| `userExtensionDefaultImpl` | Copy extension from CSR | `userExtOID` |
| `commonNameToSANDefaultImpl` | CN to SAN copy | -- |
| `sanToCNDefaultImpl` | SAN to CN copy | -- |
| `userSubjectNameDefaultImpl` | Subject name from CSR | -- |
| `ocspNoCheckExtDefaultImpl` | OCSP No Check extension | `critical` |

### Built-in Profiles

ipacta ships with these required profiles:

| Profile ID | Purpose |
|------------|---------|
| `caIPAserviceCert` | IPA service certificates (Apache, LDAP, etc.) |
| `IECUserRoles` | User certificates with IEC roles |
| `KDCs_PKINIT_Certs` | Kerberos KDC PKINIT certificates |
| `acmeIPAServerCert` | ACME-issued server certificates |
| `caSubsystemCert` | CA subsystem certificates |
| `caOCSPCert` | OCSP responder certificates |
| `caSignedLogCert` | Audit log signing certificates |

### Profile Caching and Hot-Reload

Profiles are cached in memory by the `ProfileManager` for performance.
A background `ProfileChangeMonitor` daemon thread polls LDAP every 5 seconds
for changes (using `entryUSN` tracking) and automatically invalidates the
cache when profiles are added, modified, or deleted.

The monitor reconnects automatically with a 1-second backoff on LDAP
connection failure.

### Profile Aliases

The profile manager supports aliases for backward compatibility:

- `caServerCert` -> `caIPAserviceCert`

## Global Configuration Singleton

At runtime, ipacta uses a thread-safe global configuration singleton:

```python
from ipacta import set_global_config, get_global_config, get_config_value, load_config

# Set during backend initialization (once)
set_global_config(config)

# Access from any ipacta component
config = get_global_config()
realm = config.realm
value = config.get("ca", "default_signing_algorithm")

# Convenience wrapper (raises InvalidCAConfiguration if missing and no default)
pool_max = get_config_value("ldap", "pool_max_connections", default="10")

# Load config from file (delegates to IpactaConfig.from_file())
config = load_config("/etc/ipa/ipacta.conf")
```

If `get_global_config()` is called before initialization, it raises
`CANotInitialized` (fail-fast design).
