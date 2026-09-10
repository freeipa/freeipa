# ipacta Overview

ipacta is a pure-Python Certificate Authority implementation for FreeIPA.
It replaces the Dogtag PKI (Java-based) subsystem with a lightweight CA built
on the `python-cryptography` library, providing the same functionality with
fewer dependencies and tighter integration into FreeIPA's Python codebase.

## Architecture

### Process Isolation

ipacta enforces strict process isolation to protect CA private keys:

```
   httpd (apache user)
     |
     |  ipaserver/plugins/dogtag.py
     |  (REST client -- no access to private keys)
     v
   HTTPS REST API
     |
     v
   ipacta.service (ipaca user)
     |
     |  rest_api/ --> backend.py --> ca.py / ca_internal.py
     |  (Flask app with access to CA private keys)
     v
   LDAP (storage)
```

- **httpd** runs as the `apache` user and communicates with ipacta
  exclusively through the REST API over HTTPS. It never loads `backend.py`
  or any module that touches private keys.
- **ipacta.service** runs as the `ipaca` user under systemd. It owns the
  CA signing keys, serves the REST API, and persists all state to LDAP.

### Module Map

```
ipacta/
  __init__.py            Global config singleton
  config.py              IpactaConfig (install + runtime)
  backend.py             PythonCABackend (Dogtag drop-in replacement)
  ca.py                  PythonCA -- core signing engine
  ca_internal.py         InternalCA -- adds audit + principal tracking
  subca.py               Subordinate (lightweight) CA support
  wsgi.py                WSGI/Gunicorn entry point
  gunicorn_conf.py       Gunicorn hooks (post_fork, when_ready, worker_exit)
  exceptions.py          Structured exception hierarchy
  rate_limit.py          Sliding-window rate limiter (ACME, OCSP)
  resource_tracker.py    Process resource usage tracking

  certificate/           Certificate lifecycle
    types.py               CertificateStatus, RevocationReason enums
    lifecycle.py           State machine (Valid -> Revoked, Hold, etc.)
    reload_manager.py      Hot-reload on SIGHUP

  profile/               Certificate profile management
    parser.py              .cfg profile file parser
    manager.py             Profile loading, caching, aliases
    defaults.py            Default plugin classes (value providers, e.g.
                            UserKeyDefault, SubjectNameDefault)
    constraints.py         CSR validation against profiles
    monitor.py             LDAP-based hot-reload
    # Built-in profile .cfg files live under install/share/profiles/
    # (e.g. install/share/profiles/caIPAserviceCert.cfg), not in this
    # package.

  storage/               LDAP persistence layer
    base.py                Connection pooling, schema init
    factory.py             Storage backend factory
    certificates.py        Certificate persistence
    ca.py                  CA metadata storage
    crl.py                 CRL storage
    subca.py               Sub-CA storage
    profiles.py            Profile storage
    ranges.py              Serial number range management
    acme.py                ACME order/challenge state
    kra.py                 KRA key storage
    hsm.py                 HSM config storage
    maintenance.py         Pruning and validation

  rest_api/              Flask REST API
    __init__.py            App factory, blueprint auto-discovery
    _globals.py            Shared backend instances
    _helpers.py            Error response formatting, auth decorators
    _utils.py              Request parsing utilities
    ca_core.py             CA status, account, security domain
    certs.py               Certificate CRUD + search
    crl_ocsp.py            CRL distribution, OCSP responder
    acme.py                RFC 8555 ACME endpoints
    profiles.py            Profile CRUD
    authorities.py         Lightweight CA management
    kra.py                 Key Recovery Authority
    hsm.py                 HSM management
    ranges.py              Serial number range allocation
    debug.py               Debug/diagnostics (resource snapshots, GC)

  acme.py                ACMEServer (RFC 8555 protocol)
  acme_state.py          ACME state management
  audit.py               Audit logging
  hsm.py                 HSM (PKCS#11) integration
  kra.py                 Key Recovery Authority
  key_encryption.py      Key wrapping/unwrapping
  key_escrow.py          Key escrow
  key_utils.py           Private key generation (used by nss_utils.py and
                          profile/defaults.py)
  ocsp.py                OCSP response generation
  pruning.py             Certificate/request pruning
  ldap_utils.py          LDAP connection pool
  nss_utils.py           NSS database utilities
  x509_utils.py          X.509 helpers
  jwk.py                 JSON Web Key (ACME)

  install/               FreeIPA installer integration
    certs.py               Certificate generation
    db.py                  NSS database setup
    ldap_setup.py          LDAP schema/data init
    service_mgmt.py        systemd service management
    acme.py                ACME feature setup
    kra.py                 KRA feature setup
    lwca.py                Lightweight CA setup
    replica.py             Replica configuration
    _utils.py              Installer utilities
```

### Core Components

#### PythonCA (`ca.py`)

The minimal CA engine. Handles:

- Certificate signing from CSR + profile
- Certificate revocation (revoke, hold, unhold)
- CRL generation (scheduled and on-demand)
- Serial number generation (sequential or random 128-bit)
- LDAP storage backend

This class is intentionally lean. It does not include audit logging or
principal tracking.

#### InternalCA (`ca_internal.py`)

Extends `PythonCA` for production use. Adds:

- Comprehensive audit logging (every signing/revocation event)
- Principal (Kerberos) tracking for authorization decisions
- LDAP schema initialization
- Sub-CA lifecycle management

#### PythonCABackend (`backend.py`)

The top-level entry point that ties everything together. Implements the same
interface as FreeIPA's existing Dogtag integration so that
`ipaserver/plugins/dogtag.py` can switch between backends without code
changes. Manages:

- Global config initialization
- `InternalCA` instance
- `ProfileManager` for certificate profiles
- Lazy-initialized subsystems (ACME, pruning)

#### Storage Layer (`storage/`)

All persistent state lives in LDAP under `o=ipaca`. The storage layer
provides:

- Connection pooling (`base.py`, `ldap_utils.py`)
- Per-entity modules (certificates, CRLs, profiles, serial ranges, etc.)
- Atomic operations where LDAP supports them
- Factory pattern for storage backend selection

#### REST API (`rest_api/`)

A Flask application that exposes the PKI REST API. Blueprints are
auto-discovered at import time via `pkgutil.iter_modules()`. The API
is Dogtag-compatible: FreeIPA's existing `dogtag.py` client works
without modification.

Authentication uses mutual TLS (client certificate with `CN=IPA RA`).

#### Profile System (`profile/`)

Certificate profiles define what kind of certificate to issue. Each profile
specifies:

- Subject DN template
- Validity period
- Key constraints (type, size)
- Extensions (Key Usage, EKU, SAN, AIA, CRL Distribution Points)
- Signing algorithm

Profiles are stored as `.cfg` files (Java properties format for Dogtag
compatibility) and cached in memory. A background monitor thread watches
LDAP for changes and invalidates the cache automatically.

### Key Design Principles

1. **Drop-in replacement** -- ipacta implements the same REST API as
   Dogtag PKI. The `ipaserver/plugins/dogtag.py` client works without
   modification.

2. **LDAP-native** -- All state is persisted in LDAP. No external database
   or file-based storage is required beyond the configuration file.

3. **Process isolation** -- The CA backend runs in a dedicated systemd
   service (`ipacta.service`) as the `ipaca` user. httpd never loads
   modules that access private keys.

4. **Python-only** -- Built on `python-cryptography`. No Java, no Tomcat,
   no NSS for signing operations.

5. **Profile-driven** -- Certificate issuance is controlled by profiles
   with constraints and defaults, matching Dogtag's profile system.

6. **RFC-compliant** -- ACME (RFC 8555), OCSP (RFC 6960), X.509 (RFC 5280),
   CRL (RFC 5280).

7. **Audit-ready** -- Every signing and revocation event is logged with
   principal, timestamp, and operation details.

8. **HSM-capable** -- Optional PKCS#11 Hardware Security Module support for
   CA key protection.

## Exception Hierarchy

```
IpactaError
  InvalidStateTransition
  CertificateLifecycleError
  StorageError
    CertificateNotFound
    ProfileNotFound
    StorageConnectionError
    StoragePermissionError
  CertificateRequestError
    InvalidCertificateRequest
    InvalidCSRFormat
    UnsupportedKeyType
  CertificateOperationError
  ProfileError
    ProfileValidationError
    CircularProfileInheritance
    ProfileAlreadyExists
  CAConfigurationError
    CANotInitialized
    InvalidCAConfiguration

ExternalCAStep1Complete (BaseException)
```

`InvalidStateTransition` and `CertificateLifecycleError` are sibling
classes -- both extend `IpactaError` directly.

`ExternalCAStep1Complete` inherits `BaseException` (not `Exception`) so
that broad `except Exception` blocks cannot accidentally swallow the
control-flow signal during external CA CSR generation.

All `IpactaError` subclasses support `to_dict()` for structured API
error responses. The module also provides `format_error_response()` to
wrap an exception into a dict with an HTTP status code.

## File System Layout

| Path | Purpose |
|------|---------|
| `/etc/ipa/ipacta.conf` | Main configuration file |
| `/var/lib/ipacta/` | Working directory |
| `/var/lib/ipacta/ca/` | CA certificates and keys |
| `/var/lib/ipacta/ca/subcas/` | Sub-CA key material |
| `/var/lib/ipacta/certs/` | Server certificates |
| `/var/lib/ipacta/private/` | Private keys |
| `/var/lib/ipacta/audit/` | Audit log signing keys |
| `/var/log/ipacta/` | Log files |
| `/run/ipacta/ipacta.pid` | PID file |
| `/usr/share/ipa/profiles/` | Certificate profile files |

## Dependencies

- **python-cryptography** -- X.509, signing, key generation
- **python-flask** -- REST API framework
- **python-gunicorn** -- WSGI server
- **python-ldap** -- LDAP client
- **ipaplatform** -- FreeIPA platform abstraction

## Integration with FreeIPA

ipacta integrates with FreeIPA at two points:

1. **Installation** (`ipaserver/install/ipactainstance.py`) --
   `IpactaInstance` is a `service.Service` subclass that handles
   CA deployment during `ipa-server-install` and `ipa-replica-install`.
   It uses composition with helper classes (`NSSDB`, `Certs`,
   `LDAPSetup`, `ServiceMgmt`, etc.) from `ipacta/install/`.

2. **Runtime** (`ipaserver/plugins/dogtag.py`) -- The existing Dogtag
   client plugin communicates with ipacta over HTTPS using the same
   REST API that Dogtag exposes. No changes to the client are required.

## Service Management

ipacta runs as a systemd service (`Type=notify`):

```
[Unit]
Description=IPA thin CA Service
After=network.target dirsrv.target
Wants=dirsrv.target
Conflicts=pki-tomcatd@pki-tomcat.service

[Service]
Type=notify
NotifyAccess=main
User=ipaca
Group=ipaca
Environment=LC_ALL=C.UTF-8
WorkingDirectory=/var/lib/ipacta/
RuntimeDirectory=ipacta
RuntimeDirectoryMode=0755
LogsDirectory=ipacta
LogsDirectoryMode=0750
ExecStart=$SBIN_DIR/ipacta --foreground
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ipacta /var/lib/ipa/pki-ca/publish /etc/pki/pki-tomcat/alias
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
```

The service uses `Type=notify` -- systemd considers it "started" only
after the Gunicorn arbiter sends `READY=1` via `sd_notify`
(`gunicorn_conf.when_ready()`). The `Wants=dirsrv.target` ensures
Directory Server is started alongside the CA.

The service conflicts with `pki-tomcatd@pki-tomcat.service` to ensure
mutual exclusion with Dogtag.

Sending `SIGHUP` to the service triggers a graceful certificate reload
without restarting.

### Gunicorn Process Model

ipacta uses Gunicorn as its WSGI server. The `gunicorn_conf.py`
module provides lifecycle hooks:

- **`post_fork`** -- Reinitialises the LDAP connection pool (not
  fork-safe), reopens all `FileHandler` log streams so workers get
  independent file descriptions, and starts a per-worker rate-limiter
  purge thread.
- **`when_ready`** -- Sends `READY=1` to the systemd notify socket.
- **`worker_exit`** -- Closes the LDAP connection pool in the exiting
  worker.

### Rate Limiting

A sliding-window rate limiter (`rate_limit.py`) protects ACME and OCSP
endpoints from DoS. Each limiter is keyed by client IP. Pre-configured
instances:

| Limiter | Limit | Window |
|---------|-------|--------|
| `acme_new_account` | 20 | 1 hour |
| `acme_new_order` | 60 | 1 minute |
| `acme_revoke` | 10 | 1 minute |
| `acme_general` | 120 | 1 minute |
| `ocsp` | 600 | 1 minute |

When a limit is exceeded, the endpoint returns HTTP 429 with a
`Retry-After` header and an ACME-compatible JSON error body.

Stale rate-limiter buckets are purged every 5 minutes by a daemon thread
started in each Gunicorn worker (`gunicorn_conf._start_rate_limiter_purge`).

### Resource Tracking

The `resource_tracker.py` module captures process-level resource usage
snapshots for memory-leak analysis:

- RSS / VMS (from `/proc/self/status`)
- Open file descriptor count
- Active thread count
- GC generation object counts
- LDAP connection pool statistics
- `tracemalloc` top-N allocation sites (opt-in)

Enable via `[debug] resource_log_interval` in `ipacta.conf` or the
debug REST endpoints (`/ca/rest/debug/resources`,
`/ca/rest/debug/gc`).
