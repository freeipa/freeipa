# Certificate and Profile Handling

This document covers ipacta's certificate lifecycle state machine,
certificate request processing, profile-driven issuance, and the
certificate reload mechanism.

## Certificate Lifecycle

Certificates follow a state machine defined in
`ipacta/certificate/lifecycle.py`. Every state transition is recorded
with a timestamp, principal, and reason, providing a full audit trail.

### States

| State | Terminal | Usable | Description |
|-------|----------|--------|-------------|
| `PENDING` | No | No | Request submitted, not yet issued |
| `VALID` | No | Yes | Active certificate |
| `EXPIRED` | No | No | Past `notAfter` date |
| `ON_HOLD` | No | No | Temporarily suspended (reversible) |
| `REVOKED` | Yes | No | Permanently revoked |
| `SUPERSEDED` | Yes | No | Replaced by a newer certificate |

Terminal states have no outgoing transitions. Only `VALID` certificates
are usable for authentication or signing.

### State Transitions

```
PENDING ──ISSUE──> VALID
                     │
            ┌────────┼────────┬──────────┐
            │        │        │          │
         EXPIRE   REVOKE    HOLD     SUPERSEDE
            │        │        │          │
            v        v        v          v
         EXPIRED  REVOKED  ON_HOLD  SUPERSEDED
            │                │
         REVOKE        ┌─────┼─────┐
            │          │     │     │
            v       RELEASE REVOKE EXPIRE
         REVOKED       │     │     │
                       v     v     v
                     VALID REVOKED EXPIRED
```

Full transition table:

| From State | Event | To State |
|------------|-------|----------|
| PENDING | ISSUE | VALID |
| VALID | EXPIRE | EXPIRED |
| VALID | REVOKE | REVOKED |
| VALID | HOLD | ON_HOLD |
| VALID | SUPERSEDE | SUPERSEDED |
| ON_HOLD | RELEASE | VALID |
| ON_HOLD | REVOKE | REVOKED |
| ON_HOLD | EXPIRE | EXPIRED |
| EXPIRED | REVOKE | REVOKED |
| REVOKED | (none) | -- |
| SUPERSEDED | (none) | -- |

### Events

| Event | Description |
|-------|-------------|
| `ISSUE` | Issue certificate from a pending request |
| `EXPIRE` | Certificate reaches its `notAfter` date |
| `REVOKE` | Permanently revoke the certificate |
| `HOLD` | Temporarily suspend (Certificate Hold) |
| `RELEASE` | Release from hold, returning to VALID |
| `SUPERSEDE` | Mark as replaced by a newer certificate |

### State Transition Records

Every transition creates a `StateTransition` record:

```python
@dataclass
class StateTransition:
    from_state: CertificateState
    to_state: CertificateState
    event: CertificateEvent
    timestamp: datetime          # UTC
    principal: Optional[str]     # Kerberos principal
    reason: Optional[str]        # Human-readable reason
    serial_number: Optional[int]
```

The full transition history is accessible via
`CertificateLifecycle.get_history()` and serializable via `to_dict()` /
`from_dict()`.

### Revocation Reasons

ipacta supports all RFC 5280 revocation reasons:

| Code | Enum | RFC 5280 Name |
|------|------|---------------|
| 0 | `UNSPECIFIED` | unspecified |
| 1 | `KEY_COMPROMISE` | keyCompromise |
| 2 | `CA_COMPROMISE` | CACompromise |
| 3 | `AFFILIATION_CHANGED` | affiliationChanged |
| 4 | `SUPERSEDED` | superseded |
| 5 | `CESSATION_OF_OPERATION` | cessationOfOperation |
| 6 | `CERTIFICATE_HOLD` | certificateHold |
| 8 | `REMOVE_FROM_CRL` | removeFromCRL |
| 9 | `PRIVILEGE_WITHDRAWN` | privilegeWithdrawn |
| 10 | `AA_COMPROMISE` | AACompromise |

Reason code 6 (`CERTIFICATE_HOLD`) triggers the `HOLD` event instead of
`REVOKE`, placing the certificate in the `ON_HOLD` state. No other
reason code is special-cased by `CertificateRecord.revoke()`; passing
any reason other than `CERTIFICATE_HOLD` (including code 8,
`REMOVE_FROM_CRL`) results in a normal `REVOKE` event. Taking a
certificate off hold (the `RELEASE` event) is only ever triggered by
the separate `take_certificate_off_hold()` method/event -- it is not
connected to any specific revocation reason code.

## Certificate Requests

Certificate requests are represented by `CertificateRequest`
(`certificate/types.py`):

```python
class CertificateRequest:
    csr: x509.CertificateSigningRequest
    profile: str = "caIPAserviceCert"
    request_id: str              # Auto-generated, monotonic
    status: str = "pending"
    serial_number: Optional[int]
    submitted_at: datetime       # UTC
```

Request IDs are thread-safe, monotonic integers generated per-process.
Fork detection resets the counter to avoid collisions in forked workers.

Sub-CA certificate requests use `CertificateRequest.for_subca(ca_id)`,
which sets the profile to `caSubCACert` and the status to `complete`.

## Certificate Records

A `CertificateRecord` (`certificate/types.py`) binds a certificate to its
lifecycle and request:

```python
class CertificateRecord:
    certificate: x509.Certificate
    serial_number: int
    lifecycle: CertificateLifecycle
    issued_at: datetime
    request_id: str
    profile: str
```

Construction automatically transitions the lifecycle from `PENDING` to
`VALID` via the `ISSUE` event.

Key operations on a record:

| Method | Effect |
|--------|--------|
| `revoke(reason, principal)` | Transition to REVOKED (or ON_HOLD for reason=CERTIFICATE_HOLD) |
| `put_on_hold(principal)` | Transition to ON_HOLD |
| `take_off_hold(principal)` | Transition back to VALID |
| `mark_as_expired(principal)` | Transition to EXPIRED (no error on invalid transition) |
| `supersede(principal, replacement_serial)` | Transition to SUPERSEDED |
| `get_state_history()` | Return all state transitions |

The `status` property maps lifecycle states to `CertificateStatus` values
for backward compatibility with code that expects the simpler four-value
enum (`VALID`, `EXPIRED`, `REVOKED`, `ON_HOLD`). Both `PENDING` and
`VALID` map to `CertificateStatus.VALID`; `SUPERSEDED` maps to
`CertificateStatus.REVOKED`.

## Certificate Profiles

Profiles control what kind of certificate ipacta issues. The profile
system consists of a parser, manager, constraint plugins, default plugins,
and a change monitor.

### Profile Data Model

A parsed profile (`profile/__init__.py`) contains:

```python
@dataclass
class Profile:
    profile_id: str
    class_id: str                          # e.g. "caEnrollImpl"
    name: str
    description: str
    enabled: bool
    visible: bool
    auth_instance_id: Optional[str]        # e.g. "raCertAuth"
    authz_acl: Optional[str]
    enabled_by: Optional[str]
    inputs: List[InputPlugin]
    outputs: List[OutputPlugin]
    policyset_name: str
    policies: List[PolicyRule]
    raw_config: Dict[str, str]             # Original key=value pairs
```

**Profile utility methods:**

| Method / Property | Description |
|-------------------|-------------|
| `get_policy_by_number(number)` | Look up a `PolicyRule` by its number |
| `get_allowed_signing_algorithms()` | Extract allowed algorithms from signing constraint |
| `get_default_signing_algorithm()` | Extract default algorithm from signing default |
| `validity_days` (property) | Validity period in days from the validity default |
| `validate_csr(csr, context)` | Run all constraints against a CSR, return error list |

Each `PolicyRule` pairs a constraint (validator) with a default
(value provider):

```python
@dataclass
class PolicyRule:
    number: int
    constraint_name: str
    constraint: Constraint                 # Validates CSR / context
    default_name: str
    default: Default                       # Populates certificate fields
```

### Profile Parsing

`ProfileParser` (`profile/parser.py`) reads `.cfg` files in Java
properties format (key=value, one per line). It:

1. Loads all key=value pairs, skipping comments (`#`) and blank lines.
2. Extracts metadata (`profileId`, `classId`, `name`, `desc`, `enabled`,
   `visible`, `auth.instance_id`, `enableBy`).
3. Parses `input.list` and `output.list` into plugin objects.
4. Parses `policyset.list` and each numbered policy in the set. For each
   policy, it instantiates a `Constraint` and a `Default` object from
   their `class_id` using the factory functions.
5. Performs variable substitution (`$REALM`, `$DOMAIN`, etc.) on all
   parameter values. Request-time variables (`$$request.X$$`) are
   protected from premature substitution.

The parser can read from a file path or from a string (`content`
parameter).

### Profile Manager

`ProfileManager` (`profile/manager.py`) is the central entry point for
profile operations:

**Loading priority:**
1. In-memory cache (thread-safe, `RLock`-protected)
2. LDAP storage (`ou=certificateProfiles,ou=ca,o=ipaca`)
3. IPA profiles directory (`/usr/share/ipa/profiles/`)
4. PKI profiles directory (`/usr/share/pki/ca/profiles/ca/`)

**Profile ID validation:** must match `^[a-zA-Z][a-zA-Z0-9_.-]*$`.

**Aliases:** `caServerCert` resolves to `caIPAserviceCert`.

**Required profiles** (installed during deployment):

| Profile ID | Purpose |
|------------|---------|
| `caIPAserviceCert` | IPA service certificates |
| `IECUserRoles` | User certificates with IEC roles |
| `KDCs_PKINIT_Certs` | Kerberos KDC PKINIT certificates |
| `acmeIPAServerCert` | ACME-issued server certificates |
| `caSubsystemCert` | CA subsystem certificates |
| `caOCSPCert` | OCSP responder certificates |
| `caSignedLogCert` | Audit log signing certificates |

**Key operations:**

| Method | Description |
|--------|-------------|
| `get_profile(profile_id)` | Load profile with caching and alias resolution |
| `get_profile_for_signing(profile_id)` | Load profile for certificate issuance |
| `validate_profile_for_csr(profile_id, csr)` | Validate CSR against profile constraints |
| `get_extensions_for_profile(profile_id)` | Extract X.509 extensions for legacy compatibility |
| `store_all_profiles_to_ldap()` | Install required profiles from filesystem to LDAP |
| `create_profile(profile_id, cfg_content)` | Create new profile |
| `update_profile_cfg(profile_id, cfg_content)` | Update existing profile |
| `delete_profile(profile_id)` | Delete profile from LDAP and cache |
| `export_profile_cfg(profile_id)` | Export .cfg content from LDAP |
| `list_profiles(required_only)` | List all or required-only profiles |
| `clear_profile_cache()` | Invalidate entire cache |
| `invalidate_profile(profile_id)` | Invalidate a single cached profile |

**Variable context** (built from `[global]` config section):

| Variable | Value |
|----------|-------|
| `$REALM` | Kerberos realm (e.g. `EXAMPLE.COM`) |
| `$DOMAIN` | DNS domain (e.g. `example.com`) |
| `$IPA_CA_RECORD` | `ipa-ca.{domain}` |
| `$SUBJECT_DN_O` | `O={realm}` |
| `$CRL_ISSUER` | `CN=Certificate Authority,O={realm}` |

### Constraint Plugins

Constraints validate CSR and certificate parameters during issuance.
Each constraint's `validate(csr, context)` method returns a list of
error messages (empty on success).

| Class ID | Class | Validates |
|----------|-------|-----------|
| `noConstraintImpl` | `NoConstraint` | Nothing (always passes) |
| `subjectNameConstraintImpl` | `SubjectNameConstraint` | Subject DN against regex pattern |
| `validityConstraintImpl` | `ValidityConstraint` | Validity period against max range |
| `keyConstraintImpl` | `KeyConstraint` | Key type, size, RSA exponent |
| `signingAlgConstraintImpl` | `SigningAlgConstraint` | Signing algorithm against allowed list |
| `keyUsageExtConstraintImpl` | `KeyUsageExtConstraint` | Key Usage extension bits |
| `extendedKeyUsageExtConstraintImpl` | `ExtendedKeyUsageExtConstraint` | Extended Key Usage OIDs |
| `extensionConstraintImpl` | `ExtensionConstraint` | Allowed extension OIDs |

`KeyConstraint` also enforces global limits from the `[ca]` config
section: `min_rsa_key_size` (default 2048), `max_rsa_key_size`
(default 8192), and `allowed_rsa_exponents` (default 65537).

### Default Plugins

Defaults populate certificate fields during issuance. Each default's
`apply(builder, csr, context)` method adds extensions or sets fields on
the certificate builder and may write values into the `context` dict for
downstream constraints or defaults to reference.

| Class ID | Class | Provides |
|----------|-------|----------|
| `userKeyDefaultImpl` | `UserKeyDefault` | Public key from CSR |
| `subjectNameDefaultImpl` | `SubjectNameDefault` | Subject DN with variable substitution |
| `validityDefaultImpl` | `ValidityDefault` | notBefore / notAfter dates |
| `signingAlgDefaultImpl` | `SigningAlgDefault` | Signing algorithm selection |
| `authorityKeyIdentifierExtDefaultImpl` | `AuthorityKeyIdentifierExtDefault` | AKI extension |
| `subjectKeyIdentifierExtDefaultImpl` | `SubjectKeyIdentifierExtDefault` | SKI extension |
| `keyUsageExtDefaultImpl` | `KeyUsageExtDefault` | Key Usage extension |
| `extendedKeyUsageExtDefaultImpl` | `ExtendedKeyUsageExtDefault` | Extended Key Usage extension |
| `crlDistributionPointsExtDefaultImpl` | `CRLDistributionPointsExtDefault` | CRL Distribution Points |
| `authInfoAccessExtDefaultImpl` | `AuthInfoAccessExtDefault` | Authority Info Access (OCSP URI) |
| `userExtensionDefaultImpl` | `UserExtensionDefault` | Copy extension from CSR by OID |
| `commonNameToSANDefaultImpl` | `CommonNameToSANDefault` | Copy CN to Subject Alternative Name |
| `sanToCNDefaultImpl` | `SANToCNDefault` | Copy first SAN DNS name to CN |
| `userSubjectNameDefaultImpl` | `UserSubjectNameDefault` | Subject name directly from CSR |
| `ocspNoCheckExtDefaultImpl` | `OCSPNoCheckExtDefault` | OCSP No Check extension |

`SigningAlgDefault` handles the special value `"-"` by consulting the
config's `default_signing_algorithm` setting. If that is also absent, it
infers the algorithm from the CSR key type.

Both constraint and default factories fall back gracefully: unknown
`class_id` values produce `NoConstraint` or `UserKeyDefault` respectively,
with a warning log.

### Policy Chain Execution

When issuing a certificate, the policy chain runs in order:

1. For each `PolicyRule` (sorted by `number`):
   a. `default.apply(builder, csr, context)` -- populates the builder
      and writes values into `context`.
   b. `constraint.validate(csr, context)` -- validates against the values
      that defaults have set.
2. If any constraint returns errors, issuance is rejected with a
   `ValueError` raised by `_execute_policy_chain()`.
3. If all constraints pass, the builder is signed with the CA key.

The `context` dict is shared across all policy rules in the chain,
allowing later rules to reference values set by earlier ones
(e.g. `context["final_subject_dn"]`, `context["validity_days"]`,
`context["signing_algorithm"]`, `context["key_usage"]`,
`context["extended_key_usage"]`, `context["extensions_added"]`).

### Profile Change Monitoring

`ProfileChangeMonitor` (`profile/monitor.py`) is a daemon thread that
detects profile changes in LDAP and invalidates the cache:

- **Polling interval:** 5 seconds
- **Change detection:** Compares `entryUSN` values from LDAP
- **Operations detected:** ADD, MODIFY, DELETE
- **Search base:** `ou=certificateProfiles,ou=ca,o=ipaca`
- **Search filter:** `(objectClass=certProfile)`
- **Tracked attributes:** `cn`, `entryUSN`, `nsUniqueId`
- **Reconnection:** 1-second delay on LDAP connection failure

When a change is detected:
- **ADD/MODIFY:** Updates the tracked `entryUSN` and calls
  `invalidate_profile()` on the manager, forcing a re-parse on next
  access.
- **DELETE:** Removes the profile from tracking and calls
  `remove_profile()` to clear it from the cache.

## Certificate Reload

`CertificateReloadManager` (`certificate/reload_manager.py`) handles
hot-reload of CA certificates without service restart.

**Trigger:** `SIGHUP` signal to the ipacta process.

**Reload sequence:**

The design is deliberately two-part for async-signal-safety: the
signal handler only sets a `threading.Event` (safe to call from a
signal handler context), and a separate background watcher thread
waits on that event and performs the actual reload.

1. The `SIGHUP` handler (`_handle_reload_signal`) sets a
   `threading.Event` and returns immediately -- it never calls
   `reload_certificates()` directly and never acquires a lock.
2. A background watcher thread (`_watcher_loop`), started when the
   signal handler is registered, waits on the event and, once set,
   clears it and calls `reload_certificates()`.
3. Under a lock (prevents concurrent reloads):
   a. Load CA certificate and private key from disk.
   b. Verify the certificate and key match (compare serialized public
      keys).
   c. Atomically update `ca.ca_cert` and `ca.ca_private_key`.
   d. Log old and new serial numbers.
4. Return a status dict: `{"status": "success"|"partial"|"error",
   "reloaded": [...], "errors": [...]}`.

**SSL certificate validation** (`reload_server_ssl_cert`) validates a
server cert/key pair from disk but does not update the running Gunicorn
process. A full Gunicorn graceful restart (USR2 signal) is required for
TLS certificate changes.

The reload manager is a global singleton, accessed via
`get_reload_manager()`.
