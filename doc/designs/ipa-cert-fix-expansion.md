# ipa-cert-fix Expansion: Multi-Scenario Certificate Recovery

## Overview

The `ipa-cert-fix` tool was originally designed to handle only one scenario: recovering a CA renewal master when expired certificates prevent normal operation.  It runs `pki-server cert-fix` to regenerate Dogtag subsystem certificates and installs renewed IPA service certificates.

This design is insufficient for real-world deployments where:

- Non-renewal-master CA replicas have expired certificates but the renewal master is healthy and reachable.
- CA-less replicas have only IPA service certificates (HTTP, LDAP, KDC, RA) and no local PKI.
- Some service certificates are signed by an external CA rather than the internal IPA CA.
- The renewal master is permanently unavailable and another CA replica must take over.

Running the original `ipa-cert-fix` on a non-renewal-master replica was potentially destructive: while it did not change the IPA renewal master configuration, it effectively acted as a renewal master by using `pki-server cert-fix` to regenerate all shared PKI certificates (subsystem, OCSP, audit signing, etc.) locally instead of fetching them from the actual renewal master.  These locally-regenerated certs would then conflict with the ones managed by the real renewal master, potentially disrupting certificate replication across the topology.

This expansion extends `ipa-cert-fix` to auto-detect the deployment type and choose the least-invasive fix path.  It adds non-destructive recovery for replicas by fetching certificates from a working master, and handles external certificates by generating CSRs or offering transition to the internal CA.

## Use Cases

1. **Renewal master with expired certs** -- existing use case.  The CA signing certificate must still be valid (at least one month remaining); other Dogtag and IPA service certificates are renewed via `pki-server cert-fix`.

2. **CA-full replica with working master** -- the replica fetches the CA chain, RA and shared certificates from the master's LDAP, then uses certmonger to renew expired service certificates through the master's CA.  No `pki-server cert-fix` is needed, and the renewal master role is preserved.

3. **CA-full replica, renewal master unrecoverable** -- the administrator explicitly promotes this replica to renewal master, then certificates are renewed using `pki-server cert-fix`.  CRL generation must be enabled manually afterward.

4. **CA-less replica with CA servers in topology** -- similar to use case 2 but without Dogtag certificates.  Only RA, HTTP, LDAP, and KDC certificates are renewed through a remote CA server.

5. **Externally-signed certificates** -- certificates signed by a CA other than the IPA CA cannot be renewed automatically.  The tool offers per-cert transition to the internal CA (if available) or generates CSR files and prints instructions for manual renewal.

## Design

### Deployment Detection

On startup, `ipa-cert-fix` classifies the local replica into one of four deployment types:

| Deployment Type | Condition |
|---|---|
| `CA_SELF_SIGNED` | CA installed locally, caSigningCert is self-signed |
| `CA_EXTERNALLY_SIGNED` | CA installed locally, caSigningCert issued by external CA |
| `CA_LESS` | No local CA, but CA servers exist in the topology |
| `CA_LESS_EXTERNAL` | No local CA, no CA servers in the topology |

When some service certs (HTTP, LDAP, KDC) are signed by an external CA while the CA itself is internal, the deployment is still classified as `CA_SELF_SIGNED` or `CA_EXTERNALLY_SIGNED`.  The externally-signed service certs are captured in `CertFixContext.external_certs` and handled separately by each scenario handler (offered for transition to internal CA or CSR generation).

Detection uses:
- `cainstance.is_ca_installed_locally()` to check for local PKI
- `find_providing_servers('CA', ...)` to discover CA servers in the topology
- Comparison of `caSigningCert` issuer and subject DNs for self-signed detection
- `is_ipa_issued_cert(api, cert)` on each service certificate for external detection

### Fix Scenarios

Based on the deployment type, renewal master status, and CLI options, one of five fix scenarios is selected:

| Scenario | Entry Condition | Actions |
|---|---|---|
| `RENEWAL_MASTER` | CA-full + is renewal master (or `--renewal-master`) | `pki-server cert-fix`, install certs, become RM, restart |
| `CA_FULL_WITH_MASTER` | CA-full + not RM + working master found | Fetch CA chain + RA + shared certs from master, renew server-specific via certmonger, restart, resubmit |
| `CA_FULL_PROMOTE` | CA-full + not RM + no working master | Promote to RM, then renew certs via `pki-server cert-fix` |
| `CA_LESS_WITH_MASTER` | CA-less + CA servers in topology | Fetch CA chain + RA from master, renew HTTP/LDAP/KDC via certmonger, restart |
| `EXTERNAL_CERTS` | CA-less + no CA servers, or only external certs | Generate CSRs and print manual renewal instructions (transition offered only if CA servers exist in topology) |

### CLI Options

| Option | Description |
|---|---|
| `--force-server=FQDN` | Use this server as the master to fetch certificates from |
| `--renewal-master` | Force this server to become the renewal master |
| `--dry-run` | Print intended actions without executing |
| `-U, --unattended` | Non-interactive mode, never prompt the user |

Existing options (`--verbose`, `--quiet`, `--log-file`, `--help`, `--version`) are preserved from the base `AdminTool` class.

Option validation:
- `--renewal-master` and `--force-server` are mutually exclusive (caught in `validate_options`).
- `--renewal-master` on a CA-less replica is rejected in `determine_scenario` (no local CA to become renewal master of).  The `RuntimeError` is caught by `_detect_and_dispatch` and printed as a clean error with exit code 1.

### Master Server Selection

When the tool needs a master server (replica and CA-less paths), it determines one as follows:

1. If `--force-server=FQDN` is given, use it (after reachability check).
2. Otherwise, look up the current renewal master from LDAP.  If found and it is not this server, use it as the default.
3. If no renewal master is found, discover CA servers in the topology and use the first one as the default.
4. In interactive mode, prompt the user with the default pre-filled.  The user can accept it (press Enter) or type a different FQDN.  Leaving the prompt empty (only possible when no default exists) returns `None` -- the caller routes to `CA_FULL_PROMOTE` (CA-full) or `EXTERNAL_CERTS` (CA-less).
5. In unattended mode (`-U`), the default is used automatically.  If no default exists, returns `None`.  For CA-full, `CA_FULL_PROMOTE` requires explicit `--renewal-master` in unattended mode (refuses silent promotion).

### Certificate Classification

Expired certificates are classified into three categories:

- **Dogtag certificates** -- PKI subsystem certs in the Tomcat NSS database (caSigningCert, Server-Cert, subsystemCert, ocspSigningCert, auditSigningCert, KRA certs).  Only present on CA-full replicas.
- **IPA certificates** -- service certs issued by the internal IPA CA (HTTP, LDAP, KDC, RA).
- **External certificates** -- service certs whose issuer does not match the IPA CA.  Detected by `is_ipa_issued_cert()` returning `False`.

The two-week lookahead threshold is preserved from the original implementation: certificates expiring within two weeks are treated as expired.

### RA and Subsystem LDAP Consistency

On CA-full replicas, the RA certificate on disk (`ra-agent.pem`) and the subsystem certificate in the PKI NSSDB must match their corresponding `ou=People,o=ipaca` LDAP entries (`uid=ipara` and `uid=pkidbuser`).  Both the `userCertificate` blob and the `description` field (which contains the serial number in `2;<serial>;<issuer>;<subject>` format) must be consistent.  Mismatches cause Dogtag authentication failures even when the certificates themselves are valid.

This is a common failure mode — for example, a prior `ipa-cert-fix` crash or interrupted replication can leave the LDAP entry with a stale serial or missing cert blob.

The consistency check compares all cert copies (local filesystem/NSSDB and LDAP blobs) and picks the **newest** one (by `notAfter`) as authoritative.  If the local cert is older than the LDAP blob, the local file/NSSDB is updated to match LDAP — not the other way around.  This prevents a stale local cert from overwriting a correctly-replicated LDAP entry and disrupting other servers in the topology.  Only the LDAP `description` field (serial number) is updated to match the newest cert, and only if the newest cert blob is already present in LDAP.

`_detect_ra_subsystem_mismatches` runs on CA-full deployments at two points, but never both in the same invocation:

1. **When no certs are expired** ("Nothing to do" scenario) — catches mismatches that cause authentication failures even with valid certs.  Prints what would be fixed and asks for confirmation (interactive mode), fixes automatically (unattended), or prints dry-run info.

2. **After a fix scenario completes** — verifies that certs fetched or renewed during the fix landed in LDAP correctly.  This is the only check when certs are expired, because fixing LDAP before the scenario runs would be pointless — the scenario fetches new certs that supersede the current ones.

### Certmonger Integration

For non-renewal-master scenarios, only **server-specific** certificates (sslserver, HTTP, LDAP, KDC) are renewed through certmonger.  **Shared** certificates (subsystem, OCSP, audit signing, KRA certs) are fetched directly from the master's LDAP `cn=ca_renewal` entries and installed into the local NSSDB — see [Shared vs Server-Specific Certificate Handling](#shared-vs-server-specific-certificate-handling) for details.

For the server-specific certs, the tool temporarily modifies the IPA CA helper in certmonger to point renewal requests at the master server.  This is done by appending `-J https://<master>/ipa/json` to the IPA CA helper command, which overrides the JSON-RPC endpoint that `ipa-submit` uses.

The flow for each server-specific expired certificate:

1. Look up the certmonger tracking request by certificate location criteria.
2. For Dogtag certs (sslserver): temporarily switch the CA from `dogtag-ipa-ca-renew-agent` to `IPA`, add a host principal, and override the profile to `caIPAserviceCert`.
3. Resubmit the request through the modified IPA CA helper.
4. Wait for certmonger to reach `MONITORING` state (timeout: 300 seconds).
5. Wait for certmonger to become D-Bus responsive again (post-save commands like `renew_ca_cert` may restart PKI, blocking certmonger temporarily).
6. Verify the renewed certificate has a different serial number.

All modifications are restored in a `finally` block: the original CA helper, CA assignment, profile, and temporary principals are reverted regardless of success or failure.

### External Certificate Handling

When externally-signed certificates are detected:

1. If an internal CA exists in the topology, the user is offered a per-cert choice to transition to the internal CA.  Externally-signed certificates typically have no certmonger tracking request (tracking is stopped when a cert is installed externally).  Transition is performed by:
   - Stopping any existing tracking for the certificate.
   - Creating a new certmonger tracking request with the correct IPA parameters (CA name, profile, post-save command), mirroring what `httpinstance.py`, `dsinstance.py`, and `krbinstance.py` use during server installation.
   - If a master server is available (replica scenarios), the IPA CA helper is temporarily overridden to point at the master so that certmonger can obtain the new certificate immediately.
   - Waiting for certmonger to reach `MONITORING` state.

2. For certificates not transitioned (or when no internal CA exists), the tool generates a CSR and writes it to `/run/ipa/cert-fix/<type>.csr`.  CSR generation tries three sources in order:
   - Extract existing CSR from certmonger tracking request (if tracking is still active).
   - Generate a new CSR from the existing private key and the expired certificate's subject/SANs.  For file-based keys (HTTP, KDC), uses the `cryptography` library.  For NSSDB keys (LDAP), uses `certutil -R`.
   - If neither works, prints manual instructions.

   Along with the CSR files, the tool prints the corresponding `ipa-server-certinstall` commands for each certificate type.

On `CA_LESS_EXTERNAL` deployments (no internal CA anywhere in the topology), transitions are not possible -- the tool skips the CA server lookup entirely and proceeds directly to CSR generation.  Installing an internal CA via `ipa-ca-install` is outside the scope of this tool and requires valid HTTP/LDAP certificates first.

In unattended mode, no transitions are offered -- only CSR generation.

### HSM Support

When PKI is configured with an HSM (Hardware Security Module), the private keys for Dogtag subsystem certificates (caSigningCert, subsystemCert, ocspSigningCert, auditSigningCert) reside on the HSM token rather than in the software NSSDB.  Service certificates (HTTP, LDAP, KDC) are always in software and are not affected.

On startup, `ipa-cert-fix` detects HSM configuration via `CAInstance().hsm_enabled` and stores the token name in `CertFixContext.hsm_token_name`.  This affects:

- **Renewal master path**: `pki-server cert-fix` handles HSM internally (reads token config from CS.cfg).  No changes needed.
- **Replica path**: certmonger tracking requests for Dogtag certs already include the HSM token (configured during installation).  The resubmit path reuses the existing tracking configuration.
- **CSR generation**: `certutil -K` and `certutil -R` receive `-h <token>` to access keys on the HSM token.
- **Cert transition**: `certmonger.start_tracking` receives `token_name` for any new tracking requests.

The Server-Cert (`sslserver`) always uses the internal token, even on HSM deployments.

### Error Handling and Safeguards

- **LDAP via LDAPI**: All local LDAP operations use the UNIX socket, which does not require TLS and works even with expired certificates.
- **Kerberos from host keytab**: Remote operations use `KRB5_CLIENT_KTNAME` with the host keytab and an in-memory ccache.
- **certmonger responsiveness**: A wait loop with configurable timeout checks that certmonger is responsive on D-Bus before modifying helpers.  Certmonger is NOT automatically restarted (restarting triggers renewal attempts on all tracked certs, interfering with the controlled renewal flow).
- **LDAP reconnection**: `_ensure_ldap_connected()` unconditionally disconnects and reconnects the `ldap2` backend.  Called after every operation that may restart Directory Server: `ipa-certupdate`, `pki-server cert-fix`, `ipactl restart`, and before `set_renewal_master()`.
- **ipa-certupdate skip**: Before running `ipa-certupdate`, `update_ca_cert_from_master` checks two conditions: (1) the local CA chain (`/etc/ipa/ca.crt`) is present and valid (no expired certs in the trust path), and (2) a TLS handshake to the master's port 443 succeeds using the local CA trust store.  If both pass, `ipa-certupdate` is skipped entirely, avoiding unnecessary service restarts and certmonger D-Bus disruption.  If the chain is valid but TLS fails (e.g. the master's CA cert was renewed and the local trust store is stale), `ipa-certupdate` runs to update the trust store.
- **ipa-certupdate tolerance**: When `ipa-certupdate` does run, a non-zero exit code is tolerated if the CA chain is present and contains no expired certificates.  The exit code is often non-zero due to service restart failures or certmonger D-Bus timeouts, which are expected with expired certs.  If the CA chain is missing or contains expired certs, the tool fails with instructions to fix the master first or manually copy `ca.crt`.
- **Duplicate-subject CA certs**: After CA renewal, `ca.crt` may contain both old (expired) and new (valid) CA certificates with the same subject DN.  The chain validator builds the subject-to-cert map by preferring the cert with the latest `notAfter`, so a valid chain is not rejected because the expired copy happens to appear later in the file.
- **pki-server cert-fix tolerance**: `CalledProcessError` is tolerated if the DS cert was expired (PKI restart fails) but renewed cert files exist on disk.
- **Post-renewal CA verification**: After `pki-server cert-fix` renews the CA signing cert, it is re-checked for validity.  If still expired (partial failure), the tool exits with instructions to use `ipa-cacert-manage`.
- **Externally-signed CA protection**: On `CA_EXTERNALLY_SIGNED` deployments, the `ca_issuing` cert is filtered out of the `pki-server cert-fix` arguments.  This prevents `pki-server cert-fix` from regenerating the CA cert as self-signed, which would silently overwrite the external CA chain.
- **IPA restart tolerance**: `ipactl restart` uses `--ignore-service-failures` in all scenarios because certmonger post-save commands may have already restarted individual services.
- **Resubmit safety**: `resubmit_expired_certs()` uses explicit skip/error state sets to avoid interfering with certs that certmonger is already processing (SUBMITTING, CA_WORKING, etc.).  Only certs in error states (CA_UNREACHABLE, CA_REJECTED, etc.) are resubmitted.
- **Fetched cert validation**: Every certificate fetched from the master (RA and all shared dogtag certs) is checked for expiry before installation.  If the master's cert is also expired, the tool fails with a clear message directing the administrator to fix the master first.
- **Certmonger timeout after restart**: After the final `ipactl restart`, certmonger unresponsiveness is non-fatal (certs are already installed, services restarted).  The tool prints a warning and skips `resubmit_expired_certs`.  Mid-renewal timeouts (inside `_resubmit_cert_via_master` or `_transition_cert`) remain fatal since certmonger must be responsive to proceed.
- **Renewal master detection resilience**: `check_is_renewal_master` guards against `None` CA instance (CA-less deployments) and catches LDAP errors broadly so that unexpected LDAP failures on broken systems fall through to the non-RM path rather than crashing the tool.
- **renew_certs_from_master returns only successful IDs**: `resubmit_expired_certs` receives only the IDs of successfully renewed certs, so failed certs get a second chance during the resubmit pass.
- **Always-restore**: The IPA CA helper, certmonger request parameters, Kerberos environment, and LDAP connections are always restored in `finally` blocks.
- **CA signing cert check**: On renewal master, the CA signing certificate must have at least one month of remaining validity.  This check runs inside `run_renewal_master_fix`, not as a pre-flight gate in `run()`, so it does not block replica or CA-less scenarios where the local CA cert being expired is expected.  If the CA cert is expired:
  - For **self-signed CA**: the user is directed to `ipa-cacert-manage renew`.
  - For **externally-signed CA**: the existing CSR is extracted from certmonger and written to `/var/lib/ipa/ca.csr`.  Instructions are printed to submit the CSR to the external CA and install the renewed certificate with `ipa-cacert-manage renew --external-cert-file=...` before retrying `ipa-cert-fix`.

## Implementation

### Key Types

```python
@dataclass(frozen=True)
class CertIdentity:
    """Identity and metadata for a Dogtag certificate."""
    id: str                          # e.g., 'sslserver'
    nickname: str                    # e.g., 'Server-Cert cert-pki-ca'
    is_shared: bool                  # managed by RM, replicated via LDAP
    cfg_path: Optional[str]          # CS.cfg path for this cert
    cs_cfg_directive: Optional[str]  # cert blob directive (e.g., 'ca.subsystem.cert')
    certreq_directive: Optional[str] # CSR directive (e.g., 'ca.subsystem.certreq')
    display_name: str                # property: returns nickname
    is_dogtag: bool                  # property: always True

class DeploymentType(Enum):
    CA_SELF_SIGNED = "CA-full, self-signed"
    CA_EXTERNALLY_SIGNED = "CA-full, externally-signed"
    CA_LESS = "CA-less (internal CA on other replicas)"
    CA_LESS_EXTERNAL = "CA-less (fully external)"

class FixScenario(Enum):
    RENEWAL_MASTER = "renewal_master"
    CA_FULL_WITH_MASTER = "ca_full_with_master"
    CA_FULL_PROMOTE = "ca_full_promote"
    CA_LESS_WITH_MASTER = "ca_less_with_master"
    EXTERNAL_CERTS = "external_certs"

@dataclass
class CertFixContext:
    deployment_type: DeploymentType
    scenario: FixScenario
    subject_base: DN
    ca_subject_dn: DN
    dogtag_certs: list       # [(certid, cert), ...]
    ipa_certs: list           # [(IPACertType, cert), ...]
    external_certs: list      # [(IPACertType, cert), ...]
    master_server: Optional[str]
    serverid: str             # DS instance id
    ds_dbdir: str             # DS NSS database directory
    ds_nickname: str          # DS server cert nickname
    hsm_enabled: bool
    hsm_token_name: Optional[str]
```

The `DOGTAG_CERTS` registry is a module-level dict mapping cert IDs to `CertIdentity` instances.  It is the single source of truth for Dogtag certificate metadata — nicknames, shared/server-specific classification, CS.cfg directives, and CSR directives are all derived from it.

### Architecture

The code is organized into five classes and a set of module-level utility functions:

```
IPACertFix (AdminTool)          -- CLI orchestrator (16 methods)
├── DeploymentDetector          -- detection, classification, scenario routing
├── ExternalCertHandler         -- external cert transition and CSR generation
├── CertRenewalFromMaster       -- certmonger-based renewal via master server
└── CertmongerClient            -- adapter for certmonger D-Bus/module operations
```

`CertmongerClient` is an adapter that wraps the `ipalib.install.certmonger` module.  It provides a mockable boundary for unit tests and centralizes D-Bus retry logic.  Key methods: `get_ca_helper` (reads current helper with retry), `set_ca_override`/`restore_ca_override` (manages the `-J` JSON-RPC override), `is_responsive` (polls certmonger D-Bus via `getcert list-cas`), `is_cert_valid` (checks whether a tracked cert is still valid).

`DeploymentDetector` handles deployment type detection (`detect_deployment_type`), certificate classification (`_classify_certs`), scenario routing (`determine_scenario`), CA signing cert validation (`_check_ca_signing_cert`), CA chain verification (`_verify_ca_chain_valid`), RA/subsystem LDAP consistency checking (`_detect_ra_subsystem_mismatches`), and master server selection (`get_master_server`).  Constructed with a `CertmongerClient`, CA instance, and CLI options.

`ExternalCertHandler` handles externally-signed certificates.  `handle(ctx)` dispatches to `offer_transition` (interactive per-cert transition to internal IPA CA) or `generate_csrs` (CSR generation for manual external renewal).  Transitions create new certmonger tracking requests mirroring the parameters used during IPA server installation (`httpinstance.py`, `dsinstance.py`, `krbinstance.py`).  CSR generation tries three sources in order: extract from certmonger tracking, generate from existing private key, or fall back to manual instructions.  CSR files are written to `/run/ipa/cert-fix/` with 0o600 permissions.

`CertRenewalFromMaster` manages the certmonger-based renewal flow for non-renewal-master replicas.  `renew(certs, ipa_certs, ctx)` builds a tracking list, temporarily overrides the IPA CA helper to point at the master (`-J` flag), resubmits each tracking request, and restores all certmonger state in a `finally` block.  Dogtag certs are temporarily switched from `dogtag-ipa-ca-renew-agent` to the `IPA` CA with a host principal and `caIPAserviceCert` profile.  All per-request state (original CA name, profile, principals) is tracked and restored regardless of success or failure.

`IPACertFix` is the CLI entry point (`AdminTool` subclass) and orchestrator.  It has 16 methods:

- **CLI**: `add_options`, `validate_options`
- **Bootstrap & dispatch**: `run`, `_classify_and_dispatch`
- **Scenario handlers**: `run_renewal_master_fix`, `_run_non_rm_replica_fix`, `run_ca_full_promote`, `run_external_certs`
- **Master cert operations**: `_promote_to_renewal_master`, `_fetch_certs_from_master`, `_fetch_shared_dogtag_certs`, `update_ca_cert_from_master`
- **CA-less RA staleness**: `_check_ra_cert_staleness`, `_fetch_ra_from_ca_server`
- **Shared**: `_confirm_execution`, `resubmit_expired_certs`

### Dispatch Architecture

`run()` performs bootstrap, LDAP connect, and cleanup in a `try/finally` block.  `_classify_and_dispatch()` creates the `DeploymentDetector` and `ExternalCertHandler`, performs detection and classification, then dispatches to a scenario handler via a dictionary lookup:

```python
dispatch = {
    FixScenario.RENEWAL_MASTER: self.run_renewal_master_fix,
    FixScenario.CA_FULL_WITH_MASTER: lambda ctx: self._run_non_rm_replica_fix(ctx, is_ca_full=True),
    FixScenario.CA_FULL_PROMOTE: self.run_ca_full_promote,
    FixScenario.CA_LESS_WITH_MASTER: lambda ctx: self._run_non_rm_replica_fix(ctx, is_ca_full=False),
    FixScenario.EXTERNAL_CERTS: self.run_external_certs,
}
```

Error handling convention:
- Scenario handlers return exit codes (0/1) to `_classify_and_dispatch`.
- `determine_scenario` raises `RuntimeError` for invalid option combos; `_classify_and_dispatch` catches it and returns exit code 1 with a clean message.
- Internal helpers raise `RuntimeError` for fatal errors (e.g., expired cert fetched from master, certmonger unresponsive mid-renewal); these propagate to the dispatch-level catch for a clean error message.

`_run_non_rm_replica_fix(ctx, is_ca_full)` is the shared handler for both CA-full and CA-less replica scenarios.  It sets up Kerberos credentials, updates the CA chain from the master, fetches RA and shared certs, creates a `CertRenewalFromMaster` to renew server-specific certs via certmonger, handles any external certs, restarts IPA, and resubmits remaining tracking requests.

### Shared vs Server-Specific Certificate Handling

On non-renewal-master replicas, Dogtag certificates fall into two categories:

- **Server-specific** (`sslserver`): unique per server, renewed via certmonger with the IPA CA helper pointed at the master (`-J` override).

- **Shared/replicated** (`subsystem`, `ocspSigningCert`, `auditSigningCert`, and KRA certs): identical across all replicas, managed by the renewal master and replicated via LDAP `cn=ca_renewal,cn=ipa,cn=etc`.

The distinction is encoded in `CertIdentity.is_shared` within the `DOGTAG_CERTS` registry.  `CertRenewalFromMaster._build_tracking_list` skips any cert where `is_shared` is `True` (not resubmitted via certmonger; instead fetched directly from the master's LDAP).  Only `sslserver` (the sole non-shared Dogtag cert) goes through certmonger resubmit with the `-J` override.

Because shared certs are installed directly into the NSSDB (bypassing certmonger's `renew_ca_cert` post-save command), the base64 certificate blobs in the Dogtag CS.cfg configuration files must be updated manually.  The `_update_cs_cfg` module-level function writes the new blob to the appropriate directive (looked up from `CertIdentity.cs_cfg_directive`).  The KRA transport certificate additionally requires updating `ca.connector.KRA.transportCert` in the CA config.

### Files Modified

- `ipaserver/install/ipa_cert_fix.py` -- orchestrator (`IPACertFix`), classification functions, cert operations, and re-exports from the two modules below
- `ipaserver/install/ipa_cert_fix_types.py` -- data definitions: `CertIdentity`, `DOGTAG_CERTS`, enums, `CertFixContext`, constants, string templates
- `ipaserver/install/ipa_cert_fix_services.py` -- extracted classes (`CertmongerClient`, `DeploymentDetector`, `ExternalCertHandler`, `CertRenewalFromMaster`) and helper functions they use
- `ipatests/test_integration/test_ipa_cert_fix.py` -- integration tests (15 classes, require IPA VMs)
- `ipatests/test_integration/test_ipa_cert_fix_unit.py` -- unit tests (61 classes, mock-only, run in seconds)
- `install/tools/man/ipa-cert-fix.1` -- man page

All public names remain importable from `ipaserver.install.ipa_cert_fix` via re-exports.

### Module-Level Functions

The following module-level functions support the classes above:

- **Certificate operations**: `expired_dogtag_certs()`, `expired_ipa_certs()` (with `_check_ipa_cert` helper), `print_intentions()`, `print_cert_info()`, `get_csr_from_certmonger()`, `fix_certreq_directives()`, `run_cert_fix()`, `replicate_dogtag_certs()`, `check_renewed_ipa_certs()`, `install_ipa_certs()`, `replicate_cert()`, `_get_newest_cert()`, `_fetch_and_update_cert()`
- **Infrastructure**: `_ensure_ldap_connected()`, `_check_tcp_reachable()`, `_check_tls_handshake()`, `_setup_kerberos()`, `_restore_kerberos()`, `_kill_stuck_helpers()`, `_replace_cert_in_nssdb()`, `_update_cs_cfg()`, `_find_current_renewal_master()`, `_get_pki_nssdb()`

## Upgrade

No impact on upgrades.  The new CLI options are additive and backward-compatible.  Existing invocations of `ipa-cert-fix` without options will auto-detect the deployment type and behave identically to the original tool on renewal masters.

## Future Work

### Further file split

The current three-file layout (`ipa_cert_fix_types.py`, `ipa_cert_fix_services.py`, `ipa_cert_fix.py`) keeps the orchestrator at ~1600 lines and the services file at ~2200 lines.  A follow-up refactor could promote these into an `ipaserver/install/certfix/` package with one file per class:

- `ipa_cert_fix.py` -- re-export shim (~20 lines)
- `certfix/__init__.py` -- public API re-exports
- `certfix/_constants.py` -- CertIdentity, DOGTAG_CERTS, timeouts
- `certfix/_types.py` -- enums, CertFixContext
- `certfix/_helpers.py` -- stateless utility functions
- `certfix/_certmonger.py` -- CertmongerClient
- `certfix/_classification.py` -- expired_dogtag_certs, expired_ipa_certs
- `certfix/_detection.py` -- DeploymentDetector
- `certfix/_external.py` -- ExternalCertHandler
- `certfix/_renewal.py` -- CertRenewalFromMaster
- `certfix/_certops.py` -- pki-server helpers, LDAP replication
- `certfix/_cli.py` -- IPACertFix AdminTool

This would bring the largest file to ~450 lines and enable per-class unit test files.  Deferred because the current layout works, follows existing IPA conventions, and the package split is mechanical once the three-file structure is stable.

### HSM integration tests

The HSM code path (`-h <token>` for `certutil`, HSM detection via `CAInstance().hsm_enabled`) is exercised in production but has no dedicated test coverage.  The unit tests always set `hsm_enabled=False`.  Integration tests require a SoftHSM or hardware token, which is not available in standard CI.  A future test class (e.g. `TestHSMRenewalMaster`) should:

- Install IPA with SoftHSM (`ipa-server-install --token-name=...`)
- Expire Dogtag certs and run `ipa-cert-fix`
- Verify that `certutil -K -h <token>` is used for CSR generation
- Verify that renewed certs are stored on the HSM token

### Missing unit test coverage

Several code paths lack dedicated unit tests:

- `_fetch_certs_from_master`: TLS error branch (certificate vs non-certificate exceptions)
- `_fetch_ra_from_ca_server`: expiry validation of fetched cert
- `_check_ra_cert_staleness`: serial mismatch detection
- `update_ca_cert_from_master`: ipa-certupdate partial failure (non-zero exit but valid chain)
- `run_renewal_master_fix`: externally-signed CA deployment (`ca_issuing` skip logic)
- `ExternalCertHandler._generate_csr_nssdb`: HSM token pass-through

### Automatic CRL generation after promotion

When `ipa-cert-fix` promotes a replica to renewal master (`CA_FULL_PROMOTE` scenario), CRL generation must be enabled manually afterward (`ipa-crlgen-manage enable` on the new RM, `disable` on others).  The tool prints instructions but does not act because CRL configuration is a topology-wide concern -- the administrator must also disable CRL on the old master (if it comes back) and verify CRL distribution points.  A future enhancement could automate the local `ipa-crlgen-manage enable` and optionally disable CRL on other reachable CA servers.

### Trust-on-first-use for stale CA trust store

The stale CA trust store problem (Known Limitations below) currently requires manual `ca.crt` copy.  A `--trust-on-first-use` option could fetch the CA chain over an unverified TLS connection, display the certificate fingerprint, and ask the administrator to confirm it matches out-of-band.  This would eliminate the manual file copy while preserving explicit trust verification.  The option should never be available in unattended mode.

## Known Limitations

### No concurrent execution on multiple replicas

Running `ipa-cert-fix` simultaneously on two replicas that both target the same master (e.g., both using `--force-server=master`) is not supported.  The tool temporarily modifies the certmonger IPA CA helper (a global, per-host setting) to point at the master.  If two instances run at the same time on the same host, or if a second instance starts before the first has restored the helper, the restore logic may clobber the other instance's override.

**Workaround**: Run `ipa-cert-fix` on one replica at a time.  Wait for completion before starting on the next replica.

### Stale CA trust store requires manual ca.crt copy

When the CA certificate on the master has been renewed (via `ipa-cacert-manage renew`), replicas still have the old CA certificate in their trust store (`/etc/ipa/ca.crt`).  If a replica's certificates expire in this state, `ipa-cert-fix` cannot automatically update the trust store because all remote operations (HTTPS, LDAPS) require verifying the master's TLS certificate — which is signed by the new CA that the replica doesn't trust yet.

Automatically fetching the updated CA chain over an unverified connection would risk a man-in-the-middle attack on degraded infrastructure, so `ipa-cert-fix` refuses and prints instructions for manual intervention.

**Workaround**: Before running `ipa-cert-fix` on the replica, copy `/etc/ipa/ca.crt` from the master to the replica using a trusted channel (e.g. `scp` with host key verification, or physical media).  Verify the file's authenticity by comparing checksums out-of-band.  Then re-run `ipa-cert-fix`.

### External CA certificates require manual renewal

The CA signing certificate on externally-signed CA deployments cannot be renewed by `ipa-cert-fix`.  If the CA signing certificate is expired:

- For **self-signed CA**: the tool directs the administrator to use `ipa-cacert-manage renew`.
- For **externally-signed CA**: the tool extracts the existing CSR (or directs the administrator to `ipa-cacert-manage renew --external-ca`) and prints instructions to submit it to the external CA and install the renewed certificate with `ipa-cacert-manage renew --external-cert-file`.

Only after the CA signing certificate is renewed can `ipa-cert-fix` proceed to fix the remaining service and shared certificates.

### External service certificates require manual installation

Service certificates (HTTP, LDAP, KDC) signed by an external CA cannot be renewed automatically.  The tool offers two options:

1. **Transition to internal IPA CA** (interactive only) -- creates a new certmonger tracking request with the IPA CA, obtaining a new internally-signed certificate.  This changes the trust model for that service.
2. **CSR generation** -- generates a CSR from the existing private key (file-based certs) or a new key pair (NSSDB-based certs) and writes it to `/run/ipa/cert-fix/` (root-owned tmpfs, avoids TOCTOU races inherent to `/tmp/`).  The administrator must submit the CSR to the external CA and install the renewed certificate using `ipa-server-certinstall`.

In unattended mode (`-U`), only CSR generation is performed -- no transitions are offered.

### CA-less replicas cannot become renewal masters

`--renewal-master` is rejected on CA-less replicas.  There is no local CA to become the renewal master of.  Installing a CA on a CA-less replica requires `ipa-ca-install`, which needs valid HTTP and LDAP certificates first -- so `ipa-cert-fix` must run successfully before `ipa-ca-install` can be attempted.

### pki-server cert-fix availability

The renewal master scenario requires the `pki-server cert-fix` command from the `pki-server` package.  If this command is not available (e.g., PKI is not installed or is too old), the renewal master scenario fails.  The non-destructive replica and CA-less scenarios do not require it.

### NSSDB-based CSR generation

When generating CSRs for externally-signed LDAP certificates (stored in an NSS database), the tool extracts the hex key ID via `certutil -K` and passes it to `certutil -R -k <key-id>` to reuse the existing private key.  If the key ID cannot be determined, CSR generation for that certificate is skipped and manual instructions are printed instead.  Private keys never leave the NSS database.

### GSSAPI authentication requires a working KDC

Remote LDAP operations (fetching RA and shared certs from the master) use GSSAPI authentication with the host keytab.  The Kerberos client uses the KDC(s) configured in `/etc/krb5.conf` or discovered via DNS SRV records.  If the local KDC is down (e.g., expired KDC cert) and `krb5.conf` points to it, the GSSAPI bind to the master will fail even though the master's KDC may be operational.

**Workaround**: Before running `ipa-cert-fix`, ensure at least one KDC in the topology is reachable.  If the local KDC is down, edit `/etc/krb5.conf` temporarily to point `kdc` at the master, or run `ipa-cert-fix` on the master first so its KDC is operational before fixing replicas.

## User Stories

As an IPA administrator, I want to recover a renewal master with expired Dogtag and IPA service certificates by running a single command so that I can restore IPA operations without manual certificate manipulation.

As an IPA administrator, I want to fix expired certificates on a CA-full replica by fetching them from a healthy renewal master so that I don't have to promote the replica or disrupt the topology.

As an IPA administrator, I want to promote a CA-full replica to renewal master when the original master is permanently lost so that I can recover the deployment without rebuilding from scratch.

As an IPA administrator, I want to fix expired HTTP, LDAP, and KDC certificates on a CA-less replica by renewing them through a remote CA server so that CA-less replicas are not a dead end when certs expire.

As an IPA administrator, I want ipa-cert-fix to extract the CA signing certificate CSR and print renewal instructions when my externally-signed CA certificate expires so that I know exactly what to submit to the external CA and how to install the result.

As an IPA administrator, I want to choose per-certificate whether to transition an externally-signed service certificate to the internal IPA CA or generate a CSR for manual renewal so that I retain control over my PKI trust model.

As an IPA administrator, I want a dry-run mode that shows what ipa-cert-fix would do without making changes so that I can review the plan before committing to it.

As an automation engineer, I want to run ipa-cert-fix in unattended mode with a specific server so that I can include certificate recovery in Ansible playbooks and CI pipelines without interactive prompts.

As an IPA developer, I want a dedicated test suite for ipa-cert-fix that covers each deployment type and fix scenario so that regressions are caught in upstream CI before they reach production deployments.

## Troubleshooting and debugging

### Common failure modes

**"certmonger did not become responsive"** -- certmonger is overwhelmed processing tracked requests after a restart.  The tool waits up to 120 seconds for certmonger to respond on D-Bus.  If still unresponsive, check `journalctl -u certmonger` for errors and consider restarting the certmonger service manually.

**"ipa-certupdate failed and the CA certificate chain was not updated"** -- the master server is unreachable or its certificates are also expired.  Manually copy `/etc/ipa/ca.crt` from a working server and retry.

**"Failed to set renewal master"** -- LDAP is not running or the LDAPI connection is broken.  Check Directory Server logs.

**"Certmonger request ... timed out"** -- the CA did not respond within 300 seconds.  Check CA server logs (`/var/log/pki/pki-tomcat/ca/debug`) and network connectivity.

**"Cannot connect to <server>: TLS certificate error ... Run ipa-cert-fix on <server> first"** -- the remote server's HTTPS/LDAPS certificate is expired.  The local server cannot establish a TLS connection to fetch certificates.  Run `ipa-cert-fix` on the remote server first, then retry on this server.

### Debug logging

Run with `-v` or `--verbose` to enable debug logging.  Use `--log-file` to capture output to a file.  Key information logged:

- Deployment type detection results
- Fix scenario selection
- Each certificate's serial, expiry, and issuer
- Certmonger request IDs and state transitions
- IPA CA helper modification and restoration
- LDAP operations and reconnections

### Post-fix verification

After `ipa-cert-fix` completes, run `ipa-healthcheck` to verify that no certificate issues remain:

    ipa-healthcheck --source ipahealthcheck.ipa.certs

This checks certificate expiry, certmonger tracking status, and CA chain validity.  Any remaining warnings indicate certificates that `ipa-cert-fix` could not renew (e.g. external certs awaiting manual CSR submission) or services that need a manual restart.

## Test plan

Tests marked with [x] are implemented in `ipatests/test_integration/test_ipa_cert_fix.py` (integration) or `ipatests/test_integration/test_ipa_cert_fix_unit.py` (unit).  Tests marked with [ ] are planned but not yet implemented.

### Test tiers

Each test is marked with a tier that determines where it runs:

- **Unit** -- no IPA deployment needed.  Tests pure logic (classification, routing, serialization) with mocks or fakes.  Runs in seconds in any CI environment.
- **Integration** -- single IPA server.  Tests a complete scenario end-to-end but does not require multi-host topology.
- **System** -- multi-host topology (2-3 replicas).  Tests cross-server interactions, replication, and degraded-topology recovery.  Requires VM provisioning; runs in PRCI nightly jobs.

### Cross-cutting postconditions

Every test that exercises a scenario handler (positive or negative) MUST assert these invariants after `ipa-cert-fix` returns, regardless of success or failure:

- **P1**: The certmonger IPA CA helper (`external-helper` property) is in its original state (no leftover `-J` override).
- **P2**: No certmonger tracking request has orphaned `template-principal` entries.
- **P3**: `KRB5CCNAME` is restored to its pre-invocation value (or unset if it was unset before).
- **P4**: The `ldap2` backend is either connected or cleanly disconnected -- no half-open sockets.
- **P5**: No certmonger tracking requests have been switched to a different CA name (`ca-name`) or profile (`template-profile`) without being restored.
- **P6**: HTTPS serves valid TLS — `openssl s_client` to port 443 with IPA CA trust verifies successfully.
- **P7**: PKI subsystem operational — `ipa cert-find --sizelimit=1` returns certificates (works on any enrolled host, not just CA hosts, as long as the deployment has a CA).

These postconditions are not listed in each test below to avoid repetition, but they apply to every test from T-RM-1 onward.

### 1. Renewal Master

#### Positive

[x] **T-RM-1. All certs expired, self-signed CA** [integration] -- Expire all Dogtag and IPA certs (+3 years).  Run `ipa-cert-fix`, enter "yes".  Verify: all certs renewed, certmonger returns to MONITORING, IPA operational.  Re-run: "Nothing to do".

[x] **T-RM-2. All certs expired with KRA installed** [integration] -- Same as T-RM-1 but with KRA.  Verify: KRA certs (transport, storage, audit) are also renewed (12 certs total in MONITORING).

[x] **T-RM-3. Dry-run shows plan without changes** [integration] -- Run `ipa-cert-fix --dry-run` with expired certs.  Verify: `[DRY RUN]` on all output, no certs modified, no services restarted, exit code 0.

[x] **T-RM-4. Only some certs expired** [integration] -- Expire only the HTTP and KDC certs (leave Dogtag certs valid).  Run `ipa-cert-fix`.  Verify: only the expired certs are renewed, valid certs untouched.

#### Negative

[x] **T-RM-5. CA signing cert near expiry blocks renewal** [integration] -- Set clock so caSigningCert has 15 days left.  Run `ipa-cert-fix`.  Verify: "CA signing certificate is expired or will expire within the next month", exit code 1, no certs renewed.

[ ] **T-RM-6. CA signing cert expired, self-signed** [integration] -- Expire the caSigningCert entirely (+20 years).  Verify: tool refuses, directs admin to `ipa-cacert-manage renew`.

[ ] **T-RM-7. CA signing cert expired, externally-signed** [integration] -- Deploy with external CA, expire caSigningCert.  Verify: CSR extracted and written to `/var/lib/ipa/ca.csr`, instructions printed for `ipa-cacert-manage renew --external-cert-file`, exit code 1.

[ ] **T-RM-8. CSR not found in certmonger for CA signing cert** [integration] -- Remove the CSR from the caSigningCert tracking request before running `ipa-cert-fix` on an externally-signed deployment.  Verify: "Could not extract the existing CSR", directs admin to `ipa-cacert-manage renew --external-ca`.

[x] **T-RM-9. pki-server cert-fix unavailable** [integration] -- Rename `pki-server` binary.  Verify: "'pki-server cert-fix' command is not available", exit code 1.

[x] **T-RM-10. CSR directive missing from CS.cfg** [integration] -- Remove `ca.sslserver.certreq` from `CS.cfg`, resubmit via `getcert` to recreate CSR in certmonger.  Run `ipa-cert-fix`.  Verify: directive restored from certmonger before `pki-server cert-fix` runs, no "sslserver.crt not found" error.  (Regression: issue #8618.)

[x] **T-RM-11. selftests startup directive missing** [integration] -- Remove `selftests.container.order.startup` from `CS.cfg`.  Run `ipa-cert-fix`.  Verify: on PKI < 10.11.0, error about missing directive; on PKI >= 10.11.0, warning and proceed.  (Regression: issue #8721/#8890.)

[x] **T-RM-12. User declines confirmation** [integration] -- Enter "no" at the confirmation prompt.  Verify: "Not proceeding", exit code 0, no certs modified.

### 2. CA-Full Replica (Non-Destructive)

#### Positive

[x] **T-REP-1. Replica fixed from healthy master** [system] -- 2-replica topology.  Expire certs on non-RM replica only.  Run `ipa-cert-fix`.  Verify: certs fetched from master and renewed, RM role unchanged.  Create user on master, verify on replica (replication works).

[x] **T-REP-2. Unattended with --force-server** [system] -- Run `ipa-cert-fix -U --force-server=master` on replica.  Verify: no prompts, completes autonomously, exit code 0.

[x] **T-REP-3. Dry-run on replica** [system] -- Run `ipa-cert-fix --dry-run` on replica.  Verify: shows which server would be used, no certs modified.

#### Negative

[x] **T-REP-4. --force-server points to self** [integration] -- Run `ipa-cert-fix --force-server=$(hostname)`.  Verify: error "must point to a different server".

[x] **T-REP-5. --force-server points to unreachable host** [system] -- Run `ipa-cert-fix --force-server=nonexistent.example.com`.  Verify: fails during `ipa-certupdate` or GSSAPI bind, actionable error.

[ ] **T-REP-6. --force-server points to CA-less server** [system] -- Point `--force-server` at a CA-less replica.  Verify: fails when fetching RA cert from a server without `o=ipaca`.

[ ] **T-REP-7. Master LDAP unreachable during cert fetch** [system] -- After `ipa-certupdate` succeeds, block LDAPS to master (iptables). Verify: GSSAPI bind fails, Kerberos env restored.

[ ] **T-REP-8. ipa-certupdate fails, ca.crt not updated** [system] -- Block all network to master.  Verify: "ipa-certupdate failed and the CA certificate chain was not updated", instructions to manually copy `ca.crt`.

[ ] **T-REP-9. DS stops after ipa-certupdate** [system] -- Arrange for DS to fail to restart after `ipa-certupdate`.  Verify: "LDAP server is no longer running after ipa-certupdate", exit code 1.

[ ] **T-REP-10. certmonger renewal times out** [system] -- Firewall master's port 443 after helper modification.  Verify: "Certmonger request ... timed out", IPA CA helper restored.

[ ] **T-REP-11. certmonger reaches wrong state** [system] -- Simulate CA rejection (e.g., revoke the RA cert on master).  Verify: error includes `ca-error` message, helper and profiles restored.

[ ] **T-REP-12. Tracking request missing for one cert** [system] -- Remove HTTP cert tracking from certmonger.  Run `ipa-cert-fix`. Verify: warning logged, other certs still renewed.

[x] **T-REP-13. User declines confirmation** [system] -- Enter "no" at replica fix prompt.  Verify: "Not proceeding", no changes, RM role unchanged.

### 3. CA-Full Replica -- Promote to Renewal Master

#### Positive

[x] **T-PROMO-1. Promotion when master is permanently down** [system] -- 2-replica topology.  Shut down master permanently.  Run `ipa-cert-fix` on replica.  Verify: promotion warning shown, user confirms, replica becomes RM, CRL warning printed, certs renewed.

#### Negative

[x] **T-PROMO-2. Unattended refuses silent promotion** [system] -- Run `ipa-cert-fix -U` with no reachable master and no `--force-server`.  Verify: refuses silent promotion, prints message directing to `--renewal-master` or `--force-server`, RM role unchanged, no certs renewed, exit code 1.

[ ] **T-PROMO-4. Promotion fails (LDAP error)** [system] -- Arrange for `set_renewal_master()` to fail (e.g., make the LDAP entry read-only).  Verify: "Failed to set renewal master", no certs renewed.

### 4. CA-Less Replica

#### Positive

[x] **T-CALESS-1. HTTP/LDAP/KDC renewed from CA server** [system] -- 3-host topology (2 CA-full + 1 CA-less).  Expire service certs on CA-less replica.  Run `ipa-cert-fix --force-server=<ca-server>`. Verify: only IPA service certs renewed, no Dogtag certs touched, RA cert fetched.

[x] **T-CALESS-2. Dry-run on CA-less replica** [system] -- Run `--dry-run`.  Verify: shows empty Dogtag list, lists IPA certs that would be renewed.

#### Negative

[ ] **T-CALESS-3. All CA servers unreachable** [system] -- Shut down all CA servers.  Run `ipa-cert-fix` on CA-less replica. Verify: falls back to CSR generation, does not hang.

[x] **T-CALESS-4. User declines confirmation** [system] -- Enter "no".  Verify: "Not proceeding", no changes.

### 5. External and Mixed Certificates

#### Positive

[x] **T-EXT-1. Mixed deployment, transition to internal CA** [integration] -- Replace HTTP cert with externally-signed cert, expire it.  Run `ipa-cert-fix`.  Accept transition.  Verify: HTTP cert re-issued by IPA CA, service operational.

[x] **T-EXT-2. Mixed deployment, decline transition** [integration] -- Same setup.  Decline transition.  Verify: CSR generated from existing private key and written to `/run/ipa/cert-fix/apache-https.csr`, `ipa-server-certinstall` instructions printed.

[x] **T-EXT-3. Unattended skips transition, generates CSR** [integration] -- Run with `-U`.  Verify: no transition offered, CSR generated from existing keys, written to `/run/ipa/cert-fix/`.

#### Negative

[ ] **T-EXT-4. No CSR in certmonger, fallback to key-based CSR**
[integration] -- Stop certmonger tracking for HTTP cert (simulating external cert install).  Run `ipa-cert-fix`, decline transition. Verify: CSR generated from `/var/lib/ipa/private/httpd.key` and the expired cert's subject/SANs, written to `/run/ipa/cert-fix/`.

[ ] **T-EXT-5. Cannot write CSR to /run/ipa/cert-fix** [integration] -- Make `/run/ipa` read-only (remount).  Verify: IOError caught, logged, no crash.

[ ] **T-EXT-6. Transition resubmit fails** [integration] -- Offer transition but certmonger resubmit fails (e.g., CA ACL denies the profile).  Verify: error printed for that cert, remaining certs still offered, certmonger state clean.

[x] **T-EXT-7. Fully external (CA_LESS_EXTERNAL), no tracking**
[unit] -- Verify: no CA server lookup attempted, no transition offered, CSRs generated from existing keys, `ipa-server-certinstall` instructions printed.

### 6. Topology-Wide Expiry (Degraded Master)

[x] **T-TOPO-1. Fix master first, then replica** [system] -- 2-replica topology, expire certs on both hosts.  Fix master first with `ipa-cert-fix`.  Then fix replica with `--force-server=master`. Verify: replica fetches certs from the freshly-repaired master and renews.  This is the most common real-world scenario.

[x] **T-TOPO-2. Replica attempt before master is fixed** [system] -- Expire certs on both hosts.  Do NOT fix master first.  Run `ipa-cert-fix --force-server=master` on replica.  Verify: fails because master's HTTPS cert is expired (TLS handshake rejected), actionable error telling admin to fix master first.

[ ] **T-TOPO-3. Master CA chain changed, replica stale** [system] -- Renew the CA cert on master (`ipa-cacert-manage renew`).  Replica still has old `ca.crt`.  Run `ipa-cert-fix --force-server=master` on replica.  Verify: `ipa-certupdate` updates local CA chain before cert renewal, GSSAPI bind succeeds, certs renewed.

[ ] **T-TOPO-4. Replica fixed before replication catches up** [system] -- Fix master, immediately run `ipa-cert-fix` on replica before shared certs replicate.  Verify: tool fetches directly from master's LDAP, not from local LDAP.  Replication lag does not block recovery.

[ ] **T-TOPO-5. Multiple replicas down, only master available** [system] -- 3-replica topology, shut down replicas 2 and 3.  Expire certs on replica 1.  Verify: tool discovers master from LDAP, cert fetch works despite other replicas being offline.

### 7. Cross-Cutting Concerns

#### Pre-flight checks

[x] **T-PRE-1. IPA not configured** [unit] -- Call `run()` on a system where `is_ipa_configured()` returns False. Verify: "IPA is not configured", exit code 2.

[x] **T-PRE-2. Not running as root** [unit] -- Call `validate_options()` as unprivileged user.  Verify: permission denied, exit code 1.

[x] **T-PRE-3. Directory Server down** [integration] -- Stop `dirsrv` before running `ipa-cert-fix`.  Verify: "The LDAP server is not running; cannot proceed", exit code 1.

[x] **T-PRE-4. No expired certs** [integration] -- Run `ipa-cert-fix` when all certs are valid.  Verify: "Nothing to do", exit code 0.

#### Idempotency

[x] **T-IDEM-1. Second run immediately after fix** [integration] -- After a successful fix, re-run immediately.  Verify: "Nothing to do", no double-renewal.

[ ] **T-IDEM-2. Re-run while certmonger still processing** [integration] -- Run `ipa-cert-fix` while certmonger is still re-submitting certs from the previous run.  Verify: second run sees MONITORING/SUBMITTING states, says "Nothing to do", does not interfere.

[x] **T-IDEM-3. Re-run after interrupted fix** [unit variant] -- KeyboardInterrupt during pki-server cert-fix.  Verify: certmonger state not corrupted (no resubmit called).  Full integration variant (SIGINT + re-run) deferred.

#### State restoration under failure

These tests verify the cross-cutting postconditions (P1-P7) hold after mid-flight failures.  Each test causes a failure at a specific point and checks that cleanup ran correctly.

[x] **T-RESTORE-1. IPA CA helper restored after renewal timeout**
[system] -- Cause a timeout during `renew_certs_from_master` (first cert succeeds, second times out via firewall).  Verify postcondition P1: certmonger `external-helper` matches original value.

[x] **T-RESTORE-2. Dogtag CA name and profile restored after failure**
[system] -- Cause a failure after a Dogtag cert's CA is switched to IPA.  Verify postconditions P2 and P5: `ca-name` restored to `dogtag-ipa-ca-renew-agent`, `template-profile` restored, `template-principal` cleared.

[ ] **T-RESTORE-3. Kerberos env restored after failure** [integration] -- Set `KRB5CCNAME` to a custom value, cause a failure after `_setup_kerberos()`.  Verify postcondition P3: `KRB5CCNAME` restored.

[ ] **T-RESTORE-4. LDAP reconnected after ipa-certupdate** [system] -- Run `ipa-cert-fix` where `ipa-certupdate` restarts DS.  Verify postcondition P4: `ldap2` reconnected unconditionally (not relying on `isconnected()` which may report True on a broken pipe).

#### Deployment detection edge cases

[x] **T-DETECT-1. NSS database unreadable** [integration] -- Corrupt or permission-deny the PKI Tomcat NSS database.  Verify: "Cannot read caSigningCert from NSS database", actionable error.

[ ] **T-DETECT-2. LDAP topology query fails during detection**
[integration] -- Arrange for `find_providing_servers` to raise. Verify: warning logged, detection falls back gracefully.

[x] **T-DETECT-3. One service cert file missing** [integration] -- Delete `paths.KDC_CERT`.  Verify: deployment detection and cert classification still work, missing cert skipped with debug log.

[ ] **T-DETECT-4. All service cert files missing** [integration] -- Delete HTTP, LDAP, and KDC cert files.  Verify: tool exits with actionable error, does not claim "Nothing to do".

[x] **T-DETECT-5. Custom DS cert nickname** [integration] -- Install a third-party LDAP certificate with a non-default nickname via `ipa-server-certinstall -d`.  Run `ipa-cert-fix -v`.  Verify: correct nickname used (visible in verbose output), no "certificate not found" error.  (Regression: existing test_third_party_certs.)

#### RA/Subsystem LDAP consistency

[x] **T-CONSIST-1. RA cert serial mismatch in LDAP** [integration] -- Modify the `description` field in `uid=ipara,ou=People,o=ipaca` to contain a wrong serial number.  Run `ipa-cert-fix`.  Verify: mismatch detected, user prompted, LDAP updated with correct serial after "yes".

[ ] **T-CONSIST-2. Subsystem cert blob missing in LDAP** [integration] -- Remove the `userCertificate` value from `uid=pkidbuser,ou=People,o=ipaca`.  Run `ipa-cert-fix`.  Verify: mismatch detected, cert blob added to LDAP after confirmation.

[x] **T-CONSIST-3. Dry-run shows mismatches without fixing** [integration] -- Same setup as T-CONSIST-1.  Run `ipa-cert-fix --dry-run`.  Verify: mismatch printed, no LDAP modification.

[x] **T-CONSIST-4. No mismatches, no prompt** [integration] -- Run `ipa-cert-fix` on a healthy server.  Verify: no consistency prompt shown, just "Nothing to do".

[ ] **T-CONSIST-5. Post-fix verification catches stale entry** [system] -- On a replica, expire certs and fix from master.  Artificially break `uid=ipara` description between fetch and post-fix check.  Verify: post-fix verification detects and offers to fix.

### 8. Unit Tests (no IPA deployment)

These tests exercise pure logic with mocks.  They run in seconds and should be part of every PR gate.

[x] **T-UNIT-1. KDC cert classified as KDC, not HTTPS** [unit] -- Call `expired_ipa_certs()` with a non-IPA-issued KDC cert.  Verify: it appears in `non_renewed` as `IPACertType.KDC`. (Regression: pre-existing bug fixed in this expansion.)

[x] **T-UNIT-2. D-Bus empty list uses typed Array** [unit] -- Verify that the cleanup code constructs `dbus.Array([], signature='s')` not a bare `[]` when clearing `template-principal`. (Regression: D-Bus serialization error.)

[x] **T-UNIT-3. Scenario routing for each deployment type** [unit] -- For each `DeploymentType` x `is_renewal_master` x `master_available` combination, call `determine_scenario()` with mocks.  Verify: correct `FixScenario` returned.  Matrix:

| DeploymentType | is_RM | master | Expected scenario |
|---|---|---|---|
| CA_SELF_SIGNED | yes | -- | RENEWAL_MASTER |
| CA_SELF_SIGNED | no | yes | CA_FULL_WITH_MASTER |
| CA_SELF_SIGNED | no | no | CA_FULL_PROMOTE |
| CA_EXTERNALLY_SIGNED | yes | -- | RENEWAL_MASTER |
| CA_EXTERNALLY_SIGNED | no | yes | CA_FULL_WITH_MASTER |
| CA_LESS | -- | yes | CA_LESS_WITH_MASTER |
| CA_LESS | -- | no | EXTERNAL_CERTS |
| CA_LESS_EXTERNAL | -- | -- | EXTERNAL_CERTS |

[x] **T-UNIT-4. Cert classification splits external from IPA-issued**
[unit] -- Call `_classify_certs()` with mocked `expired_ipa_certs()` returning certs in `non_renewed`.  Verify: they appear in `external_certs`, not `non_renewed`.

[x] **T-UNIT-5. --force-server=self rejected** [unit] -- Call `get_master_server()` with `options.force_server` set to the local hostname.  Verify: `RuntimeError` raised.

[x] **T-UNIT-6. Dry-run returns 0 for each scenario** [unit] -- Call each scenario handler with `options.dry_run=True` and a mocked context.  Verify: returns 0, no side-effecting methods called.

Additionally implemented but not in the original plan:

[x] **T-UNIT-7. --renewal-master + --force-server rejected** [unit] -- Verify `validate_options` rejects mutual exclusion.

[x] **T-UNIT-8. --renewal-master on CA-less rejected** [unit] -- Verify `determine_scenario` raises `RuntimeError` for CA-less + `--renewal-master`.  Also tests `CA_LESS_EXTERNAL`.

[x] **T-UNIT-9. CA cert still expired after pki-server cert-fix**
[unit] -- Verify `run_renewal_master_fix` returns 1 when post-renewal `_check_ca_signing_cert` fails.

[x] **T-UNIT-10. CA_LESS_EXTERNAL skips CA server lookup** [unit] -- Verify `_handle_external_certs` does not call `find_providing_servers` for fully-external deployments.

[x] **T-UNIT-11. No tracking generates CSR from key** [unit] -- Verify `_generate_external_csrs` calls `_generate_csr_from_key` when certmonger has no tracking request.

[x] **T-UNIT-12. Duplicate-subject CA certs prefer valid** [unit] -- `ca.crt` contains both expired and valid CA certs with same subject DN (normal after CA renewal).  Verify `_verify_ca_chain_valid` picks the valid cert regardless of file ordering.

### 9. End-to-End Story Tests

These tests walk through a complete multi-host recovery sequence. They validate that `ipa-cert-fix` works as a coherent workflow across an entire topology, not just in isolation.

[x] **T-E2E-1. Full topology recovery: master, CA replica, CA-less**
[system] -- 3-host topology: CA renewal master, CA-full replica, CA-less replica.  Expire all certs on all hosts (+3 years).  Recovery sequence:

1. Fix master with `ipa-cert-fix`.
2. Fix CA-full replica with `ipa-cert-fix --force-server=master`.
3. Fix CA-less replica with `ipa-cert-fix --force-server=master`.
4. Verify all hosts operational: `ipa user-add` on master replicates to both replicas, `kinit` works on all hosts, `getcert list` shows MONITORING on all hosts.

This is the single most important test.  If it passes, the tool works for the most common real-world disaster recovery scenario.

[ ] **T-E2E-2. Recovery with externally-signed CA** [system] -- 2-host topology with externally-signed CA.  Expire caSigningCert and service certs.  Recovery sequence:

1. Run `ipa-cert-fix` on master -- tool extracts CSR, prints instructions, exits with code 1.
2. Simulate external CA renewal: sign the CSR, install with `ipa-cacert-manage renew --external-cert-file`.
3. Re-run `ipa-cert-fix` -- now proceeds to renew remaining certs.
4. Fix replica.
5. Verify topology healthy.

[ ] **T-E2E-3. Recovery with promotion** [system] -- 2-host topology.  Shut down master (permanent failure).  Recovery:

1. Run `ipa-cert-fix` on replica -- promoted to RM, certs renewed.
2. Run `ipa-crlgen-manage enable` on replica.
3. Verify: replica is sole operational server, `ipa` commands work, CRL generation active.
