# Installation

ipacta is installed as part of FreeIPA's `ipa-server-install` and
`ipa-replica-install`. The installation is orchestrated by
`IpactaInstance` which composes focused helper classes, each handling
one domain.

## Composition Architecture

```
IpactaInstance (service.Service)
  |
  |-- _nssdb      = NSSDB()
  |-- _certs      = Certs(ldap, config, pki_config, nssdb, ...)
  |-- _ldap_setup = LDAPSetup(ldap, config, realm, basedn, clone, fqdn)
  |-- _svc        = ServiceMgmt(config, fqdn, clone, nssdb, ...)
  |-- _repl       = Replication(basedn, ldap_update_fn)
  |-- _kra        = KRAInstall(ldap, nssdb, ca_cert_path, ...)
  |-- _acme       = ACME(ldap, config, ldap_mod_fn)
  |-- _lwca       = LWCA(ldap, basedn)
  v
  No ipacta/install/ module imports ipaserver (avoids circular deps)
```

Two `service.Service` bound methods are injected as callables so that
helpers stay free of `ipaserver` imports: `self._ldap_mod` (runs
`ldapmodify` against a single LDIF with template substitution) is
passed to `KRAInstall` and `ACME`, while `self._ldap_update` (runs
`LDAPUpdate` over one or more `.uldif` update files) is passed to
`Replication` as `ldap_update_fn`.

## Helper Classes

### NSSDB (`install/db.py`)

Creates and manages the NSS certificate database.

| Method | Description |
|--------|-------------|
| `create_nssdb()` | Create NSSDB at `/etc/pki/pki-tomcat/alias/` |
| `load_nssdb_password()` | Load password from password file |
| `import_cert_to_nssdb(cert, key, nickname, trust)` | Import cert+key |
| `apply_nssdb_permissions()` | Apply ownership, mode, ACLs and create `pwdfile.txt` |

Creates the database with a strong random password stored in
`/etc/pki/pki-tomcat/password.conf` (format: `internal=password`).
Removes old NSSDB files for idempotency. Sets ownership to `ipaca:ipaca`.

### Certs (`install/certs.py`)

Certificate generation and storage.

**Constructor parameters:** `ldap, config, pki_config, nssdb, subject_base,
ca_subject, realm, fqdn, basedn, random_serial_numbers`, plus optional
parameters for signing algorithm, external CA, HSM token, and certificate
files.

**Key methods:**

| Method | Description |
|--------|-------------|
| `_configure_ca_certs()` | Generate or load CA certificate |
| `_generate_ca_certificate()` | Self-signed CA cert (RSA, 10 years) |
| `_generate_external_ca_csr()` | CSR for external CA (step 1) |
| `_install_external_ca_cert()` | Import external CA cert (step 2) |
| `_store_ca_cert_ldap()` | Store CA cert in LDAP |
| `_create_ipa_ca_entry()` | Create IPA CA entry with UUID, RSN version |
| `_init_cert_storage_schema()` | Initialize Dogtag certificate schema |
| `_store_ca_cert_in_certdb()` | Store CA cert in Dogtag storage |
| `_generate_subsystem_certs()` | Generate subsystem, audit, OCSP, agent certs |
| `_create_pkidbuser_entry(cert)` | Create `uid=pkidbuser` for healthcheck |
| `_generate_server_cert()` | Server SSL cert for Gunicorn |
| `_generate_ra_cert()` | RA agent cert (PEM for replicas) |
| `_create_ca_agent()` | Create `uid=ipara,ou=People,o=ipaca` CA agent entry |
| `_verify_ra_key_custodia()` | Test RA key Custodia access |
| `_get_signing_hash_algorithm()` | Resolve hash algorithm from config/profile |
| `_store_hsm_configuration()` | Store HSM token config in LDAP |

**Constructor full signature:** `ldap, config, pki_config, nssdb,
subject_base, ca_subject, realm, fqdn, basedn, random_serial_numbers,
ca_signing_algorithm, external_ca_step, external_ca_type,
external_ca_profile, csr_file, cert_file, cert_chain_file, tokenname,
token_library_path, token_password, load_external_cert_fn, clone`.

**Serial number handling:**
- Random serial numbers: 128-bit with MSB set (RSNv3).
- Sequential: serial 1 for CA, incremented for subsystems.

**Module-level functions:**
- `get_cert_params_from_config(pki_config, cert_type)` -- Extract key size
  and signing algorithm from PKI config.
- `convert_signing_algorithm(signing_alg)` -- Convert algorithm string to
  `cryptography` hash instance.

### LDAPSetup (`install/ldap_setup.py`)

LDAP schema and storage initialization.

| Method | Description |
|--------|-------------|
| `_install_ldap_schema()` | Load Dogtag LDAP schema |
| `_install_dogtag_schema()` | Load schema from `/usr/share/pki/server/database/ds/schema.ldif` |
| `_create_ds_db()` | Create `o=ipaca` backend and mapping tree |
| `_initialize_ldap_storage()` | Initialize storage with CA configuration |
| `_configure_ldapi_autobind()` | Configure LDAPI SASL EXTERNAL for ipaca |
| `_register_ca_service()` | Register CA in LDAP masters |
| `_import_profiles_ldap()` | Import profiles to IPA and Dogtag trees |

**LDAPI autobind:** Maps the `ipaca` Unix account to
`uid=ipacasrv,cn=sysaccounts,...` so the ipacta service can
authenticate to LDAP without a password.

### ServiceMgmt (`install/service_mgmt.py`)

Service lifecycle management.

| Method | Description |
|--------|-------------|
| `_create_directories()` | Create `/var/lib/ipacta/{ca,audit,private,certs,profiles}` |
| `_create_service_config()` | Write `ipacta.conf` via `IpactaConfig` |
| `_install_systemd_service()` | Install and enable `ipacta.service` |
| `_configure_audit_logging()` | Configure audit with signing cert from NSSDB |
| `_install_renewal_scripts()` | Install certmonger renewal helpers |
| `_configure_certmonger_renewal()` | Start certmonger tracking for NSSDB certs |
| `_cleanup_existing_tracking()` | Clean up stale certmonger requests |
| `_stop_certmonger_tracking()` | Stop all tracking |
| `_http_proxy()` | Configure Apache proxy with RA agent cert |
| `_start_service()` | Start service, wait for REST API (calls `wait_for_requests_by_postsave()` first) |
| `_wait_for_ds()` | Wait for Directory Server LDAPI socket |
| `_wait_for_ca_ready()` | Poll `https://{fqdn}:8443/ca/rest/info` (uses `http.client` directly) |
| `_generate_initial_crl()` | Generate first CRL via Python CA backend |

**Directory permissions:** `ca`, `audit`, `private` = 0o700; `certs`,
`logs` = 0o755.

### Replication (`install/replica.py`)

Replication topology activation.

| Method | Description |
|--------|-------------|
| `update_topology()` | Activate `o=ipaca` topology segment |

Applies `ca-topology.ldif` with base DN substitution.

### ACME (`install/acme.py`)

ACME service setup.

| Method | Description |
|--------|-------------|
| `setup_acme()` | Install ACME LDAP schema and storage |
| `_create_acme_config()` | Create config entry (disabled by default) |

### KRAInstall (`install/kra.py`)

Key Recovery Authority setup.

| Method | Description |
|--------|-------------|
| `enable_kra()` | Enable KRA functionality |
| `_generate_kra_audit_cert(key, cert)` | Generate KRA audit cert |
| `_add_vault_container()` | Create vault container in LDAP |
| `_register_kra_service()` | Register KRA in LDAP masters |

Creates the KRA LDAP schema (`o=kra,o=ipaca`), vault containers, and
service registration.

### LWCA (`install/lwca.py`)

Lightweight CA infrastructure.

| Method | Description |
|--------|-------------|
| `ensure_lightweight_cas_container()` | Create `ou=authorities` container |
| `add_lightweight_ca_tracking_requests()` | Track LWCA certs with certmonger |

## PKI Configuration

`_PKIConfigBuilder` merges configuration from 6 layers (later overrides
earlier):

1. `/usr/share/pki/server/etc/default.cfg` -- PKI defaults.
2. `{USR_SHARE_IPA_DIR}/ipaca_default.ini` -- IPA immutable baseline.
3. Installer parameters -- `random_serial_numbers` only.
4. `{USR_SHARE_IPA_DIR}/ipaca_customize.ini` -- IPA customizable defaults.
5. `{USR_SHARE_IPA_DIR}/ipaca_softhsm2.ini` -- HSM overrides (if enabled).
6. `pki_config_override` -- User custom overrides.

After all six layers are merged, a **final override** step sets
`ca_signing_algorithm` and `ca_key_type` (when given as installer
parameters) directly on the `ConfigParser` defaults. This has to happen
after layer merging because these installer-supplied values must win
over the `SHA256withRSA` default that `ipaca_customize.ini` hardcodes
in its `[DEFAULT]` section, and `ConfigParser` constructor defaults
cannot override values loaded from an ini file's `[DEFAULT]` section.

**Immutable keys** (`realm`, `host`, `basedn` and all keys in
`ipaca_default.ini`) cannot be overridden by later layers.

`extract_ipacta_params(pki_config)` translates PKI-specific key names
to ipacta-native names for `IpactaConfig.from_install_params()`.

## Fresh Installation Flow

```
IpactaInstance.create_instance()
  |
  |-- 1.  _svc._create_directories()
  |       Create /var/lib/ipacta/{ca,audit,private,certs,profiles}
  |
  |-- 2.  _nssdb.create_nssdb()
  |       Create /etc/pki/pki-tomcat/alias/ with random password
  |
  |-- 3.  _import_replica_keys()                     (if pkcs12_info set)
  |       Import CA keys from master PKCS#12 into NSSDB
  |
  |-- 4.  _svc._create_service_config()
  |       Write /etc/ipa/ipacta.conf
  |
  |-- 5.  _ldap_setup._install_ldap_schema()
  |       Load Dogtag LDAP schema
  |
  |-- 6.  _ldap_setup._initialize_ldap_storage()
  |       Create o=ipaca backend, mapping tree, LDAPI autobind
  |
  |-- 7.  _configure_ldap_access()
  |       Create ipacasrv sysaccount, ACI on o=ipaca, sub-CA schema
  |
  |-- 8.  _certs._configure_ca_certs()
  |       Generate self-signed CA cert+key (or external CA steps)
  |
  |-- 9.  _certs._store_ca_cert_ldap()
  |       Store CA cert at cn=CAcert,cn=ipa,cn=etc,{basedn}
  |
  |-- 10. _certs._create_ipa_ca_entry()
  |       Create cn=ipa,cn=cas,cn=ca,{basedn} with UUID and RSN version
  |
  |-- 11. _certs._init_cert_storage_schema()
  |       Initialize Dogtag certificate repository schema
  |
  |-- 12. _certs._store_ca_cert_in_certdb()
  |       Store CA cert in Dogtag storage backend
  |
  |-- 13. _ldap_setup._import_profiles_ldap()       (non-clone only)
  |-- 14. _create_default_caacl()                    (non-clone only)
  |-- 15. _lwca.ensure_lightweight_cas_container()   (non-clone only)
  |-- 16. _acme.setup_acme()                         (non-clone only)
  |       Load ACME schema, init storage, create config (disabled)
  |
  |-- 17. _certs._generate_server_cert()
  |-- 18. _certs._generate_ra_cert()
  |-- 19. _certs._create_ca_agent()
  |       Create uid=ipara,ou=People,o=ipaca CA agent LDAP entry
  |
  |-- 20. _certs._verify_ra_key_custodia()
  |-- 21. _certs._generate_subsystem_certs()
  |
  |-- 22. _svc._install_renewal_scripts()
  |-- 23. _svc._install_systemd_service()
  |-- 24. _svc._configure_audit_logging()
  |-- 25. _svc._http_proxy()
  |-- 26. _nssdb.apply_nssdb_permissions()
  |       Apply ownership, mode, ACLs on NSSDB
  |
  |-- 27. _svc._start_service()
  |       Start ipacta.service, wait for REST API
  |
  |-- 28. _svc._configure_certmonger_renewal()
  |       Start certmonger tracking (after service is running)
  |
  |-- 29. configure_agent_renewal()
  |       Configure certmonger tracking for the RA agent certificate
  |
  |-- 30. _svc._generate_initial_crl()
  |       Generate first CRL
  |
  '-- 31. __enable_instance()
          Register CA in LDAP (ldap_configure), set caRenewalMaster
```

## Replica Installation Flow

Same as fresh installation with these differences:

- Steps 13-16 are **skipped** (profiles, default CA ACL, LWCA
  container, and ACME already exist on the master).
- If `pkcs12_info` and `pkcs12_pwd` are set, step 3 imports CA keys
  from the master's PKCS#12 into the NSSDB.
- Certificate data is obtained from the master via PKCS#12 or Custodia.

## Replica Promotion Flow

When `promote=True`:

1. **Pre-promotion:** Create `o=ipaca` backend and mapping tree early
   (`_ldap_setup._create_ds_db()`).
2. **Replication:** Set up bidirectional replication agreements and
   activate the topology segment (`_repl.update_topology()`). After this
   step, `o=ipaca` data is replicated from the master.
3. **Remaining steps:** Same as fresh installation (but LDAP data is
   already populated via replication).
4. **Post-install:** `finalize_replica_config()` switches replication
   timeouts to production values.

## LDAP Modifications Summary

### Schema and Structure

| Component | LDAP Operations |
|-----------|-----------------|
| LDAPSetup | Dogtag schema, `o=ipaca` backend/mapping, ACME schema |
| Certs | `cn=CAcert`, IPA CA entry, `uid=pkidbuser` |
| IpactaInstance | `uid=ipacasrv` sysaccount, autobind mapping, ACI |
| KRAInstall | KRA schema (`o=kra,o=ipaca`), vault containers |
| ACME | ACME schema, `ou=acme,o=ipaca`, config entry |
| LWCA | `ou=authorities,ou=ca,o=ipaca` |

### Service Registration

| Service | LDAP Entry | Config |
|---------|-----------|--------|
| CA | `cn=CA,cn={fqdn},cn=masters,...` | `enabledService, startOrder 50, caRenewalMaster` |
| KRA | `cn=KRA,cn={fqdn},cn=masters,...` | `enabledService, startOrder 51` |

### Access Control

| Target | Principal | Access |
|--------|-----------|--------|
| `o=ipaca` | `uid=ipacasrv` | Full access to all Dogtag CA data |
| `cn=cas,cn=ca` | `uid=ipacasrv` | Manage sub-CA entries |

## External CA Support

ipacta supports two-step external CA signing:

**Step 1** (`external_ca_step=1`):
- Generates an RSA key pair.
- Creates a CSR with the configured subject DN.
- Writes the CSR to the file specified by `csr_file`.
- Installation exits. The administrator submits the CSR to the external
  CA and obtains the signed certificate.

**Step 2** (`external_ca_step=2`):
- Reads the signed certificate from `cert_file`.
- Reads the CA chain from `cert_chain_file`.
- Validates the certificate against the chain.
- Imports the certificate and chain into the NSSDB and LDAP.
- Continues with the rest of the installation.

## HSM Support

When `token_name` is set, keys are generated in the HSM instead of the
NSS database:

- The `Certs` helper detects HSM configuration and uses `HSMKeyBackend`
  for key generation.
- `HSMPrivateKeyProxy` wraps the HSM key so it can be used with the
  `cryptography` library signing API.
- The HSM configuration (token name, library path) is stored in LDAP
  at the IPA CA entry for replica discovery.
- Internal NSS software tokens are rejected (the token must be external
  hardware).

## Uninstallation

```python
instance.uninstall()
```

1. Stops certmonger tracking for all certificates.
2. Stops and disables `ipacta.service`.
3. Removes configuration files and directories.
4. Removes LDAP entries (service registration, backend).

## Key Design Patterns

1. **Composition over inheritance:** Each helper handles one concern;
   `IpactaInstance` orchestrates.
2. **Idempotency:** Most operations check existence before creation and
   skip if already present.
3. **NSSDB-centric:** All certificates and keys live in NSSDB except
   server cert (PEM for Gunicorn) and RA agent cert (PEM for Custodia).
4. **LDAPI autobind:** `ipaca` Unix account maps to `ipacasrv` LDAP
   account (no password needed).
5. **No circular imports:** `ipacta/install/` never imports from
   `ipaserver`; the `_ldap_mod` and `_ldap_update` callables are
   injected instead.
