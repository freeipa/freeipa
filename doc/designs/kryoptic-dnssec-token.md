# DNSSEC PKCS#11 Token: Migration from SoftHSMv2 to Kryoptic

## Overview

FreeIPA uses a PKCS#11 token to store DNSSEC signing keys managed by
OpenDNSSEC.  Historically this token was provided by
[SoftHSMv2](https://github.com/opendnssec/SoftHSMv2), a file-based
PKCS#11 implementation.  This design replaces SoftHSMv2 with
[Kryoptic](https://github.com/latchset/kryoptic), a Rust-based
PKCS#11 implementation that uses an SQLite backend and is actively
maintained by the Fedora/RHEL crypto team.

Related ticket: [FreeIPA #9985](https://pagure.io/freeipa/issue/9985)

See also: [HSM design](hsm.md) for hardware HSM support in the PKI CA/KRA.

## Scope

This change covers:

- **Fresh installations**: new IPA servers install and configure Kryoptic
  instead of SoftHSMv2.
- **Upgrades**: existing servers running SoftHSMv2 are automatically
  migrated to Kryoptic during `ipa-server-upgrade`.
- **DNSSEC token only**: the PKI CA/KRA HSM token (when using hardware
  HSMs) is a separate concern handled by the existing `--token-name` /
  `--library-path` options (see [hsm.md](hsm.md)).  This design does not
  change hardware HSM support.

## Architecture

### Token layout

| Component | SoftHSMv2 (old) | Kryoptic (new) |
|:--|:--|:--|
| Library | `/usr/lib64/pkcs11/libsofthsm2.so` | `/usr/lib64/pkcs11/libkryoptic_pkcs11.so` |
| Configuration | `/etc/ipa/dnssec/softhsm2.conf` | `/etc/ipa/dnssec/kryoptic.conf` |
| Token storage | `/var/lib/ipa/dnssec/tokens/<uuid>/` (directory tree) | `/var/lib/ipa/dnssec/tokens/kryoptic.sql` (single file) |
| User PIN | `/var/lib/ipa/dnssec/softhsm_pin` | `/var/lib/ipa/dnssec/hsm_pin` |
| SO PIN | `/etc/ipa/dnssec/softhsm_pin_so` | `/etc/ipa/dnssec/hsm_pin_so` |
| Token label | `ipaDNSSEC` | `ipaDNSSEC` (unchanged) |
| Environment var | `SOFTHSM2_CONF` | `KRYOPTIC_CONF` |
| Sysconfig key (PIN) | `DNSSEC_SOFTHSM_PIN` | `DNSSEC_HSM_PIN` |
| Init tool | `softhsm2-util --init-token` | `pkcs11-tool --init-token` (from OpenSC) |

### Kryoptic configuration format

```toml
# Kryoptic PKCS#11 configuration

[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/var/lib/ipa/dnssec/tokens/kryoptic.sql"
```

### Path constants

Backend-neutral path aliases are introduced in `ipaplatform/base/paths.py`:

| Constant | Value | Notes |
|:--|:--|:--|
| `DNSSEC_KRYOPTIC_CONF` | `/etc/ipa/dnssec/kryoptic.conf` | New |
| `DNSSEC_HSM_PIN` | `/var/lib/ipa/dnssec/hsm_pin` | Renamed from `softhsm_pin` |
| `DNSSEC_HSM_PIN_SO` | `/etc/ipa/dnssec/hsm_pin_so` | Renamed from `softhsm_pin_so` |
| `LIBKRYOPTIC_SO` | `/usr/lib/pkcs11/libkryoptic_pkcs11.so` | New |
| `PKCS11_TOOL` | `/usr/bin/pkcs11-tool` | New |
| `LEGACY_DNSSEC_SOFTHSM_PIN` | `/var/lib/ipa/dnssec/softhsm_pin` | For migration |
| `LEGACY_DNSSEC_SOFTHSM_PIN_SO` | `/etc/ipa/dnssec/softhsm_pin_so` | For migration |

Deprecated aliases (`DNSSEC_SOFTHSM_PIN`, `DNSSEC_SOFTHSM_PIN_SO`,
`DNSSEC_SOFTHSM2_CONF`) remain as pointers to the new names for
backward compatibility with external code.

## Implementation

### Fresh installation

`dnskeysyncinstance.DNSKeySyncInstance.__setup_hsm()` (renamed from
`__setup_softhsm()`) performs these steps:

1. Creates `/var/lib/ipa/dnssec/tokens/` with mode 0770, setgid,
   owned by `ods:named`.
2. Calls `write_kryoptic_config()` to generate `kryoptic.conf`.
3. Generates random user PIN and SO PIN (30 characters each).
4. Writes PINs to `hsm_pin` (0660, `ods:named`) and `hsm_pin_so`
   (0400, `root:root`).
5. Calls `p11helper.init_token()` which runs:
   - `pkcs11-tool --module <lib> --init-token --label ipaDNSSEC --so-pin <so_pin>`
   - `pkcs11-tool --module <lib> --init-pin --token-label ipaDNSSEC --login --so-pin <so_pin> --new-pin <user_pin>`
6. Configures sysconfig files with `KRYOPTIC_CONF` and `DNSSEC_HSM_PIN`
   directives.
7. Generates the OpenSSL configuration for BIND to access the token
   via `pkcs11-provider` or `openssl-pkcs11`.

### OpenDNSSEC integration

The OpenDNSSEC configuration template (`opendnssec_conf.template`)
references a `Repository` named `Kryoptic` (was `SoftHSM`).  The
template variables are renamed from `$SOFTHSM_LIB` to `$PKCS11_LIB`.

### BIND named integration

The OpenSSL configuration templates for BIND (`bind.openssl.*.template`)
reference `$PKCS11_MODULE` and `$PKCS11_PIN` instead of the old
`$SOFTHSM_MODULE` / `$SOFTHSM_PIN` variables.  The sysconfig files
(`/etc/sysconfig/named`, `/etc/sysconfig/ipa-dnskeysyncd`) export
`KRYOPTIC_CONF` instead of `SOFTHSM2_CONF`.

### p11-kit module isolation

Both Kryoptic and SoftHSMv2 are disabled in `p11-kit-proxy` to prevent
their PKCS#11 modules from leaking into NSS databases used by PKI and
other components:

```python
PKCS11_MODULES = [
    ('kryoptic', paths.LIBKRYOPTIC_SO, ['p11-kit-proxy']),
    ('softhsm2', paths.LIBSOFTHSM2_SO_64, ['p11-kit-proxy']),
]
```

Each entry generates a `.module` file in `/etc/pkcs11/modules/` with
`disable-in: p11-kit-proxy`.

### PKCS#11 attribute and mechanism fixes

**CKA_TRUSTED removal**: The `CKA_TRUSTED` attribute was removed from
all public key templates in `p11helper.py` (`generate_replica_key_pair`,
`import_public_key`, `_import_RSA_public_key`).  SoftHSMv2 accepted this
attribute, but PKCS#11 specifies it as non-settable by normal
applications; Kryoptic correctly rejects it with
`CKR_ATTRIBUTE_TYPE_INVALID`.

**AES key wrapping mechanisms**: PKCS#11 v3.0 section 2.1.23 defines
two distinct key wrapping with padding mechanisms:

- `CKM_AES_KEY_WRAP_PAD` (0x210a) — uses PKCS#7 padding followed by
  AES Key Wrap per [AES KEYWRAP] Section 6.2, with an 8-byte IV.
- `CKM_AES_KEY_WRAP_KWP` (0x210b) — uses the padding defined in
  [AES KEYWRAP] Section 6.3 / RFC 5649, with a 4-byte IV.

These are **not** interchangeable: data wrapped with one mechanism
cannot be unwrapped with the other.  FreeIPA stores wrapped keys in
LDAP using `CKM_AES_KEY_WRAP_PAD` (recorded as `aesKeyWrapPad` in
the `ipawrappingmech` attribute), so Kryoptic must support
`CKM_AES_KEY_WRAP_PAD` for backward compatibility.  Support for
`CKM_AES_KEY_WRAP_KWP` is also added to `p11helper.py` and the
wrapping mechanism registry as `aesKeyWrapKwp` for future use.

### SELinux file contexts

SELinux file contexts are updated to label the new paths with
`ipa_dnskey_t`:

```
/var/lib/ipa/dnssec/hsm_pin      -- ipa_dnskey_t
/etc/ipa/dnssec/kryoptic.conf    -- ipa_dnskey_t
/etc/ipa/dnssec/hsm_pin_so       -- ipa_dnskey_t
```

### Backup and restore

`ipa-backup` includes the new file paths (`kryoptic.conf`, `hsm_pin_so`)
in the backup set, replacing the old SoftHSMv2 references.

## Upgrade: SoftHSM to Kryoptic migration

The migration is performed by `dnssec_migrate_softhsm_to_kryoptic()`
in `ipaserver/install/server/upgrade.py`, called during
`ipa-server-upgrade`.

### Migration detection

The migration triggers when both conditions are met:

1. `/etc/ipa/dnssec/softhsm2.conf` exists.
2. The sysupgrade state `dns.kryoptic_migration` is not set.

If `softhsm2.conf` does not exist (fresh install or already migrated),
the state flag is set and migration is skipped.

### Migration steps

1. **Read existing PINs** from the legacy paths:
   - User PIN from `/var/lib/ipa/dnssec/softhsm_pin`
   - SO PIN from `/etc/ipa/dnssec/softhsm_pin_so` (if it exists;
     otherwise a new SO PIN is generated)

2. **Write Kryoptic configuration** by calling
   `dnskeysyncinstance.write_kryoptic_config()`.

3. **Initialize Kryoptic token** using `pkcs11-tool` via
   `p11helper.init_token()`.  On failure, the new files are cleaned up
   and migration is retried on the next upgrade run.

4. **Migrate token data** using `softhsm_migrate` (from the
   `kryoptic-tools` package):
   ```
   softhsm_migrate -m /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
       -i kryoptic_conf=/etc/ipa/dnssec/kryoptic.conf \
       -p <user_pin> -q <user_pin> \
       /var/lib/ipa/dnssec/tokens/<uuid>/
   ```
   This reads the SoftHSMv2 file-based object store and imports all
   objects into the Kryoptic SQLite database.  On failure, the Kryoptic
   database and config are removed and migration is retried on next
   upgrade.

5. **Rename PIN files**:
   - `softhsm_pin` -> `hsm_pin`
   - `softhsm_pin_so` -> `hsm_pin_so`

6. **Regenerate sysconfig and OpenSSL configs** to reference
   `KRYOPTIC_CONF` and `DNSSEC_HSM_PIN`.

7. **Remove stale SoftHSM directives** (`SOFTHSM2_CONF`,
   `DNSSEC_SOFTHSM_PIN`) from sysconfig files.

8. **Remove the SoftHSMv2 p11-kit module file** and `softhsm2.conf`.

9. **Set sysupgrade state** `dns.kryoptic_migration = True`.

### Idempotency

The migration is idempotent:

- The `kryoptic_migration` state flag prevents re-execution.
- If `softhsm_migrate` or `init_token` fails, partial state is cleaned
  up and the flag is not set, so the next `ipa-server-upgrade` retries.

### Rollback

There is no automatic rollback.  If a manual rollback is needed:

1. Stop `ipa-dnskeysyncd` and `ipa-ods-exporter`.
2. Restore `softhsm2.conf` and the SoftHSM token directory.
3. Rename `hsm_pin` back to `softhsm_pin` and `hsm_pin_so` to
   `softhsm_pin_so`.
4. Remove `kryoptic.conf` and `kryoptic.sql`.
5. Update sysconfig files to reference `SOFTHSM2_CONF` and
   `DNSSEC_SOFTHSM_PIN`.
6. Clear the `dns.kryoptic_migration` state from
   `/var/lib/ipa/sysupgrade.state`.
7. Restart services.

## RPM dependencies

| Old dependency | New dependency |
|:--|:--|
| `softhsm >= 2.0.0rc1-1` | `kryoptic` |
| | `kryoptic-tools` (provides `softhsm_migrate`) |
| | `opensc` (provides `pkcs11-tool`) |

`softhsm` is no longer a build or runtime dependency.

## Testing

### Unit tests

`ipatests/test_ipaserver/test_ipap11helper.py` exercises token
initialization, key generation, import/export, and wrapping operations
against a temporary Kryoptic token created via `init_token()`.

### Integration tests

#### Existing tests updated

- `test_hsm.py`: `delete_hsm_token()` uses direct file removal
  (`rm -f kryoptic.sql kryoptic.conf`) for the software token path,
  and `cleantoken.sh` for hardware HSMs.
- `test_installation.py`: `test_p11_kit_kryoptic` verifies that
  Kryoptic is registered in `p11-kit` and SoftHSM is not visible.

#### New migration test

`test_upgrade.py::TestSoftHSMToKryopticMigration`:

- `test_softhsm_to_kryoptic_migration`: creates a simulated
  pre-migration state with legacy SoftHSM artifacts (config, PIN files,
  sysconfig directives), runs `ipa-server-upgrade`, and verifies:
  - Kryoptic config is created
  - PIN files are at the new paths
  - Old `softhsm_pin` and `softhsm2.conf` are removed
  - Sysconfig references `KRYOPTIC_CONF`, not `SOFTHSM2_CONF`
  - `DNSSEC_HSM_PIN` is present in `ipa-dnskeysyncd` sysconfig
  - `DNSSEC_SOFTHSM_PIN` is absent from all sysconfig files
  - Upgrade state `dns.kryoptic_migration` is set
- `test_migration_idempotent`: verifies that re-running upgrade after
  migration is a no-op.
