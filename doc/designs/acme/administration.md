# External ACME Server: IPA Administration

This page covers IPA commands and web UI that are **identical for both
integration models** (the [RA proxy model](ra-model.md) and the
[HSM-backed external-key model](external-key-model.md)).  Model-specific
setup steps — sub-CA creation, service principal and role assignment, ACME
server configuration — are documented in the respective model design pages.

## EAB Account Management

EAB is the ACME mechanism (RFC 8555 §7.3.4) by which a CA pre-registers a
client before it can request certificates.  The client proves its identity by
signing its ACME account request with a shared HMAC secret that only the CA
and the client know.  This prevents anonymous clients from obtaining
certificates from a CA that has no prior knowledge of them.

An EAB account in IPA maps an ACME client to an IPA principal (host or
service) and to a specific ACME-dedicated sub-CA.  Each account has two
components the ACME client must supply at registration time:

- **Key ID (KID)** — a unique opaque identifier for the account, assigned by
  IPA and provided to the ACME server in the `kid` field of the EAB token.
- **HMAC key** — a cryptographically random shared secret used to sign the EAB
  token.  It authenticates the client to the CA and is never stored in
  retrievable form after initial display.

Accounts are managed with `ipa ca-acme-*` commands, where the sub-CA name
(`ca-name`) is the primary object and the KID is the per-account identifier.
A principal that uses two different ACME servers (backed by different sub-CAs)
holds two separate EAB accounts — one per sub-CA.

### Creating an EAB Account

```bash
# For an IPA host
ipa ca-acme-add acme-corp-us --host server1.ipa.example.com

# Example output:
#   Account ID:  a3f8e1c2d9b74650
#   HMAC key:    dGhpcyBpcyBhIDMyLWJ5dGUgc2VjcmV0IGtleQo  (one-time display)

# For an IPA service
ipa ca-acme-add acme-corp-us --service HTTP/app.ipa.example.com
```

The HMAC key is the shared secret the ACME client uses to sign its EAB token.
It is displayed once and cannot be retrieved again — IPA stores only a hash.
Copy it immediately and store it in a secrets manager or pass it directly to
the ACME client configuration.

### Configuring the ACME Client

Use the KID and HMAC key printed by `ca-acme-add` to register the ACME
client:

```bash
# certbot example
certbot certonly \
    --server https://acmeserver.ipa.example.com/acme/directory \
    --eab-kid  a3f8e1c2d9b74650 \
    --eab-hmac-key dGhpcyBpcyBhIDMyLWJ5dGUgc2VjcmV0IGtleQo \
    -d server1.ipa.example.com

# acme.sh example
acme.sh --register-account \
    --server https://acmeserver.ipa.example.com/acme/directory \
    --eab-kid  a3f8e1c2d9b74650 \
    --eab-hmac-key dGhpcyBpcyBhIDMyLWJ5dGUgc2VjcmV0IGtleQo
```

### Rotating the HMAC Key

If the HMAC key is compromised or needs to be rotated, regenerate it in place.
The KID is preserved, so only the ACME client's secret needs to be updated —
the account registration on the ACME server remains valid.

```bash
ipa ca-acme-mod acme-corp-us a3f8e1c2d9b74650 --hmac-key
# → prints new HMAC key once; old key is immediately invalidated
```

If the KID must also change (e.g. suspected account compromise), delete and
recreate the account:

```bash
ipa ca-acme-del acme-corp-us a3f8e1c2d9b74650
ipa ca-acme-add acme-corp-us --host server1.ipa.example.com
# → new KID and new HMAC key; update the ACME client registration
```

### Viewing and Listing EAB Accounts

```bash
# Show a single account by KID (status; never shows HMAC key)
ipa ca-acme-show acme-corp-us a3f8e1c2d9b74650

# List all EAB accounts for a given sub-CA — returns the KID, principal,
# and enabled status of every account; HMAC keys are never included
ipa ca-acme-find acme-corp-us

# List all ACME-dedicated sub-CAs
ipa ca-find --acme
```

### Disabling and Deleting EAB Accounts

Disabling an account (setting `ipaACMEEnabled: FALSE`) prevents the ACME
server from accepting new registrations for the KID without removing the
entry.  This is useful for temporarily suspending access.

```bash
# Disable (suspend) without deleting — the ACME server rejects the KID
ipa ca-acme-mod acme-corp-us a3f8e1c2d9b74650 --disable

# Re-enable
ipa ca-acme-mod acme-corp-us a3f8e1c2d9b74650 --enable

# Permanent removal — subsequent ACME registration with the old KID fails
ipa ca-acme-del acme-corp-us a3f8e1c2d9b74650
```

When decommissioning a host, revoke all outstanding ACME-issued certificates
and then delete the EAB account.  A single EAB account can have multiple valid
certificates simultaneously (different SANs, overlapping renewals, or
certificates obtained by different ACME clients), so a single `certbot revoke`
is not sufficient — it only revokes what certbot locally tracks.  Use
`ipa cert-find` to locate every valid certificate issued by the sub-CA for the
principal and revoke each one:

```bash
# 1. Find all valid certificates issued under this sub-CA for the host
ipa cert-find --subject server1.ipa.example.com --ca acme-corp-us

# 2. Revoke each certificate by serial number
ipa cert-revoke <serial1>
ipa cert-revoke <serial2>
# ... repeat for every serial returned above

# 3. Delete the EAB account so the KID cannot be re-used for new registrations
ipa ca-acme-del acme-corp-us a3f8e1c2d9b74650
```

## CLI Reference

| Command | Key Options |
|---|---|
| `ipa ca-acme-add <ca-name>` | `--host <fqdn>` or `--service <principal>` — required; generates KID and HMAC key |
| `ipa ca-acme-mod <ca-name> <kid>` | `--hmac-key` — regenerates HMAC key; `--enable` / `--disable` |
| `ipa ca-acme-show <ca-name> <kid>` | `--all` |
| `ipa ca-acme-del <ca-name> <kid>` | (none) |
| `ipa ca-acme-find <ca-name>` | `--host <fqdn>`, `--service <principal>` — optional filters |
| `ipa ca-find` | `--acme` — list only ACME-dedicated sub-CAs |

## Web UI

The IPA web UI exposes EAB account management on the sub-CA detail page and
on the Host and Service detail pages:

- On the sub-CA detail page: a list of EAB accounts associated with that CA,
  with an **"Add account"** button that opens a form to select the principal
  (host or service) and calls `ca-acme-add`.  The one-time HMAC key is shown
  in a modal dialog immediately after creation.
- On the Host (and Service) detail page: a status badge showing whether the
  host/service has an active EAB account (`ipaACMEEnabled: TRUE`) for each
  ACME-dedicated sub-CA it is enrolled with.

The HMAC key must not be stored by the UI, re-displayed on page reload, or
included in any API response after the initial creation call.

## Implementation

### Shared IPA Framework Components

The following components are required by both integration models and are
implemented once:

**New file: `ipalib/plugins/ca.py` additions (or `ipalib/plugins/acme.py`)**

EAB account commands are extensions of the `ca` object:

| Command | Action |
|---|---|
| `ca-acme-add <ca-name> --host <fqdn>` | Generate KID + HMAC key; create `ipaACMEAccount` entry in `cn=acmeaccounts,cn=ca,$SUFFIX`; display key once |
| `ca-acme-add <ca-name> --service <principal>` | Same, for service principals |
| `ca-acme-mod <ca-name> <kid> --hmac-key` | Regenerate HMAC key in place; KID unchanged; print new key once |
| `ca-acme-mod <ca-name> <kid> --enable/--disable` | Set `ipaACMEEnabled` flag |
| `ca-acme-show <ca-name> <kid>` | Show KID and `ipaACMEEnabled`; never shows HMAC key |
| `ca-acme-del <ca-name> <kid>` | Remove `ipaACMEAccount` entry |
| `ca-acme-find <ca-name>` | Search `cn=acmeaccounts` scoped to the given sub-CA |

**New schema file: `install/share/65acme.ldif`**

Defines the `ipaACMEAccount` structural objectClass and its attributes
(`ipaACMEAccountID`, `ipaACMEHMACKey`, `ipaACMESubCA`, `ipaACMEPrincipal`,
`ipaACMEEnabled`).  The objectClass and `ipaACMECA` sub-CA marker are defined
in the [overview](overview.md#external-account-binding-eab).

**Schema upgrade: `install/updates/65-acme.update`**

Adds the objectClass and attributes to the schema on upgrade of an existing
IPA deployment.

**New permission: `Read ACME Account HMAC Keys`**

Grants read access to `ipaACMEHMACKey` in `cn=acmeaccounts,cn=ca,$SUFFIX`.
Added to `install/share/bootstrap-template.ldif`.  Only the ACME server's
service principal and IPA administrators should hold this permission.

## Backup and Restore

EAB account entries (`cn=acmeaccounts,cn=ca,$SUFFIX`) are included in the
standard IPA LDAP backup (`ipa-backup --data`).

The `ipaACMEHMACKey` attribute is security-sensitive.  Restoring a backup
re-enables all previously provisioned EAB accounts with their original HMAC
keys.  If a backup is restored after a key rotation, the old (pre-rotation)
HMAC keys become active again; ACME clients that were updated to the new key
will need to be reconfigured.

## Upgrade

LDAP schema additions (`ipaACMEAccount` objectClass and its attributes) are
backward-compatible.  The new `ca-acme-*` commands are ignored by IPA
versions that do not include this feature.

ACME-dedicated sub-CAs and EAB accounts must be created explicitly by an
administrator after upgrading; they are not provisioned automatically.

## Migration impact

### IPA-to-IPA migration (`ipa-migrate`)

`ipa-migrate` is the tool for moving data from one IPA deployment to another
(e.g., upgrading to new hardware or a new OS major version).  It migrates
objects by iterating over subtrees listed in `DB_OBJECTS`
(`ipaserver/install/ipa_migrate_constants.py`).

`cn=acmeaccounts,cn=ca,$SUFFIX` is a new subtree that `ipa-migrate` does not
yet know about.  Without an explicit entry in `DB_OBJECTS`, EAB accounts will
be silently omitted from the migration.  The `ipa-migrate` tool must be
extended:

1. **Add an `acmeaccounts` entry to `DB_OBJECTS`** — analogous to the existing
   `caacls` entry — that names the `ipaACMEAccount` objectClass and sets the
   subtree to `,cn=acmeaccounts,cn=ca,$SUFFIX`.

2. **Handle `ipaACMEHMACKey` as a security-sensitive attribute** — the HMAC
   secret must be migrated verbatim (not re-hashed), so the attribute must not
   be excluded or redacted during transfer.  The target deployment must be
   secured before migration is attempted.

3. **Perform a schema check before migrating accounts** — `ipa-migrate` must
   verify that `ipaACMEAccount` is present in the target schema before
   attempting to write EAB accounts.  Migration is assumed to be
   forward-looking (target is the same version or newer); if the target schema
   is absent, `cn=acmeaccounts` must be skipped and a warning issued rather
   than aborting the entire migration.

### Standard in-place upgrade

`ipa-upgrade` processes `install/updates/65-acme.update`, which:

1. **Adds the LDAP schema** — the `ipaACMEAccount` objectClass and its
   attributes (`ipaACMEAccountID`, `ipaACMEHMACKey`, `ipaACMESubCA`,
   `ipaACMEPrincipal`, `ipaACMEEnabled`) and the `ipaACMECA` auxiliary
   objectClass for marking sub-CAs.

2. **Creates the accounts container** — `cn=acmeaccounts,cn=ca,$SUFFIX` if it
   does not already exist.  This is a new node in the DIT.  It lives under
   `cn=ca,$SUFFIX`, which is already replicated, so no new replication
   agreement is required on any replica.

3. **Adds the ACIs and permission entries** — the `Manage ACME Accounts`,
   `Read ACME Account HMAC Keys`, and self-service ACIs are written to the
   container and to `cn=permissions,cn=pbac,$SUFFIX`.

4. **Does not touch existing sub-CA entries** — no `ipaACMECA` marker is
   applied to existing sub-CAs, and existing sub-CAs cannot be converted to
   ACME-dedicated ones.  An ACME-dedicated sub-CA must be created fresh with
   `ipa ca-add <ca-name> --acme`.

### Multi-replica deployments

`cn=acmeaccounts,cn=ca,$SUFFIX` is replicated to all IPA replicas alongside
the rest of `cn=ca,$SUFFIX`.  `ipa-upgrade` must be run on every replica; it
is idempotent (the update file skips entries that already exist).  EAB account
entries created after the upgrade are replicated automatically.

## Troubleshooting

### Verifying EAB Account Entries

EAB account data lives in the dedicated accounts container:

```bash
ldapsearch -Y GSSAPI \
    -b "cn=acmeaccounts,cn=ca,dc=ipa,dc=example,dc=com" \
    "(objectClass=ipaACMEAccount)" \
    ipaACMEAccountID ipaACMESubCA ipaACMEPrincipal ipaACMEEnabled
```

The HMAC key is not shown by `ipa ca-acme-show`.  To confirm the attribute
is present (e.g., after a backup restore), use `ldapsearch` with admin
credentials:

```bash
ldapsearch -Y GSSAPI \
    -b "cn=acmeaccounts,cn=ca,dc=ipa,dc=example,dc=com" \
    "(ipaACMEAccountID=a3f8e1c2d9b74650)" ipaACMEHMACKey
```

### EAB Validation Failures

If the external ACME server logs an EAB validation failure:

1. Confirm the KID in the ACME client configuration matches the value from
   `ipa ca-acme-show`.
2. Confirm the HMAC key was copied correctly — it is base64url-encoded with no
   line breaks.
3. Confirm the ACME server service principal has valid Kerberos credentials:
   `klist -k /etc/acme-server/ipa.keytab`.
4. Confirm the ACME server can reach the IPA LDAP server:
   `ldapsearch -Y GSSAPI -H ldaps://ipa.example.com -b "" -s base`.
5. Confirm the account is enabled (`ipaACMEEnabled: TRUE` in the LDAP entry).
