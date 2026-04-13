# External ACME Server: IPA Administration

This page covers IPA commands and web UI that are **identical for both
integration models** (the [RA proxy model](ra-model.md) and the
[HSM-backed external-key model](external-key-model.md)).  Model-specific
setup steps — sub-CA creation, service principal and role assignment, ACME
server configuration — are documented in the respective model design pages.

## EAB Account Management

An External Account Binding (EAB) account maps an ACME client to an IPA
principal (host or service) and to a specific ACME-dedicated sub-CA.  The
`--acme-ca` option is required on every `host-acme-*` and `service-acme-*`
command; it specifies which sub-CA the account is scoped to.  A principal that
uses two different ACME servers (backed by different sub-CAs) needs two
separate EAB accounts.

### Creating an EAB Account

```bash
# For an IPA host
ipa host-acme-add server1.ipa.example.com --acme-ca acme-corp-us

# Example output:
#   Account ID:  a3f8e1c2d9b74650
#   HMAC key:    dGhpcyBpcyBhIDMyLWJ5dGUgc2VjcmV0IGtleQo  (one-time display)

# For an IPA service
ipa service-acme-add HTTP/app.ipa.example.com --acme-ca acme-corp-us
```

The HMAC key is displayed once and cannot be retrieved again.  Copy it
immediately and store it in a secrets manager or pass it directly to the ACME
client configuration.

### Configuring the ACME Client

Use the KID and HMAC key printed by `host-acme-add` (or `service-acme-add`)
to register the ACME client:

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
ipa host-acme-mod server1.ipa.example.com --acme-ca acme-corp-us --hmac-key
# → prints new HMAC key once; old key is immediately invalidated

ipa service-acme-mod HTTP/app.ipa.example.com --acme-ca acme-corp-us --hmac-key
```

If the KID must also change (e.g. suspected account compromise), delete and
recreate the account:

```bash
ipa host-acme-del server1.ipa.example.com --acme-ca acme-corp-us
ipa host-acme-add server1.ipa.example.com --acme-ca acme-corp-us
# → new KID and new HMAC key; update the ACME client registration
```

### Viewing and Listing EAB Accounts

```bash
# Show a single account (KID and status; never shows HMAC key)
ipa host-acme-show server1.ipa.example.com --acme-ca acme-corp-us
ipa service-acme-show HTTP/app.ipa.example.com --acme-ca acme-corp-us

# List all EAB accounts for a given sub-CA
ipa acme-account-find --acme-ca acme-corp-us

# List all ACME-dedicated sub-CAs
ipa ca-find --acme
```

### Disabling and Deleting EAB Accounts

Disabling an account (setting `ipaACMEEnabled: FALSE`) prevents the ACME
server from accepting new registrations for the KID without removing the
entry.  This is useful for temporarily suspending access.

```bash
# Disable (suspend) without deleting — the ACME server rejects the KID
ipa host-acme-mod server1.ipa.example.com --acme-ca acme-corp-us --disable

# Re-enable
ipa host-acme-mod server1.ipa.example.com --acme-ca acme-corp-us --enable

# Permanent removal — subsequent ACME registration with the old KID fails
ipa host-acme-del server1.ipa.example.com --acme-ca acme-corp-us
```

When decommissioning a host, revoke any outstanding ACME-issued certificates
before or after deleting the EAB account:

```bash
ipa host-acme-del server1.ipa.example.com --acme-ca acme-corp-us
# Revoke outstanding certs via ACME client or directly:
certbot revoke --cert-path /etc/letsencrypt/live/server1/cert.pem
```

## CLI Reference

| Command | Key Options |
|---|---|
| `ipa host-acme-add <fqdn>` | `--acme-ca <name>` — required; generates KID and HMAC key |
| `ipa host-acme-mod <fqdn>` | `--acme-ca <name>`, `--hmac-key` — regenerates HMAC key; `--enable` / `--disable` |
| `ipa host-acme-show <fqdn>` | `--acme-ca <name>`, `--all` |
| `ipa host-acme-del <fqdn>` | `--acme-ca <name>` — required |
| `ipa service-acme-add <principal>` | `--acme-ca <name>` — required; generates KID and HMAC key |
| `ipa service-acme-mod <principal>` | `--acme-ca <name>`, `--hmac-key`; `--enable` / `--disable` |
| `ipa service-acme-show <principal>` | `--acme-ca <name>`, `--all` |
| `ipa service-acme-del <principal>` | `--acme-ca <name>` — required |
| `ipa acme-account-find` | `--acme-ca <name>` — filter by sub-CA |
| `ipa ca-find` | `--acme` — list only ACME-dedicated sub-CAs |

## Web UI

The IPA web UI exposes EAB account management on the Host and Service detail
pages:

- A toggle labelled **"Enable ACME certificate issuance"** calls
  `host-acme-add` and displays the one-time HMAC key in a modal dialog.
  The dialog shows the KID and HMAC key once; they cannot be retrieved again
  through the UI.
- A status badge on the Host (and Service) detail page shows whether an ACME
  EAB account is active (`ipaACMEEnabled: TRUE`) for a given sub-CA.
- The same controls appear on the Service detail page.

The HMAC key must not be stored by the UI, re-displayed on page reload, or
included in any API response after the initial creation call.

## Implementation

### Shared IPA Framework Components

The following components are required by both integration models and are
implemented once:

**New file: `ipalib/plugins/acme_account.py`**

| Command | Action |
|---|---|
| `host-acme-add <fqdn>` | Generate KID + HMAC key; create `ipaACMEAccount` entry in `cn=acmeaccounts,cn=ca,$SUFFIX`; display key once |
| `host-acme-mod <fqdn> --hmac-key` | Regenerate HMAC key in place; KID unchanged; print new key once |
| `host-acme-mod <fqdn> --enable/--disable` | Set `ipaACMEEnabled` flag |
| `host-acme-show <fqdn>` | Show KID and `ipaACMEEnabled`; never shows HMAC key |
| `host-acme-del <fqdn>` | Remove `ipaACMEAccount` entry |
| `service-acme-add <principal>` | Same as `host-acme-add`, for service principals |
| `service-acme-mod <principal>` | Same as `host-acme-mod` |
| `service-acme-show <principal>` | Same as `host-acme-show` |
| `service-acme-del <principal>` | Same as `host-acme-del` |
| `acme-account-find` | Search `cn=acmeaccounts` container; supports `--acme-ca` filter |

All `host-acme-*` commands accept `--acme-ca <sub-ca-name>` to scope the
operation to a specific ACME-dedicated sub-CA.

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
backward-compatible.  Hosts and services without the `ipaACMEAccount`
objectClass continue to function normally.  The new `host-acme-*` and
`service-acme-*` commands are ignored by IPA versions that do not include
this feature.

ACME-dedicated sub-CAs and EAB accounts must be created explicitly by an
administrator after upgrading; they are not provisioned automatically.

## Troubleshooting

### Verifying EAB Account Entries

EAB account data lives in the dedicated accounts container:

```bash
ldapsearch -Y GSSAPI \
    -b "cn=acmeaccounts,cn=ca,dc=ipa,dc=example,dc=com" \
    "(objectClass=ipaACMEAccount)" \
    ipaACMEAccountID ipaACMESubCA ipaACMEPrincipal ipaACMEEnabled
```

The HMAC key is not shown by `ipa host-acme-show`.  To confirm the attribute
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
   `ipa host-acme-show`.
2. Confirm the HMAC key was copied correctly — it is base64url-encoded with no
   line breaks.
3. Confirm the ACME server service principal has valid Kerberos credentials:
   `klist -k /etc/acme-server/ipa.keytab`.
4. Confirm the ACME server can reach the IPA LDAP server:
   `ldapsearch -Y GSSAPI -H ldaps://ipa.example.com -b "" -s base`.
5. Confirm the account is enabled (`ipaACMEEnabled: TRUE` in the LDAP entry).
