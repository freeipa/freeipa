# External ACME Server Integration: RA Proxy Model

## Overview

FreeIPA includes a built-in ACME server (Dogtag ACME, enabled via
`ipa-acme-manage enable`). Some deployments require a **third-party** ACME
server — for example, step-ca, Boulder, or a custom implementation — that
issues certificates under a FreeIPA sub-CA while relying on IPA for identity,
authorization, and certificate lifecycle management.

This design describes the **Registration Authority (RA) proxy model**, where
the external ACME server acts purely as a protocol frontend. All cryptographic
operations (signing) remain inside FreeIPA's Dogtag CA; the ACME server submits
CSRs to IPA and returns the resulting certificates to ACME clients. No sub-CA
private key material ever leaves FreeIPA.

The complementary [HSM-backed external-key model](external-key-model.md) covers deployments where
the external ACME server must sign certificates autonomously (e.g., air-gapped
or edge sites).

### Background

ACME (RFC 8555) is a protocol for automated certificate issuance and renewal.
**External Account Binding** (EAB, RFC 8555 §7.3.4) allows an ACME server to
require clients to prove membership in an external account system before
obtaining certificates. In this design, EAB maps ACME clients to IPA host,
service, or user principals, enabling IPA's existing access-control machinery
to govern what certificates each principal may receive.

FreeIPA lightweight sub-CAs (introduced in IPA 4.4, `ipa ca-add`) create
subordinate CA keypairs inside Dogtag. A sub-CA dedicated to external ACME
issuance:

- produces certificates with a distinct issuer DN, identifiable in audit logs,
- can carry a `nameConstraints` extension limiting issuable names to the IPA
  domain,
- can be revoked or replaced independently of the root CA.

## Use Cases

### UC-1: Automated TLS Certificate Renewal for IPA-Enrolled Hosts

An administrator wants all IPA-enrolled servers to obtain short-lived (90-day)
TLS certificates via a third-party ACME server that is integrated with the IPA
CA. Certificates are renewed automatically by certbot or acme.sh running on
each host. No manual certificate signing or `ipa cert-request` invocations are
required after initial setup.

### UC-2: Per-Service ACME Certificates

A web application runs as an IPA service principal `HTTP/app.example.com`. The
application's deployment pipeline uses an ACME client to obtain a TLS
certificate. The ACME server verifies that the certificate request is authorized
for the `HTTP/app.example.com` service principal before forwarding it to IPA.

### UC-3: Constrained ACME Issuance Without Wildcard or Cross-Domain Names

The security policy prohibits wildcard certificates and certificates for names
outside the IPA domain. The ACME sub-CA carries `nameConstraints` and the
certificate profile enforces maximum 90-day validity and specific key usages, so
these policies are enforced cryptographically even if the external ACME server
is misconfigured.

### UC-4: ACME Certificate Revocation via IPA

When an IPA host is decommissioned (`ipa host-del`), an administrator also
revokes all outstanding ACME-issued certificates for that host. The external
ACME server's revoke endpoint calls `ipa cert-revoke`, updating the IPA CRL.

## How to Use

### Prerequisites

- IPA server with CA installed.
- External ACME server (third-party) installed and reachable by ACME clients.
- The external ACME server host is enrolled in IPA (`ipa-client-install`).

### Step 1: Create the ACME Sub-CA

The `--acme` flag applies the `ipaACMECA` marker objectClass to the sub-CA
entry, making it selectable by `ipa ca-find --acme` and referenceable in
`host-acme-add` commands. Choose a name that identifies the deployment; the
examples below use `acme-corp-us`.

```bash
ipa ca-add acme-corp-us \
    --subject "CN=Corp US External ACME Sub-CA,O=IPA.EXAMPLE.COM" \
    --acme \
    --desc "Sub-CA for the US corporate external ACME server"
```

Record the `ipacaid` (authority UUID) shown in the output; it is referenced
in subsequent steps.

### Step 2: Import the ACME Certificate Profile

```bash
ipa certprofile-import acmeExternalServerCert \
    --file /usr/share/ipa/profiles/acmeExternalServerCert.cfg \
    --store false \
    --desc "Certificate profile for external ACME server issuance via IPA sub-CA"
```

The `--store false` flag prevents IPA from recording each short-lived
ACME-issued certificate in the LDAP directory.

### Step 3: Configure the CA ACL

Each ACME-dedicated sub-CA has its own CA ACL. Name it to match the sub-CA:

```bash
ipa caacl-add acme-corp-us-issuance \
    --desc "Allow external ACME server to issue via acme-corp-us sub-CA"

ipa caacl-add-ca acme-corp-us-issuance --cas acme-corp-us
ipa caacl-add-profile acme-corp-us-issuance \
    --certprofiles acmeExternalServerCert

# Allow all IPA-managed hosts (adjust scope as needed)
ipa caacl-add-host acme-corp-us-issuance --hostgroups ipaservers

# Allow specific services (e.g., HTTP on any host)
ipa caacl-add-service acme-corp-us-issuance --services HTTP
```

### Step 4: Create the ACME Server Service Principal and Role

```bash
# Service principal for the external ACME server
ipa service-add acme/acmeserver.ipa.example.com

# Grant the ACME server permission to submit certificates on behalf of
# other principals and to validate EAB credentials
ipa role-add "ACME Server (RA model)"
ipa role-add-privilege "ACME Server (RA model)" "ACME Certificate Request"
ipa role-add-member "ACME Server (RA model)" \
    --services "acme/acmeserver.ipa.example.com"

# Obtain a keytab for the service
ipa-getkeytab -s ipa.example.com \
    -p acme/acmeserver.ipa.example.com \
    -k /etc/acme-server/ipa.keytab
```

### Step 5: Enable EAB for an IPA Host or Service

```bash
ipa host-acme-add server1.ipa.example.com --acme-ca acme-corp-us
ipa service-acme-add HTTP/app.ipa.example.com --acme-ca acme-corp-us
```

See [EAB Account Management](administration.md#eab-account-management) for
full details on creating, rotating, and deleting EAB credentials, and
configuring ACME clients with the printed KID and HMAC key.

### Step 6: Verify Issuance

```bash
# Check certificate was issued under the acme-corp-us sub-CA
ipa cert-find --ca acme-corp-us

# Show EAB account status for a host on a given sub-CA
ipa host-acme-show server1.ipa.example.com --acme-ca acme-corp-us

# List all EAB accounts for a sub-CA
ipa acme-account-find --acme-ca acme-corp-us
```

## Design

### Architecture

```
ACME Client (certbot/acme.sh)
        |
        |  RFC 8555 ACME (HTTPS)
        v
+-----------------------------------+
|   External ACME Server            |  Kerberos principal:
|   (step-ca, Boulder, custom)      |  acme/acmeserver.ipa.example.com
|                                   |
|  +-----------------------------+  |
|  | IPA adapter plugin:         |  |-- LDAP (Kerberos): EAB KID lookup
|  |  - EAB validator            |  |   (&(ipaACMEAccountID=<kid>))
|  |  - Identifier authorizer    |  |
|  |  - Certificate issuer (RA)  |  |-- IPA JSON-RPC (Kerberos): cert-request
|  |  - Revocation proxy         |  |   principal, CSR, profile, ca
|  +-----------------------------+  |
+-----------------------------------+
        |                   |
        | LDAP              | IPA JSON-RPC / cert-request API
        v                   v
+-----------------------------------------------+
|                  FreeIPA                       |
|                                                |
|  +--------------------+  +-----------------+  |
|  | Dogtag CA          |  | 389-DS LDAP     |  |
|  |                    |  |                 |  |
|  | Sub-CA(s):         |  | cn=acmeaccounts |  |
|  | acme-corp-us       |  |   ipaACMEAccount|  |
|  | acme-dmz-partner   |  |   ipaACMEAccountID
|  | (ipaACMECA marker) |  |   ipaACMEHMACKey|  |
|  | Keys in NSS/HSM    |  |   ipaACMESubCA  |  |
|  |                    |  |   ipaACMEPrincipal  |
|  | Profile:           |  |                 |  |
|  | acmeExternal       |  | CA ACLs, RBAC   |  |
|  | ServerCert         |  | caacl entries   |  |
|  |                    |  |                 |  |
|  | raCertAuth         |  | Service:        |  |
|  | (RA agent cert)    |  | acme/acmeserver |  |
|  +--------------------+  +-----------------+  |
+-----------------------------------------------+
```

### LDAP Schema

The `ipaACMEAccount` structural objectClass, the EAB account container
(`cn=acmeaccounts,cn=ca,$SUFFIX`), and all attributes (`ipaACMEAccountID`,
`ipaACMEHMACKey`, `ipaACMESubCA`, `ipaACMEPrincipal`, `ipaACMEEnabled`) are
defined in the [overview](overview.md#external-account-binding-eab).  The
`ipaACMECA` sub-CA marker objectClass is also defined there.  All schema is
shared between both integration models.

### EAB Workflow

```
1. Admin: ipa host-acme-add server1.ipa.example.com --acme-ca acme-corp-us
            --> Generates KID (random 16-byte hex) + HMAC key (32 random bytes)
            --> Creates entry in cn=acmeaccounts,cn=ca,$SUFFIX:
                  ipaACMEAccountID: <kid>     (used as RDN)
                  ipaACMEHMACKey:   <base64url(hmac)>
                  ipaACMESubCA:     acme-corp-us
                  ipaACMEPrincipal: fqdn=server1.ipa.example.com,cn=computers,...
                  ipaACMEEnabled:   TRUE
            --> Displays KID + HMAC key to admin (ONCE)

2. Admin configures ACME client on server1 with KID + HMAC key.

3. ACME client sends POST /acme/newAccount:
     {
       "externalAccountBinding": {
         "protected": {"kid": "<kid>", "alg": "HS256", ...},
         "payload":   <base64url(accountPublicKey)>,
         "signature": <HMAC-SHA256(protected.payload, hmac_key)>
       }
     }

4. External ACME server receives newAccount:
   a. Extracts KID from EAB header.
   b. LDAP search in cn=acmeaccounts,cn=ca,$SUFFIX:
        (&(objectClass=ipaACMEAccount)
          (ipaACMEAccountID=<kid>)
          (ipaACMESubCA=acme-corp-us))   ← server only accepts its own sub-CA
      --> Retrieves ipaACMEPrincipal DN and ipaACMEHMACKey.
   c. Validates HMAC-SHA256(accountKey, retrieved_hmac) == EAB signature.
   d. Stores mapping: acme_account_id --> ipaACMEPrincipal DN

5. ACME client sends POST /acme/newOrder:
     {identifiers: [{type: "dns", value: "server1.ipa.example.com"}]}

6. External ACME server:
   a. Looks up IPA principal DN for this ACME account.
   b. Validates identifier: "server1.ipa.example.com" is an allowed name
      for the bound host principal (checks fqdn and ipaHostAliases).
   c. Issues HTTP-01 or DNS-01 challenge.

7. ACME client completes challenge; notifies ACME server.

8. ACME client sends POST /acme/finalize with CSR.

9. External ACME server:
   a. Re-validates identifier against IPA principal.
   b. Calls IPA JSON-RPC cert-request:
        principal: "host/server1.ipa.example.com"
        csr:       <CSR PEM>
        profile:   "acmeExternalServerCert"
        cacn:      "acme-corp-us"           ← from ipaACMESubCA on the EAB account
      (authenticated as acme/acmeserver.ipa.example.com via Kerberos)
   c. IPA cert.py validates:
        - CSR SAN matches host/server1.ipa.example.com principal.
        - CA ACL: host is in acme-corp-us-issuance ACL.
        - Profile is enabled and bound to acme-corp-us CA.
   d. Dogtag signs with acme-corp-us sub-CA key.
   e. Returns certificate PEM.

10. ACME client downloads certificate from /acme/cert/<id>.
```

### Identifier Authorization

The identifier authorization rules (which principal types map to which allowed
DNS names or email addresses) are defined in the
[overview](overview.md#access-control) and apply identically to both
integration models.  The RA model has one additional enforcement point: IPA's
`cert-request` re-validates the CSR's SAN against the target principal
server-side at signing time (step 9c in the EAB workflow above), so the ACME
adapter's pre-signing check and IPA's check must both pass.

### Certificate Profile: acmeExternalServerCert

The profile is defined in the [overview](overview.md#acme-certificate-profile).
The RA-model-specific setting is `auth.instance_id=raCertAuth` (RA agent
certificate authentication), in contrast to `SessionAuthentication` used by the
built-in Dogtag ACME profile.  This allows the external ACME server to
authenticate to Dogtag with its own agent certificate when submitting CSRs on
behalf of other principals.  The full profile `.cfg` file is in
`install/share/profiles/acmeExternalServerCert.cfg`.

### Access Control Summary

The full RBAC specification — permissions with their `targetattr`,
`targetfilter`, and rights; privileges; roles; and the self-service ACI — is
in the [overview](overview.md#rbac-specification).

The RA model uses the `ACME Server (RA model)` role, which bundles the
`ACME Certificate Request` privilege.  The key operations it enables for the
`acme/<hostname>` service principal are:

| Operation | Mechanism |
|---|---|
| Read `ipaACMEHMACKey` for EAB validation | `Read ACME Account HMAC Keys` permission (targets `cn=acmeaccounts` container) |
| Submit CSR on behalf of another principal | `Request Certificate` privilege |
| Revoke certificate | `Revoke Certificate` privilege |
| Issue via the configured ACME sub-CA | CA ACL linking hosts → sub-CA → profile (one ACL per sub-CA) |
| SAN name validation | IPA `cert.py` server-side (existing logic) |

### DNS-01 Challenge via IPA DNS

For hosts in IPA-managed DNS zones, the ACME adapter can use IPA's DNS API to
create and remove `_acme-challenge` TXT records automatically, avoiding
manual DNS configuration:

```python
# Provision challenge
ipa.dnsrecord_add(
    dnszoneidnsname="example.com",
    idnsname="_acme-challenge.server1",
    addattr="TXTRecord=<token>",
)

# Deprovision after validation
ipa.dnsrecord_del(
    dnszoneidnsname="example.com",
    idnsname="_acme-challenge.server1",
    del_all=True,
)
```

The ACME server service principal requires write access to `_acme-challenge`
records. A scoped permission is preferable to full `DNS Zone Administrator`:

```bash
ipa permission-add "Manage ACME Challenge DNS Records" \
    --type dnsrecord \
    --right add,write,delete \
    --filter "(idnsname=_acme-challenge*)"
```

### Revocation

The ACME `revokeCert` endpoint calls IPA `cert-revoke` with the serial number
extracted from the submitted certificate. IPA delegates to Dogtag, which
updates the CRL for the `acme-external` sub-CA.

```bash
# Admin-initiated revocation when decommissioning a host
ipa host-acme-del server1.ipa.example.com   # invalidates EAB account
# Then revoke outstanding certs individually or via ACME client:
certbot revoke --cert-path /etc/letsencrypt/live/server1/cert.pem
```

## Implementation

### New IPA Framework Components

The shared EAB account plugin, LDAP schema, schema upgrade, and
`Read ACME Account HMAC Keys` permission are documented in
[Shared IPA Framework Components](administration.md#shared-ipa-framework-components).

RA-model-specific additions:

**New certificate profile**: `install/share/profiles/acmeExternalServerCert.cfg`
Installed into Dogtag during `ipa-server-install` or via `certprofile-import`.
Uses `auth.instance_id=raCertAuth` so the external ACME server authenticates
to Dogtag with its own RA agent certificate when submitting CSRs on behalf of
other principals.

### Dependencies

No new external dependencies. The IPA adapter plugin on the external ACME
server requires:

- `python-gssapi` (already packaged): Kerberos authentication for IPA API calls.
- `python-ldap` (already packaged): LDAP queries for EAB lookup.
- `ipalib` (already packaged as `python3-ipaclient`): IPA JSON-RPC client.

### Backup and Restore

EAB account backup is covered in
[Backup and Restore](administration.md#backup-and-restore) in the common
administration guide.

The `acme-external` sub-CA private key is stored in the Dogtag NSS database
(`/var/lib/pki/pki-tomcat/alias/`) and is covered by the existing
`ipa-backup --data` procedure which backs up the NSSDB.

## Feature Management

### UI

See [Web UI](administration.md#web-ui) in the common administration guide.

### CLI

EAB account commands (`host-acme-*`, `service-acme-*`) are documented in the
[CLI Reference](administration.md#cli-reference) in the common administration
guide.  RA-model-specific sub-CA and CA ACL commands:

| Command | Key Options |
|---|---|
| `ipa ca-add acme-external` | `--subject`, `--desc`, `--acme` |
| `ipa caacl-add acme-external-issuance` | `--desc` |
| `ipa caacl-add-ca` | `--cas acme-external` |
| `ipa caacl-add-profile` | `--certprofiles acmeExternalServerCert` |

### Configuration

The external ACME server is configured with:

- IPA realm, domain, and LDAP URI (from `/etc/ipa/default.conf`).
- Path to the keytab for `acme/acmeserver.ipa.example.com`.
- The `ipacaid` (authority UUID) of the `acme-external` sub-CA.
- The profile name `acmeExternalServerCert`.

An `ipa-acme-server-install` helper script (analogous to `ipa-replica-install`)
automates service principal creation, keytab retrieval, and initial CA ACL
configuration.

## Upgrade

See [Upgrade](administration.md#upgrade) in the common administration guide.
The `acme-external` sub-CA, CA ACL, and `acmeExternalServerCert` profile must
be created explicitly by an administrator after upgrading; they are not
provisioned automatically.

## Test Plan

| Scenario | Expected result |
|---|---|
| `host-acme-add` on enrolled host | Returns KID and HMAC key; `ipaACMEAccount` entry created in `cn=acmeaccounts` |
| `host-acme-add` on non-existent host | Error: host not found |
| `host-acme-add` twice on same host (same `--acme-ca`) | Error: ACME account already exists |
| `host-acme-mod --hmac-key` | Generates new HMAC key; KID unchanged; new key printed once; old EAB credentials rejected by ACME server |
| `host-acme-mod --hmac-key` then EAB with old HMAC | ACME server rejects with `unauthorized` |
| `host-acme-mod --hmac-key` then EAB with new HMAC | ACME server accepts |
| `host-acme-del` | Removes `ipaACMEAccount` entry; subsequent ACME registration with old KID fails |
| EAB registration with valid KID + HMAC | ACME server accepts; account created |
| EAB registration with invalid HMAC | ACME server rejects with `unauthorized` |
| EAB registration with unknown KID | ACME server rejects with `unauthorized` |
| Certificate order for authorized name | IPA issues certificate under `acme-external` sub-CA |
| Certificate order for unauthorized name (e.g., other host's FQDN) | IPA rejects: SAN does not match principal |
| Certificate order with no EAB (EAB required) | ACME server rejects: `externalAccountRequired` |
| Certificate validity exceeds 90 days | Dogtag profile constraint rejects the request |
| Revocation via ACME | IPA marks certificate revoked; appears in CRL |
| `Read ACME Account HMAC Keys` permission | Only ACME server service principal and admin can read `ipaACMEHMACKey` |
| CA ACL enforcement | Certificate request using different CA or profile is rejected |
| Sub-CA nameConstraints | Certificate with SAN outside IPA domain is rejected by Dogtag |

## Troubleshooting and Debugging

### LDAP entries and EAB validation

See [Troubleshooting](administration.md#troubleshooting) in the common
administration guide for verifying EAB account entries and diagnosing EAB
validation failures.

### IPA API calls from the ACME server

Enable IPA client-side JSON-RPC logging on the ACME server:

```
# In /etc/ipa/default.conf on the ACME server
[global]
verbose = True
```

Or set environment variable `IPA_DEBUG=1` before starting the ACME server
process to get full request/response traces.

### Certificate issuance failures

`cert-request` errors appear in `/var/log/httpd/error_log` on the IPA server.
CA ACL denials are logged at INFO level with the message `caacl_check denied`.
SAN mismatch errors include the rejected name and the principal's allowed names.

Dogtag-level errors (profile constraint violations, key size rejections) appear
in `/var/log/pki/pki-tomcat/ca/debug` on the IPA CA server.

### Sub-CA certificate chain

Verify the sub-CA is visible and its certificate is accessible:

```bash
ipa ca-show acme-external --all
ipa ca-show acme-external --chain
```

If the chain is unavailable immediately after `ca-add` on a fresh replica,
wait for LDAP replication; `ca.py` performs a Dogtag re-fetch if the
`certificate` attribute is absent from the LDAP entry.
