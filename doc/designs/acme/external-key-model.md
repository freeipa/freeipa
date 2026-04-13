# External ACME Server Integration: HSM-Backed External-Key Sub-CA Model

## Overview

The [RA proxy model](ra-model.md) keeps all cryptographic operations inside
FreeIPA: the external ACME server submits CSRs to IPA, which signs them using
Dogtag. This requires the external ACME server to have continuous Kerberos
connectivity to an IPA server at certificate issuance time.

Some deployments cannot guarantee that connectivity:

- **Edge sites** or **air-gapped networks** where IPA is not reachable from the
  ACME server during normal operations.
- **High-availability ACME servers** that must continue issuing during IPA
  maintenance windows.
- **Geographically distributed deployments** where round-trip latency to IPA
  would significantly delay certificate issuance.
- **Security policies** that require CA signing keys to reside in a hardware
  security module (HSM) that never exposes private key material.

This design describes the **HSM-backed external-key sub-CA model**, where the
external ACME server generates the sub-CA key pair on its own HSM, submits a
PKCS#10 CSR to IPA, and receives a signed sub-CA certificate in return. Dogtag
tracks the resulting authority for certificate chain and revocation purposes but
**never holds the private key**. The ACME server then signs end-entity
certificates directly and autonomously, without contacting IPA at issuance
time.

The sub-CA private key is bound to the ACME server's HSM at creation time and
remains there for the entire lifetime of the sub-CA.

IPA remains authoritative for identity (EAB accounts), access control policy,
and revocation; these operations are performed out-of-band and do not need to
be synchronous with certificate issuance.

## Use Cases

### UC-1: Air-Gapped Site with Local ACME Server

A factory floor network is isolated from corporate IPA infrastructure for
security reasons. The site has an IPA replica for local authentication, but
the replica has no outbound connectivity to the corporate CA server. The ACME
server holds its own sub-CA key in a local HSM and issues certificates
independently. Certificate issuance continues even when the WAN link to the
corporate IPA CA is down.

### UC-2: High-Availability ACME During IPA Maintenance

An organization runs a high-traffic internal ACME service. When IPA CA servers
are patched or rebooted, certificate renewals must continue uninterrupted. The
ACME server holds the sub-CA key in its own HSM and continues signing during
IPA downtime. The sub-CA certificate is refreshed from IPA after maintenance
is complete.

### UC-3: Federated Deployment with Delegated Sub-CA Authority

An organization with multiple business units delegates certificate issuance for
each unit to a separate ACME server. Each ACME server holds a distinct sub-CA
key in its own HSM, scoped to its unit's DNS namespace (enforced by
`nameConstraints` on the sub-CA certificate). Sub-CA certificates are
provisioned directly from IPA at bootstrap and rotated on a defined schedule.

### UC-4: HSM Security Policy Requirement

An organization's security policy requires that CA signing keys are generated
inside an HSM and never exported in cleartext. The ACME server generates the
key pair on its HSM, creates a CSR, and submits it to IPA for signing. The
resulting sub-CA certificate is installed alongside the (non-exportable) HSM
key. IPA never has access to the private key.

## How to Use

### Prerequisites

- IPA server with CA installed and Dogtag extended for external-key sub-CA
  support (see [Dogtag PKI Requirements](#dogtag-pki-requirements) below).
- External ACME server host enrolled in IPA with an HSM (or software keystore
  for testing).
- The ACME server's service principal has been assigned the
  `Revoke Certificate` IPA privilege (for revocation reporting).

### Step 1: Generate the Sub-CA Key Pair and CSR on the ACME Server

Perform this step **on the ACME server**, where the key will reside.

**Software keystore (testing only):**

```bash
openssl genrsa -out /etc/acme-server/subca/ca.key 3072

openssl req -new \
    -key /etc/acme-server/subca/ca.key \
    -subj "CN=Factory Floor ACME Sub-CA,O=IPA.EXAMPLE.COM" \
    -out /etc/acme-server/subca/ca.csr
```

**HSM (production):**

Use the HSM vendor's tools or `pkcs11-tool` to generate the key pair on the
token and produce a CSR. The private key must never leave the HSM.

```bash
# Example with SoftHSM2 / pkcs11-tool
pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so \
    --login --pin <pin> \
    --keypairgen --key-type rsa:3072 \
    --id 01 --label "acme-factory-floor"

# Create CSR referencing the HSM key
openssl req -new -engine pkcs11 -keyform engine \
    -key "pkcs11:object=acme-factory-floor;type=private" \
    -subj "CN=Factory Floor ACME Sub-CA,O=IPA.EXAMPLE.COM" \
    -out /etc/acme-server/subca/ca.csr
```

The subject DN in the CSR must exactly match the `--subject` value you will
pass to `ipa ca-add` in the next step.

To embed `nameConstraints` restricting the sub-CA to a specific DNS domain,
include the extension in the CSR:

```bash
cat > /tmp/ext.cnf << 'EOF'
[req]
req_extensions = v3_req
[v3_req]
nameConstraints = critical, permitted;DNS:ipa.example.com
EOF

openssl req -new \
    -key /etc/acme-server/subca/ca.key \
    -subj "CN=Factory Floor ACME Sub-CA,O=IPA.EXAMPLE.COM" \
    -config /tmp/ext.cnf \
    -out /etc/acme-server/subca/ca.csr
```

### Step 2: Create the ACME Sub-CA in IPA

Transfer the CSR to an IPA admin host and run `ipa ca-add` with `--csr-file`.
The `--acme` flag marks the sub-CA as ACME-dedicated.

```bash
ipa ca-add acme-factory-floor \
    --subject "CN=Factory Floor ACME Sub-CA,O=IPA.EXAMPLE.COM" \
    --csr-file /tmp/acme-factory-floor.csr \
    --acme \
    --desc "External ACME server sub-CA — HSM-backed, factory floor"
```

IPA passes the CSR to Dogtag, which signs it using the `caExternalKeyCACert`
profile. This profile enforces:

- `pathLen=0` — the sub-CA cannot itself issue further sub-CAs.
- RSA keys shorter than 2048 bits are rejected.
- Extensions present in the CSR (e.g. `nameConstraints`) are copied verbatim
  into the issued certificate.

The command prints the new authority's details and confirms the external-key
flag:

```
  CA name:      acme-factory-floor
  Authority DN: CN=Factory Floor ACME Sub-CA,O=IPA.EXAMPLE.COM
  ID:           3f4a9c21-1b2e-4d57-a891-0c3e7b5d9f10
  Enabled:      True
  External key: True
  Description:  External ACME server sub-CA — HSM-backed, factory floor
```

`External key: True` confirms that Dogtag does not hold the signing key and
will not use this authority for certificate issuance on its own behalf. The
authority is tracked for chain-building and revocation purposes only.

### Step 3: Retrieve the Signed Sub-CA Certificate

```bash
AID="3f4a9c21-1b2e-4d57-a891-0c3e7b5d9f10"

# PEM certificate only
ipa ca-show acme-factory-floor --certificate-out /etc/acme-server/subca/ca.crt

# Full chain (sub-CA + IPA issuer chain to root) via Dogtag REST API
curl -s -H "Accept: application/x-pem-file" \
    https://ipa.example.com:8443/ca/v2/authorities/${AID}/chain \
    -o /etc/acme-server/subca/ca-chain.pem
```

Verify the certificate chains to the IPA root CA and that the public key
matches the private key held on the ACME server:

```bash
openssl verify -CAfile /etc/ipa/ca.crt /etc/acme-server/subca/ca.crt

# Software key: compare public keys
diff <(openssl x509 -noout -pubkey -in /etc/acme-server/subca/ca.crt) \
     <(openssl rsa -pubout -in /etc/acme-server/subca/ca.key)
```

### Step 4: Enable EAB for Hosts and Services

```bash
ipa host-acme-add server1.ipa.example.com --acme-ca acme-factory-floor
ipa service-acme-add HTTP/app.ipa.example.com --acme-ca acme-factory-floor
```

The ACME server validates EAB credentials via IPA LDAP before issuing
challenges (once per ACME client registration, not at issuance time).  See
[EAB Account Management](administration.md#eab-account-management) for full
details on managing EAB accounts and configuring ACME clients.

### Step 5: Grant Revocation Privilege to the ACME Server

```bash
ipa service-add acme/acmeserver.ipa.example.com

ipa role-add "ACME Server"
ipa role-add-privilege "ACME Server" "Revoke Certificate"
ipa role-add-privilege "ACME Server" "Read ACME Account HMAC Keys"
ipa role-add-member "ACME Server" \
    --services "acme/acmeserver.ipa.example.com"

ipa-getkeytab -s ipa.example.com \
    -p acme/acmeserver.ipa.example.com \
    -k /etc/acme-server/ipa.keytab
```

### Step 6: Configure and Start the ACME Server

Configure the ACME server to use the locally held key and the sub-CA
certificate retrieved in Step 3. The exact configuration depends on the ACME
server software (step-ca, Boulder, custom implementation).

Verify the setup:

```bash
# Issue a test certificate
certbot certonly \
    --server https://acmeserver.ipa.example.com/acme/directory \
    --eab-kid  <kid> \
    --eab-hmac-key <hmac> \
    -d server1.ipa.example.com

# Verify issuer is acme-factory-floor sub-CA
openssl x509 -noout -issuer \
    -in /etc/letsencrypt/live/server1.ipa.example.com/cert.pem
```

## Design

### Architecture

```
ACME Client (certbot/acme.sh)
        |
        |  RFC 8555 ACME (HTTPS)
        v
+--------------------------------------------+
|   External ACME Server                      |
|   (step-ca, Boulder, custom)                |
|   Configured for: acme-factory-floor        |
|                                             |
|  +-----------------------------------------+
|  | At issuance time (NO IPA contact):       |
|  |   Signs CSR with sub-CA key in HSM      |
|  |   Enforces: profile constraints,        |
|  |   validity, SAN validation              |
|  +-----------------------------------------+
|  |                                         |
|  | At EAB registration time (IPA contact): |
|  |   LDAP: search cn=acmeaccounts,cn=ca   |
|  |     filter: ipaACMEAccountID=<kid>     |
|  |             ipaACMESubCA=acme-factory.. |
|  |   LDAP: get principal's allowed names  |
|  +-----------------------------------------+
|  |                                         |
|  | At revocation time (IPA contact):        |
|  |   IPA cert-revoke (Kerberos)            |
|  +-----------------------------------------+
|  |                                         |
|  | HSM / local keystore:                   |
|  |   Sub-CA private key (never exported)  |
|  |   Sub-CA certificate (from IPA)        |
|  +-----------------------------------------+
|                      |
|     IPA LDAP (EAB)   |   IPA cert-revoke
|     (Kerberos auth)  |   (Kerberos auth)
+----------------------|---------------------+
                       |
+----------------------|---------------------+
|                  FreeIPA                   |
|                       |                    |
|  +------------------------------+          |
|  | 389-DS LDAP                  |          |
|  | cn=acmeaccounts,cn=ca,...    |          |
|  | ipaACMEAccount entries:      |<---------+
|  |   ipaACMEAccountID: <kid>    |
|  |   ipaACMEHMACKey:   <secret> |
|  |   ipaACMESubCA: acme-factory-floor
|  |   ipaACMEPrincipal: <host DN>|
|  +------------------------------+
|                                            |
|  +------------------------------------------+
|  | Dogtag CA                                 |
|  | Sub-CA: acme-factory-floor               |
|  | (ipaACMECA marker in LDAP entry)         |
|  | externalKey: true — key NOT held here    |
|  | ready: false — Dogtag cannot sign via it |
|  | Used for: chain-building, revocation     |
|  | Created from: CSR submitted by ACME server|
|  +------------------------------------------+
+---------------------------------------------+
```

### LDAP Schema

The `ipaACMEAccount` auxiliary objectClass and its attributes are defined in
the [overview](overview.md#external-account-binding-eab). The schema is
shared between both integration models.

The sub-CA LDAP entry (`cn=cas,cn=ca,$SUFFIX`) requires no new attributes for
this model. The `ipaACMECA` marker objectClass and `ipacaid` are already
present. Dogtag's `authorityKeyNickname` attribute stores a sentinel value
(`#external#:<uuid>`) indicating that no PKCS#11 key is held on the IPA side.

### Sub-CA Creation: IPA `ca-add --csr-file`

The `ipa ca-add` command is extended with a `--csr-file <path>` option. When
present, IPA reads the PEM CSR and passes it as `csrData` to
`POST /ca/v2/authorities`. The Dogtag engine then:

1. Parses and validates the CSR signature.
2. Verifies the CSR subject DN matches the `--subject` argument.
3. Signs the CSR using the `caExternalKeyCACert` profile (default) or the
   profile named by `--profile`.
4. Creates the authority LDAP record with `authorityKeyNickname` set to the
   `#external#:<uuid>` sentinel.
5. Returns `externalKey: true, ready: false` in the authority metadata.

The `caExternalKeyCACert` profile enforces `pathLen=0`, rejects RSA keys below
2048 bits, and copies any extensions present in the CSR (including
`nameConstraints`) verbatim into the issued certificate.

### Sub-CA Key Material Lifecycle

```
Day 0: Admin creates sub-CA:
  ACME server generates key pair on HSM (or software for testing)
  ACME server creates CSR
  ipa ca-add acme-factory-floor \
      --csr-file /tmp/acme-factory-floor.csr --acme
  --> Dogtag signs CSR with caExternalKeyCACert profile (pathLen=0)
  --> Sub-CA cert validity: 2 years (configurable via profile)
  --> Dogtag tracks authority; does NOT hold private key
  ACME server installs signed cert from IPA
  ACME server begins issuing end-entity certs (90-day lifetime)

Before sub-CA cert expiry:
  Option A: Reuse existing key, new certificate
    ACME server creates new CSR with same key
    ipa ca-add acme-factory-floor-v2 \
        --csr-file /tmp/renewed.csr --acme \
        --desc "Renewed sub-CA"
    ACME server installs new cert, updates config to new sub-CA
    ipa ca-disable acme-factory-floor  (stop issuing from old sub-CA)

  Option B: Key rotation (recommended)
    ACME server generates new key pair + CSR (new HSM slot)
    Same ipa ca-add workflow as Day 0
    Old sub-CA disabled and eventually revoked after transition

Key compromise:
  --> Revoke old sub-CA: ipa ca-del acme-factory-floor
      (triggers CRL update; TLS clients stop trusting issued certs)
  --> Generate new key pair + CSR on ACME server (new HSM slot)
  --> ipa ca-add acme-factory-floor-v2 --csr-file /tmp/new.csr --acme
  --> Update ACME server config to new sub-CA cert
  --> Re-provision EAB accounts if sub-CA name changed
```

### ACME Certificate Issuance (Without IPA Contact)

Once the sub-CA key is loaded, the ACME server signs end-entity certificates
entirely locally. The server must enforce the same constraints that IPA would
enforce in the RA model:

| Constraint | RA model enforcer | External-key model enforcer |
|---|---|---|
| SAN matches IPA principal | IPA `cert.py` | ACME adapter (pre-signing check) |
| Max validity 90 days | Dogtag profile | ACME server local policy |
| Allowed key algorithms | Dogtag profile | ACME server local policy |
| Key usage bits | Dogtag profile | ACME server local policy |
| CA ACL (host→CA→profile) | IPA `caacl_check` | ACME server checks EAB-bound principal |
| Name constraints | Sub-CA `nameConstraints` ext | Enforced by TLS clients verifying chain |

The `nameConstraints` extension on the sub-CA certificate provides a
cryptographic backstop: even if the ACME server's local policy check is
bypassed, TLS relying parties will reject certificates with SANs outside the
constrained namespace.

### EAB Workflow

EAB registration requires LDAP contact with IPA. This is the one point of
IPA dependency in this model at account registration time (once per ACME
client). The full sequence is in the [RA model design](ra-model.md#eab-workflow);
the identifier authorization rules are in the [overview](overview.md#access-control).

The LDAP lookup for EAB validation searches the dedicated EAB container and
filters on both the Key Identifier (KID) and the server's own sub-CA name:

```ldap
(&(objectClass=ipaACMEAccount)
  (ipaACMEAccountID=<kid>)
  (ipaACMESubCA=acme-factory-floor))
```

The ACME server may cache validated ACME account → IPA principal mappings
locally so that subsequent orders do not require LDAP contact. The cache must
be invalidated when `host-acme-del` is called (a webhook or periodic LDAP sync
is needed).

### Revocation

When an ACME client sends `revokeCert`, the ACME server must report the
revocation to IPA so that the IPA CRL reflects it. This requires an IPA API
call, so revocation is **not** fully offline in this model:

```
ACME client --> revokeCert --> ACME server
                                  |
                          IPA cert-revoke (Kerberos)
                                  |
                              Dogtag CRL update
```

If IPA is temporarily unreachable, revocation must be queued and replayed
when connectivity is restored. The ACME server must persist its revocation
queue durably.

### Security Considerations

The sub-CA private key is generated on the ACME server's HSM and never
exported. IPA signs the CSR but never sees or stores the private key.

1. **CSR authenticity**: IPA verifies the CSR signature and that the CSR
   subject DN matches the `--subject` argument, but it does not verify that
   the CSR was generated by an HSM rather than a software key. Hardware
   attestation is out of scope for this design.

2. **nameConstraints on sub-CA**: Embedding `nameConstraints` in the CSR
   (and thereby in the signed sub-CA certificate) provides a cryptographic
   guarantee that the ACME server cannot issue certificates for names outside
   the constrained namespace, even if its local policy is bypassed.

3. **Access control for ca-add --csr-file**: Only IPA administrators can
   run `ipa ca-add`. Creating an external-key sub-CA requires the same admin
   credential as creating a local-key sub-CA.

4. **Local key protection**: The ACME server must protect its sub-CA private
   key with HSM access controls (PIN, operator card sets, etc.). For software
   keystores used in testing, the key file must be `0400` owned by the ACME
   server daemon user.

5. **Audit log**: Dogtag logs each sub-CA creation (including `csrData`
   submission) in its audit log. The authority UUID and `externalKey` flag
   are visible in `GET /ca/v2/authorities/<id>` responses.

**Comparison to RA model risk posture**:

| Risk | RA model | This model |
|---|---|---|
| Sub-CA key exposure | None (key never leaves Dogtag) | None (key never leaves ACME server HSM) |
| Unauthorized issuance | Blocked by IPA cert-request ACLs | Blocked by ACME server local policy + nameConstraints |
| Revocation latency | Synchronous | Asynchronous (queue + replay) |
| Availability dependency | IPA CA must be reachable at every issuance | IPA CA needed only at sub-CA creation and revocation |

## Dogtag PKI Requirements

This model depends on extensions to the Dogtag CA that are not present in the
upstream release as of writing.  The required changes are tracked in
[dogtagpki/pki#5336](https://github.com/dogtagpki/pki/issues/5336) and
implemented in [dogtagpki/pki PR#5337](https://github.com/dogtagpki/pki/pull/5337).

### What Dogtag must be extended to support

**`POST /ca/v2/authorities` — accept an external CSR (`csrData` field)**

The authority creation endpoint currently generates a key pair inside Dogtag
and signs the sub-CA certificate locally.  It must be extended to accept an
optional PEM-encoded PKCS#10 CSR in a new `csrData` request field.  When
present, Dogtag signs the submitted CSR instead of generating a key pair,
stores a sentinel value (`#external#:<uuid>`) as the authority key nickname,
and returns `externalKey: true` / `ready: false` in the authority metadata.
The private key never enters Dogtag.

**`POST /ca/v2/authorities` — accept a signing profile ID (`profileId` field)**

A companion optional `profileId` field selects which Dogtag profile signs the
sub-CA certificate.  This applies to both the external-CSR path (default:
`caExternalKeyCACert`) and the existing local-key path (default: `caCACert`).

**New profile: `caExternalKeyCACert`**

A dedicated signing profile for external-key sub-CA certificates, distinct
from the existing `caCACert` profile used for local-key sub-CAs.  Compared
with `caCACert` it enforces:

- `pathLen=0` — the issued sub-CA cannot itself sign further sub-CAs.
- RSA keys shorter than 2048 bits are rejected.
- Key usage restricted to `keyCertSign` and `crlSign` (no `digitalSignature`
  or `nonRepudiation`, which are not appropriate for CA certificates).
- Extensions present in the submitted CSR — in particular `nameConstraints`
  — are copied verbatim into the issued certificate via
  `userExtensionDefaultImpl`.

**Lifecycle correctness for external-key authorities**

Because the signing unit is never initialized for an external-key authority
(there is no NSS key to load), downstream operations that assume a signing
unit is present must be made aware of the external-key case:

- `CAEngine.revokeAuthority()` must retrieve the sub-CA certificate from the
  certificate repository (using the stored serial number) rather than
  dereferencing a null signing unit.
- `CAEngine.deleteAuthorityNSSDB()` must skip NSS cleanup for external-key
  authorities, as no certificate or key was ever written to the local NSS
  database.

**`pki ca-authority-create` CLI — `--csr-file` and `--profile` options**

The `pki` Java CLI tool must gain `--csr-file <path>` (reads a PEM CSR and
passes it as `csrData`) and `--profile <id>` (sets `profileId`) options on
`ca-authority-create`.  Output must show `External key: true` for authorities
created this way.

**Python `AuthorityData` — new fields**

The `pki.authority.AuthorityData` Python class must expose `csr_data`,
`profile_id`, `external_key`, and `ready` fields with the corresponding JSON
attribute mappings, so that Python-based tooling (including `ipa ca-add`) can
pass the CSR and read back the external-key flag.

## Implementation

### New and Changed IPA Components

The shared EAB account plugin (`ipalib/plugins/acme_account.py`), LDAP
schema (`install/share/65acme.ldif`), schema upgrade, and
`Read ACME Account HMAC Keys` permission are documented in
[Shared IPA Framework Components](administration.md#shared-ipa-framework-components).

HSM-backed-model-specific additions:

**Updated**: `ipalib/plugins/ca.py`
Add `--csr-file` option to `ca-add`. When provided, read the PEM file and
pass the content as `csrData` in the `POST /ca/v2/authorities` request body.
Expose `externalKey` from the Dogtag response as a read-only output field
`external_key` on the `ca-add` and `ca-show` commands.

### ipa ca-add --csr-file Implementation

```python
# In ipalib/plugins/ca.py, ca_add.execute():

csr_file = options.get('csr_file')
csr_data = None
if csr_file:
    with open(csr_file, 'rb') as f:
        csr_data = f.read().decode('utf-8')

authority_data = AuthorityData(
    dn=subject,
    parent_aid=parent_id,
    description=description,
    csr_data=csr_data,     # None for local-key path
    # profile_id left None: Dogtag defaults to caExternalKeyCACert
    #            when csr_data is present, caCACert otherwise
)
result = authority_client.create_ca(authority_data)

# Surface external_key flag in command output
if result.external_key:
    entry_attrs['external_key'] = True
```

### Dependencies

No new external dependencies. The `ipa ca-add --csr-file` change requires
only the updated `pki.authority.AuthorityData` Python class (with `csr_data`
and `external_key` fields).

### Backup and Restore

The sub-CA authority record in Dogtag LDAP is covered by `ipa-backup --data`.
Because Dogtag holds no private key for external-key authorities (only the
`#external#:<uuid>` sentinel nickname), there is no key material to back up
on the IPA side.

The sub-CA private key on the ACME server is outside the IPA backup scope. It
must be backed up according to the HSM vendor's key backup procedures. If the
key is permanently lost, a new key pair and CSR must be generated and a new
sub-CA must be created in IPA.

## Feature Management

### CLI

EAB account commands (`host-acme-*`, `service-acme-*`) are documented in the
[CLI Reference](administration.md#cli-reference) in the common administration
guide.  HSM-backed-model-specific sub-CA commands:

| Command | Key Options |
|---|---|
| `ipa ca-add <name>` | `--subject`, `--csr-file` — PEM CSR for external-key sub-CA; `--acme` — mark as ACME-dedicated; `--desc` |
| `ipa ca-show <name>` | `--all`, `--chain`; shows `External key: True` for external-key authorities |
| `ipa ca-find` | `--acme` — list only ACME-dedicated sub-CAs |
| `ipa ca-disable <name>` | Stop issuing from this sub-CA (used during rotation) |
| `ipa ca-del <name>` | Revoke sub-CA; triggers CRL update |

### Configuration

On the external ACME server, the adapter reads from `/etc/acme-server/ipa.conf`:

```ini
[global]
realm          = IPA.EXAMPLE.COM
domain         = ipa.example.com
ipa_server     = ipa.example.com

[subca]
name           = acme-factory-floor
cert_file      = /etc/acme-server/subca/ca.crt
chain_file     = /etc/acme-server/subca/ca-chain.pem
# key_file or HSM URI, depending on keystore type:
key_file       = /etc/acme-server/subca/ca.key
# hsm_uri      = pkcs11:token=acme-factory-floor;object=acme-factory-floor

[eab]
ldap_uri       = ldaps://ipa.example.com
keytab         = /etc/acme-server/ipa.keytab
```

## Upgrade

See [Upgrade](administration.md#upgrade) in the common administration guide.
The `--csr-file` option on `ipa ca-add` is a new optional argument; existing
sub-CA creation workflows (without `--csr-file`) are unaffected.

## Test Plan

| Scenario | Expected result |
|---|---|
| `ipa ca-add --csr-file` with valid RSA-3072 CSR | Sub-CA created; `External key: True`; cert has `pathLen:0` |
| `ipa ca-add --csr-file` with RSA-1024 CSR | Dogtag rejects with 400 (key too weak per `caExternalKeyCACert` profile) |
| `ipa ca-add --csr-file` with subject DN mismatch | Dogtag rejects with 400 (CSR subject does not match `--subject`) |
| `ipa ca-add --csr-file` with `nameConstraints` in CSR | Issued cert carries `nameConstraints` verbatim |
| `ipa ca-add` without `--csr-file` (local-key path) | Unchanged; sub-CA created with `External key: False`; `ready: True` |
| `ipa ca-show acme-factory-floor` | Shows `External key: True`; does not show `csrData` |
| EAB registration with valid credentials for correct sub-CA | ACME account created, bound to IPA principal |
| EAB registration with KID issued for different sub-CA | ACME server rejects (ipaACMESubCA mismatch in LDAP filter) |
| Certificate order for authorized DNS name | ACME server signs cert with local HSM key; issuer = acme-factory-floor sub-CA |
| Certificate order for unauthorized DNS name | ACME adapter rejects before signing |
| Certificate with SAN outside nameConstraints | TLS clients reject the certificate chain |
| Validity exceeds 90 days | ACME server local policy rejects |
| Revocation when IPA is reachable | IPA CRL updated; certificate revoked |
| Revocation when IPA is unreachable | Queued; replayed on reconnect |
| Sub-CA rotation (new key + CSR) | New authority created; ACME server reconfigured; old sub-CA disabled |
| `ipa ca-del acme-factory-floor` | Sub-CA revoked; existing ACME server can no longer issue (chain broken) |
| `host-acme-del` | EAB account removed; ACME server's cached principal mapping invalidated |

## Troubleshooting and Debugging

### Sub-CA Creation Failures

| Error | Cause | Fix |
|---|---|---|
| `400 Bad Request: key too weak` | RSA key < 2048 bits | Regenerate key pair with RSA-2048 or stronger |
| `400 Bad Request: subject DN mismatch` | CSR subject != `--subject` argument | Ensure both are identical including attribute order |
| `400 Bad Request: unknown profile` | Custom `--profile` not registered | Verify profile name with `pki ca-profile-find` |
| `401 Unauthorized` | IPA admin credentials not valid | Verify `kinit admin` and TLS connection to IPA |

### Sub-CA Key on ACME Server

Verify the sub-CA key and certificate correspond:

```bash
# Software key: compare public keys
diff <(openssl x509 -noout -pubkey -in /etc/acme-server/subca/ca.crt) \
     <(openssl rsa -pubout -in /etc/acme-server/subca/ca.key)

# HSM key via PKCS#11
openssl x509 -noout -pubkey -in /etc/acme-server/subca/ca.crt > /tmp/cert_pub.pem
pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so \
    --read-object --type pubkey --label "acme-factory-floor" \
    | openssl rsa -pubin -inform DER -outform PEM > /tmp/hsm_pub.pem
diff /tmp/cert_pub.pem /tmp/hsm_pub.pem

# Verify chain to IPA root
openssl verify -CAfile /etc/ipa/ca.crt \
    -untrusted /etc/acme-server/subca/ca-chain.pem \
    /etc/acme-server/subca/ca.crt
```

### Issued Certificate Verification

```bash
openssl verify -CAfile /etc/ipa/ca.crt \
    -untrusted /etc/acme-server/subca/ca.crt \
    /path/to/issued-cert.pem
```

### Revocation Queue

If the ACME server queued revocations while IPA was unreachable:

```bash
ipa-acme-server-status --revocation-queue

# Force replay after IPA connectivity is restored
ipa-acme-server-replay-revocations
```

### IPA LDAP Entries

See [Verifying EAB Account Entries](administration.md#verifying-eab-account-entries)
in the common administration guide for checking EAB account LDAP state.

To confirm the sub-CA entry carries the external-key sentinel nickname:

```bash
ldapsearch -Y GSSAPI \
    -b "cn=cas,cn=ca,dc=ipa,dc=example,dc=com" \
    "(cn=acme-factory-floor)" \
    ipacaid ipacaissuerdn objectClass authorityKeyNickname
# authorityKeyNickname should start with "#external#:"
```
