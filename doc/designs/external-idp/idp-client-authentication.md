# External IdP Client Authentication with RFC7523 and RFC8705

## Overview

FreeIPA supports external Identity Provider (IdP) integration using OAuth 2.0
Device Authorization Grant flow. The current implementation supports client
authentication using client ID and client secret (shared secret method) as
specified in [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749).

This design extends the external IdP support to include more secure client
authentication methods:

- [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523): JSON Web Token (JWT)
Profile for OAuth 2.0 Client Authentication and Authorization Grants - allows
using asymmetric key pairs where the client signs a JWT assertion with its
private key
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705): OAuth 2.0 Mutual-TLS
Client Authentication and Certificate-Bound Access Tokens - uses mutual TLS
(mTLS) authentication with X.509 certificates

Both authentication methods require storing a PKCS#12 bundle containing:
- A private key (for signing JWT assertions in
[RFC 7523]((https://www.rfc-editor.org/rfc/rfc7523)), or for mTLS handshake in
[RFC 8705]((https://www.rfc-editor.org/rfc/rfc8705))
- A public certificate (registered with the IdP for verification)

The private key material must be protected by Access Control Instructions (ACI)
to ensure only authorized entities can access it.

### Background

[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) defines the
`private_key_jwt` client authentication method where the client creates and
signs a JWT assertion using its private key. The Authorization Server validates
the signature using the public key or certificate previously registered for that
client. This method is more secure than shared secrets as the private key never
leaves the OAuth 2.0 client.

[RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) defines mutual TLS client
authentication where the client presents its X.509 certificate during the TLS
handshake. The Authorization Server validates the certificate against the one
registered for the client. This method provides strong authentication at the
transport layer and can also bind access tokens to the client certificate.

Both methods are widely supported by enterprise IdPs including Keycloak,
Microsoft Azure AD, Okta, and others.

## Use Cases

### Use Case 1: Enterprise IdP requiring JWT assertion authentication

An organization uses an enterprise IdP (e.g., Keycloak) that requires OAuth 2.0
clients to authenticate using JWT assertions (RFC 7523) instead of shared
secrets for enhanced security.

The FreeIPA administrator:
1. Generates a key pair and certificate for the IPA deployment
2. Registers the certificate with the IdP during OAuth 2.0 client registration
3. Creates a PKCS#12 bundle containing the private key and certificate
4. Configures the IdP reference in FreeIPA with the PKCS#12 bundle and sets the
authentication mechanism to `private_key_jwt`

When users authenticate, `ipa-otpd` uses the private key to sign JWT assertions
for client authentication.

### Use Case 2: High-security environment requiring mTLS

A high-security deployment requires mutual TLS authentication (RFC 8705) to
ensure both the client and server are authenticated at the transport layer.

The FreeIPA administrator:
1. Generates a key pair and certificate for the IPA deployment
2. Registers the certificate with the IdP
3. Creates a PKCS#12 bundle with the private key and certificate chain
4. Configures the IdP reference in FreeIPA with the PKCS#12 bundle and sets the
authentication mechanism to `tls_client_auth`

When users authenticate, `ipa-otpd` establishes mTLS connections using the
certificate.

### Use Case 3: Migration from shared secret to JWT assertion

An organization initially configured their IdP integration using client secrets
but wants to migrate to more secure JWT assertion authentication.

The FreeIPA administrator:
1. Generates a key pair and certificate
2. Updates the OAuth 2.0 client registration in the IdP to accept JWT assertions
3. Uploads the PKCS#12 bundle to the existing IdP reference
4. Changes the authentication mechanism from `client_secret` to
`private_key_jwt`
5. The client secret is no longer used (the PKCS#12 passphrase replaces it in
the same attribute)

## How to Use

### Configure IdP with JWT assertion authentication (RFC 7523)

1. Generate a key pair and certificate:

```bash
# Generate private key
openssl genrsa -out idp-client.key 2048

# Generate certificate signing request
openssl req -new -key idp-client.key -out idp-client.csr \
    -subj "/CN=ipa-oauth-client.example.com"

# Self-sign the certificate (or get it signed by CA)
openssl x509 -req -days 365 -in idp-client.csr \
    -signkey idp-client.key -out idp-client.crt

# Create PKCS#12 bundle
openssl pkcs12 -export -out idp-client.p12 \
    -inkey idp-client.key -in idp-client.crt \
    -passout pass:MyP12Password
```

2. Register the certificate with the IdP (IdP-specific process)

3. Add the IdP reference with PKCS#12 bundle:

```bash
ipa idp-add MyIdP --provider keycloak \
    --org myrealm --base-url keycloak.example.com \
    --client-id ipa-client \
    --client-auth-method private_key_jwt \
    --client-cert-p12-file idp-client.p12
# Will prompt for PKCS#12 password
# The PKCS#12 passphrase is stored in the client secret
```

The command will prompt for the PKCS#12 password.

### Configure IdP with mTLS authentication (RFC 8705)

```bash
ipa idp-add MyIdP --provider keycloak \
    --org myrealm --base-url keycloak.example.com \
    --client-id ipa-client \
    --client-auth-method tls_client_auth \
    --client-cert-p12-file idp-client.p12
# Will prompt for PKCS#12 password
# The PKCS#12 passphrase is stored in the client secret
```

### Update existing IdP to use certificate-based authentication

```bash
# Upload certificate bundle and change authentication method
ipa idp-mod MyIdP \
    --client-auth-method private_key_jwt \
    --client-cert-p12-file idp-client.p12
# Will prompt for PKCS#12 password
# The PKCS#12 passphrase replaces the client secret in storage
```

### View IdP configuration

```bash
# Users with 'System: Read External IdP' permission can see basic information
# and certificate details
ipa idp-show MyIdP
# Output includes:
#   Identity Provider server name: MyIdP
#   Authentication method: private_key_jwt


# Users with 'System: Read External IdP client secret' permission
# can also see protected attributes
ipa idp-show MyIdP --all
# Additionally shows:
#   Secret: ******** (hidden)
```

### Extract certificate from IdP reference

```bash
# Export the public certificate (requires 'System: Read External IdP' permission)
ipa idp-show MyIdP --out=idp-cert.pem
# Exports the public certificate from usercertificate attribute (no private key)
```

## Design

### High-Level Overview

The design extends external IdP support by introducing certificate-based client
authentication methods while maintaining backward compatibility with client
secret authentication. This is achieved through:

1. **New LDAP attributes** for storing authentication method, PKCS#12 bundle,
and public certificate
2. **Auxiliary object class** (`ipaIdpClientAuth`) added only when
certificate-based authentication is configured
3. **Dual-purpose secret attribute** - existing `ipaIdpClientSecret` stores
either OAuth 2.0 client secret or PKCS#12 passphrase depending on authentication
method
4. **Separated public and private data with different protection levels**:
   - `userPKCS12`: Complete PKCS#12 bundle with private key (protected by
   "System: Read External IdP client secret")
   - `usercertificate`: Public certificate only in base64-encoded format
   (protected by "System: Read External IdP")
5. **ACIs** to enforce permission-based access control for both private key
material and public certificate data

**Authentication method selection:**

| Method | Object Classes | Secret Attribute Contains | Certificate Data |
|--------|----------------|---------------------------|------------------|
| `client_secret` | `ipaIdP` | OAuth 2.0 client secret | Not used |
| `private_key_jwt` | `ipaIdP` + `ipaIdpClientAuth` | PKCS#12 passphrase | `userPKCS12` (Read External IdP client secret)<br>`usercertificate` (Read External IdP) |
| `tls_client_auth` | `ipaIdP` + `ipaIdpClientAuth` | PKCS#12 passphrase | `userPKCS12` (Read External IdP client secret)<br>`usercertificate` (Read External IdP) |

### LDAP Schema Extensions

#### New Attribute Types

Add the following attribute types to store client authentication information:

```ldif
attributeTypes: (2.16.840.1.113730.3.8.23.32 NAME 'ipaIdpClientAuthMethod'
 DESC 'OAuth 2.0 Client Authentication Method' EQUALITY caseIgnoreMatch
 SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'IPA v4.14' )
```

The usercertificate and userPKCS12 attributes are already defined:

```ldif
attributetypes: ( 2.5.4.36 NAME 'userCertificate' DESC 'X.509 user certificate'
 EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40
 X-ORIGIN ( 'RFC 4523' 'user defined' ) )
attributetypes: ( 2.16.840.1.113730.3.1.216 NAME 'userPKCS12'
 DESC 'PKCS #12 PFX PDU for exchange of personal identity information'
 SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 X-ORIGIN ( 'RFC 2798' 'user defined' ) )
```

**Attribute descriptions:**

- `ipaIdpClientAuthMethod`: Specifies the OAuth 2.0 client authentication
method. Valid values:
  - `client_secret`: Client authentication using shared secret (RFC 6749) -
  default for backward compatibility
  - `private_key_jwt`: JWT assertion signed with private key (RFC 7523)
  - `tls_client_auth`: Mutual TLS using X.509 certificate (RFC 8705)

- `userPKCS12`: Stores the complete PKCS#12 bundle as binary data (octet
string). This contains both the private key and certificate encrypted with a
passphrase. The passphrase is stored separately (see below). This attribute is
protected by ACIs and only accessible to authorized users. This attribute is
only used when `ipaIdpClientAuthMethod` is `private_key_jwt` or
`tls_client_auth`.

- `usercertificate`: Stores only the public X.509 certificate in base64-encoded
format, extracted from the PKCS#12 bundle during upload. This contains public
information only (no private key). This attribute is protected by the "System:
Read External IdP" permission. Used for displaying certificate metadata
(subject, issuer, expiration) and for exporting the public certificate without
requiring access to the PKCS#12 bundle.

#### New Auxiliary Object Class

Create an auxiliary object class for certificate-based client authentication:

```ldif
objectClasses: (2.16.840.1.113730.3.8.24.12 NAME 'ipaIdpClientAuth' SUP top
 AUXILIARY DESC 'External IdP Certificate-based Client Authentication'
 MUST ( ipaIdpClientAuthMethod ) MAY ( userPKCS12 $ usercertificate )
 X-ORIGIN 'IPA v4.14' )
```

**Object class usage:**

The `ipaIdpClientAuth` auxiliary class is added to IdP entries when:
- The IdP is configured with `--client-auth-method private_key_jwt` or
`tls_client_auth`
- A PKCS#12 bundle is uploaded via `--client-cert-p12-file`

When the PKCS#12 file is uploaded:
- The complete PKCS#12 bundle is stored in `userPKCS12` (protected by "System:
Read External IdP client secret")
- The public certificate is extracted and stored in `usercertificate` (protected
by "System: Read External IdP")

When `ipaIdpClientAuthMethod` is set to `client_secret`, this auxiliary class is
not needed and is removed if present.

**Rationale for auxiliary class:**

- **Separation of concerns**: Certificate authentication is an optional
enhancement, not required for all IdPs
- **Clean schema**: Entries using client secret authentication don't carry
unused attributes
- **Follows existing pattern**: Similar to how `ipaIdpUser` is an auxiliary
class added to user entries when needed
- **Easier migration**: Legacy IdP entries remain unchanged until certificate
authentication is configured
- **Data organization**: The auxiliary class groups certificate authentication
data with different protection levels: highly protected data (`userPKCS12` with
private key) and IdP-permission-protected data (`usercertificate` with public
certificate only)

#### Updated Base Object Class

The base `ipaIdP` object class remains unchanged from the current
implementation:

```ldif
objectClasses: (2.16.840.1.113730.3.8.24.6 NAME 'ipaIdP' SUP top STRUCTURAL
 DESC 'Identity Provider Configuration' MUST ( cn ) MAY ( ipaIdpDevAuthEndpoint
 $ ipaIdpAuthEndpoint $ ipaIdpTokenEndpoint $ ipaIdpUserInfoEndpoint
 $ ipaIdpKeysEndpoint $ ipaIdpClientId $ description $ ipaIdpClientSecret
 $ ipaIdpScope $ ipaIdpIssuerURL $ ipaIdpSub ) X-ORIGIN 'IPA v4.9' )
```

Note: The `ipaIdP` object class does not include the new attributes. They are
only present when the `ipaIdpClientAuth` auxiliary class is added.

#### Object Class Structure Summary

**Client secret authentication (default):**

```
Entry DN: cn=MyIdP,cn=idp,cn=etc,dc=example,dc=com
├── objectClass: ipaIdP (structural)
├── cn: MyIdP
├── ipaIdpClientId: ...
├── ipaIdpClientSecret: <OAuth 2.0 client secret>
└── (other IdP endpoints)
```

**Certificate-based authentication (JWT or mTLS):**

```
Entry DN: cn=MyIdP,cn=idp,cn=etc,dc=example,dc=com
├── objectClass: ipaIdP (structural)
├── objectClass: ipaIdpClientAuth (auxiliary)
├── cn: MyIdP
├── ipaIdpClientId: ...
├── ipaIdpClientSecret: <PKCS#12 passphrase> [requires: Read External IdP
client secret]
├── ipaIdpClientAuthMethod: private_key_jwt | tls_client_auth [requires: Read
External IdP]
├── userPKCS12: <binary PKCS#12 data> [requires: Read External IdP client
secret]
├── usercertificate: <public certificate in DER format> [requires: Read
External IdP]
└── (other IdP endpoints)
```

#### PKCS#12 Passphrase Storage

The PKCS#12 passphrase is stored in the existing `ipaIdpClientSecret` attribute.
The meaning of this attribute depends on the authentication method:

- When `ipaIdpClientAuthMethod` is `client_secret`: the attribute contains the
OAuth 2.0 client secret
- When `ipaIdpClientAuthMethod` is `private_key_jwt` or `tls_client_auth`: the
attribute contains the PKCS#12 passphrase

This approach:
- Reuses existing secret storage and ACI mechanisms
- Maintains backward compatibility
- Reduces schema changes

### Access Control Instructions (ACI)

#### Protecting Private Key Material

The `userPKCS12` attribute (containing the private key) must be protected with
strict ACIs. This applies to entries that have the `ipaIdpClientAuth` auxiliary
object class:

```ldif
# Only allow reading PKCS#12 bundle and passphrase with explicit permission
aci: (targetattr = "cn || createtimestamp || entryusn || ipaidpauthendpoint
      || ipaidpclientid || ipaidpclientsecret || ipaidpdevauthendpoint
      || ipaidpissuerurl || ipaidpkeysendpoint || ipaidpscope || ipaidpsub
      || ipaidptokenendpoint || ipaidpuserinfoendpoint || modifytimestamp
      || objectclass || usercertificate || userPKCS12")
     (targetfilter = "(objectclass=ipaidp)")
     (version 3.0;acl "permission:System: Read External IdP server client secret";
      allow (compare,read,search)
      groupdn = "ldap:///cn=System: Read External IdP server client secret,cn=permissions,cn=pbac,dc=ipa,dc=example";)

# Public certificate and authentication method are protected by Read External IdP server permission
aci: (targetattr = "cn || createtimestamp || entryusn || ipaidpauthendpoint
      || ipaidpclientid || ipaidpdevauthendpoint || ipaidpissuerurl
      || ipaidpkeysendpoint || ipaidpscope || ipaidpsub || ipaidptokenendpoint
      || ipaidpuserinfoendpoint || modifytimestamp || objectclass
      || usercertificate || ipaIdpClientAuthMethod")
     (targetfilter = "(objectclass=ipaidp)")
     (version 3.0;acl "permission:System: Read External IdP server";
      allow (compare,read,search)
      groupdn = "ldap:///cn=System: Read External IdP server,cn=permissions,cn=pbac,dc=ipa,dc=example";)

```

**Note on LDAPI access:**

The `ipa-otpd` daemon runs as root and connects to LDAP using LDAPI (LDAP over
Unix domain socket at `ldapi://%2fvar%2frun%2fslapd-<REALM>.socket`). When
connecting via LDAPI, the daemon authenticates as `cn=Directory Manager` and
has unrestricted access to all LDAP data, including protected attributes like
`userPKCS12` and `ipaIdpClientSecret`. This is necessary for the authentication
flow but is secure because:

- LDAPI is only accessible to local processes
- Only root can bind as Directory Manager via LDAPI
- The socket has strict file permissions
- ipa-otpd is a trusted system component

**Access levels:**

- **Read External IdP server permission** (users with "System: Read External
IdP server" permission):
  - Can see that an IdP entry exists
  - Can read `ipaIdpClientAuthMethod` if present
  - Can read `usercertificate` (public certificate only - no private key)
  - Can view certificate metadata: subject, issuer, expiration date, serial
  number
  - Cannot read `userPKCS12` or `ipaIdpClientSecret`

- **Read External IdP server client secret permission** (users with "System:
Read External IdP server client secret" permission):
  - Includes all "Read External IdP server" capabilities plus:
  - Can read `userPKCS12` (complete PKCS#12 bundle with private key)
  - Can read `ipaIdpClientSecret` (client secret or PKCS#12 passphrase)

- **System access** (ipa-otpd daemon):
  - Connects to LDAP via LDAPI (LDAP over Unix socket)
  - Authenticates as Directory Manager (cn=Directory Manager)
  - Has unrestricted access to all attributes including private key material
  - Required for reading PKCS#12 bundle and passphrase during authentication
  flow
  - LDAPI connection ensures only local root processes can authenticate as
  Directory Manager

#### Permissions

The following permissions are used to control access to IdP data:

**System: Read External IdP server** (existing permission, extended):
- Allows reading basic IdP configuration attributes
- New attributes covered by this permission:
  - `ipaIdpClientAuthMethod` - authentication method in use
  - `usercertificate` - public certificate (no private key)
- Users with this permission can view certificate metadata and export public
certificates
- Included in "External IdP Administrator" privilege

**System: Read External IdP server client secret** (existing permission,
extended):
- Allows reading sensitive authentication credentials
- Attributes covered by this permission:
  - `ipaIdpClientSecret` (existing - client secret or PKCS#12 passphrase)
  - `userPKCS12` (new - complete PKCS#12 bundle with private key)
- Users with this permission can access PKCS#12 data for backup or certificate
rotation
- **Not** included in "External IdP Administrator" privilege by default,
ensuring separation of duties
- Intended for security administrators who need to backup or rotate certificates

### Information Workflow

#### Adding IdP with Certificate Authentication

```
1. Administrator generates key pair and certificate
2. Administrator registers certificate with IdP
3. Administrator creates PKCS#12 bundle with passphrase
4. Administrator runs: ipa idp-add --client-cert-p12-file <file>
5. IPA API reads PKCS#12 file (client-side)
6. IPA API prompts for PKCS#12 passphrase
7. IPA API validates PKCS#12 bundle (can be decrypted)
8. IPA API extracts public certificate from PKCS#12 bundle
9. IPA API converts certificate to base64-encoded format
10. IPA API creates LDAP entry:
    - Base object class: ipaIdP
    - Adds auxiliary object class: ipaIdpClientAuth
    - Stores complete PKCS#12 bundle in userPKCS12 (binary, protected)
    - Stores public certificate only in usercertificate (base64-encoded format,
    public)
    - Stores passphrase in ipaIdpClientSecret (encrypted, protected)
    - Stores authentication method in ipaIdpClientAuthMethod
11. Appropriate ACIs applied to protect private key material
```

#### Authentication Flow with JWT Assertion (RFC 7523)

```
1. User initiates kinit with IdP authentication
2. KDC contacts ipa-otpd
3. ipa-otpd retrieves IdP reference from LDAP
4. ipa-otpd checks ipaIdpClientAuthMethod = "private_key_jwt"
5. ipa-otpd retrieves userPKCS12 and ipaIdpClientSecret
6. ipa-otpd decrypts PKCS#12 using passphrase
7. ipa-otpd calls oidc_child with:
   - Private key extracted from PKCS#12
   - Client authentication method
   - IdP endpoints
8. oidc_child creates JWT assertion:
   - Header: {"alg": "RS256", "typ": "JWT"}
   - Claims: {"iss": client_id, "sub": client_id,
              "aud": token_endpoint, "exp": timestamp+300}
9. oidc_child signs JWT with private key
10. oidc_child sends token request with:
    - client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    - client_assertion=<signed JWT>
11. IdP validates JWT signature using registered certificate
12. IdP returns access token
13. Authentication proceeds as normal
```

#### Authentication Flow with mTLS (RFC 8705)

```
1. User initiates kinit with IdP authentication
2. KDC contacts ipa-otpd
3. ipa-otpd retrieves IdP reference from LDAP
4. ipa-otpd checks ipaIdpClientAuthMethod = "tls_client_auth"
5. ipa-otpd retrieves userPKCS12 and ipaIdpClientSecret
6. ipa-otpd decrypts PKCS#12 using passphrase
7. ipa-otpd calls oidc_child with:
   - Certificate and private key extracted from PKCS#12
   - Client authentication method
   - IdP endpoints
8. oidc_child establishes TLS connection to IdP:
   - Presents client certificate during handshake
   - Uses private key for TLS authentication
9. oidc_child sends token request over mTLS connection:
   - client_id=<client_id>
   - No client_secret or client_assertion needed
10. IdP validates certificate against registered certificate
11. IdP returns access token (optionally certificate-bound)
12. Authentication proceeds as normal
```

### Compatibility Considerations

#### Backward Compatibility

- Existing IdP entries without `ipaIdpClientAuth` auxiliary class continue to
work unchanged
- These entries use client secret authentication by default
- Existing `ipaIdpClientSecret` continues to work as OAuth 2.0 client secret
- No schema changes to existing entries
- No automatic migration required
- The auxiliary class is only added when explicitly configuring
certificate-based authentication

#### Mixed Topology

- In mixed topology with old and new servers:
  - New LDAP attributes replicate to old servers
  - Old servers ignore unknown attributes
  - IdP management API only available on new servers
  - Authentication using certificate methods only works on new servers with
  updated ipa-otpd

## Implementation

### IPA API Changes

#### New Parameters for idp-add and idp-mod

```python
Str('ipaidpclientauthmethod?',
    cli_name='client_auth_method',
    label=_('Client authentication method'),
    values=('client_secret', 'private_key_jwt', 'tls_client_auth'),
    default='client_secret',
),
Str('ipaidpclientcertp12_file?',
    cli_name='client_cert_p12_file',
    label=_('PKCS#12 file path'),
),
```

#### Certificate Validation and Auxiliary Class Management

The API must:
1. Read PKCS#12 file from disk (client-side)
2. Prompt for PKCS#12 password if not provided
3. Validate PKCS#12 bundle can be decrypted with the provided passphrase
4. Extract public certificate from PKCS#12 bundle (client-side)
5. Convert certificate to base64-encoded format
6. Send both PKCS#12 bundle and extracted certificate to server

**Adding auxiliary class:**
- When `--client-auth-method` is `private_key_jwt` or `tls_client_auth`:
  - Add `ipaIdpClientAuth` auxiliary object class to the entry
  - Store `ipaIdpClientAuthMethod` attribute
  - Store `userPKCS12` attribute (complete PKCS#12 bundle)
  - Store `usercertificate` attribute (public certificate in base64-encoded
  format)
  - Update `ipaIdpClientSecret` to contain PKCS#12 passphrase

**Removing auxiliary class:**
- When `--client-auth-method` is changed from certificate-based to
`client_secret`:
  - Remove `ipaIdpClientAuth` auxiliary object class from the entry
  - Remove `ipaIdpClientAuthMethod` attribute
  - Remove `userPKCS12` attribute
  - Remove `usercertificate` attribute
  - Update `ipaIdpClientSecret` to contain OAuth 2.0 client secret

**Displaying certificate information:**

To display certificate information (requires "System: Read External IdP"
permission):
- Read `usercertificate` attribute directly from LDAP
- Parse base64-encoded certificate
- Display metadata: subject, issuer, expiration, serial number, key size
- Export public certificate to PEM file using `ipa idp-show <name> --out=<file>`

### Backup and Restore

PKCS#12 bundles are stored in LDAP and will be included in standard LDAP
backups:
- `ipa-backup` includes all IdP entries with PKCS#12 data
- `ipa-restore` restores PKCS#12 bundles
- **Security consideration**: Backup files contain encrypted private keys, must
be protected

Administrators should:
- Secure backup files with appropriate permissions
- Consider additional encryption for backup media
- Document PKCS#12 passphrases in secure location

### Certificate Expiration and Rotation

The implementation should include:
1. Certificate expiration monitoring (future enhancement)
2. Ability to update PKCS#12 bundle without service interruption
3. Documentation for certificate rotation procedures

## Security Considerations

### Access Control Model

The design implements a layered security model with three distinct access
levels:

#### 1. IdP Configuration and Public Certificate Data (requires "System: Read External IdP server" permission)

Users with the "System: Read External IdP server" permission can:
- View IdP configuration including authentication methods
- Read `ipaIdpClientAuthMethod` attribute
- Read `usercertificate` attribute (public certificate only, no private key
material)
- View certificate metadata: subject, issuer, expiration, serial number
- Export public certificates for verification purposes

This permission provides controlled access to IdP configuration data. Even
though `usercertificate` contains only public certificate information (no
private key), it is still protected by this permission to control who can view
IdP configuration.

This permission is appropriate for:
- IdP administrators who need to manage and verify IdP configurations
- Monitoring systems that track certificate expiration
- Support personnel who need to validate IdP setup
- Users authorized to view IdP configuration for troubleshooting

#### 2. Private Key Material (requires "System: Read External IdP server client secret" permission)

Users with the "System: Read External IdP server client secret" permission can:
- Access complete PKCS#12 bundles containing private keys
- Read PKCS#12 passphrases
- Export complete certificate bundles for backup or migration

This permission is NOT included in the "External IdP Administrator" privilege
by default, ensuring separation of duties. It should be granted only to:
- Security administrators responsible for certificate lifecycle management
- Backup operators who need to export certificates for disaster recovery
- Senior administrators performing certificate rotation

#### 3. System Access (ipa-otpd via LDAPI as Directory Manager)

The `ipa-otpd` daemon requires unrestricted access to private key material for
authentication processing:

**Connection Method:**
- Protocol: LDAPI (LDAP over Unix domain socket)
- Socket: `ldapi://%2fvar%2frun%2fslapd-<REALM>.socket`
- Authentication: Binds as `cn=Directory Manager`
- Access Level: Unrestricted access to all LDAP data

**Security Guarantees:**
- **Local-only access**: LDAPI socket is only accessible to processes on the
local IPA server
- **Root-only binding**: Only root processes can bind as Directory Manager via
LDAPI
- **File permissions**: Unix socket has strict permissions (0600 or similar)
- **No network exposure**: LDAPI is not accessible over the network
- **Trusted component**: ipa-otpd is a core IPA system service, runs as root,
systemd-managed
- **Temporary files**: PKCS#12 data written to `/run/ipa/` with 0600
permissions, deleted immediately after use
- **No caching**: Private key material is not cached in memory longer than
necessary

**Why Directory Manager access is required:**
- ACIs protecting `userPKCS12` and `ipaIdpClientSecret` cannot be bypassed by
service accounts
- Authentication processing requires reading private keys during user login
- LDAPI with Directory Manager is the standard IPA pattern for privileged
system components
- Alternative approaches (service accounts, special ACIs) would be more complex
and less secure

### Threat Model and Mitigations

| Threat | Mitigation |
|--------|------------|
| Unauthorized access to private keys via LDAP | ACIs restrict access; only Directory Manager (via LDAPI) and users with explicit permission can read |
| Malicious user accessing PKCS#12 data | "Read External IdP client secret" permission not granted by default; requires explicit privilege assignment |
| Temporary file exposure | PKCS#12 files written to `/run/ipa/` with 0600 permissions, root-only access, deleted immediately |
| Memory disclosure | ipa-otpd minimizes time private keys are held in memory; no long-term caching |
| Backup file compromise | LDAP backups contain encrypted PKCS#12 bundles; passphrases protect private keys even if backup is stolen |
| LDAPI socket compromise | Socket accessible only to local root processes; compromised root means system is already fully compromised |

### Comparison with Client Secret Security

Certificate-based authentication provides stronger security than client secrets:

| Aspect | Client Secret | Certificate-based (RFC 7523/8705) |
|--------|---------------|-----------------------------------|
| Authentication strength | Symmetric key (shared secret) | Asymmetric key (private key never shared) |
| Compromise impact | Secret must be rotated everywhere | Only public cert registered with IdP, private key stays on IPA |
| Network exposure | Secret sent over TLS to IdP | JWT signed locally or mTLS, private key never transmitted |
| Storage security | Same LDAP protection as passphrase | Same LDAP protection as passphrase |
| Rotation complexity | Must coordinate with IdP | Register new cert, update PKCS#12, no IdP coordination for rotation |

## Feature Management

### UI

#### IdP Configuration Page

In the Web UI Authentication → Identity Provider section:

**Add IdP dialog:**
- Add dropdown: "Client Authentication Method" with options:
  - "Client Secret" (default)
  - "JWT Assertion (RFC 7523)"
  - "Mutual TLS (RFC 8705)"
- When "JWT Assertion (RFC 7523)" or "Mutual TLS (RFC 8705)" selected:
  - Show "PKCS#12 Certificate" file upload field

**Show/Edit IdP page:**
- Display "Authentication Method" field
  - Requires "System: Read External IdP" permission
- Display certificate information if present (requires "System: Read External
IdP" permission):
  - Certificate Subject
  - Certificate Issuer
  - Certificate Valid from / Valid to Date
  - Certificate Serial Number
  - Actions certificate button with View / Get / Download / Delete (exports
  public certificate only from `usercertificate`)
- Add action: "Update Certificate" button (only visible when auth method is
`private_key_jwt` or `tls_client_auth`)
  - Opens dialog for PKCS#12 upload
- "Secret" field behavior:
  - If auth method is `client_secret`: label shows "Client Secret"
  - If auth method is `private_key_jwt` or `tls_client_auth`: label shows
  "Certificate Passphrase"
  - The value is obfuscated **********

### CLI

| Command | Options |
| --- | ----- |
| idp-add | --client-auth-method=STR, --client-cert-p12-file=PATH, --secret=STR |
| idp-mod | --client-auth-method=STR, --client-cert-p12-file=PATH, --secret=STR |
| idp-show | --out=FILE (to export public certificate) |

#### Examples

```bash
# Add IdP with JWT assertion authentication
ipa idp-add MyKeycloak \
    --provider keycloak \
    --org myrealm \
    --base-url keycloak.example.com \
    --client-id ipa-client \
    --client-auth-method private_key_jwt \
    --client-cert-p12-file /path/to/cert.p12
# Will prompt for PKCS#12 password

# Add IdP with mTLS authentication
ipa idp-add MyOkta \
    --provider okta \
    --base-url dev-12345.okta.com \
    --client-id ipa-client \
    --client-auth-method tls_client_auth \
    --client-cert-p12-file /path/to/cert.p12

# Update existing IdP to use JWT assertion
ipa idp-mod MyIdP \
    --client-auth-method private_key_jwt \
    --client-cert-p12-file /path/to/new-cert.p12

# Show IdP with certificate information
# (requires 'System: Read External IdP' permission)
ipa idp-show MyIdP
# Output includes:
#   Identity Provider server name: MyIdP
#   Authentication method: private_key_jwt
#   Certificate subject: CN=ipa-oauth-client.example.com
#   Certificate issuer: CN=Example CA
#   Certificate expiration: 2026-03-31 12:00:00 UTC
#   Certificate serial number: 1234567890ABCDEF

# Export public certificate
# (requires 'System: Read External IdP' permission)
ipa idp-show MyIdP --out=idp-cert.pem
```

### Configuration

No additional configuration files needed. All settings stored in LDAP.

Optional: Add certificate expiration check to `ipa-healthcheck`:

```bash
ipa-healthcheck --source ipahealthcheck.ipa.idp
```

## Upgrade

### Schema Update

During upgrade from earlier versions:
1. New LDAP attribute types added to schema (automatic):
   - `ipaIdpClientAuthMethod`
2. New auxiliary object class `ipaIdpClientAuth` added to schema
3. Schema changes replicated to all servers
4. New ACIs applied to IdP container:
   - Protect `userPKCS12` and `ipaIdpClientSecret` (requires special permission)
   - Allow `usercertificate` to be read with general IdP read permissions
5. Existing IdP entries remain unchanged (no auxiliary class added
automatically)

### Data Migration

During upgrade:
- Existing IdP entries remain unchanged (no auxiliary class added)
- They continue to use client secret authentication by default
- No `ipaIdpClientAuthMethod` attribute is set (defaults to `client_secret`
behavior)
- If any legacy values `client_secret_basic` or `client_secret_post` exist,
they can be ignored (treated as `client_secret`)
- The `ipaIdpClientAuth` auxiliary class is only added when administrators
explicitly configure certificate-based authentication

**Manual migration to certificate-based authentication:**

Administrators can migrate existing IdP references using:

```bash
ipa idp-mod <name> \
    --client-auth-method private_key_jwt \
    --client-cert-p12-file <path>
```

This will:
1. Add the `ipaIdpClientAuth` auxiliary class to the entry
2. Set `ipaIdpClientAuthMethod` to `private_key_jwt`
3. Store the complete PKCS#12 bundle in `userPKCS12` (protected)
4. Extract and store the public certificate in `usercertificate` (public)
5. Replace the client secret with the PKCS#12 passphrase in `ipaIdpClientSecret`

### Upgrade Path

1. Upgrade all IPA servers to version supporting RFC 7523/8705
2. Upgrade SSSD to version with enhanced oidc_child (coordinate releases)
3. Optionally migrate IdP references to certificate-based authentication:

```bash
ipa idp-mod <name> --client-auth-method private_key_jwt \
    --client-cert-p12-file <path>
```

## Test Plan

### Unit Tests

1. **LDAP Schema Tests**
   - Verify `ipaIdpClientAuth` auxiliary class can be added to IdP entries
   - Verify new attributes can be set and retrieved when auxiliary class is
   present
   - Verify PKCS#12 binary data storage
   - Verify ACI restricts access to PKCS#12 data
   - Verify auxiliary class is automatically removed when switching to
   `client_secret`

2. **API Tests**
   - Test idp-add with --client-cert-p12-file
   - Verify both `userPKCS12` and `usercertificate` are populated
   - Verify certificate extraction from PKCS#12 produces valid DER certificate
   - Test idp-mod updating certificate (both attributes updated)
   - Test PKCS#12 validation (can be decrypted)
   - Test public certificate display without special permissions
   - Test permission checks for PKCS#12 access (requires special permission)
   - Verify certificate metadata extraction (subject, issuer, expiration,
   serial)

### Integration Tests

1. **JWT Assertion Authentication (RFC 7523)**
   - Generate test PKCS#12 bundle
   - Configure test IdP (Keycloak) to accept JWT assertions
   - Add IdP reference with private_key_jwt method
   - Authenticate user and verify JWT assertion is sent
   - Verify successful Kerberos ticket issuance

2. **Mutual TLS Authentication (RFC 8705)**
   - Generate test certificate
   - Configure test IdP to require mTLS
   - Add IdP reference with tls_client_auth method
   - Authenticate user and verify mTLS connection
   - Verify successful Kerberos ticket issuance

3. **Migration Test**
   - Create IdP with `client_secret` authentication
   - Verify entry does not have `ipaIdpClientAuth` auxiliary class
   - Authenticate user successfully
   - Update to `private_key_jwt` authentication
   - Verify `ipaIdpClientAuth` auxiliary class was added
   - Verify `ipaIdpClientAuthMethod` and `userPKCS12` attributes are present
   - Authenticate user with new method
   - Switch back to `client_secret`
   - Verify `ipaIdpClientAuth` auxiliary class was removed
   - Verify both methods worked

4. **Permission Tests**
   - Verify users without any IdP permissions:
     - Cannot see IdP entries
     - Cannot access any IdP attributes
   - Verify users with "System: Read External IdP server" permission:
     - Can see IdP entries and basic attributes
     - Can see authentication method (`ipaIdpClientAuthMethod`)
     - Can see public certificate details from `usercertificate` (subject,
     expiration, etc.)
     - Can export public certificate
     - Cannot access PKCS#12 bundle (`userPKCS12`)
     - Cannot access client secret/passphrase (`ipaIdpClientSecret`)
   - Verify users with "System: Read External IdP server client secret"
   permission:
     - Have all "Read External IdP" capabilities plus:
     - Can access PKCS#12 bundle (`userPKCS12`)
     - Can access client secret/passphrase (`ipaIdpClientSecret`)
   - Verify ipa-otpd daemon access:
     - Connects via LDAPI as Directory Manager
     - Has unrestricted access to all attributes including protected data
     - Can read PKCS#12 and passphrase for authentication processing

5. **Replication Tests**
   - Add IdP with certificate on server A
   - Verify IdP and PKCS#12 replicate to server B
   - Authenticate against server B
   - Verify authentication works

### Test Scenarios

1. **Test with Multiple IdP Providers**
   - Keycloak with private_key_jwt
   - Okta with tls_client_auth
   - Microsoft Azure AD with private_key_jwt
   - Google (using client_secret for comparison)

2. **Negative Tests**
   - Invalid PKCS#12 file
   - Wrong PKCS#12 password
   - Expired certificate
   - Certificate not registered with IdP
   - Mismatched authentication method

3. **Security Tests**
   - PKCS#12 not accessible without permission
   - PKCS#12 passphrase not displayed in logs
   - Temporary files cleaned up properly
   - Certificate rotation doesn't leak old keys

## Troubleshooting and debugging

### Files and Keytabs

- **LDAP entries**: IdP references stored in `cn=<name>,cn=idp,<suffix>`
- **Temporary files**: ipa-otpd creates temporary PKCS#12 files in `/run/ipa/`
(automatically cleaned up)
- **Keytabs**: No additional keytabs required

### Logs

1. **ipa-otpd logs** (`journalctl -u ipa-otpd`):
   - Shows IdP retrieval and oidc_child invocation
   - Example: `Retrieved IdP reference: MyIdP, auth method: private_key_jwt`
   - Example: `Calling oidc_child with PKCS#12 bundle`

2. **oidc_child logs** (`/var/log/sssd/sssd_oidc_child.log` when debug enabled):
   - Shows JWT assertion creation
   - Shows mTLS connection establishment
   - Shows token endpoint communication

3. **KDC logs** (`/var/log/krb5kdc.log`):
   - Shows pre-authentication flow

### LDAP Entries

IdP entries structure:

**IdP with client secret authentication:**

```ldif
dn: cn=MyIdP,cn=idp,dc=example,dc=com
objectClass: ipaIdP
cn: MyIdP
ipaIdpClientId: ipa-client
ipaIdpClientSecret: encrypted_client_secret
ipaIdpTokenEndpoint: https://idp.example.com/token
ipaIdpDevAuthEndpoint: https://idp.example.com/device/authorize
```

**IdP with certificate-based authentication (JWT or mTLS):**

```
dn: cn=MyIdP,cn=idp,dc=example,dc=com
objectClass: ipaIdP
objectClass: ipaIdpClientAuth
cn: MyIdP
ipaIdpClientId: ipa-client
ipaIdpClientAuthMethod: private_key_jwt
userPKCS12: binary_PKCS_12_data_with_private_key
usercertificate: binary_DER_certificate_public_only
ipaIdpClientSecret: encrypted_PKCS_12_passphrase
ipaIdpTokenEndpoint: https://idp.example.com/token
ipaIdpDevAuthEndpoint: https://idp.example.com/device/authorize
```

**Note on access control:**

When certificate-based authentication is configured, the `ipaIdpClientAuth`
auxiliary object class is present. Access to attributes is controlled as follows:

- `ipaIdpClientAuthMethod` and `usercertificate`: Require "System: Read
External IdP" permission
- `userPKCS12` and `ipaIdpClientSecret`: Require "System: Read External IdP
client secret" permission
- `ipa-otpd` daemon: Connects via LDAPI as Directory Manager, has unrestricted
access to all attributes

### Debug Mode

Enable detailed logging:

1. **ipa-otpd debug logging**:
The logs are accessible in the journal:

```bash
journalctl -u 'ipa-otpd@*'
```

2. **Enable oidc_child debug logging**:

```bash
# Edit /etc/ipa/default.conf
[global]
oidc_child_debug_level=10
```

3. **Check certificate details**:

```bash
# View public certificate information
# (requires 'System: Read External IdP server' permission)
ipa idp-show MyIdP
# Shows: subject, issuer, expiration, serial number

# Export and verify certificate
ipa idp-show MyIdP --out=/tmp/idp-cert.pem
openssl x509 -in /tmp/idp-cert.pem -text -noout
openssl x509 -in /tmp/idp-cert.pem -enddate -noout
```

### Common Issues

| Issue | Diagnosis | Resolution |
|-------|-----------|------------|
| "Invalid PKCS#12 password" | Wrong passphrase stored | Update with correct passphrase: `ipa idp-mod MyIdP --client-cert-p12-file <file>` |
| "Certificate expired" | Check certificate expiration date | Generate new certificate and update: `ipa idp-mod MyIdP --client-cert-p12-file <new-file>` |
| "JWT signature validation failed" | Certificate mismatch with IdP | Verify certificate registered with IdP matches stored certificate |
| "TLS handshake failed" | mTLS configuration issue | Check IdP requires client certificate, verify certificate is valid |
| "Permission denied reading PKCS#12" | ACI not allowing access | This is expected; ipa-otpd runs as root and can access; verify user has permission if trying to view |

### Verification Steps

1. **Verify IdP configuration**:

```bash
ipa idp-show MyIdP
# Check Authentication method
# Certificate subject, issuer, expiration
# (requires 'System: Read External IdP server' permission)

# Verify certificate is valid
ipa idp-show MyIdP --out=/tmp/cert.pem
openssl x509 -in /tmp/cert.pem -text -noout
```

2. **Verify SSSD oidc_child can be invoked**:

```bash
# As root on IPA server
/usr/libexec/sssd/oidc_child --help
```

3. **Test authentication**:

```bash
# On IPA client
kinit -n -c /tmp/fast.ccache
kinit -T /tmp/fast.ccache testuser
# Follow device authorization prompts
```

4. **Check authentication flow**:

```bash
# On IPA server, tail logs during authentication
journalctl -f -u ipa-otpd -u krb5kdc
```

