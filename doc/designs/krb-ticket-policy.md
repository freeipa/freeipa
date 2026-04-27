# Policies by authentication indicators

## Overview

Based on the pre-authentication mechanism a user used to acquire the credential, 
the KDC can enforce policies such as service access control, 
user authentication and ticket lifetime/reissue time policies to achieve a finer control over ticket issuance.

## Authentication indicators

Authentication indicators are attached by the KDC to tickets issued to users and depend on
which pre-authentication mechanism was used to acquire the credential.

### AS-REQ indicators

These indicators are set during the initial ticket-granting ticket (TGT) request (AS-REQ) and
reflect the pre-authentication method used by the user directly against the KDC:

| Authentication indicator | Mechanism            |
|:------------------------ | :------------------- |
| radius                   | RADIUS               |
| otp                      | Two factor authentication (password + OTP) |
| pkinit                   | PKINIT               |
| hardened                 | Hardened Password (by SPAKE or FAST) |
| idp                      | External Identity Provider |
| passkey                  | Passkey (FIDO2/WebAuthn hardware authenticator) |

Hardened password means a password authentication with either SPAKE or FAST armoring enabled.
Although it is possible to assign separate indicators to SPAKE and FAST, when both SPAKE and FAST are used,
only the indicator for SPAKE will be applied.
Since there is no practical reason to forbid the use of SPAKE while using FAST armoring,
these two are assigned the same indicator to represent a brute-force hardened form of password authentication.

### S4U2Self protocol-transition indicators

These indicators are set during S4U2Self (protocol transition) requests in which a Kerberos
service presents an X.509 attestation certificate alongside `PA-FOR-X509-USER`.  They reflect
the authentication method used by the user against the *service*, not against the KDC directly.
Each indicator follows the pattern `<serviceType>-authn:<detail>`:

| Authentication indicator        | Mechanism |
|:------------------------------- |:--------- |
| `ssh-authn:publickey`           | SSH public-key authentication (attested S4U2Self) |
| `ssh-authn:password`            | SSH password authentication (attested S4U2Self) |
| `ssh-authn:keyboard-interactive`| SSH keyboard-interactive authentication (attested S4U2Self) |
| `oidc-authn:<amr>`              | OIDC/OpenID Connect; one indicator per RFC 8176 §2 AMR value (e.g. `oidc-authn:pwd`, `oidc-authn:otp`, `oidc-authn:mfa`) |
| `oidc-authn:sso`                | OIDC; fallback when no `amrValues` are present in the attestation context |

Unlike AS-REQ indicators, S4U2Self indicators are not gated by the user's `ipaUserAuthType`
setting.  They are emitted unconditionally whenever the KDB plugin successfully verifies the
attestation certificate.  Multiple `oidc-authn:*` indicators may appear simultaneously in a
single ticket (one per AMR value).

By requiring certain authentication indicators to a user, we can force a user to be authenticated with one of
the mechanisms associated with those auth indicators to obtain a ticket.
By defining an allow list of authentication indicators to a service, we can allow a user to use the service
only if the user obtained a ticket with at least one of those indicators included.

### Note

For unattended services (services that is a part of the IPA core system), the authentication indicator should not be set, 
or it may break the whole system. Examples for such services are `HTTP/*` (for webUI and IPA API end-points), 
`ldap/*` (for user data management etc.), `cifs/*` (for SMB and DCE-RPC services), 
also for `host/*` on IPA masters which are used by DCE-RPC services to validate client-server communication.

## Available policies and user interface

### Connection policy

Different service may need different security strength and consequently requires different pre-auth mechanism.

e.g. must have used 2FA or OTP in order to connect to `host/securemachine@REALM`

Services with no authentication indicator assigned will accept tickets authenticated by any mechanism.

#### CLI Workflow:

Administrators can specify required auth indicators for a service via `ipa service-mod` command.

```bash
# Require OTP or PKINIT pre-authentication:
ipa service-mod service/@REALM --auth-ind otp --auth-ind pkinit

# Require SSH public-key attestation (S4U2Self):
ipa service-mod http/api.example.com@REALM --auth-ind ssh-authn:publickey

# Require any OIDC MFA attestation:
ipa service-mod http/api.example.com@REALM --auth-ind oidc-authn:mfa
```

Accepted values for `--auth-ind` are the fixed AS-REQ indicators (`otp`,
`radius`, `pkinit`, `hardened`, `idp`, `passkey`) and any S4U2Self
protocol-transition indicator of the form `<service>-authn:<detail>`,
where `<service>` is a lowercase identifier (e.g. `ssh`, `oidc`) and
`<detail>` is a lowercase alphanumeric/hyphen string (e.g. `publickey`,
`mfa`, `keyboard-interactive`).

#### WebUI Workflow:

Administrators can specify required auth indicator on service settings page. 
As default no auth indicator is specified which means all pre-auth mechanism is accepted.

### Ticket lifecycle policy

Administrators may want to define different ticket expiration and renewal values 
as well as ticket flags based on the type of the authentication conducted.

e.g. the lifetime of the OTP based ticket can be longer than for a single-factor

Tickets without an authentication indicator will have the default lifetime / renewtime.

#### CLI Workflow:

Administrators can specify max life and renew for each auth indicator and global default via `ipa krbtpolicy-mod` command.

e.g. `ipa krbtpolicy-mod --otp-maxlife=604800 --pkinit-maxlife=604800`

S4U2Self attestation indicators have dedicated options as well:

```
ipa krbtpolicy-mod --ssh-authn-maxlife=28800 --ssh-authn-maxrenew=86400
ipa krbtpolicy-mod --oidc-authn-maxlife=43200 --oidc-authn-maxrenew=172800
```

Current `--maxlife` and `--maxrenew` options for `ipa krbtpolicy-mod` will set the default max life / renew respectively.

After this, the output for `ipa krbtpolicy-show` will look like:

```
Max life: 86400
OTP max life: 604800
PKINIT max life: 604800
SSH attestation max life: 28800
SSH attestation max renew: 86400
OIDC attestation max life: 43200
OIDC attestation max renew: 172800
Max renew: 604800
```

The `ssh-authn` and `oidc-authn` lifetime limits are enforced during **TGS-REQ** processing
(specifically during S4U2Proxy, when a delegated service ticket is issued using the S4U2Self
ticket).  The limits from the *target service's* policy are applied.  AS-REQ indicator limits
(`otp`, `pkinit`, etc.) are enforced at TGT issuance time and are not affected by this change.

#### WebUI Workflow:

In Policy/Kerberos Ticket Policy tab, there is a table 
where administrators can specify max renew and life for each supported auth indicator.

### Ticket lifetime jitter

All TGT lifetimes are varied slightly to avoid overwhelming the KDC with
simultaneous renewal requests.  Jitter will reduce lifetimes by up to one hour
from the configured maximum lifetime (per policy).  Significantly shorter
requested lifetimes will be unaffected.

## Implementation

Kerberos policy, as krb5 presents it, consists of two interfaces: 
the authentication indicator attributes and the kdcpolicy plugin.
Authentication indicator attributes allow us to make boolean access choices
(i.e. allow or deny service principal requests) on the KDC based on configuration in the Kerberos Database (KDB).
The kdcpolicy plugin is a much more powerful hook, allowing refinement of the request itself rather than 
a solely boolean decision.

Connection Policy can be implemented with authentication indicator attribute in krb5 alone, 
but ticket lifecycle policy will require LDAP to store relations between authentication indicators
and lifetime information. We have global ticket lifetime and renew time setting stored as attribute 
`krbmaxticketlife` and `krbmaxrenewableage` inside the `cn=$REALM,cn=kerberos,$SUFFIX` subtree, 
which represents the default lifetime policy.

Two new multi-valued attributes are added to store an authentication
indicator-specific maximum ticket life and ticket's maximum renewable age. The
type of authentication indicator is specified as LDAP attribute option:

```
krbAuthIndMaxTicketLife;otp: 604800
krbAuthIndMaxRenewableAge;pkinit: 604800
krbAuthIndMaxTicketLife;ssh-authn: 28800
krbAuthIndMaxRenewableAge;ssh-authn: 86400
krbAuthIndMaxTicketLife;oidc-authn: 43200
krbAuthIndMaxRenewableAge;oidc-authn: 172800
```

They are stored in the same policy object in LDAP.

### AS-REQ vs TGS-REQ enforcement

The `ipa_kdcpolicy_check_as()` hook enforces lifetime limits for AS-REQ indicators
(`otp`, `radius`, `pkinit`, `hardened`, `idp`, `passkey`).  These limits come from the
**client** (user) principal's policy and are applied at TGT issuance time.  Each indicator
is gated on the user's `ipaUserAuthType` bitmask: an OTP limit is only loaded if OTP is
enabled for that user.

The `ipa_kdcpolicy_check_tgs()` hook enforces lifetime limits for S4U2Self indicators
(`ssh-authn:*`, `oidc-authn:*`).  These limits come from the **server** (target service)
principal's policy and are applied during TGS-REQ processing — specifically during
S4U2Proxy, when a delegated ticket carrying the S4U2Self attestation indicators is used
to request access to a downstream service.  Unlike AS-REQ indicators, `ssh-authn` and
`oidc-authn` entries are always parsed regardless of the principal's `ipaUserAuthType`
setting, since they are not controlled by per-user authentication configuration.

### IPA API: `krbprincipalauthind` parameter

The `krbprincipalauthind` parameter on `ipa service-mod`, `ipa service-add`,
`ipa host-mod`, and `ipa host-add` (CLI option `--auth-ind`) previously used
`StrEnum` restricted to the fixed AS-REQ indicator set.  It has been changed to
`Str` with a `validate_auth_indicator_value()` rule that accepts:

- Any member of the fixed set: `otp`, `radius`, `pkinit`, `hardened`, `idp`,
  `passkey` — fully backward-compatible with the previous `StrEnum` behaviour
- Any string matching the pattern `^[a-z][a-z0-9]*-authn:[a-z][a-z0-9-]*$`,
  covering all current and future `<service>-authn:<detail>` S4U2Self
  attestation indicator prefixes

All values accepted by the old `StrEnum` remain valid; no migration or
configuration change is needed for existing deployments.  Invalid values (wrong
case, empty detail, unrecognised fixed names) are rejected at parameter
validation time with a descriptive error.
