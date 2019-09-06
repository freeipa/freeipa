# Policies by authentication indicators

## Overview

Based on the pre-authentication mechanism a user used to acquire the credential, 
the KDC can enforce policies such as service access control, 
user authentication and ticket lifetime/reissue time policies to achieve a finer control over ticket issuance.

## Authentication indicators

Authentication indicators are attached by KDC to tickets issued to user and depend on 
which pre-authentication mechanism used to acquire the credential. 
Indicators and corresponding mechanisms are listed below:

| Authentication indicator | Mechanism            |
|:------------------------ | :------------------- |
| radius                   | RADIUS               |
| otp                      | Two factor authentication (password + OTP) |
| pkinit                   | PKINIT               |
| hardened                 | Hardened Password (by SPAKE or FAST) |

Hardened password means a password authentication with either SPAKE or FAST armoring enabled. 
Although it is possible to assign separate indicators to SPAKE and FAST, when both SPAKE and FAST are used, 
only the indicator for SPAKE will be applied. 
Since there is no practical reason to forbid the use of SPAKE while using FAST armoring, 
these two are assigned the same indicator to represent a brute-force hardened form of password authentication.

By requiring certain authentication indicators to a user, we can force a user to be authenticated with one of 
the mechanisms associated with those auth indicators to obtain a ticket.
By defining a white list of authentication indicators to a service, we can allow a user to use the service 
only if the user obtained a ticket with at least one of those indicators included.

#### Note

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

e.g. `ipa service-mod service/@REALM --auth-ind otp --auth-ind pkinit`

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

Current `--maxlife` and `--maxrenew` options for `ipa krbtpolicy-mod` will set the default max life / renew respectively.

After this, the output for `ipa krbtpolicy-show` will look like:

```
Max life: 86400
OTP max life: 604800
PKINIT max life: 604800
Max renew: 604800
```

#### WebUI Workflow:

In Policy/Kerberos Ticket Policy tab, there is a table 
where administrators can specify max renew and life for each supported auth indicator.

### Ticket lifetime jitter

Ticket lifetimes can be jittered so that renewals / re-issues do not overwhelm the KDC at a certain moment.
The feature is enabled automatically so that we can avoid triggering an LDAP query on every `AS_REQ` and `TGS_REQ`.

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
```

They are stored in the same policy object in LDAP.
