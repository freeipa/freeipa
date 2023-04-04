# Constrained delegation for Kerberos services

## Overview

The purpose of this document is to describe an integration of two constrained
delegation mechanisms FreeIPA provides for Kerberos services:

- general constrained delegation, available since FreeIPA 3.0.0;
- resource-based constrained delegation, introduced with this design document.

Both constrained delegation mechanisms apply when Kerberos services implement
S4U2Proxy extensions as described in
[MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
specification. MIT Kerberos project has its own page that describes
[Services for User](http://k5wiki.kerberos.org/wiki/Projects/Services4User) integration.
FreeIPA work relies on the MIT Kerberos facilities to support S4U extensions,
including S4U2Proxy.

A general constrained delegation mechanism described here for the sake of
completeness. The description is based on the original design document published
originally at [FreeIPA wiki page](https://www.freeipa.org/page/V4/Service_Constraint_Delegation).

A general overview of a constrained delegation from Microsoft point of view can
be found in [this document](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview).

## Introduction

Services for User extensions were introduced as a part of Kerberos
implementation in Microsoft's Active Directory. They aim to achieve two
specific goals:

- allow Kerberos services to accept requests authenticated via a different
  protocol. A Kerberos service can ask the Kerberos KDC to issue a ticket to
  itself on behalf of a user, thus performing a protocol transition. The
  resulting service ticket is issued to the service itself, hence S4U2Self
  extension name.

- allow a Kerberos service to request a service ticket to a different
  Kerberos service on behalf of the original user, hence S4U2Proxy extension
  name. The original service ticket must be forwardable. The resulting ticket
  can be presented in the communication to that different Kerberos service and
  will show both the original user principal and a Kerberos service operating on
  its behalf.

The S4U2Proxy feature eliminates the need for the user to delegate their ticket
granting ticket (TGT). FreeIPA uses the S4U2Proxy feature to allow the web
server framework to obtain an LDAP service ticket on the user's behalf.
Similarly, it is also used by the FreeIPA's trust to Active Directory feature
to allow the web server framework to obtain an SMB service ticket on the user's
behalf when configuring Samba and a trust to Active Directory through Samba.

Kerberos KDC has control over the issuance of service tickets for both S4U2Self
and S4U2Proxy extensions. The usage of S4U2Proxy is called "constrained
delegation"; the two mechanisms that represent constrained delegation usage
have different rules associated with them.

The access control for general constrained delegation is controlled by several
LDAP entries, rules and targets, contained in `cn=s4u2proxy,cn=etc,$SUFFIX`.

Rule LDAP entry defines two elements:

- Kerberos principals to be impersonated (defaults to every principal),

- Kerberos services that can impersonate them.

Target LDAP entry defines the list of Kerberos services to which the
impersonator Kerberos services can delegate credentials.

These rules are controlled by the administrators of FreeIPA and cannot be
controlled by the services themselves.

The access control for the resource-based constrained delegation rules is
placed within the LDAP entries of the target Kerberos services. Kerberos
service which supports resource-based constrained delegation will only be able
to request a service ticket to a Kerberos service that explicitly allows this
service to ask for a constrained delegation for itself. The rules are
controlled by the services' administrators (by default, the host service
controls services associated with the host). This reduces an administrative
overhead and delegates decision-making to the application administrators.

## Use cases

The table below summarizes three types of the Kerberos delegation approaches.

A 'forest' concept in the table is an Active Directory term. FreeIPA does not
have a mechanism to place multiple AD-like domains into the same forest. All
systems which deployed to the same FreeIPA deployment are part of the same
FreeIPA domain and the same FreeIPA forest. In terms of Active Directory,
FreeIPA forest represents a single Active Directory domain, the root domain of
the forest. In Kerberos terms all these domains represent separate Kerberos
realms, within or across multiple forests.

Impersonator account in the table corresponds to the application which is
using the delegated credential. In case of a constrained delegation, it is an
application performing S4U2Proxy request.

Resource-based constrained delegation is only supported when FreeIPA is
compiled against MIT Kerberos 1.19 or later.

|                                                       | TGT forwarding, unconstrained (by policy)         | General constrained delegation                 | Resource-based constrained delegation        |
|---|---|---|---|
|Delegation attributes set on and managed by admin of   | Impersonator account (to anyone)                  | Impersonator account (to a list of resources)  | Resource account (to a list of impersonators)|
|Delegation within a domain, client from the local forest  | yes | yes  | yes |
|Delegation within a domain, client from another forest    | yes [1] | yes  | yes |
|Delegation across a domain trust within the same forest, client from the local forest | yes | no | yes |
|Delegation across a domain trust within the same forest, client from another forest | yes [1] | no | yes |
|Delegation across forest trust, client from the forest of the impersonator | yes | no | yes |
|Delegation across forest trust, client from the forest of the resource | yes [1] | no | no [2] |

- [1] With Windows updates in 2019, tgt-forwarding when the client and
  impersonator are in different forests no longer works unless explicitly
  allowed. Microsoft has [issued a guidance](https://support.microsoft.com/en-us/help/4490425/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server)
  that details the behavior.  Additionally, there is a Microsoft Word document
  describing [a KDC behavior](https://aka.ms/kcdpaper).

- [2] Refer to the KDC paper from above for the description of "round-trip
  authentication across trusts".

### General constrained delegation

General constrained delegation is often utilized in a multi-service environment
where a frontend service acts on behalf of a user against backend services.

For example, the server side implementation of IPA API framework uses the
delegation of a ticket presented to the web service to act on behalf of this
user when talking to LDAP service.

### Use cases for resource-based constrained delegation

Typical use case is to allow users from the trusted Active Directory forest to
access their network shares while logging into FreeIPA client systems. NFS
server would be enrolled either into Active Directory or the FreeIPA
deployment, FreeIPA client system would be enrolled into FreeIPA deployment.
On FreeIPA client, a user's home directory would be configured to automount NFS
share for the user and use GSSAPI authentication with the help of GSSProxy.
GSSProxy can be configured to use both S4U2Self and S4U2Proxy. This use case is
described in detail in [GSSProxy documentation](https://github.com/gssapi/gssproxy/blob/main/docs/NFS.md#user-impersonation-via-constrained-delegation).

When NFS server is located in the same Kerberos realm as the FreeIPA client
system, this use case can be implemented with general constrained delegation.

When the target service (NFS server) and the proxy service (NFS client) are in
different realms, MS-SFU specification prevents issuance of a service ticket
using S4U2Proxy extension unless there is a resource-based constrained
delegation rule defined for the target service, as outlined in the [MS-SFU 3.2.5.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/dd1b47f9-580c-4c4e-8f34-4485b9728331).

As a result, in order to allow delegation of user credentials across the forest
boundary, resource-based constrained delegation must be supported both by the
impersonating (proxy) service and by the KDC of the user forest.

## Design

MS-SFU specification defines that for full support of all S4U functionality an
account database needs to support four elements of information for each
principal, as outlined in [MS-SFU 3.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/0b4d13c4-d459-4598-8f08-1584ca1e24c9).

FreeIPA account database is not compatible with Active Directory on LDAP level,
thus implementation is slightly different.

### Unconstrained delegation

IPA API provides a way to record unconstrained delegation permission in both
host and service command families. The following commands have option
`--ok-as-delegate=BOOL`:

- `ipa host-add` and `ipa service-add`
- `ipa host-mod` and `ipa service-mod`

### S4U2Self design

Kerberos service is allowed to request a service ticket to itself on behalf of
any user. However, to make it usable for S4U2Proxy (constrained delegation),
the service ticket must be forwardable. In such case the Kerberos service would
be able to impersonate user and requires an explicit administrative permission.

IPA API provides a way to record this permission in both host and service
command families. The following commands have option
`--ok-to-auth-as-delegate=BOOL`:

- `ipa host-add` and `ipa service-add`
- `ipa host-mod` and `ipa service-mod`

This flag is equivalent to MS-SFU's `TrustedToAuthenticationForDelegation`
boolean setting.

### General constrained delegation design

General constrained delegation uses two objects: a rule and a target.
All entries are stored in the same LDAP container and the only real
distinguishing feature between a rule and a target is the objectClass
`ipaKrb5DelegationACL`:

- a rule will have these objectClasses: `top`, `groupOfPrincipals`,
  `ipaKrb5DelegationACL`.

- a target will have these objectClasses: `top`, `groupOfPrincipals`.

Kerberos KDC database driver (KDB) uses a special filter to exclude
`ipaKrb5DelegationACL` when searching for the target.

Both a rule and a target specify affected principals with `memberPrincipal`
attribute.

This combination of rules and targets allows FreeIPA to implement an equivalent
of MS-SFU's `ServicesAllowedToSendForwardedTicketsTo` information.

Management of the general constrained delegation rules and targets is done with
`ipa servicedelegation` commands.

|Command                               |Description                                                 |
|--------------------------------------|------------------------------------------------------------|
|servicedelegationrule-add             |Create a new service delegation rule.                       |
|servicedelegationrule-add-member      |Add member to a named service delegation rule.              |
|servicedelegationrule-add-target      |Add target to a named service delegation rule.              |
|servicedelegationrule-del             |Delete service delegation.                                  |
|servicedelegationrule-find            |Search for service delegations rule.                        |
|servicedelegationrule-remove-member   |Remove member from a named service delegation rule.         |
|servicedelegationrule-remove-target   |Remove target from a named service delegation rule.         |
|servicedelegationrule-show            |Display information about a named service delegation rule.  |
|servicedelegationtarget-add           |Create a new service delegation target.                     |
|servicedelegationtarget-add-member    |Add member to a named service delegation target.            |
|servicedelegationtarget-del           |Delete service delegation target.                           |
|servicedelegationtarget-find          |Search for service delegation target.                       |
|servicedelegationtarget-remove-member |Remove member from a named service delegation target.       |
|servicedelegationtarget-show          |Display information about a named service delegation target.|

### Resource-based constrained delegation design

Resource-based constrained delegation stores information in the target service
LDAP entry. This information is represented with `memberPrincipal` attribute
and is allowed with objectClass `resourceDelegation`. If a Kerberos principal
is mentioned in the `memberPrincipal` attribute of the LDAP entry and
objectClass `resourceDelegation` is present in the same entry, KDB driver will
use information from the `memberPrincipal` attribute to check whether a service
asking for S4U2Proxy extension is allowed to send a forwarded user ticket to
this service.

This approach allows implementing MS-SFU's `ServicesAllowedToReceiveForwardedTicketsFrom`
information.

Management of the resource-based constrained delegation is integrated into `ipa
host` and `ipa service` commands.

|Command                         |Description                                                 |
|--------------------------------|------------------------------------------------------------|
|service-add-delegation          |Add new resource delegation to a service                    |
|service-allow-add-delegation    |Allow users, groups, hosts or host groups to handle a resource delegation of this service.|
|service-disallow-add-delegation |Disallow users, groups, hosts or host groups to handle a resource delegation of this service.|
|service-remove-delegation       |Remove resource delegation from a service|
|host-add-delegation             |Add new resource delegation to a host|
|host-allow-add-delegation       |Allow users, groups, hosts or host groups to handle a resource delegation of this host.|
|host-disallow-add-delegation    |Disallow users, groups, hosts or host groups to handle a resource delegation of this host.|
|host-remove-delegation          |Remove resource delegation from a host|

The `*-allow-add-delegation` and `*-disallow-add-delegation` commands aim to
provide a way to extend list of actors allowed defining delegation access
control. By default, only host and service owners (the host and service
themselves, as well as those objects defined by `managedBy` attribute) allowed
to control the delegation. Additional users, groups, hosts or host groups can
be allowed to set the delegation ACL. The purpose of these commands is to allow
a flexible management without giving a control over the whole host or service
entry.

### Implementation

#### IPA API commands

In both general constrained delegation and resource-based constrained
delegation rules, targets, and delegation permission details are expressed with
`memberPrincipal` attribute. Since IPA's standard `LDAPAddMember` and
`LDAPRemoveMember` classes operate on DNs for the members, they need to be
overridden to represent Kerberos principals. The principal might be not present
in the IPA realm and thus cannot be represented as an LDAP object to which DN
could be constructed.

##### Management of a general constrained delegation

In case of general constrained delegation a special handling is added to
`LDAPAddMember` and `LDAPRemoveMember` classes to handle `memberPrincipal`.
The add/remove methods assume, and require via asserts, that all members be a
DN. `get_member_dns()` needs to ignore any `memberPrincipal` values and return
only the DN-based values when adding targets to rules to let the standard
mechanics of `LDAP*Member` do their work.

In order to handle the `memberPrincipal` values a `post_callback()` is required.
This also means that there be at worst two writes per membership update.
Given that this feature is not expected to be frequently used then speed and
efficiency are not a factor.

Similarly, we enforce that only a target is a member of a rule, and not
another rule. That would be an undefined relationship. To do this each member
needs to be retrieved and evaluated before adding as a member.

A referential integrity rule is needed for `ipaallowedtarget`.

A referential integrity rule is needed, but is not possible, for
`memberPrincipal`. It is not possible because it is not a DN. This adds the
potential to have dangling pointers. In practice, this has not been a problem
for S4U2Proxy usage as administrators rarely add the constrained delegation
rules.

The ACL system also provides a means of limiting which user's a ticket may be
obtained for using the `ipaAllowToImpersonate` attribute. This is not
implemented.

In order to maintain basic functionality, FreeIPA must have entries for
S4U2Proxy operations between IPA API framework, LDAP service, and CIFS service
on IPA server. These entries are `ipa-http-delegation` rule and
`ipa-ldap-delegation-targets` and `ipa-cifs-delegation-targets` targets.

To grant this access, two LDAP entries are required. The first is a
rule which defines the ACL:

```
 dn: cn=ipa-http-delegation,...
 objectClass: ipaKrb5DelegationACL
 objectClass: groupOfPrincipals
 cn: ipa-http-delegation
 memberPrincipal: HTTP/ipaserver.example.com@EXAMPLE.COM
 ipaAllowedTarget: cn=ipa-ldap-delegation-targets,...
```

The second LDAP entry is a target of this rule which defines which principals
may be obtained:

```
 dn: cn=ipa-ldap-delegation-targets,...
 objectClass: groupOfPrincipals
 cn: ipa-ldap-delegation-targets
 memberPrincipal: ldap/ipaserver.example.com@EXAMPLE.COM
```

Both types of entries contain members in the form of `memberPrincipal`. In the
case of a rule these are the members that the rule applies to. In the case of a
target the members are the targets of the delegation. In this case the rule has
a member of `HTTP/ipaserver.example.com@EXAMPLE.COM` and a rule with a member
of `ldap/ipaserver.example.com@EXAMPLE.COM` which means that the HTTP principal
can obtain an LDAP service ticket on behalf of the bound user.

The same approach is used to allow the IPA API framework to obtain a service
ticket on behalf of a user to Samba when a trust to Active Directory is
established. In this case, instead of `ldap/ipaserver.example.com@EXAMPLE.COM`,
a target principal of `cifs/ipaserver.example.com@EXAMPLE.COM` is used.

These two rules are configured by default in the FreeIPA deployment.

##### Resource-based constrained delegation

Resource-based constrained delegation relies on a `memberPrincipal` attribute
in the target service's LDAP object. To manage this attribute, we extend
`LDAPAddAttribute` and `LDAPRemoveAttribute` classes. Both classes were added
after general constrained delegation was implemented and present a better
abstraction to handle member principals.

To control validity of the member principals, a method that checks realms
against a list of trusted domains is added. This allows to set up
resource-based constrained delegation for cross-forest services.

Access control for resource-based constrained delegation is performed in the
following way. A service can modify own delegation list and specify which
Kerberos principals are allowed to delegate to the service. Host where service
is located can manage the service as well.

Administrators can grant other users, groups, hosts, or services permissions to
handle resource-based constrained delegation of a host or a service.

#### Kerberos KDC implementation

KDB API provides two callbacks for the database drivers to implement access
control checks for constrained delegation.

General constrained delegation callback `check_allowed_to_delegate()` allows
checking whether a server is allowed to obtain tickets from client to a target
service. This is implemented by loading constrained delegation LDAP rules and
targets associated with the target service and the proxy server and checking
that they match.

Resource-based constrained delegation callback `allowed_to_delegate_from()`
allows checking whether a target service allows a server to delegate a ticket.
This is implemented in two parts:

- first, `memberPrincipal` attribute in the principal is loaded and added to TL
  data of the principal object in KDC under `KRB5_TL_CONSTRAINED_DELEGATION_ACL` type.

- second, the resource-based constrained delegation callback retrieves
  `KRB5_TL_CONSTRAINED_DELEGATION_ACL` TL data and validates that a server is
  present in the list of principals.

Since `KRB5_TL_CONSTRAINED_DELEGATION_ACL` TL data might be present in the
Kerberos principal KDC object, destructor for the Kerberos principal is
extended to free the associated memory.

Finally, KDB driver follows requirements for [MS-SFU 3.2.5.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/ad98268b-f75b-42c3-b09b-959282770642)
and adds SIDs `S-1-18-1` or `S-1-18-2` to the MS-PAC structure's `extraSids`
field depending on how identity was verified:

* for non-S4U2Self operation initial PAC structure population includes a SID
  `S-1-18-1`, as a `AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY`,

* for S4U operation, instead, a SID `S-1-18-2` is added, as a `SERVICE_ASSERTED_IDENTITY`.

### Test Plan

General constrained delegation is already used by the IPA management framework
and thus being tested with every IPA API call.

For resource-based constrained delegation cases defined in the use case summary
table. Since FreeIPA currently does not have support for IPA to IPA trust and
does not provide a working two-way trust with Active Directory, it is not
possible to test a scenario where RBCD is applied cross-realm by FreeIPA itself
but the proxy service is in a trusted realm. When IPA to IPA trust or proper
two-way trust to Active Directory would be implemented, this scenario could be
tested.

Thus, a primary RBCD scenario to test is an interoperability with another
RBCD-enabled realm (e.g. Active Directory) where IPA client is used to
initiate the S4U2Proxy operation against a resource (service) in a trusted
realm. In this case Kerberos library on the IPA client should set RBCD support
flag in the PAC structure and trigger S4U2Proxy request. A trusted realm's KDC
will do its check and allow or deny the access request.

#### Usage examples for RBCD

##### Setup RBCD for a service

Let's consider a case where a web frontend needs to connect to an internal
SMB server running on another IPA server on behalf of a user. This is similar
to a default setup in FreeIPA with general constrained delegation but on a
different host and using a different service.

* a host `web-service.example.test` would run a web server and use
`HTTP/web-service.example.test` service principal.

* a host `file.example.test` would be a Samba server running on IPA-enrolled
  client. Its SMB server uses `cifs/file.example.test` service principal.

In RBCD model, the control over who can delegate user resources to the service
would be defined at the service side, in this case at `cifs/file.example.test`.
An RBCD access control for `cifs/file.example.test` would need to mention
`HTTP/web-service.example.test` principal to allow the web server to delegate
user's credentials to the Samba server.

Example 1: Administrator can set RBCD ACL directly:
```
$ kinit admin
$ ipa service-add-delegation cifs/file.example.test HTTP/web-service.example.test
```

Example 2: Host `file.example.test` can use a host keytab to define RBCD ACL
directly because a host always manages the services running on it:
```
# kinit -k
# ipa service-add-delegation cifs/file.example.test HTTP/web-service.example.test
```

Example 3: Allow users from a group `storage-admins` to define RBCD ACLs to
`cifs/file.example.test`:
```
$ kinit admin
$ ipa service-allow-add-delegation cifs/file.example.test --groups=storage-admins
```

Then, a user `some-user` from `storage-admins` group can add a delegation ACL:
```
$ kinit some-user
$ ipa service-add-delegation cifs/file.example.test HTTP/web-service.example.test
```

Example 4: Remove permission to add RBCD ACLs for `cifs/file.example.test` from
members of the `storage-admins` group:
```
$ kinit admin
$ ipa service-disallow-add-delegation cifs/file.example.test --groups=storage-admins
```

Now a user `some-user` from `storage-admins` group cannot add a delegation ACL:
```
$ kinit some-user
$ ipa service-add-delegation cifs/file.example.test HTTP/web-service.example.test
.. ERROR ..
```

Example 5: Test RBCD access by service `HTTP/web-service.example.test` to
`cifs/file.example.test`. In this example we assume that an RBCD ACL created in
examples 1-3 exists, there is a keytab `/path/to/web-service.keytab` for
`HTTP/web-service.example.test`, and a `cifs/file.example.test` service was
created with `ipa-install-samba` tool which ensures a keytab was obtained for
Samba service as well. The presence of keytabs ensures corresponding Kerberos
services have all needed Kerberos keys so that service tickets can be created
by KDC.

In the example below we are delegating user `some-user` credentials to the
service `cifs/file.example.test`. First, we pretend our web service has
authenticated the user with some mechanism. Then we aquire a service ticket to
ourselves (`HTTP/web-service.example.test`) with the help of `kvno -U username`
command. Finally, we use `kvno -P` option to ask for S4U2Proxy operation and
specify for which services tickets will be asked using constrained delegation.

```
# kvno -U some-user -k /path/to/web-service.keytab \
       -P HTTP/web-service.example.test cifs/file.example.test
```
