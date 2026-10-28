# FreeIPA and an external identity provider integration

FreeIPA provides an integrated identity management solution for POSIX-alike
environments. Its implementation has been based on a number of assumptions about
the usage and the representation of users and groups in a generalized POSIX
environment. Users and groups consumed by the applications running in POSIX
environment in several common ways:

 - application processes run under some user identity;
 - application processes create or access files attributed to specific users and
  groups;
 - a set of groups a user belongs to is fixed at the login time and does not
  change until that login session is completed;
 - an authentication flow of a user is directly tied with the login session that
  is instantiated as a result of authentication.

Consumption patterns described above equate presence of POSIX user and group IDs
with ability to run application processes under these identities. Interfacing
with the applications was typically done inside shell sessions initiated by the
users represented by the POSIX identities. With the move to web- and
mobile-oriented user interfaces, the POSIX user consumption patterns have become
less prominent. Applications consumed through interfaces that aren't expressed
through POSIX environments as in the past. POSIX identities, instead, relegated
to be a support mechanism for running isolated applications. This is especially
visible in Android application model or containerized environments.

Application-level identities are not necessarily the same as the system level
users anymore.

Usage shift does not, however, dictate an exclusion between the two models in
enterprise environments. The same users need to access both operating
system-level applications and be able to authenticate as application-level
identities. This is typically achieved by forming a single sign-on environment
where a user would be authenticated directly once and then the fact of
authentication is consumed by other services for a certain amount of time,
regardless of how the applications that represent these services are operating.

In this document discussion of 'application-level identities' really means
resource owner identities visible through OAuth 2.0 Authorization Framework.
This level of abstraction allows discussion of authentication and access to
resources regardless of internal details of a specific application.

There are two major use cases to be considered:
- FreeIPA serves as a backend to provide identities to an identity provider
  (IdP) to authenticate and authorize access to OAuth 2.0 clients. This IdP
  would be called 'an integrated IdP' to FreeIPA. A subset of user properties
  would be stored in IdP itself, another part retained in FreeIPA.

- FreeIPA communicates with an external IdP to perform identity verification and
  ask for an access grant to itself. Authentication and authorization of the
  identity is delegated to the external IdP and the user information in FreeIPA
  is used as an anchor to map external IdP identity to a system-level user
  identity.

The scope of this document is to address the second use case.

## Use of an external IdP to verify external identities for FreeIPA

OAuth 2.0 authorization framework concerns access control to resource owner
identities from OAuth clients. OAuth 2.0 authorization server arbitrates the
access by the OAuth clients. It also authenticates the resource owner identity
when OAuth client redirects a user (often a web browser) to the Authorization
Server to request the access grant.

In this document we would not look into details how OAuth 2.0 Authorization
Server would authenticate the resource owner identity. We assume this part is
implemented by the IdP.

In POSIX-like system environment access to resources often combines both
authentication and authorization steps. Two most common examples would be access
over a secure shell protocol variant and local system privilege escalation with
PAM interface. SSH protocol implementation often combines these two, allowing to
either authenticate with native SSH methods, with SSH key-pairs, GSSAPI
authentication, or delegate authentication to PAM (`keyboard-interactive`
method). Access control is then can be offloaded to PAM as well.

Locally, granting access to other resources often involves PAM stack processing
as well. `sudo` performs PAM authentication and authorization prior to applying
own access rules, for example.

FreeIPA already implements authorization part through PAM stack with the help of
SSSD suite. `pam_sss` PAM module allows using HBAC rules to grant access which
otherwise is denied. It also implements authentication pass-through mechanism,
allowing SSSD to handle a variety of authentication methods: LDAP binds,
Kerberos, etc.

When SSSD on FreeIPA-enrolled client needs to authenticate a user, it performs
mutual authentication with FreeIPA KDC. Mutual authentication relies on the fact
that each FreeIPA client is registered with the KDC in FreeIPA domain. In order
to request an access grant to a resource owner identity with an OAuth 2.0
authorization flow to FreeIPA-enrolled clients, this particular client has to be
registered as an OAuth client against an IdP that knows about the user. This is
impractical for FreeIPA deployments. What happens in many OAuth2 environments is
that instead of registering every single application system to the user's IdP, a
single client identity representing the whole 'application environment' is
registered. Once a user did log in into an application environment, an
application environment-specific access token is issued and used by the
application backend to access other resources in its own domain. In a sense,
this is similar to Kerberos protocol authentication process to obtain a ticket
granting ticket (TGT) and later request individual service tickets based on a
TGT.

To reduce authorization complexity we can view the whole FreeIPA deployment as a
single OAuth 2.0 client registered with an integrated IdP. The integrated IdP
would then handle authentication of the user identity and authorize access to
it. If that process would require, in turn, access to a federated identity
provider, the latter would not need to be known to FreeIPA OAuth 2.0 client.

Use of a single OAuth 2.0 client identity still presents an issue with multiple
FreeIPA-enrolled clients because they cannot easily share the client identity
while retaining a certain level of security.

Instead, in this design we consider IPA replicas to share OAuth 2.0 client
credentials in a way similar to how they do already share Kerberos realm master
keys: each IPA replica would be able to operate on its own using the same OAuth
2.0 client identity which is stored in a replicated IPA LDAP tree.

### OAuth 2.0 Device Authorization Grant

OAuth 2.0 Device Authorization Grant is defined in [RFC
8628](https://www.rfc-editor.org/rfc/rfc8628) and allows devices that either
lack a browser or input constrained to obtain user authorization to access
protected resources. Instead of performing the authorization flow right at the
device where OAuth authorization grant is requested, a user would perform it at
a separate device that has required rich browsing or input capabilities.

Following figure demonstrates a generic device authorization flow:

.. uml::

  participant "End User at Browser"
  participant "Device Client"
  participant "Authorization Server"
  "Device Client" -> "Authorization Server": (A) Client Identifier
  "Authorization Server" -> "Device Client": (B) Device Code, User Code & Verification URI
  "Device Client" -> "End User at Browser": (C) User Code & Verification URI
  "End User at Browser" <-> "Authorization Server": (D) End user reviews authorization request
  "Device Client" -> "Authorization Server": (E) Polling with Device Code and Client Identifier
  "Authorization Server" -> "Device Client": (F) Access Token (& Optional Refresh Token)

With the help of OAuth 2.0 Device Authorization Grant, OAuth authentication
process can be integrated into Kerberos authentication protocol and would allow
to not depend on OAuth2 support in all 'traditional' applications running in
FreeIPA deployment.

Since OAuth 2.0 Device Authorization Grant is not universally supported, a
federated access can be used to organize access for users who are authenticated
against an IdP without OAuth 2.0 Device Authorization Grant support. In such
case the IdP where FreeIPA OAuth 2.0 client is registered would be called "an
integrated IdP."

The use of an integrated IdP instance allows requiring support for OAuth 2.0
Device Authorization Grant flow. Since integrated IdP would have the required
capability, it is not necessary that the same capability would be supported by
all external IdPs. It also does not require registration of the individual IPA
OAuth 2.0 clients to the external IdPs.

Setting up an integrated IdP with FreeIPA is beyond scope of this document.

### High-level authentication overview

External IdP integration with FreeIPA is designed with the following
assumptions. Identities for users authenticated through the external IdPs stored
in FreeIPA as user accounts. They have no passwords associated and instead are
forced to authenticate to external IdPs over Kerberos-based authentication flow.
The user accounts for externally-authenticated users to be created in advance;
this can be achieved manually or automatically. The way how they created is out
of scope for this document.

With the following preconditions:
 - FreeIPA is registered as an OAuth 2.0 client with an external IdP
 - user account is associated with the external IdP
 - user account entry contains mapping to some resource owner identity in the
   external IdP
 - user authentication type for this user includes possibility to authenticate
   against IdP

a general authentication workflow for a user registered in External IdP would
involve following steps:
 - the user performs a prompt-based authentication to the IPA-enrolled system
 - upon login, a prompt is shown that guides the user to use a separate device
   to login to a specified URI and verify a device code shown at a prompt
 - once logged into a specified URI, the user would be asked to confirm the
   login intent
 - An empty response is entered to the original prompt following the login and
   confirmation at a specified URI
 - A backend process behind the login would perform the validation of the
   response
 - Once the response is validated, a Kerberos ticket is issued for this login
   attempt
 - successful Kerberos authentication leads to an authorization step which is
   performed using standard IPA facilities (HBAC rules, group membership, etc)
 - if both authentication and authorization are successful, user is logged into
   the system

Upon successful login, the user with External IdP identity would have an initial
Kerberos ticket granting ticket in the login session's credentials cache. This
ticket is further can be used to perform required authentication to other
IPA-provided services during its validity time.

### OpenID Connect Client-initiated backchannel authentication

An alternative to OAuth 2.0 Device Authorization Grant Flow would be to use
CIBA, OpenID Connect Client-initiated backchannel authentication flow, as
defined in
https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html.

CIBA flow is not yet supported in Keycloak. For the initial implementation of
the OAuth 2.0 authorization in FreeIPA, we would skip implementation of CIBA flow.

### OAuth 2.0 access token exchange

Another method to authorize and verify resource owner identity is to exchange
already existing OAuth 2.0 access token obtained by a different OAuth 2.0
client. This is most useful if the latter client is capable to initiate OAuth
2.0 authorization flow using a web browser.

For the initial implementation of the OAuth 2.0 authorization in FreeIPA, we
would skip this method.

### Authentication flow for OAuth2 proxying over Kerberos protocol

MIT Kerberos implements a mechanism for one-time password (OTP)
pre-authentication, as described in [RFC
6560](https://tools.ietf.org/html/rfc6560). The implementation in MIT Kerberos
allows a KDC to ask an external RADIUS server for the authentication decision
for a specific Kerberos principal. MIT Kerberos client, upon receiving a
pre-authentication mechanism response from the KDC, interacts with a user by
asking individual questions for OTP factors and further communicating back with
KDC.

FreeIPA implements a shim RADIUS proxy, called `ipa-otpd`, which listens on a
UNIX domain socket configured by default for KDC. If OTP pre-authentication
method is allowed for the requested Kerberos principal, KDC queries a RADIUS
server.

`ipa-otpd` implements two authentication flows:
- TOTP/HOTP token authentication, performed against FreeIPA LDAP server as an
  LDAP BIND operation;
- proxying RADIUS request to a remote RADIUS server

In either flow, `ipa-otpd` responds to a KDC request with a RADIUS packet
constructed out of the result of authentication. KDC then performs the remaining
communication as defined in the RFC 6560.

This approach can be used to implement other authentication flows that can fit
into a RADIUS exchange with `Accept-Request` and `Accept-Response` messages. An
example of this approach is an Azure AD multi-factor authentication (MFA)
extension to Microsoft's RADIUS server, NPS. The detailed flow is described
[Azure AD Multi-factor authentication how-to
guide](https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension).

Together with MIT Kerberos developers during a prototype investigation it was
decided to not extend existing OTP pre-authentication mechanism to add support
for external IdPs support but rather implement a separate Kerberos
pre-authentication mechanism based on similar ideas.

Original design for `idp` pre-authentication mechanism used RADIUS attribute
`State` to pass through the state of OAuth 2.0 flow. In RADIUS packets, size of
RADIUS attributes is limited up to 254 bytes. For many IdPs, the state can be
larger than 253 bytes. MIT Kerberos `krad` library supports concatenating
multiple appearances of the same attribute in the packet when retrieving the
value. `State` attribute semantics are defined in [RFC
2865](https://tools.ietf.org/html/rfc2865), where  `State` attribute can only be
present at most once. Therefore, was decided to utilize `Proxy-State` attribute
instead. `Proxy-State` allows multiple appearances in a single RADIUS packet.

Additionally, a bug was found in `krad` library implementation which prevented
to use RADIUS attribute values larger than 127 bytes. As of now, the fix for MIT
Kerberos is expected to be released with MIT Kerberos 1.20. Those fixes include
commits from upstream pull requests
[krb5#1229](https://github.com/krb5/krb5/pull/1229) and
[krb5#1230](https://github.com/krb5/krb5/pull/1230). They were backported to
RHEL 8.7, RHEL 9.1, and Fedora 34-37 releases ahead of MIT Kerberos 1.20
release.

Finally, as with `otp` pre-authentication mechanism, use of `idp` method
requires a FAST channel. Any valid Kerberos ticket can be used to form the FAST
channel. SSSD would automatically use host principal's keytab to generate one.
Anonymous PKINIT can also be used. The following sequence of `kinit` commands
can be used to prepare for use of `idp` pre-authentication mechanism:

```
kinit -n -c $TMPDIR/anonymous.ccache
kinit -T $TMPDIR/anonymous.ccache idpuser
```

The new pre-authentication mechanism was released in [SSSD 2.7.0
release](https://sssd.io/release-notes/sssd-2.7.0.html).

The `idp` pre-authentication mechanism flow can be described with the following
sequence diagram:

.. uml::
   :scale: 50%

   participant Operator
   participant "Kerberos client"
   box "FreeIPA server" #LightBlue
       participant "Kerberos KDC"
       participant "ipa-otpd"
       participant "oidc_child"
   end box
   box "External IdP" #LightYellow
   participant "Authorization Server"
   participant "Device code portal"
   end box

   Operator -> "Kerberos client": kinit -Tsome-ccache idp-user
   "Kerberos client" -> "Kerberos KDC" : AP-REQ
   "Kerberos KDC" -> "ipa-otpd": Access-Request
   "ipa-otpd" -> "oidc_child": Provide Device auth state
   "oidc_child" -> "Authorization Server": Initiate OAuth 2.0 Device authorization grant flow
   "Authorization Server" -> "oidc_child": device_code: ..., user_code: XXXXX, verification_uri: ....
   "oidc_child" -> "ipa-otpd": Device auth state: device_code: ...., user_code: XXXXX, verification_uri: ....
   "ipa-otpd" -> "Kerberos KDC": Access-Challenge with idp state
   "Kerberos KDC" -> "Kerberos client": idp state returned
   "Kerberos client" -> Operator: Please visit https://... and enter device code XXXXX
   Operator -> "Device code portal": visit https://... in browser and authorize access
   "Device code portal" -> Operator: Now you can close this window and continue
   "Operator" -> "Kerberos client": <ENTER>
   "Kerberos client" -> "Kerberos KDC": idp state returned
   "Kerberos KDC" -> "ipa-otpd": Access-Request with idp state as Proxy-State attribute
   "ipa-otpd" -> "oidc_child": Request access token with idp state provided
   "oidc_child" -> "Authorization Server": request access token
   "Authorization Server" -> "oidc_child": access token YYYY given
   "oidc_child" -> "Authorization Server": request userinfo using access token YYYY
   "Authorization Server" -> "oidc_child": userinfo details
   "oidc_child" -> "ipa-otpd": user information
   "ipa-otpd" -> "Kerberos KDC": Access-Response or Access-Reject
   "Kerberos KDC" -> "Kerberos client": AP-REP with a ticket or an error
   "Kerberos client" -> Operator: kinit: success or error message

- Kerberos client advertises 'idp' pre-authentication mechanism in the initial
  request to KDC
- KDC will look up Kerberos principal to initiate processing of AP-REQ request
- IPA KDB driver is expected to set JSON metadata named `idp` for the Kerberos
  principal which is allowed to use IdP method
- KDC side of the 'idp' pre-authentication method will notice `idp` metadata and
  will request default RADIUS end-point to authenticate the Kerberos principal.
  Default RADIUS end-point on FreeIPA KDC points to `ipa-otpd` daemon over UNIX
  domain socket, activated with the help of systemd.
- Upon receiving RADIUS request for Kerberos principal authentication,
  `ipa-otpd` will discover that the user entry is associated with a particular
  IdP.
- `ipa-otpd` will collect details for the OAuth 2.0 client associated with the
  IdP and will launch a helper `oidc_child`, provided by SSSD, to communicate
  with the IdP
- `oidc_child` will perform a request to initiate OAuth 2.0 Device
  Authorization Grant flow against the IdP
- Device authorization end-point of the IdP will return an initial information
  about the transaction state
- `oidc_child` will relay this information to `ipa-otpd`
- `ipa-otpd` will re-pack this information in a `Access-Challenge` RADIUS packet
  with a number of `Proxy-State` attributes representing the transaction state
  and return it to the KDC.
- KDC side of the pre-authentication method will re-pack the transaction state
  into a JSON metadata to send it as a part of the KDC response to the Kerberos
  client
- Kerberos client will receive a KDC response and will allow pre-authentication
  methods to handle it one by one. `idp` method will be triggered because the
  response contains `idp` method response.
- `idp` pre-authentication method will display the message to instruct a user to
  visit an IdP-specific URL and enter provided device code. It then waits for
  the user to press `<ENTER>` to continue.
- Once user completed authentication and authorization flow as defined by the
  IdP, `<ENTER>` is pressed to allow Kerberos client to complete the TGT
  acquisition.
- `idp` pre-authentication method sends back the same metadata it received from
  the KDC side.
- Upon receiving the transaction state metadata, KDC side of the `idp`
  pre-authentication method will perform another request to the default RADIUS
  end-point, sending `Proxy-State` attribute with the state as a part of the
  RADIUS package
- Upon receiving the transaction state, `ipa-otpd` will launch `oidc_child`
  again to verify completion of the authorization step.
- `oidc_child` will perform verification of the authorization step and would
  obtain an OAuth 2.0 token to access `userinfo` OAuth 2.0 end-point
- `oidc_child` will retrieve information about the resource owner identity from
  the `userinfo` OAuth 2.0 end-point using scopes defined for this IdP.
- The user information is then returned to `ipa-otpd` daemon which performs
  comparison of the identity subject against the one recorded in the user entry
  in LDAP.
- If the comparison is successful, `Access-Response` RADIUS packet is returned,
  allowing KDC to issue Kerberos ticket.

## Authentication to IPA web UI

At this point, no direct login to Web UI would be available for users
authenticated against an external IdP. They can obtain Kerberos ticket first and
then login to Web UI.

In the future, we may implement OAuth 2.0 native flow to redirect to an IdP-provided
Authorization Server and rely on OAuth 2.0 authorization flow with PKCE. There
are several unsolved issues at the moment that prevent this to be done.

### Stable callback URI

OAuth 2.0 authorization flows rely on HTTP redirects handled by the resource
owner's browser to complete the authorization. Once Authorization Server has
done its job, it would redirect the resource owner's browser to the web resource
define as a callback URI in the OAuth 2.0 client definition. This callback is
not expected to change dynamically and is set as a part of the OAuth 2.0 client
registration.

The IPA servers provide Web UI access on their own individual URIs. There is
already a precedent to provide a stable URI for ACME operations with
`ipa-ca.$DOMAIN` host. Each IPA server's HTTP certificate includes
`ipa-ca.$DOMAIN` SAN dNSName. A similar extension could be added to provide a
stable `ipa-idp.$DOMAIN` stable URI.

### OAuth 2.0 proxy app

Adding a stable `ipa-idp.$DOMAIN` stable URI would need to be complemented by a
web application that would respond at that URI. This application would
essentially need to implement a specialized OAuth 2.0 proxy flow to allow a web
application in IPA domain to initiate OAuth 2.0-based login on behalf of that
application.

Such OAuth 2.0 proxy would be hosted on IPA servers and would have access to the
definition of IdPs associated with the specific users. A user, effectively,
would be redirected to the OAuth 2.0 proxy, then redirected to their IdP for the
authorization, then logged in into the OAuth 2.0 proxy and, finally, redirected
back to the original web app.

An OAuth 2.0 proxy app would need to mutually authenticate the original web app.
If it were to use OAuth 2.0 token issued by IPA deployment itself, it would, in
fact, be an integrated IdP. It is a tempting option but it would require
additional infrastructure overhead on IPA side.

On the other hand, each host enrolled into IPA domain already has means to
authenticate any other Kerberos service with the help of Kerberos
infrastructure. Such OAuth 2.0 proxy might be able to accept HTTPS connections
authenticated by the Kerberos ticket of the requester service. Once OAuth 2.0
authorization of the resource owner (user) is done through the OAuth 2.0 proxy
app, following outcomes are possible:

- OAuth 2.0 proxy app returns a state that can describe a user from the external
  IdP in IPA Kerberos point of view and the requester service then uses S4U2Self
  to acquire a Kerberos ticket to itself on the resource owner's identity
  behalf;

- OAuth 2.0 proxy app returns a limited access token that the requester service
  then passes into `idp` pre-authentication method through AP-REQ to turn it
  into a normal Kerberos ticket of the resource owner's identity.

Initial implementation does not include support for this approach.

## Individual tasks

### Manage IdP references in IPA

Implement a method to manage IdP references in IPA. It can be done similarly to
how RADIUS proxy links are managed but with more complex data structures
specific for OAuth2.

Topic commands:
```
  idp-add   Add new external IdP server.
  idp-del   Delete an external IdP server.
  idp-find  Search for external IdP servers.
  idp-mod   Modify an external IdP server.
  idp-show  Display information about an external IdP server.
```
For more details about IPA API and Web UI implementation please refer to
[idp-api].

### Extend supported user authentication methods in IPA

In order to recognize new authentication method to perform OAuth 2.0 Device
Authorization Grant flow, IPA needs to be extended to support the new method:

- in IPA API, to allow managing the method in `ipa user-mod --user-auth-type`
  and similar commands;
- in IPA KDB driver, to recognize that the user has IdP authentication method
  and trigger OTP pre-authentication response;
- in IPA KDB driver, to associate a new authentication indicator with the IdP
  authentication method.

Both the authentication method and the authentication indicator are called
`idp`. This would allow to distinguish it from the regular RADIUS or OTP
authentication indicators.

### Extend `ipa-otpd` daemon to recognize IdP references

`ipa-otpd` supports two methods at the moment:
 - native IPA OTP authentication
 - RADIUS proxy authentication

`ipa-otpd` itself does not implement any OAuth 2.0 calls. Instead, configuration
of the OAuth 2.0 client and IdP reference passed to the `oidc_child` process
provided by SSSD in `sssd-idp` package. `oidc_child` uses `curl` and `cjose`
libraries to implement OAuth 2.0 communication.

`ipa-otpd` retrieves IdP references associated with the user being authenticated
and calls out to the `oidc_child` process to verify the user identity against an
associated IdP.

[idp-api]: idp-api.html

## Security

* communication between Kerberos client and KDC happens over FAST channel
* communication between KDC and FreeIPA (`ipa-otpd`) happens over root-owned
  UNIX domain socket
* communication between `oidc_child` and IdP happens over `https`
* no authentication tokens are exchanged between client, KDC and FreeIPA
* IdP server URLs can only be set by administrator
* IdP server URLs are not auto discovered, they need to be added manually
* user authenticates to the external identity provider using the method required
  by the provider, FreeIPA does not have any control over the selected method

### Recommendations

* administrators must thoroughly check all URLs they add when creating the IdP
  server
* users must check that the presented device authorization URL is correct and
  that the authentication happens over secure channel (usually `https`) with
  valid certificate
