# IPA and an external identity provider integration - idp objects

IPA needs to store and manage IdP references. As a new IPA object, IdP reference needs:
* creation of an LDAP object class and LDAP attribute types used to store IdP
information
* creation of a new IPA API managing the IdP references
* definition of access control lists protecting access to the IdP references
* upgrade and backward compatibility.

## LDAP Schema

### New attribute types

The external IdP reference object needs to contain the following information:
* name (string)
* authorization endpoint (URI mapped as a case-sensitive string),
* device authorization endpoint (URI mapped as a case-sensitive string), for instance https://oauth2.googleapis.com/device/code
* token endpoint (URI mapped as a case-sensitive string), for instance https://oauth2.googleapis.com/token
* userinfo endpoint (URI mapped as a case-sensitive string)
* JWKS endpoint (URI mapped as a case-sensitive string)
* OIDC URL (URI mapped as a case-sensitive string)
* `client_id` (case-sensitive string)
* `client_secret` (optional, may be an empty string, must be protected as a password)
* scope (case sensitive string)
* user subject attribute (case-sensitive string)

Additionally, an idp object needs to be referenced from a user object, thus a link attribute has to be defined. This translates into the following attribute type definitions:
```text
attributeTypes: (2.16.840.1.113730.3.8.23.15 NAME 'ipaIdpDevAuthEndpoint' DESC 'Identity Provider Device Authorization Endpoint' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.16 NAME 'ipaIdpAuthEndpoint' DESC 'Identity Provider Authorization Endpoint' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.17 NAME 'ipaIdpTokenEndpoint' DESC 'Identity Provider Token Endpoint' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.18 NAME 'ipaIdpClientId' DESC 'Identity Provider Client Identifier' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.19 NAME 'ipaIdpClientSecret' DESC 'Identity Provider Client Secret' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.20 NAME 'ipaIdpScope' DESC 'Identity Provider Scope' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.21 NAME 'ipaIdpConfigLink' DESC 'Corresponding Identity Provider Configuration link' SUP distinguishedName EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE X-ORIGIN 'IPA v4.9')
attributeTypes: (2.16.840.1.113730.3.8.23.22 NAME 'ipaIdpSub' DESC 'Identity Provider User Subject' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.23 NAME 'ipaIdpIssuerURL' DESC 'Identity Provider OIDC URL' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.24 NAME 'ipaIdpUserInfoEndpoint' DESC 'Identity Provider UserInfo Endpoint' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
attributeTypes: (2.16.840.1.113730.3.8.23.25 NAME 'ipaIdpKeysEndpoint' DESC 'Identity Provider JWKS Endpoint' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.9' )
```

### New objectclasses for idp

In addition to IdP configuration object, a special object class is added to be able to store IdP configuration link in a user object:

```text
objectClasses: (2.16.840.1.113730.3.8.24.6 NAME 'ipaIdP' SUP top STRUCTURAL DESC 'Identity Provider Configuration' MUST ( cn ) MAY ( ipaIdpDevAuthEndpoint $ ipaIdpAuthEndpoint $ ipaIdpTokenEndpoint $ ipaIdpUserInfoEndpoint $ ipaIdpKeysEndpoint $ ipaIdpClientId $ description $ ipaIdpClientSecret $ ipaIdpScope $ ipaIdpIssuerURL $ ipaIdpSub ) X-ORIGIN 'IPA v4.9' )
objectClasses: (2.16.840.1.113730.3.8.24.7 NAME 'ipaIdpUser' SUP top AUXILIARY DESC 'User from an external Identity Provider ' MAY ( ipaIdpConfigLink $ ipaIdpSub ) X-ORIGIN 'IPA v4.9' )
```

In the current implementation, a user can be connected to a single IdP
reference. This is similar to RADIUS proxy references already used in IPA. For
both RADIUS and IdP cases IPA needs to know a particular user identity within
the context of the referred resource (IdP or RADIUS server). Without associated
IdP user information authentication of the IPA user will not be triggered.

### LDAP indices

Indices need to be defined for all the attributes that can be used in
`ipa idp-find` command.

- The `cn` attribute is already indexed.
- The `ipaidpdevauthendpoint`, `ipaidpauthendpoint`, `idaidptokenendpoint`, and `idpidpscope` attributes
need indices (equality and substring indices).


## IdP reference API

### Command Line Interface
```
 idp-add   Add new external IdP server.
 idp-del   Delete an external IdP server.
 idp-find  Search for external IdP servers.
 idp-mod   Modify an external IdP server.
 idp-show  Display information about an external IdP server.
```

Following common options defined for the external IdP server object:

| Option                | Description                                                 |
|:--------------------- | :---------------------                                      |
| `--dev-auth-uri`=URI  | Device authorization endpoint                               |
| `--auth-uri`=URI      | General OAuth 2.0 authorization endpoint                    |
| `--token-uri`=URI     | Token endpoint                                              |
| `--userinfo-uri`=URI  | User information endpoint                                   |
| `--keys-uri`=URI      | JWKS endpoint                                               |
| `--issuer-url`=URI    | The Identity Provider OIDC URL                              |
| `--client-id`=STR     | The client identifier issued by the IdP during registration |
| `--secret`            | The client secret, asked interactively                      |
| `--scope`=STR         | OAuth 2.0 scopes of the access request                      |
| `--idp-user-id`=STR   | Attribute holding user identity in User info                |

`--scope` option expects space-separated list of OAuth 2.0 scopes. Since the
value includes space, it has to be enclosed in quotes:

```
ipa idp-mod foo --scope="openid email"
```

Not all common options are required at the same time in the context of different commands.

`ipa idp-add` command adds three more options:

| Option                | Description                                                 |
|:--------------------- | :---------------------                                      |
| `--provider`=STR      | One of [google, github, microsoft, okta, keycloak]          |
| `--org`=STR           | IdP-specific organization (tenant or realm) ID              |
| `--base-url`=URI      | IdP-specific base URL (e.g. `idp-host.$DOMAIN:$PORT/prefix`)|

In order to ease the creation of idp, IPA pre-populates a set of
templates for well-known IdPs so that the user does not need to provide the
individual endpoint details.

For instance, for `google` provider, adding a new IdP would look like:
```
ipa idp-add MyGoogleIdP --provider google \
    --client-id nZ8JDrV8Hklf3JumewRl2ke3ovPZn5Ho \
```

This call would be equivalent to the following:
```
ipa idp-add MyGoogleIdP \
    --dev-auth-uri https://oauth2.googleapis.com/device/code \
    --token-uri https://oauth2.googleapis.com/token \
    --client-id nZ8JDrV8Hklf3JumewRl2ke3ovPZn5Ho \
    --scope "profile email"
```

As a consequence, `--provider` option and URI-specific options `--auth-uri`,
`--dev-auth-uri`, `--keys-uri`, and `--token-uri` are mutually exclusive.

`ipa idp-add` command does not currently use `--issuer-url` option URL
to dynamically look up other URIs through a well-known OIDC endpoints. Some of
the IdPs do not provide well-known OIDC endpoints URL at all. This option can
be used in `ipa idp-mod` to set `ipaIdpIssuerURL` LDAP attribute. If this
attribute is set, it will be passed to SSSD's `oidc_child` helper during actual
authorization processing.

The `scope` is optional, and the `client_id` is mandatory.

The `client_secret` must not be displayed by `ipa idp-find` or `ipa idp-show`
commands unless permission 'System: Read External IdP client secret' is
assigned to the authenticated user running the command.

### Pre-populated IdP templates

List of pre-populated IdP types is currently limited by the following provider
"names":

* google
* github
* microsoft
* okta
* keycloak

Some IdP providers support parametrized URIs which include organization or a
realm name, or specific base URL, or both.

One notable omission in the pre-populated IdP types above is Gitlab.

FreeIPA only supports IdPs that implement OAuth 2.0 Device authorization
grant flow as defined by the [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628).
If required IdP cannot be made to support Device authorization grant flow, it
is recommended to use OAuth 2.0 federation within an IdP that supports this
method. Gitlab does not support OAuth 2.0 Device authorization grant flow and
thus is not supported directly.

SSSD 2.7.0 implements Kerberos pre-authentication method `idp` (registered as a
pre-authentication type 152, PA-REDHAT-IDP-OAUTH2). It relies on IPA KDB driver
to provide a metadata in the Kerberos principal entry to specify use of IdP.
KDC side of the pre-authentication method 'idp' then communicates with IPA
`ipa-otpd` daemon which reads external IdP reference object associated with the
user and spawns `oidc_child` helper from SSSD to complete authorization.

`oidc_child` helper performs OAuth 2.0 device authorization grant flow. Since
it only supports a single authorization method, not all endpoints are required.
In order to authenticate users associated with external IdPs to access IPA Web
UI, a general OAuth 2.0 authorization endpoint is required. Thus, this endpoint
information is stored in the object but not otherwise used by the Kerberos
flow.

#### Google IdPs

Choosing `--provider=google` would expand to use the following options:

| Option                | Value                                              |
|:--------------------- | :---------------------                             |
| `--auth-uri`=URI      | `https://accounts.google.com/o/oauth2/auth`        |
| `--dev-auth-uri`=URI  | `https://oauth2.googleapis.com/device/code`        |
| `--token-uri`=URI     | `https://oauth2.googleapis.com/token`              |
| `--userinfo-uri`=URI  | `https://openidconnect.googleapis.com/v1/userinfo` |
| `--keys-uri`=URI      | `https://www.googleapis.com/oauth2/v3/certs`       |
| `--scope`=STR         | `openid email`                                     |
| `--idp-user-id`=STR   | `email`                                            |

#### Github IdPs

Choosing `--provider=github` would expand to use the following options:

| Option                | Value                                              |
|:--------------------- | :---------------------                             |
| `--auth-uri`=URI      | `https://github.com/login/oauth/authorize`         |
| `--dev-auth-uri`=URI  | `https://github.com/login/device/code`             |
| `--token-uri`=URI     | `https://github.com/login/oauth/access_token`      |
| `--userinfo-uri`=URI  | `https://openidconnect.googleapis.com/v1/userinfo` |
| `--keys-uri`=URI      | `https://api.github.com/user`                      |
| `--scope`=STR         | `user`                                             |
| `--idp-user-id`=STR   | `login`                                            |

Please note that Github explicitly states that a user login is not unique and
can be reused after a user account was deleted. The configuration above aims
for an easy setup for testing. If production deployment with Github IdP would
be required, it is recommended to change `--idp-user-id` to a more unique subject
like `id`. Unfortunately, Github UI does not give an easy way to discover a
user ID. Other IdPs also lack an easy way to resolve these internal identifiers
when not authorized by the user themselves.

For Github, user's ID can be looked up without authentication through the Users
API. Assuming we have `curl` and `jq` utilities available, a request to
discover an ID of a Github user named `test` would look like:

```
$ curl --silent \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/users/test | jq .id

383316
```


#### Microsoft IdPs

Microsoft Azure IdPs allow parametrization based on the Azure tenant ID
which can be specified with `--org` option to `ipa idp-add`. If support for
live.com IdP is required, specify organization ID `common`, e.g.

```
ipa idp-add LiveCom --provider microsoft --org common --client-id some-client-id
```

Choosing `--provider=microsoft` would expand to use the following options. A string
`${ipaidporg}` will be replaced by the value of `--org` option.

| Option                | Value                                                                  |
|:--------------------- | :---------------------                                                 |
| `--auth-uri`=URI      | `https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/authorize` |
| `--dev-auth-uri`=URI  | `https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/devicecode`|
| `--token-uri`=URI     | `https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/token`     |
| `--userinfo-uri`=URI  | `https://graph.microsoft.com/oidc/userinfo`                            |
| `--keys-uri`=URI      | `https://login.microsoftonline.com/common/discovery/v2.0/keys`         |
| `--scope`=STR         | `openid email`                                                         |
| `--idp-user-id`=STR   | `email`                                                                |


#### Okta IdPs

Upon registration of a new organization in Okta, a new base URL is associated
with it. It can be specified with `--base-url` option to `ipa idp-add`:

```
ipa idp-add MyOkta --provider okta --base-url dev-12345.okta.com --client-id some-client-id
```

Choosing `--provider=okta` would expand to use the following options. A string
`${ipaidpbaseurl}` will be replaced by the value of `--base-url` option.

| Option                | Value                                                                  |
|:--------------------- | :---------------------                                                 |
| `--auth-uri`=URI      | `https://${ipaidpbaseurl}/oauth2/v1/authorize`                         |
| `--dev-auth-uri`=URI  | `https://${ipaidpbaseurl}/oauth2/v1/device/authorize`                  |
| `--token-uri`=URI     | `https://${ipaidpbaseurl}/oauth2/v1/token`                             |
| `--userinfo-uri`=URI  | `https://${ipaidpbaseurl}/oauth2/v1/userinfo`                          |
| `--scope`=STR         | `openid email`                                                         |
| `--idp-user-id`=STR   | `email`                                                                |


#### Keycloak IdPs

Keycloak allows defining multiple realms (organizations). Since it is often a
part of a custom deployment, both base URL and realm ID are required and
can be specified with `--base-url` and `--org` options to `ipa idp-add`:

```
ipa idp-add MySSO --provider keycloak \
    --org master --base-url keycloak.$DOMAIN:$PORT/prefix \
    --client-id some-client-id
```

Quarkus version of the Keycloak 17 or later has removed `/auth/` part of the URI. If
your deployment is using non-Quarkus distribution of the Keycloak, `--base-url`
would need to include `/auth/` component as well.

Choosing `--provider=keycloak` would expand to use the following options. A string
`${ipaidpbaseurl}` will be replaced by the value of `--base-url` option. A string
`${ipaidporg}` will be replaced by the value of `--org` option.

| Option                | Value                                                                              |
|:--------------------- | :---------------------                                                             |
| `--auth-uri`=URI      | `https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/openid-connect/auth`        |
| `--dev-auth-uri`=URI  | `https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/openid-connect/auth/device` |
| `--token-uri`=URI     | `https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/openid-connect/token`       |
| `--userinfo-uri`=URI  | `https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/openid-connect/userinfo`    |
| `--scope`=STR         | `openid email`                                                                     |
| `--idp-user-id`=STR   | `email`                                                                            |


#### User-specific options

Similar to RADIUS proxy support, external IdP authentication only triggered
when the following three conditions are true:

* user entry contains external IdP reference
* user entry has external IdP user name (subject) set
* either global user authentication type or per-user authentication type includes `idp` method

Therefore, two additional attributes available for User object in IPA API:

| Option                | Description                                                 |
|:--------------------- | :---------------------                                      |
| `--idp`=STR           | External IdP object reference                               |
| `--idp-user-id`=STR   | External IdP's user name (subject)                          |

External IdP user name format is specific to individual IdPs. Most OAuth 2.0
IdPs provide `email` scope to retrieve email associated with the OAuth 2.0
resource owner (user) subject. Pre-populated IdP templates described above
include `email` scope by default. If external IdP references were created with
the help of these templates, user's email can be set to `--idp-user-id` to match
the resource owner subject. Please read Security section for details on when
this is inappropriate.

Below is an example how to associate a user account with a specific IdP reference:

```
ipa user-mod test --user-auth-type=idp --idp google --idp-user-id test@example.test
```

### WebUI

The IdP server objects need to be accessible in the WebUI. A new tab for
IdP will be created in the "Authentication" section, similar to
the existing _RADIUS servers_ tab. It will contain a table with the
list of IdP objects, enabling to add or delete an object.
Each object must be clickable in order to be edited.

In the _settings_ page for IdP objects, all the properties must be editable
but the client secret must not be displayed unless the authenticated user permitted
with the help of the `System: Read External IdP client secret` permission.

In order to change the client secret, the admin will click on
_Actions:Reset secret_.

Web UI for user entry attributes have to be extended to include both external
IdP reference and IdP user subject.

## Access control

Specific permissions need to be created to protect access to the IdP objects:
* System: Add External IdP
* System: Read External IdP (does not provide access to the client secret)
* System: Modify External IdP
* System: Delete External IdP
* System: Read External IdP client secret

Specific Privileges:
* External IdP Administrator: all the permissions related to external idp
except _System: Read External IdP client secret_

Any user who is a member of the admins group will be able to manage the
IdP server objects.

## Security

IPA objects representing external IdP references are OAuth 2.0 clients. The
client ID and client secret details can be used to impersonate OAuth 2.0
client. For public OAuth 2.0 client access to Client ID is enough. It is not
considered secure as it is typically a part of the HTTP redirect in OAuth 2.0
authorization flows.

Client secret has to be protected as it is typically used for private (trusted)
OAuth 2.0 clients.

Kerberos pre-authentication method `idp` relies on the user subject
(`ipaIdpSub` LDAP attribute) defined in the LDAP object entry to match the
Kerberos principal and the OAuth 2.0 resource owner. When `openid` OAuth 2.0
scope is used, this typically maps to `sub` value. Since there are no ways to
pull this value for all users in advance, pre-populated IdP templates set OAuth
2.0 scopes to include `email` and then use `email` to map IdP subject where possible.
There are some well-known IdPs which allow reuse of user accounts and emails, this
applies to both Github and Gitlab. Since Gitlab does not support OAuth 2.0
Device authorization grant flow, it is not an issue in itself for this project. However,
for Github it is known that user accounts can be recycled after their removal. In
this case we would recommend to use internal Github identifier instead.

## Upgrade and backward compatibility

As the new object class and attribute types are added in the LDAP schema, there
is no need for a specific upgrade task.
Upon normal upgrade, the new schema is applied and replicated to the other
servers, even if they are installed with a version which does not define the
new object class / attribute types.

In a mixed topology containing old and new servers, the new API is provided
only by the new servers.
