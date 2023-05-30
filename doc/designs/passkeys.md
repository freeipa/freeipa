# Passkey authentication

## Overview

Traditional authentication with a password is not considered secure enough
by many companies or government agencies. Alternate and more secure
solutions exist, among which the use of passkeys, where the private
key is stored on the device and the server only needs to know the public
key.

For the purpose of this feature, passkey is a FIDO2 compatible device supported
by the libfido2 library. For more details, refer to
https://fidoalliance.org/fido2/

The goal of this feature is to use a passkey to authenticate a user
against IPA.

The project will be jointly developed by SSSD and IPA:

- IPA provides the interface to store the user's public credentials
- IPA provides the interface to configure passkey settings
- SSSD performs the actual authentication

SSSD has defined the implementation in two design pages:

- [Local passkey authentication](https://sssd.io/design-pages/passkey_authentication.html).
- [Passkey Kerberos integration](https://sssd.io/design-pages/passkey_kerberos.html)

## Use Cases

- The administrator or the user registers a passkey into IPA, associated
to a user account. The registration process stores a description of the passkey
bound to IPA deployment and requires a direct communication with the passkey
device. Alternatively the description string can be obtained through the SSSD
registration tool and added without the presence of the passkey device.
- The user is then able to authenticate to any IPA enrolled host using the
passkey. The first round of passkey integration is targeting a login to
services implementing login with the help of PAM library locally on the host.
This includes direct console or graphical desktop login and authentication
to PAM-protected shell services like 'su' or 'sudo'. To access remote services
a Kerberos ticket can be obtained and used against those services later.

## How to Use

### Configuration of the passkey settings by the administrator

The administrator is able to specify common settings that will apply:

- require user verification during authentication (True/False):
  - True: require user verification during authentication (PIN for instance).
  - False: do not require user verification during authentication.
The default value is True.

### Registration of credentials

The user can register credentials for himself, or the admin (or any user with
the permission "System: Manage User passkeys") can register
credentials for another user.

During the registration process, it is possible to specify
- a COSE type: `es256`, `rs256` or `eddsa`
- request user verification: true or false
the authentication will force to execute the user verification check even if
the passkey settings do not set this flag. If credentials are registered without
the flag, the global passkey settings apply.
- credential type: `server-side` or `discoverable`
Discoverable credentials do not require to first identify the user.

When the passkey credential is registered, a relaying party (RP) is set to be
the IPA domain (e.g. ipa.test). While using a domain-wide relaying party
reduces access control capabilities for individual application's use of the
registered passkey, IPA provides own access control mechanisms to be layered
on top. We choose to combine existing authorization features of IPA with an
ease of use for the passkeys.

### Authentication

#### Console or desktop authentication

The user has a passkey in his possession that was already registered to IPA
and has physical access to a machine enrolled in IPA.

At Gnome login, he types his username and inserts the device.

At console login, he types his username and inserts the device.

If user verification is enabled, then the PIN is prompted. SSSD validates the
credentials and checks that the passkey allows authentication.

#### PAM-protected service access

The following example is using the su command, but would apply to any other
PAM-protected service.

The user passkeyuser has a passkey in his possession that was already
registered to IPA and has physical access to a machine enrolled in IPA. He
is already logged into the machine as a different user and wants to perform
su to authenticate as passkeyuser.

Inside a terminal, he inserts his device and enters the `su - passkeyuser`
command.

SSSD validates the credentials and checks that the passkey allows
authentication.


## Design

### Configuration of the passkey settings

A new LDAP entry stores the passkey configuration and needs a new objectclass
and a new attributetype:
```
dn: cn=passkeyconfig,cn=etc,$BASEDN
objectclass: top
objectclass: nsContainer
objectclass: ipapasskeyconfigObject
cn: passkeyconfig
ipaRequireUserVerification: True
```

The object class allows a single attribute, require user verification,
which is mandatory, single valued, and stores a boolean (TRUE, FALSE).
The LDAP entry is added when IPA server is installed or when the server is
upgraded to a version supporting passkeys, with a default value = TRUE.

### Storage of the passkey mapping

The passkey mapping is stored directly in the user entry. It needs a
new auxiliary objectclass and a new attributetype.

Note: a first proposal intended to store the value in the ipasshpubkey
attribute, but this attribute has a special handling (a new fingerprint is
calculated for each public key and added into the attribute sshpubkeyfp)
which makes it unsuitable for storing values that are not keys.

The attribute is multi valued, optional.

```
dn: uid=idmuser,cn=users,cn=accounts,dc=ipa,dc=test
uid: idmuser
...
objectClass: top
objectClass: person
...
objectClass: ipapasskeyuser
ipapasskey: passkey:9S87qLk8/RxYJ3skwwYduomAM+/HDtz41N0+w/vRL6aGKJkLMsg+2OhO0E8pK5DuO1KmdK61K8PmH7jiYuOqbg==,9YE1s/f7J47h2A/DXCVFWulqoBXFzCSxcbGEBadkpSUFjwUudhPLnPUTv2qNamakXJgRYCZQ7vpS/t5zXMLnkw==
```

The passkey mapping has the format `passkey:credentialid,pubkey`. credential
ID and public key are obtained during the registration phase, for instance
by calling SSSD helper process `sssctl passkey-exec --register` or the IPA Command
`ipa user-add-passkey LOGIN --register`.


### Access control

#### Permissions

- New permission created for writing the passkey configuration:
`System: Modify Passkey Configuration`. Granted to the Privilege `Passkey Administrators`
- New permission created for reading the passkey configuration:
`System: Read Passkey configuration`. Granted to all authenticated users.
- New permission for managing passkey mapping:
`System: Manage Passkey Mappings`. Granted to the Privilege: `Passkey Administrators`

- Extend existing permission" `System: Read User IPA Attributes`:
allow read access to the ipapasskey attribute (granted to all authenticated
users). This attribute is not sensitive as it contains only public data.

#### Self-service Permission

- New self-service permission for managing their own passkey mapping:
`Users can manage their own passkey mappings`

#### Privilege

- New privilege `Passkey Administrators` with the permissions `System: Modify Passkey Configuration` and `System: Manage Passkey Mappings`.

By default only members of the admins group are allowed to modify the passkey
settings or another user's passkeys.

## Implementation

### LDAP schema

New objectclass and attribute for the passkey configuration object:
```
attributeTypes: ( 2.16.840.1.113730.3.8.23.26 NAME 'ipaRequireUserVerification' DESC 'require passkey user verification' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE X-ORIGIN 'IPA v4.10')
objectclasses: ( 2.16.840.1.113730.3.8.24.8 NAME 'ipaPasskeyConfigObject' DESC 'IPA passkey global config options' AUXILIARY MUST ipaRequireUserVerification X-ORIGIN 'IPA v4.10')
```

New objectclass and attribute for the passkey mapping:
```
attributeTypes: ( 2.16.840.1.113730.3.8.23.27 NAME 'ipapasskey' DESC 'Passkey mapping' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'IPA v4.10' )
objectclasses: ( 2.16.840.1.113730.3.8.24.9 NAME 'ipaPasskeyUser' DESC 'IPA passkey user' AUXILIARY MAY ipapasskey X-ORIGIN 'IPA v4.10')
```

### Indices

No need to add a new index for ipapasskey as the search performed by SSSD
will use a filter based on the user uid.


## Feature Management

### UI

- A new tab will be added below "Policy", at the same level as `Host-Based Access Control`, `Sudo`, `SELInux User Maps`, `Password Policies` and `Kerberos Ticket Policy`, with the label `Passkey Configuration`.

It will allow to configure the attribute `Require User Verification`, with a check box: `on` or `off`.

- In the `User` facet, a new field will be added, below `SSH public keys`, with the label `Passkey mappings`, and will display the values, or allow to add a new value.

Note: since the Web browser may be running on a non-enrolled host without
the required packages, the WebUI will probably need specific javascript code
to register a key by inserting it on the machine where the browser is
running.

Investigations TBD regarding the possible solutions. The key registration
using the WebUI will not be part of the original implementation.


### CLI

| Command |	Options | Description |
| --- | ----- | --- |
| **Passkey configuration** | | |
| passkeyconfig-show | | This command displays the Passkey settings |
| passkeyconfig-mod | --require-user-verification=BOOL | This command modifies the Passkey settings |
| **User Mapping** | | |
| user-add-passkey | LOGIN [PASSKEY...] | This command does not require the device to be inserted and can directly add the mapping data, obtained through another mean (for instance through sssctl passkey-exec --register) |
| user-add-passkey | LOGIN --register [--cose-type=['es256', 'rs256', 'eddsa']] [--require-user-verification=BOOL] | This command requires the insertion of the device, performs the registration with the specified cose type + user verification requirement, and adds the mapping data to the user entry |
| user-remove-passkey | LOGIN PASSKEY... | |
| user-show | LOGIN | This command displays the passkey mapping if set, with the label `Passkey mapping` |
| stageuser-add-passkey | LOGIN [PASSKEY...] | This command does not require the device to be inserted and can directly add the mapping data, obtained through another mean (for instance through sssctl passkey-exec --register) |
| stageuser-add-passkey | LOGIN --register [--cose-type=['es256', 'rs256', 'eddsa']] [--require-user-verification=BOOL] | This command requires the insertion of the passkey, performs the registration with the specified cose type + user verification requirement, and adds the mapping data to the user entry |
| stageuser-remove-passkey | LOGIN PASSKEY... | |
| stageuser-show | LOGIN | This command displays the passkey mapping if set, with the label `Passkey mapping` |


### Configuration

The global settings can be read or modified using `ipa passkeyconfig-[show|mod]`.

## Upgrade

During upgrade, the new LDAP schema is automatically added and replicated to the replicas.

The upgrade must create the Passkey configuration entry if it does not already exist, with value='true' for the 'require user verification' setting.

## Test plan

XMLRPC tests must validate the new CLI.

## Troubleshooting and debugging

SSSD provides 2 new commands that can be used for debugging:
* `/usr/sbin/sssctl passkey-exec --register`: documented and supported. This command can be run as root only.
* `/usr/libexec/sssd/passkey_child --register`: internally called by `sssctl passkey-exec --register`. This command does not require root access.

IPA command `ipa user-add-passkey --register` internally calls `passkey_child`.

SSSD's helper `passkey_child` provides debugging options:

`passkey_child --register --username=passkeyuser --domain=ipa.test --debug-level=9 --logger=stderr --debug-libfido2`

SSSD's helper can also be used to test the authentication:

`passkey_child --authenticate --username=passkeyuser --domain=ipa.test --public-key=... --key-handle=... --debug-level=9 --logger=stderr --debug-libfido2`

SSSD logs are available in `/var/log/sssd/`.

