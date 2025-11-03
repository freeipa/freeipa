# LDAP system accounts

## Overview

Two important FreeIPA components are LDAP server and Kerberos infrastructure. When Kerberos protocol
is used for authentication in FreeIPA deployments, context of the original authentication is
preserved. This allows applications to inspect it and make decisions based not only on user identity
but also how the original authentication has happened. For applications that do not support
integration with Kerberos, a traditional LDAP bind is used. In this case, the original
authentication context is lost and the application can only see the identity of the user that has
authenticated.

Applications which do not support Kerberos authentication also need to authenticate to the LDAP
server. This is typically done using an LDAP system account. They are not used in the POSIX
environment and are not associated with any user. System accounts are typically used by applications
to authenticate to the LDAP server and perform operations on behalf of the application.

This document describes the design of the system accounts in FreeIPA.

## Use Cases

### Use Case 1: Legacy Application authentication

A legacy application that does not support Kerberos authentication needs to authenticate to the LDAP
server. The application uses an LDAP system account to authenticate to the LDAP server. After
successful authentication, the application can perform operations on behalf of the system account.

### Use Case 2: External account password rotation

An external system controls the passwords of user accounts in FreeIPA. The external system uses an
LDAP system account to authenticate to the LDAP server and change the password of a user account.
The change of the user account's password should not trigger the password policy reset for the user
account.

## How to Use

LDAP system account is addressed by its LDAP DN. An application can bind to LDAP by presenting both
LDAP DN of the object to bind as and its password. The password is stored in the `userPassword`
attribute of the system account object.

A typical LDAP authentication operation with the system account would look like this:

```
$ ldapsearch -D "uid=system-account,cn=sysaccounts,cn=etc,dc=example,dc=com" -W -b "dc=example,dc=com" -s sub "(objectclass=*)"
```

In the `ldapsearch` command above, the system account
`uid=systemaccount,cn=sysaccounts,cn=etc,dc=example,dc=com` is used to authenticate to the LDAP
server. Its password is not provided directly but `ldapsearch` command will prompt for it due to
`-W` option.

If the system account is used to perform LDAP operations, the system account should have the
necessary permissions to perform the operation. The permissions are granted using the LDAP access
controls (ACIs).

## Design

### System Account LDAP Object

System account object is a regular LDAP entry with at least two object classes defined: `account`
and `simpleSecurityObject`. The object is stored in the `cn=sysaccounts,cn=etc` container. In order
to allow membership in groups and roles, object class `nsMemberOf` can be used. The object has the
following attributes:

- `uid`: The unique identifier of the system account.

- `userPassword`: The password of the system account.

- `description`: A human-readable description of the system account.

- `memberOf`: The groups and roles the system account is a member of, in case the `nsMemberOf`
  object class is used.

Other attributes can be added to the system account object as needed but they aren't used by the
system account itself.

## Implementation

### LDAP BIND Operation

FreeIPA provides a number of plugins that alter the behavior of the LDAP server. One of these
plugins is the `ipa_pwd_extop` plugin. This plugin is used to intercept the LDAP BIND operation and
perform additional checks and operations. In particular, this plugin enforces two-factor
authentication for the user accounts if `EnforceLDAPOTP` global option is set or LDAP client
enforced the check through an LDAP control.

When `EnforceLDAPOTP` mode is enabled, any LDAP bind must be performed with a user account that has
two-factor authentication enabled. This would break LDAP binds with system accounts as they do not
have two-factor authentication enabled. `ipa_pwd_extop` plugin accounts for this by checking that
the LDAP object pointed by the LDAP bind has `simpleSecurityObject` object class. If the object does
have this object class, the plugin allows the bind to proceed.

### Password modifications using system accounts

FreeIPA implements a password change policy that ensures only users can keep the passwords they
changed. If a password change came from any other source, it will be marked for a change next time
it is used. For example, an administrator may reset a user's password but this password will have to
be changed next time user authenticates to the system. This is enforced through both LDAP and
Kerberos authentication flows.

In order to allow external systems to synchronize passwords without triggering the password reset,
FreeIPA implements two exceptions:

- `cn=Directory Manager` can change passwords without marking them for a change.

- LDAP objects whose DNs are stored in the `passSyncManagersDNs` attribute of the
  `cn=ipa_pwd_extop,cn=plugins,cn=config` LDAP entry can change passwords without marking them for a
  change.

The latter exception is used internally by the FreeIPA replication system to synchronize data from
Windows domain controllers with the help of PassSync plugin. However, both of these exceptions also
avoid password policy checks for the new passwords.

In order to differentiate the `passSyncManagersDNs` and the system accounts, we introduce a
separate attribute `SysAcctManagersDNs`. The system accounts DNs can be added to the
`SysAcctManagersDNs` attribute to allow them to update user passwords without marking them for a
change.

Members whose DNs are stored in `SysAcctManagersDNs` attribute will have the following semantics in
`ipa_pwd_extop` processing of the password changes:

- the password change will be subject to the password policy associated with the user account, like
  for the normal user password changes;

- the password change initiated by the system account will not force expiration of the user's
  password unlike the administrator-initiated password change.

The LDAP entry `cn=ipa_pwd_extop,cn=plugins,cn=config` is not replicated. Every IPA server has its
own configuration. If more than one server needs to allow a way to modify passwords without reset,
each server's configuration must be updated.

### Access controls

To simplify administration of the system accounts, a new privilege `System Accounts Administrators`
is added. This privilege is granted by default to the `Security Architect` role.

The privilege gives access to the following separate permissions:

- `System: Add System Accounts`: allows to create system account objects
- `System: Check System Accounts passwords`: allows to check whether system accounts have passwords
  defined
- `System: Modify System Accounts`: allows to update system account information, including a
  password
- `System: Remove System Accounts`: allows to remove the system account

The system account itself needs to be permitted to modify user passwords. To help with that, a role
management is extended to allow system accounts membership. Thus, a corresponding permission
(`System: Change User password`) can be associated through the privilege system and granted via the
role.

Even when a system account is granted permission to modify user accounts, treating the change to not
cause a password reset needs an explicit buy-in, as described in the previous session.

In order to provide the management of the `SysAcctManagersDNs` attribute, FreeIPA defines two
additional permissions:

- `Modify System Account Managers Configuration` permission allows adding and removing DNs to and
  from the `SysAcctManagersDNs` attribute.

- `Read System Account Managers Configuration` permission allows reading the `SysAcctManagersDNs`
  attribute.

Both these permissions are granted to the `System Accounts Administrators` privilege and, through
that privilege, to the `Security Architect` role. Members of `admins` group are not members of the
`Security Architect` role by default. Instead, they are added to the `System Accounts
Administrators` privilege through the 'Replication Administrators' privilege.

The following sequence will allow a system account `my-app` to change user passwords:

```bash
$ kinit admin
$ ipa sysaccount-add 'my-app' --random
$ ipa privilege-add 'my-app password change privilege'
$ ipa privilege-add-permission 'my-app password change privilege' \
                  --permission 'System: Change User password'
$ ipa role-add 'my-app role'
$ ipa role-add-privilege 'my-app role' \
             --privilege 'my-app password change privilege'
$ ipa role-add-member 'my-app role' --sysaccounts 'my-app'
# In order to allow password changes without reset:
$ ipa sysaccount-policy 'my-app' --privileged=true
```

## Feature Management

### CLI

| Command            | Options | Description                                    |
| ------------------ | ------- | ---------------------------------------------- |
| sysaccount-add     | name    | Create LDAP object for a new system account    |
| sysaccount-del     | name    | Remove LDAP object used for the system account |
| sysaccount-find    | [name]  | Return list of existing system accounts        |
| sysaccount-mod     | name    | Modify settings for the system account         |
| sysaccount-policy  | name    | Update `SysAcctManagersDNs` configuration      |
| sysaccount-enable  | name    | Allow use of system account for LDAP BIND      |
| sysaccount-disable | name    | Disable use of system account for LDAP BIND    |

The following commands provide an additional `--privileged=TRUE|FALSE` option:
`sysaccount-add`, `sysaccount-mod`, and `sysaccount-policy`. This option is used to allow a
system account to update user passwords without forcing them being requested to change on the next
login by the user. This is done by adding the DN of this system account to the list of DNs allowed
to manage password synchronization (`SysAcctManagersDNs` LDAP attribute) of the `ipa_pwd_extop`
plugin.

In order to allow adding system accounts to roles, `role` object has been extended to allow
membership of system accounts. The command `ipa role-add-member 'my-role' --sysaccounts
'my-account'` will make sure to grant `my-account` system account all privileges associated with the
`my-role` role.

An example of running `ipa sysaccount-add -v my-app --random --privileged=true`, where `-v` option
allows to see the `INFO` level message that shows bind DN of the created system account:

```bash
$ ipa sysaccount-add -v my-app --random --privileged=true
ipa: WARNING: Password reset permission is local to server server.ipa.test.
Restart the Directory Server services on it. Run the 'sysaccount-policy'
command against each server you want to allow or disable to reset passwords on.
ipa: INFO: To bind to LDAP with system account 'my-app', use the bind DN 'uid=my-app,cn=sysaccounts,cn=etc,dc=ipa,dc=test'.
------------------------------
Added system account "my-app"
------------------------------
  System account ID: my-app
  Random password: <some value>
```

Due to the fact that `SysAcctManagersDNs` configuration setting is not replicated across IPA
servers, the update of the configuration will issue a warning to make sure to update other IPA
servers as well. It will also tell that an LDAP server on the specific server where command was
executed must be restarted to apply changes to the `ipa_pwd_extop` plugin configuration.

Typically, external consumers of the system accounts operate against a single IPA server, thus
changing the configuration at a single system is enough. As mentioned earlier, `ipa_pwd_extop`
plugin configuration is not replicated and must be modified on each IPA replica. IPA command line
tool, `ipa`, can be run on the individual IPA server to force connection to that specific server.

Command `sysaccount-del` will automatically remove the deleted system account reference from the
`ipa_pwd_extop` configuration, if any. However, it will only be done on the single master. Thus, it
is recommended to remove the entry from all affected IPA servers using `ipa sysaccount-policy`
before removing the system account with `sysaccount-del` command.

Three examples below demonstrate different ways to perform the policy operation on a system account
in order to affect a specific IPA server's `ipa_pwd_extop` plugin configuration:

1. Use `ipa` tool as unprivileged user with administrative Kerberos ticket:

```bash
... ssh to ipa-server
[ipa-server] $ kinit admin
[ipa-server] $ ipa sysaccount-policy my-app --privileged=true
```

2. Newer `ipa` tool implementations might provide `--force-server <server-name>` option that allows
   to choose the server to communicate with:

```bash
$ kinit admin
$ ipa --force-server ipa-server sysaccount-policy my-app --privileged=true
```

3. Run `ipa` tool as the privileged root user on the IPA server:

```bash
... login as root on the ipa-server
[ipa-server] # ipa -e in_server=true sysaccount-policy my-app --privileged=true
```

In the latter example `ipa` tool will directly connect to LDAPI endpoint and POSIX root user will be
mapped to `cn=Directory Manager` LDAP administrator account. This approach also works for
deployments where Kerberos infrastructure is temporarily unavailable.
