# App passwords

**DESIGN STAGE**

## Overview

FreeIPA does not currently allow users to have more than one password.
Using a single password for the user's account carries potential risk and
inconvenience with it. If the password is compromised on only one of the devices
the user uses, the attacker gains full administrative access to the user's
account and all systems and services associated with it. The user can then halt
it only by changing this single account's password and reconfiguring all systems
and applications using that password for authentication (even if only to one
particular service) to use the new one.

This enhancement therefore brings support for app passwords (sometimes also
called application-specific passwords), a form of multiple passwords for a single
user. Only this would, if app passwords are each used only on one device, increase
convenience in the case that the user can no longer trust a password used on one
of his devices. Namely, he can revoke or change only that password, without
needing to revoke or change his other passwords, including the primary password.
What is more, app passwords will generally not be usable for account management.

As a further possible future enhancement, this design page also outlines a
proposal to add support for use of app passwords with FreeIPA's Kerberos
functionality, what would enable to use the HBAC (host-based access control) to
allow specifying what app passwords can be used to log into a particular system
or service. The use of HBAC with app passwords would add another security
benefit on top of those mentioned above - the intruder's access to the user's
account might be denied not only to the account management, but also to at least
some of the systems and services that it is used for.

Resolves: https://pagure.io/freeipa/issue/4510

How Google does it: https://support.google.com/accounts/answer/185833?hl=en

## Use cases

### Use with password-only authentication

The user can set multiple passwords per account. Each password can be then used
for authenticating on only one device. Various passwords can as well be used to
authenticate to various services or their sets. These divisions can even be
combined, thus - in the most extreme case - having one password for
authenticating to one specific service on one particular device. Granularity of
such divisions will be fully up to user's discretion.

### Use as a part of 2FA (OTP)

When 2FA will be enabled, it will work (and be required) only for the user's
primary password, not for any of the app passwords, as that would cause too much
trouble.

### Use as a fallback mechanism when 2FA is activated, but the client app does not support it

As 2FA will not be applied to app passwords, the user can use an app password to
log into a service that does not support 2FA.

## Design

### Multiple passwords for a single user and related changes

App passwords will be stored in a new LDAP subtree in the form
```
dn: uid=user-1,cn=myapp,cn=apps,cn=accounts,$SUFFIX
uid: user-1
displayName: My eMail app password for tablet
appname: myapp
entryUUID: XXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
userPassword: *********************
managedby: uid=user,cn=users,cn=accounts,$SUFFIX

dn: uid=user-2,cn=myapp,cn=apps,cn=accounts,$SUFFIX
uid: user-2
displayName: My eMail app password for smartphone
appname: myapp
entryUUID: XXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
userPassword: *********************
managedby: uid=user,cn=users,cn=accounts,$SUFFIX
```
Every app will have its own subtree in which users will be able to create their
objects if they will want to use that app - this means objects containing app
passwords will not be grouped by users, but by apps. The object containing an
app password will have the following attributes:
* `uid` - will identify the object, and will also contain a number - this allows
  for one user having multiple passwords for the same app, its value will be
  enforced by LDAP ACIs
* `displayname` - the descriptive label of the password, search display
  attribute
* `appname` - the name of the app the password is used for, it is the same as
  the CN of the parent entry of the object
* `entryUUID` - a UUID, which will be useful to uniquely identify a password
  even in extreme cases when `uid`, `displayname` and `appname` will be the same
  for some password; `entryUUID` will be also used to identify the app password
  to delete
* `userpassword` - will hold the app password itself for LDAP
* `random` - auxiliary virtual attribute, a flag denoting whether to generate
  the password
* `randompassword` - auxiliary virtual attribute, stores the generated password
  for display in the POST callback of the modification command
* `managedby` - backlink to the owning user (that created it); it will be
  automatically filled and maintained with respect to referential integrity;
  search attribute; inspiration - otptoken ownership

The definition of the new object and its attributes holding app passwords and
related information, as well as operations with them - add, list, delete - will
be contained in a new file - `ipaserver/plugins/apppw.py`.

It will be possible to add app passwords only by generating them - FreeIPA's
existing mechanism for generating passwords will be used for this.

There will be no option to reset an app password.

### Permissions management for app passwords

A static set of new ACIs must be added, which will ensure that the owning user
will have read-write access to all (and only) objects holding his
app passwords, as well as appropriate access to their attributes - both when
logged in using the primary password and when logged in using the respective app
password. This is the only thing to do with respect to ACIs and app passwords,
as ACIs serve only for work with the LDAP database.

The only general limitation when the user is logged in using an app password
will be the inability to manage the account (modify the information about the
user, change his other passwords...). As existing ACIs will not apply to users
logged in using an app password, even a limitation such as reducing the
effective permissions of the current user session (possibly according to the app
policy) using a 389-DS plugin is not needed.

### SSSD support for the aforementioned functionality

Interactions with SSSD using the new functionality must be tested in
`ipatests/test_integration/test_sssd.py`.

If needed, SSSD will also be extended to support the aforementioned
functionality. This will be done by a closely related, but separate extension of
SSSD.

## Implementation

The extension must be backward compatible, that means not breaking any existing
functionality and passing all existing tests.

As for changes to the data storage:
* As described above, a new LDAP subtree will be created for app passwords, with
  objects holding them being grouped by app, and their attributes being, besides
  an app password itself for LDAP, a uid, a descriptive display name, an app
  name, a UUID, and a backlink to the owning user.
* New ACIs will be created so that users will have needed access to objects
  holding their own app passwords.

A new objectclass will be created for the `apppw` object and added into
the LDAP schema. This objectclass will be defined in
`install/share/60basev3.ldif`:
```
objectClasses:
    (2.16.840.1.113730.3.8.12.XX
    NAME 'ipaAppPw'
    DESC 'Object containing an app password and related data'
    SUP top
    MUST ( uid $ displayName $ appName $ entryUUID $ managedBy )
    X-ORIGIN 'IPA v4.9')
```

The `userPassword` attribute will be added by including the
`simpleSecurityObject` into the `apppw` object.

The LDIF code to add the `cn=apps,cn=accounts,$SUFFIX` entry, as well as new
ACIs for access to the `apppw` object and its attributes, during
* new installations will be in `install/share/apppw.ldif`,
* upgrades will be in `install/updates/19-apppw.update` (entry) and
  `install/updates/20-aci.update` (ACIs).

There will be the following ACIs on the `cn=apps,cn=accounts,$SUFFIX` entry:
```
aci: (target = "cn=\*,cn=apps,cn=accounts,$SUFFIX")
     (version 3.0; acl "Allow users to add entries grouping app passwords for a
     particular app";
     allow (add) 
     userdn = "ldap:///all;)
aci: (target = "ldap:///uid=($dn)-\*,cn=\*,cn=apps,cn=accounts,$SUFFIX")
     (targetattr = "uid || displayName || userPassword || appName || entryUUID
     || managedBy")
     (targetfilter=(objectClass=ipaAppPw))
     (version 3.0; acl "Allow users to add an app password for themselves";
     allow (add) 
     userdn = "ldap:///uid=($dn),cn=users,cn=accounts,$SUFFIX";)
aci: (targetattr = "managedBy")
     (targetfilter=(objectClass=ipaAppPw))
     (version 3.0; acl "Allow users to search for their app passwords";
     allow (search) 
     userdn = "ldap:///self" OR
     userattr = "managedBy#USERDN";)
aci: (targetattr = "displayName")
     (targetfilter=(objectClass=ipaAppPw))
     (version 3.0; acl "Allow users to read display names for their app
     passwords";
     allow (read) 
     userdn = "ldap:///self" OR
     userattr = "managedBy#USERDN";)
aci: (target = "ldap:///uid=\*,cn=\*,cn=apps,cn=accounts,$SUFFIX")
     (targetattr = "uid || displayName || userPassword || appName || entryUUID
     || managedBy")
     (targetfilter=(objectClass=ipaAppPw))
     (version 3.0; acl "Allow users to delete their app password";
     allow (delete) 
     userdn = "ldap:///self" OR
     userattr = "managedBy#USERDN";)
```

Backup and restore is out of scope of this extension, but it will probably work
with the new functionality.

I do not need to enforce anything for app passwords. I suppose it will then be
best to implement some if-else branching in
`daemons/ipa-slapi-plugins/ipa-pwd-extop/prepost.c`, where it will be tested if
the Password attribute being modified is not from the subtree for app passwords,
and if it is, then no check and enforcements, as well as no OTP validation will
be performed for it.

**New dependencies**: TBD, not expected for now

## Feature management

The login process will remain the same, only instead of entering the primary
password, the user will enter an app password. And as already stated, the user
then will not have access to the account management.

### UI

TBD

### CLI

| Command | Arguments | Options |
| ------- | --------- | ------- |
| apppw-add | username (user's uid), displayname, appname |  |
| apppw-list | username (user's uid) |  |
| apppw-del | username (user's uid), uuid |  |

## Test Plan

1. All existing tests must pass. This also ensures that the user can have only
one password.
2. Test app passwords:
   1. Add one app password using WebUI and one using CLI.
   2. Check that using these app passwords, it is possible to authenticate to
      all services and systems, but not to the FreeIPA server itself for account
      management.
   3. Log in using the primary password.
   4. Check whether all user's passwords are listed in the WebUI or by using an
      appropriate command in CLI.
   5. Delete both app passwords - the one created using WebUI by using CLI, and
      vice versa.
   6. Repeat steps 2.1 - 2.6 with using the both the deleted old and new app
      passwords in step 2.2. Authentication using the deleted old app passwords
      must fail, and authentication using the new app passwords must succeed.
   7. Chceck that the user now only has the primary password.
3. Test interactions with SSSD using the new functionality.
   * Repeat all procedures from the point 2, but when testing logins to apps,
     perform them on a client using SSSD configured against the testing FreeIPA
     server.

## Possible future enhancements

### Support for use of the aforementioned functionality with Kerberos

Support for use of the aforementioned functionality with Kerberos is necessary
for HBAC to be applicable to users logged in using app passwords.

Subaccounts will be introduced with principals in the form 
```_user_/_appname_@_REALM_```
(to be consistent with other things in FreeIPA) - a username will remain the
same for subaccounts, only the principal will contain the app name. The code of
FreeIPA must be modified to take into account the newly changed assumptions.
Until now, these were:
* two-component principals with a host as the first component are always host
  principals (`_host_/_fqdn_`)
* all other two-component principals are always service principals
  (`_service_/_fqdn_`)
* single-component principals are always users (user)
Now, they will be:
* two-component principals with an app name as the first component are users
  logged in with an app password (`_user_/_appname_`)
* two-component principals with a host as the first component are host
  principals (`_host_/_fqdn_`)
* all other two-component principals are service principals (`_service_/_fqdn_`)
* single-component principals are users logged in with their primary password
  (`user`)

The user must not be able to create a principal looking like a host or a 
service, or even set a password for another user. These problems are already
addressed. The latter problem will be avoided by setting the username part of
the principal automatically to the user's username. The former problem is
already addressed - it is prevented by disallowing dots in the app name, which
will be set by the user. The app name also must not be 'admin', as
`_user_/_admin_@_REALM_` are principals of administrators. These constraints are
enforced at the LDAP ACI level, not in the IPA Python frontend.

The ipa-kdb daemon probably will not have to be extended to support this
functionality, but it is possible.

### HBAC for app passwords

Two-component principals for subaccounts, as described above, will be used for
assigning HBAC rules to users logged in using app passwords. These HBAC rules
will be assigned by administrators just as the other ones.

Hostgroups will be used to allow applying the same HBAC rule to different
servers for the same app.

HBAC itself will not need to be extended.
