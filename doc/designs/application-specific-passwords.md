# Application-specific passwords

**DESIGN STAGE**

## Overview

FreeIPA does not currently allow users to have more than one password.
Using a single password for the user's account carries potential risk and
inconvenience with it. If the password is compromised on only one of the devices
the user uses, the attacker gains full administrative access to the user's
account and all services associated with it. The user can then halt it only by
changing this single account's password and reconfiguring all systems and
applications using that password for authentication (even if only to one
particular service) to use the new one.

This enhancement therefore brings support for multiple passwords for a single
user and extends the HBAC (host-based access control) to allow specifying what
application-specific passwords can be used to log into a particular service.
Only allowing multiple passwords for a single user itself would, if
application-specific passwords are each used only on one device, increase
convenience in the case that the user can no longer trust a password used on one
of his devices. Namely, he can revoke or change only that password, without
needing to revoke or change his other passwords, including the primary password.
What is more, application-specific passwords will generally not be usable for
account management. The use of HBAC with them will add another security benefit
to this - the intruder's access to the user's account might be denied not only
to the account management, but also to at least some of the services that it is
used for. The proposed HBAC extension would further strenghten this benefit.

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
primary password, not for any of the application-specific passwords, as that
would cause too much trouble.

### Use as a fallback mechanism when 2FA is activated, but the client
    application does not support it

As 2FA will not be applied to application-specific passwords, the user can use
an application-specific password to log into a service that does not support
2FA.

## Design

### Multiple passwords for a single user and related changes

Application-specific passwords will be stored in a new LDAP subtree in the form
```
dn: uid=user-1,cn=myapp,cn=apps,cn=accounts,$SUFFIX
uid: user-1
displayName: My eMail app password for tablet
userPassword: *********************

dn: uid=user-2,cn=myapp,cn=apps,cn=accounts,$SUFFIX
uid: user-2
displayName: My eMail app password for smartphone
userPassword: *********************
```
Every application will have its own subtree in which users will be able to
create their objects if they will want to use that application - this means
objects containing application-specific passwords will not be grouped by users,
but by applications. The object containing an application-specific password will
have the following attributes:
* `uid` - will identify the object, and will also contain a number - this allows
  for one user having multiple passwords for the same application
* `displayname` - the descriptive label of the password
* `userpassword` - will hold the application-specific password itself, for LDAP
* `random` - auxiliary virtual attribute, a flag denoting whether to generate
  the password
* `randompassword` - auxiliary virtual attribute, stores the generated password
  for display in the POST callback of the modification command
* `krbprincipalkey` - will hold the application-specific password itself, for
  Kerberos
* `krbprincipalname` - (see below) two-component Kerberos principal, the user
  will set the application name within constraints, and the rest will be filled
  automatically
* managedby - backlink to the owning user (that created it); it will be
  automatically filled and maintained with respect to referential integrity;
  inspiration - hostgroups or otptoken ownership?

The definition of the new object and its attributes holding application-specific
passwords and related information, as well as operations with them (add, modify,
delete) will be contained in a new file - `ipaserver/plugins/appspecificpw.py`.

The existing mechanism for generating passwords will be made available for use
for application-specific passwords as well.

There will be no option to reset an application-specific password.

### Support for use of the aforementioned functionality with Kerberos --
    OPTIONAL, TBD

~~The ipa-kdb daemon will be extended to support application-specific passwords
as well, so that they can be used with Kerberos and HBAC.~~

Subaccounts will be introduced with principals in the form 
```_user_/_appname_@_REALM_```
(to be consistent with other things in FreeIPA) - a username will remain the
same for subaccounts, only the principal will contain the application name. The
code of FreeIPA must be modified to take into account the newly changed
assumptions. Until now, these were:
* two-component principals with a host as the first component are always host
  principals (`_host_/_fqdn_`)
* all other two-component principals are always service principals
  (`_service_/_fqdn_`)
* single-component principals are always users (user)
Now, they will be:
* two-component principals with an application name as the first component are
  users logged in with an application-specific password (`_user_/_appname_`)
* two-component principals with a host as the first component are host
  principals (`_host_/_fqdn_`)
* all other two-component principals are service principals (`_service_/_fqdn_`)
* single-component principals are users logged in with their primary password
  (`user`)

The user must not be able to create a principal looking like a host or a
service, or even set a password for another user. The latter problem will be
avoided by setting the username part of the principal automatically to the
user's username. The former problem will be prevented by disallowing dots in the
application name, which will be set by the user. The application name also must
not be 'admin', as `_user_/_admin_@_REALM_` are principals of administrators.
These constraints need to be enforced at the LDAP ACI level, not in the IPA
python frontend.

### Permissions management for application-specific passwords

A static set of new ACIs must be added, which will ensure that the owning user
will have read-write access to all (and only) objects holding his
application-specific passwords - both when logged in using the primary password
and when logged in using the respective application-specific password. This is
the only thing to do with respect to RBAC and application-specific passwords,
as RBAC serves only for work with LDAP in FreeIPA.

The only general limitation for subaccounts will be the inability to manage the
account (modify the information about the user, change his other passwords...).
As all permissions for them will be assigned by administrators separately and
from scratch, even a limitation such as reducing the effective permissions of
the current user session (possibly according to the application policy) using a
389-DS plugin probably will not be needed.

#### HBAC for application-specific passwords -- OPTIONAL, TBD

Two-component principals for subaccounts, as described above, will be used for
assigning HBAC rules to users logged in using application-specific passwords.
These HBAC rules will be assigned by administrators just as the other ones.

Hostgroups will be used to allow applying the same HBAC rule to different
servers for the same application.

TBD: When an application-specific password is deleted, delete the associated
HBAC rules automatically, or keep them?

~~hbacrule plugin therefore will need to be extended with the ability to assign
allowed LDAP subtrees to application-specific passwords as a part of HBAC rules.
hbactest plugin will be extended to test this, and it will be used to test HBAC
with application-specific passwords in general.~~

### SSSD support for the aforementioned functionality

SSSD will also be extended to support the aforementioned functionality. This
will be done by a closely related, but separate extension of SSSD. On the
side of FreeIPA, after SSSD is extended, interactions with SSSD using the new
functionality must be tested in `ipatests/test_integration/test_sssd.py`.

## Implementation

The extension must be backward compatible, that means not breaking any existing
functionality and passing all existing tests.

As for changes to the data storage:
* As described above, a new LDAP subtree will be created for
  application-specific passwords, with objects holding them being grouped by
  application, and their attributes being, besides an application-specific
  password itself, a two-component Kerberos principal containing the application
  name, and a backlink to the owning user.
* New ACIs will be automatically created and maintained so that users will have
  read-write access to objects holding their own application-specific passwords.
* HBAC rules for subaccounts will be assigned in the same way as the other ones,
  using the two-component principal.
* Permitted LDAP subtrees for application-specific passwords will be stored as a
  part of HBAC rules.

The new additions to the data storage (including the new object and its
attributes) must be specified in LDIF files in `install/share/`, probably in
`60basev3.ldif`, or alternatively, in a new file.

Analogically, such records probably will be added to a new file in 
`install/updates`.

Backup and restore is out of scope of this extension, but it will probably work
with the new functionality.

**New dependencies**: TBD, not expected for now

## Feature management

### UI

It is not necessary that the new functionality be available in WebUI, but it
would be good to do it.

TBD

### CLI

TBD

The tests for XMLRPC can be extended and used for automatized testing of the new
functionality.

## How to test

TBD

## Test Plan

1. All existing tests must pass. This also ensures that the user can have only
one password.
2. Test (password policy-compliant) application-specific passwords and HBAC
   rules for them:
   2.1 Add one application-specific password using WebUI and one using CLI.
   2.2 Check that the user is not able to log in using either of these new
       passwords.
   2.3 Add some HBAC rules for both application-specific passwords. Do not
       specify permitted LDAP subtrees, these will be tested in the point 5.
   2.4 Check that using these application-specific passwords, it is possible to
       authenticate to all and only those services and systems that they have
       been permitted to in the previous step.
   2.5 Log in using the primary password.
   2.6 Check whether all user's passwords are listed in the WebUI or by using an
       appropriate command in CLI.
   2.7 Change both application-specific passwords - the one created using WebUI
       by using CLI, and vice versa.
   2.8 Repeat step 2.4 using the changed application-specific passwords.
   2.9 Remove both application-specific passwords - one by using WebUI, and the
       other one by using CLI.
   2.10 Chceck that the user now only has the primary password.
3. Test whether the password policies in force for the given user automatically
   apply for all of his passwords - i.e. they cannot be bypassed by setting
   another password:
   * Try to add an application-specific password that is in breach of the
     password policy in place. This must fail.
4. Test application-specific passwords and their permissions management with
   Kerberos (ipa-kdb):
   * Repeat the steps 2.1 - 2.10, but instead of logging in by entering the
     password directly, obtain a Kerberos ticket by entering the password into
     the corresponding prompt and then log in using the obtained ticket.
5. Test permitted LDAP subtrees for application-specific passwords:
   5.1 Create some application-specific passwords and HBAC rules for them, out
       of which some will limit logging in to the given application to the
       passwords from the permitted LDAP subtree.
   5.2 Try logging into some of the applications where logging in is limited in
       this way using application-specific passwords stored outside of the
       permitted subtrees. All these attempts must fail.
   5.3 Try logging into some of the applications where logging in is limited in
       this way using application-specific passwords stored inside of the
       permitted subtrees. All these attempts must succeed.
   5.4 Remove the application-specific passwords (and HBAC rules for them)
       created in the step 5.1.
6. Test interactions with SSSD using the new functionality.
   * Repeat all procedures from the points 1. - 5., but when testing logins to
     applications, perform them on a client using SSSD configured against the
     testing FreeIPA server.
