# Manage FreeIPA as a user from a trusted Active Directory domain

Allow users from trusted Active Directory forests to manage FreeIPA
resources if they are part of appropriate roles in FreeIPA. For example,
adding an Active Directory user as a member of 'admins' group would make
it equivalent to built-in FreeIPA 'admin' user.

The feature utilizes existing infrastructure for adding ID overrides of users
from trusted domains in the `Default Trust View`. User ID overrides in the
`Default Trust View` can only be created for the users from trusted Active
Directory forests. When Active Directory user authenticates with GSSAPI against
the FreeIPA LDAP server, its Kerberos principal is automatically mapped to the
user's ID override in the `Default Trust View`. LDAP server's access control
plugin uses membership information of the corresponding LDAP entry to decide
how access can be allowed.

## Use Cases

* As an Administrator in AD I want to also be able to fully administer FreeIPA
  as if I am an FreeIPA admin so that I do not have to have two different
  accounts and passwords.

* As an AD user I want to be able to use self service features of FreeIPA Web
  UI for example to upload my SSH keys or change other related to me data that
  is managed in FreeIPA on my behalf.

* As an AD user or Admin I want to be able to access FreeIPA Web UI with SSO if
  I have a valid kerberos ticket

* As an AD user or Admin I want to be able to access FreeIPA Web UI and be
  prompted for user name and password

* As an AD user who is assigned appropriate privileges in FreeIPA, I'd like to
  be able enroll FreeIPA hosts.

* As an AD user who is assigned appropriate privileges in FreeIPA, I'd like to
  be able to promote FreeIPA hosts to replicas.

* As an AD user who is assigned appropriate privileges in FreeIPA, I'd like to
  be able to issue certificates for FreeIPA resources [not implemented].

## Design

### FreeIPA integration

FreeIPA allows to associate an ID override with an Active Directory
user. This user ID override stores information about user-specific POSIX
attributes: POSIX IDs for explicitly defined ID range case, home
directory, user's shell, SSH public keys, and associated user
certificates. ID overrides can be defined in a number of ID views, with
`Default Trust View` always applied by SSSD whenever information about
this AD user is requested in the FreeIPA realm.

Existence of the user ID override in the `Default Trust View` also
allows this user to bind to FreeIPA LDAP server when using GSSAPI
authentication. This is a feature that FreeIPA Web UI utilizes to
provide a web interfaces for a self-service of Active Directory users.

### Implementation

From the LDAP server perspective, FreeIPA access controls are based on the
membership in a certain group and role. If an LDAP object identity to which
authenticated LDAP bind is mapped belongs to a group or a role that allows
certain operations in the access controls, this identity is granted access
defined by the access controls.

Since user ID override is represented as a separate LDAP object in FreeIPA
LDAP store, its DN can be included into a group as a member. `memberof` plugin
requires to be able to add `memberof` attribute back to the entry that is added
as a member. As a result, ID override entry must include an object class that
allows this operation to succeed.

Thus, making ID override a group member in LDAP requires to expand existing set
of object classes in the ID override entry. There is standard object class in
389-ds, `nsmemberof`, that allows `memberof` attribute.

Another part of the requirement for members of groups in FreeIPA is to be able
to map a member DN back to its primary key for FreeIPA API purposes. This
requirement allows API to provide virtual attributes `member_<object>` that
contain primary keys of the members per each object type, to allow UI and CLI
to show them in a structured way.

For this to work, an object representing the group member has to provide an
implementation of the `LDAPObject.get_primary_key_from_dn()` method. For ID
overrides this method just needs to call existing
`resolve_anchor_to_object_name()` helper that performs SID or ipaUniqueID to
name transformation.

For Web UI operations, there is another requirement: group membership
management implementation requires lookup of an object by its primary key. In
case of ID overrides the overrides actually referred by a pair `<ID view, ID
override anchor>`. Since it is not possible to pass ID view detail, ID view is
set to be empty in those API calls. Since only Default Trust View is used for
mapping ID overrides to LDAP objects for authenticated LDAP binds, we can
default to `Default Trust View` in case the view is missing from the API call.

#### Web UI

In Web UI upon login there is a code that defines what view should be visible
for the user. This view already deals with Active Directory users and provides
them with a self-service view of their ID override entry in the `Default Trust
View`. With the proper support for the membership of ID overrides, ID override
entry now also return virtual attributes `memberof_group`, `memberofindirect_group`,
`memberof_role`, and `memberofindirect_role` that can be checked the same way
how membership is checked for normal IPA users.

### Access Control

389-ds LDAP server implements access control with the help of `acl` plugin.
This plugin relies on the membership information of the LDAP object of the
identity currenly bound to the LDAP server connection.

The `acl` plugin retrieves list of groups the bound LDAP object belongs to and
then evaluates each access based on the membership information and access
control lists (ACLs). Most if not all FreeIPA ACLs rely on the group membership
through the role/privilege/permission concepts.

If an active LDAP bound object belongs to certain groups and these groups
mentioned in the ACLs, this LDAP bound object will be allowed to perform those
LDAP operations which allowed through the ACLs.

### Upgrade and migration

The plugin does not require any schema updates because `nsMemberOf` is part of
the core 389-ds LDAP schema.

## Usage

In order to allow Active Directory user to manage FreeIPA, following steps
should be done:

* An ID override for the user should be created in the `Default Trust View`

* An ID override for the user should be added to an IPA group or directly to an
  IPA role

* This group should be part of a role/privilege that allows
  modification/management of any IPA object

### Sample usage

1.  As admin, add ID override for a user (ad-user@ad.example.test):
```console
    ipa idoverrideuser-add 'default trust view' ad-user@ad.example.test
```

2.  Add ad-user\@ad.example.test to 'admins' group:
```console
    ipa group-add-member admins --idoverrideusers ad-user@ad.example.test
```

3. Alternatively, the ID override can be added to a role:
```console
    ipa role-add-member 'User Administrator' --idoverrideusers ad-user@ad.example.test
```

When ID override membership is removed from a group or a role, it will lose all
the power for any consequent authenticated LDAP session.

