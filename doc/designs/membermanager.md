# Member Manager for group membership

## Overview

A member manager is a principal that is able to manage members of a
group. Member managers are able to add new members to a group or remove
existing members from a group. They cannot modify additional attributes
of a group as a part of the member manager role.

Member management is implemented for *user groups* and *host groups*.
Membership can be managed by users or user groups. Member managers are
independent from members. A principal can be a member manager of a
group without being a member of a group.


## Use Cases

An administrator can use member management feature to delegate some
control over user groups and host groups to users. For example a
project manager is now able to add new team members to a project group.

A NFS admin with member management capability for a host group is able
to indirectly influence an HBAC rules and control which hosts can
connect to an NFS file share.

## Implementation

The user group commands and host group commands are extended to handle
member managers. The plugin classes grow two additional sub commands,
one for adding and one for removing member managers. The show command
prints member manager users and member manager groups. The find command
can search by member manager.

Member managers are stored in a new LDAP attribute ``memberManager``
with OID 2.16.840.1.113730.3.8.23.1. It is multi-valued and contains
DNs of users and groups which can manage members of the group. The
attribute can be added to entries with object class ``ipaUserGroup``
or ``ipaHostGroup``. The attribute is indexed and its membership
controlled by referential integrity postoperation plugin.
New userattr ACIs grant principals with user DN or group DN in
``memberManager`` write permission to the ``member`` attribute of the
group.

The ``memberManager`` attribute is protected by the generic read and
modify permissions for each type of group. It is readable by everybody
with ``System: Read Groups`` / ``System: Read Hostgroups`` permission
and writable by everybody with ``System: Modify Groups`` /
``System: Modify Hostgroups`` permission.


## Examples

Add example user and groups:

```
$ kinit admin
$ ipa user-add john --first John --last Doe --random
$ ipa user-add tom --first Tom --last Doe --random
$ ipa group-add project
$ ipa group-add project_admins
```

Make user and group member managers:

```
$ ipa group-add-member-manager project --users=john
$ ipa group-add-member-manager project --groups=project_admins
```

Show group:

```
$ ipa group-show project
  Group name: project
  GID: 787600003
  Membership managed by groups: project_admins
  Membership managed by users: john
```

Find groups by member managers:

```
$ ipa group-find --membermanager-users=john
---------------
1 group matched
---------------
  Group name: project
  GID: 787600003
----------------------------
Number of entries returned 1
----------------------------
$ ipa group-find --membermanager-groups=project_admins
---------------
1 group matched
---------------
  Group name: project
  GID: 787600003
----------------------------
Number of entries returned 1
----------------------------
```

Use member management capability:

```
$ kinit john
$ ipa group-add-member project --users=tom
  Group name: project
  GID: 787600003
  Member users: tom
  Membership managed by groups: project_admins
  Membership managed by users: john
-------------------------
Number of members added 1
-------------------------
```

Remove member management capability:

```
$ kinit admin
$ ipa group-remove-member-manager project --groups=project_admins
  Group name: project
  GID: 787600003
  Member users: tom
  Membership managed by users: john
---------------------------
Number of members removed 1
---------------------------
```
