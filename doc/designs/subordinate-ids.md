# Central management of subordinate user and group ids

Subordinate ids are a Linux Kernel feature to grant a user additional
user and group id ranges. Amongst others the feature can be used
by container runtime engies to implement rootless containers.
Traditionally subordinate id ranges are configured in ``/etc/subuid``
and ``/etc/subgid``.

To make rootless containers in a large environment as easy as pie, IPA
gains the ability to centrally manage and assign subordinate id ranges.
SSSD and shadow-util are extended to read subordinate ids from IPA and
provide them to userspace tools.

## Overview

Feature requests

* [FreeIPA feature request #8361](https://pagure.io/freeipa/issue/8361)
* [SSSD feature request #5197](https://github.com/SSSD/sssd/issues/5197)
* [shadow-util feature request #154](https://github.com/shadow-maint/shadow/issues/154)
* [389-DS RFE for DNA plugin rhbz#1938239](https://bugzilla.redhat.com/show_bug.cgi?id=1938239)

Man pages

* [man subuid(5)](https://man7.org/linux/man-pages/man5/subuid.5.html)
* [man subgid(5)](https://man7.org/linux/man-pages/man5/subgid.5.html)
* [man user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
* [man newuidmap(1)](https://man7.org/linux/man-pages/man1/newuidmap.1.html)

Articles / blog posts
* [Basic Setup and Use of Podman in a Rootless environment](https://github.com/containers/podman/blob/master/docs/tutorials/rootless_tutorial.md)
* [How does rootless Podman work](https://opensource.com/article/19/2/how-does-rootless-podman-work)

## Design choices

Some design choices are owed to the circumstance that uids and gids
are limited datatypes. The Linux Kernel and userland defines
``uid_t`` and ``gid_t`` as unsigned 32bit integers (``uint32_t``), which
limits possible values for numeric user and group ids to
``0 .. 2^32-2``. ``(uid_t)-1`` is reserved for error reporting. On the
other hand the user ``nobody`` typically has uid 65534 / gid 65534. This
means we need to assign 65,536 subordinate ids to every user. The
theoretical maximum amount of subordinate ranges is less than 65,536
(``65536 * 65536 == 2^32``). [``logins.def``](https://man7.org/linux/man-pages/man5/login.defs.5.html)
also uses 65536 as default setting for ``SUB_UID_COUNT``.

The practical limit is far smaller. Subordinate ids should not overlap
with system accounts, local user accounts, IPA user accounts, and
mapped accounts from Active Directory. Therefore IPA uses the upper
half of the uid_t range (>= 2^31 == 2,147,483,648) for subordinate ids.
The high bit is rarely used. IPA limits general numeric ids
(``uidNumber``, ``gidNumber``, ID ranges) to maximum values of signed
32bit integer (2^31-1) for backwards compatibility with XML-RPC.
``logins.def`` defaults to ``SUB_UID_MAX`` 600,100,000.

A default subordinate id count of 65,536 and a total range of approx.
2.1 billion limits IPA to slightly more than 32,000 possible ranges. It
may sound like a lot of users, but there are much bigger installations
of IPA. For comparison Fedora Accounts has over 120,000 users stored in
IPA.

For that reason we treat subordinate id space as premium real estate
and don't auto-map or auto-assign subordinate ids by default. Instead
we give the admin several options to assign them manually, semi-manual,
or automatically.

### Revision 1 limitation

The first revision of the feature is deliberately limited and
restricted. We are aiming for a simple implementation that covers
basic use cases. Some restrictions may be lifted in the future.

* subuid and subgids cannot be set independently. They are always set
  to the same value.
* counts are hard-coded to value 65536
* once assigned subids cannot be removed
* IPA does not support multiple subordinate id ranges. Contrary to
  ``/etc/subuid``, users are limited to one set of subordinate ids.
* subids are auto-assigned. Auto-assignment is currently emulated
  until 389-DS has been extended to support DNA with step interval.
* subids are allocated from hard-coded range
  ``[2147483648..4294901767]`` (``2^31`` to ``2^32-1-65536``), which
  is the upper 2.1 billion uids of ``uid_t`` (``uint32_t``). The range
  can hold little 32,767 subordinate id ranges.
* Active Directory support is out of scope and may be provided in the
  future.

### Subid assignment example

```
>>> import itertools
>>> def subids():
...     for n in itertools.count(start=0):
...         start = SUBID_RANGE_START + (n * SUBID_COUNT)
...         last = start + SUBID_COUNT - 1
...         yield (start, last)
...
>>> gen = subids()
>>> next(gen)
(2147483648, 2147549183)
>>> next(gen)
(2147549184, 2147614719)
>>> next(gen)
(2147614720, 2147680255)
```

The first user has 65565 subordinate ids from uid/gid ``2147483648``
to ``2147549183``, the next user has ``2147549184`` to ``2147614719``,
and so on. The range count includes the start value.

An installation with multiple servers, 389-DS'
[DNA](https://directory.fedoraproject.org/docs/389ds/design/dna-plugin.html)
plug-in takes care of delegating and assigning chunks of subid ranges
to servers. The DNA plug-in guarantees uniqueness across servers.

## LDAP

### LDAP schema extension

The subordinate id feature introduces a new auxiliar object class
``ipaSubordinateId`` with four required attributes ``ipaSubUidNumber``,
``ipaSubUidCount``, ``ipaSubGidNumber``, and ``ipaSubGidCount``. The
attributes with ``number`` suffix store the start value of the interval.
The ``count`` attributes contain the size of the interval including the
start value. The maximum subid is
``ipaSubUidNumber + ipaSubUidCount - 1``.

All four attributes are single-value ``INTEGER`` type with standard
integer matching rules. OIDs ``2.16.840.1.113730.3.8.23.8`` and
``2.16.840.1.113730.3.8.23.11`` are reserved for future use.

```raw
attributeTypes: (
  2.16.840.1.113730.3.8.23.6
  NAME 'ipaSubUidNumber'
  DESC 'Numerical subordinate user ID (range start value)'
  EQUALITY integerMatch ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
attributeTypes: (
  2.16.840.1.113730.3.8.23.7
  NAME 'ipaSubUidCount'
  DESC 'Subordinate user ID count (range size)'
  EQUALITY integerMatch ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
attributeTypes: (
  2.16.840.1.113730.3.8.23.9
  NAME 'ipaSubGidNumber'
  DESC 'Numerical subordinate group ID (range start value)'
  EQUALITY integerMatch ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
attributeTypes: (
  2.16.840.1.113730.3.8.23.10
  NAME 'ipaSubGidCount'
  DESC 'Subordinate group ID count (range size)'
  EQUALITY integerMatch ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
```

The ``ipaSubordinateId`` object class is an auxiliar subclass of
``top`` and requires all four subordinate id attributes as well as
``uidNumber``. It does not subclass ``posixAccount`` to make
the class reusable in idview overrides later.

```raw
objectClasses: (
  2.16.840.1.113730.3.8.24.4
  NAME 'ipaSubordinateId'
  DESC 'Subordinate uid and gid for users'
  SUP top AUXILIARY
  MUST ( uidNumber $ ipaSubUidNumber $ ipaSubUidCount $ ipaSubGidNumber $ ipaSubGidCount )
  X-ORIGIN 'IPA v4.9'
)
```

The ``ipaSubordinateGid`` and ``ipaSubordinateUid`` are defined for
future use. IPA always assumes the presence of ``ipaSubordinateId`` and
does not use these object classes.

```raw
objectClasses: (
  2.16.840.1.113730.3.8.24.2
  NAME 'ipaSubordinateUid'
  DESC 'Subordinate uids for users, see subuid(5)'
  SUP top AUXILIARY
  MUST ( uidNumber $ ipaSubUidNumber $ ipaSubUidCount )
  X-ORIGIN 'IPA v4.9'
 )
objectClasses: (
  2.16.840.1.113730.3.8.24.3
  NAME 'ipaSubordinateGid'
  DESC 'Subordinate gids for users, see subgid(5)'
  SUP top AUXILIARY
  MUST ( uidNumber $ ipaSubGidNumber $ ipaSubGidCount )
  X-ORIGIN 'IPA v4.9'
)
```

### Index

The attributes ``ipaSubUidNumber`` and ``ipaSubGidNumber`` are index
for ``pres`` and ``eq`` with ``nsMatchingRule: integerOrderingMatch``
to enable efficient ``=``, ``>=``, and ``<=`` searches.

### Distributed numeric assignment (DNA) plug-in extension

Subordinate id auto-assignment requires an extension of 389-DS'
[DNA](https://directory.fedoraproject.org/docs/389ds/design/dna-plugin.html)
plug-in. The DNA plug-in is responsible for safely assigning unique
numeric ids across all replicas.

Currently the DNA plug-in only supports a step size of ``1``. A new
option ``dnaStepAttr`` (name is tentative) will tell the DNA plug-in
to use the value of entry attributes as step size.


## Permissions, Privileges, Roles

### Self-servive RBAC

The self-service permission enables users to request auto-assignment
of subordinate uid and gid ranges for themselves. Subordinate ids cannot
be modified or deleted.

* ACI: *selfservice: Add subordinate id*
* Permission: *Self-service subordinate ID*
* Privilege: *Subordinate ID Selfservice User*
* Role: *Subordinate ID Selfservice Users*
* role default member: n/a

### Administrator RBAC

The administrator permission allows privileged users to auto-assign
subordinate ids to users. Once assigned subordinate ids cannot
be modified or deleted.

* ACI: *Add subordinate ids to any user*
* Permission: *Manage subordinate ID*
* Privilege: *Subordinate ID Administrators*
* default privilege role: *User Administrator*


## Workflows

In the default configuration of IPA, neither existing users nor new
users will have subordinate ids assigned. There are a couple of ways
to assign subordinate ids to users.

### User administrator

Users with *User Administrator* role and members of the *admins* group
have permission to auto-assign new subordinate ids to any user. Auto
assignment can be performed with new ``user-auto-subid`` command on the
command line or with the *Auto assign subordinate ids* action in the
*Actions* drop-down menu in the web UI.

```shell
$ ipa user-auto-subid someusername
```

### Self-service for group members

Ordinary users cannot self-service subordinate ids by default. Admins
can assign the new *Subordinate ID Selfservice User* to users group to
enable self-service for members of the group.

For example to enable self-service for all members of the default user
group ``ipausers``, do:

```shell
$ ipa role-add-member "Subordinate ID Selfservice User" --groups=ipausers
```

This allows members of ``ipausers`` to request subordinate ids with
the ``user-auto-subid`` command or the *Auto assign subordinate ids*
action in the web UI.

```shell
$ ipa user-auto-subid myusername
```

### Auto assignment with user default object class

Admins can also enable auto-assignment of subordinate ids for all new
users by adding ``ipasubordinateid`` as a default user objectclass.
This can be accomplished in the web UI under "IPA Server" /
"Configuration" / "Default user objectclasses" or on the command line
with:

```shell
$ ipa config-mod --addattr="ipaUserObjectClasses=ipasubordinateid"
```

**NOTE:** The objectclass must be written all lower case.

### ipa-subid tool

Finally IPA includes a new tool for mass-assignment of subordinate ids.
The command uses automatic LDAPI EXTERNAL bind when it's executed as
root user. Other it requires valid Kerberos TGT of an admin or user
administrator.

```raw

# /usr/libexec/ipa/ipa-subids --help
Usage: ipa-subids

Mass-assign subordinate ids

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  --group=GROUP         Filter by group membership
  --filter=USER_FILTER  Raw LDAP filter
  --dry-run             Dry run mode.
  --all-users           All users

  Logging and output options:
    -v, --verbose       print debugging information
    -d, --debug         alias for --verbose (deprecated)
    -q, --quiet         output only errors
    --log-file=FILE     log to the given file

# # /usr/libexec/ipa/ipa-subids --group ipausers
Processing user 'testsubordinated1' (1/15)
Processing user 'testsubordinated2' (2/15)
Processing user 'testsubordinated3' (3/15)
Processing user 'testsubordinated4' (4/15)
Processing user 'testsubordinated5' (5/15)
Processing user 'testsubordinated6' (6/15)
Processing user 'testsubordinated7' (7/15)
Processing user 'testsubordinated8' (8/15)
Processing user 'testsubordinated9' (9/15)
Processing user 'testsubordinated10' (10/15)
Processing user 'testsubordinated11' (11/15)
Processing user 'testsubordinated12' (12/15)
Processing user 'testsubordinated13' (13/15)
Processing user 'testsubordinated14' (14/15)
Processing user 'testsubordinated15' (15/15)
Processed 15 user(s)
The ipa-subids command was successful
```

### Find and match users by any subordinate id

The ``user-find`` command search by start value of subordinate uid and
gid range. The new command ``user-match-subid`` can be used to find a
user by any subordinate id in their range.

```raw
$ ipa user-match-subid --subuid=2153185287
  User login: asmith
  First name: Alice
  Last name: Smith
  ...
  SubUID range start: 2153185280
  SubUID range size: 65536
  SubGID range start: 2153185280
  SubGID range size: 65536
----------------------------
Number of entries returned 1
----------------------------
$ ipa user-match-subid --subuid=2153185279
  User login: bjones
  First name: Bob
  Last name: Jones
  ...
  SubUID range start: 2153119744
  SubUID range size: 65536
  SubGID range start: 2153119744
  SubGID range size: 65536
----------------------------
Number of entries returned 1
----------------------------
```

## SSSD integration

* base: ``cn=accounts,$SUFFIX`` / ``cn=users,cn=accounts,$SUFFIX``
* scope: ``SCOPE_SUBTREE`` (2) / ``SCOPE_ONELEVEL`` (1)
* user filter: should include ``(objectClass=posixAccount)``
* attributes: ``uidNumber ipaSubUidNumber ipaSubUidCount ipaSubGidNumber ipaSubGidCount``

SSSD can safely assume that only *user accounts* of type ``posixAccount``
have subordinate ids. In the first revision there are no other entries
with subordinate ids. The ``posixAccount`` object class has ``uid``
(user login name) and ``uidNumber`` (numeric user id) as mandatory
attributes. The ``uid`` attribute is guaranteed to be unique across
all user accounts in an IPA domain.

The ``uidNumber`` attribute is commonly unique, too. However it's
technically possible that an administrator has assigned the same
numeric user id to multiple users. Automatically assigned uid numbers
don't conflict. SSSD should treat multiple users with same numeric
user id as an error.

The attribute ``ipaSubUidNumber`` is always accompanied by
``ipaSubUidCount`` and ``ipaSubGidNumber`` is always accompanied
by ``ipaSubGidCount``. In revision 1 the presence of
``ipaSubUidNumber`` implies presence of the other three attributes.
All four subordinate id attributes and ``uidNumber`` are single-value
``INTEGER`` types. Any value outside of range of ``uint32_t`` must
treated as invalid. SSSD will never see the DNA magic value ``-1``
in ``cn=accounts,$SUFFIX`` subtree.

IPA recommends that SSSD simply extends its existing query for user
accounts and requests the four subordinate attributes additionally to
RFC 2307 attributes ``rfc2307_user_map``. SSSD can directly take the
values and return them without further processing, e.g.
``uidNumber:ipaSubUidNumber:ipaSubUidCount`` for ``/etc/subuid``.

Filters for additional cases:

* subuid filter (find user with subuid by numeric uid):
  ``&((objectClass=posixAccount)(ipaSubUidNumber=*)(uidNumber=$UID))``,
  ``(&(objectClass=ipaSubordinateId)(uidNumber=$UID))``, or similar
* subuid enumeration filter:
  ``&((objectClass=posixAccount)(ipaSubUidNumber=*)(uidNumber=*))``,
  ``(objectClass=ipaSubordinateId)``, or similar
* subgid filter (find user with subgid by numeric uid):
  ``&((objectClass=posixAccount)(ipaSubGidNumber=*)(uidNumber=$UID))``,
  ``(&(objectClass=ipaSubordinateId)(uidNumber=$UID))``, or similar
* subgid enumeration filter:
  ``&((objectClass=posixAccount)(ipaSubGidNumber=*)(uidNumber=*))``,
  ``(objectClass=ipaSubordinateId)``, or similar

## Implementation details

* The four subid attributes are not included in
  ``baseuser.default_attributes`` on purpose. The ``config-mod``
  command does not permit removal of a user default objectclasses
  when the class is the last provider of an attribute in
  ``default_attributes``.
* ``ipaSubordinateId`` object class does not subclass the other two
  object classes. LDAP supports
  ``SUP ( ipaSubordinateGid $ ipaSubordinateUid )`` but 389-DS only
  auto-inherits from first object class.
* The idrange entry ``$REALM_subid_range`` has preconfigured base RIDs
  and SID so idrange plug-in and sidgen task ignore the entry. It's the
  simplest approach to ensure backwards compatibility with older IPA
  server versions that don't know how to handle the new range.
  The SID is ``S-1-5-21-738065-838566-$DOMAIN_HASH``. ``S-1-5-21``
  is the well-known SID prefix for domain SIDs.  ``738065-838566`` is
  the decimal representation of the string ``IPA-SUB``. ``DOMAIN_HASH``
  is the MURMUR-3 hash of the domain name for key ``0xdeadbeef``. SSSD
  rejects SIDs unless they are prefixed with ``S-1-5-21`` (see
  ``sss_idmap.c:is_domain_sid()``).
* The new ``$REALM_subid_range`` entry uses range type ``ipa-ad-trust``
  instead of range type ``ipa-local-subid`` for backwards compatibility
  with older SSSD clients, see
  [SSSD #5571](https://github.com/SSSD/sssd/issues/5571).
* Shared DNA configuration entries in ``cn=dna,cn=ipa,cn=etc,$SUFFIX``
  are automatically removed by existing code. Server and replication
  plug-ins search and delete entries by ``dnaHostname`` attribute.

### TODO

* enable configuration for ``dnaStepAttr``
* remove ``fake_dna_plugin`` hack from ``baseuser`` plug-in.
* add custom range type for idranges and teach AD trust, sidgen, and
  range overlap check code to deal with new range type.
