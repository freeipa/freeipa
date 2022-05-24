# Central management of subordinate user and group ids

Subordinate ids are a Linux Kernel feature to grant a user additional
user and group id ranges. Amongst others the feature can be used
by container runtime engines to implement rootless containers.
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
* counts are hard-coded to value 65536.
* once assigned subids cannot be removed.
* IPA does not support multiple subordinate id ranges, yet. Contrary to
  ``/etc/subuid``, users are limited to one set of subordinate ids. The
  limitation is implemented with a unique index on owner reference and
  can be lifted in the future.
* subids are auto-assigned from 389-DS DNA plugin (dnaInterval).
* subids are allocated from hard-coded range
  ``[2147483648..4294901767]`` (``2^31`` to ``2^32-1-65536``), which
  is the upper 2.1 billion uids of ``uid_t`` (``uint32_t``). The range
  can hold little 32,767 subordinate id ranges.
* Active Directory support is out of scope and may be provided in the
  future.


Finally, it is important to note that new installations come with a new
idrange for subordinate ids. The new ``$REALM_subid_range`` entry uses
range type ``ipa-ad-trust`` instead of range type ``ipa-local-subid``
for backwards compatibility with older SSSD clients, see [SSSD #5571](https://github.com/SSSD/sssd/issues/5571).

```text
dn: cn=TESTREALM.TEST_subid_range,cn=ranges,cn=etc,dc=testrealm,dc=test
objectClass: top
objectClass: ipaIDrange
objectClass: ipaTrustedADDomainRange
cn: TESTREALM.TEST_subid_range
ipaBaseID: 2147483648
ipaIDRangeSize: 2147352576
ipaBaseRID: 2147283648
ipaNTTrustedDomainSID: S-1-5-21-738065-838566-1351619967
ipaRangeType: ipa-ad-trust
```

The additional idrange entry is defined as: ``cn=$REALM_subid_range,cn=ranges,cn=etc,dc=ipa,dc=test``,
which is visible with ``ipa idrange-find``.


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
``ipaSubordinateId`` with five required attributes ``ipaOwner``,
``ipaSubUidNumber``, ``ipaSubUidCount``, ``ipaSubGidNumber``, and
``ipaSubGidCount``. The attributes with ``number`` suffix store the
start value of the interval. The ``count`` attributes contain the
size of the interval including the start value. The maximum subid is
``ipaSubUidNumber + ipaSubUidCount - 1``. The ``ipaOwner`` attribute
is a reference to the owning user.

All count and number attributes are single-value ``INTEGER`` type with
standard integer matching rules. OIDs ``2.16.840.1.113730.3.8.23.8`` and
``2.16.840.1.113730.3.8.23.11`` are reserved for future use.

```text
attributeTypes: (
  2.16.840.1.113730.3.8.23.7
  NAME 'ipaSubUidNumber'
  DESC 'Numerical subordinate user ID (range start value)'
  EQUALITY integerMatch ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
attributeTypes: (
  2.16.840.1.113730.3.8.23.8
  NAME 'ipaSubUidCount'
  DESC 'Subordinate user ID count (range size)'
  EQUALITY integerMatch ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
attributeTypes: (
  2.16.840.1.113730.3.8.23.10
  NAME 'ipaSubGidNumber'
  DESC 'Numerical subordinate group ID (range start value)'
  EQUALITY integerMatch ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
attributeTypes: (
  2.16.840.1.113730.3.8.23.11
  NAME 'ipaSubGidCount'
  DESC 'Subordinate group ID count (range size)'
  EQUALITY integerMatch ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
```

The ``ipaOwner`` attribute is a single-value DN attribute that refers
to user entry that owns the subordinate ID entry. The proposal does not
reuse any of the existing attributes like ``owner`` or ``member``,
because they are all multi-valued.

```
attributeTypes: (
  2.16.840.1.113730.3.8.23.13
  NAME 'ipaOwner'
  DESC 'Owner of an entry'
  SUP distinguishedName
  EQUALITY distinguishedNameMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.9')
```

The ``ipaSubordinateId`` object class is an auxiliary subclass of
``top`` and requires all four subordinate id attributes as well as
``ipaOwner`` attribute``

```text
objectClasses: (
  2.16.840.1.113730.3.8.24.4
  NAME 'ipaSubordinateId'
  DESC 'Subordinate uid and gid for users'
  SUP top
  AUXILIARY
  MUST ( ipaOwner $ ipaSubUidNumber $ ipaSubUidCount $ ipaSubGidNumber $ ipaSubGidCount )
  X-ORIGIN 'IPA v4.9'
)
```

The ``ipaSubordinateGid`` and ``ipaSubordinateUid`` are defined for
future use. IPA always assumes the presence of ``ipaSubordinateId``.

```text
objectClasses: (
  2.16.840.1.113730.3.8.24.2
  NAME 'ipaSubordinateUid'
  DESC 'Subordinate uids for users, see subuid(5)'
  SUP top
  AUXILIARY
  MUST ( ipaOwner $ ipaSubUidNumber $ ipaSubUidCount )
  X-ORIGIN 'IPA v4.9'
 )
objectClasses: (
  2.16.840.1.113730.3.8.24.3
  NAME 'ipaSubordinateGid'
  DESC 'Subordinate gids for users, see subgid(5)'
  SUP top
  AUXILIARY
  MUST ( ipaOwner $ ipaSubGidNumber $ ipaSubGidCount )
  X-ORIGIN 'IPA v4.9'
)
```

Subordinate id entries have the structural object class
``ipaSubordinateIdEntry`` and one or more of the auxiliary object
classes ``ipaSubordinateId``, ``ipaSubordinateGid``, or
``ipaSubordinateUid``. ``ipaUniqueId`` is used as a primary key (RDN).

```text
objectClasses: (
  2.16.840.1.113730.3.8.24.5
  NAME 'ipaSubordinateIdEntry'
  DESC 'Subordinate uid and gid entry'
  SUP top
  STRUCTURAL
  MUST ( ipaUniqueId ) MAY ( description ) X-ORIGIN 'IPA v4.9'
)
```

Finally, setting ``ipaUserDefaultSubordinateId`` to TRUE will cause
new user entries to gain subordinate id by default:

```text
attributeTypes: (
  2.16.840.1.113730.3.8.23.14
  NAME 'ipaUserDefaultSubordinateId'
  DESC 'Enable adding user entries with subordinate id'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.7
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.9'
)
```

### cn=subids,cn=accounts,$SUFFIX

Subordinate ids and ACIs are stored in the new subtree
``cn=subids,cn=accounts,$SUFFIX``.

The following is an example of a subordinate id entry:

```text
dn: ipauniqueid=8a7c0808-375b-4643-9582-e9c851a4b45d,cn=subids,cn=accounts,dc=
 testrealm,dc=test
ipaOwner: uid=asmith-auto,cn=users,cn=accounts,dc=testrealm,dc=test
ipaUniqueID: 8a7c0808-375b-4643-9582-e9c851a4b45d
description: auto-assigned subid
objectClass: ipasubordinateidentry
objectClass: ipasubordinateuid
objectClass: ipasubordinateid
objectClass: ipasubordinategid
objectClass: top
ipaSubUidCount: 65536
ipaSubGidCount: 65536
ipaSubUidNumber: 2147745792
ipaSubGidNumber: 2147745792
```

where as can be seen, it shows the link to the ipa user ``asmith-auto`` throught
the ipaOwner attribute:

```text
ipaOwner: uid=asmith-auto,cn=users,cn=accounts,dc=testrealm,dc=test
```

### Index, integrity, memberOf

The attributes ``ipaSubUidNumber`` and ``ipaSubGidNumber`` are index
for ``pres`` and ``eq`` with ``nsMatchingRule: integerOrderingMatch``
to enable efficient ``=``, ``>=``, and ``<=`` searches.

The attribute ``ipaOwner`` is indexed for ``pres`` and ``eq``. This DN
attribute is also checked for referential integrity and uniqueness
within the ``cn=subids,cn=accounts,$SUFFIX`` subtree. The memberOf
plugin creates back-references for ``ipaOwner`` references.


### Distributed numeric assignment (DNA) plug-in extension

Subordinate id auto-assignment requires an extension of 389-DS'
[DNA](https://directory.fedoraproject.org/docs/389ds/design/dna-plugin.html)
plug-in. The DNA plug-in is responsible for safely assigning unique
numeric ids across all replicas.

A new option ``dnaInterval`` will tell the DNA plug-in to use the value of
entry attributes as interval size.


## IPA plugins and commands

The config plugin has a new option to enable or disable generation of
subordinate id entries for new users:

```text
$ ipa config-mod --user-default-subid=true
```

Subordinate ids are managed by a new plugin class. The ``subid-add``
and ``subid-del`` commands are hidden from command line. New subordinate
ids are generated and auto-assigned with ``subid-generate``.

```text
$ ipa help subid
Topic commands:
  subid-find      Search for subordinate id.
  subid-generate  Generate and auto-assign subuid and subgid range to user entry
  subid-match     Match users by any subordinate uid in their range
  subid-mod       Modify a subordinate id.
  subid-show      Display information about a subordinate id.
  subid-stats     Subordinate id statistics
```

```text
$ ipa subid-generate --owner testuser
-----------------------------------------------------------
Added subordinate id "2cf2c0db-aa9d-45d8-acbd-118aba0c1db3"
-----------------------------------------------------------
  Unique ID: 2cf2c0db-aa9d-45d8-acbd-118aba0c1db3
  Description: auto-assigned subid
  Owner: testuser
  SubUID range start: 2147680256
  SubUID range size: 65536
  SubGID range start: 2147680256
  SubGID range size: 65536
```


```text
$ ipa subid-find --owner testuser
------------------------
1 subordinate id matched
------------------------
  Unique ID: 2cf2c0db-aa9d-45d8-acbd-118aba0c1db3
  Owner: testuser
  SubUID range start: 2147680256
  SubUID range size: 65536
  SubGID range start: 2147680256
  SubGID range size: 65536
----------------------------
Number of entries returned 1
----------------------------
```

```text
$ ipa -vv subid-stats
...
ipa: INFO: Response: {
    "error": null,
    "id": 0,
    "principal": "admin@TESTREALM.TEST",
    "result": {
        "result": {
            "assigned_subids": 1,
            "baseid": 2147483648,
            "dna_remaining": 65527,
            "rangesize": 2147352576,
            "remaining_subids": 0
        },
        "summary": "0 remaining subordinate id ranges"
    },
    "version": "4.9.9"
}
---------------------------------
0 remaining subordinate id ranges
---------------------------------
```

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

### Managed permissions

* *System: Read Subordinate Id Attributes* (all authenticated users)
* *System: Read Subordinate Id Count* (all authenticated usrs)
* *System: Manage Subordinate Ids* (User Administrators)
* *System: Remove Subordinate Ids* (User Administrators)


## Workflows

In the default configuration of IPA, neither existing users nor new
users will have subordinate ids assigned. There are a couple of ways
to assign subordinate ids to users.

### User administrator

Users with *User Administrator* role and members of the *admins* group
have permission to auto-assign new subordinate ids to any user. Auto
assignment can be performed with new ``subid-generate`` command on the
command line or with the *Auto assign subordinate ids* action in the
*Actions* drop-down menu in the web UI.

```shell
$ ipa subid-generate --owner myusername
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
the ``subid-generate`` command or the *Auto assign subordinate ids*
action in the web UI. The command picks the name of the current user
principal automatically.

```shell
$ ipa subid-generate
```

### ipa-subid tool

Finally IPA includes a new tool for mass-assignment of subordinate ids.
The command uses automatic LDAPI EXTERNAL bind when it's executed as
root user. Other it requires valid Kerberos TGT of an admin or user
administrator.

```text

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

# /usr/libexec/ipa/ipa-subids --group ipausers
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

The ``user-find`` command is now able to search for users matching a
particular subordinate id when using ``--in-subids`` option:

```text
$ ipa user-find --in-subids=8a7c0808-375b-4643-9582-e9c851a4b45d
--------------
1 user matched
--------------
  User login: asmith-auto
  First name: asmith
  Last name: auto
  Home directory: /home/asmith-auto
  Login shell: /bin/sh
  Principal name: asmith-auto@TESTREALM.TEST
  Principal alias: asmith-auto@TESTREALM.TEST
  Email address: asmith-auto@testrealm.test
  UID: 1242200006
  GID: 1242200006
  Account disabled: False
----------------------------
Number of entries returned 1
----------------------------
```

and search for users not matching a particular subordinate id when
using ``--not-in-subids`` option:

```text
$ ipa user-find --not-in-subids=8a7c0808-375b-4643-9582-e9c851a4b45d
--------------
1 user matched
--------------
  User login: bjones-auto
  First name: bjones
  Last name: auto
  Home directory: /home/bjones-auto
  Login shell: /bin/sh
  Principal name: bjones-auto@TESTREALM.TEST
  Principal alias: bjones-auto@TESTREALM.TEST
  Email address: bjones-auto@testrealm.test
  UID: 1242200007
  GID: 1242200007
  Account disabled: False
```

Additionally, the new command ``subid-match`` can be used to find a user
by any subordinate id in their range when using the ``--subuid`` option:


```text
$ ipa subid-match --subuid=2147745792
------------------------
1 subordinate id matched
------------------------
  Unique ID: 8a7c0808-375b-4643-9582-e9c851a4b45d
  Owner: asmith-auto
  SubUID range start: 2147745792
  SubUID range size: 65536
  SubGID range start: 2147745792
  SubGID range size: 65536
----------------------------
Number of entries returned 1
----------------------------
```

## SSSD integration

* search base: ``cn=subids,cn=accounts,$SUFFIX``
* scope: ``SCOPE_ONELEVEL`` (1)
* filter: ``(objectClass=ipaSubordinateId)``
* attributes: ``ipaOwner ipaSubUidNumber ipaSubUidCount ipaSubGidNumber ipaSubGidCount``

The attribute ``ipaSubUidNumber`` is always accompanied by
``ipaSubUidCount`` and ``ipaSubGidNumber`` is always accompanied
by ``ipaSubGidCount``. In revision 1 the presence of
``ipaSubUidNumber`` implies presence of the other three attributes.
All four subordinate id attributes are single-value ``INTEGER`` types.
Any value outside of range of ``uint32_t`` must treated as invalid.
SSSD will never see the DNA magic value ``-1`` in
``cn=accounts,$SUFFIX`` subtree. In revision 1 each user subordinate
id entry is assigned to exactly one user and each user has either 0
or 1 subid.

IPA recommends that SSSD uses LDAP deref controls for ``ipaOwner``
attribute to fetch ``uidNumber`` from the user object.

### Deref control example

```text
$ ldapsearch -L -E '!deref=ipaOwner:uid,uidNumber' \
      -b 'cn=subids,cn=accounts,dc=ipasubid,dc=test' \
      '(ipaOwner=uid=testuser10,cn=users,cn=accounts,dc=ipasubid,dc=test)'

dn: ipauniqueid=35c02c93-3799-4551-a355-ebbf042e431c,cn=subids,cn=accounts,dc=ipasubid,dc=test
# control: 1.3.6.1.4.1.4203.666.5.16 false MIQAAABxMIQAAABrBAhpcGFPd25lcgQ3dWlk
 PXRlc3R1c2VyMTAsY249dXNlcnMsY249YWNjb3VudHMsZGM9aXBhc3ViaWQsZGM9dGVzdKCEAAAAIj
 CEAAAAHAQJdWlkTnVtYmVyMYQAAAALBAk2MjgwMDAwMTE=
# ipaOwner: <uidNumber=628000011>;uid=testuser10,cn=users,cn=accounts,dc=ipasubid,dc=test

ipaOwner: uid=testuser10,cn=users,cn=accounts,dc=ipasubid,dc=test
ipaUniqueID: 35c02c93-3799-4551-a355-ebbf042e431c
description: auto-assigned subid
objectClass: ipasubordinateidentry
objectClass: ipasubordinategid
objectClass: ipasubordinateuid
objectClass: ipasubordinateid
objectClass: top
ipaSubUidNumber: 3434020864
ipaSubGidNumber: 3434020864
ipaSubUidCount: 65536
ipaSubGidCount: 65536
```

### Configure subid managed at IPA level

Starting in FreeIPA 4.10.0 release, ipa-client-install provides a new option that
allows to configure the client subid managed at IPA level. This way, ipa-client-install
can configure the sssd profile and customize /etc/nsswitch.conf in such a way the subid
database relies on IPA instead of both of the local files /etc/subuid and /etc/subgid.

It is important to note that the default behavior remains unchanged and ``--subid`` option
must be provided to the client, server and replica installers in order to have SSSD setup
as a datasource for subid in /etc/nsswitch.conf


## Implementation details

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
* ``ipaSubordinateId`` entries no longer contains ``uidNumber``
  attribute. I considered to use CoS plugin to provide ``uidNumber``
  as virtual attribute. However it's not possible to
  ``objectClass: cosIndirectDefinition`` with
  ``cosIndirectSpecifier: ipaOwner`` and
  ``cosAttribute: uidNumber override`` for the task. Indexes and
  searches don't work with virtual attributes.

### TODO

* add custom range type for idranges and teach AD trust, sidgen, and
  range overlap check code to deal with new range type.
* ipa subid-stats should include assigned_subids value as output, since
  the remaning_subids value is always seen as 0, its better to display
  assigned_subids as output for #ipa subid-stats which will be more useful
  ([RFE#2063176](https://bugzilla.redhat.com/show_bug.cgi?id=2063176))
* user-del --preserve and user-undel. Preserving a user with
  ``ipa user-del --preserve`` is possible however it deletes the
  associated subid, meaning that ``ipa user-undel <ipauser>``
  is not able to restore the subid of the deleted user ([RFE#2063168](https://bugzilla.redhat.com/show_bug.cgi?id=2063168)).
