# Identity Mapping

In FreeIPA deployments user and group objects get their POSIX identities (IDs)
assigned and managed in an automated way. This document describes how
identity mapping is performed and enforced in FreeIPA deployments.

## Overview

FreeIPA deployment has three major identity mapping elements:
- automated identifier assignment through LDAP
- automated identifier assignment through SSSD
- identity information consistency enforcement in LDAP and Kerberos KDC

POSIX identities are allocated to objects that need to be visible at run-time
in POSIX environment. These are typically POSIX users and groups but there are
some exceptions to these objects, to accomodate specialized use cases.

In POSIX environment user and group identities are properties of several
different objects. When login session is initiated, the login process is
started as root (ID 0) and during login flow at some point a switch to a
certain user ID is performed. User's primary group is associated with a process
and information about other groups a user is a member of is populated as
'secondary groups' of the process. During lifetime of the process these lists
are typically left intact and cannot be modified unless a process possesses
certain administrative capabilities.

Both user and group IDs in POSIX environment are represented by unsigned
integers. In Linux environment user and group ID spaces are separate and fit
into 32-bit unsigned integer since 2001. Due to historical reasons, some of
file formats might not support more than 16- or 15-bit unsigned integer spaces
for UID and GID values. FreeIPA environment assumes operations in a
contemporary environment, with 32-bit user and group IDs.

[Linux Standard Base](https://en.wikipedia.org/wiki/Linux_Standard_Base) Core
Specification defines certain reserved ID ranges. Some Linux distributions or
projects go beyond that and define own ID ranges. To avoid conflicts with these
ranges, FreeIPA defines its own default ID ranges above 16-bit space.

For interoperability purposes a mapping between POSIX and non-POSIX identities
has to be established. The only supported non-POSIX identities for which there
exists a well defined mapping mechanism are identities represented with the
help of Security IDentifiers (SIDs) from Active Directory.

## Identity ranges

Each POSIX identity issued by the FreeIPA server is generated within a certain
identity range. ID ranges serve several purposes: they help multiple
FreeIPA components to coordinate identity allocation and convey details of the
purpose of the allocated identity ranges.

ID ranges are stored in LDAP, under `cn=ranges,cn=etc,$BASEDN` subtree. LDAP
objects for ID ranges are based on the `ipaidrange` objectclass. Depending on
the type of the range, other objectclasses might be added to express additional
attributes.

As of FreeIPA 4.11, there are following ID range categories in FreeIPA:

- local FreeIPA POSIX ID range (`ipa-local` ID range type)
- POSIX ID range for local subordinate identities (`ipa-ad-trust`)
- trusted domain ID range using automated allocation based on SID of an object (`ipa-ad-trust`)
- trusted domain ID range using explicit allocation for POSIX identities (`ipa-ad-trust-posix`)

These four categories expressed using three ID range types for technical reasons.

More ID ranges can be added through the lifetime of the deployment to
accomodate administrative needs. The main requirement for these additional
ranges is to not overlap with existing ranges. Range consistency is controlled
with the help of a specialized plugin to 389-ds LDAP server, `ipa-range-check`.
When a new range conflicts with existing configuration, its acceptance will be
refused and an LDAP error `LDAP_CONSTRAINT_VIOLATION` will be returned. This
ensures all ranges are in consistent state.

Trusted domain ID ranges have information about the domain SID of the
associated domain stored directly in the range LDAP object. For the local
domain ID ranges this information is stored elsewhere because only a single
organizational domain (as opposed to DNS domains) can be present in IPA
deployment.

Information about SID and other parameters of the local domain is stored in the
LDAP object `cn=<domain>,cn=ad,cn=etc,$SUFFIX`. This information is used for ID
mapping enforcement purposes by SID generation plugin and Kerberos KDC driver.

Information about SID and other parameters of a trusted domain is stored in the
LDAP object `cn=<domain>,cn=ad,cn=trusts,$SUFFIX`. It is used by the Kerberos
KDC driver when processing Kerberos requests.

### Local FreeIPA POSIX ID range

Each FreeIPA deployment has its own primary (or local) POSIX ID range. The
range is chosen during an initial server deployment and cannot be changed.
Initial `admin` user and associated groups (e.g. `admins`) are all allocated
from this range. The range size defaults to 200000 identities but both starting
point and the size of the range can be modified with `ipa-server-install`
options.

The primary ID range corresponds to the DNA range also created during the
initial IPA server deployment. When replica is deployed, this ID range already
exists in the topology and is visible to the replica. However, a corresponding
slice of the DNA range will not be created on the replica until the DNA plugin
on the replica is not asked to allocate an ID. See `Automated Identifier Assignment Through LDAP`_
section for details how DNA ranges are used.

### POSIX ID range for local subordinate identities

Subordinate identities are a Linux Kernel feature to grant a user additional
user and group ID ranges. Amongst others, the feature can be used by container
runtime engines to implement rootless containers. Traditionally subordinate ID
ranges are configured in `/etc/subuid` and `/etc/subgid`. More details about
subordinate ranges can be found in ["Subordinate IDs"](subordinate-ids.html)
design page.

Due to a technical use of a trusted domain type to represent ID range of the
local subordinate identities, the ID range has a domain SID associated with it.
The SID has a special structure: `S-1-5-21-738065-838566-$DOMAIN_HASH`.
`S-1-5-21` is the well-known SID prefix for domain SIDs.  `738065-838566`
is the representation of the string `IPA-SUB`. `DOMAIN_HASH` is the
[MURMUR-3](https://en.wikipedia.org/wiki/MurmurHash) hash of the domain name
for key `0xdeadbeef`. SSSD rejects SIDs unless they are prefixed with
`S-1-5-21`. This SID is never used for any SID generation.

### Trusted domain ID range using automated allocation based on SID of an object

Active Directory environment does not use itself any POSIX identities because
they have no meaning within the context of Windows operating system. Each
object in Active Directory has associated security identifier (SID). SIDs stay
the same for the lifetime of the object and never re-used by other objects. SID
can be used to map an object in Active Directory to POSIX environment.

There are several methods to map SIDs to POSIX IDs. FreeIPA relies on an
algorithmic method provided by SSSD. The algorithm is described in
[sssd-ad(5) manual page](https://manpages.org/sssd-ad/5) in the section
"Mapping algorithm".

On start-up, SSSD looks up all ID ranges from the active IPA server and uses
information about trusted domains to map between SIDs and POSIX IDs. This
avoids static allocation of identities in LDAP. Instead, ID ranges in
FreeIPA serve as fences, to prevent other allocators from using these ranges
for static allocation.

For each trusted domain, a separate ID range is created since every trusted
domain has unique domain SID. Each ID range will have own POSIX ID range
allocation. These allocations can be created automatically during `ipa
trust-add` operation or ID ranges can be pre-created in advance with `ipa
idrange-add` operation. The latter is useful when there is a need to explicitly
define specific POSIX ID range boundaries as `ipa trust-add` command only
allows to define a new range's size.


### Trusted domain ID range using explicit allocation for POSIX identities

In case there is already existing static mapping of POSIX identities in Active
Directory, one can explicitly define ID range assocated with the trust to
Active Directory to handle explicit allocation. In this case SSSD will not use
algorithmic method but instead will look up identities from LDAP entry (e.g.
`uidNumber` and `gidNumber` attributes).

In case of explicit allocation, ID range associated with the trusted forest
Active Directory root domain must have ID range type of `ipa-ad-trust-posix`,
as well as all other domains visible through the trust link.

## ID range allocation

During deployment FreeIPA takes a random ID range slice from `(1,10000)` and
multiplies the base offset by 200000. This base becomes a starting point for
the deployment's ID range.

Both starting point and size of the range can be overridden by an administrator
who deploys the initial server. The minimal value for the initial ID range
start cannot be less than `UID_MAX` or `GID_MAX` from `/etc/login.defs`. This
range is then used by all systems enrolled into the domain managed by this
initial server.

Thus, a default range that FreeIPA chooses the deployment ID range from is
200000...2000000000. If this is a single domain and amount of users in it is
not going to be above 200K, then FreeIPA administrators may never need to
allocate another ID range within 200000...2000000000 and that original ID range
stays fixed forever.

There are two other use cases:

 - trusting another IPA or AD deployment, and

 - migrating pre-existing deployment not based on IPA.

When there are multiple organizational domains around and they need to
interoperate (establish trust between them), additional ID ranges get added on
the consuming side to represent trusted domain(s). For a trusted domain that is
an Active Directory, there would be two possibilities, managed within SSSD and
IPA:

 - an ID range is implicit, defined through a murmurhash3 hash of the domain
   SID,

 - an ID range is explicit, defined by the admin as UID/GID values stored in AD
   LDAP user entries for each user. The explicitly defined ID ranges most
   likely are part of a legacy setup and most likely are within `UID_MAX` and
   `GID_MAX` values from `/etc/login.defs`. There are exceptions, of course.

An implicit ID range derivation by SSSD is described in `sssd-ad(5)`, section 'ID
Mapping'. Samba has own way to derive similar ID ranges based on different
properties of the domain SID, handled by individual `idmap` modules but
conceptually it is similar: a rule is chosen to map those properties to POSIX
IDs and a map is maintained, algorithmically or based on a stored mapping in
Samba's own ID database.

With Active Directory environments all domain objects have their own unique
identifier, in the form of a SID. RID value of the SID is never reused when
objects get deleted and added. This means that for a company with an Active
Directory domain of ~20-25 years and large churn of employees over that time it
is not uncommon to see RIDs above 200K. For such deployments an ID range
SSSD and IPA would need to synthesize on Linux side would have size larger than
200K.

Thus ID range landscape is 'dynamic'. At a given time SSSD on the client will
be able to see all the ID ranges defined within the domain they enrolled into.
When a new trust is established and a new ID range for that trusted domain is
added, SSSD on the client will see this new ID range and will be able to derive
user/group IDs automatically for them. Most likely there are no existing files
on the client with ownership for these IDs yet -- except networking file
systems but for those to be usable at least one system should be able to create
those files with those POSIX IDs on a compatible client.

Existing ranges never change, LDAP plugins provided by FreeIPA prevent
modifying existing ranges in IPA or delete them if there are users/groups
with IDs assigned from those ID ranges.

## Automated identifier assignment through LDAP

When algorithmic ID range is used, SSSD only maps existing users and groups
coming from trusted Active Directory domains and those so based on their SID
values. For all other range types allocation of POSIX IDs is done in advance,
typically when user or group is created or moved from staged/preserved state.

This automated allocation is done with the help of [Distributed Numeric
Assignment (DNA) plugin](https://access.redhat.com/documentation/en-us/red_hat_directory_server/11/html/administration_guide/dna)
in 389-ds LDAP server. DNA plugin has its own identity ranges and provides a
generic mechanism to assign identities to various objects across the whole LDAP
topology. During installation of the original IPA server a DNA range is created
to match the primary IPA ID range. When new replicas added to IPA topology,
their DNA plugins become aware of the overal DNA range and may ask for a
sub-set of it for own needs. This sub-allocation only happens when DNA plugin
needs a range to allocate an ID. For example, when a user or a group is created
on that replica.

Since DNA ranges only get splitted and not extended automatically, IPA ID
ranges aren't tracking changes in DNA ranges. However, if somebody adds new DNA
ranges outside of the original primary IPA ID range, then a corresponding IPA
ID range needs to be created manually. This affects a lot of legacy deployments
where no real control over use of POSIX IDs through static allocation was done.

Another automatic ID assignment happens for SIDs. For each object in LDAP that
has POSIX attributes and `ipaNTUserAttrs` or `ipaNTGroupAttrs` object classes
upon creation a SID is generated by the `ipa-sidgen` 389-ds plugin. The SID is
stored in `ipaNTSecurityIdentifier` attribute. There is also another plugin,
`ipa-sidgen-task`, which handles a task of generating of SIDs for existing
objects. Both plugins issue error messages in the 389-ds error log in case they
were unable to map POSIX ID to a SID.

## ID mapping adjustments using ID overrides

On top of automatically or algorithmically allocated POSIX IDs, administrators
have possiblity to adjust POSIX IDs locally for users and groups coming from
trusted Active Directory domains. The same mechanism can also be used for
adjustments of POSIX IDs on individual IPA clients (or groups of IPA clients)
for legacy compatibility. These mechanisms should not be used for IPA users and
groups in general case because they might break certain assumptions in SSSD and
Kerberos KDC driver.

For users and groups from trusted Active Directory domains, ID overrides in
"Default Trust View" are used by SSSD on IPA server to override any ID
retrieved from the trusted domain controler side or generated algorithmically.
This mechanism allows to migrate pre-defined POSIX IDs from Active Directory by
creating ID overrides for individual users and groups.

From SSSD point of view, these ID overrides represent `uidNumber` and
`gidNumber` attributes as if they were specified in the original LDAP object
entry.

IPA users and groups cannot have ID overrides in the "Default Trust View".
Their POSIX IDs have to be present in their own LDAP object entries.

## Security IDentifiers

While primary goal of FreeIPA is to serve identities for POSIX environment, a
large effort is put into making interoperability with other identity management
systems, out of which Active Directory is the most important one. Active
Directory is using a different method to control access to their resources than
POSIX environment and this method extends from identity management to
authorization mechanisms. It is also has visible effects on various protocols
through which FreeIPA interoperability with Active Directory is achieved.

One of the corner stones of Active Directory security model is the [security
identifier (SID)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25)
assignment to each object in Active Directory that can be used for security
evaluation. Objects grouped by Active Directory domains, each domain having a
domain SID and all objects within the same domain have their SIDs starting with
the SID of the domain. The relative identifier (RID) is the unique identity of
an object within the domain scope. A full object SID, thus, is a combination of
the `<domain-SID>-<object RID>`.

Since objects are unique within the domain, RIDs can be reused in different
domains. There are common, so-called ['well-known'
identifiers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab),
which express the same functional objects in different domains. These
well-known objects have the same RID values but still be distinct: Objects from
`domain1.test` and `domain2.test` with the same RID values will be different.
For example, domain administrator user `Administrator` has RID value 500.
`Administrator` user from `domain1.test` would be different from
`Administrator` user from `domain2.test`, even though their individual RIDs
(500) would be the same. If `domain1.test` has SID `S-1-5-21-123-45-6789` and
`domain2.test` has SID `S-1-5-21-54-321-6789` then `Administrator` user from
`domain1.test` would have SID `S-1-5-21-123-45-6789-500` and `Administrator`
user from `domain2.test` would have SID `S-1-5-21-54-321-6789-500`.

Internally Active Directory does only use user and group names to perform
translation to a SID. Once SID of the object who authenticated the connection
is established, names don't matter anymore. For each authenticated object
within a specific connection a special security token is built which contains
this object's membership information in form of SIDs of groups it belongs to.
Access control lists attached to Active Directory objects contain SIDs as well,
making access control evaluation straightforward: security token SID details
evaluated against access control lists to grant or deny access.

This model is loosely similar to how processes in POSIX environment get
evaluated when accessing resources. Each POSIX process has user identity it is
running under, with a set of primary and secondary groups associated with the
identity as part of the process description. The difference is that POSIX UID
and GID values exist only on a single machine and a care to avoid conflicts
between multiple systems should be taken. In Active Directory model the SIDs
are already bearing domain-specific information, hence allowing to distinguish
objects belonging to different systems. The latter means for both networking
and local resources such as file systems a single access control list mechanism
can be used to address both remote and local identities.

Since SIDs do not exist in POSIX environment, mapping of objects from trusted
Active Directory domains to POSIX environment within IPA deployment is based on
other properties. In particular, a fully-qualified user or group name is used
to represent the user (or group): a user Administrator from `domain1.test`
would have a fully-qualified name `Administrator@domain1.test`, different from
the user Administrator of the domain `domain2.test` which would have a
fully-qualified name of `Administrator@domain2.test`.

Above description uses so-called user principal name (UPN) notation to describe
user names. In this notation a user name corresponds to a (case-insensitive)
Kerberos principal name. Since each Active Directory domain is a Kerberos
realm, this allows to establish mapping between identities on POSIX and Active
Directory levels through Kerberos authorization mechanism.

Active Directory has extended Kerberos protocol by adding a privilege
attributes certificate (PAC) information to the Kerberos ticket issued by
Active Directory domain controllers. The PAC part contains the security token
details of the authenticated object represented by the Kerberos principal.
These details are protected by a set of security checksums that prevent
external modifications to the PAC content. This information is detailed in the
[MS-PAC] and [MS-KILE] specifications Microsoft has published and Open Source
projects such as MIT Kerberos, Heimdal Kerberos, Samba, and FreeIPA have since
implemented.

## Enforcement of ID mapping

For trusted domains using Kerberos protocol to establish trust, a duty to
validate information falls onto Kerberos KDCs of each realm. FreeIPA KDCs
re-assess content of the presented Kerberos tickets and validate PAC issued by
a trusted domain's domain controller. This validation includes checks to make
sure only SIDs from trusted domains can be present there and a trusted domain's
KDC cannot inject SIDs that belong to IPA domain.

The latter is needed because both sides of the trust possess a key that
represents a cross-realm service principal, `krbtgt/DOMAIN1.TEST@DOMAIN2.TEST`.
This key allows KDC from `DOMAIN1.TEST` realm to issue a service ticket that a
client from `DOMAIN1.TEST` can present to a KDC from `DOMAIN2.TEST` to request
a service ticket for a service from `DOMAIN2.TEST`. If a KDC from
`DOMAIN1.TEST` goes rogue and decides to inject SIDs of groups from
`DOMAIN2.TEST` into a security token of the user from `DOMAIN1.TEST`, nothing
can stop it. Thus, a KDC from `DOMAIN2.TEST` must validate that a token encoded
in the PAC buffer of the Kerberos ticket coming from the `DOMAIN1.TEST` is
'sane'.

Sanity checks performed by the KDC in FreeIPA include multiple steps. For each
trusted domain FreeIPA records a list of SIDs that must be filtered out
unconditionally. This list is based on the section ['4.1.2.2 SID Filtering and
Claims Transformation'](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
of the [MS-PAC] specification. The list can be extended for each specific
domain using `ipa trust-mod` command for both incoming
(`--sid-blacklist-incoming`) and outgoing (`--sid-blacklist-outgoing`)
directions.

Additionally, KDC verifies that a PAC issued by a trusted domain's KDC does not
contain SIDs from IPA domain. In such case the ticket issuance will be rejected.

For each ticket issued, KDC adds information about the requestor's SID
in a separate PAC buffer. During processing of the consequent requests KDC does
validate that a requestor SID is the same as the SID of the identity of the
security token in PAC buffer. This information is then cross-verified against
the list of known trusted domains to avoid cases of impersonation exploited
through [CVE-2020-25721].

As a consequence of these checks, FreeIPA Kerberos KDC only issues initial
Kerberos tickets for principals which have SID assigned. The SID assignment in
FreeIPA is tied to presence of an ID range that covers both `uidNumber` and
`gidNumber` of the LDAP object representing the principal. If there is no such
range can be found, SID will not be issued and a Kerberos principal associated
with this LDAP object will be used for authentication. Thus, SID and POSIX
attributes are tied together.


[MS-KILE]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9
[MS-PAC]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962
[CVE-2020-25721]: https://www.samba.org/samba/security/CVE-2020-25721.html


