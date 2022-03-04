# IPA Migration

## Overview

IPA has had a plugin-based migration for remote LDAP servers since
version 2.0.0. It will only migrate users and groups.

It has some powerful capabilities for working around eccentricities in
the remote server including:

* it is idempotent
* support for both RFC2307 and 2307bis
* support for ignoring specified objectclasses and attributes
* allows excluding some users and/or groups
* flexibility in the remote DIT, e.g. specifying user/group containers

This is insufficient for the following reasons:

* It severely limits IPA-to-IPA migration as all other entry types are lost
* User-private groups are not maintained
* Syntax errors can cause migration to fail with the only resolution
  being to skip broken entries or fix the remote LDAP server
* It is executed as a server-side plugin and if it runs long enough the
  client may disconnect
* There is no feedback during the migration beyond watching the logs
* There is no migration-specific log

The basic operation includes:

* loop through the remote user and group containers examining each entry
* if it looks like a user or group (based on objectclass) try to
  migrate it
* convert group membership from the detected or provided RFC
* retain passwords if the provider LDAP bind user can read them
* drop conflicting attributes (like kerberos)
* skip duplicates so it can be rerun multiple times
* convert groups to IPA POSIX groups

## Use Cases

There are two use-cases driving a re-implementation (or extension) of
migration:

1. Addressing bugs in current LDAP-only migration code

2. Adding IPA-to-IPA migration including all entry types.

## Migration basics

### General considerations

LDAP stores information in a tree structure known as the Directory
Information Tree (DIT). Each node in the tree is an entry and each
entry contains information in an attribute=value form. It is a very
different storage model than a relational database as there is no
"join" capability between entries (among other things).

The organization of the entries depends on schema which defines which
object types (objectclasses) and attributes (attributetypes) are
allowed. https://ldap.com/ has a pretty decent introduction to LDAP,
schemas, etc. The important thing to understand is that in order for
an attribute to be in an entry, there must be a corresponding
objectclass which allows it, either as a MUST or MAY. The schema defines
a syntax for that attribute which defines what type of data may be
stored in it. Some LDAP servers do a better job than others at enforcing
this syntax.

### pure LDAP migration

While it is easy to see a remote LDAP migration as a subset of IPA to
IPA it is better to keep them as separate for the following reasons:

1. It represents a small subset of a typical IPA installation: only
   users and groups.
2. The remote schema and DIT are unknown and different for each migration so it will require more care.
3. The quality of the data is unknown. 389-ds, used by IPA, enforces proper syntax where other servers may not.

### IPA to IPA migration

For an IPA to IPA migration it is possible to make certain assumptions
that aren't possible in a pure LDAP migration including:

1. The DIT is understood and consistent
2. Unique UID/GID/login/group name(s) so additional checking is not necessary
3. A consistent schema (perhaps variability for users and groups)

## Design

### IPA to IPA migration

It would be risky to hardcode the data to pull in. It is far simpler to
iterate the things you *don't* want to migrate. This should also improve
the chances for future-proofing and preventing bugs like not migrating
some new feature area. It will require that versions only migrate up or
sideways and not backwards.

IPA-to-IPA migration will be implemented as an AdminTool standalone
client.

#### Prerequisites

A migration should only be done to a single IPA server. This will greatly
simplify certain things, particularly performance. We may want an option
to allow this and deny it by default.

If DNS is enabled on the remote server it will need to be enabled in
the local one in order to migrate DNS data. It would need to be determined
if the DNS DIT exists in a migrated server would allow bind to be
configured (I suspect it will) but we don't want to get into a situation
where the migrated DNS data is unusable.

#### Retain REALM/domain

It will be optional to retain the same REALM and domain. This will make the
use-cases of staging and development server migration possible.

#### Retain ranges

This is TBD. I don't know of a reason why a user wouldn't want to retain the
ranges as it would affect owned files, etc, but *someone* may want to make a
clean break. I don't believe it would be difficult to deal with as we would
just set the magic values for DNA generation.

In order to retain the range then the remote and local ranges would need to
be compared and the migration rejected if they do not overlap (perhaps allowed
with --force).

As for DNA, if the range remains some effort will need to be made to set the
local DNS configuration to match what is available remotely.

This may not be ideal. The basic process would be:

  * connect to all servers in the remote IPA installation
  * collect the DNA and on-deck ranges
  * determine the starting point
  * set the local DNA range to this starting point + the range end - 1

This could well leave huge holes of allocated values within the range but the
DNA plugin should be able to handle that.

subids TBD. It may be fine to just straight migrate the range and records.

#### Discovery of IPA objects

The objects to migrate can be determined by examining the local API.
It can be iterated to discover the available class objects which contain
the container_dn and other useful information. Not all objects need
to be migrated either because they are internal objects, represent
schema or represent commands that have no underlying storage.
Initialize the API and iterate over Object:

    api.bootstrap(in_server=True, context='migrate')
    api.finalize()

    for obj in api.Object:
       work()

This gives us an alphabetized list of objects. An implicit relationship
can be determined by examining the member* values in `obj.attribute_members`
if it is present.

Using this list we know which are "leaf" entries which have no dependencies.
These are migrated first. Then the list is iterated again looking for
those with dependencies that are already satisfied and those are migrated.
And so on.

So for example users and hosts are migrated. Then groups, which has a dependency on
users. Then hostgroups can then be migrated.

Some objects, like hostgroups, can be nested. These will need to be deferred until
all of their members are added. If a running list of objects that have been migrated
is maintained then it can be easily calculated which are ready for migration and
which are not without having to refer to LDAP.

#### Objects to ignore

The IPA API object list includes an number of internal-only objects and
some classes that represent informational commands so they can be skipped
for migration.

| Object |	Reason |
| --- | ----- |
| certreq | no storage |
| class | schema |
| command | internal |
| cosentry | migration not needed |
| dns_system_records | no storage |
| metaobject | schema |
| param | internal |
| pkinit | no storage |
| topic | internal |
| userstatus | no storage |

#### Objects TBD

Each DNS record type is represented as a separate class. It is probably safe
to just bulk import all dns records as there isn't any IPA-specific information in them.

So basically add them to the ignore list.

#### Other Containers

Not all data in IPA can be manipulated with the API.

cn=certificates,cn=ipa,cn=etc,$SUFFIX contains any user-provided certificates.
I think we can skip this and require that any necessary certificates be
re-added. Otherwise, to be safe, we should validatate the trust and expiration
dates on all of them.

DNA ranges. Depending on the local ranges we could try to recover them.

#### Items to NOT be migrated

We will not have migrate existing keys from the remote IPA server so the
following will not be migrated:

* Self-signed CA certificates (maybe we import user-added CA certs)
* KRA keys
* sub-CAs
* caacls
* DNSSEC keys
* admin password
* DM password
* Basically anything in Custodia

#### Migrating conflicting data

For new entries (users, groups, hosts, etc) we can do a straight LDAP
ADD after massaging necessary attributes (see Attributes to not migrate).

That is the easy part.

There are some parts of IPA that are default and will exist in both servers
such as the configuration (config commands), allow_all HBAC rule,
permissions, privileges, roles, selinux mappings, ipaservers hostgroup and more.

The strategy for this will be use the existing entry comparison in ldap2 and
modify the new IPA instation to match the original minus some specific things like
the CA subject base in the config. So in most cases we favor the remote IPA
installation except for things which are installation-dependent.

The downside of this is that it could interpret "fresher" defaults in the
new IPA server with stale ones from the old. We will need good logging around
these types of entries.

Standard boilerplate will not be evaluated, things like cosTemplates. These are not
user-modifiable and if a user decides to mess with them, they can correct it
after migration.

#### Migrating cn=config

A number of plugins are optional in IPA: nis, compat, ACME.

These will be enabled in the new IPA server if enabled in the remote at
the end of migration:

* cn=Schema Compatibility, cn=plugins, cn=config
* cn=NIS Server, cn=plugins, cn=config

Schema compatibility will be disabled during migration as it can cause
performance issues and we don't want to try to migrate anything in
cn=compat since it is generated data.

ACME is a feature of the CA. We should be able to import ipa_acme_manage
and call enable/disable within the migration if it is remotely enabled.

#### Configuration to not migrate

These will not be migrated:

* AD Trusts
* Winsync configuration (though the entries will)
* CA, KRA
* DNSSEC

#### Special migration

cn=kerberos contains the Kerberos master key as well as the default
ticket policy. Only the policy can be migrated.

#### Attributes to not migrate

Some attributes we will need to completely drop because they contain key or
server-specific information for the remote IPA server. This may also
include objectClasses that may need to be dropped if the last attribute
is removed.

* krbPrincipalKey (will require dropping objectclasses)
* krbExtraData
* ipaNTSecurityIdentifier
* memberOf (will be reconstructed after the migration)
* userCertificate if issued by the remote IPA server

#### Attributes to update to new REALM

If a REALM change is part of migration then these will need to be updated
to reflect the new installation.

* krbPrincipalKey
* krbCanonicalName

#### Attributes to change basedn

Prior to writing a new value any DN syntax attributes will need to be
examined to see if they contain the remote baseDN if it is different. If
so then the following need to be updated:

* mepManagedEntry
* mepManagedBy

#### Migrating custom schema

Schema is stored in LDAP so we *should* be able to use our ldap library
to discover differences. We probably want to do only ADD and bail if we
determine something will be a MOD or DEL.

#### Excluding specific entries

The ignore user/group options of migrate-ds were introduced so that non-compliant
entries could be skipped to not block the migration. We can ignore these for now.

#### Performance considerations

Some benefits would be likely if common entry types were added in
batches rather than individually. This would not easily allow for a
"stop on failure" approach but could be considerably faster.

The basic idea is that added entries of the same type (user, group, etc)
would be accumulated and added together. The result would be iterated
through and logged.

The memberOf plugin should be disabled. A fixup task can be run post-migration
to calculate the memberships.

#### Idempotency

The migrate-ds plugin manages idempotency because it skips over entries
that already have been migrated (or exist). This new migration will handle
it by merging the remote and local entries. This may not be desirable in
all cases.

#### Migration steps

A simplistic view of the steps

Set migration mode=True
Disable compat
Disable memberof
Migrate schema
Loop through the list of remote objects:
  - fix up any DN values or other syntaxes
  - remove conflicting attributes/objectclasses
  - write new entry
      - if entry already exists, merge them if possible preferring remote side
Enable memberOf
Create memberOf fixup task
Enable compat
Restart world
Run ipa-server-upgrade

### pure LDAP migration

The current code generally works minus a few bugs and RFEs, some of which are resolved
by doing an IPA-to-IPA migration instead. It should be maintained for now and migrated
to the standalone client in the future.

These bugs should be considered for the existing plugin.

* https://pagure.io/freeipa/issue/3096 - error when migrating unknown schema
* https://pagure.io/freeipa/issue/3100 - Check for userPassword in migration
* https://pagure.io/freeipa/issue/4738 - [RFE] ipa migrate-ds should provide option for creating UPG from posixGroup objectClass
* https://pagure.io/freeipa/issue/5020 - migrate-ds: does not show migrated users if an error happened during group migration
* https://pagure.io/freeipa/issue/5693 - Passwords become "expired" when migrating from directory server to IPA
* https://pagure.io/freeipa/issue/6105 - migrate-ds is not completely ignoring attributes.
* https://pagure.io/freeipa/issue/6360 - ipa migrate-ds does not rename uniquemember/member attributes properly
* https://pagure.io/freeipa/issue/6380 - ipa migrate-ds should print warning for referrals
* https://pagure.io/freeipa/issue/7368 - ipa migrate-ds converts groupofuniquenames objects to groupofnames, but leaves groupofuniquenames objectclass present
* https://pagure.io/freeipa/issue/7749 - `ipa migrate-ds` fails to migrate user and group data from directory server to IDM.

## Logging

By default the log file will be /var/log/ipa-migrate.log and will be appended to
and not overwritten. This is so it can reflect multiple runs if they are required.

At least the DN of all entries written should be logged (pkey may be sufficient).

Logging by object type could be handy and should natural since this is how the
objects will be sorted.

DEBUG logging may want to show gory details, particularly when merging entries.

## Implementation

The command will be named ipa-migrate. It must determine whether the remote server is
actually an IPA server or not. ipaclient/discovery.py::ipacheckldap may be re-usable.

The standalone client should use a unique context, migration. This will
allow for a separate configuration file.

## Feature Management

### UI

No UI option will be provided. This is command-line client only.

### CLI

Overview of the CLI commands.

#### IPA to IPA

Advance knowledge of the DIT substantially reduces the number of options
necessary for migration.

| Option | Description |
| --- | --- |
| --dry-run | try the migration without writing data |
| --force | ignore errors and keep going |
| --version | version of the tool |
| --quiet | output only errors |
| --log-file | log to the given file |
| --help | this message |

The DM password will be prompted for interactively.

| Argument | Description |
| url | ldap url for remote IPA server |

#### pure LDAP

Will remain unchanged unless one of the bug fixes requires it (perhaps for the UPG
ticket).

### Configuration

N/A

## Upgrade

N/A

## Test plan

There are currently no tests for migration.

Some simplisitic approaches for starting testing might include:
* Count the number of entries that will be migrated and ensure they were migrated, by type (hosts, groups, etc).
* Verify that the services enabled on the remote side are enabled after migration (NIS, ACME, etc).
* Double-check, perhaps spot-checking, memberOf
* Migrate a password to ensure it was imported properly

We have a data generation script in freeipa-tools that may be leveraged to generate the data but it currently generates a LOT of entries which is likely too much for automation.

## Troubleshooting and debugging

Include as much information as possible that would help troubleshooting:
- Does the feature rely on existing files (keytabs, config file...)
- Does the feature produce logs? in a file or in the journal?
- Does the feature create/rely on LDAP entries? 
- How to enable debug logs?
- When the feature doesn't work, is it possible to diagnose which step failed? Are there intermediate steps that produce logs?

[1] https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/installing_identity_management/migrating-from-an-ldap-directory-to-idm_migrating-to-idm-from-external-sources

## Future

We may eventually want to add the ability to skip entire types of data.
For example, drop all sudo rules.
