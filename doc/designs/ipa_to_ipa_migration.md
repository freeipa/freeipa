# IPA Migration

## Overview of the old plugin-based migration

IPA has had a plugin-based migration for remote LDAP servers since version 2.0.0. It will only migrate users and groups.

It has some powerful capabilities for working around eccentricities in the remote server including:

* it is idempotent
* support for both RFC2307 and 2307bis
* support for ignoring specified objectclasses and attributes
* allows excluding some users and/or groups
* flexibility in the remote DIT, e.g. specifying user/group containers

This is insufficient for the following reasons:

* It severely limits IPA-to-IPA migration as all other entry types are lost
* User-private groups are not maintained
* Syntax errors can cause migration to fail with the only resolution being to skip broken entries or fix the remote LDAP server
* It is executed as a server-side plugin and if it runs long enough the client may disconnect
* There is no feedback during the migration beyond watching the logs
* There is no migration-specific log

The basic operation includes:

* loop through the remote user and group containers examining each entry
* if it looks like a user or group (based on objectclass) try to migrate it
* convert group membership from the detected or provided RFC
* retain passwords if the provider LDAP bind user can read them
* drop conflicting attributes (like kerberos)
* skip duplicates so it can be rerun multiple times
* convert groups to IPA POSIX groups

### Use cases for a new IPA to IPA migration tool

There are two use-cases driving a re-implementation (or extension) of migration:

1. Addressing bugs in current LDAP-only migration code

2. Adding IPA-to-IPA migration including all entry types.

## IPA to IPA migration

### Terminology

In the following sections we will describe the IPA server that has the data we are pulling the migration data from as the **remote server**, and the **local server** is the new IPA server that will receive this data.  So the **local server** is the new server and also the server where the migration tool will be run from.  In other words the migration tool pulls from the remote server and applies it to the local server.

### Prerequisites

You must install IPA on the new system (local server), and the domain/suffix must be the final expected values. The remote data will be converted to match the new local server. Typically it is expected that this installation be bare.  The tool was not designed to merge two different installations (although it might work).

### IPA to IPA migration design

- IPA-to-IPA migration will be implemented as an *AdminTool* standalone client tool:  **/usr/sbin/ipa-migrate**
- Migration will consist of three areas:
    - Schema - the LDAP schema (objectclasses and attributes)
    - Config - the LDAP configuration under **cn=config** (dse.ldif)
    - Database - the main LDAP database
- Allow online (LDAP over the network) or offline (LDIF file) migration. You can mix and match
LDIF (offline) with LDAP (online)

### Online migration

Online migration consists of contacting the remote server over the network and pulling in all the required information.  With very large databases this could impact the tool's performance

### Offline migration

Offline migration consists of using LDIF files from the remote server
- Config - the DS config file: **/etc/dirsrv/slapd-YOUR_LDAP_INSTANCE/dse.ldif**
- Schema - all the schema files found under **/etc/dirsrv/schema/** and **/etc/dirsrv/slapd-YOUR_LDAP_INSTANCE/schema/**
- Database - You need to export the **userroot** database to an ldif file

Then copy these LDIF files to the new **local server**

### Mixing online and offline methods

You are allowed to mix and match both approaches.  The most advantageous reason to mix and match these approaches would be if you have a very large database.  You can do the config and schema migration online and then use a database LDIF from the remote server for the database migration.  This will perform faster than reading and comparing thousands of entries over the network.  It will also be more stable.  You won't have to worry about network issues breaking the process mid-migration.

### Dry-run migrations

You can also do a dry-run of the migration to see what would be migrated to the new local server.  In addition to a dry-run you can also record to an LDIF file what LDAP operation would be performed during the migration.  This LDIF file can be inspected to see fine grained details about what the migration would do, "replayed" to perform the migration at later date, or to reuse a common deployment on multiple IPA servers.

### Migration modes

As of right now there are two migration modes, but in the future there could be more.  Migration modes allow for easier use of the tool.  the mode will define what is migrated and what is not.

#### Production mode

In production mode basically everything is brought over. It is assumed that the *remote server* is/was fully functional and the database and entry states are valid.  This means things like DNA ranges, IDs, and SIDs (ipantsecurityidentifier) will be migrated as is.

#### Staging mode

In this mode it is assumed that the remote server was in a staging environment and that things like the DNA ranges and ID attributes (uidNumber, gidNumber, etc) should **not** be migrated as is. The DNA entry attributes will be reset to the *magic regen* value.

### Migration content

This section will describe how various entries & attributes will be migrated to the local server.

#### REALM/Domain

For realm/domain/suffixes all the remote data will be converted to match the the new local server.  This will apply to all the entries and subtrees.  This is an automatic process and can not be adjusted or disabled.  This is why it's important when you install the new local server that you set the realm/domain/database suffix to the expected production values.

#### ID ranges

The migration mode (production or staging) will determine if the ID ranges are migrated or not.  You can still skip the ID range migration in production mode using a CLI option and the tool will reset the DNA attributes (uidNumber, gidNumber, etc) to the magic regeneration value.

#### Skipped attributes

When adding new entries to the local server the following attributes are skipped ...

Operational attributes
- modifiersname
- modifytimestamp
- creatorsname
- createtimestamp
- nsuniqueid
- dsentrydn
- entryuuid

Standard attributes
- krbextradata
- krblastfailedauth
- krblastpwdchange
- krbloginfailedcount
- krbticketflags
- krbmkey
- ipasshpubkey  -->  We do keep the public key for users
- mepmanagedentry
- memberof
- krbprincipalkey
- memberofindirect
- memberindirect
- memberofindirect
- memberindirect
- userCertificate  --> if issued by the remote IPA server

#### Ignored attributes

When comparing entries (not when adding entries) the following attributes are ignored and the value that exists on the local server will remain intact

- description
- ipasshpubkey
- ipantsecurityidentifier --> except in production mode
- ipantflatname
- ipamigrationenabled
- ipauniqueid
- serverhostname
- krbpasswordexpiration
- krblastadminunlock

#### DNS records

By default all DNS entries are migrated, but you can skip the DNS records via a CLI option.

#### Limited migration

If there are cases where you don't want to migrate the configuration or schema there are CLI options to skip each of these areas.

#### Non-IPA content

Some Administrators store non-IPA content in the database tree. In order for this content to be migrated it must be specified via a CLI option.

### Configuration migration design

The following sections of the Directory Server configuration will be migrated

#### Core configuration (cn=config)

The core configuration attributes will be migrated to the core server.  Things like performance tuning, security settings, and log rotation settings.

#### Database settings

The various look through limits, ID scan limits, import cache size, backend indexes, and encrypted attributes are migrated.

#### Plugins

The following plugins are migrated

- Attribute Uniqueness plugins
- DNA Plugins
- MemberOf plugin
- Referential integrity plugin
- Retro Changelog plugin
- SASL Mapping plugins
- IPA DNS plugin
- IPA Enrollment plugin
- IPA Extdom plugin
- IPA Graceperiod plugin
- IPA Lockout plugin
- IPA Password Policy plugin
- IPA Topology plugin
- IPA Unique ID plugins
- IPA Winsync plugin
- Schema Compatibility plugin
- Slapi NIS plugin

### Schema migration design

By default any *missing* objectclasses and attributes are migrated.  There is also a CLI option to completely overwrite the existing schema on the local server with the remote server's schema.

### Database migration design

The following subtrees and entries are migrated.  Any missing entries will be added, and any existing entries will be compared and any differences will be merged into the new local server

#### Plugin entries

- Automember Definitions (subtree of ```cn=automember,cn=etc,$SUFFIX```)
- DNA Ranges (subtree of ```cn=ranges,cn=etc,$SUFFIX```)
- DNA Posix IDs (```cn=automember,cn=etc,$SUFFIX```)
- DNA SubIDs (```cn=subordinate-ids,cn=dna,cn=ipa,cn=etc,$SUFFIX```)
- MEP Templates (subtree of ```cn=templates,cn=managed entries,cn=etc,$SUFFIX```)
- MEP Definitions (subtree of ```cn=definitions,cn=managed entries,cn=etc,$SUFFIX```)

#### Etc entries

- Anonymous Limits (```cn=anonymous-limits,cn=etc,$SUFFIX```)
- CA (```cn=ca,$SUFFIX```)
- IPA Config (```cn=ipaconfig,cn=etc,$SUFFIX```)
- Sys Accounts (subtree of ```cn=sysaccounts,cn=etc,$SUFFIX```)
- Topology (subtree of ```cn=topology,cn=ipa,cn=etc,$SUFFIX```)
- Certmap (```cn=certmap,$SUFFIX```) 
- Certmap Rules (subtree of ```cn=certmaprules,cn=certmap,$SUFFIX```)
- s4u2proxy (subtree of ```cn=s4u2proxy,cn=etc,$SUFFIX```)
- Passkey Config (```cn=passkeyconfig,cn=etc,$SUFFIX```)
- Desktop Profile (```cn=desktop-profile,$SUFFIX```)
- OTP (```cn=otp,cn=etc,$SUFFIX``)
- Realm (subtree of ```cn=realm domains,cn=ipa,cn=etc,$SUFFIX```)
- AD (subtree of ```cn=ad,cn=etc,$SUFFIX```)
- Master Configurations (subtree of ```cn=masters,cn=ipa,cn=etc,$SUFFIX```)
- Domain Configuration (```cn=domain level,cn=ipa,cn=etc,$SUFFIX```)

#### Accounts

- Computers (subtree of ```cn=computers,cn=accounts,$SUFFIX```)
- Administrator (uid=admin,cn=users,cn=accounts,$SUFFIX)
- Users (subtree of ```cn=users,cn=accounts,$SUFFIX```)
- Groups (subtree of ```cn=groups,cn=accounts,$SUFFIX```)
- Roles (subtree of ```cn=roles,cn=accounts,$SUFFIX```)
- Host Groups (subtree of ```cn=hostgroups,cn=accounts,$SUFFIX```)
- Services (subtree of ```cn=services,cn=accounts,$SUFFIX```)
- Views (subtree of ```cn=views,cn=accounts,$SUFFIX```)
- IP Services (subtree of ```cn=ipservices,cn=accounts,$SUFFIX```)
- Sub IDs (subtree of ```cn=subids,cn=accounts,$SUFFIX```)

#### HBAC & PBAC

- HBAC Services (subtree of ```cn=hbacservices,cn=hbac,$SUFFIX```)
- HBAC Service Groups (subtree of ```cn=hbacservicegroups,cn=hbac,$SUFFIX```)
- PBAC Privileges (subtree of ```cn=privileges,cn=pbac,$SUFFIX```)
- PBAC Permissions (subtree of ```cn=permissions,cn=pbac,$SUFFIX```)

#### Sudo

- Sudo Rules (subtree of ```cn=sudorules,cn=sudo,$SUFFIX```)
- Sudo Commands (subtree of ```cn=sudocmds,cn=sudo,$SUFFIX```)
- Sudo Command Groups (subtree of ```cn=sudocmdgroups,cn=sudo,$SUFFIX```)

#### DNS

- DNS Records (subtree of ```cn=dns,$SUFFIX```)
- DNS Servers (subtree of ```cn=servers,cn=dns,$SUFFIX```)

#### Kerberos

- Kerberos Realm & Policy (subtree of ```cn=kerberos,$SUFFIX```)
- Kerberos Password Policy (```cn=global_policy,cn=$REALM,cn=kerberos,$SUFFIX```)
- Kerberos Default Password Policy (```cn=default kerberos service password policy,cn=$REALM,cn=kerberos,$SUFFIX```)

#### Misc

- Automounts & Automount Maps (subtree of ```cn=automount,$SUFFIX```)
- Trusts (subtree of ```cn=trusts,$SUFFIX```)
- Provisioning (subtree of ```cn=accounts,cn=provisioning,$SUFFIX```)
- SELinux Usermaps (subtree of ```cn=usermap,cn=selinux,$SUFFIX```)
- DUA Config Profiles (subtree of ```ou=profile,$SUFFIX```)
- CA Certificates (subtree of ```cn=certificates,cn=ipa,cn=etc,$SUFFIX```)

#### Excluded Subtrees

- All Class Of Service (COS) entries
- ```cn=sec,cn=dns,$SUFFIX```
- ```cn=custodia,cn=ipa,cn=etc,$SUFFIX```

#### Entries NOT be to migrated

We will not have migrate existing keys from the remote IPA server so the
following will not be migrated:

* Self-signed CA certificates (maybe we import user-added CA certs)
* KRA keys
* sub-CAs
* caacls
* DNSSEC keys
* admin password
* DM password
* Anything in Custodia

### Migration steps

A simplistic view of the steps (the following might be outdated/unnecessary - TODO)

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

#### Supported Migration Scenarios

There are quite a few ways that migration can be done, both for testing and production uses. Any scenario not specifically mentioned here should be considered unsupported.

These scenarios are not enforced by code. At best we can prompt the user
for confirmation if we believe that they are non-conformant but I choose
the trade-off of allowing for unsupported migrations to the flexibility
of not trying to force square pegs into round holes.

There are a few points to consider.

**Replicas**

All references to replicas in the existing deployment will not be migrated. There is no mechanism to one-by-one replace each server with a new one using migration. One will be migrated and new replicas will need to be manually added directly to that using ipa-replica-install.

**Kerberos**

The Kerberos master key will not be migrated. Kerberos principals are retained but the keys are not.

**Certificates**

The existing CA will be abandoned in favor of a CA on the new installation.

If the realm, domain and CA subject base (default is O=REALM) are identical between the two installations then there is no way, other than the CA private key, to distinguish between the original CA and the new CA. Therefore no certificates will be maintained in the migration. All certificates other than those already present in the new IPA server as part of installation will need to be re-issued.

If one of these doesn't match then the certificates will be retained but the backing PKI will be lost so there will be no possibility of renewals or revocation (no OCSP or CRL).


##### Scenario 1 - Production to new production

Preconditions:
* There is a existing production IPA server (or servers)
* There is a new IPA server installation with the same realm and domain

Optional:
* If desired the realm and domain may be changed. The migrated data will accommodate these changes but this will require reconfiguration of all clients, etc. beyond just re-enrollment.

Result:
* All valid IPA entries will be migrated
* All ids (uid, gid, SID, etc) will be maintained
* All certificates issued from the previous CA will be dropped unless the CA subject base DN, or the realm, is changed in the new deployment.
* All clients must re-enroll to the new deployment
* Users will have to migrate their passwords to generate Kerberos and other keys

##### Scenario 2 - Production to new staging

Preconditions:
* There is an existing production IPA server (or servers)
* There is a new IPA server installation with a different realm and domain (e.g. staging.example.test)

Result:
* All valid IPA entries will be migrated
* All ids (uid, gid, SID, etc) will be re-generated
* All certificates from the previous CA will be preserved
* Given this is a new staging deployment there will be no enrolled clients. The host entries from the production deployment will exist but all keys are dropped.
* Users will have to migrate their passwords to generate Kerberos and other keys

##### Scenario 3 - Staging to new production

Preconditions:
* There is an existing production IPA server (or servers)
* There is a new IPA server installation with a different realm and domain (e.g. staging.example.test)

Result:
* All valid IPA entries will be migrated
* All ids (uid, gid, SID, etc) will be re-generated
* All certificates from the previous CA will be removed
* Users will have to migrate their passwords to generate Kerberos and other keys


##### Scenario 4 - From IPA backup

The migration tool will have the capability to do offline migration using an LDIF file. An IPA backup is a tar ball that contains the IPA data in EXAMPLE-TEST-userRoot.ldif

Preconditions:
* A backup from an existing IPA installation exists
* There is a new IPA server installation with the same realm and domain

Result:
* All valid IPA entries will be migrated
* All ids (uid, gid, SID, etc) will be maintained
* All certificates issued from the previous CA will be dropped unless the CA subject base DN, or the realm, is changed in the new deployment.
* All clients must re-enroll to the new deployment
* Users will have to migrate their passwords to generate Kerberos and other keys

## Logging

By default the log file will be /var/log/ipa-migrate.log and will be appended to
and not overwritten. This is so it can reflect multiple runs if they are required.

### Standard logging

Here is an example of the standard logging

```
024-02-27T17:10:03Z DEBUG ================================================================================
2024-02-27T17:10:03Z INFO IPA to IPA migration starting ...
2024-02-27T17:10:03Z DEBUG Migration options:
2024-02-27T17:10:03Z DEBUG --mode=prod-mode
2024-02-27T17:10:03Z DEBUG --hostname=hpe-dl385gen8-01.hpe2.lab.eng.bos.redhat.com
2024-02-27T17:10:03Z DEBUG --verbose=False
2024-02-27T17:10:03Z DEBUG --bind-dn=cn=directory manager
2024-02-27T17:10:03Z DEBUG --bind-pw-file=None
2024-02-27T17:10:03Z DEBUG --cacertfile=None
2024-02-27T17:10:03Z DEBUG --subtree=[]
2024-02-27T17:10:03Z DEBUG --log-file=/var/log/ipa-migrate.log
2024-02-27T17:10:03Z DEBUG --skip-schema=False
2024-02-27T17:10:03Z DEBUG --skip-config=False
2024-02-27T17:10:03Z DEBUG --skip-dns=False
2024-02-27T17:10:03Z DEBUG --dryrun=True
2024-02-27T17:10:03Z DEBUG --dryrun-record=None
2024-02-27T17:10:03Z DEBUG --force=False
2024-02-27T17:10:03Z DEBUG --version=False
2024-02-27T17:10:03Z DEBUG --quiet=False
2024-02-27T17:10:03Z DEBUG --schema-overwrite=False
2024-02-27T17:10:03Z DEBUG --reset-range=False
2024-02-27T17:10:03Z DEBUG --db-ldif=None
2024-02-27T17:10:03Z DEBUG --schema-ldif=None
2024-02-27T17:10:03Z DEBUG --config-ldif=None
2024-02-27T17:10:03Z DEBUG --no-prompt=False
2024-02-27T17:10:03Z DEBUG flushing ldapi://%2Frun%2Fslapd-HPE2-LAB-ENG-BOS-REDHAT-COM.socket from SchemaCache
2024-02-27T17:10:03Z DEBUG retrieving schema for SchemaCache url=ldapi://%2Frun%2Fslapd-HPE2-LAB-ENG-BOS-REDHAT-COM.socket conn=<ldap.ldapobject.SimpleLDAPObject object at 0x7f5a1eb68210>
2024-02-27T17:10:03Z DEBUG retrieving schema for SchemaCache url=ldap://hpe-dl385gen8-01.hpe2.lab.eng.bos.redhat.com conn=<ldap.ldapobject.SimpleLDAPObject object at 0x7f5a1e7eba10>
2024-02-27T17:10:04Z DEBUG Found realm from remote server: HPE2.LAB.ENG.BOS.REDHAT.COM
2024-02-27T17:10:04Z INFO Migrating schema ...
2024-02-27T17:10:04Z DEBUG Getting schema from the remote server ...
2024-02-27T17:10:04Z DEBUG Retrieved 1556 attributes and 349 objectClasses
2024-02-27T17:10:07Z DEBUG Migrated 0 attributes and 0 objectClasses
2024-02-27T17:10:07Z DEBUG Skipped 1556 attributes and 349 objectClasses
2024-02-27T17:10:07Z INFO Migrating configuration ...
2024-02-27T17:10:07Z DEBUG Getting config from the remote server ...
2024-02-27T17:10:08Z DEBUG flushing ldapi://%2Frun%2Fslapd-HPE2-LAB-ENG-BOS-REDHAT-COM.socket from SchemaCache
2024-02-27T17:10:08Z DEBUG retrieving schema for SchemaCache url=ldapi://%2Frun%2Fslapd-HPE2-LAB-ENG-BOS-REDHAT-COM.socket conn=<ldap.ldapobject.SimpleLDAPObject object at 0x7f5a1eb68210>
2024-02-27T17:10:09Z INFO Migrating database ... (this make take a while)
2024-02-27T17:10:11Z DEBUG Removed IPA issued userCertificate from: krbprincipalname=ldap/hpe-dl385gen8-01.hpe2.lab.eng.bos.redhat.com@HPE2.LAB.ENG.BOS.REDHAT.COM,cn=services,cn=accounts,dc=hpe2,dc=lab,dc=eng,dc=bos,dc=redhat,dc=com
2024-02-27T17:10:11Z DEBUG Skipping remote certificate entry: 'cn=HPE2.LAB.ENG.BOS.REDHAT.COM IPA CA,cn=certificates,cn=ipa,cn=etc,dc=hpe2,dc=lab,dc=eng,dc=bos,dc=redhat,dc=com' Issuer: CN=Certificate Authority,O=HPE2.LAB.ENG.BOS.REDHAT.COM
2024-02-27T17:10:11Z DEBUG Removed IPA issued userCertificate from: krbprincipalname=HTTP/hpe-dl385gen8-01.hpe2.lab.eng.bos.redhat.com@HPE2.LAB.ENG.BOS.REDHAT.COM,cn=services,cn=accounts,dc=hpe2,dc=lab,dc=eng,dc=bos,dc=redhat,dc=com
2024-02-27T17:10:16Z INFO Running ipa-server-upgrade ... (this make take a while)
2024-02-27T17:10:16Z INFO Skipping ipa-server-upgrade in dryrun mode.
2024-02-27T17:10:16Z INFO Running SIDGEN task ...
2024-02-27T17:10:16Z INFO Skipping SIDGEN task in dryrun mode.
2024-02-27T17:10:16Z INFO Migration complete!
```

### Verbose logging

If get the verbose logging you simply just use the **--verbose, -v** CLI option. Here you will see the exact operations there were performed.  Here is an example showing the additional information that is logged.


```
...
...
2024-02-28T15:30:53Z INFO Migrating database ... (this make take a while)
2024-02-28T15:30:53Z INFO Entry is different and will be updated: 'uid=admin,cn=users,cn=accounts,dc=hpe2,dc=lab,dc=eng,dc=bos,dc=redhat,dc=com' attribute 'ipaNTSecurityIdentifier' replaced with val 'S-1-5-21-404865364-1326736403-3398440945-501' old value: ['S-1-5-21-404865364-1326736403-3398440945-500']
2024-02-28T15:30:53Z INFO Add db entry 'uid=mark,cn=users,cn=accounts,dc=hpe2,dc=lab,dc=eng,dc=bos,dc=redhat,dc=com - users'
2024-02-28T15:30:53Z INFO Entry is different and will be updated: 'cn=HPE2.LAB.ENG.BOS.REDHAT.COM_id_range,cn=ranges,cn=etc,dc=hpe2,dc=lab,dc=eng,dc=bos,dc=redhat,dc=com' attribute 'ipaBaseID' replaced with val '9000999' old value: ['90000000']
2024-02-28T15:30:53Z INFO Entry is different and will be updated: 'cn=HPE2.LAB.ENG.BOS.REDHAT.COM_subid_range,cn=ranges,cn=etc,dc=hpe2,dc=lab,dc=eng,dc=bos,dc=redhat,dc=com' attribute 'ipaIDRangeSize' replaced with val '2147352575' old value: ['2147352576']
...
...
```


## Feature Management

### UI

No UI option will be provided. This is command-line client only.

### CLI

Overview of the CLI usage

    ipa-migrate <prod-mode|stage-mode> <HOSTNAME> [options]

| Option | Description |
| --- | --- |
| --bind-dn, -D | The bind DN to use for authentication to the remote IPA server (default is "cn=directory manager") |
| --bind-pw, -w | The password for the bind DN |
| --bind-pw-file, -j | A file that contains the password |
| --cacertfile, -Z | The CA cert file |
| --skip-schema, -S | Do not migrate the schema |
| --skip-config, -C | Do not migrate the DS configuration |
| --schema-overwrite, -O | Completely overwrite schema |
| --reset-range, -r | Reset all the DNA attributes (uidNumber, etc) to the magic regen value (-1)  |
| --db-ldif, -f | An LDIF file containing the export of the userRoot database |
| --schema-ldif, -m | An LDIF file containing the schema from the remote server |
| --config-ldif, -g | The DS config file dse.ldif |
| --skip-dns, -B | Do not migrate the DNS records in the database |
| --subtree, -s | Non standard IPA subtree to include in the migration |
| --dryrun, -x | try the migration without writing data |
| --dryrun-record, -o | Perform dryrun but record all the LDAP changes to a LDIF file |
| --force. -F | ignore errors and keep going |
| --version, -V | version of the tool |
| --quiet, -q | output only errors |
| --no-prompt, -n | Do not do a confirmation prompt about starting the migration |
| --log-file, -l | log to the given file |
| --verbose, -v | Display verbose output |
| --help, -h | this message |

If the DM password is not provided then you will be prompted for it.

#### Examples

    # ipa-migrate prod-mode remote.server.com
   
    # ipa-migrate prod-mode remote.server.com --dryrun
    
    # ipa-migrate prod-mode remote.server.com -D "cn=directory manager" -j ./passwd.txt
   
    # ipa-migrate prod-mode remote.server.com --db-ldif=/tmp/remote-userroot.ldif
   
    # ipa-migrate prod-mode remote.server.com --skip-config --skip-schema
   
    # ipa-migrate stage-mode remote.server.com --dryrun-record=/tmp/dryrun-ops.ldif
   
    # ipa-migrate stage-mode remote.server.com --config-ldif=/tmp/dse.ldif --schema-ldif=/tmp/schema.ldif --db-ldif=/tmp/remote-userroot.ldif

    # ipa-migrate stage-mode remote.server.com --subtree="ou=my own data,dc=ipa,dc=com"


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
