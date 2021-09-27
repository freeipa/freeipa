#  Integrate SID configuration into base IPA installers

## Overview

FreeIPA is able to issue Kerberos tickets with PAC data when it is configured
for trust. The goal of this feature is to allow PAC generation in the
general use case, even without trust, as it is a first step towards
IPA-IPA trust.

Reference: https://pagure.io/freeipa/issue/8995

In order to generate PAC data for a kerberos principal, IPA needs to assign
a SID to the users and groups. IPA installers (`ipa-server-install`,
`ipa-replica-install`) must handle the configuration related to SID:
- assign a NetBIOS name to the server
- assign a domain SID to the IPA domain
- configure the local id range with primary RID base and secondary RID base
- enable the sidgen plugin on 389ds server

The code handling these steps is already available in ipa-adtrust-install
and needs to be moved to the general installers.

## Use Cases

### Fresh install
As administrator, I want to deploy an IPA topology that automatically
assigns SIDs to users and groups and issues kerberos tickets with PAC data,
without the need to configure IPA for trust.

If I later decide to configure IPA for trust, I can still run the command
`ipa-adtrust-install`.

### Existing installation, no trust

As IPA administrator, I am managing an existing IPA installation without any
trust. I want to update IPA and have the choice of enabling (or not) the
generation of SIDs and PAC data.

If I choose to enable PAC data, I just need to run a command that requires
an admin kerberos ticket. The command handles the SID-related configuration 
and prompts me whether I want to immediately generate SIDs for
existing users/groups or run that task later.

### Existing installation, trust configured

In this topology with trust configured (the command `ipa-adtrust-install` has 
been executed), IPA is already able to issue Kerberos tickets with PAC data.
Update does not modify the configuration.

### Mixed topology

As IPA administrator, I am managing an existing server setup without trust and
without PAC data. I want to add a replica into my existing topology and
automatically enable PAC data generation, without the need to configure IPA
for trust.

## How to Use

### Fresh installation
Run `ipa-server-install`, with the ability to define:
- NetBIOS Name: if not specified, the default value is generated from
the IPA domain name (transform the left-most label into uppercase, keep only
ascii characters, digits and dashes).
- Primary RID base (default if not set: 1000)
- Secondary RID base (default if not set: 1000000)

On a replica: run `ipa-replica-install`, with the ability to define the same
parameters as `ipa-server-install`, plus the following parameter:
- Run SIDgen task immediately: yes/no (default=no)

If conflicting values are specified in `ipa-replica-install`, the installer
must warn that existing values will be overwritten (same message as when
`ipa-adtrust-install` is run multiple times with conflicting values).

### Upgrade

- Run `dnf update *ipa-server`. The upgrade doesn't configure SID-related
options and doesn't enable PAC generation.
- Obtain a ticket for the admin (or any member of the admins group).
- Run the new command allowing to setup the SID-related configuration.
- Run the existing command to modify base RID and secondary base RID:
```
ipa idrange-mod --rid-base INT --secondary-rid-base INT RANGENAME
```

### Mixed topology

The existing server is not setup for PAC data generation. The future replica
is installed with the latest packages, containing the updated installers.

Run `ipa-replica-install`, with the ability to define:
- NetBIOS Name: if not specified, the default value is generated from
the IPA domain name (transform the left-most label into uppercase, keep only
ascii characters, digits and dashes).
- Primary RID base (default if not set: 1000)
- Secondary RID base (default if not set: 1000000)
- Run SIDgen task immediately: yes/no (default=no)


## Design

Installers and SID-related options:
- the options `--add-sids`, `--netbios-name`, `--rid-base` and 
`--secondary-rid-base` are moved from ADTrustInstallInterface to a separate
new InstallInterface: SIDInstallInterface.
- ADTrustInstallInterface now inherits from SIDInstallInterface.
- `adtrustinstance.ADTRUSTInstance.__init__` now accepts an additional
parameter: `fulltrust`. When set to True, the class ADTRUSTInstance configures
the trust as usual. When set to False, only the SID-related part is executed.
- `ipa-server-install` and `ipa-replica-install` now always call
`adtrust.install_check` and `adtrust.install`, but the method is using the
provided options (especially `options.setup_adtrust`) to know if full
configuration is required or only the SID-related part.

The `ipa-adtrust-install` code is already written in order to be
idempotent (can be called multiple times, even with different values), and
this property is of great value for this feature. It allows to keep
the changes as minimal as possible to the existing installers, and
call `ipa-adtrust-install` even if the SID-part is already setup.

New command to enable SID generation after an upgrade:
as we don't want to automatically enable SID generation during an upgrade,
a new command is provided in order to manually enable the feature. The command
only requires an admin ticket (no need to be root) and relies on the admin
framework.

The command uses a mechanism similar to server_conncheck:
- the user must have Replication Administrators privilege
- the user launches an ipa command communicating with IPA framework
- the admin framework uses Dbus to get access a DBus interface that
launches a command through oddjob, allowing the command to run as root.
The oddjob command is a wrapper around `adtrustinstance.ADTRUSTInstance`.

## Implementation

- Dependencies: no additional dependency on ipa-server package
- Backup and Restore: no new file to backup

## Feature Management

### UI

No new UI for server/replica installation.

`IPA server / ID ranges` tab is already available and displays Primary and 
Secondary RID base.

`IPA Server / Trusts / Global Trust Configuration` tab already displays the
NetBIOS Name and Security Identifier.

These values can also be added in the `IPA Server / Configuration` tab.

The User View displays SMB attributes if they exist and could be enhanced
with a note if the user entry does not have any SID, pointing the admin
to a procedure in order to generate the missing SIDs.

### CLI

| Command |	Options |
| --- | ----- |
| ipa-server-install | [--netbios-name=NETBIOS_NAME] [--rid-base=RID_BASE] [--secondary-rid-base=SECONDARY_RID_BASE]  |
| ipa-replica-install | [--netbios-name=NETBIOS_NAME] [--rid-base=RID_BASE] [--secondary-rid-base=SECONDARY_RID_BASE] [--add-sids] |
| ipa config-mod | --enable-sid [--add-sids] [--netbios-name=NETBIOS_NAME]  |

#### `ipa config-mod --enable-sid` details:

The `--enable-sid` option turns the feature on, and `--add-sids` triggers
the SIDgen task in order to immediately generate SID for existing users or
groups.

`--add-sids` requires the `--enable-sid`option.

The `--netbios-name` option specifies the NetBIOS Name and is optional. If
not provided, the NetBIOS Name is generated from the leading part of the
DNS name.

`--netbios-name` requires the `--enable-sid` option.


### Configuration

When the feature is turned on, it is possible to modify the primary and
secondary RID bases for the local id range with the existing
`ipa idrange-mod` command.

The NetBIOS Name can be overwritten (with warning) when `ipa-adtrust-install`
is run.

## Upgrade

The upgrade does not turn on the feature. If the admin wants to enable
SID generation, he needs to update the packages and run the new command
`ipa config-mod --enable-sid`.


## Test plan

Note: PRCI currently doesn't have the ability to test upgrade.

Scenarios to be tested: fresh install, test PAC generation
- Add active user testuser (reinitialize password)
- On IPA server run `kinit -k` to get a ticket for `host/fqdn@REALM`
- On IPA server run `/usr/libexec/ipa/ipa-print-pac ticket testuser` and
ensure that PAC data is properly displayed.
- Same test on IPA replica

Tests outside of PRCI:
- Existing topology without trust, update one server, ensure SID generation
hasn't been automatically enabled
- Existing topology without trust, update one server, manually enable SID
generation with the new command
- Existing topology without trust, insert a new replica, ensure SID generation
has been automatically enabled
- Existing topology with trust, update one server, ensure SID generation is
still working
- Existing topology with trust, insert a new replica, ensure SID generation
is still working
- Ensure that `ipa-adtrust-install` is still working with the previous
scenarios.

## Troubleshooting and debugging

When the feature is turned on (whatever the path, either through fresh
server installation, fresh replica installation, or with the new command), the
following LDAP entries are expected:

- `cn=ad,cn=trusts,dc=ipa,dc=test` which is a simple `nsContainer`
- `cn=ad,cn=etc,dc=ipa,dc=test` which is a simple `nsContainer`
- `cn=ipa.test,cn=ad,cn=etc,dc=ipa,dc=test`: must define the NetBIOS Name in
`ipaNTFlatName`, the SID in `ipaNTSecurityIdentifier` and the default SMB
group in `ipaNTFallbackPrimaryGroup`
- `cn=Default SMB Group,cn=groups,cn=accounts,dc=ipa,dc=test`: must define
a SID belonging to the IPA domain SID in `ipaNTSecurityIdentifier`

(replace ipa.test with the actual domain name and dc=ipa,dc=test with the
actual base DN).

The admin user must have a SID ending with -500 (well-known SID for the
domain administrator):
```
# ipa user-show admin --all | grep ipantsecurityidentifier
  ipantsecurityidentifier: S-1-5-21-2633809701-976279387-419745629-500
```

The admins group must have a SID ending with -512 (well-known SID for domain
administrators group):
```
# ipa group-show admins --all | grep ipantsecurityidentifier
  ipantsecurityidentifier: S-1-5-21-2633809701-976279387-419745629-512
```

The sidgen plugin must be enabled in /etc/dirsrv/slapd-IPA-TEST/dse.ldif:
```
dn: cn=IPA SIDGEN,cn=plugins,cn=config
cn: IPA SIDGEN
nsslapd-basedn: dc=ipa,dc=test
nsslapd-plugin-depends-on-type: database
nsslapd-pluginDescription: Add a SID to newly added or modified objects with u
 id pr gid numbers
nsslapd-pluginEnabled: on
nsslapd-pluginId: IPA SIDGEN postop plugin
nsslapd-pluginInitfunc: ipa_sidgen_init
nsslapd-pluginPath: libipa_sidgen
nsslapd-pluginType: postoperation
nsslapd-pluginVendor: FreeIPA project
nsslapd-pluginVersion: FreeIPA/1.0
objectClass: top
objectClass: nsSlapdPlugin
objectClass: extensibleObject

```

If the PAC data is not generated for a user, ensure that the user contains a
SID in its `ipantsecurityidentifier` attribute. If the SID is missing, run
the SIDgen task in order to generate SID for existing users and groups:
- Find ipa base DN with: `grep basedn /etc/ipa/default.conf | cut -d= -f2-`
- Copy `/usr/share/ipa/ipa-sidgen-task-run.ldif` to
`/tmp/ipa-sidgen-task-run.ldif`
- Edit the copy `/tmp/ipa-sidgen-task-run.ldif` and replace $SUFFIX with
IPA base DN
- As root, launch the task (replace IPA-TEST with the proper value):
`ldapmodify -H ldapi://%2Frun%2Fslapd-IPA-TEST.socket -f /tmp/ipa-sidgen-task-run.ldif`

In order to check if the PAC data gets added to the user ticket, on a server:
```
# kinit -k
# /usr/libexec/ipa/ipa-print-pac ticket USERNAME
```

If the PAC data is properly added, the `ipa-print-pac` command displays:
```
# /usr/libexec/ipa/ipa-print-pac ticket testuser
Password: 
Acquired credentials for testuser
PAC_DATA: struct PAC_DATA
    num_buffers              : 0x00000005 (5)
    version                  : 0x00000000 (0)
    buffers: ARRAY(5)
        buffers: struct PAC_BUFFER
...
```