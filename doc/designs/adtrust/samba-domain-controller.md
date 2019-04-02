# Support domain controller for Samba file server as domain member on IPA client

## Table of Contents

* [Introduction](#introduction)
* [Domain controller side configuration overview](#domain-controller-side-configuration-overview)
* [Changes required on domain controller](#changes-required-on-domain-controller)
* [Notes about unfinished Samba work](#notes-about-unfinished-samba-work)


## Introduction

[Samba] is a free software that implements various aspects of SMB protocol and
Active Directory infrastructure. Apart from the networking file system that SMB
is well known for, Samba provides services to resolve user and group identities
for resources accessible via SMB. SMB protocol identity model is based on a
Windows NT concept of security identifiers (SIDs) and access control lists
(ACLs) which is not directly compatible with a concept of identities employed
in POSIX environment model. Thus, Samba suite serves as a translation layer
between the two environments.

Active Directory is an extension of Windows NT identity model where identity
information is stored in a database exposed to the world via a combination of
LDAP and SMB protocols, with authentication provided with both password
(NTLMSSP) and Kerberos methods. Systems in Active Directory are organized into
logical groups, domains, where some nodes, domain controllers, are used to
store domain-specific information and others, domain members, utilize the
information via SMB, LDAP, and Kerberos protocols.

SMB protocol has a mechanism for encapsulating and channeling through itself
other types of requests, expressed as an access to "files" over a specialized
share `IPC$`. There are multiple interfaces provided by a typical domain
controller and domain member servers, most well-known ones are LSA (local
security authority, documented in [MS-LSAD] and [MS-LSAT]) and NETLOGON remote
protocol (documented in [MS-NRPC]). LSA remote procedure calls are used, among
other needs, for retrieving identity information about SIDs and their
relationship to other objects. NETLOGON, as its name suggests, is utilized for
authentication in a domain environment, across domains, and across forests of
domains.

In a traditional domain member set up, the member machine has no possession of
a particular user credentials. Instead, it relies on its own connection to its
own domain controller to identify a user and to proxy a user's authentication
to the domain controller of the domain a user belongs to. In case a user is
performing a remote authentication using Kerberos, a remote system has to
present a Kerberos ticket to the domain member's SMB service, like with any
other Kerberos services.

To operate as a domain member in a FreeIPA domain, thus, Samba needs a FreeIPA
master to be configured as a domain controller and a FreeIPA client needs to be
configured in a specific way to allow Samba to talk to a domain controller. This
document overviews a set of implementation tasks to achieve the domain
controller operation.

## Domain controller side configuration overview

FreeIPA master can be configured to perform as a 'trust controller' with the
help of `ipa-adtrust-intall` tool. The tool creates required subtrees and
objects in LDAP, configures Samba to use an `ipasam` PASSDB module which knows
how to deal with FreeIPA LDAP schema for Samba-specific attributes and supports
storing and retrieving information about trusted domains from LDAP. The tool
also makes sure certain 389-ds plugins provided by FreeIPA are enabled and
initialized.

As a result of the configuration, Samba considers itself a domain controller
for the traditional (Windows NT) domain type. Such traditional domain controller
is not capable to serve as a fully-fledged Active Directory domain controller
due to few important limitations:

- Samba traditional domain controller role is not implementing AD DC itself

- LDAP schema used by FreeIPA is different from Active Directory LDAP schema

- LDAP directory information tree (DIT) is different from what Active Directory
  clients expect from an AD DC

- No Global Catalog service is provided

Additionally, `ipasam` PASSDB module is not capable to create machine accounts
for requests coming from Samba. This means `net rpc join` will not work when
issued from FreeIPA domain members. Also, traditional (Windows NT) domain
controller role in Samba is not able to create machine accounts on request from
`net ads join`, a procedure to join machine to an Active Directory.

The limitations above are fine for FreeIPA environment because FreeIPA clients
perform its own enrollment process via IPA API and a special LDAP control
extension.

When a domain member establishes a secure channel connection to a domain
controller, following is considered on the domain controller side:

- DCE RPC connection is negotiated and authenticated. As part of authentication,
  either NTLMSSP or Kerberos token is processed and converted into a local NT
  token.

- Local NT token represents a remote user (machine account) on the domain
  controller. The information includes POSIX attributes as well as NT attributes
  since Samba will spawn a process to handle the connection under local POSIX
  user identity. Each machine account, therefore, requires associated POSIX
  attributes.

- DCE RPC connection from a domain member is authenticated by use of mutually
  known secret, machine account credentials. Additionally, when Kerberos is in
  use, DCE RPC packets might be signed with the use of a service ticket to the
  domain controller's machine account (`host/...` principal in Kerberos) because
  on Windows systems all other service principals (SPNs) are presented as
  aliases to the machine account.

## Changes required on domain controller

Domain controller configuration is mostly covered already by the
`ipa-adtrust-install` installation utility. The only missing part is to make
sure Samba has access to the host keytab. The host keytab's content is copied
during upgrade process and also is added during initial `ipa-adtrust-install`
run.

The rest of the changes fall into specific parts of FreeIPA configuration.

### Changes to FreeIPA framework

A new command is added to the `ipa service` family, `ipa service-add-smb`. This
command creates LDAP object that represents `cifs/...` service principal for the
domain member. This LDAP object must have a number of attributes assigned that
cannot be assigned past creation because otherwise object classes set on the
object will not pass through constraint checks.

The SMB service object needs to have:
 - POSIX attributes
 - NT attributes, including `ipaNTSecurityIdentifier`

`ipaNTSecurityIdentifier` is filled in by the SID generation plugin at the
object creation time for SMB service.

`ipaNTSecurityIdentifier` attribute is a part of `ipaNTUserAttrs` object class
for users and SMB services. IPA groups also can contain the attribute via
`ipaNTGroupAttrs` object class.

With the help of the `sidgen` plugin, ipaNTSecurityIdentifier attribute is only
added when:
 - the object has POSIX attributes `uidNumber` and `gidNumber`
 - the values of those attributes are within 32-bit unsigned integer
 - the object has any of the following object classes: `ipaIDObject`,
   `posixAccount`, or `posixGroup`
 - the object has no `ipaNTSecurityIdentifier` attribute already.

`sidgen` plugin will add `ipaNTUserAttrs` object class for non-group objects and
`ipaNTGroupAttr` for the group object type. A plugin is triggered at an object
creation or via an LDAP task. One can trigger task run by running
`ipa-adtrust-install --add-sids` on the trust controller.

LDAP object class `ipaNTUserAttrs` defines few other attributes. These
attributes, called below 'SMB attributes', are required by the domain controller
to define content of an NT token for an authenticated identity (user or a
machine account).

SMB attributes are:
 - `ipaNTLogonScript`
   : Path to a script executed on a Windows system at logon
 - `ipaNTProfilePath`
   : Path to a user profile, in UNC format `\\server\share\`
 - `ipaNTHomeDirectory`
   : Path to a user's home directory, in UNC format `\\server\share`
 - `ipaNTHomeDirectoryDrive`
   : a letter `[A-Z]` for the drive to mount the home directory to on a Windows system

All SMB attributes require the presence of `ipaNTUserAttrs` object class in the
user object LDAP entry. This object class cannot be added without
`ipaNTSecurityIdentifier`. Adding SID requires to consume IDs from a range
suitable for SIDs and this logic is recorded in the `sidgen` plugin. Thus, until
SID is generated, no attributes can be set on the user entry.

As result of it, SMB attributes are not available at `ipa user-add` or
`ipa stageuser-add` level. Instead, it is possible to modify a user object with
`ipa user-mod` or `ipa stageuser-mod` commands:

```
$ ipa user-mod --help
Usage: ipa [global-options] user-mod LOGIN [options]

Modify a user.
Options:
...
  --smb-logon-script=STR    SMB logon script path
  --smb-profile-path=STR    SMB profile path
  --smb-home-dir=STR        SMB Home Directory
  --smb-home-drive=['A:', 'B:', 'C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:',
                    'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:', 'U:', 'V:',
                    'W:', 'X:', 'Y:', 'Z:']
                   SMB Home Directory Drive
...

$ ipa stageuser-mod --help
Usage: ipa [global-options] stageuser-mod LOGIN [options]

Modify a stage user.
Options:
...
  --smb-logon-script=STR    SMB logon script path
  --smb-profile-path=STR    SMB profile path
  --smb-home-dir=STR        SMB Home Directory
  --smb-home-drive=['A:', 'B:', 'C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:',
                    'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:', 'U:', 'V:',
                    'W:', 'X:', 'Y:', 'Z:']
                   SMB Home Directory Drive
...
```

Due to limitations on how SMB attributes can be added, Web UI shows the section
"User attributes for SMB services" without any values for those users who have
no SID assigned.

### Changes to LDAP storage

By default, POSIX attribute can only be searched by LDAP clients in
`cn=users,cn=accounts,$basedn` and `cn=groups,cn=accounts,$basedn` subtrees.
Since SMB service belongs to `cn=services,cn=accounts,$basedn` subtree, new ACI
has to be added.

```
'System: Read POSIX details of the SMB services': {
    'replaces_global_anonymous_aci': True,
    'ipapermbindruletype': 'all',
    'ipapermright': {'read', 'search', 'compare'},
    'ipapermdefaultattr': {
        'objectclass', 'cn', 'uid', 'gecos', 'gidnumber',
        'homedirectory', 'loginshell', 'uidnumber',
        'ipantsecurityidentifier',
    },
}
```

SMB attributes for users are now accessible for self-modification and also
readable by the members of `cn=adtrust agents,cn=sysaccounts,cn=etc,$basedn`
group which contains, among others, service principals of the domain
controllers.

### Changes to LDAP plugins

As mentioned above, both domain controller and domain member need to know common
secret -- the machine account credential of the domain member. For the purpose
of [MS-NRPC] section 3.1.4.3.1, it is enough to know RC4-HMAC hash. Given that
there is general willingness to not allow access to RC4-HMAC key over Kerberos
in contemporary systems, FreeIPA code was changed to explicitly allow generation
of RC4-HMAC hash for SMB service only. For users in FreeIPA generation of
RC4-HMAC will be disabled.

Combined with system-wide crypto policy changes in Fedora 30, it means that both
in FIPS and non-FIPS environment RC4-HMAC will not be usable as a Kerberos
encryption type unless an application explicitly specifies it and RC4-HMAC key
exists in the principal's database entry in FreeIPA.

A consequence of it is that RC4-HMAC hash will not be usable for FreeRADIUS
integration because the hashes will be missing from user entries.

### Changes to Kerberos KDC driver

Support for recognizing SMB service principals as machine accounts is added to
Kerberos KDB driver. For SMB service principal an MS-PAC record is generated.

### Changes to Samba PASSDB driver

Support for resolving SIDs to user and group names is added. This is needed to
allow Samba domain controller to resolve requests from Samba domain member
servers for SID to ID conversion.

Support for recognizing machine accounts as `ACB_WSTRUS` entry type in PASSDB is
added. This is needed to allow Samba domain members to login to Samba domain
controller for LSA RPC and Netlogon operations.

Support is added to recognize machine account names (NetBIOS names plus '$'
sign) as machines. Multivalued `uid` attribute in the LDAP object entry is now
supported as SMB service objects will have both `cifs/...` and `NetBIOS$` names
assigned to `uid` attribute. Samba looks up POSIX entries by using either
Kerberos principal name or machine account name depending on a code flow in
different parts of the SMB login processing, thus both needs to be supported.

## Notes about unfinished Samba work

Since changes on Samba side apply for both domain controller and domain member,
unfinished work is reflected in a single place only.

Below is the current list, most of the entries on it are still open.

 - Samba needs to implement 'net ads offlinejoin' call to allow setting
   up a machine account and SID without actually joining the machine via
   DCE RPC (for IPA or VAS or other join types).

   See https://lists.samba.org/archive/samba-technical/2018-November/131274.html
   for one part that should explain failures with 'did we join?' message in the
   logs.

 - windbindd daemon attempts to look up list of trusted domains from own domain
   controller. Samba domain controller, as used in FreeIPA does not implement
   `netr_DsrEnumerateDomainTrust` call. The situation here is the same as in
   https://lists.samba.org/archive/samba-technical/2019-May/133662.html which is
   another call we need to implement to allow Windows side operations.

    ```
    [2019/06/28 04:27:35.699042,  1, pid=31998, effective(0, 0), real(0, 0), class=rpc_cli] ../source3/rpc_client/cli_pipe.c:569(cli_pipe_validate_current_pdu)
      ../source3/rpc_client/cli_pipe.c:569: RPC fault code DCERPC_NCA_S_OP_RNG_ERROR received from host master.ipa.test!
    [2019/06/28 04:27:35.699065, 10, pid=31998, effective(0, 0), real(0, 0), class=rpc_cli] ../source3/rpc_client/cli_pipe.c:979(rpc_api_pipe_got_pdu)
      rpc_api_pipe: got frag len of 32 at offset 0: NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE
    [2019/06/28 04:27:35.699159,  3, pid=31998, effective(0, 0), real(0, 0), class=winbind] ../source3/winbindd/winbindd_ads.c:1391(trusted_domains)
      ads: trusted_domains
    [2019/06/28 04:27:35.699191,  1, pid=31998, effective(0, 0), real(0, 0), class=rpc_parse] ../librpc/ndr/ndr.c:471(ndr_print_function_debug)
          netr_DsrEnumerateDomainTrusts: struct netr_DsrEnumerateDomainTrusts
              in: struct netr_DsrEnumerateDomainTrusts
                  server_name              : *
                      server_name              : 'master.ipa.test'
                  trust_flags              : 0x00000023 (35)
                        1: NETR_TRUST_FLAG_IN_FOREST
                        1: NETR_TRUST_FLAG_OUTBOUND
                        0: NETR_TRUST_FLAG_TREEROOT
                        0: NETR_TRUST_FLAG_PRIMARY
                        0: NETR_TRUST_FLAG_NATIVE
                        1: NETR_TRUST_FLAG_INBOUND
                        0: NETR_TRUST_FLAG_MIT_KRB5
                        0: NETR_TRUST_FLAG_AES
    ```

[Samba]: https://www.samba.org/
[MS-NRPC]: https://msdn.microsoft.com/en-us/library/cc237008.aspx
[MS-LSAD]: https://msdn.microsoft.com/en-us/library/cc234225.aspx
[MS-LSAT]: https://msdn.microsoft.com/en-us/library/cc234420.aspx


