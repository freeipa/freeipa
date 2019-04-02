# Support Samba file server as a domain member on IPA client

## Table of Contents

* [Introduction](#introduction)
* [Domain member configuration overview](#domain-member-configuration-overview)
* [Domain controller side configuration overview](#domain-controller-side-configuration-overview)
* [Changes required on domain member](#changes-required-on-domain-member)
* [Example of using Samba file server on IPA client](#example-of-using-samba-file-server-on-ipa-client)

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
configured in a specific way to allow Samba to talk to a domain controller.
This document overviews a set of implementation tasks to achieve the domain
member operation. Most of these tasks are related to FreeIPA components but
some of changes required do belong to Samba itself.

## Domain member configuration overview

Samba suite, when running as a domain member, starts two daemons:

- `smbd`, the main process which handles network connections, file system
  operations, and remote procedure calls like LSA and NETLOGON. Each connection
is handled by a separate `smbd` child;

- `winbindd`, a process to perform identity resolution for all configured and
  known domains. Active connection to a domain is handled by a separate
  `winbindd` child. `winbindd` processes connect to domain controllers and
  perform required LSA and NETLOGON operations against them. Normally,
  authentication of a user from a trusted domain is delegated to the domain
  member's own domain controller which then forwards it further.

Both `smbd` and `winbindd` daemons rely on a number of pluggable components to
abstract out various aspects of their operations. For `smbd`, there are
pluggable modules to represent file system operations. It also uses so-called
PASSDB interface to convert SIDs to POSIX identities and back --- this
interface might be optional on a domain member. In some special cases `smbd`
also directly resolves a name of a user associated with the authenticated
connection using standard POSIX API for name resolution (getpwnam() and similar
calls). All other identity resolution operations it delegates to `winbindd`.

`winbindd` uses a set of identity mapping modules collectively called 'idmap
modules' in Samba terminology. Each `idmap` module represents a strategy to map
SIDs to corresponding POSIX IDs. Since SID name space in Active Directory is
common for all kind of objects and POSIX ID name space is separate for users and
groups, with both POSIX ID name spaces being smaller than a common SID name
space, there exist multiple approaches to perform the translation. A choice of a
translation method is tightly connected with a specific deployment
configuration. ID mapping module should be coordinated with a PASSDB module (if
one is defined) and how an operating system represents the POSIX users and
groups.

To communicate with its domain controller, Samba needs to know own machine
account information. Machine account is an account in Active Directory that has
its name derived from a NetBIOS machine name (due to Windows NT past) post-fixed
with a `$` sign, e.g. `MY-MACHINE$`. Password for the machine account is the
same as the one used to derive Kerberos keys for the `host/..` and `cifs/..`
principals of the same host. In Active Directory all Kerberos principals
associated with the host (service principal names, SPNs) share the same Kerberos
keys. Thus, Samba needs to known a clear text password for the machine account
and it can derive all Kerberos keys for itself based on that knowledge. The
clear text password knowledge is also important for the case of machine account
password rotation.

The knowledge of the machine account password is recorded in a special
database, `secrets.tdb`, during the process of a machine join to the domain.
For FreeIPA client the join process is different from the one Samba uses for
Active Directory, thus we need to seed the machine account password separately
to enrolling FreeIPA client. Note that FreeIPA machine enrollment does not
allow to share clear text machine account password as it is not recorded
anywhere.

## Domain controller side configuration overview

See [samba-domain-controller] for the details of how Samba domain controller is
set up and configured in FreeIPA.

## Changes required on domain member

In order to configure the domain member part of Samba suite, following steps
need to be preformed. These steps are implemented as an installer utility
`ipa-client-samba` and are provided here for documentation purpose only.

Assumptions:

* At least one of IPA masters is configured as a trust controller using
   `ipa-adtrust-install`. This is required to enable a hybrid SMB domain where
   Samba domain controller would understand Samba domain members enrolled via
   IPA tools but will not be able to enroll them any other way.

* A client host is enrolled into IPA, with a fully-qualified hostname,
  `${hostname}`. Additional elements that will be referred to below:

  `${realm}`
  : IPA domain's realm

  `${netbios_name}`
  : NetBIOS name of a domain, whether it is IPA or a trusted Active Directory domain

  `${machine_name}`
  : NetBIOS name of the client where Samba domain member is being deployed

Next steps should be performed on the client itself. With the support for Samba
domain member enabled, IPA masters allow creation of the required records with
the host credentials (`host/${hostname}`).

```
# kinit -k
```

1. Retrieve information about Security Identifier and NetBIOS name of the IPA
   domain:

   ```
   # kinit -k
   # ipa trustconfig-show --raw
     cn: ipa.realm
     ipantsecurityidentifier: S-1-5-21-570121326-3336757064-1157332047
     ipantflatname: ipa
     ipantdomainguid: be06e132-876a-4f9c-aed4-ef2dc1de8118
     ipantfallbackprimarygroup: cn=Default SMB Group,cn=groups,cn=accounts,dc=ipa,dc=realm
   ```

   In the output above,

   `cn`
   : IPA domain's realm, `${realm}`, in lower case

   `ipantsecurityidentifier`
   : IPA domain's SID (security identifier)

   `ipaflatname`
   : IPA domain's NetBIOS name, `${netbios_name}, also known as the flat name in Active Directory

   `ipantdomainguid`
   : IPA domain's globally unique identifier (GUID)

2. Retrieve ID range information for the IPA domain and other trusted domains:

   ```
   # ipa idrange-find --raw
   ----------------
   2 ranges matched
   ----------------
     cn: AD.DOMAIN_id_range
     ipabaseid: 967000000
     ipaidrangesize: 200000
     ipabaserid: 0
     ipanttrusteddomainsid: S-1-5-21-1356309095-650748730-1613512775
     iparangetype: ipa-ad-trust

     cn: IPA.REALM_id_range
     ipabaseid: 1536000000
     ipaidrangesize: 200000
     ipabaserid: 1000
     ipasecondarybaserid: 100000000
     iparangetype: ipa-local
   ----------------------------
   Number of entries returned 2
   ----------------------------
   ```

   From the output above, `ipabaseid` and `ipaidrangesize` attributes are used
   to define ranges for Samba configuration. Samba requires to have IDMAP ranges
   set for specific domains. For each such range, a pair of (range start, range
   end) values will need to be calculated:

   ```
   ${range_id_min} = ipabaseid
   ${range_id_max} = ipabaseid + ipaidrangesize - 1
   ```

3. Add Samba-specific Kerberos service principal using `ipa service-add-smb`
   command. This command runs a sequence of operations on IPA master that create
   an LDAP object for the Samba service Kerberos principal with required LDAP
   object classes and attributes. Some of the attributes have to be set at the
   creation time because they are auto-generated when the object is added, thus
   a sequence of `ipa service-add` and `ipa service-mod` commands cannot be used
   instead.

   ```
   # ipa service-add-smb <hostname> [<NetBIOS name>]
   ```

4. Generate a random pre-defined password for the machine account that will be
   used for both Samba-specific Kerberos service princiapl and for Samba machine
   account. The generated password has to follow few rules to be usable by
   Samba. In particular, it has to be encoded in UTF-16. Samba Python bindings
   provide two methods to allow the password generation,
   `generate_random_machine_password()` and `generate_random_password()`. While
   the former call is what is needed, it returns munged UTF-16 which is not
   readable by `net changesecretpwd -f` utility. Thus, the latter call is used
   instead. Its output is limited to ASCII characters but still should be strong
   enough for a machine account password. The code used by the
   `ipa-client-samba` utility is equivalent for the following call:

   ```
   # python3 -c 'import samba; print(samba.generate_random_password(128, 255))'
   ```

5. Retrieve the Kerberos key for `cifs/<hostname>` service using pre-defined
   password for the key. The domain controller must know RC4-HMAC hash of the
   domain member machine account in order to allow NetLogon ServerAuthenticate3
   operation. ServerAuthenticate3 call needs an AES session key which is
   calculated based on an RC4-HMAC of the machine account credential according
   to [MS-NRPC] section 3.1.4.3.1. The code used by the `ipa-client-samba`
   utility is equivalent for the following call:

   ```
   # ipa-getkeytab -p cifs/<hostname> -k /etc/samba/samba.keytab -P \
                   -e aes128-cts-hmac-sha1-96,aes256-cts-hmac-sha1-96,arcfour-hmac
   ```
   Note that in the call above three encryption types were passed explicitly.
   The reason for that is to allow to pass RC4-HMAC encryption type request
   through Kerberos library used by `ipa-getkeytab` in FIPS mode.
   `ipa-getkeytab` utility uses Kerberos encryption types internally. If
   RC4-HMAC is not allowed for use by the system-wide crypto policy, it will not
   be specified in the list of default encryption types. If `ipa-getkeytab`
   utility gets `-e` option, it overrides rather than amends the list of the
   default encryption types, thus forcing to specify the whole set of encryption
   types explicitly.

6. Create Samba config as `/etc/samba/smb.conf` on the client:

   ```
   [global]
    # Limit number of forked processes to avoid SMBLoris attack
    max smbd processes = 1000
    # Use dedicated Samba keytab. The key there must be synchronized
    # with Samba tdb databases or nothing will work
    dedicated keytab file = FILE:/etc/samba/samba.keytab
    kerberos method = dedicated keytab
    # Set up logging per machine and Samba process
    log file = /var/log/samba/log.%m
    log level = 1
    # We force 'member server' role to allow winbind automatically
    # discover what is supported by the domain controller side
    server role = member server
    realm = IPA.REALM
    netbios name = ${machine_name}
    workgroup = ${netbios_name}
    # Local writable range for IDs not coming from IPA or trusted domains
    idmap config * : range = 0 - 0
    idmap config * : backend = tdb
    idmap config ${netbios_name} : range = ${range_id_min} - ${range_id_max}
    idmap config ${netbios_name} : backend = sss
   ```

   In the config above two IDMAP configurations were defined:
    * for the IPA domain the range from `ipabaseid` to
      `ipabaseid + ipaidrangesize - 1` is used. IDMAP backend configuration says
      that the range is served by SSSD, using `idmap_sss` module. `idmap_sss`
      module is provided by `sssd-winbind-idmap` package.

    * for all unknown domains a local 'tdb' IDMAP backend and a range that
      doesn't conflict with IPA domain is used. In fact, this has to be choosen
      carefully, especially if IPA setup already integrates with Active
      Directory and other ranges defined for AD domains. In such case one needs
      to define separate `idmap config FOO : range` and
      `idmap config FOO : backend` options per each AD domain that is served
      through IPA trust to Active Directory the same way as for
      `idmap config IPA`. The values there should come from the corresponding ID
      ranges for AD domains.

7. Defining access to specific shares can be done with a normal Samba
   `write list` option. An example below grants access to share `shared` to
   everyone in IPA `admins` group. The group membership resolution will be done
   by SSSD. It is recommended to use POSIX ACLs tools to set up access controls
   on the local file system instead of directly setting them in the Samba
   configuration as this gives more flexibility. Also, one needs to make sure
   that the POSIX path specified in the share actually allows write access to
   the users or groups from the `write list`:

   ```
   [shared]
     path = /srv/shared
     read only = No
     write list = @admins

   [homes]
     browsable = no
     writable = yes

   ```

8. Samba configuration has to use the same Security Identifier for the domain as
   is used by the IPA domain controller. The original value is retrieved in step
   1 as `ipantsecurityidentifier`. This information is not stored in the
   `smb.conf`. Instead, it is stored in the binary databases managed by Samba.
   It can be set through `net setdomainsid` command:

   ```
   # net setdomainsid ${ipantsecurityidentifier}
   ```

9. For SMB protocol, `BUILTIN\Guests` group has always to be mapped to a local
   POSIX groups. It is typically mapped to a local nobody group. This is
   required in all recent Samba releases:

   ```
   # net groupmap add sid=S-1-5-32-546 unixgroup=nobody type=builtin
   ```

10. Before using Samba, it needs to know the machine account credentials.
    Unfortunately, it is only possible to change the machine account credentials
    when Samba is already enrolled into domain or set it when it is being
    enrolled with `net [ads|rpc] join` command. Since IPA client host is
    enrolled using an alternative method, the join command cannot be used and
    internal binary databases do not contain correct values that allow Samba to
    see itself as an enrolled one.

    Instead, until a support for 'offline' enrollment is added, the following
    procedure has to be used. The procedure employs low-level tools to
    manipulate Samba TDB databases:

    ```
    # tdbtool /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_LAST_CHANGE_TIME/${netbios_name} '2\00'
    # tdbtool /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_PASSWORD/${netbios_name} '2\00'
    # net changesecretpw -f
    ```
    `${netbios_name}` value in the calls above corresponds to the IPA domain's
    NetBIOS name. `net changesecretpw -f` call will require entering the
    password generated at the step 4.

11. Start Samba systemd services. At least `smb.service` and `winbind.service`
    services has to be started because Samba cannot function without both of
    them in newer releases. `winbindd` daemon is an integral part of Samba and
    all fallback code for the cases when `winbindd` was not running in some
    configurations was removed from `smbd` daemon in newer Samba releases.

    ```
    # systemctl start smb winbind
    ```

## Example of using Samba file server on IPA client

Once `ipa-client-samba` utility was used to configure Samba services, the shares
were added and systemd services `smb.service` and `winbind.service` were
started, one can access a Samba share as a user from IPA domain. Below is an
example from the test run of `ipatests/test_integration/test_smb.py` done by PR
CI.

```
# kinit athena
Password for athena@IPA.TEST:
# mkdir -p /mnt/athena
# mount -t cifs //replica0.ipa.test/homes  /mnt/athena -o user=athena,sec=krb5i
# dd  count=1024 bs=1K if=/dev/zero of=/mnt/athena/athena.dat
1024+0 records in
1024+0 records out
1048576 bytes (1.0 MB, 1.0 MiB) copied, 0.0339479 s, 30.9 MB/s
# findmnt -t cifs
TARGET      SOURCE                    FSTYPE OPTIONS
/mnt/athena //replica0.ipa.test/homes cifs   rw,relatime,vers=3.1.1,sec=krb5,cruid=0i,cache=strict,username=athena,uid=0,noforceuid,gid=0,noforcegid,addr=192.168.121.171,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1
# ls -laZ /mnt/athena/athena.dat
 -rwxr-xr-x 1 root root ? 1048576 Jun 19 11:45 /mnt/athena/athena.dat
# smbstatus

Samba version 4.10.4
PID     Username     Group        Machine                                   Protocol Version  Encryption           Signing
----------------------------------------------------------------------------------------------------------------------------------------
17249   athena       athena       192.168.121.43 (ipv4:192.168.121.43:46286) SMB3_11           -                    AES-128-CMAC
 
Service      pid     Machine       Connected at                     Encryption   Signing     
---------------------------------------------------------------------------------------------
IPC$         17249   192.168.121.43 Wed Jun 19 11:45:46 AM 2019 UTC  -            AES-128-CMAC
athena       17249   192.168.121.43 Wed Jun 19 11:45:46 AM 2019 UTC  -            AES-128-CMAC

No locked files

# umount -a -t cifs
# smbclient -k //replica0.ipa.test/homes -c 'allinfo athena.dat'
 altname: athena.dat
 create_time:    Wed Jun 19 11:45:46 AM 2019 UTC
 access_time:    Wed Jun 19 11:45:46 AM 2019 UTC
 write_time:     Wed Jun 19 11:45:46 AM 2019 UTC
 change_time:    Wed Jun 19 11:45:46 AM 2019 UTC
 attributes: A (20)
 stream: [::$DATA], 1048576 bytes
 # kdestroy -A
 ```


## Notes about unfinished Samba work

Since changes on Samba side apply for both domain controller and domain member,
unfinished work is reflected in a single place only. Please see [samba-domain-controller]
for details.

[Samba]: https://www.samba.org/
[MS-NRPC]: https://msdn.microsoft.com/en-us/library/cc237008.aspx
[MS-LSAD]: https://msdn.microsoft.com/en-us/library/cc234225.aspx
[MS-LSAT]: https://msdn.microsoft.com/en-us/library/cc234420.aspx
[samba-domain-controller]: samba-domain-controller.md

