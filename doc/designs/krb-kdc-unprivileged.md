# Run Kerberos server processes as unprivileged user

**DRAFT**

## Abstract

This design document proposes to run Kerberos server as a less
privileged service user and LDAP instead of privileged root user and
Directory Manager account.

## Rational

The two main benefits for running less processes as root are

1. general security hardening
2. better integration with containers

...

## Terminology

Kerberos is a core component of FreeIPA. Every FreeIPA server runs two
Kerberos daemons in systemd which listen and process incoming requests.
The key distribution center (``krb5kdc``) handles authentication and
ticket requests like ``kinit``. The Kerberos administrative server
(``kadmind``) deals with password changes and ``kadmin`` requests.

Both services run as privileged root user. Both processes connect to a
local 389-DS LDAP server instance over Unix domain socket to read and
write all account data and most of their configuration. The LDAP server
is configured to use LDAPI AutoBind feature (``SO_PEERCRED``) to
authenticate connection by uid 0 (root) as ``cn=Directory Manager``.
The Directory Manager has unrestricted read/write access.

## Implementation details

### LDAPI AutoBind

389-DS's [auto bind feature](
https://directory.fedoraproject.org/docs/389ds/FAQ/ldapi-and-autobind.html)
for LDAPI connections maps effective uid and gid of a client process
to an LDAP account. Currently autobind is configured to map only
root/root to ``cn=Directory Manager``. In order to map other euid/egid
combinations ``nsslapd-ldapientrysearchbase`` in ``cn=config`` must
be reconfigured and an LDAP entry with matching ``uidNumber`` and
``gidNumber`` must exist. On LDAPI connection with SASL EXTERNAL auth
the LDAP server performs a query
``(&(uidNumber=<uid>)(gidNumber=<gid>)`` with base DN
``nsslapd-ldapientrysearchbase``. The search base is currently not set.
To prevent mapping of standard user accounts the search base for LDAPI
is limited to system accounts ``cn=sysaccounts,cn=etc,$SUFFIX``.

```raw
dn: cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX
objectClass: groupofnames
objectClass: ipaIDobject
objectClass: top
cn: krb5kdc
uidNumber: $KRB5KDC_UID
gidNumber: $KRB5KDC_GID
```

* ``groupofnames`` for ``CN`` and ``memberOf`` (not used yet)
* ``ipaIDobject`` for ``uidNumber`` and ``gidNumber``
* ``top`` for structur

### LDAP ACIs

The KDC is configured and started very early. FreeIPA's RBAC
permissions and privileges are not available yet. Therefore the
``krb5kdc`` cannot use permissions and requires dedicated ACIs.

#### read, search, compare

* Kerberos ticket policy ``objectClass=krbticketpolicyaux``
* Kerberos principal ``objectClass=krbPrincipal`` / ``objectClass=krbPrincipalAux``
* IPA Kerberos principal ``objectClass=ipaKrbPrincipal``
* Kerberos realm ``objectClass=krbRealmContainer``
* password policy ``objectClass=krbPwdPolicy``
* S4U2Proxy delecation ACLs ``objectClass=ipaKrb5DelegationACL``
* OTP tokens ``objectClass=ipaToken``
* COS templates ``objectClass=costemplate``
* ipaConfigString, ipaKrbAuthzData, ipaUserAuthType, ``cn=ipaConfig,cn=etc,$SUFFIX``
* POSIX accounts (covered by krbticketpolicyaux ???) ``objectClass=posixaccount``
* Samba and NT passwords ???
* ...

#### write

* principal key, password history, last login, ...

### User account with soft-static UID and GID

Since the ``krb5kdc`` LDAP sysaccount is replicated, the uid and
primary gid of the system account must be equal on all servers. The
account cannot be stored in LDAP because the KDC is configured before
SSSD and user accounts are set up. Therefore a [soft-static allocated](
https://docs.fedoraproject.org/en-US/packaging-guidelines/UsersAndGroups/)
uid and gid must be requested from Fedora Packaging Committee.

### Binding to low ports

The KDC listens on 88/TCP and 88/UDP, the kadmin daemon on 464/TCP,
464/UDP, and 749/TCP. By default Linux prevents non-root users to bind
to low ports < 1024. systemd has an option to grant net bind service
capability to a process so it can bind to low ports.

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

**NOTE** The capability ``CAP_NET_BIND_SERVICE`` is not strictly
required and only used to simply configuration for non-container case.
It's also possible to bind ``krb5kdc`` and ``kadmind`` processes to
high ports and map ports with firewall rules.

### KDC config files

By default the config files and ``kdc.key`` under
``/var/kerberos/krb5kdc/`` are readable by root user only. The
``krb5kdc`` system user must be allowed to read these files.

### PID files

``krb5kdc`` and ``kadmind`` are forking daemons and therefore require
a PID file to interact with systemd correctly. By default the processes
store their pid files in ``/run/`` (aka ``/var/run/``). The directory
is only writable by root. Therefore the pid file location must be
changed to a dedicated directories that are writable by ``krb5kdc``
user and have correct SELinux file context ``krb5kdc_var_run_t``
for ``krb5kdc`` and ``kadmind_var_run_t`` for ``kadmind``. Since
``/run`` is a volatile file system the directory must be created by
``systemd-tmpfiles``.

The pid file location can be changed by systemd unit drop-in.

### Log files

Both daemons store their log files in ``/var/log`` by default. Like in
the pid files case the location is not writable by non-root. Log files
must be written to a new directory ``/var/log/krb5kdc`` that is owned
by ``krb5kdc`` system account. The log file location is configured in
``/var/kerberos/krb5kdc/kdc.conf``.

The logrotate service and SOS reporter must be updated to use the new
file locations.

### ipa-pwd-extop LDAP plugin

Password changes from ``cn=krb5kdc,cn=sysaccounts`` must be treated as
``IPA_CHANGETYPE_DSMGR`` so the plugin does not expire passwords
on change. The sysaccount is registered as a pass sync manager account.

### ipa-otpd

The Unix socket of the OTPD responder must be owned by ``kdc5kdc`` user
and the process can now be executed as ``krb5kdc`` user, too.

### Other files and directories

* ``/run/krb5kdc`` must be owned by ``krb5kdc:krb5kdc`` user and group
* ``/var/cache/krb5rcache`` ?

### SELinux file context

* ``/var/log/krb5kdc/krb5kdc.log*`` -> ``krb5kdc_log_t``
* ``/var/log/krb5kdc/kadmind.log*`` -> ``kadmind_log_t``
* ``/run/krb5kdc`` -> ``krb5kdc_var_run_t``
* ``/run/kadmind`` -> ``kadmind_var_run_t``

## TODO

- [ ] change permissions and ownership of KDC cert and key
- [ ] request pre-allocated uid/gid from FCP
- [ ] properly implement ipa_powd_extop check for cn=krb5kdc or use
  ``passSyncManagersDNs``
- [ ] define fine grained ACIs for cn=krb5kdc
- [ ] implement update code
- [ ] update Debian and SuSE platform definitions
- [ ] run ``ipa-otpd`` as krb5kdc user?
- [x] SELinux rule updates for krd5kdc and kadmind
- [ ] Move SELinux file contexts to upstream

## Dump

```raw
dn: $SUFFIX
changetype: modify
add: aci
# cn=System: Read Default Kerberos Ticket Policy,cn=permissions,cn=pbac,$SUFFIX
aci: (targetattr = "createtimestamp || entryusn || krbauthindmaxrenewableage || krbauthindmaxticketlife || krbdefaultencsalttypes || krbmaxrenewableage || krbmaxticketlife || krbsupportedencsalttypes || modifytimestamp || objectclass")(targetfilter = "(objectclass=krbticketpolicyaux)")(version 3.0;acl "KRB5KDC:System: Read Default Kerberos Ticket Policy";allow (compare,read,search) userdn = "ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)
# cn=System: Read Group Password Policy costemplate,cn=permissions,cn=pbac,$SUFFIX
aci: (targetattr = "cn || cospriority || createtimestamp || entryusn || krbpwdpolicyreference || modifytimestamp || objectclass")(targetfilter = "(objectclass=costemplate)")(version 3.0;acl "KRB5KDC:System: Read Group Password Policy costemplate";allow (compare,read,search)  userdn = "ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)
# cn=System: Read User Kerberos Login Attributes,cn=permissions,cn=pbac,$SUFFIX
aci: (targetattr = "krblastadminunlock || krblastfailedauth || krblastpwdchange || krblastsuccessfulauth || krbloginfailedcount || krbpwdpolicyreference || krbticketpolicyreference || krbupenabled")(targetfilter = "(objectclass=posixaccount)")(version 3.0;acl "KRB5KDC:System: Read User Kerberos Login Attributes";allow (compare,read,search)  userdn = "ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)
# cn=System: Read system trust accounts,cn=permissions,cn=pbac,$SUFFIX
aci: (targetattr = "gidnumber || krbprincipalname || uidnumber")(version 3.0;acl "permission:System: Read system trust accounts";allow (compare,read,search) groupdn = "ldap:///cn=System: Read system trust accounts,cn=permissions,cn=pbac,dc=ipa,dc=example";)
# extra KRB stuff
aci: (targetattr = "ipakrbauthzdata || ipakrbprincipalalias || ipauniqueid || krbcanonicalname || krbobjectreferences || krbpasswordexpiration || krbprincipalaliases || krbprincipalauthind || krbprincipalexpiration || krbprincipalname")(version 3.0;acl "KRB5KDC:System: Read Other Kerberos Attributes";allow (compare,read,search)  userdn = "ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)
# ALL
aci:(targetattr = "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory || krbMKey || krbPrincipalName || krbCanonicalName || krbPwdHistory || krbLastPwdChange || krbExtraData || krbLastSuccessfulAuth || krbLastFailedAuth || ipaNTHash")(version 3.0; acl "KRB5 KDC can read/write credentials"; allow (all) userdn = "ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)
# read tokens
aci: (targetfilter = "(objectClass=ipaToken)")(targetattrs = "objectclass || description || managedBy || ipatokenUniqueID || ipatokenDisabled || ipatokenNotBefore || ipatokenNotAfter || ipatokenVendor || ipatokenModel || ipatokenSerial || ipatokenOwner")(version 3.0; acl "KRB5KDC:System: KDC can read basic token inf"; allow (read, search, compare) userdn="ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)
# XXX
# aci: (targetattr = "krbPrincipalName || krbCanonicalName || krbUPEnabled || krbPrincipalKey || krbTicketPolicyReference || krbPrincipalExpiration || krbPasswordExpiration || krbPwdPolicyReference || krbPrincipalType || krbPwdHistory || krbLastPwdChange || krbPrincipalAliases || krbLastSuccessfulAuth || krbLastFailedAuth || krbLoginFailedCount || krbPrincipalAuthInd || krbExtraData || krbLastAdminUnlock || krbObjectReferences || krbTicketFlags || krbMaxTicketLife || krbMaxRenewableAge || nsaccountlock || passwordHistory || ipaKrbAuthzData || ipaUserAuthType || ipatokenRadiusConfigLink || krbAuthIndMaxTicketLife || krbAuthIndMaxRenewableAge || objectClass")(version 3.0; acl "System: KDC"; allow (read, search, compare) userdn="ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)

dn: cn=$REALM,cn=kerberos,$SUFFIX
changetype: modify
add: aci
# read password policies
aci:(targetfilter = "(objectClass=krbPwdPolicy)")(targetattr = "krbMaxPwdLife || krbMinPwdLife || krbPwdMinDiffChars || krbPwdMinLength || krbPwdHistoryLength || objectClass || cn")(version 3.0;acl "KRB5KDC: KDC can read password policies"; allow (read, search, compare) userdn="ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)

dn: cn=s4u2proxy,cn=etc,$SUFFIX
changetype: modify
add: aci
aci: (targetfilter = "(objectClass=ipaKrb5DelegationACL)")(targetattr = "objectClass || cn || ipaAllowToImpersonate || ipaAllowedTarget || memberPrincipal")(version 3.0;acl "KRB5KDC: KDC can read KRB5 delegation ACLs"; allow (read, search, compare) userdn="ldap:///cn=krb5kdc,cn=sysaccounts,cn=etc,$SUFFIX";)
```