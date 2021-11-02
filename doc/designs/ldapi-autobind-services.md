# LDAPI autobind authentication for services

## Overview

This design proposed to use LDAPI autobind for some internal FreeIPA
services, so they can be started and used before KRB5 KDC service is
operational. The proposal makes use of 389 DS' existing [LDAPI autobind](
https://www.port389.org/docs/389ds/FAQ/ldapi-and-autobind.html)
implementation and new [LDAPI autobind DN rewriter](
https://www.port389.org/docs/389ds/design/ldapi-auto-auth-dn-design.html)
feature, which will be available in early 2021.

LDAPI autobind is a form of authentication that uses the effective
UID and GID of a process as credentials. It uses ``SO_PEERCRED`` feature
of [unix socket](https://man7.org/linux/man-pages/man7/unix.7.html)
connection and SASL EXTERNAL mechanism. Autobind enables secure and
fast authentication for local services without using KRB5 KDC.

## Technical background

### Benefits

LDAPI autobind does not depend on Kerberos/GSSAPI. This fact permits
services to authenticate and operate before KRB5 KDC is up and running.
For example DNS services can be started before KDC, so a time sync
daemon can synchronize clocks before KDC starts.

It's faster than GSSAPI. On a test system ``ldapwhoami`` command
with ``-Y EXTERNAL`` takes around 12ms real time. On the same system
``-Y GSSAPI`` over LDAPI with a cached service ticket takes between
20ms to 500ms real time.

### Drawbacks

On Fedora and RHEL-based systems, FreeIPA's keytabs are not only
protected by DAC permissions (discrete access control, also known as
Unix file permissions) but also by SELinux's mandatory access control.
For example ``named.keytab`` is only readable by user ``named`` or
group members of group ``named`` and processes that are
allowed to open files with SELinux type ``etc_t``. ``SO_PEERCRED``-based
authentication no longer verifies the SELinux context of a process.
It is possible to retrieve the security context of a peer process
with ``SO_PEERSEC``, but 389-DS does not implement the feature.

The risk is negligible for BIND named. Most process are allowed to
read files with ``etc_t`` any way.

### Containers

``SO_PEERCRED`` based authentication works across containers if and
only if the 389-DS server process and LDAP client process can share a
mount point and a common user namespace. The mount point is required
to share the Unix socket file of the 389-DS process. The user namespace
must be shared, because the Kernel translates UID and GID numbers
between namespaces. Disjunct namespaces result in UID/GID ``-1``.

## Candidates

* BIND named service, so ``named`` and ``chronyd`` can be started
  before KDC.
* krb5kdc and kadmin service (after dropping root privileges)
* ipa-custodia (after dropping root privileges)

## Implementation

The implementation makes use of the new DN rewriter feature for
autobind. The feature enables FreeIPA to store the UID/GID mapping in
the local, non-replicated ``cn=config`` backend and then map succesful
binds to a DN in the replicated domain database. The approach has two
benefits:

1) FreeIPA does not depend on reserved and uniform UID/GID allocation
   across all servers. Each server can map its local UID/GID assignment
   to a principal.
2) FreeIPA can map UID/GID combination to a host-specific service
   principal. For example server ``srv1`` can map UID ``25`` / GID
   ``25`` to ``DNS/srv1.ipa.example@IPA.EXAMPLE``. ``srv2`` can map the
   same UID and GID to its principal
   ``DNS/srv2.ipa.example@IPA.EXAMPLE``.

### global settings

LDAPI mappings, search base for UID/GID, and mapping base for
``nsslapd-authenticateAsDN`` must be configured in ``cn=config``.

```
dn: cn=config
nsslapd-ldapimaptoentries: on
nsslapd-ldapientrysearchbase: cn=auto_bind,cn=config
nsslapd-ldapidnmappingbase: cn=auto_bind,cn=config
```

### service-specific settings

LDAPI DN rewriter feature comes with a new object class for mapping
UID/GID to another DN. For example a mapping for BIND named would look
like this:

```
dn: cn=named,cn=auto_bind,cn=config
objectClass: top
objectClass: nsLDAPIFixedAuthMap
cn: named
uidNumber: $NAMED_UID
gidNumber: $NAMED_GID
nsslapd-authenticateAsDN: krbprincipalname=DNS/$FQDN@$REALM,cn=services,cn=accounts,$SUFFIX
```

**NOTE** 389-DS does not enforce referential integrity in ``cn=config``.
``nsslapd-authenticateAsDN`` can reference DNs that do not exist yet. A
missing target results into authenticate error.

### reload LDAPI mappings

389-DS has an internal cache for LDAPI mappings. The cache must be
refreshed after mapping are added, removed, or changed. A refresh can
be accomplished by either restarting the server process or running the
`reload ldapi mappings` task. The implementation detail will be
handled automatically by new API and ``ipa-ldap-updater`` framework.

### backup / restore

It is possible that UID or GID can change, when a server is reinstalled
and restored from a backup. ``ipa-restore`` will refresh all mappings
on restore.

## References

* [389-DS LDAPI autobind](
https://www.port389.org/docs/389ds/FAQ/ldapi-and-autobind.html)
* [LDAPI autobind DN rewriter](
https://www.port389.org/docs/389ds/design/ldapi-auto-auth-dn-design.html)
* 389-DS feature request [GH-4381](https://github.com/389ds/389-ds-base/issues/4381)
* FreeIPA bug report [pagure-8544](https://pagure.io/freeipa/issue/8544)
  for replication issue due to clock mismatch.
