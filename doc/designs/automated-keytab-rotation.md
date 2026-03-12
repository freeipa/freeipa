# Automated keytab rotation

## Overview

On some IPA domains, IPA services (HTTP API, LDAP, Dogtag, named, ...) were
initialized with a list of key types that has since been extended with
stronger types. There is no automated mechanism to add keys with these new
types to existing IPA service keytabs.

This prevents old domains running on RHEL 8 servers in FIPS mode from
upgrading to RHEL 9 in FIPS mode, because such an upgrade requires AES
HMAC-SHA2 support. If IPA services on RHEL 8 do not support and use AES
HMAC-SHA2 by default, they cannot interoperate with their counterparts on
FIPS RHEL 9 servers.

This design describes automated rotation of IPA service keytabs so that they
include keys for newly supported encryption types. The feature relies on the
changes implemented in [freeipa#7861](https://github.com/freeipa/freeipa/pull/7861)
(master key upgrade and permitted enctypes from crypto-policies).

## Use Cases

* **RHEL 8 to RHEL 9 FIPS upgrade**: An IPA domain runs on RHEL 8 in FIPS
  mode. After upgrading replicas to RHEL 9 in FIPS mode, service keytabs must
  include AES HMAC-SHA2. Automated rotation adds the new key types at IPA
  startup so the domain can operate without manual keytab updates.

* **Crypto policy or permitted_enctypes change**: The system’s crypto policy
  or `permitted_enctypes` is updated (e.g. new default enctypes). IPA service
  keytabs should be refreshed so they match the new permitted list. Rotation
  runs on the next IPA start and updates keytabs as needed.

## How to Use

No administrator action is required. Rotation runs automatically when IPA
starts. After the KDC starts, keytabs are checked; if any are outdated, new
keys are generated and all IPA services are restarted so they use the updated
keytabs. Old keys are removed later (see [Design](#design)) after the maximum 
renewable age has passed; scheduling of that cleanup is done through a cron job. // TODO: Add cron job details / systemd

## Design

### Keytabs in scope

The following keytabs are checked and rotated when necessary:

| Keytab path | Service |
|-------------|---------|
| `/etc/dirsrv/ds.keytab` | 389 Directory Server (LDAP) |
| `/var/lib/ipa/gssproxy/http.keytab` | HTTP API (gssproxy) |
| `/var/lib/ipa/api/anon.keytab` | Anonymous bind |
| `/etc/pki/pki-tomcat/dogtag.keytab` | Dogtag (PKI) |
| `/etc/named.keytab` | named (DNS) |
| `/etc/ipa/dnssec/ipa-dnskeysyncd.keytab` | DNSSEC key sync |
| `/etc/samba/samba.keytab` | Samba |
| `/var/lib/sss/keytabs/<domain>.keytab` | SSSD (one keytab per trusted domain) |

The host keytab (`/etc/krb5.keytab`) is not rotated by this mechanism; it is
used only to obtain credentials for running `ipa-getkeytab` when renewing
service keys. We do not handle the host keytab rotation here, because users
might lock themselves out.

### Timing and impact

Rotation can be done without impacting domain operations if timing is handled
correctly:

1. **Adding new keys**: When new keys are written to the KDC, the old keys
   remain. No new tickets are issued for the old keys, but existing tickets
   for those keys remain valid until they expire or reach their maximum
   renewable lifetime.

2. **Removing old keys**: After the maximum renewable age has passed, no valid
   tickets can exist for the old keys, and the KDC no longer issues tickets
   with them. The old keys can then be removed from the keytab.

Hence, old keys are removed only after the realm's maximum renewable time
(e.g. `krbMaxRenewableAge`, by default 7 days) has passed since the new keys
were created.

### Generating new IPA service keys

#### When to check

The check runs at **IPA startup**. After the Directory Server is up, the KDC
(`krb5kdc`) is started first. On start, the KDC service layer invokes the
keytab rotation logic. If any keytab is rotated, IPA restarts all services so
they pick up the new keytabs.

#### Discovering current key types in a keytab

Current key types are discovered with:

```bash
/usr/bin/klist -ekt /var/lib/ipa/gssproxy/http.keytab
```

Example output:

```
Keytab name: FILE:/var/lib/ipa/gssproxy/http.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   1 02/13/2026 08:59:28 HTTP/server.ipa.domain@IPA.DOMAIN (aes256-cts-hmac-sha1-96)
   1 02/13/2026 08:59:28 HTTP/server.ipa.domain@IPA.DOMAIN (aes128-cts-hmac-sha1-96)
   ...
   2 02/13/2026 10:11:46 HTTP/server.ipa.domain@IPA.DOMAIN (aes256-cts-hmac-sha1-96)
   2 02/13/2026 10:11:46 HTTP/server.ipa.domain@IPA.DOMAIN (aes128-cts-hmac-sha1-96)
   ...
```

For service keytabs (all except the host keytab `/etc/krb5.keytab`), the
implementation considers only the **highest KVNO** for each principal.
From those entries, it collects the encryption types (the strings in
parentheses, e.g. `aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96`).

#### Permitted encryption types

The reference list of permitted encryption types (ordered by preference) is
produced by:

```bash
/usr/bin/ipa-getkeytab --permitted-enctypes
```

This reflects the configuration from `/etc/krb5.conf.d/crypto-policies` (and
related crypto-policy configuration). Example:

```
aes256-cts-hmac-sha384-192
aes128-cts-hmac-sha256-128
aes256-cts-hmac-sha1-96
aes128-cts-hmac-sha1-96
camellia256-cts-cmac
camellia128-cts-cmac
```

#### Deciding when to rotate

The key types from the keytab (for the highest KVNO) are compared to the list
from `ipa-getkeytab --permitted-enctypes`. If the keytab’s types are not
exactly the same as the permitted list (same set and same order), the keytab
is considered outdated and the service keys are rotated.

Note, we do not care about the salt type of the keys, only the encryption type,
that is we ignore the :special and :normal suffixes in the permitted list.

#### Performing rotation

Rotation uses `ipa-getkeytab`, which requires administrative credentials. The
host keytab is used to obtain a TGT for the host principal, then
`ipa-getkeytab` is run for each affected service principal:

```bash
/usr/bin/kinit -kt /etc/krb5.keytab host/server.ipa.domain@IPA.DOMAIN
/usr/bin/ipa-getkeytab -p HTTP/server.ipa.domain@IPA.DOMAIN -k /var/lib/ipa/gssproxy/http.keytab
/usr/bin/kdestroy
```

`ipa-getkeytab` adds new keys (new KVNO) with the current permitted encryption
types; existing entries in the keytab are left in place until they are pruned
later (see [Removing outdated keys](#removing-outdated-keys)).

(Note that kadmin.local ktadd would be a more convenient way to add the new
keys to the service keytabs. However, the recent work on the upstream pull
request has shown that the list of key types for service principals when
generated using kadmin, is based on the supported_enctypes parameter from
`kdc.conf`, which is never updated. Hence we have no guarantee this list
is up-to-date, while `ipa-getkeytab` relies on the permitted_enctypes list
controlled by the crypto-policies system.)

### Removing outdated keys

Old keys must remain in the keytab until no ticket can still be renewed for
them. That time is the realm's **maximum renewable age** (`krbMaxRenewableAge`),
e.g. 604800 seconds (7 days) by default.

The value can be read from LDAP, for example:

```bash
ldapsearch -o ldif-wrap=no -LLL -Q -s base -b 'cn=IPA.DOMAIN,cn=kerberos,dc=ipa,dc=domain' krbMaxRenewableAge
```

Example result:

```
dn: cn=IPA.DOMAIN,cn=kerberos,dc=ipa,dc=domain
krbMaxRenewableAge: 604800
```

A robust approach is to schedule a **recurring task** (e.g. cron or systemd
timer) that, after the maximum renewable age has passed since a rotation,
removes old KVNOs from the keytabs. // TODO: Add cron job details / systemd

Outdated keys are removed with `kadmin.local ktremove` by principal and KVNO:

```bash
/usr/bin/kadmin.local ktremove -k /var/lib/ipa/gssproxy/http.keytab HTTP/server.ipa.domain@IPA.DOMAIN 1
```

Repeated for each KVNO that is older than the current set and past the maximum
renewable age. Each call removes all key entries for that principal and KVNO
from the keytab.

We should retry in case of a failed removal, details should be logged. // TODO: Add retry and logging details.

### ipactl service ordering and restart behaviour

To support keytab rotation at startup, ipactl changes the order in which
services are started and, when rotation occurs, performs a full restart of
all IPA services.

**Why start the KDC first:** The keytab check and rotation logic runs inside
the KDC service’s `start()` path (via the platform-specific
`RedHatKRB5KDCService` / `SuseKRB5KDCService`). The KDC should be started before
any other IPA services, but after Directory Server, to allow communication with
the Directory Server. ipactl therefore reorders the service list so that 
`krb5kdc` is always started first, before any other services.

**What happens when keytabs are rotated:** Rotation updates keytab files on
disk. Processes that already have those keytabs open or that have bound to
the KDC with old keys will not see the new keys until they reload their
keytab or restart. To avoid leaving any service using stale keys, ipactl
treats a rotation as a “second startup”:

1. Stop all services (in reverse order of the service list).
2. Restart Directory Server so that 389 DS reloads its keytab (`ds.keytab`).
3. Start the KDC again (no rotation is performed this time, since keytabs are
   already up to date).
4. Start the remaining services in the usual order.

**Why restart everything:** Services do not re-read their keytab files on a
timer; they typically load the keytab once at startup. Restarting all services
ensures that every service that uses a rotated keytab picks up the new keys
on its next start.

**Behaviour on `ipa start`:**

1. Start Directory Server.
2. Start the KDC. During this start, `check_and_rotate_keytabs()` runs; if
   it rotates any keytab, the KDC service object’s `rotated_keys` is set to
   True.
3. If `rotated_keys` is True: stop all services (reverse order), restart
   Directory Server, start the KDC again, then start the rest of the services
   in order.
4. If `rotated_keys` is False: start the remaining services in order (KDC is
   already running).

**Behaviour on `ipa restart`:** 

1. Start Directory Server if not running.
2. Stop already running services.
3. Restart Directory Server if was running before starting.
4. Start the KDC. During this start, `check_and_rotate_keytabs()` runs; if
   it rotates any keytab, the KDC service object’s `rotated_keys` is set to
   True.
5. If `rotated_keys` is True: stop all services (reverse order), restart
   Directory Server, start the KDC again, then start services that were off
   in order.
6. Restart other services that were running before starting.

## Implementation

* **Module**: `ipapython.krb5util`
* **Entry point**: `check_and_rotate_keytabs(instance)` is invoked from the
  platform KDC service’s `start()` (e.g. `RedHatKRB5KDCService`,
  `SuseKRB5KDCService`) after `krb5kdc` has started.
* **Permitted types**: `_get_krb_permitted_types()` runs
  `ipa-getkeytab --permitted-enctypes` and normalizes lines (strips
  `:special` / `:normal` suffixes for comparison).
* **Keytab parsing**: `_list_keytab()` runs `klist -ekt <keytab>` and parses
  output into `KeytabEntry` objects (filepath, kvno, timestamp, principal,
  list of enctypes). Only the highest KVNO per principal is used for the
  “current” key set.
* **Validation**: `KeytabEntry.valid_enctypes(permitted_enctypes)` returns True
  only if the entry’s enctypes list matches the permitted list in length and
  order.
* **Rotation**: For each keytab that has at least one entry with invalid
  enctypes, the code schedules removal of outdated KVNOs (see [Design](#design))
  and adds `(keytab_path, principal)` to a list. `_generate_keys()` then runs
  `kinit -kt` with the host principal from `/etc/krb5.keytab`, then
  `ipa-getkeytab -p <principal> -k <keytab>` for each such keytab, and schedule
  removal of outdated KVNOs.

## Feature Management

### Configuration

No option to disable this feature.

## Upgrade

This feature allows upgrading RHEL 8 to RHEL 9 in FIPS mode, because it
ensures that the IPA service keytabs include keys for the new encryption types.

In general it allows automatic rotation of IPA service keytabs when the
crypto policy or permitted_enctypes change.

## Test plan

Tests will be provided with implementation, manual testing can be done by following:

1. Edit `/etc/krb5.conf.d/crypto-policies` to change the permitted encryption types.
2. Install FreeIPA
3. Revert changes made to `/etc/krb5.conf.d/crypto-policies`.
4. Run ipactl restart to trigger the rotation.

Verify that the keytabs include the new encryption types.

```bash
klist -ekt /var/lib/ipa/gssproxy/http.keytab
```

Verify jobs are scheduled.

// TODO: Add how and where?

You can manually trigger the scheduled tasks.

// TODO: Add how to trigger the scheduled tasks.

Verify the keytabs have old keys removed, keytab should contain only one KVNO.

```bash
klist -ekt /var/lib/ipa/gssproxy/http.keytab
```

## Troubleshooting and debugging

The feature produces logs, when keytabs can not be read, rotated etc.
The logs are available in the `ipactl.log` file. Available at `/var/log/ipactl.log`.

The automated deletion produces logs elsewhere // TODO: Where? How?
