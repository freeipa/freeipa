# Master key upgrade

## Relevant case

FreeIPA domains initialized before the switch to AES256 HMAC-SHA2 as encryption type for the Kerberos master key are still using an AES256 HMAC-SHA1 one. This is a blocker for upgrading a domain from CentOS Stream/RHEL 8 to 9 replicas in FIPS mode, because AES HMAC-SHA1 encryption types are not longer allowed in FIPS mode on version 9. And this will eventually be required for non-FIPS environment too when it is the turn of AES HMAC-SHA1 to be deprecated entirely.

The encryption type of the Kerberos master key can be checked by running the following command as root on one of the FreeIPA replicas:

```
# kdb5_util list_mkeys
Master keys for Principal: K/M@EXAMPLE.COM
KVNO: 1, Enctype: aes256-cts-hmac-sha1-96, Active on: Wed Dec 31 19:00:00 EST 1969 *
```

There should be only one key, and its encryption type should be `aes256-cts-hmac-sha384-192`. If it is not, it means that the Kerberos master key has to be upgraded.

## Requirements

* Be logged on a FreeIPA replica as root
* With up-to-date krb5-server and ipa-server packages
* On RHEL 8, the minor version of the replica must be 8.10

## Procedure

This procedure must be executed on a single replica. The changes are automatically replicated to the rest of the domain.

First add a new master key to the list. Be sure to use a strong secret:

```
# kdb5_util add_mkey -e aes256-sha2 -s
Creating new master key for master key principal 'K/M@EXAMPLE.COM'
You will be prompted for a new database Master Password.
It is important that you NOT FORGET this password.
Enter KDC database master key: 
Re-enter KDC database master key to verify: 
```

The new key should now appear in the master key list and have the `aes256-cts-hmac-sha384-192` encryption type. The old key should have a `*` character at the end of its line. This means it is still the active master key, which means new keys are still going to be encrypted using the old master key at this point.

```
# kdb5_util list_mkeys
Master keys for Principal: K/M@EXAMPLE.COM
KVNO: 2, Enctype: aes256-cts-hmac-sha384-192, No activate time set
KVNO: 1, Enctype: aes256-cts-hmac-sha1-96, Active on: Wed Dec 31 19:00:00 EST 1969 *
```

The next step is to set the new master key as the active one.

The behavior of FreeIPA differs from MIT Kerberos, because at this point of the upgrade process, if a new principal (user or service) is created, when initializing its key, the new master key will be used. While on MIT Kerberos, the old active key would be used.

To activate the new master key, use the following command with the KVNO of the new master key (in this example, the KVNO is 2):

```
# kdb5_util use_mkey 2
```

Both master keys should still be there afterwards, but now the new key has the `*` character. It signifies it is the new active key:

```
# kdb5_util list_mkeys
Master keys for Principal: K/M@EXAMPLE.COM
KVNO: 2, Enctype: aes256-cts-hmac-sha384-192, Active on: Wed Jun 25 10:04:59 EDT 2025 *
KVNO: 1, Enctype: aes256-cts-hmac-sha1-96, Active on: Wed Dec 31 19:00:00 EST 1969
```

So at this point, the new keys will be encrypted using the new master key, but the already existing keys are still using the old master key. If you query a principal whose credentials were not updated since the new key was set as active, it should still refer to the old master key (here the master key with KVNO 1):

```
# kadmin.local getprinc ldap/ipa01.example.com | grep -E '^MKey:'
MKey: vno 1
```

This is why, before removing the old master key, all the other keys in the database have to be re-encrypted using the new active master key. This operation will send a lot of modification requests to the database, so it is preferable to execute it on a moment when the FreeIPA replicas are the least busy. Also be sure to keep the `-x unlockiter` option for not locking the database during the process:

```
# kdb5_util -x unlockiter update_princ_encryption -vf
Principals whose keys are being re-encrypted to master key vno 2 if necessary:
updating: admin@EXAMPLE.COM
updating: krbtgt/EXAMPLE.COM@EXAMPLE.COM
updating: kadmin/admin@EXAMPLE.COM
updating: kadmin/changepw@EXAMPLE.COM
[...]
XXXX principals processed: XXXX updated, 0 already current
```

Note that this step does not upgrade the key types themselves; it only upgrades how they are encrypted in the database. There is no automated mechanism to upgrade the key types; upgrading them requires generating a new version of the key.

Once this operation is complete, the principal queried before should now have its keys encrypted with the new active master key:

```
# kadmin.local getprinc ldap/ipa01.example.com | grep -E '^MKey:'
MKey: vno 2
```

Since the old master key is not used anymore, it is now safe to delete it:

```
# kdb5_util purge_mkeys -vf
Purging the following master key(s) from K/M@EXAMPLE.COM:
KVNO: 1
1 key(s) purged.
```

And the new AES256 HMAC-SHA2 master key should be the only one left:

```
# kdb5_util list_mkeys
Master keys for Principal: K/M@EXAMPLE.COM
KVNO: 2, Enctype: aes256-cts-hmac-sha384-192, Active on: Wed Jun 25 10:04:59 EDT 2025 *
```

Finally, restart the IPA service on all replicas.
