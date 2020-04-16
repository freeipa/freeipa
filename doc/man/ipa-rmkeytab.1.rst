.. AUTO-GENERATED FILE, DO NOT EDIT!

============================================================
ipa-rmkeytab(1) -- Remove a kerberos principal from a keytab
============================================================

SYNOPSIS
========

::

   ipa-rmkeytab [ -p principal-name ] [ -k keytab-file ] [ -r realm ] [ -d ]

DESCRIPTION
===========

Removes a kerberos principal from a *keytab*.

Kerberos keytabs are used for services (like sshd) to perform kerberos
authentication. A keytab is a file with one or more secrets (or keys)
for a kerberos principal.

A kerberos service principal is a kerberos identity that can be used for
authentication. Service principals contain the name of the service, the
hostname of the server, and the realm name.

ipa-rmkeytab provides two ways to remove principals. A specific
principal can be removed or all principals for a given realm can be
removed.

All encryption types and versions of a principal are removed.

The realm may be included when removing a specific principal but it is
not required.

**NOTE:** removing a principal from the keytab does not affect the
Kerberos principal stored in the IPA server. It merely removes the entry
from the local keytab.

OPTIONS
=======

.. option:: -p principal-name

   The non-realm part of the full principal name.

.. option:: -k keytab-file

   The keytab file to remove the principal(s) from.

.. option:: -r realm

   A realm to remove all principals for.

.. option:: -d

   Debug mode. Additional information is displayed.

EXAMPLES
========

Remove the NFS service principal on the host foo.example.com from
/tmp/nfs.keytab.

# ipa-rmkeytab -p nfs/foo.example.com -k /tmp/nfs.keytab

Remove the ldap service principal on the host foo.example.com from
/etc/krb5.keytab.

# ipa-rmkeytab -p ldap/foo.example.com -k /etc/krb5.keytab

Remove all principals for the realm EXAMPLE.COM.

# ipa-rmkeytab -r EXAMPLE.COM -k /etc/krb5.keytab

EXIT STATUS
===========

The exit status is 0 on success, nonzero on error.

1 Kerberos initialization failed

2 Memory allocation error

3 Unable to open keytab

4 Unable to parse the principal name

5 Principal name or realm not found in keytab

6 Unable to remove principal from keytab
