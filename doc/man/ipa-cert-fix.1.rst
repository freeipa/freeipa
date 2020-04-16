.. AUTO-GENERATED FILE, DO NOT EDIT!

=============================================
ipa-cert-fix(1) -- Renew expired certificates
=============================================

SYNOPSIS
========

ipa-cert-fix [options]

DESCRIPTION
===========

*ipa-cert-fix* is a tool for recovery when expired certificates prevent
the normal operation of FreeIPA. It should ONLY be used in such
scenarios, and backup of the system, especially certificates and keys,
is **STRONGLY RECOMMENDED**.

Do not use this program unless expired certificates are inhibiting
normal operation and renewal procedures.

To renew the IPA CA certificate, use *ipa-cacert-manage(1)*.

This tool cannot renew certificates signed by external CAs. To install
new, externally-signed HTTP, LDAP or KDC certificates, use
*ipa-server-certinstall(1)*.

*ipa-cert-fix* will examine FreeIPA and Certificate System certificates
and renew certificates that are expired, or close to expiry (less than
two weeks). If any "shared" certificates are renewed, *ipa-cert-fix*
will set the current server to be the CA renewal master, and add the new
shared certificate(s) to LDAP for replication to other CA servers.
Shared certificates include all Dogtag system certificates except the
HTTPS certificate, and the IPA RA certificate.

To repair certificates across multiple CA servers, first ensure that
LDAP replication is working across the topology. Then run *ipa-cert-fix*
on one CA server. Before running *ipa-cert-fix* on another CA server,
trigger Certmonger renewals for shared certificates via
*getcert-resubmit(1)* (on the other CA server). This is to avoid
unnecessary renewal of shared certificates.

OPTIONS
=======

.. option:: --version

   Show the program's version and exit.

.. option:: -h, --help

   Show the help for this program.

.. option:: -v, --verbose

   Print debugging information.

.. option:: -q, --quiet

   Output only errors (output from child processes may still be shown).

.. option:: --log-file=<FILE>

   Log to the given file.

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred

SEE ALSO
========

**ipa-cacert-manage(1)** **ipa-server-certinstall(1)**
**getcert-resubmit(1)**
