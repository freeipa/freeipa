.. AUTO-GENERATED FILE, DO NOT EDIT!

============================================================================
ipa-replica-conncheck(1) -- Check a replica-master network connection before
============================================================================
installation

SYNOPSIS
========

ipa-replica-conncheck [*OPTION*]...

DESCRIPTION
===========

When an IPA replica is being installed a network connection between a
replica machine and a replicated IPA master machine has to be prepared
for master-replica communication. In case of a flawed connection the
installation may fail with inconvenient error messages. A common
connection problem is a misconfigured firewall with closed required port
on a replica or master machine.

The connection is checked by running a set of tests from both master and
replica machines. The program is incorporated to ipa-replica-install(1)
but can be also run separately.

OPTIONS
=======

REPLICA MACHINE OPTIONS
-----------------------

This set of options is used when the connection check is run on a
prepared IPA replica machine.

.. option:: -m <MASTER>, --master=<MASTER>

   Remote master machine address

.. option:: -a, --auto-master-check

   Automatically log in to master machine and execute the master machine
   part of the connection check. The following options for replica part
   are only evaluated when this option is set

.. option:: -r <REALM>, --realm=<REALM>

   The Kerberos realm name for the IPA server

.. option:: -k <KDC>, --kdc=<KDC>

   KDC server address. Defaults to *MASTER*

.. option:: -p <PRINCIPAL>, --principal=<PRINCIPAL>

   Authorized Kerberos principal to use to log in to master machine.
   Defaults to *admin*

.. option:: -w <PASSWORD>, --password=<PASSWORD>

   Password for given principal. The password will be prompted
   interactively when this option is missing

MASTER MACHINE OPTIONS
----------------------

This set of options is used when the connection check is run on a master
machine against a running ipa-replica-conncheck(1) on a replica machine.

.. option:: -R <REPLICA>, --replica=<REPLICA>

   Remote replica machine address

COMMON OPTIONS
--------------

.. option:: -c, --check-ca

   Include in a check also a set of dogtag connection requirements. Only
   needed when the master was installed with Dogtag 9 or lower.

.. option:: -h <HOSTNAME>, --hostname=<HOSTNAME>

   The hostname of this server (FQDN). By default the result of
   getfqdn() call from Python's socket module is used.

.. option:: -d, --debug

   Print debugging information

.. option:: -q, --quiet

   Output only errors

EXAMPLES
========

**ipa-replica-conncheck -m master.example.com**
   Run a replica machine connection check against a remote master
   *master.example.com*. If the connection to the remote master machine
   is successful the program will switch to listening mode and prompt
   for running the master machine part. The second part check the
   connection from master to replica.

**ipa-replica-conncheck -R replica.example.com**
   Run a master machine connection check part. This is either run
   automatically by replica part of the connection check program (when
   *-a* option is set) or manually by the user. A running
   ipa-replica-conncheck(1) in a listening mode must be already running
   on a replica machine.

**ipa-replica-conncheck -m master.example.com -a -r EXAMPLE.COM -w password**
   Run a replica-master connection check. In case of a success switch to
   listening mode, automatically log to *master.example.com* in a realm
   *EXAMPLE.COM* with a password *password* and run the second part of
   the connection check.

EXIT STATUS
===========

0 if the connection check was successful

1 if an error occurred

SEE ALSO
========

**ipa-replica-install**\ (1)
