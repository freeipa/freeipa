.. AUTO-GENERATED FILE, DO NOT EDIT!

===========================================================================
ipa-join(1) -- Join a machine to an IPA realm and get a keytab for the host
===========================================================================
service principal

SYNOPSIS
========

::

   ipa-join [-d|--debug] [-q|--quiet] [-u|--unenroll] [-h|--hostname hostname] [-s|--server hostname] [-k|--keytab filename] [-w|--bindpw password] [-b|--basedn basedn] [-?|--help] [--usage]

DESCRIPTION
===========

Joins a host to an IPA realm and retrieves a kerberos *keytab* for the
host service principal, or unenrolls an enrolled host from an IPA
server.

Kerberos keytabs are used for services (like sshd) to perform kerberos
authentication. A keytab is a file with one or more secrets (or keys)
for a kerberos principal.

The ipa-join command will create and retrieve a service principal for
host/foo.example.com@EXAMPLE.COM and place it by default into
/etc/krb5.keytab. The location can be overridden with the -k option.

The IPA server to contact is set in /etc/ipa/default.conf by default and
can be overridden using the -s,--server option.

In order to join the machine needs to be authenticated. This can happen
in one of two ways:

\* Authenticate using the current kerberos principal

\* Provide a password to authenticate with

If a client host has already been joined to the IPA realm the ipa-join
command will fail. The host will need to be removed from the server
using \`ipa host-del FQDN\` in order to join the client to the realm.

This command is normally executed by the ipa-client-install command as
part of the enrollment process.

The reverse is unenrollment. Unenrolling a host removes the Kerberos key
on the IPA server. This prepares the host to be re-enrolled. This uses
the host principal stored in /etc/krb5.conf to authenticate to the IPA
server to perform the unenrollment.

Please note, that while the ipa-join option removes the client from the
domain, it does not actually uninstall the client or properly remove all
of the IPA-related configuration. The only way to uninstall a client
completely is to use ipa-client-install --uninstall (see
**ipa-client-install**\ (1)).

OPTIONS
=======

.. option:: -h,--hostname hostname

   The hostname of this server (FQDN). By default of nodename from
   uname(2) is used.

.. option:: -s,--server server

   The hostname of the IPA server (FQDN). Note that by default there is
   no /etc/ipa/default.conf, in most cases it needs to be supplied.

.. option:: -k,--keytab keytab-file

   The keytab file where to append the new key (will be created if it
   does not exist). Default: /etc/krb5.keytab

.. option:: -w,--bindpw password

   The password to use if not using Kerberos to authenticate. Use a
   password of this particular host (one time password created on IPA
   server)

.. option:: -b,--basedn basedn

   The basedn of the IPA server (of the form dc=example,dc=com). This is
   only needed when not using Kerberos to authenticate and anonymous
   binds are disallowed in the IPA LDAP server.

.. option:: -f,--force

   Force enrolling the host even if host entry exists.

.. option:: -u,--unenroll

   Unenroll this host from the IPA server. No keytab entry is removed in
   the process (see **ipa-rmkeytab**\ (1)).

.. option:: -q,--quiet

   Quiet mode. Only errors are displayed.

.. option:: -d,--debug

   Print the raw XML-RPC output in GSSAPI mode.

EXAMPLES
========

Join IPA domain and retrieve a keytab with kerberos credentials.

# kinit admin # ipa-join

Join IPA domain and retrieve a keytab using a one-time password.

# ipa-join -w secret123

Join IPA domain and save the keytab in another location.

# ipa-join -k /tmp/host.keytab

EXIT STATUS
===========

The exit status is 0 on success, nonzero on error.

0 Success

1 Kerberos context initialization failed

2 Incorrect usage

3 Out of memory

4 Invalid service principal name

5 No Kerberos credentials cache

6 No Kerberos principal and no bind DN and password

7 Failed to open keytab

8 Failed to create key material

9 Setting keytab failed

10 Bind password required when using a bind DN

11 Failed to add key to keytab

12 Failed to close keytab

13 Host is already enrolled

14 LDAP failure

15 Incorrect bulk password

16 Host name must be fully-qualified

17 XML-RPC fault

18 Principal not found in host entry

19 Unable to generate Kerberos credentials cache

20 Unenrollment result not in XML-RPC response

21 Failed to get default Kerberos realm

SEE ALSO
========

**ipa-rmkeytab**\ (1) **ipa-client-install**\ (1)
