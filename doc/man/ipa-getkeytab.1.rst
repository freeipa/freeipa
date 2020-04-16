.. AUTO-GENERATED FILE, DO NOT EDIT!

=========================================================
ipa-getkeytab(1) -- Get a keytab for a Kerberos principal
=========================================================

SYNOPSIS
========

::

   ipa-getkeytab -p principal-name -k keytab-file [ -e encryption-types ] [ -s ipaserver ] [ -q ] [ -D|--binddn BINDDN ] [ -w|--bindpw ] [ -W ] [ -P|--password PASSWORD ] [ --cacert CACERT ] [ -H|--ldapuri URI ] [ -Y|--mech GSSAPI|EXTERNAL ] [ -r ]

DESCRIPTION
===========

Retrieves a Kerberos *keytab*.

Kerberos keytabs are used for services (like sshd) to perform Kerberos
authentication. A keytab is a file with one or more secrets (or keys)
for a Kerberos principal.

A Kerberos service principal is a Kerberos identity that can be used for
authentication. Service principals contain the name of the service, the
hostname of the server, and the realm name. For example, the following
is an example principal for an ldap server:

ldap/foo.example.com@EXAMPLE.COM

When using ipa-getkeytab the realm name is already provided, so the
principal name is just the service name and hostname
(ldap/foo.example.com from the example above).

ipa-getkeytab is used during IPA client enrollment to retrieve a host
service principal and store it in /etc/krb5.keytab. It is possible to
retrieve the keytab without Kerberos credentials if the host was
pre-created with a one-time password. The keytab can be retrieved by
binding as the host and authenticating with this one-time password. The
**-D|--binddn** **-w|--bindpw** options are used for this
authentication. **-W** can be used instead of **-w|--bindpw** to
interactively prompt for the bind password.

**WARNING:** retrieving the keytab resets the secret for the Kerberos
principal. This renders all other keytabs for that principal invalid.
When multiple hosts or services need to share the same key (for instance
in high availability or load balancing clusters), the **-r** option must
be used to retrieve the existing key instead of generating a new one
(please refer to the EXAMPLES section).

Note that the user or host calling **ipa-getkeytab** needs to be allowed
to generate the key with **ipa host-allow-create-keytab** or **ipa
service-allow-create-keytab**, and the user or host calling
**ipa-getkeytab -r** needs to be allowed to retrieve the keytab for the
host or service with **ipa host-allow-retrieve-keytab** or **ipa
service-allow-retrieve-keytab**.

OPTIONS
=======

.. option:: -p principal-name

   The non-realm part of the full principal name.

.. option:: -k keytab-file

   The keytab file where to append the new key (will be created if it
   does not exist).

.. option:: -e encryption-types

   The list of encryption types to use to generate keys. ipa-getkeytab
   will use local client defaults if not provided. Valid values depend
   on the Kerberos library version and configuration. Common values are:
   aes256-cts aes128-cts aes256-sha2 aes128-sha2 camellia256-cts-cmac
   camellia128-cts-cmac arcfour-hmac

.. option:: -s ipaserver

   The IPA server to retrieve the keytab from (FQDN). If this option is
   not provided the server name is read from the IPA configuration file
   (/etc/ipa/default.conf). Cannot be used together with **-H**.

.. option:: -q

   Quiet mode. Only errors are displayed.

.. option:: --permitted-enctypes

   This options returns a description of the permitted encryption types,
   like this: Supported encryption types: AES-256 CTS mode with 96-bit
   SHA-1 HMAC AES-128 CTS mode with 96-bit SHA-1 HMAC AES-128 CTS mode
   with 128-bit SHA-256 HMAC AES-256 CTS mode with 192-bit SHA-384 HMAC
   ArcFour with HMAC/md5

.. option:: -P, --password

   Use this password for the key instead of one randomly generated. The
   length of the password is limited by 1024 characters. Note that MIT
   Kerberos also limits passwords entered through kpasswd and kadmin
   commands to the same length.

.. option:: -D, --binddn

   The LDAP DN to bind as when retrieving a keytab without Kerberos
   credentials. Generally used with the **-w** or **-W** options.

.. option:: -w, --bindpw

   The LDAP password to use when not binding with Kerberos. **-D** and
   **-w** can not be used together with **-Y**.

.. option:: -W

   Interactive prompt for the bind password. **-D** and **-W** can not
   be used together with **-Y**

.. option:: --cacert

   The path to the IPA CA certificate used to validate LDAPS/STARTTLS
   connections. Defaults to /etc/ipa/ca.crt

.. option:: -H, --ldapuri

   LDAP URI. If ldap:// is specified, STARTTLS is initiated by default.
   Can not be used with **-s**.

.. option:: -Y, --mech

   SASL mechanism to use if **-D** and **-w** are not specified. Use
   either GSSAPI or EXTERNAL.

.. option:: -r

   Retrieve mode. Retrieve an existing key from the server instead of
   generating a new one. This is incompatible with the --password
   option, and will work only against a FreeIPA server more recent than
   version 3.3. The user requesting the keytab must have access to the
   keys for this operation to succeed.

EXAMPLES
========

Add and retrieve a keytab for the NFS service principal on the host
foo.example.com and save it in the file /tmp/nfs.keytab and retrieve
just the aes256-sha2 key.

::

      # ipa-getkeytab -p nfs/foo.example.com -k /tmp/nfs.keytab -e aes-sha2

Add and retrieve a keytab for the ldap service principal on the host
foo.example.com and save it in the file /tmp/ldap.keytab.

::

      # ipa-getkeytab -s ipaserver.example.com -p ldap/foo.example.com -k /tmp/ldap.keytab

Retrieve a keytab using LDAP credentials (this will typically be done by
**ipa-join(1)** when enrolling a client using the
**ipa-client-install(1)** command:

::

      # ipa-getkeytab -s ipaserver.example.com -p host/foo.example.com -k /etc/krb5.keytab -D fqdn=foo.example.com,cn=computers,cn=accounts,dc=example,dc=com -w password

Add and retrieve a keytab for a clustered HTTP service deployed on
client1.example.com and client2.example.com (already enrolled), using
the client-frontend.example.com host name:

::

      # ipa host-add client-frontend.example.com --ip-address 10.1.2.3
      # ipa service-add HTTP/client-frontend.example.com
      # ipa service-allow-retrieve-keytab HTTP/client-frontend.example.com --hosts={client1.example.com,client2.example.com}
      # ipa server-allow-create-keytab HTTP/client-frontend.example.com --hosts=client1.example.com

On client1, generate and retrieve a new keytab for
client-frontend.example.com:

::

      # kinit -k
      # ipa-getkeytab -p HTTP/client-frontend.example.com -k /tmp/http.keytab

On client2, retrieve the existing keytab for
client-frontend.example.com:

::

      # kinit -k
      # ipa-getkeytab -r -p HTTP/client-frontend.example.com -k /tmp/http.keytab

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
