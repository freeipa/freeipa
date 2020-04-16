.. AUTO-GENERATED FILE, DO NOT EDIT!

================================================================
ipa-server-certinstall(1) -- Install new SSL server certificates
================================================================

SYNOPSIS
========

ipa-server-certinstall [*OPTION*]... FILE...

DESCRIPTION
===========

Replace the current Directory server SSL certificate, Apache server SSL
certificate and/or Kerberos KDC certificate with the certificate in the
specified files. The files are accepted in PEM and DER certificate,
PKCS#7 certificate chain, PKCS#8 and raw private key and PKCS#12
formats.

PKCS#12 is a file format used to safely transport SSL certificates and
public/private keypairs.

They may be generated and managed using the NSS pk12util command or the
OpenSSL pkcs12 command.

The service(s) are not automatically restarted. In order to use the
newly installed certificate(s) you will need to manually restart the
Directory, Apache and/or Krb5kdc servers.

OPTIONS
=======

.. option:: -d, --dirsrv

   Install the certificate on the Directory Server

.. option:: -w, --http

   Install the certificate in the Apache Web Server

.. option:: -k, --kdc

   Install the certificate in the Kerberos KDC

.. option:: --pin=<PIN>

   The password to unlock the private key

.. option:: --cert-name=<NAME>

   Name of the certificate to install

.. option:: -p, --dirman-password=<DIRMAN_PASSWORD>

   Directory Manager password

.. option:: --version

   Show the program's version and exit

.. option:: -h, --help

   Show the help for this program

.. option:: -v, --verbose

   Print debugging information

.. option:: -q, --quiet

   Output only errors

.. option:: --log-file=<FILE>

   Log to the given file

EXIT STATUS
===========

0 if the installation was successful

1 if an error occurred
