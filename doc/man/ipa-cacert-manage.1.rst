.. AUTO-GENERATED FILE, DO NOT EDIT!

=====================================================
ipa-cacert-manage(1) -- Manage CA certificates in IPA
=====================================================

SYNOPSIS
========

| **ipa-cacert-manage** [*OPTIONS*...] renew
| **ipa-cacert-manage** [*OPTIONS*...] install *CERTFILE*...
| **ipa-cacert-manage** [*OPTIONS*...] delete *NICKNAME*
| **ipa-cacert-manage** [*OPTIONS*...] list

DESCRIPTION
===========

**ipa-cacert-manage** can be used to manage CA certificates in IPA.

COMMANDS
========

**renew**
   - Renew the IPA CA certificate

..

   This command can be used to manually renew the CA certificate of the
   IPA CA (NSS database nickname: "caSigningCert cert-pki-ca"). To renew
   other certificates, use getcert-resubmit(1).

   When the IPA CA is the root CA (the default), it is not usually
   necessary to manually renew the CA certificate, as it will be renewed
   automatically when it is about to expire, but you can do so if you
   wish.

   When the IPA CA is subordinate of an external CA, the renewal process
   involves submitting a CSR to the external CA and installing the newly
   issued certificate in IPA, which cannot be done automatically. It is
   necessary to manually renew the CA certificate in this setup.

   When the IPA CA is not configured, this command is not available.

**install**
   - Install one or more CA certificates

..

   This command can be used to install the certificates contained in
   *CERTFILE* as additional CA certificates to IPA.

   Important: this does not replace IPA CA but adds the provided
   certificate as a known CA. This is useful for instance when using
   ipa-server-certinstall to replace HTTP/LDAP certificates with
   third-party certificates signed by this additional CA.

   Please do not forget to run ipa-certupdate on the master, all the
   replicas and all the clients after this command in order to update
   IPA certificates databases.

   The supported formats for the certificate files are DER, PEM and
   PKCS#7 format.

**delete**
   - Remove a CA certificate

..

   Remove a CA from IPA. The nickname of a CA to be removed can be found
   using the list command. The CA chain is validated before allowing a
   CA to be removed so leaf certificates in a chain need to be removed
   first.

   Please do not forget to run ipa-certupdate on the master, all the
   replicas and all the clients after this command in order to update
   IPA certificates databases.

**list**
   - List the stored CA certificates

..

   Display a list of the nicknames or subjects of the CA certificates
   that have been installed.

COMMON OPTIONS
==============

.. option:: --version

   Show the program's version and exit.

.. option:: -h, --help

   Show the help for this program.

.. option:: -p <DM_PASSWORD>, --password=<DM_PASSWORD>

   The Directory Manager password to use for authentication.

.. option:: -v, --verbose

   Print debugging information.

.. option:: -q, --quiet

   Output only errors.

.. option:: --log-file=<FILE>

   Log to the given file.

RENEW OPTIONS
=============

.. option:: --self-signed

   Sign the renewed certificate by itself.

.. option:: --external-ca

   Sign the renewed certificate by external CA.

.. option:: --external-ca-type=<TYPE>

   Type of the external CA. Possible values are "generic", "ms-cs".
   Default value is "generic". Use "ms-cs" to include the template name
   required by Microsoft Certificate Services (MS CS) in the generated
   CSR (see ``**--external-ca-profile**`` for full details).

.. option:: --external-ca-profile=<PROFILE_SPEC>

   Specify the certificate profile or template to use at the external
   CA.

   When ``**--external-ca-type**`` is "ms-cs" the following specifiers may
   be used:

   **<oid>:<majorVersion>[:<minorVersion>]**
      Specify a certificate template by OID and major version,
      optionally also specifying minor version.

   **<name>**
      Specify a certificate template by name. The name cannot contain
      any *:* characters and cannot be an OID (otherwise the OID-based
      template specifier syntax takes precedence).

   **default**
      If no template is specified, the template name "SubCA" is used.

.. option:: --external-cert-file=<FILE>

   File containing the IPA CA certificate and the external CA
   certificate chain. The file is accepted in PEM and DER certificate
   and PKCS#7 certificate chain formats. This option may be used
   multiple times.

INSTALL OPTIONS
===============

.. option:: -n <NICKNAME>, --nickname=<NICKNAME>

   Nickname for the certificate. Applicable only when a single
   certificate is being installed.

.. option:: -t <TRUST_FLAGS>, --trust-flags=<TRUST_FLAGS>

   Trust flags for the certificate in certutil format. Trust flags are
   of the form "A,B,C" or "A,B,C,D" where A is for SSL, B is for S/MIME,
   C is for code signing, and D is for PKINIT. Use ",," for no explicit
   trust.

The supported trust flags are:

      C - CA trusted to issue server certificates

      T - CA trusted to issue client certificates

      p - not trusted

DELETE OPTIONS
==============

.. option:: -f, --force

   Force a CA certificate to be removed even if chain validation fails.

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred

SEE ALSO
========

**getcert-resubmit(1)**
