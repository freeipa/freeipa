IPA certificate operations
==========================

Implements a set of commands for managing server SSL certificates.

Certificate requests exist in the form of a Certificate Signing Request (CSR)
in PEM format.

The dogtag CA uses just the CN value of the CSR and forces the rest of the
subject to values configured in the server.

A certificate is stored with a service principal and a service principal
needs a host.

In order to request a certificate:

- The host must exist
- The service must exist (or you use the --add option to automatically add it)


**SEARCHING**

Certificates may be searched on by certificate subject, serial number,
revocation reason, validity dates and the issued date.

When searching on dates the _from date does a >= search and the _to date
does a <= search. When combined these are done as an AND.

Dates are treated as GMT to match the dates in the certificates.

The date format is YYYY-mm-dd.


**EXAMPLES**

 Request a new certificate and add the principal:

 .. code-block:: console

    ipa cert-request --add --principal=HTTP/lion.example.com example.csr

 Retrieve an existing certificate:

 .. code-block:: console

    ipa cert-show 1032

 Revoke a certificate (see RFC 5280 for reason details):

 .. code-block:: console

    ipa cert-revoke --revocation-reason=6 1032

 Remove a certificate from revocation hold status:

 .. code-block:: console

    ipa cert-remove-hold 1032

 Check the status of a signing request:

 .. code-block:: console

    ipa cert-status 10

 Search for certificates by hostname:

 .. code-block:: console

    ipa cert-find --subject=ipaserver.example.com

 Search for revoked certificates by reason:

 .. code-block:: console

    ipa cert-find --revocation-reason=5

 Search for certificates based on issuance date

 .. code-block:: console

    ipa cert-find --issuedon-from=2013-02-01 --issuedon-to=2013-02-07

 Search for certificates owned by a specific user:

 .. code-block:: console

    ipa cert-find --user=user

 Examine a certificate:

 .. code-block:: console

    ipa cert-find --file=cert.pem --all

 Verify that a certificate is owned by a specific user:

 .. code-block:: console

    ipa cert-find --file=cert.pem --user=user

IPA currently immediately issues (or declines) all certificate requests so
the status of a request is not normally useful. This is for future use
or the case where a CA does not immediately issue a certificate.

The following revocation reasons are supported:

    - 0 - unspecified
    - 1 - keyCompromise
    - 2 - cACompromise
    - 3 - affiliationChanged
    - 4 - superseded
    - 5 - cessationOfOperation
    - 6 - certificateHold
    - 8 - removeFromCRL
    - 9 - privilegeWithdrawn
    - 10 - aACompromise

Note that reason code 7 is not used.  See RFC 5280 for more details:

http://www.ietf.org/rfc/rfc5280.txt

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `cert-find`_
     - Search for existing certificates.
   * - `cert-remove-hold`_
     - Take a revoked certificate off hold.
   * - `cert-request`_
     - Submit a certificate signing request.
   * - `cert-revoke`_
     - Revoke a certificate.
   * - `cert-show`_
     - Retrieve an existing certificate.
   * - `cert-status`_
     - Check the status of a certificate signing request.

----

.. _cert-find:

cert-find
~~~~~~~~~

**Usage:** ``ipa [global-options] cert-find [CRITERIA] [options]``

Search for existing certificates.


.. code-block:: console

    For certificates not issued by IPA CA,
    only --certificate option is supported.


Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CRITERIA``
     - no
     - A string searched in all relevant object attributes

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded certificate.
   * - ``--issuer ISSUER``
     - Issuer DN
   * - ``--revocation-reason REVOCATION-REASON``
     - Reason for revoking the certificate (0-10). Type "ipa help cert" for revocation reason details.
   * - ``--ca CA``
     - Name of issuing CA
   * - ``--subject SUBJECT``
     - Match cn attribute in subject
   * - ``--min-serial-number MIN-SERIAL-NUMBER``
     - minimum serial number
   * - ``--max-serial-number MAX-SERIAL-NUMBER``
     - maximum serial number
   * - ``--exactly``
     - match the common name exactly
   * - ``--validnotafter-from VALIDNOTAFTER-FROM``
     - Valid not after from this date (YYYY-mm-dd)
   * - ``--validnotafter-to VALIDNOTAFTER-TO``
     - Valid not after to this date (YYYY-mm-dd)
   * - ``--validnotbefore-from VALIDNOTBEFORE-FROM``
     - Valid not before from this date (YYYY-mm-dd)
   * - ``--validnotbefore-to VALIDNOTBEFORE-TO``
     - Valid not before to this date (YYYY-mm-dd)
   * - ``--issuedon-from ISSUEDON-FROM``
     - Issued on from this date (YYYY-mm-dd)
   * - ``--issuedon-to ISSUEDON-TO``
     - Issued on to this date (YYYY-mm-dd)
   * - ``--revokedon-from REVOKEDON-FROM``
     - Revoked on from this date (YYYY-mm-dd)
   * - ``--revokedon-to REVOKEDON-TO``
     - Revoked on to this date (YYYY-mm-dd)
   * - ``--status STATUS``
     - Status of the certificate
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("certificate")
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--users USERS``
     - Search for certificates with these owner users.
   * - ``--no-users NO-USERS``
     - Search for certificates without these owner users.
   * - ``--hosts HOSTS``
     - Search for certificates with these owner hosts.
   * - ``--no-hosts NO-HOSTS``
     - Search for certificates without these owner hosts.
   * - ``--services SERVICES``
     - Search for certificates with these owner services.
   * - ``--no-services NO-SERVICES``
     - Search for certificates without these owner services.

----

.. _cert-remove-hold:

cert-remove-hold
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] cert-remove-hold SERIAL-NUMBER [options]``

Take a revoked certificate off hold.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SERIAL-NUMBER``
     - yes
     - Serial number in decimal or if prefixed with 0x in hexadecimal

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--ca CA``
     - Name of issuing CA

----

.. _cert-request:

cert-request
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] cert-request CSR-FILE [options]``

Submit a certificate signing request.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CSR-FILE``
     - yes
     - CSR

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--profile-id PROFILE-ID``
     - Certificate Profile to use
   * - ``--ca CA``
     - Name of issuing CA
   * - ``--principal PRINCIPAL``
     - Principal for this certificate (e.g. HTTP/test.example.com)
   * - ``--add``
     - automatically add the principal if it doesn't exist (service principals only)
   * - ``--chain``
     - Include certificate chain in output
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _cert-revoke:

cert-revoke
~~~~~~~~~~~

**Usage:** ``ipa [global-options] cert-revoke SERIAL-NUMBER [options]``

Revoke a certificate.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SERIAL-NUMBER``
     - yes
     - Serial number in decimal or if prefixed with 0x in hexadecimal

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--revocation-reason REVOCATION-REASON``
     - Reason for revoking the certificate (0-10). Type "ipa help cert" for revocation reason details.
   * - ``--ca CA``
     - Name of issuing CA

----

.. _cert-show:

cert-show
~~~~~~~~~

**Usage:** ``ipa [global-options] cert-show SERIAL-NUMBER [options]``

Retrieve an existing certificate.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SERIAL-NUMBER``
     - yes
     - Serial number in decimal or if prefixed with 0x in hexadecimal

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--ca CA``
     - Name of issuing CA
   * - ``--out OUT``
     - File to store the certificate in.
   * - ``--chain``
     - Include certificate chain in output
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _cert-status:

cert-status
~~~~~~~~~~~

**Usage:** ``ipa [global-options] cert-status REQUEST-ID [options]``

Check the status of a certificate signing request.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``REQUEST-ID``
     - yes
     - Request id

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--ca CA``
     - Name of issuing CA
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

