Manage Certificate Profiles
===========================

Certificate Profiles are used by Certificate Authority (CA) in the signing of
certificates to determine if a Certificate Signing Request (CSR) is acceptable,
and if so what features and extensions will be present on the certificate.

The Certificate Profile format is the property-list format understood by the
Dogtag or Red Hat Certificate System CA.


**PROFILE ID SYNTAX**

A Profile ID is a string without spaces or punctuation starting with a letter
and followed by a sequence of letters, digits or underscore ("_").


**EXAMPLES**

  Import a profile that will not store issued certificates:

  .. code-block:: console

      ipa certprofile-import ShortLivedUserCert \
        --file UserCert.profile --desc "User Certificates" \
        --store=false

  Delete a certificate profile:

  .. code-block:: console

      ipa certprofile-del ShortLivedUserCert

  Show information about a profile:

  .. code-block:: console

      ipa certprofile-show ShortLivedUserCert

  Save profile configuration to a file:

  .. code-block:: console

      ipa certprofile-show caIPAserviceCert --out caIPAserviceCert.cfg

  Search for profiles that do not store certificates:

  .. code-block:: console

      ipa certprofile-find --store=false


**PROFILE CONFIGURATION FORMAT**

The profile configuration format is the raw property-list format
used by Dogtag Certificate System.  The XML format is not supported.

The following restrictions apply to profiles managed by IPA:

- When importing a profile the "profileId" field, if present, must
  match the ID given on the command line.

- The "classId" field must be set to "caEnrollImpl"

- The "auth.instance_id" field must be set to "raCertAuth"

- The "certReqInputImpl" input class and "certOutputImpl" output
  class must be used.

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `certprofile-del`_
     - Delete a Certificate Profile.
   * - `certprofile-find`_
     - Search for Certificate Profiles.
   * - `certprofile-import`_
     - Import a Certificate Profile.
   * - `certprofile-mod`_
     - Modify Certificate Profile configuration.
   * - `certprofile-show`_
     - Display the properties of a Certificate Profile.

----

.. _certprofile-del:

certprofile-del
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certprofile-del ID [options]``

Delete a Certificate Profile.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Profile ID for referring to this profile

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.

----

.. _certprofile-find:

certprofile-find
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certprofile-find [CRITERIA] [options]``

Search for Certificate Profiles.

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
   * - ``--id ID``
     - Profile ID for referring to this profile
   * - ``--desc DESC``
     - Brief description of this profile
   * - ``--store STORE``
     - Whether to store certs issued using this profile
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("id")

----

.. _certprofile-import:

certprofile-import
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certprofile-import ID [options]``

Import a Certificate Profile.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Profile ID for referring to this profile

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Brief description of this profile
   * - ``--store STORE``
     - Whether to store certs issued using this profile
   * - ``--file FILE``
     - Filename of a raw profile. The XML format is not supported.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _certprofile-mod:

certprofile-mod
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certprofile-mod ID [options]``

Modify Certificate Profile configuration.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Profile ID for referring to this profile

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Brief description of this profile
   * - ``--store STORE``
     - Whether to store certs issued using this profile
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--file FILE``
     - File containing profile configuration
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _certprofile-show:

certprofile-show
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certprofile-show ID [options]``

Display the properties of a Certificate Profile.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Profile ID for referring to this profile

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--out OUT``
     - Write profile configuration to file
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

