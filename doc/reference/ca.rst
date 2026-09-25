Manage Certificate Authorities
==============================

Subordinate Certificate Authorities (Sub-CAs) can be added for scoped issuance
of X.509 certificates.

CAs are enabled on creation, but their use is subject to CA ACLs unless the
operator has permission to bypass CA ACLs.

All CAs except the 'IPA' CA can be disabled or re-enabled.  Disabling a CA
prevents it from issuing certificates but does not affect the validity of its
certificate.

CAs (all except the 'IPA' CA) can be deleted.  Deleting a CA causes its signing
certificate to be revoked and its private key deleted.


**EXAMPLES**

  Create new CA, subordinate to the IPA CA (requires permission

  "System: Add CA"):


  .. code-block:: console

      ipa ca-add puppet --desc "Puppet" \
          --subject "CN=Puppet CA,O=EXAMPLE.COM"

  Disable a CA (requires permission "System: Modify CA"):


  .. code-block:: console

      ipa ca-disable puppet

  Re-enable a CA (requires permission "System: Modify CA"):


  .. code-block:: console

      ipa ca-enable puppet

  Delete a CA (requires permission "System: Delete CA"; also requires

  CA to be disabled first):


  .. code-block:: console

      ipa ca-del puppet


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `ca-add`_
     - Create a CA.
   * - `ca-del`_
     - Delete a CA (must be disabled first).
   * - `ca-disable`_
     - Disable a CA.
   * - `ca-enable`_
     - Enable a CA.
   * - `ca-find`_
     - Search for CAs.
   * - `ca-mod`_
     - Modify CA configuration.
   * - `ca-show`_
     - Display the properties of a CA.

----

.. _ca-add:

ca-add
~~~~~~

**Usage:** ``ipa [global-options] ca-add NAME [options]``

Create a CA.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - Name for referencing the CA

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description of the purpose of the CA
   * - ``--subject SUBJECT``
     - Subject Distinguished Name
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--chain``
     - Include certificate chain in output
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _ca-del:

ca-del
~~~~~~

**Usage:** ``ipa [global-options] ca-del NAME [options]``

Delete a CA (must be disabled first).

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - Name for referencing the CA

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

.. _ca-disable:

ca-disable
~~~~~~~~~~

**Usage:** ``ipa [global-options] ca-disable NAME [options]``

Disable a CA.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - Name for referencing the CA

----

.. _ca-enable:

ca-enable
~~~~~~~~~

**Usage:** ``ipa [global-options] ca-enable NAME [options]``

Enable a CA.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - Name for referencing the CA

----

.. _ca-find:

ca-find
~~~~~~~

**Usage:** ``ipa [global-options] ca-find [CRITERIA] [options]``

Search for CAs.

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
   * - ``--name NAME``
     - Name for referencing the CA
   * - ``--desc DESC``
     - Description of the purpose of the CA
   * - ``--id ID``
     - Dogtag Authority ID
   * - ``--subject SUBJECT``
     - Subject Distinguished Name
   * - ``--issuer ISSUER``
     - Issuer Distinguished Name
   * - ``--randomserialnumberversion RANDOMSERIALNUMBERVERSION``
     - Random Serial Number Version
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _ca-mod:

ca-mod
~~~~~~

**Usage:** ``ipa [global-options] ca-mod NAME [options]``

Modify CA configuration.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - Name for referencing the CA

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description of the purpose of the CA
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--rename RENAME``
     - Rename the Certificate Authority object

----

.. _ca-show:

ca-show
~~~~~~~

**Usage:** ``ipa [global-options] ca-show NAME [options]``

Display the properties of a CA.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - Name for referencing the CA

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--chain``
     - Include certificate chain in output
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

