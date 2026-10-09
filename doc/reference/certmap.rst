Certificate Identity Mapping
============================

Manage Certificate Identity Mapping configuration and rules.

IPA supports the use of certificates for authentication. Certificates can
either be stored in the user entry (full certificate in the usercertificate
attribute), or simply linked to the user entry through a mapping.
This code enables the management of the rules allowing to link a
certificate to a user entry.


**EXAMPLES**

 Display the Certificate Identity Mapping global configuration:

 .. code-block:: console

    ipa certmapconfig-show

 Modify Certificate Identity Mapping global configuration:

 .. code-block:: console

    ipa certmapconfig-mod --promptusername=TRUE

 Create a new Certificate Identity Mapping Rule:

 .. code-block:: console

    ipa certmaprule-add rule1 --desc="Link certificate with subject and issuer"

 Modify a Certificate Identity Mapping Rule:

 .. code-block:: console

    ipa certmaprule-mod rule1 --maprule="<ALT-SEC-ID-I-S:altSecurityIdentities>"

 Disable a Certificate Identity Mapping Rule:

 .. code-block:: console

    ipa certmaprule-disable rule1

 Enable a Certificate Identity Mapping Rule:

 .. code-block:: console

    ipa certmaprule-enable rule1

 Display information about a Certificate Identity Mapping Rule:

 .. code-block:: console

    ipa certmaprule-show rule1

 Find all Certificate Identity Mapping Rules with the specified domain:

 .. code-block:: console

    ipa certmaprule-find --domain example.com

 Delete a Certificate Identity Mapping Rule:

 .. code-block:: console

    ipa certmaprule-del rule1


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `certmap-match`_
     - Search for users matching the provided certificate.
   * - `certmapconfig-mod`_
     - Modify Certificate Identity Mapping configuration.
   * - `certmapconfig-show`_
     - Show the current Certificate Identity Mapping configuration.
   * - `certmaprule-add`_
     - Create a new Certificate Identity Mapping Rule.
   * - `certmaprule-del`_
     - Delete a Certificate Identity Mapping Rule.
   * - `certmaprule-disable`_
     - Disable a Certificate Identity Mapping Rule.
   * - `certmaprule-enable`_
     - Enable a Certificate Identity Mapping Rule.
   * - `certmaprule-find`_
     - Search for Certificate Identity Mapping Rules.
   * - `certmaprule-mod`_
     - Modify a Certificate Identity Mapping Rule.
   * - `certmaprule-show`_
     - Display information about a Certificate Identity Mapping Rule.

----

.. _certmap-match:

certmap-match
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmap-match CERTIFICATE [options]``

Search for users matching the provided certificate.


.. code-block:: console

    This command relies on SSSD to retrieve the list of matching users and
    may return cached data. For more information on purging SSSD cache,
    please refer to sss_cache documentation.


Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CERTIFICATE``
     - yes
     - Base-64 encoded user certificate

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _certmapconfig-mod:

certmapconfig-mod
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmapconfig-mod [options]``

Modify Certificate Identity Mapping configuration.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--promptusername PROMPTUSERNAME``
     - Prompt for the username when multiple identities are mapped to a certificate
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

----

.. _certmapconfig-show:

certmapconfig-show
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmapconfig-show [options]``

Show the current Certificate Identity Mapping configuration.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _certmaprule-add:

certmaprule-add
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmaprule-add RULENAME [options]``

Create a new Certificate Identity Mapping Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``RULENAME``
     - yes
     - Certificate Identity Mapping Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Certificate Identity Mapping Rule description
   * - ``--maprule MAPRULE``
     - Rule used to map the certificate with a user entry
   * - ``--matchrule MATCHRULE``
     - Rule used to check if a certificate can be used for authentication
   * - ``--domain DOMAIN``
     - Domain where the user entry will be searched
   * - ``--priority PRIORITY``
     - Priority of the rule (higher number means lower priority
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _certmaprule-del:

certmaprule-del
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmaprule-del RULENAME [options]``

Delete a Certificate Identity Mapping Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``RULENAME``
     - yes
     - Certificate Identity Mapping Rule name

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

.. _certmaprule-disable:

certmaprule-disable
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmaprule-disable RULENAME [options]``

Disable a Certificate Identity Mapping Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``RULENAME``
     - yes
     - Certificate Identity Mapping Rule name

----

.. _certmaprule-enable:

certmaprule-enable
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmaprule-enable RULENAME [options]``

Enable a Certificate Identity Mapping Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``RULENAME``
     - yes
     - Certificate Identity Mapping Rule name

----

.. _certmaprule-find:

certmaprule-find
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmaprule-find [CRITERIA] [options]``

Search for Certificate Identity Mapping Rules.

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
   * - ``--rulename RULENAME``
     - Certificate Identity Mapping Rule name
   * - ``--desc DESC``
     - Certificate Identity Mapping Rule description
   * - ``--maprule MAPRULE``
     - Rule used to map the certificate with a user entry
   * - ``--matchrule MATCHRULE``
     - Rule used to check if a certificate can be used for authentication
   * - ``--domain DOMAIN``
     - Domain where the user entry will be searched
   * - ``--priority PRIORITY``
     - Priority of the rule (higher number means lower priority
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("rulename")

----

.. _certmaprule-mod:

certmaprule-mod
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmaprule-mod RULENAME [options]``

Modify a Certificate Identity Mapping Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``RULENAME``
     - yes
     - Certificate Identity Mapping Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Certificate Identity Mapping Rule description
   * - ``--maprule MAPRULE``
     - Rule used to map the certificate with a user entry
   * - ``--matchrule MATCHRULE``
     - Rule used to check if a certificate can be used for authentication
   * - ``--domain DOMAIN``
     - Domain where the user entry will be searched
   * - ``--priority PRIORITY``
     - Priority of the rule (higher number means lower priority
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

----

.. _certmaprule-show:

certmaprule-show
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] certmaprule-show RULENAME [options]``

Display information about a Certificate Identity Mapping Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``RULENAME``
     - yes
     - Certificate Identity Mapping Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

