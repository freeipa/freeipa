HBAC Service Groups
===================

HBAC service groups can contain any number of individual services,
or "members". Every group must have a description.


**EXAMPLES**

 Add a new HBAC service group:

 .. code-block:: console

    ipa hbacsvcgroup-add --desc="login services" login

 Add members to an HBAC service group:

 .. code-block:: console

    ipa hbacsvcgroup-add-member --hbacsvcs=sshd --hbacsvcs=login login

 Display information about a named group:

 .. code-block:: console

    ipa hbacsvcgroup-show login

 Delete an HBAC service group:

 .. code-block:: console

    ipa hbacsvcgroup-del login


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `hbacsvcgroup-add`_
     - Add a new HBAC service group.
   * - `hbacsvcgroup-add-member`_
     - Add members to an HBAC service group.
   * - `hbacsvcgroup-del`_
     - Delete an HBAC service group.
   * - `hbacsvcgroup-find`_
     - Search for an HBAC service group.
   * - `hbacsvcgroup-mod`_
     - Modify an HBAC service group.
   * - `hbacsvcgroup-remove-member`_
     - Remove members from an HBAC service group.
   * - `hbacsvcgroup-show`_
     - Display information about an HBAC service group.

----

.. _hbacsvcgroup-add:

hbacsvcgroup-add
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvcgroup-add NAME [options]``

Add a new HBAC service group.

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
     - Service group name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - HBAC service group description
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _hbacsvcgroup-add-member:

hbacsvcgroup-add-member
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvcgroup-add-member NAME [options]``

Add members to an HBAC service group.

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
     - Service group name

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
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--hbacsvcs HBACSVCS``
     - HBAC services to add

----

.. _hbacsvcgroup-del:

hbacsvcgroup-del
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvcgroup-del NAME [options]``

Delete an HBAC service group.

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
     - Service group name

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

.. _hbacsvcgroup-find:

hbacsvcgroup-find
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvcgroup-find [CRITERIA] [options]``

Search for an HBAC service group.

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
     - Service group name
   * - ``--desc DESC``
     - HBAC service group description
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

.. _hbacsvcgroup-mod:

hbacsvcgroup-mod
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvcgroup-mod NAME [options]``

Modify an HBAC service group.

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
     - Service group name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - HBAC service group description
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
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _hbacsvcgroup-remove-member:

hbacsvcgroup-remove-member
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvcgroup-remove-member NAME [options]``

Remove members from an HBAC service group.

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
     - Service group name

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
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--hbacsvcs HBACSVCS``
     - HBAC services to remove

----

.. _hbacsvcgroup-show:

hbacsvcgroup-show
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvcgroup-show NAME [options]``

Display information about an HBAC service group.

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
     - Service group name

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
   * - ``--no-members``
     - Suppress processing of membership attributes.

