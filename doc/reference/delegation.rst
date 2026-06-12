Group to Group Delegation
=========================

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

Group to Group Delegations grants the members of one group to update a set
of attributes of members of another group.


**EXAMPLES**

 Add a delegation rule to allow managers to edit employee's addresses:

 .. code-block:: console

    ipa delegation-add --attrs=street --group=managers --membergroup=employees "managers edit employees' street"

 When managing the list of attributes you need to include all attributes

 in the list, including existing ones. Add postalCode to the list:

 .. code-block:: console

    ipa delegation-mod --attrs=street --attrs=postalCode --group=managers --membergroup=employees "managers edit employees' street"

 Display our updated rule:

 .. code-block:: console

    ipa delegation-show "managers edit employees' street"

 Delete a rule:

 .. code-block:: console

    ipa delegation-del "managers edit employees' street"


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `delegation-add`_
     - Add a new delegation.
   * - `delegation-del`_
     - Delete a delegation.
   * - `delegation-find`_
     - Search for delegations.
   * - `delegation-mod`_
     - Modify a delegation.
   * - `delegation-show`_
     - Display information about a delegation.

----

.. _delegation-add:

delegation-add
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] delegation-add NAME [options]``

Add a new delegation.

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
     - Delegation name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--permissions PERMISSIONS``
     - Permissions to grant (read, write). Default is write.
   * - ``--attrs ATTRS``
     - Attributes to which the delegation applies
   * - ``--membergroup MEMBERGROUP``
     - User group to apply delegation to
   * - ``--group GROUP``
     - User group ACI grants access to
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _delegation-del:

delegation-del
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] delegation-del NAME [options]``

Delete a delegation.

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
     - Delegation name

----

.. _delegation-find:

delegation-find
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] delegation-find [CRITERIA] [options]``

Search for delegations.

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
     - Delegation name
   * - ``--permissions PERMISSIONS``
     - Permissions to grant (read, write). Default is write.
   * - ``--attrs ATTRS``
     - Attributes to which the delegation applies
   * - ``--membergroup MEMBERGROUP``
     - User group to apply delegation to
   * - ``--group GROUP``
     - User group ACI grants access to
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _delegation-mod:

delegation-mod
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] delegation-mod NAME [options]``

Modify a delegation.

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
     - Delegation name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--permissions PERMISSIONS``
     - Permissions to grant (read, write). Default is write.
   * - ``--attrs ATTRS``
     - Attributes to which the delegation applies
   * - ``--membergroup MEMBERGROUP``
     - User group to apply delegation to
   * - ``--group GROUP``
     - User group ACI grants access to
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _delegation-show:

delegation-show
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] delegation-show NAME [options]``

Display information about a delegation.

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
     - Delegation name

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

