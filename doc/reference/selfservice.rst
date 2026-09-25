Self-service Permissions
========================

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

A Self-service permission defines what an object can change in its own entry.



**EXAMPLES**

 Add a self-service rule to allow users to manage their address (using Bash

 brace expansion):

 .. code-block:: console

    ipa selfservice-add --permissions=write --attrs={street,postalCode,l,c,st} "Users manage their own address"

 When managing the list of attributes you need to include all attributes

 in the list, including existing ones.

 Add telephoneNumber to the list (using Bash brace expansion):

 .. code-block:: console

    ipa selfservice-mod --attrs={street,postalCode,l,c,st,telephoneNumber} "Users manage their own address"

 Display our updated rule:

 .. code-block:: console

    ipa selfservice-show "Users manage their own address"

 Delete a rule:

 .. code-block:: console

    ipa selfservice-del "Users manage their own address"


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `selfservice-add`_
     - Add a new self-service permission.
   * - `selfservice-del`_
     - Delete a self-service permission.
   * - `selfservice-find`_
     - Search for a self-service permission.
   * - `selfservice-mod`_
     - Modify a self-service permission.
   * - `selfservice-show`_
     - Display information about a self-service permission.

----

.. _selfservice-add:

selfservice-add
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selfservice-add NAME [options]``

Add a new self-service permission.

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
     - Self-service name

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
     - Attributes to which the permission applies.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _selfservice-del:

selfservice-del
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selfservice-del NAME [options]``

Delete a self-service permission.

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
     - Self-service name

----

.. _selfservice-find:

selfservice-find
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selfservice-find [CRITERIA] [options]``

Search for a self-service permission.

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
     - Self-service name
   * - ``--permissions PERMISSIONS``
     - Permissions to grant (read, write). Default is write.
   * - ``--attrs ATTRS``
     - Attributes to which the permission applies.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _selfservice-mod:

selfservice-mod
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selfservice-mod NAME [options]``

Modify a self-service permission.

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
     - Self-service name

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
     - Attributes to which the permission applies.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _selfservice-show:

selfservice-show
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selfservice-show NAME [options]``

Display information about a self-service permission.

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
     - Self-service name

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

