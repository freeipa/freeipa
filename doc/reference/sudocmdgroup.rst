Groups of Sudo Commands
=======================

Manage groups of Sudo Commands.


**EXAMPLES**

 Add a new Sudo Command Group:

 .. code-block:: console

    ipa sudocmdgroup-add --desc='administrators commands' admincmds

 Remove a Sudo Command Group:

 .. code-block:: console

    ipa sudocmdgroup-del admincmds

 Manage Sudo Command Group membership, commands:

 .. code-block:: console

    ipa sudocmdgroup-add-member --sudocmds=/usr/bin/less --sudocmds=/usr/bin/vim admincmds

 Manage Sudo Command Group membership, commands:

 .. code-block:: console

    ipa sudocmdgroup-remove-member --sudocmds=/usr/bin/less admincmds

 Show a Sudo Command Group:

 .. code-block:: console

    ipa sudocmdgroup-show admincmds


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `sudocmdgroup-add`_
     - Create new Sudo Command Group.
   * - `sudocmdgroup-add-member`_
     - Add members to Sudo Command Group.
   * - `sudocmdgroup-del`_
     - Delete Sudo Command Group.
   * - `sudocmdgroup-find`_
     - Search for Sudo Command Groups.
   * - `sudocmdgroup-mod`_
     - Modify Sudo Command Group.
   * - `sudocmdgroup-remove-member`_
     - Remove members from Sudo Command Group.
   * - `sudocmdgroup-show`_
     - Display Sudo Command Group.

----

.. _sudocmdgroup-add:

sudocmdgroup-add
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmdgroup-add SUDOCMDGROUP-NAME [options]``

Create new Sudo Command Group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDOCMDGROUP-NAME``
     - yes
     - Sudo Command Group

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Group description
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

.. _sudocmdgroup-add-member:

sudocmdgroup-add-member
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmdgroup-add-member SUDOCMDGROUP-NAME [options]``

Add members to Sudo Command Group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDOCMDGROUP-NAME``
     - yes
     - Sudo Command Group

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
   * - ``--sudocmds SUDOCMDS``
     - sudo commands to add

----

.. _sudocmdgroup-del:

sudocmdgroup-del
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmdgroup-del SUDOCMDGROUP-NAME [options]``

Delete Sudo Command Group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDOCMDGROUP-NAME``
     - yes
     - Sudo Command Group

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

.. _sudocmdgroup-find:

sudocmdgroup-find
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmdgroup-find [CRITERIA] [options]``

Search for Sudo Command Groups.

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
   * - ``--sudocmdgroup-name SUDOCMDGROUP-NAME``
     - Sudo Command Group
   * - ``--desc DESC``
     - Group description
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("sudocmdgroup-name")

----

.. _sudocmdgroup-mod:

sudocmdgroup-mod
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmdgroup-mod SUDOCMDGROUP-NAME [options]``

Modify Sudo Command Group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDOCMDGROUP-NAME``
     - yes
     - Sudo Command Group

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Group description
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

.. _sudocmdgroup-remove-member:

sudocmdgroup-remove-member
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmdgroup-remove-member SUDOCMDGROUP-NAME [options]``

Remove members from Sudo Command Group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDOCMDGROUP-NAME``
     - yes
     - Sudo Command Group

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
   * - ``--sudocmds SUDOCMDS``
     - sudo commands to remove

----

.. _sudocmdgroup-show:

sudocmdgroup-show
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmdgroup-show SUDOCMDGROUP-NAME [options]``

Display Sudo Command Group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDOCMDGROUP-NAME``
     - yes
     - Sudo Command Group

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

