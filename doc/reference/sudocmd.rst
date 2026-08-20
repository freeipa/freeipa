Sudo Commands
=============

Commands used as building blocks for sudo


**EXAMPLES**

 Create a new command

 .. code-block:: console

    ipa sudocmd-add --desc='For reading log files' /usr/bin/less

 Remove a command

 .. code-block:: console

    ipa sudocmd-del /usr/bin/less


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `sudocmd-add`_
     - Create new Sudo Command.
   * - `sudocmd-del`_
     - Delete Sudo Command.
   * - `sudocmd-find`_
     - Search for Sudo Commands.
   * - `sudocmd-mod`_
     - Modify Sudo Command.
   * - `sudocmd-show`_
     - Display Sudo Command.

----

.. _sudocmd-add:

sudocmd-add
~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmd-add COMMAND [options]``

Create new Sudo Command.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``COMMAND``
     - yes
     - Sudo Command

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this command
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

.. _sudocmd-del:

sudocmd-del
~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmd-del COMMAND [options]``

Delete Sudo Command.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``COMMAND``
     - yes
     - Sudo Command

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

.. _sudocmd-find:

sudocmd-find
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmd-find [CRITERIA] [options]``

Search for Sudo Commands.

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
   * - ``--command COMMAND``
     - Sudo Command
   * - ``--desc DESC``
     - A description of this command
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("command")

----

.. _sudocmd-mod:

sudocmd-mod
~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmd-mod COMMAND [options]``

Modify Sudo Command.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``COMMAND``
     - yes
     - Sudo Command

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this command
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

.. _sudocmd-show:

sudocmd-show
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudocmd-show COMMAND [options]``

Display Sudo Command.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``COMMAND``
     - yes
     - Sudo Command

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

