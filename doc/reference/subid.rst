Subordinate ids
===============

Manage subordinate user and group ids for users


**EXAMPLES**

 Auto-assign a subordinate id range to current user

 .. code-block:: console

    ipa subid-generate

 Auto-assign a subordinate id range to user alice:

 .. code-block:: console

    ipa subid-generate --owner=alice

 Find subordinate ids for user alice:

 .. code-block:: console

    ipa subid-find --owner=alice

 Match entry by any subordinate uid in range:

 .. code-block:: console

    ipa subid-match --subuid=2147483649


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `subid-find`_
     - Search for subordinate id.
   * - `subid-generate`_
     - Generate and auto-assign subuid and subgid range to user entry
   * - `subid-match`_
     - Match users by any subordinate uid in their range
   * - `subid-mod`_
     - Modify a subordinate id.
   * - `subid-show`_
     - Display information about a subordinate id.
   * - `subid-stats`_
     - Subordinate id statistics

----

.. _subid-find:

subid-find
~~~~~~~~~~

**Usage:** ``ipa [global-options] subid-find [CRITERIA] [options]``

Search for subordinate id.

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
     - Unique ID
   * - ``--desc DESC``
     - Subordinate id description
   * - ``--owner OWNER``
     - Owning user of subordinate id entry
   * - ``--subuid SUBUID``
     - Start value for subordinate user ID (subuid) range
   * - ``--subgid SUBGID``
     - Start value for subordinate group ID (subgid) range
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

.. _subid-generate:

subid-generate
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] subid-generate [options]``

Generate and auto-assign subuid and subgid range to user entry

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--owner OWNER``
     - Owning user of subordinate id entry
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _subid-match:

subid-match
~~~~~~~~~~~

**Usage:** ``ipa [global-options] subid-match [CRITERIA] [options]``

Match users by any subordinate uid in their range

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
   * - ``--subuid SUBUID``
     - Match value for subordinate user ID
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

.. _subid-mod:

subid-mod
~~~~~~~~~

**Usage:** ``ipa [global-options] subid-mod ID [options]``

Modify a subordinate id.

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
     - Unique ID

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Subordinate id description
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

.. _subid-show:

subid-show
~~~~~~~~~~

**Usage:** ``ipa [global-options] subid-show ID [options]``

Display information about a subordinate id.

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
     - Unique ID

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

.. _subid-stats:

subid-stats
~~~~~~~~~~~

**Usage:** ``ipa [global-options] subid-stats [options]``

Subordinate id statistics

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

