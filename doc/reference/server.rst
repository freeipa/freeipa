IPA servers
===========

Get information about installed IPA servers.


**EXAMPLES**

  Find all servers:

  .. code-block:: console

      ipa server-find

  Show specific server:

  .. code-block:: console

      ipa server-show ipa.example.com


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `server-del`_
     - Delete IPA server.
   * - `server-find`_
     - Search for IPA servers.
   * - `server-mod`_
     - Modify information about an IPA server.
   * - `server-show`_
     - Show IPA server.
   * - `server-state`_
     - Set enabled/hidden state of a server.

----

.. _server-del:

server-del
~~~~~~~~~~

**Usage:** ``ipa [global-options] server-del NAME [options]``

Delete IPA server.

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
     - IPA server hostname

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.
   * - ``--ignore-topology-disconnect``
     - Ignore topology connectivity problems after removal
   * - ``--ignore-last-of-role``
     - Skip a check whether the last CA master or DNS server is removed
   * - ``--force``
     - Force server removal even if it does not exist

----

.. _server-find:

server-find
~~~~~~~~~~~

**Usage:** ``ipa [global-options] server-find [CRITERIA] [options]``

Search for IPA servers.

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
     - IPA server hostname
   * - ``--minlevel MINLEVEL``
     - Minimum domain level
   * - ``--maxlevel MAXLEVEL``
     - Maximum domain level
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
   * - ``--topologysuffixes TOPOLOGYSUFFIXES``
     - Search for servers with these managed suffixes.
   * - ``--no-topologysuffixes NO-TOPOLOGYSUFFIXES``
     - Search for servers without these managed suffixes.
   * - ``--in-locations IN-LOCATIONS``
     - Search for servers with these ipa locations.
   * - ``--not-in-locations NOT-IN-LOCATIONS``
     - Search for servers without these ipa locations.
   * - ``--servroles SERVROLES``
     - Search for servers with these enabled roles.

----

.. _server-mod:

server-mod
~~~~~~~~~~

**Usage:** ``ipa [global-options] server-mod NAME [options]``

Modify information about an IPA server.

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
     - IPA server hostname

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--location LOCATION``
     - Server DNS location
   * - ``--service-weight SERVICE-WEIGHT``
     - Weight for server services
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

.. _server-show:

server-show
~~~~~~~~~~~

**Usage:** ``ipa [global-options] server-show NAME [options]``

Show IPA server.

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
     - IPA server hostname

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

----

.. _server-state:

server-state
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] server-state NAME [options]``

Set enabled/hidden state of a server.

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
     - IPA server hostname

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--state STATE``
     - Server state

