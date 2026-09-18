IPA server roles
================

Get status of roles (DNS server, CA, etc.) provided by IPA masters.

The status of a role is either enabled, configured, or absent.


**EXAMPLES**

  Show status of 'DNS server' role on a server:

  .. code-block:: console

      ipa server-role-show ipa.example.com "DNS server"

  Show status of all roles containing 'AD' on a server:

  .. code-block:: console

      ipa server-role-find --server ipa.example.com --role="AD trust controller"

  Show status of all configured roles on a server:

  .. code-block:: console

      ipa server-role-find ipa.example.com

  Show implicit IPA master role:

  .. code-block:: console

      ipa server-role-find --include-master


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `server-role-find`_
     - Find a server role on a server(s)
   * - `server-role-show`_
     - Show role status on a server

----

.. _server-role-find:

server-role-find
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] server-role-find [CRITERIA] [options]``

Find a server role on a server(s)

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
   * - ``--server SERVER``
     - IPA server hostname
   * - ``--role ROLE``
     - IPA server role name
   * - ``--status STATUS``
     - Status of the role
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--include-master``
     - Include IPA master entries
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _server-role-show:

server-role-show
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] server-role-show SERVER ROLE [options]``

Show role status on a server

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SERVER``
     - yes
     - IPA server hostname
   * - ``ROLE``
     - yes
     - IPA server role name

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

