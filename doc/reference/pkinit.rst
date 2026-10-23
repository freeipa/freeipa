Kerberos PKINIT feature status reporting tools.
===============================================

Report IPA masters on which Kerberos PKINIT is enabled or disabled

EXAMPLES:

 List PKINIT status on all masters:

 .. code-block:: console

    ipa pkinit-status

 Check PKINIT status on `ipa.example.com`:

 .. code-block:: console

    ipa pkinit-status --server ipa.example.com

 List all IPA masters with disabled PKINIT:

 .. code-block:: console

    ipa pkinit-status --status='disabled'

For more info about PKINIT support see:

https://www.freeipa.org/page/V4/Kerberos_PKINIT

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `pkinit-status`_
     - Report PKINIT status on the IPA masters

----

.. _pkinit-status:

pkinit-status
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] pkinit-status [CRITERIA] [options]``

Report PKINIT status on the IPA masters

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
   * - ``--status STATUS``
     - Whether PKINIT is enabled or disabled
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

