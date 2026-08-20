Misc plug-ins
=============

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `env`_
     - Show environment variables.
   * - `plugins`_
     - Show all loaded plugins.

----

.. _env:

env
~~~

**Usage:** ``ipa [global-options] env [VARIABLES] [options]``

Show environment variables.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``VARIABLES``
     - no
     - <variables>

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--server``
     - Forward to server instead of running locally

----

.. _plugins:

plugins
~~~~~~~

**Usage:** ``ipa [global-options] plugins [options]``

Show all loaded plugins.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--server``
     - Forward to server instead of running locally

