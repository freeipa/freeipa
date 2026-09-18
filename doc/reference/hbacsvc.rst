HBAC Services
=============

The PAM services that HBAC can control access to. The name used here
must match the service name that PAM is evaluating.


**EXAMPLES**

 Add a new HBAC service:

 .. code-block:: console

    ipa hbacsvc-add tftp

 Modify an existing HBAC service:

 .. code-block:: console

    ipa hbacsvc-mod --desc="TFTP service" tftp

 Search for HBAC services. This example will return two results, the FTP

 service and the newly-added tftp service:

 .. code-block:: console

    ipa hbacsvc-find ftp

 Delete an HBAC service:

 .. code-block:: console

    ipa hbacsvc-del tftp


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `hbacsvc-add`_
     - Add a new HBAC service.
   * - `hbacsvc-del`_
     - Delete an existing HBAC service.
   * - `hbacsvc-find`_
     - Search for HBAC services.
   * - `hbacsvc-mod`_
     - Modify an HBAC service.
   * - `hbacsvc-show`_
     - Display information about an HBAC service.

----

.. _hbacsvc-add:

hbacsvc-add
~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvc-add SERVICE [options]``

Add a new HBAC service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SERVICE``
     - yes
     - HBAC service

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - HBAC service description
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

.. _hbacsvc-del:

hbacsvc-del
~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvc-del SERVICE [options]``

Delete an existing HBAC service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SERVICE``
     - yes
     - HBAC service

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

.. _hbacsvc-find:

hbacsvc-find
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvc-find [CRITERIA] [options]``

Search for HBAC services.

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
   * - ``--service SERVICE``
     - HBAC service
   * - ``--desc DESC``
     - HBAC service description
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("service")

----

.. _hbacsvc-mod:

hbacsvc-mod
~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvc-mod SERVICE [options]``

Modify an HBAC service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SERVICE``
     - yes
     - HBAC service

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - HBAC service description
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

.. _hbacsvc-show:

hbacsvc-show
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacsvc-show SERVICE [options]``

Display information about an HBAC service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SERVICE``
     - yes
     - HBAC service

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

