RADIUS Proxy Servers
====================

Manage RADIUS Proxy Servers.

IPA supports the use of an external RADIUS proxy server for krb5 OTP
authentications. This permits a great deal of flexibility when
integrating with third-party authentication services.


**EXAMPLES**

 Add a new server:

 .. code-block:: console

    ipa radiusproxy-add MyRADIUS --server=radius.example.com:1812

 Find all servers whose entries include the string "example.com":

 .. code-block:: console

    ipa radiusproxy-find example.com

 Examine the configuration:

 .. code-block:: console

    ipa radiusproxy-show MyRADIUS

 Change the secret:

 .. code-block:: console

    ipa radiusproxy-mod MyRADIUS --secret

 Delete a configuration:

 .. code-block:: console

    ipa radiusproxy-del MyRADIUS


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `radiusproxy-add`_
     - Add a new RADIUS proxy server.
   * - `radiusproxy-del`_
     - Delete a RADIUS proxy server.
   * - `radiusproxy-find`_
     - Search for RADIUS proxy servers.
   * - `radiusproxy-mod`_
     - Modify a RADIUS proxy server.
   * - `radiusproxy-show`_
     - Display information about a RADIUS proxy server.

----

.. _radiusproxy-add:

radiusproxy-add
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] radiusproxy-add NAME [options]``

Add a new RADIUS proxy server.

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
     - RADIUS proxy server name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this RADIUS proxy server
   * - ``--server SERVER``
     - The hostname or IP (with or without port)
   * - ``--secret SECRET``
     - The secret used to encrypt data
   * - ``--timeout TIMEOUT``
     - The total timeout across all retries (in seconds)
   * - ``--retries RETRIES``
     - The number of times to retry authentication
   * - ``--userattr USERATTR``
     - The username attribute on the user object
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _radiusproxy-del:

radiusproxy-del
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] radiusproxy-del NAME [options]``

Delete a RADIUS proxy server.

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
     - RADIUS proxy server name

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

.. _radiusproxy-find:

radiusproxy-find
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] radiusproxy-find [CRITERIA] [options]``

Search for RADIUS proxy servers.

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
     - RADIUS proxy server name
   * - ``--desc DESC``
     - A description of this RADIUS proxy server
   * - ``--server SERVER``
     - The hostname or IP (with or without port)
   * - ``--timeout TIMEOUT``
     - The total timeout across all retries (in seconds)
   * - ``--retries RETRIES``
     - The number of times to retry authentication
   * - ``--userattr USERATTR``
     - The username attribute on the user object
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

----

.. _radiusproxy-mod:

radiusproxy-mod
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] radiusproxy-mod NAME [options]``

Modify a RADIUS proxy server.

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
     - RADIUS proxy server name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this RADIUS proxy server
   * - ``--server SERVER``
     - The hostname or IP (with or without port)
   * - ``--secret SECRET``
     - The secret used to encrypt data
   * - ``--timeout TIMEOUT``
     - The total timeout across all retries (in seconds)
   * - ``--retries RETRIES``
     - The number of times to retry authentication
   * - ``--userattr USERATTR``
     - The username attribute on the user object
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
   * - ``--rename RENAME``
     - Rename the RADIUS proxy server object

----

.. _radiusproxy-show:

radiusproxy-show
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] radiusproxy-show NAME [options]``

Display information about a RADIUS proxy server.

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
     - RADIUS proxy server name

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

