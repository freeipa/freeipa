Host-based access control
=========================

Control who can access what services on what hosts. You
can use HBAC to control which users or groups can
access a service, or group of services, on a target host.

You can also specify a category of users and target hosts.
This is currently limited to "all", but might be expanded in the
future.

Target hosts in HBAC rules must be hosts managed by IPA.

The available services and groups of services are controlled by the
hbacsvc and hbacsvcgroup plug-ins respectively.


**EXAMPLES**

 Create a rule, "test1", that grants all users access to the host "server" from

 anywhere:

 .. code-block:: console

    ipa hbacrule-add --usercat=all test1
    ipa hbacrule-add-host --hosts=server.example.com test1

 Display the properties of a named HBAC rule:

 .. code-block:: console

    ipa hbacrule-show test1

 Create a rule for a specific service. This lets the user john access

 the sshd service on any machine from any machine:

 .. code-block:: console

    ipa hbacrule-add --hostcat=all john_sshd
    ipa hbacrule-add-user --users=john john_sshd
    ipa hbacrule-add-service --hbacsvcs=sshd john_sshd

 Create a rule for a new service group. This lets the user john access

 the FTP service on any machine from any machine:

 .. code-block:: console

    ipa hbacsvcgroup-add ftpers
    ipa hbacsvc-add sftp
    ipa hbacsvcgroup-add-member --hbacsvcs=ftp --hbacsvcs=sftp ftpers
    ipa hbacrule-add --hostcat=all john_ftp
    ipa hbacrule-add-user --users=john john_ftp
    ipa hbacrule-add-service --hbacsvcgroups=ftpers john_ftp

 Disable a named HBAC rule:

 .. code-block:: console

    ipa hbacrule-disable test1

 Remove a named HBAC rule:

 .. code-block:: console

    ipa hbacrule-del allow_server


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `hbacrule-add`_
     - Create a new HBAC rule.
   * - `hbacrule-add-host`_
     - Add target hosts and hostgroups to an HBAC rule.
   * - `hbacrule-add-service`_
     - Add services to an HBAC rule.
   * - `hbacrule-add-user`_
     - Add users and groups to an HBAC rule.
   * - `hbacrule-del`_
     - Delete an HBAC rule.
   * - `hbacrule-disable`_
     - Disable an HBAC rule.
   * - `hbacrule-enable`_
     - Enable an HBAC rule.
   * - `hbacrule-find`_
     - Search for HBAC rules.
   * - `hbacrule-mod`_
     - Modify an HBAC rule.
   * - `hbacrule-remove-host`_
     - Remove target hosts and hostgroups from an HBAC rule.
   * - `hbacrule-remove-service`_
     - Remove service and service groups from an HBAC rule.
   * - `hbacrule-remove-user`_
     - Remove users and groups from an HBAC rule.
   * - `hbacrule-show`_
     - Display the properties of an HBAC rule.

----

.. _hbacrule-add:

hbacrule-add
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-add NAME [options]``

Create a new HBAC rule.

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
     - Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
   * - ``--servicecat SERVICECAT``
     - Service category the rule applies to
   * - ``--desc DESC``
     - Description
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

.. _hbacrule-add-host:

hbacrule-add-host
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-add-host NAME [options]``

Add target hosts and hostgroups to an HBAC rule.

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
     - Rule name

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
   * - ``--hosts HOSTS``
     - hosts to add
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add

----

.. _hbacrule-add-service:

hbacrule-add-service
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-add-service NAME [options]``

Add services to an HBAC rule.

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
     - Rule name

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
   * - ``--hbacsvcs HBACSVCS``
     - HBAC services to add
   * - ``--hbacsvcgroups HBACSVCGROUPS``
     - HBAC service groups to add

----

.. _hbacrule-add-user:

hbacrule-add-user
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-add-user NAME [options]``

Add users and groups to an HBAC rule.

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
     - Rule name

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
   * - ``--users USERS``
     - users to add
   * - ``--groups GROUPS``
     - groups to add

----

.. _hbacrule-del:

hbacrule-del
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-del NAME [options]``

Delete an HBAC rule.

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
     - Rule name

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

.. _hbacrule-disable:

hbacrule-disable
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-disable NAME [options]``

Disable an HBAC rule.

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
     - Rule name

----

.. _hbacrule-enable:

hbacrule-enable
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-enable NAME [options]``

Enable an HBAC rule.

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
     - Rule name

----

.. _hbacrule-find:

hbacrule-find
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-find [CRITERIA] [options]``

Search for HBAC rules.

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
     - Rule name
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
   * - ``--servicecat SERVICECAT``
     - Service category the rule applies to
   * - ``--desc DESC``
     - Description
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

.. _hbacrule-mod:

hbacrule-mod
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-mod NAME [options]``

Modify an HBAC rule.

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
     - Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
   * - ``--servicecat SERVICECAT``
     - Service category the rule applies to
   * - ``--desc DESC``
     - Description
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
   * - ``--rename RENAME``
     - Rename the HBAC rule object

----

.. _hbacrule-remove-host:

hbacrule-remove-host
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-remove-host NAME [options]``

Remove target hosts and hostgroups from an HBAC rule.

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
     - Rule name

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
   * - ``--hosts HOSTS``
     - hosts to remove
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove

----

.. _hbacrule-remove-service:

hbacrule-remove-service
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-remove-service NAME [options]``

Remove service and service groups from an HBAC rule.

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
     - Rule name

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
   * - ``--hbacsvcs HBACSVCS``
     - HBAC services to remove
   * - ``--hbacsvcgroups HBACSVCGROUPS``
     - HBAC service groups to remove

----

.. _hbacrule-remove-user:

hbacrule-remove-user
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-remove-user NAME [options]``

Remove users and groups from an HBAC rule.

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
     - Rule name

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
   * - ``--users USERS``
     - users to remove
   * - ``--groups GROUPS``
     - groups to remove

----

.. _hbacrule-show:

hbacrule-show
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hbacrule-show NAME [options]``

Display the properties of an HBAC rule.

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
     - Rule name

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

