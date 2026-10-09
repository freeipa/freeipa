Sudo Rules
==========

Sudo (su "do") allows a system administrator to delegate authority to
give certain users (or groups of users) the ability to run some (or all)
commands as root or another user while providing an audit trail of the
commands and their arguments.

IPA provides a means to configure the various aspects of Sudo:

.. code-block:: console

   Users: The user(s)/group(s) allowed to invoke Sudo.
   Hosts: The host(s)/hostgroup(s) which the user is allowed to to invoke Sudo.
   Allow Command: The specific command(s) permitted to be run via Sudo.
   Deny Command: The specific command(s) prohibited to be run via Sudo.
   RunAsUser: The user(s) or group(s) of users whose rights Sudo will be invoked with.
   RunAsGroup: The group(s) whose gid rights Sudo will be invoked with.
   Options: The various Sudoers Options that can modify Sudo's behavior.

Each option needs to be added separately and no validation is done whether
the option is known by sudo or is in a valid format. Environment variables
also need to be set individually. For example env_keep="FOO BAR" in sudoers
needs be represented as --sudooption env_keep=FOO --sudooption env_keep+=BAR.

An order can be added to a sudorule to control the order in which they
are evaluated (if the client supports it). This order is an integer and
must be unique.

IPA provides a designated binddn to use with Sudo located at:
uid=sudo,cn=sysaccounts,cn=etc,dc=example,dc=com

To enable the binddn run the following command to set the password:
LDAPTLS_CACERT=/etc/ipa/ca.crt /usr/bin/ldappasswd -S -W -H ldap://ipa.example.com -ZZ -D "cn=Directory Manager" uid=sudo,cn=sysaccounts,cn=etc,dc=example,dc=com


**EXAMPLES**

 Create a new rule:

 .. code-block:: console

    ipa sudorule-add readfiles

 Add sudo command object and add it as allowed command in the rule:

 .. code-block:: console

    ipa sudocmd-add /usr/bin/less
    ipa sudorule-add-allow-command readfiles --sudocmds /usr/bin/less

 Add a host to the rule:

 .. code-block:: console

    ipa sudorule-add-host readfiles --hosts server.example.com

 Add a user to the rule:

 .. code-block:: console

    ipa sudorule-add-user readfiles --users jsmith

 Add a special Sudo rule for default Sudo server configuration:

 .. code-block:: console

    ipa sudorule-add defaults

 Set a default Sudo option:

 .. code-block:: console

    ipa sudorule-add-option defaults --sudooption '!authenticate'

 Set multiple default Sudo options:

 .. code-block:: console

    ipa sudorule-add-option defaults --sudooption '!authenticate'    --sudooption mail_badpass

 Set SELinux type and role transitions on a rule:

 .. code-block:: console

    ipa sudorule-add-option sysadmin_sudo --sudooption type=unconfined_t
    ipa sudorule-add-option sysadmin_sudo --sudooption role=unconfined_r


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `sudorule-add`_
     - Create new Sudo Rule.
   * - `sudorule-add-allow-command`_
     - Add commands and sudo command groups affected by Sudo Rule.
   * - `sudorule-add-deny-command`_
     - Add commands and sudo command groups affected by Sudo Rule.
   * - `sudorule-add-host`_
     - Add hosts and hostgroups affected by Sudo Rule.
   * - `sudorule-add-option`_
     - Add an option to the Sudo Rule.
   * - `sudorule-add-runasgroup`_
     - Add group for Sudo to execute as.
   * - `sudorule-add-runasuser`_
     - Add users and groups for Sudo to execute as.
   * - `sudorule-add-user`_
     - Add users and groups affected by Sudo Rule.
   * - `sudorule-del`_
     - Delete Sudo Rule.
   * - `sudorule-disable`_
     - Disable a Sudo Rule.
   * - `sudorule-enable`_
     - Enable a Sudo Rule.
   * - `sudorule-find`_
     - Search for Sudo Rule.
   * - `sudorule-mod`_
     - Modify Sudo Rule.
   * - `sudorule-remove-allow-command`_
     - Remove commands and sudo command groups affected by Sudo Rule.
   * - `sudorule-remove-deny-command`_
     - Remove commands and sudo command groups affected by Sudo Rule.
   * - `sudorule-remove-host`_
     - Remove hosts and hostgroups affected by Sudo Rule.
   * - `sudorule-remove-option`_
     - Remove an option from Sudo Rule.
   * - `sudorule-remove-runasgroup`_
     - Remove group for Sudo to execute as.
   * - `sudorule-remove-runasuser`_
     - Remove users and groups for Sudo to execute as.
   * - `sudorule-remove-user`_
     - Remove users and groups affected by Sudo Rule.
   * - `sudorule-show`_
     - Display Sudo Rule.

----

.. _sudorule-add:

sudorule-add
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-add SUDORULE-NAME [options]``

Create new Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
     - yes
     - Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
   * - ``--cmdcat CMDCAT``
     - Command category the rule applies to
   * - ``--runasusercat RUNASUSERCAT``
     - RunAs User category the rule applies to
   * - ``--runasgroupcat RUNASGROUPCAT``
     - RunAs Group category the rule applies to
   * - ``--order ORDER``
     - integer to order the Sudo rules
   * - ``--externaluser EXTERNALUSER``
     - External User the rule applies to (sudorule-find only)
   * - ``--runasexternaluser RUNASEXTERNALUSER``
     - External User the commands can run as (sudorule-find only)
   * - ``--runasexternalgroup RUNASEXTERNALGROUP``
     - External Group the commands can run as (sudorule-find only)
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

.. _sudorule-add-allow-command:

sudorule-add-allow-command
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-add-allow-command SUDORULE-NAME [options]``

Add commands and sudo command groups affected by Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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
   * - ``--sudocmds SUDOCMDS``
     - sudo commands to add
   * - ``--sudocmdgroups SUDOCMDGROUPS``
     - sudo command groups to add

----

.. _sudorule-add-deny-command:

sudorule-add-deny-command
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-add-deny-command SUDORULE-NAME [options]``

Add commands and sudo command groups affected by Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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
   * - ``--sudocmds SUDOCMDS``
     - sudo commands to add
   * - ``--sudocmdgroups SUDOCMDGROUPS``
     - sudo command groups to add

----

.. _sudorule-add-host:

sudorule-add-host
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-add-host SUDORULE-NAME [options]``

Add hosts and hostgroups affected by Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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
   * - ``--hostmask HOSTMASK``
     - host masks of allowed hosts

----

.. _sudorule-add-option:

sudorule-add-option
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-add-option SUDORULE-NAME [options]``

Add an option to the Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
     - yes
     - Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--sudooption SUDOOPTION``
     - Sudo Option
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _sudorule-add-runasgroup:

sudorule-add-runasgroup
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-add-runasgroup SUDORULE-NAME [options]``

Add group for Sudo to execute as.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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
   * - ``--groups GROUPS``
     - groups to add

----

.. _sudorule-add-runasuser:

sudorule-add-runasuser
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-add-runasuser SUDORULE-NAME [options]``

Add users and groups for Sudo to execute as.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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

.. _sudorule-add-user:

sudorule-add-user
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-add-user SUDORULE-NAME [options]``

Add users and groups affected by Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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

.. _sudorule-del:

sudorule-del
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-del SUDORULE-NAME [options]``

Delete Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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

.. _sudorule-disable:

sudorule-disable
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-disable SUDORULE-NAME [options]``

Disable a Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
     - yes
     - Rule name

----

.. _sudorule-enable:

sudorule-enable
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-enable SUDORULE-NAME [options]``

Enable a Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
     - yes
     - Rule name

----

.. _sudorule-find:

sudorule-find
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-find [CRITERIA] [options]``

Search for Sudo Rule.

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
   * - ``--sudorule-name SUDORULE-NAME``
     - Rule name
   * - ``--desc DESC``
     - Description
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
   * - ``--cmdcat CMDCAT``
     - Command category the rule applies to
   * - ``--runasusercat RUNASUSERCAT``
     - RunAs User category the rule applies to
   * - ``--runasgroupcat RUNASGROUPCAT``
     - RunAs Group category the rule applies to
   * - ``--order ORDER``
     - integer to order the Sudo rules
   * - ``--externaluser EXTERNALUSER``
     - External User the rule applies to (sudorule-find only)
   * - ``--runasexternaluser RUNASEXTERNALUSER``
     - External User the commands can run as (sudorule-find only)
   * - ``--runasexternalgroup RUNASEXTERNALGROUP``
     - External Group the commands can run as (sudorule-find only)
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("sudorule-name")

----

.. _sudorule-mod:

sudorule-mod
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-mod SUDORULE-NAME [options]``

Modify Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
     - yes
     - Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
   * - ``--cmdcat CMDCAT``
     - Command category the rule applies to
   * - ``--runasusercat RUNASUSERCAT``
     - RunAs User category the rule applies to
   * - ``--runasgroupcat RUNASGROUPCAT``
     - RunAs Group category the rule applies to
   * - ``--order ORDER``
     - integer to order the Sudo rules
   * - ``--externaluser EXTERNALUSER``
     - External User the rule applies to (sudorule-find only)
   * - ``--runasexternaluser RUNASEXTERNALUSER``
     - External User the commands can run as (sudorule-find only)
   * - ``--runasexternalgroup RUNASEXTERNALGROUP``
     - External Group the commands can run as (sudorule-find only)
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
     - Rename the sudo rule object

----

.. _sudorule-remove-allow-command:

sudorule-remove-allow-command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-remove-allow-command SUDORULE-NAME [options]``

Remove commands and sudo command groups affected by Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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
   * - ``--sudocmds SUDOCMDS``
     - sudo commands to remove
   * - ``--sudocmdgroups SUDOCMDGROUPS``
     - sudo command groups to remove

----

.. _sudorule-remove-deny-command:

sudorule-remove-deny-command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-remove-deny-command SUDORULE-NAME [options]``

Remove commands and sudo command groups affected by Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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
   * - ``--sudocmds SUDOCMDS``
     - sudo commands to remove
   * - ``--sudocmdgroups SUDOCMDGROUPS``
     - sudo command groups to remove

----

.. _sudorule-remove-host:

sudorule-remove-host
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-remove-host SUDORULE-NAME [options]``

Remove hosts and hostgroups affected by Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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
   * - ``--hostmask HOSTMASK``
     - host masks of allowed hosts

----

.. _sudorule-remove-option:

sudorule-remove-option
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-remove-option SUDORULE-NAME [options]``

Remove an option from Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
     - yes
     - Rule name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--sudooption SUDOOPTION``
     - Sudo Option
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _sudorule-remove-runasgroup:

sudorule-remove-runasgroup
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-remove-runasgroup SUDORULE-NAME [options]``

Remove group for Sudo to execute as.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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
   * - ``--groups GROUPS``
     - groups to remove

----

.. _sudorule-remove-runasuser:

sudorule-remove-runasuser
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-remove-runasuser SUDORULE-NAME [options]``

Remove users and groups for Sudo to execute as.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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

.. _sudorule-remove-user:

sudorule-remove-user
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-remove-user SUDORULE-NAME [options]``

Remove users and groups affected by Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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

.. _sudorule-show:

sudorule-show
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sudorule-show SUDORULE-NAME [options]``

Display Sudo Rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``SUDORULE-NAME``
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

