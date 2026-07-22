SELinux User Mapping
====================

Map IPA users to SELinux users by host.

Hosts, hostgroups, users and groups can be either defined within
the rule or it may point to an existing HBAC rule. When using
--hbacrule option to ``selinuxusermap-find`` an exact match is made on the
HBAC rule name, so only one or zero entries will be returned.


**EXAMPLES**

 Create a rule, "test1", that sets all users to xguest_u:s0 on the host "server":

 .. code-block:: console

    ipa selinuxusermap-add --usercat=all --selinuxuser=xguest_u:s0 test1
    ipa selinuxusermap-add-host --hosts=server.example.com test1

 Create a rule, "test2", that sets all users to guest_u:s0 and uses an existing HBAC rule for users and hosts:

 .. code-block:: console

    ipa selinuxusermap-add --usercat=all --hbacrule=webserver --selinuxuser=guest_u:s0 test2

 Display the properties of a rule:

 .. code-block:: console

    ipa selinuxusermap-show test2

 Create a rule for a specific user. This sets the SELinux context for

 user john to unconfined_u:s0-s0:c0.c1023 on any machine:

 .. code-block:: console

    ipa selinuxusermap-add --hostcat=all --selinuxuser=unconfined_u:s0-s0:c0.c1023 john_unconfined
    ipa selinuxusermap-add-user --users=john john_unconfined

 Disable a rule:

 .. code-block:: console

    ipa selinuxusermap-disable test1

 Enable a rule:

 .. code-block:: console

    ipa selinuxusermap-enable test1

 Find a rule referencing a specific HBAC rule:

 .. code-block:: console

    ipa selinuxusermap-find --hbacrule=allow_some

 Remove a rule:

 .. code-block:: console

    ipa selinuxusermap-del john_unconfined


**SEEALSO**

 The list controlling the order in which the SELinux user map is applied

 and the default SELinux user are available in the ``config-show`` command.

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `selinuxusermap-add`_
     - Create a new SELinux User Map.
   * - `selinuxusermap-add-host`_
     - Add target hosts and hostgroups to an SELinux User Map rule.
   * - `selinuxusermap-add-user`_
     - Add users and groups to an SELinux User Map rule.
   * - `selinuxusermap-del`_
     - Delete a SELinux User Map.
   * - `selinuxusermap-disable`_
     - Disable an SELinux User Map rule.
   * - `selinuxusermap-enable`_
     - Enable an SELinux User Map rule.
   * - `selinuxusermap-find`_
     - Search for SELinux User Maps.
   * - `selinuxusermap-mod`_
     - Modify a SELinux User Map.
   * - `selinuxusermap-remove-host`_
     - Remove target hosts and hostgroups from an SELinux User Map rule.
   * - `selinuxusermap-remove-user`_
     - Remove users and groups from an SELinux User Map rule.
   * - `selinuxusermap-show`_
     - Display the properties of a SELinux User Map rule.

----

.. _selinuxusermap-add:

selinuxusermap-add
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-add NAME [options]``

Create a new SELinux User Map.

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
   * - ``--selinuxuser SELINUXUSER``
     - SELinux User
   * - ``--hbacrule HBACRULE``
     - HBAC Rule that defines the users, groups and hostgroups
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
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

.. _selinuxusermap-add-host:

selinuxusermap-add-host
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-add-host NAME [options]``

Add target hosts and hostgroups to an SELinux User Map rule.

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

.. _selinuxusermap-add-user:

selinuxusermap-add-user
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-add-user NAME [options]``

Add users and groups to an SELinux User Map rule.

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

.. _selinuxusermap-del:

selinuxusermap-del
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-del NAME [options]``

Delete a SELinux User Map.

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

.. _selinuxusermap-disable:

selinuxusermap-disable
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-disable NAME [options]``

Disable an SELinux User Map rule.

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

.. _selinuxusermap-enable:

selinuxusermap-enable
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-enable NAME [options]``

Enable an SELinux User Map rule.

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

.. _selinuxusermap-find:

selinuxusermap-find
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-find [CRITERIA] [options]``

Search for SELinux User Maps.

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
   * - ``--selinuxuser SELINUXUSER``
     - SELinux User
   * - ``--hbacrule HBACRULE``
     - HBAC Rule that defines the users, groups and hostgroups
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
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

.. _selinuxusermap-mod:

selinuxusermap-mod
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-mod NAME [options]``

Modify a SELinux User Map.

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
   * - ``--selinuxuser SELINUXUSER``
     - SELinux User
   * - ``--hbacrule HBACRULE``
     - HBAC Rule that defines the users, groups and hostgroups
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
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

----

.. _selinuxusermap-remove-host:

selinuxusermap-remove-host
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-remove-host NAME [options]``

Remove target hosts and hostgroups from an SELinux User Map rule.

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

.. _selinuxusermap-remove-user:

selinuxusermap-remove-user
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-remove-user NAME [options]``

Remove users and groups from an SELinux User Map rule.

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

.. _selinuxusermap-show:

selinuxusermap-show
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] selinuxusermap-show NAME [options]``

Display the properties of a SELinux User Map rule.

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

