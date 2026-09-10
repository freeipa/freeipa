Roles
=====

A role is used for fine-grained delegation. A permission grants the ability
to perform given low-level tasks (add a user, modify a group, etc.). A
privilege combines one or more permissions into a higher-level abstraction
such as useradmin. A useradmin would be able to add, delete and modify users.

Privileges are assigned to Roles.

Users, groups, hosts and hostgroups may be members of a Role.

Roles can not contain other roles.


**EXAMPLES**

 Add a new role:

 .. code-block:: console

    ipa role-add --desc="Junior-level admin" junioradmin

 Add some privileges to this role:

 .. code-block:: console

    ipa role-add-privilege --privileges=addusers junioradmin
    ipa role-add-privilege --privileges=change_password junioradmin
    ipa role-add-privilege --privileges=add_user_to_default_group junioradmin

 Add a group of users to this role:

 .. code-block:: console

    ipa group-add --desc="User admins" useradmins
    ipa role-add-member --groups=useradmins junioradmin

 Display information about a role:

 .. code-block:: console

    ipa role-show junioradmin

 The result of this is that any users in the group 'junioradmin' can

 add users, reset passwords or add a user to the default IPA user group.

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `role-add`_
     - Add a new role.
   * - `role-add-member`_
     - Add members to a role.
   * - `role-add-privilege`_
     - Add privileges to a role.
   * - `role-del`_
     - Delete a role.
   * - `role-find`_
     - Search for roles.
   * - `role-mod`_
     - Modify a role.
   * - `role-remove-member`_
     - Remove members from a role.
   * - `role-remove-privilege`_
     - Remove privileges from a role.
   * - `role-show`_
     - Display information about a role.

----

.. _role-add:

role-add
~~~~~~~~

**Usage:** ``ipa [global-options] role-add NAME [options]``

Add a new role.

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
     - Role name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this role-group
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

.. _role-add-member:

role-add-member
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] role-add-member NAME [options]``

Add members to a role.

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
     - Role name

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
   * - ``--hosts HOSTS``
     - hosts to add
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add
   * - ``--services SERVICES``
     - services to add
   * - ``--idoverrideusers IDOVERRIDEUSERS``
     - User ID overrides to add
   * - ``--sysaccounts SYSACCOUNTS``
     - system accounts to add

----

.. _role-add-privilege:

role-add-privilege
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] role-add-privilege NAME [options]``

Add privileges to a role.

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
     - Role name

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
   * - ``--privileges PRIVILEGES``
     - privileges

----

.. _role-del:

role-del
~~~~~~~~

**Usage:** ``ipa [global-options] role-del NAME [options]``

Delete a role.

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
     - Role name

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

.. _role-find:

role-find
~~~~~~~~~

**Usage:** ``ipa [global-options] role-find [CRITERIA] [options]``

Search for roles.

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
     - Role name
   * - ``--desc DESC``
     - A description of this role-group
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

.. _role-mod:

role-mod
~~~~~~~~

**Usage:** ``ipa [global-options] role-mod NAME [options]``

Modify a role.

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
     - Role name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this role-group
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
     - Rename the role object

----

.. _role-remove-member:

role-remove-member
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] role-remove-member NAME [options]``

Remove members from a role.

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
     - Role name

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
   * - ``--hosts HOSTS``
     - hosts to remove
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove
   * - ``--services SERVICES``
     - services to remove
   * - ``--idoverrideusers IDOVERRIDEUSERS``
     - User ID overrides to remove
   * - ``--sysaccounts SYSACCOUNTS``
     - system accounts to remove

----

.. _role-remove-privilege:

role-remove-privilege
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] role-remove-privilege NAME [options]``

Remove privileges from a role.

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
     - Role name

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
   * - ``--privileges PRIVILEGES``
     - privileges

----

.. _role-show:

role-show
~~~~~~~~~

**Usage:** ``ipa [global-options] role-show NAME [options]``

Display information about a role.

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
     - Role name

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

