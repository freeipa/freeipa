System accounts
===============

System accounts designed to allow applications to query LDAP database.
Unlike IPA users, system accounts have no POSIX properties and cannot be
resolved as 'users' in a POSIX environment.

System accounts are stored in cn=sysaccounts,cn=etc LDAP subtree. Some of
system accounts are special to IPA's own operations and cannot be removed.


**EXAMPLES**

 Add a new system account, set random password:

 .. code-block:: console

    ipa sysaccount-add my-app --random

 Allow the system account to change user passwords without triggering a reset:

 .. code-block:: console

    ipa sysaccount-mod my-app --privileged=True

The system account still needs to be permitted to modify user passwords through
a role that includes a corresponding permission ('System: Change User
password'), through the privilege system:

.. code-block:: console

    ipa privilege-add 'my-app password change privilege'
    ipa privilege-add-permission 'my-app password change privilege'                       --permission 'System: Change User password'
    ipa role-add 'my-app role'
    ipa role-add-privilege 'my-app role'                            --privilege 'my-app password change privilege'
    ipa role-add-member 'my-app role' --sysaccounts my-app

 Delete a system account:

 .. code-block:: console

    ipa sysaccount-del my-app

 Find all system accounts:

 .. code-block:: console

    ipa sysaccount-find

 Disable the system account:

 .. code-block:: console

    ipa sysaccount-disable my-app

 Re-enable the system account:

 .. code-block:: console

    ipa sysaccount-enable my-app

 Allow the system account to change user passwords without a reset:

 .. code-block:: console

    ipa sysaccount-policy my-app --privileged=true


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `sysaccount-add`_
     - Add a new IPA system account.
   * - `sysaccount-del`_
     - Delete an IPA system account.
   * - `sysaccount-disable`_
     - Disable a system account.
   * - `sysaccount-enable`_
     - Enable a system account.
   * - `sysaccount-find`_
     - Search for IPA system accounts.
   * - `sysaccount-mod`_
     - Modify an existing IPA system account.
   * - `sysaccount-policy`_
     - Manage the system account policy.
   * - `sysaccount-show`_
     - Display information about an IPA system account.

----

.. _sysaccount-add:

sysaccount-add
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sysaccount-add LOGIN [options]``

Add a new IPA system account.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOGIN``
     - yes
     - System account ID

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of system account
   * - ``--password PASSWORD``
     - Prompt to set the user password
   * - ``--random``
     - Generate a random user password
   * - ``--disabled DISABLED``
     - Account disabled
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--privileged PRIVILEGED``
     - Allow password updates without reset
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _sysaccount-del:

sysaccount-del
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sysaccount-del LOGIN [options]``

Delete an IPA system account.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOGIN``
     - yes
     - System account ID

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

.. _sysaccount-disable:

sysaccount-disable
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sysaccount-disable LOGIN [options]``

Disable a system account.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOGIN``
     - yes
     - System account ID

----

.. _sysaccount-enable:

sysaccount-enable
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sysaccount-enable LOGIN [options]``

Enable a system account.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOGIN``
     - yes
     - System account ID

----

.. _sysaccount-find:

sysaccount-find
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sysaccount-find [CRITERIA] [options]``

Search for IPA system accounts.

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
   * - ``--login LOGIN``
     - System account ID
   * - ``--desc DESC``
     - A description of system account
   * - ``--disabled DISABLED``
     - Account disabled
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("login")

----

.. _sysaccount-mod:

sysaccount-mod
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sysaccount-mod LOGIN [options]``

Modify an existing IPA system account.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOGIN``
     - yes
     - System account ID

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of system account
   * - ``--password PASSWORD``
     - Prompt to set the user password
   * - ``--random``
     - Generate a random user password
   * - ``--disabled DISABLED``
     - Account disabled
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--privileged PRIVILEGED``
     - Allow password updates without reset
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _sysaccount-policy:

sysaccount-policy
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sysaccount-policy LOGIN [options]``

Manage the system account policy.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOGIN``
     - yes
     - System account ID

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--privileged PRIVILEGED``
     - Allow password updates without reset
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _sysaccount-show:

sysaccount-show
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] sysaccount-show LOGIN [options]``

Display information about an IPA system account.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOGIN``
     - yes
     - System account ID

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

