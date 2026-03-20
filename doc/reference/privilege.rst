Privileges
==========

A privilege combines permissions into a logical task. A permission provides
the rights to do a single task. There are some IPA operations that require
multiple permissions to succeed. A privilege is where permissions are
combined in order to perform a specific task.

For example, adding a user requires the following permissions:

 - Creating a new user entry
 - Resetting a user password
 - Adding the new user to the default IPA users group

Combining these three low-level tasks into a higher level task in the
form of a privilege named "Add User" makes it easier to manage Roles.

A privilege may not contain other privileges.

See role and permission for additional information.

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `privilege-add`_
     - Add a new privilege.
   * - `privilege-add-permission`_
     - Add permissions to a privilege.
   * - `privilege-del`_
     - Delete a privilege.
   * - `privilege-find`_
     - Search for privileges.
   * - `privilege-mod`_
     - Modify a privilege.
   * - `privilege-remove-permission`_
     - Remove permissions from a privilege.
   * - `privilege-show`_
     - Display information about a privilege.

----

.. _privilege-add:

privilege-add
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] privilege-add NAME [options]``

Add a new privilege.

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
     - Privilege name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Privilege description
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

.. _privilege-add-permission:

privilege-add-permission
~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] privilege-add-permission NAME [options]``

Add permissions to a privilege.

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
     - Privilege name

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
   * - ``--permissions PERMISSIONS``
     - permissions

----

.. _privilege-del:

privilege-del
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] privilege-del NAME [options]``

Delete a privilege.

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
     - Privilege name

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

.. _privilege-find:

privilege-find
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] privilege-find [CRITERIA] [options]``

Search for privileges.

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
     - Privilege name
   * - ``--desc DESC``
     - Privilege description
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

.. _privilege-mod:

privilege-mod
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] privilege-mod NAME [options]``

Modify a privilege.

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
     - Privilege name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Privilege description
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
     - Rename the privilege object

----

.. _privilege-remove-permission:

privilege-remove-permission
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] privilege-remove-permission NAME [options]``

Remove permissions from a privilege.

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
     - Privilege name

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
   * - ``--permissions PERMISSIONS``
     - permissions

----

.. _privilege-show:

privilege-show
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] privilege-show NAME [options]``

Display information about a privilege.

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
     - Privilege name

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

