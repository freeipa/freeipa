Netgroups
=========

A netgroup is a group used for permission checking. It can contain both
user and host values.


**EXAMPLES**

 Add a new netgroup:

 .. code-block:: console

    ipa netgroup-add --desc="NFS admins" admins

 Add members to the netgroup:

 .. code-block:: console

    ipa netgroup-add-member --users=tuser1 --users=tuser2 admins

 Remove a member from the netgroup:

 .. code-block:: console

    ipa netgroup-remove-member --users=tuser2 admins

 Display information about a netgroup:

 .. code-block:: console

    ipa netgroup-show admins

 Delete a netgroup:

 .. code-block:: console

    ipa netgroup-del admins


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `netgroup-add`_
     - Add a new netgroup.
   * - `netgroup-add-member`_
     - Add members to a netgroup.
   * - `netgroup-del`_
     - Delete a netgroup.
   * - `netgroup-find`_
     - Search for a netgroup.
   * - `netgroup-mod`_
     - Modify a netgroup.
   * - `netgroup-remove-member`_
     - Remove members from a netgroup.
   * - `netgroup-show`_
     - Display information about a netgroup.

----

.. _netgroup-add:

netgroup-add
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] netgroup-add NAME [options]``

Add a new netgroup.

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
     - Netgroup name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Netgroup description
   * - ``--nisdomain NISDOMAIN``
     - NIS domain name
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
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

.. _netgroup-add-member:

netgroup-add-member
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] netgroup-add-member NAME [options]``

Add members to a netgroup.

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
     - Netgroup name

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
   * - ``--netgroups NETGROUPS``
     - netgroups to add

----

.. _netgroup-del:

netgroup-del
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] netgroup-del NAME [options]``

Delete a netgroup.

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
     - Netgroup name

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

.. _netgroup-find:

netgroup-find
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] netgroup-find [CRITERIA] [options]``

Search for a netgroup.

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
     - Netgroup name
   * - ``--desc DESC``
     - Netgroup description
   * - ``--nisdomain NISDOMAIN``
     - NIS domain name
   * - ``--uuid UUID``
     - IPA unique ID
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--managed``
     - search for managed groups
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")
   * - ``--netgroups NETGROUPS``
     - Search for netgroups with these member netgroups.
   * - ``--no-netgroups NO-NETGROUPS``
     - Search for netgroups without these member netgroups.
   * - ``--users USERS``
     - Search for netgroups with these member users.
   * - ``--no-users NO-USERS``
     - Search for netgroups without these member users.
   * - ``--groups GROUPS``
     - Search for netgroups with these member groups.
   * - ``--no-groups NO-GROUPS``
     - Search for netgroups without these member groups.
   * - ``--hosts HOSTS``
     - Search for netgroups with these member hosts.
   * - ``--no-hosts NO-HOSTS``
     - Search for netgroups without these member hosts.
   * - ``--hostgroups HOSTGROUPS``
     - Search for netgroups with these member host groups.
   * - ``--no-hostgroups NO-HOSTGROUPS``
     - Search for netgroups without these member host groups.
   * - ``--in-netgroups IN-NETGROUPS``
     - Search for netgroups with these member of netgroups.
   * - ``--not-in-netgroups NOT-IN-NETGROUPS``
     - Search for netgroups without these member of netgroups.

----

.. _netgroup-mod:

netgroup-mod
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] netgroup-mod NAME [options]``

Modify a netgroup.

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
     - Netgroup name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Netgroup description
   * - ``--nisdomain NISDOMAIN``
     - NIS domain name
   * - ``--usercat USERCAT``
     - User category the rule applies to
   * - ``--hostcat HOSTCAT``
     - Host category the rule applies to
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

.. _netgroup-remove-member:

netgroup-remove-member
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] netgroup-remove-member NAME [options]``

Remove members from a netgroup.

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
     - Netgroup name

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
   * - ``--netgroups NETGROUPS``
     - netgroups to remove

----

.. _netgroup-show:

netgroup-show
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] netgroup-show NAME [options]``

Display information about a netgroup.

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
     - Netgroup name

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

