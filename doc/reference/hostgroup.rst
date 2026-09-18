Groups of hosts.
================

Manage groups of hosts. This is useful for applying access control to a
number of hosts by using Host-based Access Control.


**EXAMPLES**

 Add a new host group:

 .. code-block:: console

    ipa hostgroup-add --desc="Baltimore hosts" baltimore

 Add another new host group:

 .. code-block:: console

    ipa hostgroup-add --desc="Maryland hosts" maryland

 Add members to the hostgroup (using Bash brace expansion):

 .. code-block:: console

    ipa hostgroup-add-member --hosts={box1,box2,box3} baltimore

 Add a hostgroup as a member of another hostgroup:

 .. code-block:: console

    ipa hostgroup-add-member --hostgroups=baltimore maryland

 Remove a host from the hostgroup:

 .. code-block:: console

    ipa hostgroup-remove-member --hosts=box2 baltimore

 Display a host group:

 .. code-block:: console

    ipa hostgroup-show baltimore

 Add a member manager:

 .. code-block:: console

    ipa hostgroup-add-member-manager --users=user1 baltimore

 Remove a member manager

 .. code-block:: console

    ipa hostgroup-remove-member-manager --users=user1 baltimore

 Delete a hostgroup:

 .. code-block:: console

    ipa hostgroup-del baltimore


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `hostgroup-add`_
     - Add a new hostgroup.
   * - `hostgroup-add-member`_
     - Add members to a hostgroup.
   * - `hostgroup-add-member-manager`_
     - Add users that can manage members of this hostgroup.
   * - `hostgroup-del`_
     - Delete a hostgroup.
   * - `hostgroup-find`_
     - Search for hostgroups.
   * - `hostgroup-mod`_
     - Modify a hostgroup.
   * - `hostgroup-remove-member`_
     - Remove members from a hostgroup.
   * - `hostgroup-remove-member-manager`_
     - Remove users that can manage members of this hostgroup.
   * - `hostgroup-show`_
     - Display information about a hostgroup.

----

.. _hostgroup-add:

hostgroup-add
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-add HOSTGROUP-NAME [options]``

Add a new hostgroup.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTGROUP-NAME``
     - yes
     - Name of host-group

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this host-group
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

.. _hostgroup-add-member:

hostgroup-add-member
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-add-member HOSTGROUP-NAME [options]``

Add members to a hostgroup.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTGROUP-NAME``
     - yes
     - Name of host-group

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

.. _hostgroup-add-member-manager:

hostgroup-add-member-manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-add-member-manager HOSTGROUP-NAME [options]``

Add users that can manage members of this hostgroup.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTGROUP-NAME``
     - yes
     - Name of host-group

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

.. _hostgroup-del:

hostgroup-del
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-del HOSTGROUP-NAME [options]``

Delete a hostgroup.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTGROUP-NAME``
     - yes
     - Name of host-group

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

.. _hostgroup-find:

hostgroup-find
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-find [CRITERIA] [options]``

Search for hostgroups.

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
   * - ``--hostgroup-name HOSTGROUP-NAME``
     - Name of host-group
   * - ``--desc DESC``
     - A description of this host-group
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("hostgroup-name")
   * - ``--hosts HOSTS``
     - Search for host groups with these member hosts.
   * - ``--no-hosts NO-HOSTS``
     - Search for host groups without these member hosts.
   * - ``--hostgroups HOSTGROUPS``
     - Search for host groups with these member host groups.
   * - ``--no-hostgroups NO-HOSTGROUPS``
     - Search for host groups without these member host groups.
   * - ``--in-hostgroups IN-HOSTGROUPS``
     - Search for host groups with these member of host groups.
   * - ``--not-in-hostgroups NOT-IN-HOSTGROUPS``
     - Search for host groups without these member of host groups.
   * - ``--in-netgroups IN-NETGROUPS``
     - Search for host groups with these member of netgroups.
   * - ``--not-in-netgroups NOT-IN-NETGROUPS``
     - Search for host groups without these member of netgroups.
   * - ``--in-hbacrules IN-HBACRULES``
     - Search for host groups with these member of HBAC rules.
   * - ``--not-in-hbacrules NOT-IN-HBACRULES``
     - Search for host groups without these member of HBAC rules.
   * - ``--in-sudorules IN-SUDORULES``
     - Search for host groups with these member of sudo rules.
   * - ``--not-in-sudorules NOT-IN-SUDORULES``
     - Search for host groups without these member of sudo rules.
   * - ``--membermanager-users MEMBERMANAGER-USERS``
     - Search for host groups with these group membership managed by users.
   * - ``--not-membermanager-users NOT-MEMBERMANAGER-USERS``
     - Search for host groups without these group membership managed by users.
   * - ``--membermanager-groups MEMBERMANAGER-GROUPS``
     - Search for host groups with these group membership managed by groups.
   * - ``--not-membermanager-groups NOT-MEMBERMANAGER-GROUPS``
     - Search for host groups without these group membership managed by groups.

----

.. _hostgroup-mod:

hostgroup-mod
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-mod HOSTGROUP-NAME [options]``

Modify a hostgroup.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTGROUP-NAME``
     - yes
     - Name of host-group

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this host-group
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
     - Rename the host group object

----

.. _hostgroup-remove-member:

hostgroup-remove-member
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-remove-member HOSTGROUP-NAME [options]``

Remove members from a hostgroup.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTGROUP-NAME``
     - yes
     - Name of host-group

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

.. _hostgroup-remove-member-manager:

hostgroup-remove-member-manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-remove-member-manager HOSTGROUP-NAME [options]``

Remove users that can manage members of this hostgroup.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTGROUP-NAME``
     - yes
     - Name of host-group

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

.. _hostgroup-show:

hostgroup-show
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] hostgroup-show HOSTGROUP-NAME [options]``

Display information about a hostgroup.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTGROUP-NAME``
     - yes
     - Name of host-group

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

