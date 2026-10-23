Groups of users
===============

Manage groups of users, groups, or services. By default, new groups are POSIX
groups. You can add the --nonposix option to the ``group-add`` command to mark a
new group as non-POSIX. You can use the --posix argument with the ``group-mod``
command to convert a non-POSIX group into a POSIX group. POSIX groups cannot be
converted to non-POSIX groups.

Every group must have a description.

The group name must follow these rules:

- cannot contain only numbers
- must start with a letter, a number, _ or .
- may contain letters, numbers, _, ., or -
- may end with a letter, a number, _, ., - or $

POSIX groups must have a Group ID (GID) number. Changing a GID is
supported but can have an impact on your file permissions. It is not necessary
to supply a GID when creating a group. IPA will generate one automatically
if it is not provided.

Groups members can be users, other groups, and Kerberos services. In POSIX
environments only users will be visible as group members, but nested groups and
groups of services can be used for IPA management purposes.


**EXAMPLES**

 Add a new group:

 .. code-block:: console

    ipa group-add --desc='local administrators' localadmins

 Add a new non-POSIX group:

 .. code-block:: console

    ipa group-add --nonposix --desc='remote administrators' remoteadmins

 Convert a non-POSIX group to posix:

 .. code-block:: console

    ipa group-mod --posix remoteadmins

 Add a new POSIX group with a specific Group ID number:

 .. code-block:: console

    ipa group-add --gid=500 --desc='unix admins' unixadmins

 Add a new POSIX group and let IPA assign a Group ID number:

 .. code-block:: console

    ipa group-add --desc='printer admins' printeradmins

 Remove a group:

 .. code-block:: console

    ipa group-del unixadmins

 To add the "remoteadmins" group to the "localadmins" group:

 .. code-block:: console

    ipa group-add-member --groups=remoteadmins localadmins

 Add multiple users to the "localadmins" group:

 .. code-block:: console

    ipa group-add-member --users=test1 --users=test2 localadmins

 To add Kerberos services to the "printer admins" group:

 .. code-block:: console

    ipa group-add-member --services=CUPS/some.host printeradmins

 Remove a user from the "localadmins" group:

 .. code-block:: console

    ipa group-remove-member --users=test2 localadmins

 Display information about a named group.

 .. code-block:: console

    ipa group-show localadmins

Group membership managers are users or groups that can add members to a
group or remove members from a group.

 Allow user "test2" to add or remove members from group "localadmins":

 .. code-block:: console

    ipa group-add-member-manager --users=test2 localadmins

 Revoke membership management rights for user "test2" from "localadmins":

 .. code-block:: console

    ipa group-remove-member-manager --users=test2 localadmins

External group membership is designed to allow users from trusted domains
to be mapped to local POSIX groups in order to actually use IPA resources.
External members should be added to groups that specifically created as
external and non-POSIX. Such group later should be included into one of POSIX
groups.

An external group member is currently a Security Identifier (SID) as defined by
the trusted domain. When adding external group members, it is possible to
specify them in either SID, or DOM\name, or name@domain format. IPA will attempt
to resolve passed name to SID with the use of Global Catalog of the trusted domain.


**Example**

1. Create group for the trusted domain admins' mapping and their local POSIX group:


.. code-block:: console

   ipa group-add --desc='<ad.domain> admins external map' ad_admins_external --external
   ipa group-add --desc='<ad.domain> admins' ad_admins

2. Add security identifier of Domain Admins of the <ad.domain> to the ad_admins_external
   group:


.. code-block:: console

   ipa group-add-member ad_admins_external --external 'AD\Domain Admins'

3. Allow members of ad_admins_external group to be associated with ad_admins POSIX group:


.. code-block:: console

   ipa group-add-member ad_admins --groups ad_admins_external

4. List members of external members of ad_admins_external group to see their SIDs:


.. code-block:: console

   ipa group-show ad_admins_external


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `group-add`_
     - Create a new group.
   * - `group-add-member`_
     - Add members to a group.
   * - `group-add-member-manager`_
     - Add users that can manage members of this group.
   * - `group-del`_
     - Delete group.
   * - `group-detach`_
     - Detach a managed group from a user.
   * - `group-find`_
     - Search for groups.
   * - `group-mod`_
     - Modify a group.
   * - `group-remove-member`_
     - Remove members from a group.
   * - `group-remove-member-manager`_
     - Remove users that can manage members of this group.
   * - `group-show`_
     - Display information about a named group.

----

.. _group-add:

group-add
~~~~~~~~~

**Usage:** ``ipa [global-options] group-add GROUP-NAME [options]``

Create a new group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Group description
   * - ``--gid GID``
     - GID (use this option to set it manually)
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--nonposix``
     - Create as a non-POSIX group
   * - ``--external``
     - Allow adding external non-IPA members from trusted domains
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _group-add-member:

group-add-member
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] group-add-member GROUP-NAME [options]``

Add members to a group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--external EXTERNAL``
     - Members of a trusted domain in DOM\\name or name@domain form
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
   * - ``--services SERVICES``
     - services to add
   * - ``--idoverrideusers IDOVERRIDEUSERS``
     - User ID overrides to add

----

.. _group-add-member-manager:

group-add-member-manager
~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] group-add-member-manager GROUP-NAME [options]``

Add users that can manage members of this group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

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

.. _group-del:

group-del
~~~~~~~~~

**Usage:** ``ipa [global-options] group-del GROUP-NAME [options]``

Delete group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

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

.. _group-detach:

group-detach
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] group-detach GROUP-NAME [options]``

Detach a managed group from a user.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

----

.. _group-find:

group-find
~~~~~~~~~~

**Usage:** ``ipa [global-options] group-find [CRITERIA] [options]``

Search for groups.

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
   * - ``--group-name GROUP-NAME``
     - Group name
   * - ``--desc DESC``
     - Group description
   * - ``--gid GID``
     - GID (use this option to set it manually)
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--private``
     - search for private groups
   * - ``--posix``
     - search for POSIX groups
   * - ``--external``
     - search for groups with support of external non-IPA members from trusted domains
   * - ``--nonposix``
     - search for non-POSIX groups
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("group-name")
   * - ``--users USERS``
     - Search for groups with these member users.
   * - ``--no-users NO-USERS``
     - Search for groups without these member users.
   * - ``--groups GROUPS``
     - Search for groups with these member groups.
   * - ``--no-groups NO-GROUPS``
     - Search for groups without these member groups.
   * - ``--services SERVICES``
     - Search for groups with these member services.
   * - ``--no-services NO-SERVICES``
     - Search for groups without these member services.
   * - ``--idoverrideusers IDOVERRIDEUSERS``
     - Search for groups with these member User ID overrides.
   * - ``--no-idoverrideusers NO-IDOVERRIDEUSERS``
     - Search for groups without these member User ID overrides.
   * - ``--in-groups IN-GROUPS``
     - Search for groups with these member of groups.
   * - ``--not-in-groups NOT-IN-GROUPS``
     - Search for groups without these member of groups.
   * - ``--in-netgroups IN-NETGROUPS``
     - Search for groups with these member of netgroups.
   * - ``--not-in-netgroups NOT-IN-NETGROUPS``
     - Search for groups without these member of netgroups.
   * - ``--in-roles IN-ROLES``
     - Search for groups with these member of roles.
   * - ``--not-in-roles NOT-IN-ROLES``
     - Search for groups without these member of roles.
   * - ``--in-hbacrules IN-HBACRULES``
     - Search for groups with these member of HBAC rules.
   * - ``--not-in-hbacrules NOT-IN-HBACRULES``
     - Search for groups without these member of HBAC rules.
   * - ``--in-sudorules IN-SUDORULES``
     - Search for groups with these member of sudo rules.
   * - ``--not-in-sudorules NOT-IN-SUDORULES``
     - Search for groups without these member of sudo rules.
   * - ``--membermanager-users MEMBERMANAGER-USERS``
     - Search for groups with these group membership managed by users.
   * - ``--not-membermanager-users NOT-MEMBERMANAGER-USERS``
     - Search for groups without these group membership managed by users.
   * - ``--membermanager-groups MEMBERMANAGER-GROUPS``
     - Search for groups with these group membership managed by groups.
   * - ``--not-membermanager-groups NOT-MEMBERMANAGER-GROUPS``
     - Search for groups without these group membership managed by groups.

----

.. _group-mod:

group-mod
~~~~~~~~~

**Usage:** ``ipa [global-options] group-mod GROUP-NAME [options]``

Modify a group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Group description
   * - ``--gid GID``
     - GID (use this option to set it manually)
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--posix``
     - change to a POSIX group
   * - ``--external``
     - change to support external non-IPA members from trusted domains
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--rename RENAME``
     - Rename the group object

----

.. _group-remove-member:

group-remove-member
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] group-remove-member GROUP-NAME [options]``

Remove members from a group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--external EXTERNAL``
     - Members of a trusted domain in DOM\\name or name@domain form
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
   * - ``--services SERVICES``
     - services to remove
   * - ``--idoverrideusers IDOVERRIDEUSERS``
     - User ID overrides to remove

----

.. _group-remove-member-manager:

group-remove-member-manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] group-remove-member-manager GROUP-NAME [options]``

Remove users that can manage members of this group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

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

.. _group-show:

group-show
~~~~~~~~~~

**Usage:** ``ipa [global-options] group-show GROUP-NAME [options]``

Display information about a named group.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP-NAME``
     - yes
     - Group name

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

