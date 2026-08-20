Permissions
===========

A permission enables fine-grained delegation of rights. A permission is
a human-readable wrapper around a 389-ds Access Control Rule,
or instruction (ACI).
A permission grants the right to perform a specific task such as adding a
user, modifying a group, etc.

A permission may not contain other permissions.

- A permission grants access to read, write, add, delete, read, search,
  or compare.
- A privilege combines similar permissions (for example all the permissions
  needed to add a user).
- A role grants a set of privileges to users, groups, hosts or hostgroups.

A permission is made up of a number of different parts:

1. The name of the permission.
2. The target of the permission.
3. The rights granted by the permission.

Rights define what operations are allowed, and may be one or more
of the following:

1. write - write one or more attributes
2. read - read one or more attributes
3. search - search on one or more attributes
4. compare - compare one or more attributes
5. add - add a new entry to the tree
6. delete - delete an existing entry
7. all - all permissions are granted

Note the distinction between attributes and entries. The permissions are
independent, so being able to add a user does not mean that the user will
be editable.

There are a number of allowed targets:

1. subtree: a DN; the permission applies to the subtree under this DN
2. target filter: an LDAP filter
3. target: DN with possible wildcards, specifies entries permission applies to

Additionally, there are the following convenience options.
Setting one of these options will set the corresponding attribute(s).

1. type: a type of object (user, group, etc); sets subtree and target filter.
2. memberof: apply to members of a group; sets target filter
3. targetgroup: grant access to modify a specific group (such as granting
   the rights to manage group membership); sets target.

Managed permissions

Permissions that come with IPA by default can be so-called "managed"
permissions. These have a default set of attributes they apply to,
but the administrator can add/remove individual attributes to/from the set.

Deleting or renaming a managed permission, as well as changing its target,
is not allowed.


**EXAMPLES**

 Add a permission that grants the creation of users:

 .. code-block:: console

    ipa permission-add --type=user --permissions=add "Add Users"

 Add a permission that grants the ability to manage group membership:

 .. code-block:: console

    ipa permission-add --attrs=member --permissions=write --type=group "Manage Group Members"


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `permission-add`_
     - Add a new permission.
   * - `permission-del`_
     - Delete a permission.
   * - `permission-find`_
     - Search for permissions.
   * - `permission-mod`_
     - Modify a permission.
   * - `permission-show`_
     - Display information about a permission.

----

.. _permission-add:

permission-add
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] permission-add NAME [options]``

Add a new permission.

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
     - Permission name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--right RIGHT``
     - Rights to grant (read, search, compare, write, add, delete, all)
   * - ``--attrs ATTRS``
     - All attributes to which the permission applies
   * - ``--bindtype BINDTYPE``
     - Bind rule type
   * - ``--subtree SUBTREE``
     - Subtree to apply permissions to
   * - ``--filter FILTER``
     - Extra target filter
   * - ``--rawfilter RAWFILTER``
     - All target filters, including those implied by type and memberof
   * - ``--target TARGET``
     - Optional DN to apply the permission to (must be in the subtree, but may not yet exist)
   * - ``--targetto TARGETTO``
     - Optional DN subtree where an entry can be moved to (must be in the subtree, but may not yet exist)
   * - ``--targetfrom TARGETFROM``
     - Optional DN subtree from where an entry can be moved (must be in the subtree, but may not yet exist)
   * - ``--memberof MEMBEROF``
     - Target members of a group (sets memberOf targetfilter)
   * - ``--targetgroup TARGETGROUP``
     - User group to apply permissions to (sets target)
   * - ``--type TYPE``
     - Type of IPA object (sets subtree and objectClass targetfilter)
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

.. _permission-del:

permission-del
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] permission-del NAME [options]``

Delete a permission.

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
     - Permission name

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

.. _permission-find:

permission-find
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] permission-find [CRITERIA] [options]``

Search for permissions.

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
     - Permission name
   * - ``--right RIGHT``
     - Rights to grant (read, search, compare, write, add, delete, all)
   * - ``--attrs ATTRS``
     - All attributes to which the permission applies
   * - ``--includedattrs INCLUDEDATTRS``
     - User-specified attributes to which the permission applies
   * - ``--excludedattrs EXCLUDEDATTRS``
     - User-specified attributes to which the permission explicitly does not apply
   * - ``--defaultattrs DEFAULTATTRS``
     - Attributes to which the permission applies by default
   * - ``--bindtype BINDTYPE``
     - Bind rule type
   * - ``--subtree SUBTREE``
     - Subtree to apply permissions to
   * - ``--filter FILTER``
     - Extra target filter
   * - ``--rawfilter RAWFILTER``
     - All target filters, including those implied by type and memberof
   * - ``--target TARGET``
     - Optional DN to apply the permission to (must be in the subtree, but may not yet exist)
   * - ``--targetto TARGETTO``
     - Optional DN subtree where an entry can be moved to (must be in the subtree, but may not yet exist)
   * - ``--targetfrom TARGETFROM``
     - Optional DN subtree from where an entry can be moved (must be in the subtree, but may not yet exist)
   * - ``--memberof MEMBEROF``
     - Target members of a group (sets memberOf targetfilter)
   * - ``--targetgroup TARGETGROUP``
     - User group to apply permissions to (sets target)
   * - ``--type TYPE``
     - Type of IPA object (sets subtree and objectClass targetfilter)
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

.. _permission-mod:

permission-mod
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] permission-mod NAME [options]``

Modify a permission.

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
     - Permission name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--right RIGHT``
     - Rights to grant (read, search, compare, write, add, delete, all)
   * - ``--attrs ATTRS``
     - All attributes to which the permission applies
   * - ``--includedattrs INCLUDEDATTRS``
     - User-specified attributes to which the permission applies
   * - ``--excludedattrs EXCLUDEDATTRS``
     - User-specified attributes to which the permission explicitly does not apply
   * - ``--bindtype BINDTYPE``
     - Bind rule type
   * - ``--subtree SUBTREE``
     - Subtree to apply permissions to
   * - ``--filter FILTER``
     - Extra target filter
   * - ``--rawfilter RAWFILTER``
     - All target filters, including those implied by type and memberof
   * - ``--target TARGET``
     - Optional DN to apply the permission to (must be in the subtree, but may not yet exist)
   * - ``--targetto TARGETTO``
     - Optional DN subtree where an entry can be moved to (must be in the subtree, but may not yet exist)
   * - ``--targetfrom TARGETFROM``
     - Optional DN subtree from where an entry can be moved (must be in the subtree, but may not yet exist)
   * - ``--memberof MEMBEROF``
     - Target members of a group (sets memberOf targetfilter)
   * - ``--targetgroup TARGETGROUP``
     - User group to apply permissions to (sets target)
   * - ``--type TYPE``
     - Type of IPA object (sets subtree and objectClass targetfilter)
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
     - Rename the permission object

----

.. _permission-show:

permission-show
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] permission-show NAME [options]``

Display information about a permission.

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
     - Permission name

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

