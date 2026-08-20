Auto Membership Rule.
=====================

Bring clarity to the membership of hosts and users by configuring inclusive
or exclusive regex patterns, you can automatically assign a new entries into
a group or hostgroup based upon attribute information.

A rule is directly associated with a group by name, so you cannot create
a rule without an accompanying group or hostgroup.

A condition is a regular expression used by 389-ds to match a new incoming
entry with an automember rule. If it matches an inclusive rule then the
entry is added to the appropriate group or hostgroup.

A default group or hostgroup could be specified for entries that do not
match any rule. In case of user entries this group will be a fallback group
because all users are by default members of group specified in IPA config.

The ``automember-rebuild`` command can be used to retroactively run automember rules
against existing entries, thus rebuilding their membership.


**EXAMPLES**

 Add the initial group or hostgroup:

 .. code-block:: console

    ipa hostgroup-add --desc="Web Servers" webservers
    ipa group-add --desc="Developers" devel

 Add the initial rule:

 .. code-block:: console

    ipa automember-add --type=hostgroup webservers
    ipa automember-add --type=group devel

 Add a condition to the rule:

 .. code-block:: console

    ipa automember-add-condition --key=fqdn --type=hostgroup --inclusive-regex=^web[1-9]+\.example\.com webservers
    ipa automember-add-condition --key=manager --type=group --inclusive-regex=^uid=mscott devel

 Add an exclusive condition to the rule to prevent auto assignment:

 .. code-block:: console

    ipa automember-add-condition --key=fqdn --type=hostgroup --exclusive-regex=^web5\.example\.com webservers

 Add a host:

 .. code-block:: console

     ipa host-add web1.example.com

 Add a user:

 .. code-block:: console

     ipa user-add --first=Tim --last=User --password tuser1 --manager=mscott

 Verify automembership:

 .. code-block:: console

     ipa hostgroup-show webservers
       Host-group: webservers
       Description: Web Servers
       Member hosts: web1.example.com

     ipa group-show devel
       Group name: devel
       Description: Developers
       GID: 1004200000
       Member users: tuser

 Remove a condition from the rule:

 .. code-block:: console

    ipa automember-remove-condition --key=fqdn --type=hostgroup --inclusive-regex=^web[1-9]+\.example\.com webservers

 Modify the automember rule:

 .. code-block:: console

     ipa automember-mod

 Set the default (fallback) target group:

 .. code-block:: console

     ipa automember-default-group-set --default-group=webservers --type=hostgroup
     ipa automember-default-group-set --default-group=ipausers --type=group

 Remove the default (fallback) target group:

 .. code-block:: console

     ipa automember-default-group-remove --type=hostgroup
     ipa automember-default-group-remove --type=group

 Show the default (fallback) target group:

 .. code-block:: console

     ipa automember-default-group-show --type=hostgroup
     ipa automember-default-group-show --type=group

 Find all of the automember rules:

 .. code-block:: console

     ipa automember-find

 Find all of the orphan automember rules:

 .. code-block:: console

     ipa automember-find-orphans --type=hostgroup

 Find all of the orphan automember rules and remove them:

 .. code-block:: console

     ipa automember-find-orphans --type=hostgroup --remove

 Display a automember rule:

 .. code-block:: console

     ipa automember-show --type=hostgroup webservers
     ipa automember-show --type=group devel

 Delete an automember rule:

 .. code-block:: console

     ipa automember-del --type=hostgroup webservers
     ipa automember-del --type=group devel

 Rebuild membership for all users:

 .. code-block:: console

     ipa automember-rebuild --type=group

 Rebuild membership for all hosts:

 .. code-block:: console

     ipa automember-rebuild --type=hostgroup

 Rebuild membership for specified users:

 .. code-block:: console

     ipa automember-rebuild --users=tuser1 --users=tuser2

 Rebuild membership for specified hosts:

 .. code-block:: console

     ipa automember-rebuild --hosts=web1.example.com --hosts=web2.example.com


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `automember-add`_
     - Add an automember rule.
   * - `automember-add-condition`_
     - Add conditions to an automember rule.
   * - `automember-default-group-remove`_
     - Remove default (fallback) group for all unmatched entries.
   * - `automember-default-group-set`_
     - Set default (fallback) group for all unmatched entries.
   * - `automember-default-group-show`_
     - Display information about the default (fallback) automember groups.
   * - `automember-del`_
     - Delete an automember rule.
   * - `automember-find`_
     - Search for automember rules.
   * - `automember-find-orphans`_
     - Search for orphan automember rules. The command might need to be run as
   * - `automember-mod`_
     - Modify an automember rule.
   * - `automember-rebuild`_
     - Rebuild auto membership.
   * - `automember-remove-condition`_
     - Remove conditions from an automember rule.
   * - `automember-show`_
     - Display information about an automember rule.

----

.. _automember-add:

automember-add
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-add AUTOMEMBER-RULE [options]``

Add an automember rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMEMBER-RULE``
     - yes
     - Automember Rule

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this auto member rule
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automember-add-condition:

automember-add-condition
~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-add-condition AUTOMEMBER-RULE [options]``

Add conditions to an automember rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMEMBER-RULE``
     - yes
     - Automember Rule

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this auto member rule
   * - ``--inclusive-regex INCLUSIVE-REGEX``
     - Inclusive Regex
   * - ``--exclusive-regex EXCLUSIVE-REGEX``
     - Exclusive Regex
   * - ``--key KEY``
     - Attribute to filter via regex. For example fqdn for a host, or manager for a user
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automember-default-group-remove:

automember-default-group-remove
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-default-group-remove [options]``

Remove default (fallback) group for all unmatched entries.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automember-default-group-set:

automember-default-group-set
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-default-group-set [options]``

Set default (fallback) group for all unmatched entries.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--default-group DEFAULT-GROUP``
     - Default (fallback) group for entries to land
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automember-default-group-show:

automember-default-group-show
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-default-group-show [options]``

Display information about the default (fallback) automember groups.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automember-del:

automember-del
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-del AUTOMEMBER-RULE [options]``

Delete an automember rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMEMBER-RULE``
     - yes
     - Automember Rule

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--type TYPE``
     - Grouping to which the rule applies

----

.. _automember-find:

automember-find
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-find [CRITERIA] [options]``

Search for automember rules.

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
   * - ``--desc DESC``
     - A description of this auto member rule
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("automember-rule")

----

.. _automember-find-orphans:

automember-find-orphans
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-find-orphans [CRITERIA] [options]``

Search for orphan automember rules. The command might need to be run as

.. code-block:: console

    a privileged user user to get all orphan rules.


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
   * - ``--desc DESC``
     - A description of this auto member rule
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--remove``
     - Remove orphan automember rules
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("automember-rule")

----

.. _automember-mod:

automember-mod
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-mod AUTOMEMBER-RULE [options]``

Modify an automember rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMEMBER-RULE``
     - yes
     - Automember Rule

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this auto member rule
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automember-rebuild:

automember-rebuild
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-rebuild [options]``

Rebuild auto membership.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--users USERS``
     - Rebuild membership for specified users
   * - ``--hosts HOSTS``
     - Rebuild membership for specified hosts
   * - ``--no-wait``
     - Don't wait for rebuilding membership
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automember-remove-condition:

automember-remove-condition
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-remove-condition AUTOMEMBER-RULE [options]``

Remove conditions from an automember rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMEMBER-RULE``
     - yes
     - Automember Rule

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this auto member rule
   * - ``--inclusive-regex INCLUSIVE-REGEX``
     - Inclusive Regex
   * - ``--exclusive-regex EXCLUSIVE-REGEX``
     - Exclusive Regex
   * - ``--key KEY``
     - Attribute to filter via regex. For example fqdn for a host, or manager for a user
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automember-show:

automember-show
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automember-show AUTOMEMBER-RULE [options]``

Display information about an automember rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMEMBER-RULE``
     - yes
     - Automember Rule

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--type TYPE``
     - Grouping to which the rule applies
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

