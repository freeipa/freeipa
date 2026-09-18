Service Constrained Delegation
==============================

Manage rules to allow constrained delegation of credentials so
that a service can impersonate a user when communicating with another
service without requiring the user to actually forward their TGT.
This makes for a much better method of delegating credentials as it
prevents exposure of the short term secret of the user.

The naming convention is to append the word "target" or "targets" to
a matching rule name. This is not mandatory but helps conceptually
to associate rules and targets.

A rule consists of two things:

  - A list of targets the rule applies to
  - A list of memberPrincipals that are allowed to delegate for

.. code-block:: console

    those targets

A target consists of a list of principals that can be delegated.

In English, a rule says that this principal can delegate as this
list of principals, as defined by these targets.

In both a rule and a target Kerberos principals may be specified
by their name or an alias and the realm can be omitted. Additionally,
hosts can be specified by their names. If Kerberos principal specified
has a single component and does not end with '$' sign, it will be treated
as a host name. Kerberos principal names ending with '$' are typically
used as aliases for Active Directory-related services.


**EXAMPLES**

 Add a new constrained delegation rule:

 .. code-block:: console

    ipa servicedelegationrule-add ftp-delegation

 Add a new constrained delegation target:

 .. code-block:: console

    ipa servicedelegationtarget-add ftp-delegation-target

 Add a principal to the rule:

 .. code-block:: console

    ipa servicedelegationrule-add-member --principals=ftp/ipa.example.com       ftp-delegation

 Add a host principal of the host 'ipa.example.com' to the rule:

 .. code-block:: console

    ipa servicedelegationrule-add-member --principals=ipa.example.com       ftp-delegation

 Add our target to the rule:

 .. code-block:: console

    ipa servicedelegationrule-add-target       --servicedelegationtargets=ftp-delegation-target ftp-delegation

 Add a principal to the target:

 .. code-block:: console

    ipa servicedelegationtarget-add-member --principals=ldap/ipa.example.com       ftp-delegation-target

 Display information about a named delegation rule and target:

 .. code-block:: console

    ipa servicedelegationrule_show ftp-delegation
    ipa servicedelegationtarget_show ftp-delegation-target

 Remove a constrained delegation:

 .. code-block:: console

    ipa servicedelegationrule-del ftp-delegation-target
    ipa servicedelegationtarget-del ftp-delegation

In this example the ftp service can get a TGT for the ldap service on
the bound user's behalf.

It is strongly discouraged to modify the delegations that ship with
IPA, ipa-http-delegation and its targets ipa-cifs-delegation-targets and
ipa-ldap-delegation-targets. Incorrect changes can remove the ability
to delegate, causing the framework to stop functioning.

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `servicedelegationrule-add`_
     - Create a new service delegation rule.
   * - `servicedelegationrule-add-member`_
     - Add member to a named service delegation rule.
   * - `servicedelegationrule-add-target`_
     - Add target to a named service delegation rule.
   * - `servicedelegationrule-del`_
     - Delete service delegation.
   * - `servicedelegationrule-find`_
     - Search for service delegations rule.
   * - `servicedelegationrule-remove-member`_
     - Remove member from a named service delegation rule.
   * - `servicedelegationrule-remove-target`_
     - Remove target from a named service delegation rule.
   * - `servicedelegationrule-show`_
     - Display information about a named service delegation rule.
   * - `servicedelegationtarget-add`_
     - Create a new service delegation target.
   * - `servicedelegationtarget-add-member`_
     - Add member to a named service delegation target.
   * - `servicedelegationtarget-del`_
     - Delete service delegation target.
   * - `servicedelegationtarget-find`_
     - Search for service delegation target.
   * - `servicedelegationtarget-remove-member`_
     - Remove member from a named service delegation target.
   * - `servicedelegationtarget-show`_
     - Display information about a named service delegation target.

----

.. _servicedelegationrule-add:

servicedelegationrule-add
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationrule-add DELEGATION-NAME [options]``

Create a new service delegation rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
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

.. _servicedelegationrule-add-member:

servicedelegationrule-add-member
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationrule-add-member DELEGATION-NAME [options]``

Add member to a named service delegation rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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
   * - ``--principals PRINCIPALS``
     - principal to add

----

.. _servicedelegationrule-add-target:

servicedelegationrule-add-target
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationrule-add-target DELEGATION-NAME [options]``

Add target to a named service delegation rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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
   * - ``--servicedelegationtargets SERVICEDELEGATIONTARGETS``
     - service delegation targets to add

----

.. _servicedelegationrule-del:

servicedelegationrule-del
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationrule-del DELEGATION-NAME [options]``

Delete service delegation.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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

.. _servicedelegationrule-find:

servicedelegationrule-find
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationrule-find [CRITERIA] [options]``

Search for service delegations rule.

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
   * - ``--delegation-name DELEGATION-NAME``
     - Delegation name
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("delegation-name")

----

.. _servicedelegationrule-remove-member:

servicedelegationrule-remove-member
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationrule-remove-member DELEGATION-NAME [options]``

Remove member from a named service delegation rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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
   * - ``--principals PRINCIPALS``
     - principal to remove

----

.. _servicedelegationrule-remove-target:

servicedelegationrule-remove-target
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationrule-remove-target DELEGATION-NAME [options]``

Remove target from a named service delegation rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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
   * - ``--servicedelegationtargets SERVICEDELEGATIONTARGETS``
     - service delegation targets to remove

----

.. _servicedelegationrule-show:

servicedelegationrule-show
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationrule-show DELEGATION-NAME [options]``

Display information about a named service delegation rule.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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

----

.. _servicedelegationtarget-add:

servicedelegationtarget-add
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationtarget-add DELEGATION-NAME [options]``

Create a new service delegation target.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _servicedelegationtarget-add-member:

servicedelegationtarget-add-member
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationtarget-add-member DELEGATION-NAME [options]``

Add member to a named service delegation target.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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
   * - ``--principals PRINCIPALS``
     - principal to add

----

.. _servicedelegationtarget-del:

servicedelegationtarget-del
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationtarget-del DELEGATION-NAME [options]``

Delete service delegation target.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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

.. _servicedelegationtarget-find:

servicedelegationtarget-find
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationtarget-find [CRITERIA] [options]``

Search for service delegation target.

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
   * - ``--delegation-name DELEGATION-NAME``
     - Delegation name
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("delegation-name")

----

.. _servicedelegationtarget-remove-member:

servicedelegationtarget-remove-member
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationtarget-remove-member DELEGATION-NAME [options]``

Remove member from a named service delegation target.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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
   * - ``--principals PRINCIPALS``
     - principal to remove

----

.. _servicedelegationtarget-show:

servicedelegationtarget-show
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] servicedelegationtarget-show DELEGATION-NAME [options]``

Display information about a named service delegation target.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DELEGATION-NAME``
     - yes
     - Delegation name

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

