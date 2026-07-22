Password policy
===============

A password policy sets limitations on IPA passwords, including maximum
lifetime, minimum lifetime, the number of passwords to save in
history, the number of character classes required (for stronger passwords)
and the minimum password length.

By default there is a single, global policy for all users. You can also
create a password policy to apply to a group. Each user is only subject
to one password policy, either the group policy or the global policy. A
group policy stands alone; it is not a super-set of the global policy plus
custom settings.

Each group password policy requires a unique priority setting. If a user
is in multiple groups that have password policies, this priority determines
which password policy is applied. A lower value indicates a higher priority
policy.

Group password policies are automatically removed when the groups they
are associated with are removed.

Grace period defines the number of LDAP logins allowed after expiration.
-1 means do not enforce expiration to match previous behavior. 0 allows
no additional logins after expiration.

The pwquality options are either mutually exclusive, or take
precedence, over the standard password policy values. In the case
of minimum password length if any pwquality-based options are used then
the minimum length must be >= 6.

The "credit" settings are used to adjust password complexity requirements.

- With a value of 0, the default, the option is ignored.
- With a positive value each character of that type in the password
  contributes towards meeting the mininum length requirement.

  .. code-block:: console

     For example, with a password policy of `minlength=6`, `dcredit=1`,
     these passwords are valid: abcdef or abcd1

- With a negative value signifies a minimum number of that character type
  that must be present.


**EXAMPLES**

 Modify the global policy:

 .. code-block:: console

    ipa pwpolicy-mod --minlength=10

 Add a new group password policy:

 .. code-block:: console

    ipa pwpolicy-add --maxlife=90 --minlife=1 --history=10 --minclasses=3 --minlength=8 --priority=10 localadmins

 Display the global password policy:

 .. code-block:: console

    ipa pwpolicy-show

 Display a group password policy:

 .. code-block:: console

    ipa pwpolicy-show localadmins

 Display the policy that would be applied to a given user:

 .. code-block:: console

    ipa pwpolicy-show --user=tuser1

 Modify a group password policy:

 .. code-block:: console

    ipa pwpolicy-mod --minclasses=2 localadmins


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `pwpolicy-add`_
     - Add a new group password policy.
   * - `pwpolicy-del`_
     - Delete a group password policy.
   * - `pwpolicy-find`_
     - Search for group password policies.
   * - `pwpolicy-mod`_
     - Modify a group password policy.
   * - `pwpolicy-show`_
     - Display information about password policy.

----

.. _pwpolicy-add:

pwpolicy-add
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] pwpolicy-add GROUP [options]``

Add a new group password policy.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP``
     - yes
     - Manage password policy for specific group

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--maxlife MAXLIFE``
     - Maximum password lifetime (in days)
   * - ``--minlife MINLIFE``
     - Minimum password lifetime (in hours)
   * - ``--history HISTORY``
     - Password history size
   * - ``--minclasses MINCLASSES``
     - Minimum number of character classes
   * - ``--minlength MINLENGTH``
     - Minimum length of password
   * - ``--priority PRIORITY``
     - Priority of the policy (higher number means lower priority
   * - ``--maxfail MAXFAIL``
     - Consecutive failures before lockout
   * - ``--failinterval FAILINTERVAL``
     - Period after which failure count will be reset (seconds)
   * - ``--lockouttime LOCKOUTTIME``
     - Period for which lockout is enforced (seconds)
   * - ``--maxrepeat MAXREPEAT``
     - Maximum number of same consecutive characters
   * - ``--maxsequence MAXSEQUENCE``
     - The max. length of monotonic character sequences (abcd)
   * - ``--dictcheck DICTCHECK``
     - Check if the password is a dictionary word
   * - ``--usercheck USERCHECK``
     - Check if the password contains the username
   * - ``--dcredit DCREDIT``
     - The max credit for digits in the password.
   * - ``--ucredit UCREDIT``
     - The max credit for uppercase characters in the password.
   * - ``--lcredit LCREDIT``
     - The max credit for lowercase characters in the password.
   * - ``--ocredit OCREDIT``
     - The max credit for other characters in the password.
   * - ``--gracelimit GRACELIMIT``
     - Number of LDAP authentications allowed after expiration
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _pwpolicy-del:

pwpolicy-del
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] pwpolicy-del GROUP [options]``

Delete a group password policy.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP``
     - yes
     - Manage password policy for specific group

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

.. _pwpolicy-find:

pwpolicy-find
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] pwpolicy-find [CRITERIA] [options]``

Search for group password policies.

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
   * - ``--group GROUP``
     - Manage password policy for specific group
   * - ``--maxlife MAXLIFE``
     - Maximum password lifetime (in days)
   * - ``--minlife MINLIFE``
     - Minimum password lifetime (in hours)
   * - ``--history HISTORY``
     - Password history size
   * - ``--minclasses MINCLASSES``
     - Minimum number of character classes
   * - ``--minlength MINLENGTH``
     - Minimum length of password
   * - ``--priority PRIORITY``
     - Priority of the policy (higher number means lower priority
   * - ``--maxfail MAXFAIL``
     - Consecutive failures before lockout
   * - ``--failinterval FAILINTERVAL``
     - Period after which failure count will be reset (seconds)
   * - ``--lockouttime LOCKOUTTIME``
     - Period for which lockout is enforced (seconds)
   * - ``--maxrepeat MAXREPEAT``
     - Maximum number of same consecutive characters
   * - ``--maxsequence MAXSEQUENCE``
     - The max. length of monotonic character sequences (abcd)
   * - ``--dictcheck DICTCHECK``
     - Check if the password is a dictionary word
   * - ``--usercheck USERCHECK``
     - Check if the password contains the username
   * - ``--dcredit DCREDIT``
     - The max credit for digits in the password.
   * - ``--ucredit UCREDIT``
     - The max credit for uppercase characters in the password.
   * - ``--lcredit LCREDIT``
     - The max credit for lowercase characters in the password.
   * - ``--ocredit OCREDIT``
     - The max credit for other characters in the password.
   * - ``--gracelimit GRACELIMIT``
     - Number of LDAP authentications allowed after expiration
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("group")

----

.. _pwpolicy-mod:

pwpolicy-mod
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] pwpolicy-mod [GROUP] [options]``

Modify a group password policy.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP``
     - no
     - Manage password policy for specific group

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--maxlife MAXLIFE``
     - Maximum password lifetime (in days)
   * - ``--minlife MINLIFE``
     - Minimum password lifetime (in hours)
   * - ``--history HISTORY``
     - Password history size
   * - ``--minclasses MINCLASSES``
     - Minimum number of character classes
   * - ``--minlength MINLENGTH``
     - Minimum length of password
   * - ``--priority PRIORITY``
     - Priority of the policy (higher number means lower priority
   * - ``--maxfail MAXFAIL``
     - Consecutive failures before lockout
   * - ``--failinterval FAILINTERVAL``
     - Period after which failure count will be reset (seconds)
   * - ``--lockouttime LOCKOUTTIME``
     - Period for which lockout is enforced (seconds)
   * - ``--maxrepeat MAXREPEAT``
     - Maximum number of same consecutive characters
   * - ``--maxsequence MAXSEQUENCE``
     - The max. length of monotonic character sequences (abcd)
   * - ``--dictcheck DICTCHECK``
     - Check if the password is a dictionary word
   * - ``--usercheck USERCHECK``
     - Check if the password contains the username
   * - ``--dcredit DCREDIT``
     - The max credit for digits in the password.
   * - ``--ucredit UCREDIT``
     - The max credit for uppercase characters in the password.
   * - ``--lcredit LCREDIT``
     - The max credit for lowercase characters in the password.
   * - ``--ocredit OCREDIT``
     - The max credit for other characters in the password.
   * - ``--gracelimit GRACELIMIT``
     - Number of LDAP authentications allowed after expiration
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

----

.. _pwpolicy-show:

pwpolicy-show
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] pwpolicy-show [GROUP] [options]``

Display information about password policy.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``GROUP``
     - no
     - Manage password policy for specific group

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--user USER``
     - Display effective policy for a specific user
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

