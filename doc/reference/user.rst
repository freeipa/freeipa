Users
=====

Manage user entries. All users are POSIX users.

IPA supports a wide range of username formats, but you need to be aware of any
restrictions that may apply to your particular environment. For example,
usernames that start with a digit or usernames that exceed a certain length
may cause problems for some UNIX systems.
Use 'ipa ``config-mod``' to change the username format allowed by IPA tools.

The user name must follow these rules:

- cannot contain only numbers
- must start with a letter, a number, _ or .
- may contain letters, numbers, _, ., or -
- may end with a letter, a number, _, ., - or $

Disabling a user account prevents that user from obtaining new Kerberos
credentials. It does not invalidate any credentials that have already
been issued.

Password management is not a part of this module. For more information
about this topic please see: ipa help passwd

Account lockout on password failure happens per IPA master. The ``user-status``
command can be used to identify which master the user is locked out on.
It is on that master the administrator must unlock the user.


**EXAMPLES**

 Add a new user:

 .. code-block:: console

    ipa user-add --first=Tim --last=User --password tuser1

 Find all users whose entries include the string "Tim":

 .. code-block:: console

    ipa user-find Tim

 Find all users with "Tim" as the first name:

 .. code-block:: console

    ipa user-find --first=Tim

 Disable a user account:

 .. code-block:: console

    ipa user-disable tuser1

 Enable a user account:

 .. code-block:: console

    ipa user-enable tuser1

 Delete a user:

 .. code-block:: console

    ipa user-del tuser1


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `user-add`_
     - Add a new user.
   * - `user-add-cert`_
     - Add one or more certificates to the user entry
   * - `user-add-certmapdata`_
     - Add one or more certificate mappings to the user entry.
   * - `user-add-manager`_
     - Add a manager to the user entry
   * - `user-add-passkey`_
     - Add one or more passkey mappings to the user entry.
   * - `user-add-principal`_
     - Add new principal alias to the user entry
   * - `user-del`_
     - Delete a user.
   * - `user-disable`_
     - Disable a user account.
   * - `user-enable`_
     - Enable a user account.
   * - `user-find`_
     - Search for users.
   * - `user-mod`_
     - Modify a user.
   * - `user-remove-cert`_
     - Remove one or more certificates to the user entry
   * - `user-remove-certmapdata`_
     - Remove one or more certificate mappings from the user entry.
   * - `user-remove-manager`_
     - Remove a manager to the user entry
   * - `user-remove-passkey`_
     - Remove one or more passkey mappings from the user entry.
   * - `user-remove-principal`_
     - Remove principal alias from the user entry
   * - `user-show`_
     - Display information about a user.
   * - `user-stage`_
     - Move deleted user into staged area
   * - `user-status`_
     - Lockout status of a user account
   * - `user-undel`_
     - Undelete a delete user account.
   * - `user-unlock`_
     - Unlock a user account

----

.. _user-add:

user-add
~~~~~~~~

**Usage:** ``ipa [global-options] user-add LOGIN [options]``

Add a new user.

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
     - User login

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--first FIRST``
     - First name
   * - ``--last LAST``
     - Last name
   * - ``--cn CN``
     - Full name
   * - ``--displayname DISPLAYNAME``
     - Display name
   * - ``--initials INITIALS``
     - Initials
   * - ``--homedir HOMEDIR``
     - Home directory
   * - ``--gecos GECOS``
     - GECOS
   * - ``--shell SHELL``
     - Login shell
   * - ``--principal PRINCIPAL``
     - Principal alias
   * - ``--principal-expiration PRINCIPAL-EXPIRATION``
     - Kerberos principal expiration
   * - ``--password-expiration PASSWORD-EXPIRATION``
     - User password expiration
   * - ``--email EMAIL``
     - Email address
   * - ``--password PASSWORD``
     - Prompt to set the user password
   * - ``--random``
     - Generate a random user password
   * - ``--uid UID``
     - User ID Number (system will assign one if not provided)
   * - ``--gidnumber GIDNUMBER``
     - Group ID Number
   * - ``--street STREET``
     - Street address
   * - ``--city CITY``
     - City
   * - ``--state STATE``
     - State/Province
   * - ``--postalcode POSTALCODE``
     - ZIP
   * - ``--phone PHONE``
     - Telephone Number
   * - ``--mobile MOBILE``
     - Mobile Telephone Number
   * - ``--pager PAGER``
     - Pager Number
   * - ``--fax FAX``
     - Fax Number
   * - ``--orgunit ORGUNIT``
     - Org. Unit
   * - ``--title TITLE``
     - Job Title
   * - ``--manager MANAGER``
     - Manager
   * - ``--carlicense CARLICENSE``
     - Car License
   * - ``--sshpubkey SSHPUBKEY``
     - SSH public key
   * - ``--user-auth-type USER-AUTH-TYPE``
     - Types of supported user authentication
   * - ``--class CLASS``
     - User category (semantics placed on this attribute are for local interpretation)
   * - ``--radius RADIUS``
     - RADIUS proxy configuration
   * - ``--radius-username RADIUS-USERNAME``
     - RADIUS proxy username
   * - ``--idp IDP``
     - External IdP configuration
   * - ``--idp-user-id IDP-USER-ID``
     - A string that identifies the user at external IdP
   * - ``--departmentnumber DEPARTMENTNUMBER``
     - Department Number
   * - ``--employeenumber EMPLOYEENUMBER``
     - Employee Number
   * - ``--employeetype EMPLOYEETYPE``
     - Employee Type
   * - ``--preferredlanguage PREFERREDLANGUAGE``
     - Preferred Language
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--noprivate``
     - Don't create user private group
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _user-add-cert:

user-add-cert
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-add-cert LOGIN [options]``

Add one or more certificates to the user entry

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
     - User login

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
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate

----

.. _user-add-certmapdata:

user-add-certmapdata
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-add-certmapdata LOGIN [CERTMAPDATA] [options]``

Add one or more certificate mappings to the user entry.

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
     - User login
   * - ``CERTMAPDATA``
     - no
     - Certificate mapping data

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--issuer ISSUER``
     - Issuer of the certificate
   * - ``--subject SUBJECT``
     - Subject of the certificate
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _user-add-manager:

user-add-manager
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-add-manager LOGIN [options]``

Add a manager to the user entry

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
     - User login

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

----

.. _user-add-passkey:

user-add-passkey
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-add-passkey LOGIN PASSKEY [options]``

Add one or more passkey mappings to the user entry.

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
     - User login
   * - ``PASSKEY``
     - yes
     - Passkey mapping

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

----

.. _user-add-principal:

user-add-principal
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-add-principal LOGIN [PRINCIPAL] [options]``

Add new principal alias to the user entry

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
     - User login
   * - ``PRINCIPAL``
     - no
     - Principal alias

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

----

.. _user-del:

user-del
~~~~~~~~

**Usage:** ``ipa [global-options] user-del LOGIN [options]``

Delete a user.

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
     - User login

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.
   * - ``--preserve PRESERVE``
     - <preserve>

----

.. _user-disable:

user-disable
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-disable LOGIN [options]``

Disable a user account.

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
     - User login

----

.. _user-enable:

user-enable
~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-enable LOGIN [options]``

Enable a user account.

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
     - User login

----

.. _user-find:

user-find
~~~~~~~~~

**Usage:** ``ipa [global-options] user-find [CRITERIA] [options]``

Search for users.

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
     - User login
   * - ``--first FIRST``
     - First name
   * - ``--last LAST``
     - Last name
   * - ``--cn CN``
     - Full name
   * - ``--displayname DISPLAYNAME``
     - Display name
   * - ``--initials INITIALS``
     - Initials
   * - ``--homedir HOMEDIR``
     - Home directory
   * - ``--gecos GECOS``
     - GECOS
   * - ``--shell SHELL``
     - Login shell
   * - ``--principal PRINCIPAL``
     - Principal alias
   * - ``--principal-expiration PRINCIPAL-EXPIRATION``
     - Kerberos principal expiration
   * - ``--password-expiration PASSWORD-EXPIRATION``
     - User password expiration
   * - ``--email EMAIL``
     - Email address
   * - ``--password PASSWORD``
     - Prompt to set the user password
   * - ``--uid UID``
     - User ID Number (system will assign one if not provided)
   * - ``--gidnumber GIDNUMBER``
     - Group ID Number
   * - ``--street STREET``
     - Street address
   * - ``--city CITY``
     - City
   * - ``--state STATE``
     - State/Province
   * - ``--postalcode POSTALCODE``
     - ZIP
   * - ``--phone PHONE``
     - Telephone Number
   * - ``--mobile MOBILE``
     - Mobile Telephone Number
   * - ``--pager PAGER``
     - Pager Number
   * - ``--fax FAX``
     - Fax Number
   * - ``--orgunit ORGUNIT``
     - Org. Unit
   * - ``--title TITLE``
     - Job Title
   * - ``--manager MANAGER``
     - Manager
   * - ``--carlicense CARLICENSE``
     - Car License
   * - ``--user-auth-type USER-AUTH-TYPE``
     - Types of supported user authentication
   * - ``--class CLASS``
     - User category (semantics placed on this attribute are for local interpretation)
   * - ``--radius RADIUS``
     - RADIUS proxy configuration
   * - ``--radius-username RADIUS-USERNAME``
     - RADIUS proxy username
   * - ``--idp IDP``
     - External IdP configuration
   * - ``--idp-user-id IDP-USER-ID``
     - A string that identifies the user at external IdP
   * - ``--departmentnumber DEPARTMENTNUMBER``
     - Department Number
   * - ``--employeenumber EMPLOYEENUMBER``
     - Employee Number
   * - ``--employeetype EMPLOYEETYPE``
     - Employee Type
   * - ``--preferredlanguage PREFERREDLANGUAGE``
     - Preferred Language
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate
   * - ``--smb-logon-script SMB-LOGON-SCRIPT``
     - SMB logon script path
   * - ``--smb-profile-path SMB-PROFILE-PATH``
     - SMB profile path
   * - ``--smb-home-dir SMB-HOME-DIR``
     - SMB Home Directory
   * - ``--smb-home-drive SMB-HOME-DRIVE``
     - SMB Home Directory Drive
   * - ``--disabled DISABLED``
     - Account disabled
   * - ``--preserved PRESERVED``
     - Preserved user
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--whoami``
     - Display user record for current Kerberos principal
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("login")
   * - ``--in-groups IN-GROUPS``
     - Search for users with these member of groups.
   * - ``--not-in-groups NOT-IN-GROUPS``
     - Search for users without these member of groups.
   * - ``--in-netgroups IN-NETGROUPS``
     - Search for users with these member of netgroups.
   * - ``--not-in-netgroups NOT-IN-NETGROUPS``
     - Search for users without these member of netgroups.
   * - ``--in-roles IN-ROLES``
     - Search for users with these member of roles.
   * - ``--not-in-roles NOT-IN-ROLES``
     - Search for users without these member of roles.
   * - ``--in-hbacrules IN-HBACRULES``
     - Search for users with these member of HBAC rules.
   * - ``--not-in-hbacrules NOT-IN-HBACRULES``
     - Search for users without these member of HBAC rules.
   * - ``--in-sudorules IN-SUDORULES``
     - Search for users with these member of sudo rules.
   * - ``--not-in-sudorules NOT-IN-SUDORULES``
     - Search for users without these member of sudo rules.
   * - ``--in-subids IN-SUBIDS``
     - Search for users with these member of Subordinate ids.
   * - ``--not-in-subids NOT-IN-SUBIDS``
     - Search for users without these member of Subordinate ids.

----

.. _user-mod:

user-mod
~~~~~~~~

**Usage:** ``ipa [global-options] user-mod LOGIN [options]``

Modify a user.

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
     - User login

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--first FIRST``
     - First name
   * - ``--last LAST``
     - Last name
   * - ``--cn CN``
     - Full name
   * - ``--displayname DISPLAYNAME``
     - Display name
   * - ``--initials INITIALS``
     - Initials
   * - ``--homedir HOMEDIR``
     - Home directory
   * - ``--gecos GECOS``
     - GECOS
   * - ``--shell SHELL``
     - Login shell
   * - ``--principal PRINCIPAL``
     - Principal alias
   * - ``--principal-expiration PRINCIPAL-EXPIRATION``
     - Kerberos principal expiration
   * - ``--password-expiration PASSWORD-EXPIRATION``
     - User password expiration
   * - ``--email EMAIL``
     - Email address
   * - ``--password PASSWORD``
     - Prompt to set the user password
   * - ``--random``
     - Generate a random user password
   * - ``--uid UID``
     - User ID Number (system will assign one if not provided)
   * - ``--gidnumber GIDNUMBER``
     - Group ID Number
   * - ``--street STREET``
     - Street address
   * - ``--city CITY``
     - City
   * - ``--state STATE``
     - State/Province
   * - ``--postalcode POSTALCODE``
     - ZIP
   * - ``--phone PHONE``
     - Telephone Number
   * - ``--mobile MOBILE``
     - Mobile Telephone Number
   * - ``--pager PAGER``
     - Pager Number
   * - ``--fax FAX``
     - Fax Number
   * - ``--orgunit ORGUNIT``
     - Org. Unit
   * - ``--title TITLE``
     - Job Title
   * - ``--manager MANAGER``
     - Manager
   * - ``--carlicense CARLICENSE``
     - Car License
   * - ``--sshpubkey SSHPUBKEY``
     - SSH public key
   * - ``--user-auth-type USER-AUTH-TYPE``
     - Types of supported user authentication
   * - ``--class CLASS``
     - User category (semantics placed on this attribute are for local interpretation)
   * - ``--radius RADIUS``
     - RADIUS proxy configuration
   * - ``--radius-username RADIUS-USERNAME``
     - RADIUS proxy username
   * - ``--idp IDP``
     - External IdP configuration
   * - ``--idp-user-id IDP-USER-ID``
     - A string that identifies the user at external IdP
   * - ``--departmentnumber DEPARTMENTNUMBER``
     - Department Number
   * - ``--employeenumber EMPLOYEENUMBER``
     - Employee Number
   * - ``--employeetype EMPLOYEETYPE``
     - Employee Type
   * - ``--preferredlanguage PREFERREDLANGUAGE``
     - Preferred Language
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate
   * - ``--smb-logon-script SMB-LOGON-SCRIPT``
     - SMB logon script path
   * - ``--smb-profile-path SMB-PROFILE-PATH``
     - SMB profile path
   * - ``--smb-home-dir SMB-HOME-DIR``
     - SMB Home Directory
   * - ``--smb-home-drive SMB-HOME-DRIVE``
     - SMB Home Directory Drive
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
     - Rename the user object

----

.. _user-remove-cert:

user-remove-cert
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-remove-cert LOGIN [options]``

Remove one or more certificates to the user entry

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
     - User login

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
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate

----

.. _user-remove-certmapdata:

user-remove-certmapdata
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-remove-certmapdata LOGIN [CERTMAPDATA] [options]``

Remove one or more certificate mappings from the user entry.

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
     - User login
   * - ``CERTMAPDATA``
     - no
     - Certificate mapping data

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--issuer ISSUER``
     - Issuer of the certificate
   * - ``--subject SUBJECT``
     - Subject of the certificate
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _user-remove-manager:

user-remove-manager
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-remove-manager LOGIN [options]``

Remove a manager to the user entry

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
     - User login

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

----

.. _user-remove-passkey:

user-remove-passkey
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-remove-passkey LOGIN PASSKEY [options]``

Remove one or more passkey mappings from the user entry.

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
     - User login
   * - ``PASSKEY``
     - yes
     - Passkey mapping

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

----

.. _user-remove-principal:

user-remove-principal
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-remove-principal LOGIN [PRINCIPAL] [options]``

Remove principal alias from the user entry

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
     - User login
   * - ``PRINCIPAL``
     - no
     - Principal alias

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

----

.. _user-show:

user-show
~~~~~~~~~

**Usage:** ``ipa [global-options] user-show LOGIN [options]``

Display information about a user.

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
     - User login

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--out OUT``
     - file to store certificate in
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _user-stage:

user-stage
~~~~~~~~~~

**Usage:** ``ipa [global-options] user-stage LOGIN [options]``

Move deleted user into staged area

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
     - User login

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

.. _user-status:

user-status
~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-status LOGIN [options]``

Lockout status of a user account


.. code-block:: console

    An account may become locked if the password is entered incorrectly too
    many times within a specific time period as controlled by password
    policy. A locked account is a temporary condition and may be unlocked by
    an administrator.

    This connects to each IPA master and displays the lockout status on
    each one.

    To determine whether an account is locked on a given server you need
    to compare the number of failed logins and the time of the last failure.
    For an account to be locked it must exceed the maxfail failures within
    the failinterval duration as specified in the password policy associated
    with the user.

    The failed login counter is modified only when a user attempts a log in
    so it is possible that an account may appear locked but the last failed
    login attempt is older than the lockouttime of the password policy. This
    means that the user may attempt a login again.


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
     - User login

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

----

.. _user-undel:

user-undel
~~~~~~~~~~

**Usage:** ``ipa [global-options] user-undel LOGIN [options]``

Undelete a delete user account.

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
     - User login

----

.. _user-unlock:

user-unlock
~~~~~~~~~~~

**Usage:** ``ipa [global-options] user-unlock LOGIN [options]``

Unlock a user account


.. code-block:: console

    An account may become locked if the password is entered incorrectly too
    many times within a specific time period as controlled by password
    policy. A locked account is a temporary condition and may be unlocked by
    an administrator.


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
     - User login

