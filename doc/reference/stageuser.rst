Stageusers
==========

Manage stage user entries.

Stage user entries are directly under the container: "cn=stage users,
cn=accounts, cn=provisioning, SUFFIX".
Users can not authenticate with those entries (even if the entries
contain credentials). Those entries are only candidate to become Active entries.

Active user entries are Posix users directly under the container: "cn=accounts, SUFFIX".
Users can authenticate with Active entries, at the condition they have
credentials.

Deleted user entries are Posix users directly under the container: "cn=deleted users,
cn=accounts, cn=provisioning, SUFFIX".
Users can not authenticate with those entries, even if the entries contain credentials.

The stage user container contains entries:

    - created by 'stageuser-add' commands that are Posix users,
    - created by external provisioning system.

A valid stage user entry MUST have:

    - entry RDN is 'uid',
    - ipaUniqueID is 'autogenerate'.

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



**EXAMPLES**

 Add a new stageuser:

 .. code-block:: console

    ipa stageuser-add --first=Tim --last=User --password tuser1

 Add a stageuser from the deleted users container:

 .. code-block:: console

    ipa stageuser-add  --first=Tim --last=User --from-delete tuser1


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `stageuser-activate`_
     - Activate a stage user.
   * - `stageuser-add`_
     - Add a new stage user.
   * - `stageuser-add-cert`_
     - Add one or more certificates to the stageuser entry
   * - `stageuser-add-certmapdata`_
     - Add one or more certificate mappings to the stage user entry.
   * - `stageuser-add-manager`_
     - Add a manager to the stage user entry
   * - `stageuser-add-passkey`_
     - Add one or more passkey mappings to the stage user entry.
   * - `stageuser-add-principal`_
     - Add new principal alias to the stageuser entry
   * - `stageuser-del`_
     - Delete a stage user.
   * - `stageuser-find`_
     - Search for stage users.
   * - `stageuser-mod`_
     - Modify a stage user.
   * - `stageuser-remove-cert`_
     - Remove one or more certificates to the stageuser entry
   * - `stageuser-remove-certmapdata`_
     - Remove one or more certificate mappings from the stage user entry.
   * - `stageuser-remove-manager`_
     - Remove a manager to the stage user entry
   * - `stageuser-remove-passkey`_
     - Remove one or more passkey mappings from the stage user entry.
   * - `stageuser-remove-principal`_
     - Remove principal alias from the stageuser entry
   * - `stageuser-show`_
     - Display information about a stage user.

----

.. _stageuser-activate:

stageuser-activate
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-activate LOGIN [options]``

Activate a stage user.

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

----

.. _stageuser-add:

stageuser-add
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-add LOGIN [options]``

Add a new stage user.

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
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _stageuser-add-cert:

stageuser-add-cert
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-add-cert LOGIN [options]``

Add one or more certificates to the stageuser entry

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

.. _stageuser-add-certmapdata:

stageuser-add-certmapdata
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-add-certmapdata LOGIN [CERTMAPDATA] [options]``

Add one or more certificate mappings to the stage user entry.

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

.. _stageuser-add-manager:

stageuser-add-manager
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-add-manager LOGIN [options]``

Add a manager to the stage user entry

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

.. _stageuser-add-passkey:

stageuser-add-passkey
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-add-passkey LOGIN PASSKEY [options]``

Add one or more passkey mappings to the stage user entry.

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

.. _stageuser-add-principal:

stageuser-add-principal
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-add-principal LOGIN [PRINCIPAL] [options]``

Add new principal alias to the stageuser entry

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

.. _stageuser-del:

stageuser-del
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-del LOGIN [options]``

Delete a stage user.

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

.. _stageuser-find:

stageuser-find
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-find [CRITERIA] [options]``

Search for stage users.

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
   * - ``--in-groups IN-GROUPS``
     - Search for stage users with these member of groups.
   * - ``--not-in-groups NOT-IN-GROUPS``
     - Search for stage users without these member of groups.
   * - ``--in-netgroups IN-NETGROUPS``
     - Search for stage users with these member of netgroups.
   * - ``--not-in-netgroups NOT-IN-NETGROUPS``
     - Search for stage users without these member of netgroups.
   * - ``--in-roles IN-ROLES``
     - Search for stage users with these member of roles.
   * - ``--not-in-roles NOT-IN-ROLES``
     - Search for stage users without these member of roles.
   * - ``--in-hbacrules IN-HBACRULES``
     - Search for stage users with these member of HBAC rules.
   * - ``--not-in-hbacrules NOT-IN-HBACRULES``
     - Search for stage users without these member of HBAC rules.
   * - ``--in-sudorules IN-SUDORULES``
     - Search for stage users with these member of sudo rules.
   * - ``--not-in-sudorules NOT-IN-SUDORULES``
     - Search for stage users without these member of sudo rules.
   * - ``--in-subids IN-SUBIDS``
     - Search for stage users with these member of Subordinate ids.
   * - ``--not-in-subids NOT-IN-SUBIDS``
     - Search for stage users without these member of Subordinate ids.

----

.. _stageuser-mod:

stageuser-mod
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-mod LOGIN [options]``

Modify a stage user.

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
     - Rename the stage user object

----

.. _stageuser-remove-cert:

stageuser-remove-cert
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-remove-cert LOGIN [options]``

Remove one or more certificates to the stageuser entry

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

.. _stageuser-remove-certmapdata:

stageuser-remove-certmapdata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-remove-certmapdata LOGIN [CERTMAPDATA] [options]``

Remove one or more certificate mappings from the stage user entry.

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

.. _stageuser-remove-manager:

stageuser-remove-manager
~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-remove-manager LOGIN [options]``

Remove a manager to the stage user entry

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

.. _stageuser-remove-passkey:

stageuser-remove-passkey
~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-remove-passkey LOGIN PASSKEY [options]``

Remove one or more passkey mappings from the stage user entry.

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

.. _stageuser-remove-principal:

stageuser-remove-principal
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-remove-principal LOGIN [PRINCIPAL] [options]``

Remove principal alias from the stageuser entry

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

.. _stageuser-show:

stageuser-show
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] stageuser-show LOGIN [options]``

Display information about a stage user.

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
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

