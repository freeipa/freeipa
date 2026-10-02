Server configuration
====================

Manage the default values that IPA uses and some of its tuning parameters.


**NOTES**

The password notification value (--pwdexpnotify) is stored here so it will
be replicated. It is not currently used to notify users in advance of an
expiring password.

Some attributes are read-only, provided only for information purposes. These
include:

Certificate Subject base: the configured certificate subject base,

  e.g. O=EXAMPLE.COM.  This is configurable only at install time.

Password plug-in features: currently defines additional hashes that the

  password will generate (there may be other conditions).

When setting the order list for mapping SELinux users you may need to
quote the value so it isn't interpreted by the shell.

The maximum length of a hostname in Linux is controlled by
MAXHOSTNAMELEN in the kernel and defaults to 64. Some other operating
systems, Solaris for example, allows hostnames up to 255 characters.
This option will allow flexibility in length but by default limiting
to the Linux maximum length.


**EXAMPLES**

 Show basic server configuration:

 .. code-block:: console

    ipa config-show

 Show all configuration options:

 .. code-block:: console

    ipa config-show --all

 Change maximum username length to 99 characters:

 .. code-block:: console

    ipa config-mod --maxusername=99

 Change maximum host name length to 255 characters:

 .. code-block:: console

    ipa config-mod --maxhostname=255

 Increase default time and size limits for maximum IPA server search:

 .. code-block:: console

    ipa config-mod --searchtimelimit=10 --searchrecordslimit=2000

 Set default user e-mail domain:

 .. code-block:: console

    ipa config-mod --emaildomain=example.com

 Enable migration mode to make "ipa ``migrate-ds``" command operational:

 .. code-block:: console

    ipa config-mod --enable-migration=TRUE

 Define SELinux user map order:

 .. code-block:: console

    ipa config-mod --ipaselinuxusermaporder='guest_u:s0$xguest_u:s0$user_u:s0-s0:c0.c1023$staff_u:s0-s0:c0.c1023$unconfined_u:s0-s0:c0.c1023'


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `config-mod`_
     - Modify configuration options.
   * - `config-show`_
     - Show the current configuration.

----

.. _config-mod:

config-mod
~~~~~~~~~~

**Usage:** ``ipa [global-options] config-mod [options]``

Modify configuration options.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--maxusername MAXUSERNAME``
     - Maximum username length
   * - ``--maxhostname MAXHOSTNAME``
     - Maximum hostname length
   * - ``--homedirectory HOMEDIRECTORY``
     - Default location of home directories
   * - ``--defaultshell DEFAULTSHELL``
     - Default shell for new users
   * - ``--defaultgroup DEFAULTGROUP``
     - Default group for new users
   * - ``--emaildomain EMAILDOMAIN``
     - Default e-mail domain
   * - ``--searchtimelimit SEARCHTIMELIMIT``
     - Maximum amount of time (seconds) for a search (-1 or 0 is unlimited)
   * - ``--searchrecordslimit SEARCHRECORDSLIMIT``
     - Maximum number of records to search (-1 or 0 is unlimited)
   * - ``--usersearch USERSEARCH``
     - A comma-separated list of fields to search in when searching for users
   * - ``--groupsearch GROUPSEARCH``
     - A comma-separated list of fields to search in when searching for groups
   * - ``--enable-migration ENABLE-MIGRATION``
     - Enable migration mode
   * - ``--groupobjectclasses GROUPOBJECTCLASSES``
     - Default group objectclasses (comma-separated list)
   * - ``--userobjectclasses USEROBJECTCLASSES``
     - Default user objectclasses (comma-separated list)
   * - ``--pwdexpnotify PWDEXPNOTIFY``
     - Number of days's notice of impending password expiration
   * - ``--ipaconfigstring IPACONFIGSTRING``
     - Extra hashes to generate in password plug-in
   * - ``--ipaselinuxusermaporder IPASELINUXUSERMAPORDER``
     - Order in increasing priority of SELinux users, delimited by $
   * - ``--ipaselinuxusermapdefault IPASELINUXUSERMAPDEFAULT``
     - Default SELinux user when no match is found in SELinux map rule
   * - ``--pac-type PAC-TYPE``
     - Default types of PAC supported for services
   * - ``--user-auth-type USER-AUTH-TYPE``
     - Default types of supported user authentication
   * - ``--user-default-subid USER-DEFAULT-SUBID``
     - Enable adding subids to new users
   * - ``--ca-renewal-master-server CA-RENEWAL-MASTER-SERVER``
     - Renewal master for IPA certificate authority
   * - ``--domain-resolution-order DOMAIN-RESOLUTION-ORDER``
     - colon-separated list of domains used for short name qualification
   * - ``--enable-sid``
     - New users and groups automatically get a SID assigned
   * - ``--add-sids``
     - Add SIDs for existing users and groups
   * - ``--netbios-name NETBIOS-NAME``
     - NetBIOS name of the IPA domain
   * - ``--key-type-size KEY-TYPE-SIZE``
     - IPA Service key type:size
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

.. _config-show:

config-show
~~~~~~~~~~~

**Usage:** ``ipa [global-options] config-show [options]``

Show the current configuration.

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

