Migration to IPA
================

Migrate users and groups from an LDAP server to IPA.

This performs an LDAP query against the remote server searching for
users and groups in a container. In order to migrate passwords you need
to bind as a user that can read the userPassword attribute on the remote
server. This is generally restricted to high-level admins such as
cn=Directory Manager in 389-ds (this is the default bind user).

The default user container is ou=People.

The default group container is ou=Groups.

Users and groups that already exist on the IPA server are skipped.

Two LDAP schemas define how group members are stored: RFC2307 and
RFC2307bis. RFC2307bis uses member and uniquemember to specify group
members, RFC2307 uses memberUid. The default schema is RFC2307bis.

The schema compat feature allows IPA to reformat data for systems that
do not support RFC2307bis. It is recommended that this feature is disabled
during migration to reduce system overhead. It can be re-enabled after
migration. To migrate with it enabled use the "--with-compat" option.

Migrated users do not have Kerberos credentials, they have only their
LDAP password. To complete the migration process, users need to go
to http://ipa.example.com/ipa/migration and authenticate using their
LDAP password in order to generate their Kerberos credentials.

Migration is disabled by default. Use the command ipa ``config-mod`` to
enable it:

 ipa ``config-mod`` --enable-migration=TRUE

If a base DN is not provided with --basedn then IPA will use either
the value of defaultNamingContext if it is set or the first value
in namingContexts set in the root of the remote LDAP server.

Users are added as members to the default user group. This can be a
time-intensive task so during migration this is done in a batch
mode for every 100 users. As a result there will be a window in which
users will be added to IPA but will not be members of the default
user group.


**EXAMPLES**

 The simplest migration, accepting all defaults:

 .. code-block:: console

    ipa migrate-ds ldap://ds.example.com:389

 Specify the user and group container. This can be used to migrate user

 and group data from an IPA v1 server:

 .. code-block:: console

    ipa migrate-ds --user-container='cn=users,cn=accounts' \
        --group-container='cn=groups,cn=accounts' \
        ldap://ds.example.com:389

 Since IPA v2 server already contain predefined groups that may collide with

 groups in migrated (IPA v1) server (for example admins, ipausers), users

 having colliding group as their primary group may happen to belong to

 an unknown group on new IPA v2 server.

 Use --group-overwrite-gid option to overwrite GID of already existing groups

 to prevent this issue:

 .. code-block:: console

     ipa migrate-ds --group-overwrite-gid \
         --user-container='cn=users,cn=accounts' \
         --group-container='cn=groups,cn=accounts' \
         ldap://ds.example.com:389

 Migrated users or groups may have object class and accompanied attributes

 unknown to the IPA v2 server. These object classes and attributes may be

 left out of the migration process:

 .. code-block:: console

     ipa migrate-ds --user-container='cn=users,cn=accounts' \
        --group-container='cn=groups,cn=accounts' \
        --user-ignore-objectclass=radiusprofile \
        --user-ignore-attribute=radiusgroupname \
        ldap://ds.example.com:389


**LOGGING**

Migration will log warnings and errors to the Apache error log. This
file should be evaluated post-migration to correct or investigate any
issues that were discovered.

For every 100 users migrated an info-level message will be displayed to
give the current progress and duration to make it possible to track
the progress of migration.

If the log level is debug, either by setting debug = True in
/etc/ipa/default.conf or /etc/ipa/server.conf, then an entry will be printed
for each user added plus a summary when the default user group is
updated.

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `migrate-ds`_
     - Migrate users and groups from DS to IPA.

----

.. _migrate-ds:

migrate-ds
~~~~~~~~~~

**Usage:** ``ipa [global-options] migrate-ds LDAP-URI PASSWORD [options]``

Migrate users and groups from DS to IPA.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LDAP-URI``
     - yes
     - LDAP URI of DS server to migrate from
   * - ``PASSWORD``
     - yes
     - bind password

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--bind-dn BIND-DN``
     - Bind DN
   * - ``--user-container USER-CONTAINER``
     - DN of container for users in DS relative to base DN
   * - ``--group-container GROUP-CONTAINER``
     - DN of container for groups in DS relative to base DN
   * - ``--user-objectclass USER-OBJECTCLASS``
     - Objectclasses used to search for user entries in DS
   * - ``--group-objectclass GROUP-OBJECTCLASS``
     - Objectclasses used to search for group entries in DS
   * - ``--user-ignore-objectclass USER-IGNORE-OBJECTCLASS``
     - Objectclasses to be ignored for user entries in DS
   * - ``--user-ignore-attribute USER-IGNORE-ATTRIBUTE``
     - Attributes to be ignored for user entries in DS
   * - ``--group-ignore-objectclass GROUP-IGNORE-OBJECTCLASS``
     - Objectclasses to be ignored for group entries in DS
   * - ``--group-ignore-attribute GROUP-IGNORE-ATTRIBUTE``
     - Attributes to be ignored for group entries in DS
   * - ``--group-overwrite-gid``
     - When migrating a group already existing in IPA domain overwrite the group GID and report as success
   * - ``--schema SCHEMA``
     - The schema used on the LDAP server. Supported values are RFC2307 and RFC2307bis. The default is RFC2307bis
   * - ``--continue``
     - Continuous operation mode. Errors are reported but the process continues
   * - ``--base-dn BASE-DN``
     - Base DN on remote LDAP server
   * - ``--with-compat``
     - Allows migration despite the usage of compat plugin
   * - ``--ca-cert-file CA-CERT-FILE``
     - Load CA certificate of LDAP server from FILE
   * - ``--use-default-group USE-DEFAULT-GROUP``
     - Add migrated users without a group to a default group (default: true)
   * - ``--scope SCOPE``
     - LDAP search scope for users and groups: base, onelevel, or subtree. Defaults to onelevel
   * - ``--exclude-users EXCLUDE-USERS``
     - users to exclude from migration
   * - ``--exclude-groups EXCLUDE-GROUPS``
     - groups to exclude from migration

