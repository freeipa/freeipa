#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

__doc__ = _("""
Migration to IPA

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

Migration is disabled by default. Use the command ipa config-mod to
enable it:

 ipa config-mod --enable-migration=TRUE

If a base DN is not provided with --basedn then IPA will use either
the value of defaultNamingContext if it is set or the first value
in namingContexts set in the root of the remote LDAP server.

Users are added as members to the default user group. This can be a
time-intensive task so during migration this is done in a batch
mode for every 100 users. As a result there will be a window in which
users will be added to IPA but will not be members of the default
user group.

EXAMPLES:

 The simplest migration, accepting all defaults:
   ipa migrate-ds ldap://ds.example.com:389

 Specify the user and group container. This can be used to migrate user
 and group data from an IPA v1 server:
   ipa migrate-ds --user-container='cn=users,cn=accounts' \
       --group-container='cn=groups,cn=accounts' \
       ldap://ds.example.com:389

 Since IPA v2 server already contain predefined groups that may collide with
 groups in migrated (IPA v1) server (for example admins, ipausers), users
 having colliding group as their primary group may happen to belong to
 an unknown group on new IPA v2 server.
 Use --group-overwrite-gid option to overwrite GID of already existing groups
 to prevent this issue:
    ipa migrate-ds --group-overwrite-gid \
        --user-container='cn=users,cn=accounts' \
        --group-container='cn=groups,cn=accounts' \
        ldap://ds.example.com:389

 Migrated users or groups may have object class and accompanied attributes
 unknown to the IPA v2 server. These object classes and attributes may be
 left out of the migration process:
    ipa migrate-ds --user-container='cn=users,cn=accounts' \
       --group-container='cn=groups,cn=accounts' \
       --user-ignore-objectclass=radiusprofile \
       --user-ignore-attribute=radiusgroupname \
       ldap://ds.example.com:389

LOGGING

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
""")

register = Registry()


@register()
class migrate_ds(Command):
    __doc__ = _("Migrate users and groups from DS to IPA.")

    takes_args = (
        parameters.Str(
            'ldapuri',
            cli_name='ldap_uri',
            label=_('LDAP URI'),
            doc=_('LDAP URI of DS server to migrate from'),
        ),
        parameters.Password(
            'bindpw',
            cli_name='password',
            label=_('Password'),
            doc=_('bind password'),
        ),
    )
    takes_options = (
        parameters.DNParam(
            'binddn',
            required=False,
            cli_name='bind_dn',
            label=_('Bind DN'),
            default=DN('cn=directory manager'),
            autofill=True,
        ),
        parameters.DNParam(
            'usercontainer',
            cli_name='user_container',
            label=_('User container'),
            doc=_('DN of container for users in DS relative to base DN'),
            default=DN('ou=people'),
            autofill=True,
        ),
        parameters.DNParam(
            'groupcontainer',
            cli_name='group_container',
            label=_('Group container'),
            doc=_('DN of container for groups in DS relative to base DN'),
            default=DN('ou=groups'),
            autofill=True,
        ),
        parameters.Str(
            'userobjectclass',
            multivalue=True,
            cli_name='user_objectclass',
            label=_('User object class'),
            doc=_('Objectclasses used to search for user entries in DS'),
            default=('person',),
            autofill=True,
        ),
        parameters.Str(
            'groupobjectclass',
            multivalue=True,
            cli_name='group_objectclass',
            label=_('Group object class'),
            doc=_('Objectclasses used to search for group entries in DS'),
            default=('groupOfUniqueNames', 'groupOfNames'),
            autofill=True,
        ),
        parameters.Str(
            'userignoreobjectclass',
            required=False,
            multivalue=True,
            cli_name='user_ignore_objectclass',
            label=_('Ignore user object class'),
            doc=_('Objectclasses to be ignored for user entries in DS'),
            default=(),
            autofill=True,
        ),
        parameters.Str(
            'userignoreattribute',
            required=False,
            multivalue=True,
            cli_name='user_ignore_attribute',
            label=_('Ignore user attribute'),
            doc=_('Attributes to be ignored for user entries in DS'),
            default=(),
            autofill=True,
        ),
        parameters.Str(
            'groupignoreobjectclass',
            required=False,
            multivalue=True,
            cli_name='group_ignore_objectclass',
            label=_('Ignore group object class'),
            doc=_('Objectclasses to be ignored for group entries in DS'),
            default=(),
            autofill=True,
        ),
        parameters.Str(
            'groupignoreattribute',
            required=False,
            multivalue=True,
            cli_name='group_ignore_attribute',
            label=_('Ignore group attribute'),
            doc=_('Attributes to be ignored for group entries in DS'),
            default=(),
            autofill=True,
        ),
        parameters.Flag(
            'groupoverwritegid',
            cli_name='group_overwrite_gid',
            label=_('Overwrite GID'),
            doc=_('When migrating a group already existing in IPA domain overwrite the group GID and report as success'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'schema',
            required=False,
            cli_metavar="['RFC2307bis', 'RFC2307']",
            label=_('LDAP schema'),
            doc=_('The schema used on the LDAP server. Supported values are RFC2307 and RFC2307bis. The default is RFC2307bis'),
            default='RFC2307bis',
            autofill=True,
        ),
        parameters.Flag(
            'continue',
            required=False,
            label=_('Continue'),
            doc=_('Continuous operation mode. Errors are reported but the process continues'),
            default=False,
            autofill=True,
        ),
        parameters.DNParam(
            'basedn',
            required=False,
            cli_name='base_dn',
            label=_('Base DN'),
            doc=_('Base DN on remote LDAP server'),
        ),
        parameters.Flag(
            'compat',
            required=False,
            cli_name='with_compat',
            label=_('Ignore compat plugin'),
            doc=_('Allows migration despite the usage of compat plugin'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'cacertfile',
            required=False,
            cli_name='ca_cert_file',
            label=_('CA certificate'),
            doc=_('Load CA certificate of LDAP server from FILE'),
        ),
        parameters.Str(
            'exclude_groups',
            required=False,
            multivalue=True,
            doc=_('groups to exclude from migration'),
            default=(),
            autofill=True,
        ),
        parameters.Str(
            'exclude_users',
            required=False,
            multivalue=True,
            doc=_('users to exclude from migration'),
            default=(),
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'result',
            dict,
            doc=_('Lists of objects migrated; categorized by type.'),
        ),
        output.Output(
            'failed',
            dict,
            doc=_('Lists of objects that could not be migrated; categorized by type.'),
        ),
        output.Output(
            'enabled',
            bool,
            doc=_('False if migration mode was disabled.'),
        ),
        output.Output(
            'compat',
            bool,
            doc=_('False if migration fails because the compatibility plug-in is enabled.'),
        ),
    )
