#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import
import six

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

__doc__ = _(r"""
Groups of users

Manage groups of users. By default, new groups are POSIX groups. You
can add the --nonposix option to the group-add command to mark a new group
as non-POSIX. You can use the --posix argument with the group-mod command
to convert a non-POSIX group into a POSIX group. POSIX groups cannot be
converted to non-POSIX groups.

Every group must have a description.

POSIX groups must have a Group ID (GID) number. Changing a GID is
supported but can have an impact on your file permissions. It is not necessary
to supply a GID when creating a group. IPA will generate one automatically
if it is not provided.

EXAMPLES:

 Add a new group:
   ipa group-add --desc='local administrators' localadmins

 Add a new non-POSIX group:
   ipa group-add --nonposix --desc='remote administrators' remoteadmins

 Convert a non-POSIX group to posix:
   ipa group-mod --posix remoteadmins

 Add a new POSIX group with a specific Group ID number:
   ipa group-add --gid=500 --desc='unix admins' unixadmins

 Add a new POSIX group and let IPA assign a Group ID number:
   ipa group-add --desc='printer admins' printeradmins

 Remove a group:
   ipa group-del unixadmins

 To add the "remoteadmins" group to the "localadmins" group:
   ipa group-add-member --groups=remoteadmins localadmins

 Add multiple users to the "localadmins" group:
   ipa group-add-member --users=test1 --users=test2 localadmins

 Remove a user from the "localadmins" group:
   ipa group-remove-member --users=test2 localadmins

 Display information about a named group.
   ipa group-show localadmins

External group membership is designed to allow users from trusted domains
to be mapped to local POSIX groups in order to actually use IPA resources.
External members should be added to groups that specifically created as
external and non-POSIX. Such group later should be included into one of POSIX
groups.

An external group member is currently a Security Identifier (SID) as defined by
the trusted domain. When adding external group members, it is possible to
specify them in either SID, or DOM\name, or name@domain format. IPA will attempt
to resolve passed name to SID with the use of Global Catalog of the trusted domain.

Example:

1. Create group for the trusted domain admins' mapping and their local POSIX group:

   ipa group-add --desc='<ad.domain> admins external map' ad_admins_external --external
   ipa group-add --desc='<ad.domain> admins' ad_admins

2. Add security identifier of Domain Admins of the <ad.domain> to the ad_admins_external
   group:

   ipa group-add-member ad_admins_external --external 'AD\Domain Admins'

3. Allow members of ad_admins_external group to be associated with ad_admins POSIX group:

   ipa group-add-member ad_admins --groups ad_admins_external

4. List members of external members of ad_admins_external group to see their SIDs:

   ipa group-show ad_admins_external
""")

register = Registry()


@register()
class group(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Group name'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_(u'Description'),
            doc=_(u'Group description'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_(u'GID'),
            doc=_(u'GID (use this option to set it manually)'),
        ),
        parameters.Str(
            'member_user',
            required=False,
            label=_(u'Member users'),
        ),
        parameters.Str(
            'member_group',
            required=False,
            label=_(u'Member groups'),
        ),
        parameters.Str(
            'memberof_group',
            required=False,
            label=_(u'Member of groups'),
        ),
        parameters.Str(
            'memberof_role',
            required=False,
            label=_(u'Roles'),
        ),
        parameters.Str(
            'memberof_netgroup',
            required=False,
            label=_(u'Member of netgroups'),
        ),
        parameters.Str(
            'memberof_sudorule',
            required=False,
            label=_(u'Member of Sudo rule'),
        ),
        parameters.Str(
            'memberof_hbacrule',
            required=False,
            label=_(u'Member of HBAC rule'),
        ),
        parameters.Str(
            'memberindirect_user',
            required=False,
            label=_(u'Indirect Member users'),
        ),
        parameters.Str(
            'memberindirect_group',
            required=False,
            label=_(u'Indirect Member groups'),
        ),
        parameters.Str(
            'memberofindirect_group',
            required=False,
            label=_(u'Indirect Member of group'),
        ),
        parameters.Str(
            'memberofindirect_netgroup',
            required=False,
            label=_(u'Indirect Member of netgroup'),
        ),
        parameters.Str(
            'memberofindirect_role',
            required=False,
            label=_(u'Indirect Member of role'),
        ),
        parameters.Str(
            'memberofindirect_sudorule',
            required=False,
            label=_(u'Indirect Member of Sudo rule'),
        ),
        parameters.Str(
            'memberofindirect_hbacrule',
            required=False,
            label=_(u'Indirect Member of HBAC rule'),
        ),
    )


@register()
class group_add(Method):
    __doc__ = _("Create a new group.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='group_name',
            label=_(u'Group name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'Group description'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            cli_name='gid',
            label=_(u'GID'),
            doc=_(u'GID (use this option to set it manually)'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'nonposix',
            doc=_(u'Create as a non-POSIX group'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'external',
            doc=_(u'Allow adding external non-IPA members from trusted domains'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class group_add_member(Method):
    __doc__ = _("Add members to a group.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='group_name',
            label=_(u'Group name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'ipaexternalmember',
            required=False,
            multivalue=True,
            cli_name='external',
            label=_(u'External member'),
            doc=_(u'Members of a trusted domain in DOM\\name or name@domain form'),
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'member user'),
            doc=_(u'users to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'member group'),
            doc=_(u'groups to add'),
            alwaysask=True,
        ),
    )
    has_output = (
        output.Entry(
            'result',
        ),
        output.Output(
            'failed',
            dict,
            doc=_(u'Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members added'),
        ),
    )


@register()
class group_del(Method):
    __doc__ = _("Delete group.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='group_name',
            label=_(u'Group name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_(u'List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class group_detach(Method):
    __doc__ = _("Detach a managed group from a user.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='group_name',
            label=_(u'Group name'),
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class group_find(Method):
    __doc__ = _("Search for groups.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='group_name',
            label=_(u'Group name'),
            no_convert=True,
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'Group description'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            cli_name='gid',
            label=_(u'GID'),
            doc=_(u'GID (use this option to set it manually)'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned (0 is unlimited)'),
        ),
        parameters.Flag(
            'private',
            doc=_(u'search for private groups'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'posix',
            doc=_(u'search for POSIX groups'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'external',
            doc=_(u'search for groups with support of external non-IPA members from trusted domains'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'nonposix',
            doc=_(u'search for non-POSIX groups'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("group-name")'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'user'),
            doc=_(u'Search for groups with these member users.'),
        ),
        parameters.Str(
            'no_user',
            required=False,
            multivalue=True,
            cli_name='no_users',
            label=_(u'user'),
            doc=_(u'Search for groups without these member users.'),
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'group'),
            doc=_(u'Search for groups with these member groups.'),
        ),
        parameters.Str(
            'no_group',
            required=False,
            multivalue=True,
            cli_name='no_groups',
            label=_(u'group'),
            doc=_(u'Search for groups without these member groups.'),
        ),
        parameters.Str(
            'in_group',
            required=False,
            multivalue=True,
            cli_name='in_groups',
            label=_(u'group'),
            doc=_(u'Search for groups with these member of groups.'),
        ),
        parameters.Str(
            'not_in_group',
            required=False,
            multivalue=True,
            cli_name='not_in_groups',
            label=_(u'group'),
            doc=_(u'Search for groups without these member of groups.'),
        ),
        parameters.Str(
            'in_netgroup',
            required=False,
            multivalue=True,
            cli_name='in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for groups with these member of netgroups.'),
        ),
        parameters.Str(
            'not_in_netgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for groups without these member of netgroups.'),
        ),
        parameters.Str(
            'in_role',
            required=False,
            multivalue=True,
            cli_name='in_roles',
            label=_(u'role'),
            doc=_(u'Search for groups with these member of roles.'),
        ),
        parameters.Str(
            'not_in_role',
            required=False,
            multivalue=True,
            cli_name='not_in_roles',
            label=_(u'role'),
            doc=_(u'Search for groups without these member of roles.'),
        ),
        parameters.Str(
            'in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for groups with these member of HBAC rules.'),
        ),
        parameters.Str(
            'not_in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='not_in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for groups without these member of HBAC rules.'),
        ),
        parameters.Str(
            'in_sudorule',
            required=False,
            multivalue=True,
            cli_name='in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for groups with these member of sudo rules.'),
        ),
        parameters.Str(
            'not_in_sudorule',
            required=False,
            multivalue=True,
            cli_name='not_in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for groups without these member of sudo rules.'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_(u'True if not all results were returned'),
        ),
    )


@register()
class group_mod(Method):
    __doc__ = _("Modify a group.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='group_name',
            label=_(u'Group name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'Group description'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            cli_name='gid',
            label=_(u'GID'),
            doc=_(u'GID (use this option to set it manually)'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(u'Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'posix',
            doc=_(u'change to a POSIX group'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'external',
            doc=_(u'change to support external non-IPA members from trusted domains'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'rename',
            required=False,
            label=_(u'Rename'),
            doc=_(u'Rename the group object'),
            no_convert=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class group_remove_member(Method):
    __doc__ = _("Remove members from a group.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='group_name',
            label=_(u'Group name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'ipaexternalmember',
            required=False,
            multivalue=True,
            cli_name='external',
            label=_(u'External member'),
            doc=_(u'Members of a trusted domain in DOM\\name or name@domain form'),
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_(u'member user'),
            doc=_(u'users to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_(u'member group'),
            doc=_(u'groups to remove'),
            alwaysask=True,
        ),
    )
    has_output = (
        output.Entry(
            'result',
        ),
        output.Output(
            'failed',
            dict,
            doc=_(u'Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members removed'),
        ),
    )


@register()
class group_show(Method):
    __doc__ = _("Display information about a named group.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='group_name',
            label=_(u'Group name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
