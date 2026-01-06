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

unicode = str

__doc__ = _("""
Permissions

A permission enables fine-grained delegation of rights. A permission is
a human-readable wrapper around a 389-ds Access Control Rule,
or instruction (ACI).
A permission grants the right to perform a specific task such as adding a
user, modifying a group, etc.

A permission may not contain other permissions.

* A permission grants access to read, write, add, delete, read, search,
  or compare.
* A privilege combines similar permissions (for example all the permissions
  needed to add a user).
* A role grants a set of privileges to users, groups, hosts or hostgroups.

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

EXAMPLES:

 Add a permission that grants the creation of users:
   ipa permission-add --type=user --permissions=add "Add Users"

 Add a permission that grants the ability to manage group membership:
   ipa permission-add --attrs=member --permissions=write --type=group "Manage Group Members"
""")

register = Registry()


@register()
class permission(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_('Permission name'),
        ),
        parameters.Str(
            'ipapermright',
            required=False,
            multivalue=True,
            label=_('Granted rights'),
            doc=_('Rights to grant (read, search, compare, write, add, delete, all)'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_('Effective attributes'),
            doc=_('All attributes to which the permission applies'),
        ),
        parameters.Str(
            'ipapermincludedattr',
            required=False,
            multivalue=True,
            label=_('Included attributes'),
            doc=_('User-specified attributes to which the permission applies'),
        ),
        parameters.Str(
            'ipapermexcludedattr',
            required=False,
            multivalue=True,
            label=_('Excluded attributes'),
            doc=_('User-specified attributes to which the permission explicitly does not apply'),
        ),
        parameters.Str(
            'ipapermdefaultattr',
            required=False,
            multivalue=True,
            label=_('Default attributes'),
            doc=_('Attributes to which the permission applies by default'),
        ),
        parameters.Str(
            'ipapermbindruletype',
            label=_('Bind rule type'),
        ),
        parameters.Str(
            'ipapermlocation',
            required=False,
            label=_('Subtree'),
            doc=_('Subtree to apply permissions to'),
        ),
        parameters.Str(
            'extratargetfilter',
            required=False,
            multivalue=True,
            label=_('Extra target filter'),
        ),
        parameters.Str(
            'ipapermtargetfilter',
            required=False,
            multivalue=True,
            label=_('Raw target filter'),
            doc=_('All target filters, including those implied by type and memberof'),
        ),
        parameters.DNParam(
            'ipapermtarget',
            required=False,
            label=_('Target DN'),
            doc=_('Optional DN to apply the permission to (must be in the subtree, but may not yet exist)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            multivalue=True,
            label=_('Member of group'),
            doc=_('Target members of a group (sets memberOf targetfilter)'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_('Target group'),
            doc=_('User group to apply permissions to (sets target)'),
        ),
        parameters.Str(
            'type',
            required=False,
            label=_('Type'),
            doc=_('Type of IPA object (sets subtree and objectClass targetfilter)'),
        ),
        parameters.Str(
            'filter',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use extratargetfilter'),
        ),
        parameters.Str(
            'subtree',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use ipapermlocation'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use ipapermright'),
        ),
        parameters.Str(
            'member_privilege',
            required=False,
            label=_('Granted to Privilege'),
        ),
        parameters.Str(
            'memberindirect_role',
            required=False,
            label=_('Indirect Member of roles'),
        ),
    )


@register()
class permission_add(Method):
    __doc__ = _("Add a new permission.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Permission name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipapermright',
            required=False,
            multivalue=True,
            cli_name='right',
            cli_metavar="['read', 'search', 'compare', 'write', 'add', 'delete', 'all']",
            label=_('Granted rights'),
            doc=_('Rights to grant (read, search, compare, write, add, delete, all)'),
            alwaysask=True,
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_('Effective attributes'),
            doc=_('All attributes to which the permission applies'),
        ),
        parameters.Str(
            'ipapermbindruletype',
            cli_name='bindtype',
            cli_metavar="['permission', 'all', 'anonymous']",
            label=_('Bind rule type'),
            default='permission',
            autofill=True,
        ),
        parameters.Str(
            'ipapermlocation',
            required=False,
            cli_name='subtree',
            label=_('Subtree'),
            doc=_('Subtree to apply permissions to'),
            alwaysask=True,
        ),
        parameters.Str(
            'extratargetfilter',
            required=False,
            multivalue=True,
            cli_name='filter',
            label=_('Extra target filter'),
        ),
        parameters.Str(
            'ipapermtargetfilter',
            required=False,
            multivalue=True,
            cli_name='rawfilter',
            label=_('Raw target filter'),
            doc=_('All target filters, including those implied by type and memberof'),
        ),
        parameters.DNParam(
            'ipapermtarget',
            required=False,
            cli_name='target',
            label=_('Target DN'),
            doc=_('Optional DN to apply the permission to (must be in the subtree, but may not yet exist)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            multivalue=True,
            label=_('Member of group'),
            doc=_('Target members of a group (sets memberOf targetfilter)'),
            alwaysask=True,
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_('Target group'),
            doc=_('User group to apply permissions to (sets target)'),
            alwaysask=True,
        ),
        parameters.Str(
            'type',
            required=False,
            label=_('Type'),
            doc=_('Type of IPA object (sets subtree and objectClass targetfilter)'),
            alwaysask=True,
        ),
        parameters.Str(
            'filter',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use extratargetfilter'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'subtree',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use ipapermlocation'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use ipapermright'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class permission_add_member(Method):
    __doc__ = _("Add members to a permission.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Permission name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'privilege',
            required=False,
            multivalue=True,
            cli_name='privileges',
            label=_('member privilege'),
            doc=_('privileges to add'),
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
            doc=_('Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members added'),
        ),
    )


@register()
class permission_add_noaci(Method):
    __doc__ = _("Add a system permission without an ACI (internal command)")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Permission name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipapermissiontype',
            multivalue=True,
            label=_('Permission flags'),
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class permission_del(Method):
    __doc__ = _("Delete a permission.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_('Permission name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'force',
            label=_('Force'),
            doc=_('force delete of SYSTEM permissions'),
            exclude=('cli', 'webui'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_('List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class permission_find(Method):
    __doc__ = _("Search for permissions.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='name',
            label=_('Permission name'),
        ),
        parameters.Str(
            'ipapermright',
            required=False,
            multivalue=True,
            cli_name='right',
            cli_metavar="['read', 'search', 'compare', 'write', 'add', 'delete', 'all']",
            label=_('Granted rights'),
            doc=_('Rights to grant (read, search, compare, write, add, delete, all)'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_('Effective attributes'),
            doc=_('All attributes to which the permission applies'),
        ),
        parameters.Str(
            'ipapermincludedattr',
            required=False,
            multivalue=True,
            cli_name='includedattrs',
            label=_('Included attributes'),
            doc=_('User-specified attributes to which the permission applies'),
        ),
        parameters.Str(
            'ipapermexcludedattr',
            required=False,
            multivalue=True,
            cli_name='excludedattrs',
            label=_('Excluded attributes'),
            doc=_('User-specified attributes to which the permission explicitly does not apply'),
        ),
        parameters.Str(
            'ipapermdefaultattr',
            required=False,
            multivalue=True,
            cli_name='defaultattrs',
            label=_('Default attributes'),
            doc=_('Attributes to which the permission applies by default'),
        ),
        parameters.Str(
            'ipapermbindruletype',
            required=False,
            cli_name='bindtype',
            cli_metavar="['permission', 'all', 'anonymous']",
            label=_('Bind rule type'),
            default='permission',
        ),
        parameters.Str(
            'ipapermlocation',
            required=False,
            cli_name='subtree',
            label=_('Subtree'),
            doc=_('Subtree to apply permissions to'),
        ),
        parameters.Str(
            'extratargetfilter',
            required=False,
            multivalue=True,
            cli_name='filter',
            label=_('Extra target filter'),
        ),
        parameters.Str(
            'ipapermtargetfilter',
            required=False,
            multivalue=True,
            cli_name='rawfilter',
            label=_('Raw target filter'),
            doc=_('All target filters, including those implied by type and memberof'),
        ),
        parameters.DNParam(
            'ipapermtarget',
            required=False,
            cli_name='target',
            label=_('Target DN'),
            doc=_('Optional DN to apply the permission to (must be in the subtree, but may not yet exist)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            multivalue=True,
            label=_('Member of group'),
            doc=_('Target members of a group (sets memberOf targetfilter)'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_('Target group'),
            doc=_('User group to apply permissions to (sets target)'),
        ),
        parameters.Str(
            'type',
            required=False,
            label=_('Type'),
            doc=_('Type of IPA object (sets subtree and objectClass targetfilter)'),
        ),
        parameters.Str(
            'filter',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use extratargetfilter'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'subtree',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use ipapermlocation'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use ipapermright'),
            exclude=('cli', 'webui'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned'),
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("name")'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_('Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_('True if not all results were returned'),
        ),
    )


@register()
class permission_mod(Method):
    __doc__ = _("Modify a permission.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Permission name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'ipapermright',
            required=False,
            multivalue=True,
            cli_name='right',
            cli_metavar="['read', 'search', 'compare', 'write', 'add', 'delete', 'all']",
            label=_('Granted rights'),
            doc=_('Rights to grant (read, search, compare, write, add, delete, all)'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_('Effective attributes'),
            doc=_('All attributes to which the permission applies'),
        ),
        parameters.Str(
            'ipapermincludedattr',
            required=False,
            multivalue=True,
            cli_name='includedattrs',
            label=_('Included attributes'),
            doc=_('User-specified attributes to which the permission applies'),
        ),
        parameters.Str(
            'ipapermexcludedattr',
            required=False,
            multivalue=True,
            cli_name='excludedattrs',
            label=_('Excluded attributes'),
            doc=_('User-specified attributes to which the permission explicitly does not apply'),
        ),
        parameters.Str(
            'ipapermbindruletype',
            required=False,
            cli_name='bindtype',
            cli_metavar="['permission', 'all', 'anonymous']",
            label=_('Bind rule type'),
            default='permission',
        ),
        parameters.Str(
            'ipapermlocation',
            required=False,
            cli_name='subtree',
            label=_('Subtree'),
            doc=_('Subtree to apply permissions to'),
        ),
        parameters.Str(
            'extratargetfilter',
            required=False,
            multivalue=True,
            cli_name='filter',
            label=_('Extra target filter'),
        ),
        parameters.Str(
            'ipapermtargetfilter',
            required=False,
            multivalue=True,
            cli_name='rawfilter',
            label=_('Raw target filter'),
            doc=_('All target filters, including those implied by type and memberof'),
        ),
        parameters.DNParam(
            'ipapermtarget',
            required=False,
            cli_name='target',
            label=_('Target DN'),
            doc=_('Optional DN to apply the permission to (must be in the subtree, but may not yet exist)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            multivalue=True,
            label=_('Member of group'),
            doc=_('Target members of a group (sets memberOf targetfilter)'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_('Target group'),
            doc=_('User group to apply permissions to (sets target)'),
        ),
        parameters.Str(
            'type',
            required=False,
            label=_('Type'),
            doc=_('Type of IPA object (sets subtree and objectClass targetfilter)'),
        ),
        parameters.Str(
            'filter',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use extratargetfilter'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'subtree',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use ipapermlocation'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            doc=_('Deprecated; use ipapermright'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_('Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'rename',
            required=False,
            label=_('Rename'),
            doc=_('Rename the permission object'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class permission_remove_member(Method):
    __doc__ = _("Remove members from a permission.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Permission name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'privilege',
            required=False,
            multivalue=True,
            cli_name='privileges',
            label=_('member privilege'),
            doc=_('privileges to remove'),
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
            doc=_('Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_('Number of members removed'),
        ),
    )


@register()
class permission_show(Method):
    __doc__ = _("Display information about a permission.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Permission name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_('Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
