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

__doc__ = _("""
Permissions

A permission enables fine-grained delegation of rights. A permission is
a human-readable form of a 389-ds Access Control Rule, or instruction (ACI).
A permission grants the right to perform a specific task such as adding a
user, modifying a group, etc.

A permission may not contain other permissions.

* A permission grants access to read, write, add or delete.
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
3. add - add a new entry to the tree
4. delete - delete an existing entry
5. all - all permissions are granted

Read permission is granted for most attributes by default so the read
permission is not expected to be used very often.

Note the distinction between attributes and entries. The permissions are
independent, so being able to add a user does not mean that the user will
be editable.

There are a number of allowed targets:
1. type: a type of object (user, group, etc).
2. memberof: a member of a group or hostgroup
3. filter: an LDAP filter
4. subtree: an LDAP filter specifying part of the LDAP DIT. This is a
   super-set of the "type" target.
5. targetgroup: grant access to modify a specific group (such as granting
   the rights to manage group membership)

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
            label=_(u'Permission name'),
        ),
        parameters.Str(
            'permissions',
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'Comma-separated list of permissions to grant (read, write, add, delete, all)'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_(u'Attributes'),
            doc=_(u'Comma-separated list of attributes'),
        ),
        parameters.Str(
            'type',
            required=False,
            label=_(u'Type'),
            doc=_(u'Type of IPA object (user, group, host, hostgroup, service, netgroup, dns)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of group'),
            doc=_(u'Target members of a group'),
        ),
        parameters.Str(
            'filter',
            required=False,
            label=_(u'Filter'),
            doc=_(u'Legal LDAP filter (e.g. ou=Engineering)'),
        ),
        parameters.Str(
            'subtree',
            required=False,
            label=_(u'Subtree'),
            doc=_(u'Subtree to apply permissions to'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'User group to apply permissions to'),
        ),
        parameters.Str(
            'member_privilege',
            required=False,
            label=_(u'Granted to Privilege'),
        ),
        parameters.Str(
            'memberindirect_role',
            required=False,
            label=_(u'Indirect Member of roles'),
        ),
    )


@register()
class permission_add(Method):
    __doc__ = _("Add a new permission.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Permission name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'permissions',
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'Comma-separated list of permissions to grant (read, write, add, delete, all)'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_(u'Attributes'),
            doc=_(u'Comma-separated list of attributes'),
            alwaysask=True,
            no_convert=True,
        ),
        parameters.Str(
            'type',
            required=False,
            cli_metavar="['user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord']",
            label=_(u'Type'),
            doc=_(u'Type of IPA object (user, group, host, hostgroup, service, netgroup, dns)'),
            alwaysask=True,
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of group'),
            doc=_(u'Target members of a group'),
            alwaysask=True,
        ),
        parameters.Str(
            'filter',
            required=False,
            label=_(u'Filter'),
            doc=_(u'Legal LDAP filter (e.g. ou=Engineering)'),
            alwaysask=True,
        ),
        parameters.Str(
            'subtree',
            required=False,
            label=_(u'Subtree'),
            doc=_(u'Subtree to apply permissions to'),
            alwaysask=True,
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'User group to apply permissions to'),
            alwaysask=True,
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
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
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
            label=_(u'Permission name'),
        ),
    )
    takes_options = (
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
        parameters.Str(
            'privilege',
            required=False,
            multivalue=True,
            cli_name='privileges',
            label=_(u'member privilege'),
            doc=_(u'comma-separated list of privileges to add'),
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
class permission_add_noaci(Method):
    __doc__ = _("Add a system permission without an ACI")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Permission name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'permissiontype',
            required=False,
            cli_metavar="['SYSTEM']",
            label=_(u'Permission type'),
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
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
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
            label=_(u'Permission name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'force',
            label=_(u'Force'),
            doc=_(u'force delete of SYSTEM permissions'),
            exclude=('cli', 'webui'),
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
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class permission_find(Method):
    __doc__ = _("Search for permissions.")

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
            cli_name='name',
            label=_(u'Permission name'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'Comma-separated list of permissions to grant (read, write, add, delete, all)'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_(u'Attributes'),
            doc=_(u'Comma-separated list of attributes'),
            no_convert=True,
        ),
        parameters.Str(
            'type',
            required=False,
            cli_metavar="['user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord']",
            label=_(u'Type'),
            doc=_(u'Type of IPA object (user, group, host, hostgroup, service, netgroup, dns)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of group'),
            doc=_(u'Target members of a group'),
        ),
        parameters.Str(
            'filter',
            required=False,
            label=_(u'Filter'),
            doc=_(u'Legal LDAP filter (e.g. ou=Engineering)'),
        ),
        parameters.Str(
            'subtree',
            required=False,
            label=_(u'Subtree'),
            doc=_(u'Subtree to apply permissions to'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'User group to apply permissions to'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned'),
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
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("name")'),
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
class permission_mod(Method):
    __doc__ = _("Modify a permission.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Permission name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'Comma-separated list of permissions to grant (read, write, add, delete, all)'),
        ),
        parameters.Str(
            'attrs',
            required=False,
            multivalue=True,
            label=_(u'Attributes'),
            doc=_(u'Comma-separated list of attributes'),
            no_convert=True,
        ),
        parameters.Str(
            'type',
            required=False,
            cli_metavar="['user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord']",
            label=_(u'Type'),
            doc=_(u'Type of IPA object (user, group, host, hostgroup, service, netgroup, dns)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of group'),
            doc=_(u'Target members of a group'),
        ),
        parameters.Str(
            'filter',
            required=False,
            label=_(u'Filter'),
            doc=_(u'Legal LDAP filter (e.g. ou=Engineering)'),
        ),
        parameters.Str(
            'subtree',
            required=False,
            label=_(u'Subtree'),
            doc=_(u'Subtree to apply permissions to'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'User group to apply permissions to'),
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
        parameters.Str(
            'rename',
            required=False,
            label=_(u'Rename'),
            doc=_(u'Rename the permission object'),
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
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
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
            label=_(u'Permission name'),
        ),
    )
    takes_options = (
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
        parameters.Str(
            'privilege',
            required=False,
            multivalue=True,
            cli_name='privileges',
            label=_(u'member privilege'),
            doc=_(u'comma-separated list of privileges to remove'),
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
class permission_show(Method):
    __doc__ = _("Display information about a permission.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Permission name'),
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
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
