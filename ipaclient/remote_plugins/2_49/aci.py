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
Directory Server Access Control Instructions (ACIs)

ACIs are used to allow or deny access to information. This module is
currently designed to allow, not deny, access.

The aci commands are designed to grant permissions that allow updating
existing entries or adding or deleting new ones. The goal of the ACIs
that ship with IPA is to provide a set of low-level permissions that
grant access to special groups called taskgroups. These low-level
permissions can be combined into roles that grant broader access. These
roles are another type of group, roles.

For example, if you have taskgroups that allow adding and modifying users you
could create a role, useradmin. You would assign users to the useradmin
role to allow them to do the operations defined by the taskgroups.

You can create ACIs that delegate permission so users in group A can write
attributes on group B.

The type option is a map that applies to all entries in the users, groups or
host location. It is primarily designed to be used when granting add
permissions (to write new entries).

An ACI consists of three parts:
1. target
2. permissions
3. bind rules

The target is a set of rules that define which LDAP objects are being
targeted. This can include a list of attributes, an area of that LDAP
tree or an LDAP filter.

The targets include:
- attrs: list of attributes affected
- type: an object type (user, group, host, service, etc)
- memberof: members of a group
- targetgroup: grant access to modify a specific group. This is primarily
  designed to enable users to add or remove members of a specific group.
- filter: A legal LDAP filter used to narrow the scope of the target.
- subtree: Used to apply a rule across an entire set of objects. For example,
  to allow adding users you need to grant "add" permission to the subtree
  ldap://uid=*,cn=users,cn=accounts,dc=example,dc=com. The subtree option
  is a fail-safe for objects that may not be covered by the type option.

The permissions define what the ACI is allowed to do, and are one or
more of:
1. write - write one or more attributes
2. read - read one or more attributes
3. add - add a new entry to the tree
4. delete - delete an existing entry
5. all - all permissions are granted

Note the distinction between attributes and entries. The permissions are
independent, so being able to add a user does not mean that the user will
be editable.

The bind rule defines who this ACI grants permissions to. The LDAP server
allows this to be any valid LDAP entry but we encourage the use of
taskgroups so that the rights can be easily shared through roles.

For a more thorough description of access controls see
http://www.redhat.com/docs/manuals/dir-server/ag/8.0/Managing_Access_Control.html

EXAMPLES:

NOTE: ACIs are now added via the permission plugin. These examples are to
demonstrate how the various options work but this is done via the permission
command-line now (see last example).

 Add an ACI so that the group "secretaries" can update the address on any user:
   ipa group-add --desc="Office secretaries" secretaries
   ipa aci-add --attrs=streetAddress --memberof=ipausers --group=secretaries --permissions=write --prefix=none "Secretaries write addresses"

 Show the new ACI:
   ipa aci-show --prefix=none "Secretaries write addresses"

 Add an ACI that allows members of the "addusers" permission to add new users:
   ipa aci-add --type=user --permission=addusers --permissions=add --prefix=none "Add new users"

 Add an ACI that allows members of the editors manage members of the admins group:
   ipa aci-add --permissions=write --attrs=member --targetgroup=admins --group=editors --prefix=none "Editors manage admins"

 Add an ACI that allows members of the admins group to manage the street and zip code of those in the editors group:
   ipa aci-add --permissions=write --memberof=editors --group=admins --attrs=street,postalcode --prefix=none "admins edit the address of editors"

 Add an ACI that allows the admins group manage the street and zipcode of those who work for the boss:
   ipa aci-add --permissions=write --group=admins --attrs=street,postalcode --filter="(manager=uid=boss,cn=users,cn=accounts,dc=example,dc=com)" --prefix=none "Edit the address of those who work for the boss"

 Add an entirely new kind of record to IPA that isn't covered by any of the --type options, creating a permission:
   ipa permission-add  --permissions=add --subtree="cn=*,cn=orange,cn=accounts,dc=example,dc=com" --desc="Add Orange Entries" add_orange


The show command shows the raw 389-ds ACI.

IMPORTANT: When modifying the target attributes of an existing ACI you
must include all existing attributes as well. When doing an aci-mod the
targetattr REPLACES the current attributes, it does not add to them.
""")

register = Registry()


@register()
class aci(Object):
    takes_params = (
        parameters.Str(
            'aciname',
            primary_key=True,
            label=_(u'ACI name'),
        ),
        parameters.Str(
            'permission',
            required=False,
            label=_(u'Permission'),
            doc=_(u'Permission ACI grants access to'),
        ),
        parameters.Str(
            'group',
            required=False,
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
        ),
        parameters.Str(
            'permissions',
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'comma-separated list of permissions to grant(read, write, add, delete, all)'),
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
            doc=_(u'type of IPA object (user, group, host, hostgroup, service, netgroup)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of'),
            doc=_(u'Member of a group'),
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
            doc=_(u'Subtree to apply ACI to'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'Group to apply ACI to'),
        ),
        parameters.Flag(
            'selfaci',
            required=False,
            label=_(u'Target your own entry (self)'),
            doc=_(u'Apply ACI to your own entry (self)'),
        ),
    )


@register()
class aci_add(Method):
    __doc__ = _("Create new ACI.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'ACI name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'permission',
            required=False,
            label=_(u'Permission'),
            doc=_(u'Permission ACI grants access to'),
        ),
        parameters.Str(
            'group',
            required=False,
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
        ),
        parameters.Str(
            'permissions',
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'comma-separated list of permissions to grant(read, write, add, delete, all)'),
            no_convert=True,
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
            cli_metavar="['user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord']",
            label=_(u'Type'),
            doc=_(u'type of IPA object (user, group, host, hostgroup, service, netgroup)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of'),
            doc=_(u'Member of a group'),
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
            doc=_(u'Subtree to apply ACI to'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'Group to apply ACI to'),
        ),
        parameters.Flag(
            'selfaci',
            required=False,
            cli_name='self',
            label=_(u'Target your own entry (self)'),
            doc=_(u'Apply ACI to your own entry (self)'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'aciprefix',
            cli_name='prefix',
            cli_metavar="['permission', 'delegation', 'selfservice', 'none']",
            label=_(u'ACI prefix'),
            doc=_(u'Prefix used to distinguish ACI types (permission, delegation, selfservice, none)'),
        ),
        parameters.Flag(
            'test',
            required=False,
            doc=_(u"Test the ACI syntax but don't write anything"),
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


@register()
class aci_del(Method):
    __doc__ = _("Delete ACI.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'ACI name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'aciprefix',
            cli_name='prefix',
            cli_metavar="['permission', 'delegation', 'selfservice', 'none']",
            label=_(u'ACI prefix'),
            doc=_(u'Prefix used to distinguish ACI types (permission, delegation, selfservice, none)'),
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
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class aci_find(Method):
    __doc__ = _("""
Search for ACIs.

    Returns a list of ACIs

    EXAMPLES:

     To find all ACIs that apply directly to members of the group ipausers:
       ipa aci-find --memberof=ipausers

     To find all ACIs that grant add access:
       ipa aci-find --permissions=add

    Note that the find command only looks for the given text in the set of
    ACIs, it does not evaluate the ACIs to see if something would apply.
    For example, searching on memberof=ipausers will find all ACIs that
    have ipausers as a memberof. There may be other ACIs that apply to
    members of that group indirectly.
    """)

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
        ),
    )
    takes_options = (
        parameters.Str(
            'aciname',
            required=False,
            cli_name='name',
            label=_(u'ACI name'),
        ),
        parameters.Str(
            'permission',
            required=False,
            label=_(u'Permission'),
            doc=_(u'Permission ACI grants access to'),
        ),
        parameters.Str(
            'group',
            required=False,
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'comma-separated list of permissions to grant(read, write, add, delete, all)'),
            no_convert=True,
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
            cli_metavar="['user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord']",
            label=_(u'Type'),
            doc=_(u'type of IPA object (user, group, host, hostgroup, service, netgroup)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of'),
            doc=_(u'Member of a group'),
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
            doc=_(u'Subtree to apply ACI to'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'Group to apply ACI to'),
        ),
        parameters.Bool(
            'selfaci',
            required=False,
            cli_name='self',
            label=_(u'Target your own entry (self)'),
            doc=_(u'Apply ACI to your own entry (self)'),
            default=False,
        ),
        parameters.Str(
            'aciprefix',
            required=False,
            cli_name='prefix',
            cli_metavar="['permission', 'delegation', 'selfservice', 'none']",
            label=_(u'ACI prefix'),
            doc=_(u'Prefix used to distinguish ACI types (permission, delegation, selfservice, none)'),
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("name")'),
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
class aci_mod(Method):
    __doc__ = _("Modify ACI.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'ACI name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'permission',
            required=False,
            label=_(u'Permission'),
            doc=_(u'Permission ACI grants access to'),
        ),
        parameters.Str(
            'group',
            required=False,
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'comma-separated list of permissions to grant(read, write, add, delete, all)'),
            no_convert=True,
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
            cli_metavar="['user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord']",
            label=_(u'Type'),
            doc=_(u'type of IPA object (user, group, host, hostgroup, service, netgroup)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of'),
            doc=_(u'Member of a group'),
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
            doc=_(u'Subtree to apply ACI to'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'Group to apply ACI to'),
        ),
        parameters.Flag(
            'selfaci',
            required=False,
            cli_name='self',
            label=_(u'Target your own entry (self)'),
            doc=_(u'Apply ACI to your own entry (self)'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'aciprefix',
            cli_name='prefix',
            cli_metavar="['permission', 'delegation', 'selfservice', 'none']",
            label=_(u'ACI prefix'),
            doc=_(u'Prefix used to distinguish ACI types (permission, delegation, selfservice, none)'),
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
class aci_rename(Method):
    __doc__ = _("Rename an ACI.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'ACI name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'permission',
            required=False,
            label=_(u'Permission'),
            doc=_(u'Permission ACI grants access to'),
        ),
        parameters.Str(
            'group',
            required=False,
            label=_(u'User group'),
            doc=_(u'User group ACI grants access to'),
        ),
        parameters.Str(
            'permissions',
            required=False,
            multivalue=True,
            label=_(u'Permissions'),
            doc=_(u'comma-separated list of permissions to grant(read, write, add, delete, all)'),
            no_convert=True,
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
            cli_metavar="['user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord']",
            label=_(u'Type'),
            doc=_(u'type of IPA object (user, group, host, hostgroup, service, netgroup)'),
        ),
        parameters.Str(
            'memberof',
            required=False,
            label=_(u'Member of'),
            doc=_(u'Member of a group'),
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
            doc=_(u'Subtree to apply ACI to'),
        ),
        parameters.Str(
            'targetgroup',
            required=False,
            label=_(u'Target group'),
            doc=_(u'Group to apply ACI to'),
        ),
        parameters.Flag(
            'selfaci',
            required=False,
            cli_name='self',
            label=_(u'Target your own entry (self)'),
            doc=_(u'Apply ACI to your own entry (self)'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'aciprefix',
            cli_name='prefix',
            cli_metavar="['permission', 'delegation', 'selfservice', 'none']",
            label=_(u'ACI prefix'),
            doc=_(u'Prefix used to distinguish ACI types (permission, delegation, selfservice, none)'),
        ),
        parameters.Str(
            'newname',
            doc=_(u'New ACI name'),
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
class aci_show(Method):
    __doc__ = _("Display a single ACI given an ACI name.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'aciname',
            cli_name='name',
            label=_(u'ACI name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'aciprefix',
            cli_name='prefix',
            cli_metavar="['permission', 'delegation', 'selfservice', 'none']",
            label=_(u'ACI prefix'),
            doc=_(u'Prefix used to distinguish ACI types (permission, delegation, selfservice, none)'),
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
