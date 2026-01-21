#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

__doc__ = _("""
Netgroups

A netgroup is a group used for permission checking. It can contain both
user and host values.

EXAMPLES:

 Add a new netgroup:
   ipa netgroup-add --desc="NFS admins" admins

 Add members to the netgroup:
   ipa netgroup-add-member --users=tuser1 --users=tuser2 admins

 Remove a member from the netgroup:
   ipa netgroup-remove-member --users=tuser2 admins

 Display information about a netgroup:
   ipa netgroup-show admins

 Delete a netgroup:
   ipa netgroup-del admins
""")

register = Registry()


@register()
class netgroup(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_('Netgroup name'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_('Description'),
            doc=_('Netgroup description'),
        ),
        parameters.Str(
            'nisdomainname',
            required=False,
            label=_('NIS domain name'),
        ),
        parameters.Str(
            'ipauniqueid',
            required=False,
            label=_('IPA unique ID'),
            doc=_('IPA unique ID'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            label=_('User category'),
            doc=_('User category the rule applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_('External host'),
        ),
        parameters.Str(
            'member_netgroup',
            required=False,
            label=_('Member netgroups'),
        ),
        parameters.Str(
            'memberof_netgroup',
            required=False,
            label=_('Member of netgroups'),
        ),
        parameters.Str(
            'memberindirect_netgroup',
            required=False,
            label=_('Indirect Member netgroups'),
        ),
        parameters.Str(
            'memberuser_user',
            required=False,
            label=_('Member User'),
        ),
        parameters.Str(
            'memberuser_group',
            required=False,
            label=_('Member Group'),
        ),
        parameters.Str(
            'memberhost_host',
            required=False,
            label=_('Member Host'),
        ),
        parameters.Str(
            'memberhost_hostgroup',
            required=False,
            label=_('Member Hostgroup'),
        ),
    )


@register()
class netgroup_add(Method):
    __doc__ = _("Add a new netgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Netgroup name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('Netgroup description'),
        ),
        parameters.Str(
            'nisdomainname',
            required=False,
            cli_name='nisdomain',
            label=_('NIS domain name'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_('User category'),
            doc=_('User category the rule applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_('External host'),
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
            (str, type(None)),
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
class netgroup_add_member(Method):
    __doc__ = _("Add members to a netgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Netgroup name'),
            no_convert=True,
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
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('member user'),
            doc=_('users to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_('member group'),
            doc=_('groups to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('hosts to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('member host group'),
            doc=_('host groups to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'netgroup',
            required=False,
            multivalue=True,
            cli_name='netgroups',
            label=_('member netgroup'),
            doc=_('netgroups to add'),
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
class netgroup_del(Method):
    __doc__ = _("Delete a netgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_('Netgroup name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
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
class netgroup_find(Method):
    __doc__ = _("Search for a netgroup.")

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
            label=_('Netgroup name'),
            no_convert=True,
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('Netgroup description'),
        ),
        parameters.Str(
            'nisdomainname',
            required=False,
            cli_name='nisdomain',
            label=_('NIS domain name'),
        ),
        parameters.Str(
            'ipauniqueid',
            required=False,
            cli_name='uuid',
            label=_('IPA unique ID'),
            doc=_('IPA unique ID'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_('User category'),
            doc=_('User category the rule applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_('External host'),
            exclude=('cli', 'webui'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
        ),
        parameters.Flag(
            'private',
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'managed',
            doc=_('search for managed groups'),
            default=False,
            default_from=DefaultFrom(lambda private: private),
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
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("name")'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'netgroup',
            required=False,
            multivalue=True,
            cli_name='netgroups',
            label=_('netgroup'),
            doc=_('Search for netgroups with these member netgroups.'),
        ),
        parameters.Str(
            'no_netgroup',
            required=False,
            multivalue=True,
            cli_name='no_netgroups',
            label=_('netgroup'),
            doc=_('Search for netgroups without these member netgroups.'),
        ),
        parameters.Str(
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('user'),
            doc=_('Search for netgroups with these member users.'),
        ),
        parameters.Str(
            'no_user',
            required=False,
            multivalue=True,
            cli_name='no_users',
            label=_('user'),
            doc=_('Search for netgroups without these member users.'),
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_('group'),
            doc=_('Search for netgroups with these member groups.'),
        ),
        parameters.Str(
            'no_group',
            required=False,
            multivalue=True,
            cli_name='no_groups',
            label=_('group'),
            doc=_('Search for netgroups without these member groups.'),
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('host'),
            doc=_('Search for netgroups with these member hosts.'),
        ),
        parameters.Str(
            'no_host',
            required=False,
            multivalue=True,
            cli_name='no_hosts',
            label=_('host'),
            doc=_('Search for netgroups without these member hosts.'),
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('host group'),
            doc=_('Search for netgroups with these member host groups.'),
        ),
        parameters.Str(
            'no_hostgroup',
            required=False,
            multivalue=True,
            cli_name='no_hostgroups',
            label=_('host group'),
            doc=_('Search for netgroups without these member host groups.'),
        ),
        parameters.Str(
            'in_netgroup',
            required=False,
            multivalue=True,
            cli_name='in_netgroups',
            label=_('netgroup'),
            doc=_('Search for netgroups with these member of netgroups.'),
        ),
        parameters.Str(
            'not_in_netgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_netgroups',
            label=_('netgroup'),
            doc=_('Search for netgroups without these member of netgroups.'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
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
class netgroup_mod(Method):
    __doc__ = _("Modify a netgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Netgroup name'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('Netgroup description'),
        ),
        parameters.Str(
            'nisdomainname',
            required=False,
            cli_name='nisdomain',
            label=_('NIS domain name'),
        ),
        parameters.Str(
            'usercategory',
            required=False,
            cli_name='usercat',
            cli_metavar="['all']",
            label=_('User category'),
            doc=_('User category the rule applies to'),
        ),
        parameters.Str(
            'hostcategory',
            required=False,
            cli_name='hostcat',
            cli_metavar="['all']",
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
        ),
        parameters.Str(
            'externalhost',
            required=False,
            multivalue=True,
            label=_('External host'),
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
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
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
class netgroup_remove_member(Method):
    __doc__ = _("Remove members from a netgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Netgroup name'),
            no_convert=True,
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
            'user',
            required=False,
            multivalue=True,
            cli_name='users',
            label=_('member user'),
            doc=_('users to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'group',
            required=False,
            multivalue=True,
            cli_name='groups',
            label=_('member group'),
            doc=_('groups to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('hosts to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('member host group'),
            doc=_('host groups to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'netgroup',
            required=False,
            multivalue=True,
            cli_name='netgroups',
            label=_('member netgroup'),
            doc=_('netgroups to remove'),
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
class netgroup_show(Method):
    __doc__ = _("Display information about a netgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Netgroup name'),
            no_convert=True,
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
            (str, type(None)),
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
