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
Groups of hosts.

Manage groups of hosts. This is useful for applying access control to a
number of hosts by using Host-based Access Control.

EXAMPLES:

 Add a new host group:
   ipa hostgroup-add --desc="Baltimore hosts" baltimore

 Add another new host group:
   ipa hostgroup-add --desc="Maryland hosts" maryland

 Add members to the hostgroup (using Bash brace expansion):
   ipa hostgroup-add-member --hosts={box1,box2,box3} baltimore

 Add a hostgroup as a member of another hostgroup:
   ipa hostgroup-add-member --hostgroups=baltimore maryland

 Remove a host from the hostgroup:
   ipa hostgroup-remove-member --hosts=box2 baltimore

 Display a host group:
   ipa hostgroup-show baltimore

 Delete a hostgroup:
   ipa hostgroup-del baltimore
""")

register = Registry()


@register()
class hostgroup(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Host-group'),
            doc=_(u'Name of host-group'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_(u'Description'),
            doc=_(u'A description of this host-group'),
        ),
        parameters.Str(
            'member_host',
            required=False,
            label=_(u'Member hosts'),
        ),
        parameters.Str(
            'member_hostgroup',
            required=False,
            label=_(u'Member host-groups'),
        ),
        parameters.Str(
            'memberof_hostgroup',
            required=False,
            label=_(u'Member of host-groups'),
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
            'memberindirect_host',
            required=False,
            label=_(u'Indirect Member hosts'),
        ),
        parameters.Str(
            'memberindirect_hostgroup',
            required=False,
            label=_(u'Indirect Member host-groups'),
        ),
        parameters.Str(
            'memberofindirect_hostgroup',
            required=False,
            label=_(u'Indirect Member of host-group'),
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
class hostgroup_add(Method):
    __doc__ = _("Add a new hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_(u'Host-group'),
            doc=_(u'Name of host-group'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this host-group'),
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
class hostgroup_add_member(Method):
    __doc__ = _("Add members to a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_(u'Host-group'),
            doc=_(u'Name of host-group'),
            no_convert=True,
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'member host'),
            doc=_(u'hosts to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_(u'member host group'),
            doc=_(u'host groups to add'),
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
class hostgroup_del(Method):
    __doc__ = _("Delete a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='hostgroup_name',
            label=_(u'Host-group'),
            doc=_(u'Name of host-group'),
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
class hostgroup_find(Method):
    __doc__ = _("Search for hostgroups.")

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
            cli_name='hostgroup_name',
            label=_(u'Host-group'),
            doc=_(u'Name of host-group'),
            no_convert=True,
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this host-group'),
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
            doc=_(u'Results should contain primary key attribute only ("hostgroup-name")'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'host'),
            doc=_(u'Search for host groups with these member hosts.'),
        ),
        parameters.Str(
            'no_host',
            required=False,
            multivalue=True,
            cli_name='no_hosts',
            label=_(u'host'),
            doc=_(u'Search for host groups without these member hosts.'),
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_(u'host group'),
            doc=_(u'Search for host groups with these member host groups.'),
        ),
        parameters.Str(
            'no_hostgroup',
            required=False,
            multivalue=True,
            cli_name='no_hostgroups',
            label=_(u'host group'),
            doc=_(u'Search for host groups without these member host groups.'),
        ),
        parameters.Str(
            'in_hostgroup',
            required=False,
            multivalue=True,
            cli_name='in_hostgroups',
            label=_(u'host group'),
            doc=_(u'Search for host groups with these member of host groups.'),
        ),
        parameters.Str(
            'not_in_hostgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_hostgroups',
            label=_(u'host group'),
            doc=_(u'Search for host groups without these member of host groups.'),
        ),
        parameters.Str(
            'in_netgroup',
            required=False,
            multivalue=True,
            cli_name='in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for host groups with these member of netgroups.'),
        ),
        parameters.Str(
            'not_in_netgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for host groups without these member of netgroups.'),
        ),
        parameters.Str(
            'in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for host groups with these member of HBAC rules.'),
        ),
        parameters.Str(
            'not_in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='not_in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for host groups without these member of HBAC rules.'),
        ),
        parameters.Str(
            'in_sudorule',
            required=False,
            multivalue=True,
            cli_name='in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for host groups with these member of sudo rules.'),
        ),
        parameters.Str(
            'not_in_sudorule',
            required=False,
            multivalue=True,
            cli_name='not_in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for host groups without these member of sudo rules.'),
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
class hostgroup_mod(Method):
    __doc__ = _("Modify a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_(u'Host-group'),
            doc=_(u'Name of host-group'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this host-group'),
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
class hostgroup_remove_member(Method):
    __doc__ = _("Remove members from a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_(u'Host-group'),
            doc=_(u'Name of host-group'),
            no_convert=True,
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
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'member host'),
            doc=_(u'hosts to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_(u'member host group'),
            doc=_(u'host groups to remove'),
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
class hostgroup_show(Method):
    __doc__ = _("Display information about a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_(u'Host-group'),
            doc=_(u'Name of host-group'),
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
