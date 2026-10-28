#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Method, Object
from ipalib import parameters, output
from ipalib.plugable import Registry
from ipalib.text import _

__doc__ = _("""
Groups of hosts.

Manage groups of hosts. This is useful for applying access control to a
number of hosts by using Host-based Access Control.

EXAMPLES:

 Add a new host group:
   ipa hostgroup-add --desc="Baltimore hosts" baltimore

 Add another new host group:
   ipa hostgroup-add --desc="Maryland hosts" maryland

 Add members to the hostgroup:
   ipa hostgroup-add-member --hosts=box1,box2,box3 baltimore

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
            label=_('Host-group'),
            doc=_('Name of host-group'),
        ),
        parameters.Str(
            'description',
            label=_('Description'),
            doc=_('A description of this host-group'),
        ),
        parameters.Str(
            'member_host',
            required=False,
            label=_('Member hosts'),
        ),
        parameters.Str(
            'member_hostgroup',
            required=False,
            label=_('Member host-groups'),
        ),
        parameters.Str(
            'memberof_hostgroup',
            required=False,
            label=_('Member of host-groups'),
        ),
        parameters.Str(
            'memberof_netgroup',
            required=False,
            label=_('Member of netgroups'),
        ),
        parameters.Str(
            'memberof_sudorule',
            required=False,
            label=_('Member of Sudo rule'),
        ),
        parameters.Str(
            'memberof_hbacrule',
            required=False,
            label=_('Member of HBAC rule'),
        ),
        parameters.Str(
            'memberindirect_host',
            required=False,
            label=_('Indirect Member hosts'),
        ),
        parameters.Str(
            'memberindirect_hostgroup',
            required=False,
            label=_('Indirect Member host-groups'),
        ),
        parameters.Str(
            'memberofindirect_hostgroup',
            required=False,
            label=_('Indirect Member of host-group'),
        ),
        parameters.Str(
            'memberofindirect_sudorule',
            required=False,
            label=_('Indirect Member of Sudo rule'),
        ),
        parameters.Str(
            'memberofindirect_hbacrule',
            required=False,
            label=_('Indirect Member of HBAC rule'),
        ),
    )


@register()
class hostgroup_add(Method):
    __doc__ = _("Add a new hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host-group'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(
                'Set an attribute to a name/value pair. '
                'Format is attr=value.\nFor multi-valued attributes, '
                'the command replaces the values already present.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(
                'Add an attribute/value pair. Format is attr=value. '
                'The attribute\nmust be part of the schema.'
            ),
            exclude=('webui',),
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
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
        output.Output(
            'value',
            str,
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class hostgroup_add_member(Method):
    __doc__ = _("Add members to a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('comma-separated list of hosts to add'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('member host group'),
            doc=_('comma-separated list of host groups to add'),
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
class hostgroup_del(Method):
    __doc__ = _("Delete a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='hostgroup_name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
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
        output.Output(
            'value',
            str,
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class hostgroup_find(Method):
    __doc__ = _("Search for hostgroups.")

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
            cli_name='hostgroup_name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
            no_convert=True,
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host-group'),
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
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_(
                'Results should contain primary key attribute only '
                '("hostgroup-name")'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('host'),
            doc=_('Search for host groups with these member hosts.'),
        ),
        parameters.Str(
            'no_host',
            required=False,
            multivalue=True,
            cli_name='no_hosts',
            label=_('host'),
            doc=_('Search for host groups without these member hosts.'),
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('host group'),
            doc=_('Search for host groups with these member host groups.'),
        ),
        parameters.Str(
            'no_hostgroup',
            required=False,
            multivalue=True,
            cli_name='no_hostgroups',
            label=_('host group'),
            doc=_('Search for host groups without these member host groups.'),
        ),
        parameters.Str(
            'in_hostgroup',
            required=False,
            multivalue=True,
            cli_name='in_hostgroups',
            label=_('host group'),
            doc=_('Search for host groups with these member of host groups.'),
        ),
        parameters.Str(
            'not_in_hostgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_hostgroups',
            label=_('host group'),
            doc=_(
                'Search for host groups without these member of host groups.'
            ),
        ),
        parameters.Str(
            'in_netgroup',
            required=False,
            multivalue=True,
            cli_name='in_netgroups',
            label=_('netgroup'),
            doc=_('Search for host groups with these member of netgroups.'),
        ),
        parameters.Str(
            'not_in_netgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_netgroups',
            label=_('netgroup'),
            doc=_('Search for host groups without these member of netgroups.'),
        ),
        parameters.Str(
            'in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='in_hbacrules',
            label=_('HBAC rule'),
            doc=_('Search for host groups with these member of HBAC rules.'),
        ),
        parameters.Str(
            'not_in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='not_in_hbacrules',
            label=_('HBAC rule'),
            doc=_('Search for host groups without these member of HBAC rules.'),
        ),
        parameters.Str(
            'in_sudorule',
            required=False,
            multivalue=True,
            cli_name='in_sudorules',
            label=_('sudo rule'),
            doc=_('Search for host groups with these member of sudo rules.'),
        ),
        parameters.Str(
            'not_in_sudorule',
            required=False,
            multivalue=True,
            cli_name='not_in_sudorules',
            label=_('sudo rule'),
            doc=_('Search for host groups without these member of sudo rules.'),
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
class hostgroup_mod(Method):
    __doc__ = _("Modify a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this host-group'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(
                'Set an attribute to a name/value pair. '
                'Format is attr=value.\nFor multi-valued attributes, '
                'the command replaces the values already present.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(
                'Add an attribute/value pair. Format is attr=value. '
                'The attribute\nmust be part of the schema.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(
                'Delete an attribute/value pair. '
                'The option will be evaluated\nlast, after all sets and adds.'
            ),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_(
                'Display the access rights of this entry (requires --all). '
                'See ipa man page for details.'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
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
        output.Output(
            'value',
            str,
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class hostgroup_remove_member(Method):
    __doc__ = _("Remove members from a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_('member host'),
            doc=_('comma-separated list of hosts to remove'),
            alwaysask=True,
        ),
        parameters.Str(
            'hostgroup',
            required=False,
            multivalue=True,
            cli_name='hostgroups',
            label=_('member host group'),
            doc=_('comma-separated list of host groups to remove'),
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
class hostgroup_show(Method):
    __doc__ = _("Display information about a hostgroup.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostgroup_name',
            label=_('Host-group'),
            doc=_('Name of host-group'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_(
                'Display the access rights of this entry (requires --all). '
                'See ipa man page for details.'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
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
        output.Output(
            'value',
            str,
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
