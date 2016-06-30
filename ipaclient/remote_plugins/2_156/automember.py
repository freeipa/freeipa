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
Auto Membership Rule.

Bring clarity to the membership of hosts and users by configuring inclusive
or exclusive regex patterns, you can automatically assign a new entries into
a group or hostgroup based upon attribute information.

A rule is directly associated with a group by name, so you cannot create
a rule without an accompanying group or hostgroup.

A condition is a regular expression used by 389-ds to match a new incoming
entry with an automember rule. If it matches an inclusive rule then the
entry is added to the appropriate group or hostgroup.

A default group or hostgroup could be specified for entries that do not
match any rule. In case of user entries this group will be a fallback group
because all users are by default members of group specified in IPA config.

The automember-rebuild command can be used to retroactively run automember rules
against existing entries, thus rebuilding their membership.

EXAMPLES:

 Add the initial group or hostgroup:
   ipa hostgroup-add --desc="Web Servers" webservers
   ipa group-add --desc="Developers" devel

 Add the initial rule:
   ipa automember-add --type=hostgroup webservers
   ipa automember-add --type=group devel

 Add a condition to the rule:
   ipa automember-add-condition --key=fqdn --type=hostgroup --inclusive-regex=^web[1-9]+\.example\.com webservers
   ipa automember-add-condition --key=manager --type=group --inclusive-regex=^uid=mscott devel

 Add an exclusive condition to the rule to prevent auto assignment:
   ipa automember-add-condition --key=fqdn --type=hostgroup --exclusive-regex=^web5\.example\.com webservers

 Add a host:
    ipa host-add web1.example.com

 Add a user:
    ipa user-add --first=Tim --last=User --password tuser1 --manager=mscott

 Verify automembership:
    ipa hostgroup-show webservers
      Host-group: webservers
      Description: Web Servers
      Member hosts: web1.example.com

    ipa group-show devel
      Group name: devel
      Description: Developers
      GID: 1004200000
      Member users: tuser

 Remove a condition from the rule:
   ipa automember-remove-condition --key=fqdn --type=hostgroup --inclusive-regex=^web[1-9]+\.example\.com webservers

 Modify the automember rule:
    ipa automember-mod

 Set the default (fallback) target group:
    ipa automember-default-group-set --default-group=webservers --type=hostgroup
    ipa automember-default-group-set --default-group=ipausers --type=group

 Remove the default (fallback) target group:
    ipa automember-default-group-remove --type=hostgroup
    ipa automember-default-group-remove --type=group

 Show the default (fallback) target group:
    ipa automember-default-group-show --type=hostgroup
    ipa automember-default-group-show --type=group

 Find all of the automember rules:
    ipa automember-find

 Display a automember rule:
    ipa automember-show --type=hostgroup webservers
    ipa automember-show --type=group devel

 Delete an automember rule:
    ipa automember-del --type=hostgroup webservers
    ipa automember-del --type=group devel

 Rebuild membership for all users:
    ipa automember-rebuild --type=group

 Rebuild membership for all hosts:
    ipa automember-rebuild --type=hostgroup

 Rebuild membership for specified users:
    ipa automember-rebuild --users=tuser1 --users=tuser2

 Rebuild membership for specified hosts:
    ipa automember-rebuild --hosts=web1.example.com --hosts=web2.example.com
""")

register = Registry()


@register()
class automember(Object):
    takes_params = (
        parameters.Str(
            'description',
            required=False,
            label=_(u'Description'),
            doc=_(u'A description of this auto member rule'),
        ),
        parameters.Str(
            'automemberdefaultgroup',
            required=False,
            label=_(u'Default (fallback) Group'),
            doc=_(u'Default group for entries to land'),
        ),
    )


@register()
class automember_add(Method):
    __doc__ = _("Add an automember rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='automember_rule',
            label=_(u'Automember Rule'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this auto member rule'),
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
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automember_add_condition(Method):
    __doc__ = _("Add conditions to an automember rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='automember_rule',
            label=_(u'Automember Rule'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this auto member rule'),
        ),
        parameters.Str(
            'automemberinclusiveregex',
            required=False,
            multivalue=True,
            cli_name='inclusive_regex',
            label=_(u'Inclusive Regex'),
            alwaysask=True,
        ),
        parameters.Str(
            'automemberexclusiveregex',
            required=False,
            multivalue=True,
            cli_name='exclusive_regex',
            label=_(u'Exclusive Regex'),
            alwaysask=True,
        ),
        parameters.Str(
            'key',
            label=_(u'Attribute Key'),
            doc=_(u'Attribute to filter via regex. For example fqdn for a host, or manager for a user'),
        ),
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
        output.Output(
            'failed',
            dict,
            doc=_(u'Conditions that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of conditions added'),
        ),
    )


@register()
class automember_default_group_remove(Method):
    __doc__ = _("Remove default (fallback) group for all unmatched entries.")

    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this auto member rule'),
        ),
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automember_default_group_set(Method):
    __doc__ = _("Set default (fallback) group for all unmatched entries.")

    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this auto member rule'),
        ),
        parameters.Str(
            'automemberdefaultgroup',
            cli_name='default_group',
            label=_(u'Default (fallback) Group'),
            doc=_(u'Default (fallback) group for entries to land'),
        ),
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automember_default_group_show(Method):
    __doc__ = _("Display information about the default (fallback) automember groups.")

    takes_options = (
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automember_del(Method):
    __doc__ = _("Delete an automember rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='automember_rule',
            label=_(u'Automember Rule'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
class automember_find(Method):
    __doc__ = _("Search for automember rules.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this auto member rule'),
        ),
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
class automember_mod(Method):
    __doc__ = _("Modify an automember rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='automember_rule',
            label=_(u'Automember Rule'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this auto member rule'),
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
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automember_rebuild(Command):
    __doc__ = _("Rebuild auto membership.")

    takes_options = (
        parameters.Str(
            'type',
            required=False,
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Rebuild membership for all members of a grouping'),
            doc=_(u'Grouping to which the rule applies'),
        ),
        parameters.Str(
            'users',
            required=False,
            multivalue=True,
            label=_(u'Users'),
            doc=_(u'Rebuild membership for specified users'),
        ),
        parameters.Str(
            'hosts',
            required=False,
            multivalue=True,
            label=_(u'Hosts'),
            doc=_(u'Rebuild membership for specified hosts'),
        ),
        parameters.Flag(
            'no_wait',
            required=False,
            label=_(u'No wait'),
            doc=_(u"Don't wait for rebuilding membership"),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automember_remove_condition(Method):
    __doc__ = _("Remove conditions from an automember rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='automember_rule',
            label=_(u'Automember Rule'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this auto member rule'),
        ),
        parameters.Str(
            'automemberinclusiveregex',
            required=False,
            multivalue=True,
            cli_name='inclusive_regex',
            label=_(u'Inclusive Regex'),
            alwaysask=True,
        ),
        parameters.Str(
            'automemberexclusiveregex',
            required=False,
            multivalue=True,
            cli_name='exclusive_regex',
            label=_(u'Exclusive Regex'),
            alwaysask=True,
        ),
        parameters.Str(
            'key',
            label=_(u'Attribute Key'),
            doc=_(u'Attribute to filter via regex. For example fqdn for a host, or manager for a user'),
        ),
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
        output.Output(
            'failed',
            dict,
            doc=_(u'Conditions that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of conditions removed'),
        ),
    )


@register()
class automember_show(Method):
    __doc__ = _("Display information about an automember rule.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='automember_rule',
            label=_(u'Automember Rule'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'type',
            cli_metavar="['group', 'hostgroup']",
            label=_(u'Grouping Type'),
            doc=_(u'Grouping to which the rule applies'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
