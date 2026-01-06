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
IPA servers

Get information about installed IPA servers.

EXAMPLES:

  Find all servers:
    ipa server-find

  Show specific server:
    ipa server-show ipa.example.com
""")

register = Registry()


@register()
class server(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_('Server name'),
            doc=_('IPA server hostname'),
        ),
        parameters.Str(
            'iparepltopomanagedsuffix',
            label=_('Managed suffix'),
        ),
        parameters.Int(
            'ipamindomainlevel',
            label=_('Min domain level'),
            doc=_('Minimum domain level'),
        ),
        parameters.Int(
            'ipamaxdomainlevel',
            label=_('Max domain level'),
            doc=_('Maximum domain level'),
        ),
    )


@register()
class server_del(Method):
    __doc__ = _("Delete IPA server.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_('Server name'),
            doc=_('IPA server hostname'),
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
class server_find(Method):
    __doc__ = _("Search for IPA servers.")

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
            label=_('Server name'),
            doc=_('IPA server hostname'),
        ),
        parameters.Str(
            'iparepltopomanagedsuffix',
            required=False,
            cli_name='suffix',
            label=_('Managed suffix'),
        ),
        parameters.Int(
            'ipamindomainlevel',
            required=False,
            cli_name='minlevel',
            label=_('Min domain level'),
            doc=_('Minimum domain level'),
        ),
        parameters.Int(
            'ipamaxdomainlevel',
            required=False,
            cli_name='maxlevel',
            label=_('Max domain level'),
            doc=_('Maximum domain level'),
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
class server_show(Method):
    __doc__ = _("Show IPA server.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_('Server name'),
            doc=_('IPA server hostname'),
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
