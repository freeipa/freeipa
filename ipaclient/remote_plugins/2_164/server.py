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
            label=_(u'Server name'),
            doc=_(u'IPA server hostname'),
        ),
        parameters.Str(
            'iparepltopomanagedsuffix',
            required=False,
            multivalue=True,
        ),
        parameters.Str(
            'iparepltopomanagedsuffix_topologysuffix',
            required=False,
            multivalue=True,
            label=_(u'Managed suffixes'),
        ),
        parameters.Int(
            'ipamindomainlevel',
            label=_(u'Min domain level'),
            doc=_(u'Minimum domain level'),
        ),
        parameters.Int(
            'ipamaxdomainlevel',
            label=_(u'Max domain level'),
            doc=_(u'Maximum domain level'),
        ),
    )


@register()
class server_conncheck(Method):
    __doc__ = _("Check connection to remote IPA server.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Server name'),
            doc=_(u'IPA server hostname'),
        ),
        parameters.Str(
            'remote_cn',
            cli_name='remote_name',
            label=_(u'Remote server name'),
            doc=_(u'Remote IPA server hostname'),
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
class server_del(Method):
    __doc__ = _("Delete IPA server.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_(u'Server name'),
            doc=_(u'IPA server hostname'),
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
class server_find(Method):
    __doc__ = _("Search for IPA servers.")

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
            label=_(u'Server name'),
            doc=_(u'IPA server hostname'),
        ),
        parameters.Int(
            'ipamindomainlevel',
            required=False,
            cli_name='minlevel',
            label=_(u'Min domain level'),
            doc=_(u'Minimum domain level'),
        ),
        parameters.Int(
            'ipamaxdomainlevel',
            required=False,
            cli_name='maxlevel',
            label=_(u'Max domain level'),
            doc=_(u'Maximum domain level'),
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
            doc=_(u'Results should contain primary key attribute only ("name")'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'topologysuffix',
            required=False,
            multivalue=True,
            cli_name='topologysuffixes',
            label=_(u'suffix'),
            doc=_(u'Search for servers with these managed suffixes.'),
        ),
        parameters.Str(
            'no_topologysuffix',
            required=False,
            multivalue=True,
            cli_name='no_topologysuffixes',
            label=_(u'suffix'),
            doc=_(u'Search for servers without these managed suffixes.'),
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
class server_show(Method):
    __doc__ = _("Show IPA server.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'Server name'),
            doc=_(u'IPA server hostname'),
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
