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
RADIUS Proxy Servers

Manage RADIUS Proxy Servers.

IPA supports the use of an external RADIUS proxy server for krb5 OTP
authentications. This permits a great deal of flexibility when
integrating with third-party authentication services.

EXAMPLES:

 Add a new server:
   ipa radiusproxy-add MyRADIUS --server=radius.example.com:1812

 Find all servers whose entries include the string "example.com":
   ipa radiusproxy-find example.com

 Examine the configuration:
   ipa radiusproxy-show MyRADIUS

 Change the secret:
   ipa radiusproxy-mod MyRADIUS --secret

 Delete a configuration:
   ipa radiusproxy-del MyRADIUS
""")

register = Registry()


@register()
class radiusproxy(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'RADIUS proxy server name'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_(u'Description'),
            doc=_(u'A description of this RADIUS proxy server'),
        ),
        parameters.Str(
            'ipatokenradiusserver',
            multivalue=True,
            label=_(u'Server'),
            doc=_(u'The hostname or IP (with or without port)'),
        ),
        parameters.Password(
            'ipatokenradiussecret',
            label=_(u'Secret'),
            doc=_(u'The secret used to encrypt data'),
        ),
        parameters.Int(
            'ipatokenradiustimeout',
            required=False,
            label=_(u'Timeout'),
            doc=_(u'The total timeout across all retries (in seconds)'),
        ),
        parameters.Int(
            'ipatokenradiusretries',
            required=False,
            label=_(u'Retries'),
            doc=_(u'The number of times to retry authentication'),
        ),
        parameters.Str(
            'ipatokenusermapattribute',
            required=False,
            label=_(u'User attribute'),
            doc=_(u'The username attribute on the user object'),
        ),
    )


@register()
class radiusproxy_add(Method):
    __doc__ = _("Add a new RADIUS proxy server.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'RADIUS proxy server name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this RADIUS proxy server'),
        ),
        parameters.Str(
            'ipatokenradiusserver',
            multivalue=True,
            cli_name='server',
            label=_(u'Server'),
            doc=_(u'The hostname or IP (with or without port)'),
        ),
        parameters.Password(
            'ipatokenradiussecret',
            cli_name='secret',
            label=_(u'Secret'),
            doc=_(u'The secret used to encrypt data'),
            exclude=('cli', 'webui'),
            confirm=True,
        ),
        parameters.Int(
            'ipatokenradiustimeout',
            required=False,
            cli_name='timeout',
            label=_(u'Timeout'),
            doc=_(u'The total timeout across all retries (in seconds)'),
        ),
        parameters.Int(
            'ipatokenradiusretries',
            required=False,
            cli_name='retries',
            label=_(u'Retries'),
            doc=_(u'The number of times to retry authentication'),
        ),
        parameters.Str(
            'ipatokenusermapattribute',
            required=False,
            cli_name='userattr',
            label=_(u'User attribute'),
            doc=_(u'The username attribute on the user object'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class radiusproxy_del(Method):
    __doc__ = _("Delete a RADIUS proxy server.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='name',
            label=_(u'RADIUS proxy server name'),
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
class radiusproxy_find(Method):
    __doc__ = _("Search for RADIUS proxy servers.")

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
            label=_(u'RADIUS proxy server name'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this RADIUS proxy server'),
        ),
        parameters.Str(
            'ipatokenradiusserver',
            required=False,
            multivalue=True,
            cli_name='server',
            label=_(u'Server'),
            doc=_(u'The hostname or IP (with or without port)'),
        ),
        parameters.Password(
            'ipatokenradiussecret',
            required=False,
            cli_name='secret',
            label=_(u'Secret'),
            doc=_(u'The secret used to encrypt data'),
            exclude=('cli', 'webui'),
            confirm=True,
        ),
        parameters.Int(
            'ipatokenradiustimeout',
            required=False,
            cli_name='timeout',
            label=_(u'Timeout'),
            doc=_(u'The total timeout across all retries (in seconds)'),
        ),
        parameters.Int(
            'ipatokenradiusretries',
            required=False,
            cli_name='retries',
            label=_(u'Retries'),
            doc=_(u'The number of times to retry authentication'),
        ),
        parameters.Str(
            'ipatokenusermapattribute',
            required=False,
            cli_name='userattr',
            label=_(u'User attribute'),
            doc=_(u'The username attribute on the user object'),
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
class radiusproxy_mod(Method):
    __doc__ = _("Modify a RADIUS proxy server.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'RADIUS proxy server name'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
            doc=_(u'A description of this RADIUS proxy server'),
        ),
        parameters.Str(
            'ipatokenradiusserver',
            required=False,
            multivalue=True,
            cli_name='server',
            label=_(u'Server'),
            doc=_(u'The hostname or IP (with or without port)'),
        ),
        parameters.Password(
            'ipatokenradiussecret',
            required=False,
            cli_name='secret',
            label=_(u'Secret'),
            doc=_(u'The secret used to encrypt data'),
            exclude=('cli', 'webui'),
            confirm=True,
        ),
        parameters.Int(
            'ipatokenradiustimeout',
            required=False,
            cli_name='timeout',
            label=_(u'Timeout'),
            doc=_(u'The total timeout across all retries (in seconds)'),
        ),
        parameters.Int(
            'ipatokenradiusretries',
            required=False,
            cli_name='retries',
            label=_(u'Retries'),
            doc=_(u'The number of times to retry authentication'),
        ),
        parameters.Str(
            'ipatokenusermapattribute',
            required=False,
            cli_name='userattr',
            label=_(u'User attribute'),
            doc=_(u'The username attribute on the user object'),
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
            doc=_(u'Rename the RADIUS proxy server object'),
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
class radiusproxy_show(Method):
    __doc__ = _("Display information about a RADIUS proxy server.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='name',
            label=_(u'RADIUS proxy server name'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
