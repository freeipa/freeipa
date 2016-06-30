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
Misc plug-ins
""")

register = Registry()


@register()
class env(Command):
    __doc__ = _("Show environment variables.")

    takes_args = (
        parameters.Str(
            'variables',
            required=False,
            multivalue=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'server',
            required=False,
            doc=_(u'Forward to server instead of running locally'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=True,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'result',
            dict,
            doc=_(u'Dictionary mapping variable name to value'),
        ),
        output.Output(
            'total',
            int,
            doc=_(u'Total number of variables env (>= count)'),
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of variables returned (<= total)'),
        ),
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
    )


@register()
class plugins(Command):
    __doc__ = _("Show all loaded plugins.")

    takes_options = (
        parameters.Flag(
            'server',
            required=False,
            doc=_(u'Forward to server instead of running locally'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=True,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'result',
            dict,
            doc=_(u'Dictionary mapping plugin names to bases'),
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of plugins loaded'),
        ),
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
    )
