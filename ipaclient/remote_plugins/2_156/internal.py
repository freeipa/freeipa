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
Plugins not accessible directly through the CLI, commands used internally
""")

register = Registry()


@register()
class i18n_messages(Command):
    NO_CLI = True

    takes_options = (
    )
    has_output = (
        output.Output(
            'texts',
            dict,
            doc=_(u'Dict of I18N messages'),
        ),
    )


@register()
class json_metadata(Command):
    __doc__ = _("Export plugin meta-data for the webUI.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'objname',
            required=False,
            doc=_(u'Name of object to export'),
        ),
        parameters.Str(
            'methodname',
            required=False,
            doc=_(u'Name of method to export'),
        ),
    )
    takes_options = (
        parameters.Str(
            'object',
            required=False,
            doc=_(u'Name of object to export'),
        ),
        parameters.Str(
            'method',
            required=False,
            doc=_(u'Name of method to export'),
        ),
        parameters.Str(
            'command',
            required=False,
            doc=_(u'Name of command to export'),
        ),
    )
    has_output = (
        output.Output(
            'objects',
            dict,
            doc=_(u'Dict of JSON encoded IPA Objects'),
        ),
        output.Output(
            'methods',
            dict,
            doc=_(u'Dict of JSON encoded IPA Methods'),
        ),
        output.Output(
            'commands',
            dict,
            doc=_(u'Dict of JSON encoded IPA Commands'),
        ),
    )
