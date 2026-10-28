#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Command
from ipalib import parameters, output
from ipalib.plugable import Registry
from ipalib.text import _

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
            doc=_('Dict of I18N messages'),
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
            doc=_('Name of object to export'),
        ),
        parameters.Str(
            'methodname',
            required=False,
            doc=_('Name of method to export'),
        ),
    )
    takes_options = (
        parameters.Str(
            'object',
            required=False,
            doc=_('Name of object to export'),
        ),
        parameters.Str(
            'method',
            required=False,
            doc=_('Name of method to export'),
        ),
        parameters.Str(
            'command',
            required=False,
            doc=_('Name of command to export'),
        ),
    )
    has_output = (
        output.Output(
            'objects',
            dict,
            doc=_('Dict of JSON encoded IPA Objects'),
        ),
        output.Output(
            'methods',
            dict,
            doc=_('Dict of JSON encoded IPA Methods'),
        ),
        output.Output(
            'commands',
            dict,
            doc=_('Dict of JSON encoded IPA Commands'),
        ),
    )
