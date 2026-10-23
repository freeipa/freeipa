#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Command
from ipalib import parameters, output
from ipalib.plugable import Registry
from ipalib.text import _

__doc__ = _("""
Raise the IPA Domain Level.
""")

register = Registry()


@register()
class domainlevel_get(Command):
    __doc__ = _("Query current Domain Level.")

    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
            int,
            doc=_('Current domain level:'),
        ),
    )


@register()
class domainlevel_set(Command):
    __doc__ = _("Change current Domain Level.")

    takes_args = (
        parameters.Int(
            'ipadomainlevel',
            cli_name='level',
            label=_('Domain Level'),
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
            int,
            doc=_('Current domain level:'),
        ),
    )
