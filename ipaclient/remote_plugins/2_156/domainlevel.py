#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

__doc__ = _("""
Raise the IPA Domain Level.
""")

register = Registry()


@register()
class domainlevel_get(Command):
    __doc__ = _("Query current Domain Level.")

    NO_CLI = True

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

    NO_CLI = True

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
