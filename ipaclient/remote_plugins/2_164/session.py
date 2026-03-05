#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Command
from ipalib import output
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


@register()
class session_logout(Command):
    __doc__ = _("RPC command used to log the current user out of their session.")

    NO_CLI = True

    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )
