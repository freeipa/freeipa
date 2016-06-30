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
