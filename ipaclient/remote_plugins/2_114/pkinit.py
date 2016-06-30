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
Kerberos pkinit options

Enable or disable anonymous pkinit using the principal
WELLKNOWN/ANONYMOUS@REALM. The server must have been installed with
pkinit support.

EXAMPLES:

 Enable anonymous pkinit:
  ipa pkinit-anonymous enable

 Disable anonymous pkinit:
  ipa pkinit-anonymous disable

For more information on anonymous pkinit see:

http://k5wiki.kerberos.org/wiki/Projects/Anonymous_pkinit
""")

register = Registry()


@register()
class pkinit(Object):
    takes_params = (
    )


@register()
class pkinit_anonymous(Command):
    __doc__ = _("Enable or Disable Anonymous PKINIT.")

    takes_args = (
        parameters.Str(
            'action',
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )
