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
Joining an IPA domain
""")

register = Registry()


@register()
class join(Command):
    __doc__ = _("Join an IPA domain")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='hostname',
            doc=_(u'The hostname to register as'),
            default_from=DefaultFrom(lambda : None),
            # FIXME:
            # lambda: unicode(installutils.get_fqdn())
            autofill=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'realm',
            doc=_(u'The IPA realm'),
            default_from=DefaultFrom(lambda : None),
            # FIXME:
            # lambda: get_realm()
            autofill=True,
        ),
        parameters.Str(
            'nshardwareplatform',
            required=False,
            cli_name='platform',
            doc=_(u'Hardware platform of the host (e.g. Lenovo T61)'),
        ),
        parameters.Str(
            'nsosversion',
            required=False,
            cli_name='os',
            doc=_(u'Operating System and version of the host (e.g. Fedora 9)'),
        ),
    )
    has_output = (
    )
