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
Ping the remote IPA server to ensure it is running.

The ping command sends an echo request to an IPA server. The server
returns its version information. This is used by an IPA client
to confirm that the server is available and accepting requests.

The server from xmlrpc_uri in /etc/ipa/default.conf is contacted first.
If it does not respond then the client will contact any servers defined
by ldap SRV records in DNS.

EXAMPLES:

 Ping an IPA server:
   ipa ping
   ------------------------------------------
   IPA server version 2.1.9. API version 2.20
   ------------------------------------------

 Ping an IPA server verbosely:
   ipa -v ping
   ipa: INFO: trying https://ipa.example.com/ipa/xml
   ipa: INFO: Forwarding 'ping' to server u'https://ipa.example.com/ipa/xml'
   -----------------------------------------------------
   IPA server version 2.1.9. API version 2.20
   -----------------------------------------------------
""")

register = Registry()


@register()
class ping(Command):
    __doc__ = _("Ping a remote server.")

    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
    )
