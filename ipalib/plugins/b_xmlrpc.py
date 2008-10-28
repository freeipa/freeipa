# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Backend plugin for XML-RPC client.

This provides a lightwieght XML-RPC client using Python standard library
``xmlrpclib`` module.
"""

import xmlrpclib
import socket
import httplib
import kerberos
from ipalib.backend import Backend
from ipalib.util import xmlrpc_marshal
from ipalib import api
from ipalib import errors

class xmlrpc(Backend):
    """
    XML-RPC client backend plugin.
    """

    def get_client(self):
        """
        Return an xmlrpclib.ServerProxy instance (the client).
        """
        uri = self.api.env.xmlrpc_uri
        if uri.startswith('https://'):
            return xmlrpclib.ServerProxy(uri,
                transport=KerbTransport(),
                verbose=self.api.env.verbose,
            )
        return xmlrpclib.ServerProxy(uri, verbose=self.api.env.verbose)

    def forward_call(self, name, *args, **kw):
        """
        Forward a call over XML-RPC to an IPA server.
        """
        client = self.get_client()
        command = getattr(client, name)
        params = xmlrpc_marshal(*args, **kw)
        try:
            return command(*params)
        except socket.error, e:
            print e[1]
        except xmlrpclib.Fault, e:
            err = errors.convertFault(e)
            code = getattr(err,'faultCode',None)
            faultString = getattr(err,'faultString',None)
            if not code:
                raise err
            if code < errors.IPA_ERROR_BASE:
                print "%s: %s" % (code, faultString)
            else:
                print "%s: %s" % (code, getattr(err,'__doc__',''))
        return

api.register(xmlrpc)

class KerbTransport(xmlrpclib.SafeTransport):
    """Handles Kerberos Negotiation authentication to an XML-RPC server."""

    def get_host_info(self, host):

        host, extra_headers, x509 = xmlrpclib.Transport.get_host_info(self, host)

        # Set the remote host principal
        h = host
        hostinfo = h.split(':')
        service = "HTTP@" + hostinfo[0]

        try:
            rc, vc = kerberos.authGSSClientInit(service);
        except kerberos.GSSError, e:
            raise kerberos.GSSError(e)

        try:
            kerberos.authGSSClientStep(vc, "");
        except kerberos.GSSError, e:
            raise kerberos.GSSError(e)

        extra_headers = [
            ("Authorization", "negotiate %s" % kerberos.authGSSClientResponse(vc) )
            ]

        return host, extra_headers, x509
