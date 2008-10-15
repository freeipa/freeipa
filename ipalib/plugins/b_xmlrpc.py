# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
from ipalib.backend import Backend
from ipalib.util import xmlrpc_marshal
from ipalib import api
from ipalib import errors

class xmlrpc(Backend):
    """
    Kerberos backend plugin.
    """

    def get_client(self, verbose=False):
        # FIXME: The server uri should come from self.api.env.server_uri
        return xmlrpclib.ServerProxy('http://localhost:8888', verbose=verbose)

    def forward_call(self, name, *args, **kw):
        """
        Forward a call over XML-RPC to an IPA server.
        """
        client = self.get_client(verbose=api.env.get('verbose', False))
        command = getattr(client, name)
        params = xmlrpc_marshal(*args, **kw)
        try:
            return command(*params)
        except socket.error, e:
            print e[1]
        except xmlrpclib.Fault, e:
            err = errors.convertFault(e)
            code = getattr(err,'faultCode',None)
            if code:
                print "%s: %s" % (code, getattr(err,'__doc__',''))
            else:
                raise err
        return {}

api.register(xmlrpc)
