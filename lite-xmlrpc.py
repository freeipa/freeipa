#!/usr/bin/env python

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
In-tree XML-RPC server using SimpleXMLRPCServer.
"""

import sys
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import krbV
from ipalib import api


class Server(SimpleXMLRPCServer):
    """
    Custom server implementing `Server._marshaled_dispatch()`.
    """

    def _marshaled_dispatch(self, data, dispatch_method=None):
        """
        Use `ipaserver.rpcserver.xmlserver.marshaled_dispatch()`.
        """
        try:
            ccache=krbV.default_context().default_ccache().name
            return api.Backend.xmlserver.marshaled_dispatch(data, ccache)
        except Exception, e:
            api.log.exception('lite-xmlrpc: caught error in _marshaled_dispatch()')
            raise e


class RequestHandler(SimpleXMLRPCRequestHandler):

    def do_POST(self):
        try:
            client = '%r %r' % self.client_address
        except Exception, e:
            api.log.exception('lite-xmlrpc: caught error in do_POST()')
            raise e
        return SimpleXMLRPCRequestHandler.do_POST(self)


api.bootstrap_with_global_options(context='server')
api.finalize()

kw = dict(requestHandler=RequestHandler, logRequests=False)
if sys.version_info[:2] != (2, 4):
    kw.update(dict(encoding='UTF-8', allow_none=True))
server = Server(('', api.env.lite_xmlrpc_port), **kw)

api.log.info('Logging to file %r', api.env.log)
api.log.info('Listening on port %d', api.env.lite_xmlrpc_port)


try:
    server.serve_forever()
except KeyboardInterrupt:
    api.log.info('KeyboardInterrupt: shutting down server...')
    server.server_close()
    api.log.info('Server shutdown.')
