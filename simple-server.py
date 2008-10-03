#!/usr/bin/python

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
A simple XML-RPC test server using SimpleXMLRPCServer.

The server will run at http://localhost:8080
"""

from SimpleXMLRPCServer import SimpleXMLRPCServer
from ipalib import api
from ipalib import load_plugins

api.finalize()

class Dispatch(object):
    def __init__(self, cmd):
        self.__cmd = cmd

    def __call__(self, *params):
        if len(params) > 0:
            kw = params[0]
        else:
            kw = {}
        args = params[1:]
        return cmd(*args, **kw)


server = SimpleXMLRPCServer(('localhost', 8080))
server.register_introspection_functions()
for cmd in api.Command():
    server.register_function(Dispatch(cmd), cmd.name)

server.serve_forever()
