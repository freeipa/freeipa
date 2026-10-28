# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2008-2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
RPC client plugins.
"""

from ipalib import Registry, api

register = Registry()


if 'in_server' in api.env and api.env.in_server is False:
    from ipalib.rpc import xmlclient, jsonclient
    register()(xmlclient)
    register()(jsonclient)

    # FIXME: api.register only looks at the class name, so we need to create
    # trivial subclasses with the desired name.
    if api.env.rpc_protocol == 'xmlrpc':

        class rpcclient(xmlclient):
            """xmlclient renamed to 'rpcclient'"""

        register()(rpcclient)

    elif api.env.rpc_protocol == 'jsonrpc':

        class rpcclient(jsonclient):
            """jsonclient renamed to 'rpcclient'"""

        register()(rpcclient)

    else:
        raise ValueError('unknown rpc_protocol: %s' % api.env.rpc_protocol)
