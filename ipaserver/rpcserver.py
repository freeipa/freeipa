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
RPC server.

Also see the `ipalib.rpc` module.
"""

from xmlrpclib import Fault
from ipalib.backend import Executioner
from ipalib.errors2 import PublicError, InternalError, CommandError
from ipalib.rpc import xml_dumps, xml_loads
from ipalib.util import make_repr


def params_2_args_options(params):
    assert type(params) is tuple
    if len(params) == 0:
        return (tuple(), dict())
    if type(params[-1]) is dict:
        return (params[:-1], params[-1])
    return (params, dict())


class xmlserver(Executioner):
    """
    Execution backend plugin for XML-RPC server.

    Also see the `ipalib.rpc.xmlclient` plugin.
    """

    def finalize(self):
        self.__system = {
            'system.listMethods': self.listMethods,
            'system.methodSignature': self.methodSignature,
            'system.methodHelp': self.methodHelp,
        }
        super(xmlserver, self).finalize()

    def listMethods(self, *params):
        return tuple(name.encode('UTF-8') for name in self.Command)

    def methodSignature(self, *params):
        return 'methodSignature not supported'

    def methodHelp(self, *params):
        return 'methodHelp not supported'

    def marshaled_dispatch(self, data, ccache):
        """
        Execute the XML-RPC request in contained in ``data``.
        """
        try:
            #self.create_context(ccache=ccache)
            (params, name) = xml_loads(data)
            if name in self.__system:
                response = (self.__system[name](*params),)
            else:
                (args, options) = params_2_args_options(params)
                response = (self.execute(name, *args, **options),)
        except PublicError, e:
            self.info('response: %s: %s', e.__class__.__name__, str(e))
            response = Fault(e.errno, e.strerror)
        return xml_dumps(response, methodresponse=True)
