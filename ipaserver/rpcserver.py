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
Execute an RPC request.
"""

from xmlrpclib import dumps, loads, Fault
from ipalib import Backend
from ipalib.errors import HandledError, CommandError
from ipalib.rpc import xml_wrap, xml_unwrap


def params_2_args_options(params):
    assert type(params) is tuple
    if len(params) == 0:
        return (tuple(), dict())
    if type(params[-1]) is dict:
        return (params[:-1], params[-1])
    return (params, dict())


class xmlrpc(Backend):

    def dispatch(self, method, params):
        assert type(method) is str
        assert type(params) is tuple
        self.info('Received RPC call to %r', method)
        if method not in self.Command:
            raise CommandError(name=method)
        (args, options) = params_2_args_options(xml_unwrap(params))
        result = self.Command[method](*args, **options)
        return (xml_wrap(result),)

    def execute(self, data, ccache=None, client_ip=None, locale=None):
        try:
            (params, method) = loads(data)
            response = self.dispatch(method, params)
        except Exception, e:
            if not isinstance(e, HandledError):
                e = UnknownError()
            assert isinstance(e, HandledError)
            response = Fault(e.code, e.message)
        return dumps(response)
