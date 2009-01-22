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
from ipalib import Backend
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


class xmlserver(Backend):
    """
    Execution backend for XML-RPC server.
    """

    def dispatch(self, method, params):
        self.debug('Received RPC call to %r', method)
        if method not in self.Command:
            raise CommandError(name=method)
        self.info('params = %r', params)
        (args, options) = params_2_args_options(params)
        self.info('args = %r', args)
        self.info('options = %r', options)
        self.debug(make_repr(method, *args, **options))
        result = self.Command[method](*args, **options)
        return (result,)  # Must wrap XML-RPC response in a tuple singleton

    def execute(self, data):
        """
        Execute the XML-RPC request in contained in ``data``.
        """
        try:
            (params, method) = xml_loads(data)
            response = self.dispatch(method, params)
            print 'okay'
        except Exception, e:
            if not isinstance(e, PublicError):
                e = InternalError()
            assert isinstance(e, PublicError)
            self.debug('Returning %r exception', e.__class__.__name__)
            response = Fault(e.errno, e.strerror)
        return xml_dumps(response, methodresponse=True)
