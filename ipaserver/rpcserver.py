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

from cgi import parse_qs
from xmlrpclib import Fault
from ipalib.backend import Executioner
from ipalib.errors import PublicError, InternalError, CommandError, JSONError
from ipalib.request import context, Connection, destroy_context
from ipalib.rpc import xml_dumps, xml_loads
from ipalib.util import make_repr
import json


def read_input(environ):
    """
    Read the request body from environ['wsgi.input'].
    """
    try:
        length = int(environ.get('CONTENT_LENGTH'))
    except (ValueError, TypeError):
        return
    return environ['wsgi.input'].read(length)


def params_2_args_options(params):
    assert type(params) is tuple
    if len(params) == 0:
        return (tuple(), dict())
    if type(params[-1]) is dict:
        return (params[:-1], params[-1])
    return (params, dict())


def nicify_query(query, encoding='utf-8'):
    if not query:
        return
    for (key, value) in query.iteritems():
        if len(value) == 0:
            yield (key, None)
        elif len(value) == 1:
            yield (key, value[0].decode(encoding))
        else:
            yield (key, tuple(v.decode(encoding) for v in value))


def extract_query(environ):
    """
    Return the query as a ``dict``, or ``None`` if no query is presest.
    """
    qstr = None
    if environ['REQUEST_METHOD'] == 'POST':
        if environ['CONTENT_TYPE'] == 'application/x-www-form-urlencoded':
            qstr = read_input(environ)
    elif environ['REQUEST_METHOD'] == 'GET':
        qstr = environ['QUERY_STRING']
    if qstr:
        query = dict(nicify_query(
            parse_qs(qstr, keep_blank_values=True)
        ))
    else:
        query = {}
    environ['wsgi.query'] = query
    return query


class WSGIExecutioner(Executioner):
    """
    Base class for execution backends with a WSGI application interface.
    """

    def finalize(self):
        url = self.env['mount_' + self.name]
        if url.startswith('/'):
            self.url = url
        else:
            self.url = self.env.mount_ipa + url
        super(WSGIExecutioner, self).finalize()

    def execute(self, environ):
        result = None
        error = None
        _id = None
        try:
            try:
                self.create_context(ccache=environ.get('KRB5CCNAME'))
                if (
                    environ.get('CONTENT_TYPE', '').startswith(self.content_type)
                    and environ['REQUEST_METHOD'] == 'POST'
                ):
                    data = read_input(environ)
                    (name, args, options, _id) = self.unmarshal(data)
                else:
                    (name, args, options, _id) = self.simple_unmarshal(environ)
                if name not in self.Command:
                    raise CommandError(name=name)
                result = self.Command[name](*args, **options)
            except PublicError, e:
                error = e
            except StandardError, e:
                self.exception(
                    'non-public: %s: %s', e.__class__.__name__, str(e)
                )
                error = InternalError()
        finally:
            destroy_context()
        return self.marshal(result, error, _id)

    def simple_unmarshal(self, environ):
        name = environ['PATH_INFO'].strip('/')
        options = extract_query(environ)
        return (name, tuple(), options, None)

    def __call__(self, environ, start_response):
        """
        WSGI application for execution.
        """
        try:
            status = '200 OK'
            response = self.execute(environ)
            headers = [('Content-Type', self.content_type + '; charset=utf-8')]
        except StandardError, e:
            self.exception('%s.__call__():', self.name)
            status = '500 Internal Server Error'
            response = status
            headers = [('Content-Type', 'text/plain')]
        start_response(status, headers)
        return [response]

    def unmarshal(self, data):
        raise NotImplementedError('%s.unmarshal()' % self.fullname)

    def marshal(self, result, error, _id=None):
        raise NotImplementedError('%s.marshal()' % self.fullname)


class xmlserver(WSGIExecutioner):
    """
    Execution backend plugin for XML-RPC server.

    Also see the `ipalib.rpc.xmlclient` plugin.
    """

    content_type = 'text/xml'

    def finalize(self):
        self.__system = {
            'system.listMethods': self.listMethods,
            'system.methodSignature': self.methodSignature,
            'system.methodHelp': self.methodHelp,
        }
        super(xmlserver, self).finalize()

    def listMethods(self, *params):
        return tuple(name.decode('UTF-8') for name in self.Command)

    def methodSignature(self, *params):
        return u'methodSignature not implemented'

    def methodHelp(self, *params):
        return u'methodHelp not implemented'

    def marshaled_dispatch(self, data, ccache):
        """
        Execute the XML-RPC request contained in ``data``.
        """
        try:
            self.create_context(ccache=ccache)
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

    def unmarshal(self, data):
        (params, name) = xml_loads(data)
        (args, options) = params_2_args_options(params)
        return (name, args, options, None)

    def marshal(self, result, error, _id=None):
        if error:
            response = Fault(error.errno, error.strerror)
        else:
            response = (result,)
        return xml_dumps(response, methodresponse=True)


class jsonserver(WSGIExecutioner):
    """
    JSON RPC server.

    For information on the JSON-RPC spec, see:

        http://json-rpc.org/wiki/specification
    """

    content_type = 'application/json'

    def marshal(self, result, error, _id=None):
        if error:
            assert isinstance(error, PublicError)
            error = dict(
                code=error.errno,
                message=error.strerror,
                name=error.__class__.__name__,
                kw=dict(error.kw),
            )
        response = dict(
            result=result,
            error=error,
            id=_id,
        )
        return json.dumps(response, sort_keys=True, indent=4)

    def unmarshal(self, data):
        try:
            d = json.loads(data)
        except ValueError, e:
            raise JSONError(error=e)
        if not isinstance(d, dict):
            raise JSONError(error='Request must be a dict')
        if 'method' not in d:
            raise JSONError(error='Request is missing "method"')
        if 'params' not in d:
            raise JSONError(error='Request is missing "params"')
        method = d['method']
        params = d['params']
        _id = d.get('id')
        if not isinstance(params, (list, tuple)):
            raise JSONError(error='params must be a list')
        if len(params) != 2:
            raise JSONError(
                error='params must contain [args, options]'
            )
        args = params[0]
        if not isinstance(args, (list, tuple)):
            raise JSONError(
                error='params[0] (aka args) must be a list'
            )
        options = params[1]
        if not isinstance(options, dict):
            raise JSONError(
                error='params[1] (aka options) must be a dict'
            )
        return (method, args, options, _id)
