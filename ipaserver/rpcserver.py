# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
RPC server.

Also see the `ipalib.rpc` module.
"""

from cgi import parse_qs
from xml.sax.saxutils import escape
from xmlrpclib import Fault
from ipalib.backend import Executioner
from ipalib.errors import PublicError, InternalError, CommandError, JSONError, ConversionError, CCacheError
from ipalib.request import context, Connection, destroy_context
from ipalib.rpc import xml_dumps, xml_loads
from ipalib.util import make_repr
from ipalib.compat import json
from wsgiref.util import shift_path_info
import base64
import os
import string
_not_found_template = """<html>
<head>
<title>404 Not Found</title>
</head>
<body>
<h1>Not Found</h1>
<p>
The requested URL <strong>%(url)s</strong> was not found on this server.
</p>
</body>
</html>"""


def not_found(environ, start_response):
    """
    Return a 404 Not Found error.
    """
    status = '404 Not Found'
    response_headers = [('Content-Type', 'text/html')]
    start_response(status, response_headers)
    output = _not_found_template % dict(
        url=escape(environ['SCRIPT_NAME'] + environ['PATH_INFO'])
    )
    return [output]

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
    if len(params) == 0:
        return (tuple(), dict())
    if len(params) == 1:
        return (params[0], dict())
    return (params[0], params[1])


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
            parse_qs(qstr)#, keep_blank_values=True)
        ))
    else:
        query = {}
    environ['wsgi.query'] = query
    return query


class session(Executioner):
    """
    WSGI routing middleware and entry point into IPA server.

    The `session` plugin is the entry point into the IPA server.  It will create
    an LDAP connection (from a session cookie or the KRB5CCNAME header) and then
    dispatch the request to the appropriate application.  In WSGI parlance,
    `session` is *middleware*.
    """

    def __init__(self):
        super(session, self).__init__()
        self.__apps = {}

    def __iter__(self):
        for key in sorted(self.__apps):
            yield key

    def __getitem__(self, key):
        return self.__apps[key]

    def __contains__(self, key):
        return key in self.__apps

    def __call__(self, environ, start_response):
        try:
            self.create_context(ccache=environ.get('KRB5CCNAME'))
            return self.route(environ, start_response)
        finally:
            destroy_context()

    def finalize(self):
        self.url = self.env['mount_ipa']
        super(session, self).finalize()

    def route(self, environ, start_response):
        key = shift_path_info(environ)
        if key in self.__apps:
            app = self.__apps[key]
            return app(environ, start_response)
        return not_found(environ, start_response)

    def mount(self, app, key):
        """
        Mount the WSGI application *app* at *key*.
        """
#        if self.__islocked__():
#            raise StandardError('%s.mount(): locked, cannot mount %r at %r' % (
#                self.name, app, key)
#            )
        if key in self.__apps:
            raise StandardError('%s.mount(): cannot replace %r with %r at %r' % (
                self.name, self.__apps[key], app, key)
            )
        self.debug('Mounting %r at %r', app, key)
        self.__apps[key] = app





class WSGIExecutioner(Executioner):
    """
    Base class for execution backends with a WSGI application interface.
    """

    content_type = None
    key = ''

    def set_api(self, api):
        super(WSGIExecutioner, self).set_api(api)
        if 'session' in self.api.Backend:
            self.api.Backend.session.mount(self, self.key)

    def finalize(self):
        self.url = self.env.mount_ipa + self.key
        super(WSGIExecutioner, self).finalize()

    def wsgi_execute(self, environ):
        result = None
        error = None
        _id = None
        lang = os.environ['LANG']
        if not 'KRB5CCNAME' in environ:
            return self.marshal(result, CCacheError(), _id)
        try:
            if ('HTTP_ACCEPT_LANGUAGE' in environ):
                lang_reg_w_q = environ['HTTP_ACCEPT_LANGUAGE'].split(',')[0]
                lang_reg = lang_reg_w_q.split(';')[0]
                lang_ = lang_reg.split('-')[0]
                if '-' in lang_reg:
                    reg = lang_reg.split('-')[1].upper();
                else:
                    reg = lang_.upper()
                os.environ['LANG'] = '%s_%s' % (lang_, reg)
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
            os.environ['LANG'] = lang
        if error is None:
            params = self.Command[name].args_options_2_params(*args, **options)
            if error:
                self.info('%s: %s(%s): %s', context.principal, name, ', '.join(self.Command[name]._repr_iter(**params)), e.__class__.__name__)
            else:
                self.info('%s: %s(%s): SUCCESS', context.principal, name, ', '.join(self.Command[name]._repr_iter(**params)))
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
            response = self.wsgi_execute(environ)
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
    key = 'xml'

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

    def marshaled_dispatch(self, data, ccache, client_ip):
        """
        Execute the XML-RPC request contained in ``data``.
        """
        try:
            self.create_context(ccache=ccache, client_ip=client_ip)
            (params, name) = xml_loads(data)
            if name in self.__system:
                response = (self.__system[name](*params),)
            else:
                (args, options) = params_2_args_options(params)
                response = (self.execute(name, *args, **options),)
        except PublicError, e:
            self.debug('response: %s: %s', e.__class__.__name__, str(e))
            response = Fault(e.errno, e.strerror)
        return xml_dumps(response, methodresponse=True)

    def unmarshal(self, data):
        (params, name) = xml_loads(data)
        (args, options) = params_2_args_options(params)
        return (name, args, options, None)

    def marshal(self, result, error, _id=None):
        if error:
            self.debug('response: %s: %s', error.__class__.__name__, str(error))
            response = Fault(error.errno, error.strerror)
        else:
            if isinstance(result, dict):
                self.debug('response: entries returned %d', result.get('count', 1))
            response = (result,)
        return xml_dumps(response, methodresponse=True)


def json_encode_binary(val):
    '''
   JSON cannot encode binary values. We encode binary values in Python str
   objects and text in Python unicode objects. In order to allow a binary
   object to be passed through JSON we base64 encode it thus converting it to
   text which JSON can transport. To assure we recognize the value is a base64
   encoded representation of the original binary value and not confuse it with
   other text we convert the binary value to a dict in this form:

   {'__base64__' : base64_encoding_of_binary_value}

   This modification of the original input value cannot be done "in place" as
   one might first assume (e.g. replacing any binary items in a container
   (e.g. list, tuple, dict) with the base64 dict because the container might be
   an immutable object (i.e. a tuple). Therefore this function returns a copy
   of any container objects it encounters with tuples replaced by lists. This
   is O.K. because the JSON encoding will map both lists and tuples to JSON
   arrays.
   '''

    if isinstance(val, dict):
        new_dict = {}
        for k,v in val.items():
            if isinstance(v, str):
                new_dict[k] = {'__base64__' : base64.b64encode(v)}
            else:
                new_dict[k] = json_encode_binary(v)
        del val
        return new_dict
    elif isinstance(val, (list, tuple)):
        new_list = []
        n = len(val)
        i = 0
        while i < n:
            v = val[i]
            if isinstance(v, str):
                new_list.append({'__base64__' : base64.b64encode(v)})
            else:
                new_list.append(json_encode_binary(v))
            i += 1
        del val
        return new_list
    elif isinstance(val, str):
        return {'__base64__' : base64.b64encode(val)}
    else:
        return val

def json_decode_binary(val):
    '''
    JSON cannot transport binary data. In order to transport binary data we
    convert binary data to a form like this:

   {'__base64__' : base64_encoding_of_binary_value}

   see json_encode_binary()

    After JSON had decoded the JSON stream back into a Python object we must
    recursively scan the object looking for any dicts which might represent
    binary values and replace the dict containing the base64 encoding of the
    binary value with the decoded binary value. Unlike the encoding problem
    where the input might consist of immutable object, all JSON decoded
    container are mutable so the conversion could be done in place. However we
    don't modify objects in place because of side effects which may be
    dangerous. Thus we elect to spend a few more cycles and avoid the
    possibility of unintended side effects in favor of robustness.
    '''

    if isinstance(val, dict):
        if val.has_key('__base64__'):
            return base64.b64decode(val['__base64__'])
        else:
            new_dict = {}
            for k,v in val.items():
                if isinstance(v, dict) and v.has_key('__base64__'):
                        new_dict[k] = base64.b64decode(v['__base64__'])
                else:
                    new_dict[k] = json_decode_binary(v)
            del val
            return new_dict
    elif isinstance(val, list):
        new_list = []
        n = len(val)
        i = 0
        while i < n:
            v = val[i]
            if isinstance(v, dict) and v.has_key('__base64__'):
                binary_val = base64.b64decode(v['__base64__'])
                new_list.append(binary_val)
            else:
                new_list.append(json_decode_binary(v))
            i += 1
        del val
        return new_list
    else:
        if isinstance(val, basestring):
            try:
                return val.decode('utf-8')
            except UnicodeDecodeError:
                raise ConversionError(
                    name=val,
                    error='incorrect type'
                )
        else:
            return val

class jsonserver(WSGIExecutioner):
    """
    JSON RPC server.

    For information on the JSON-RPC spec, see:

        http://json-rpc.org/wiki/specification
    """

    content_type = 'application/json'
    key = 'json'

    def marshal(self, result, error, _id=None):
        if error:
            assert isinstance(error, PublicError)
            error = dict(
                code=error.errno,
                message=error.strerror,
                name=error.__class__.__name__,
            )
        response = dict(
            result=result,
            error=error,
            id=_id,
        )
        response = json_encode_binary(response)
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
        d = json_decode_binary(d)
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
        options = dict((str(k), v) for (k, v) in options.iteritems())
        return (method, args, options, _id)
