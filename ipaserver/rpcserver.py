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
from ipalib.errors import PublicError, InternalError, CommandError, JSONError, ConversionError, CCacheError, RefererError
from ipalib.request import context, Connection, destroy_context
from ipalib.rpc import xml_dumps, xml_loads
from ipalib.util import make_repr, parse_time_duration
from ipapython.compat import json
from ipalib.session import session_mgr, AuthManager, read_krbccache_file, store_krbccache_file, delete_krbccache_file, fmt_time, default_max_session_lifetime
from ipalib.backend import Backend
from ipalib.krb_utils import krb5_parse_ccache, KRB5_CCache, krb_ticket_expiration_threshold
from wsgiref.util import shift_path_info
from ipapython.version import VERSION
import base64
import os
import string
import datetime
from decimal import Decimal
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


class wsgi_dispatch(Executioner):
    """
    WSGI routing middleware and entry point into IPA server.

    The `wsgi_dispatch` plugin is the entry point into the IPA server.
    It dispatchs the request to the appropriate wsgi application
    handler which is specific to the authentication and RPC mechanism.
    """

    def __init__(self):
        super(wsgi_dispatch, self).__init__()
        self.__apps = {}

    def __iter__(self):
        for key in sorted(self.__apps):
            yield key

    def __getitem__(self, key):
        return self.__apps[key]

    def __contains__(self, key):
        return key in self.__apps

    def __call__(self, environ, start_response):
        self.debug('WSGI wsgi_dispatch.__call__:')
        try:
            return self.route(environ, start_response)
        finally:
            destroy_context()

    def _on_finalize(self):
        self.url = self.env['mount_ipa']
        super(wsgi_dispatch, self)._on_finalize()

    def route(self, environ, start_response):
        key = environ.get('PATH_INFO')
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
        if 'wsgi_dispatch' in self.api.Backend:
            self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def _on_finalize(self):
        self.url = self.env.mount_ipa + self.key
        super(WSGIExecutioner, self)._on_finalize()

    def wsgi_execute(self, environ):
        result = None
        error = None
        _id = None
        lang = os.environ['LANG']
        name = None
        args = ()
        options = {}

        if not 'HTTP_REFERER' in environ:
            return self.marshal(result, RefererError(referer='missing'), _id)
        if not environ['HTTP_REFERER'].startswith('https://%s/ipa' % self.api.env.host) and not self.env.in_tree:
            return self.marshal(result, RefererError(referer=environ['HTTP_REFERER']), _id)
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
        if name:
            try:
                params = self.Command[name].args_options_2_params(*args, **options)
            except Exception, e:
                self.info(
                   'exception %s caught when converting options: %s', e.__class__.__name__, str(e)
                )
                # get at least some context of what is going on
                params = options
            if error:
                self.info('%s: %s(%s): %s', context.principal, name, ', '.join(self.Command[name]._repr_iter(**params)), e.__class__.__name__)
            else:
                self.info('%s: %s(%s): SUCCESS', context.principal, name, ', '.join(self.Command[name]._repr_iter(**params)))
        else:
            self.info('%s: %s', context.principal, e.__class__.__name__)
        return self.marshal(result, error, _id)

    def simple_unmarshal(self, environ):
        name = environ['PATH_INFO'].strip('/')
        options = extract_query(environ)
        return (name, tuple(), options, None)

    def __call__(self, environ, start_response):
        """
        WSGI application for execution.
        """

        self.debug('WSGI WSGIExecutioner.__call__:')
        try:
            status = '200 OK'
            response = self.wsgi_execute(environ)
            headers = [('Content-Type', self.content_type + '; charset=utf-8')]
        except StandardError, e:
            self.exception('WSGI %s.__call__():', self.name)
            status = '500 Internal Server Error'
            response = status
            headers = [('Content-Type', 'text/plain')]

        session_data = getattr(context, 'session_data', None)
        if session_data is not None:
            # Send session cookie back and store session data
            # FIXME: the URL path should be retreived from somewhere (but where?), not hardcoded
            session_cookie = session_mgr.generate_cookie('/ipa', session_data['session_id'])
            headers.append(('Set-Cookie', session_cookie))

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
    key = '/xml'

    def _on_finalize(self):
        self.__system = {
            'system.listMethods': self.listMethods,
            'system.methodSignature': self.methodSignature,
            'system.methodHelp': self.methodHelp,
        }
        super(xmlserver, self)._on_finalize()

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI xmlserver.__call__:')
        ccache=environ.get('KRB5CCNAME')
        if ccache is None:
            return self.marshal(None, CCacheError())
        self.create_context(ccache=ccache)
        try:
            self.create_context(ccache=environ.get('KRB5CCNAME'))
            response = super(xmlserver, self).__call__(environ, start_response)
        except PublicError, e:
            status = '200 OK'
            response = status
            headers = [('Content-Type', 'text/plain')]
            start_response(status, headers)
            return self.marshal(None, e)
        finally:
            destroy_context()
        return response

    def listMethods(self, *params):
        return tuple(name.decode('UTF-8') for name in self.Command)

    def methodSignature(self, *params):
        return u'methodSignature not implemented'

    def methodHelp(self, *params):
        return u'methodHelp not implemented'

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
    elif isinstance(val, Decimal):
        return {'__base64__' : base64.b64encode(str(val))}
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

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI jsonserver.__call__:')

        response = super(jsonserver, self).__call__(environ, start_response)
        return response

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
            principal=unicode(context.principal),
            version=unicode(VERSION),
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

class AuthManagerKerb(AuthManager):
    '''
    Instances of the AuthManger class are used to handle
    authentication events delivered by the SessionManager. This class
    specifcally handles the management of Kerbeos credentials which
    may be stored in the session.
    '''

    def __init__(self, name):
        super(AuthManagerKerb, self).__init__(name)

    def logout(self, session_data):
        '''
        The current user has requested to be logged out. To accomplish
        this we remove the user's kerberos credentials from their
        session. This does not destroy the session, it just prevents
        it from being used for fast authentication. Because the
        credentials are no longer in the session cache any future
        attempt will require the acquisition of credentials using one
        of the login mechanisms.
        '''

        if session_data.has_key('ccache_data'):
            self.debug('AuthManager.logout.%s: deleting ccache_data', self.name)
            del session_data['ccache_data']
        else:
            self.error('AuthManager.logout.%s: session_data does not contain ccache_data', self.name)


class jsonserver_session(jsonserver):
    """
    JSON RPC server protected with session auth.
    """

    key = '/session/json'

    def __init__(self):
        super(jsonserver_session, self).__init__()
        auth_mgr = AuthManagerKerb(self.__class__.__name__)
        session_mgr.auth_mgr.register(auth_mgr.name, auth_mgr)

    def need_login(self, start_response):
        status = '401 Unauthorized'
        headers = []
        response = ''

        self.debug('jsonserver_session: %s', status)

        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI jsonserver_session.__call__:')

        # Load the session data
        session_data = session_mgr.load_session_data(environ.get('HTTP_COOKIE'))
        session_id = session_data['session_id']

        self.debug('jsonserver_session.__call__: session_id=%s start_timestamp=%s write_timestamp=%s expiration_timestamp=%s',
                   session_id,
                   fmt_time(session_data['session_start_timestamp']),
                   fmt_time(session_data['session_write_timestamp']),
                   fmt_time(session_data['session_expiration_timestamp']))

        ccache_data = session_data.get('ccache_data')

        # Redirect to login if no Kerberos credentials
        if ccache_data is None:
            self.debug('no ccache, need login')
            return self.need_login(start_response)

        krbccache_pathname = store_krbccache_file(ccache_data)

        # Redirect to login if Kerberos credentials are expired
        cc = KRB5_CCache(krbccache_pathname)
        if not cc.valid(self.api.env.host, self.api.env.realm):
            self.debug('ccache expired, deleting session, need login')
            delete_krbccache_file(krbccache_pathname)
            return self.need_login(start_response)

        # Store the session data in the per-thread context
        setattr(context, 'session_data', session_data)

        self.create_context(ccache=krbccache_pathname)

        try:
            response = super(jsonserver_session, self).__call__(environ, start_response)
        finally:
            # Kerberos may have updated the ccache data during the
            # execution of the command therefore we need refresh our
            # copy of it in the session data so the next command sees
            # the same state of the ccache.
            #
            # However we must be careful not to restore the ccache
            # data in the session data if it was explicitly deleted
            # during the execution of the command. For example the
            # logout command removes the ccache data from the session
            # data to invalidate the session credentials.

            if session_data.has_key('ccache_data'):
                session_data['ccache_data'] = read_krbccache_file(krbccache_pathname)

            # Delete the temporary ccache file we used
            delete_krbccache_file(krbccache_pathname)
            # Store the session data.
            session_mgr.store_session_data(session_data)
            destroy_context()

        return response

class jsonserver_kerb(jsonserver):
    """
    JSON RPC server protected with kerberos auth.
    """

    key = '/json'

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI jsonserver_kerb.__call__:')

        ccache=environ.get('KRB5CCNAME')
        if ccache is None:
            return self.marshal(None, CCacheError())
        self.create_context(ccache=ccache)

        try:
            response = super(jsonserver_kerb, self).__call__(environ, start_response)
        finally:
            destroy_context()

        return response


class krblogin(Backend):
    key = '/login'

    def __init__(self):
        super(krblogin, self).__init__()

    def _on_finalize(self):
        super(krblogin, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

        # Set the session expiration time
        try:
            seconds = parse_time_duration(self.api.env.session_auth_duration)
            self.session_auth_duration = int(seconds)
            self.debug("session_auth_duration: %s", datetime.timedelta(seconds=self.session_auth_duration))
        except Exception, e:
            self.session_auth_duration = default_max_session_lifetime
            self.error('unable to parse session_auth_duration, defaulting to %d: %s',
                       self.session_auth_duration, e)


    def __call__(self, environ, start_response):
        headers = []

        self.debug('WSGI krblogin.__call__:')

        # Get the ccache created by mod_auth_kerb
        ccache=environ.get('KRB5CCNAME')
        if ccache is None:
            status = '500 Internal Error'
            response = 'KRB5CCNAME not defined'
            start_response(status, headers)
            return [response]

        ccache_scheme, ccache_location = krb5_parse_ccache(ccache)
        assert ccache_scheme == 'FILE'

        # Retrieve the session data (or newly create)
        session_data = session_mgr.load_session_data(environ.get('HTTP_COOKIE'))
        session_id = session_data['session_id']

        # Copy the ccache file contents into the session data
        session_data['ccache_data'] = read_krbccache_file(ccache_location)

        # Compute when the session will expire
        cc = KRB5_CCache(ccache)
        endtime = cc.endtime(self.api.env.host, self.api.env.realm)

        # Account for clock skew and/or give us some time leeway
        krb_expiration = endtime - krb_ticket_expiration_threshold

        # Set the session expiration time
        session_mgr.set_session_expiration_time(session_data,
                                                lifetime=self.session_auth_duration,
                                                max_age=krb_expiration)

        # Store the session data now that it's been updated with the ccache
        session_mgr.store_session_data(session_data)

        self.debug('krblogin: ccache="%s" session_id="%s" ccache="%s"',
                   ccache, session_id, ccache)

        # Return success and set session cookie
        status = '200 Success'
        response = ''

        session_cookie = session_mgr.generate_cookie('/ipa', session_id)
        headers.append(('Set-Cookie', session_cookie))

        start_response(status, headers)
        return [response]
