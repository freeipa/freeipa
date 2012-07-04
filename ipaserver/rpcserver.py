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
from wsgiref.util import shift_path_info
import base64
import os
import string
import datetime
from decimal import Decimal
import urlparse
import time

from ipalib import plugable
from ipalib.backend import Executioner
from ipalib.errors import PublicError, InternalError, CommandError, JSONError, ConversionError, CCacheError, RefererError, InvalidSessionPassword, NotFound, ACIError, ExecutionError
from ipalib.request import context, Connection, destroy_context
from ipalib.rpc import xml_dumps, xml_loads
from ipalib.util import parse_time_duration
from ipapython.dn import DN
from ipaserver.plugins.ldap2 import ldap2
from ipapython.compat import json
from ipalib.session import session_mgr, AuthManager, get_ipa_ccache_name, load_ccache_data, bind_ipa_ccache, release_ipa_ccache, fmt_time, default_max_session_duration
from ipalib.backend import Backend
from ipalib.krb_utils import krb5_parse_ccache, KRB5_CCache, krb_ticket_expiration_threshold, krb5_format_principal_name
from ipapython import ipautil
from ipapython.version import VERSION
from ipalib.text import _

HTTP_STATUS_SUCCESS = '200 Success'
HTTP_STATUS_SERVER_ERROR = '500 Internal Server Error'

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

_bad_request_template = """<html>
<head>
<title>400 Bad Request</title>
</head>
<body>
<h1>Bad Request</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

_internal_error_template = """<html>
<head>
<title>500 Internal Server Error</title>
</head>
<body>
<h1>Internal Server Error</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

_unauthorized_template = """<html>
<head>
<title>401 Unauthorized</title>
</head>
<body>
<h1>Invalid Authentication</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

_pwchange_template = """<html>
<head>
<title>200 Success</title>
</head>
<body>
<h1>%(title)s</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

class HTTP_Status(plugable.Plugin):
    def not_found(self, environ, start_response, url, message):
        """
        Return a 404 Not Found error.
        """
        status = '404 Not Found'
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        self.info('%s: URL="%s", %s', status, url, message)
        start_response(status, response_headers)
        output = _not_found_template % dict(url=escape(url))
        return [output]

    def bad_request(self, environ, start_response, message):
        """
        Return a 400 Bad Request error.
        """
        status = '400 Bad Request'
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        self.info('%s: %s', status, message)

        start_response(status, response_headers)
        output = _bad_request_template % dict(message=escape(message))
        return [output]

    def internal_error(self, environ, start_response, message):
        """
        Return a 500 Internal Server Error.
        """
        status = HTTP_STATUS_SERVER_ERROR
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        self.error('%s: %s', status, message)

        start_response(status, response_headers)
        output = _internal_error_template % dict(message=escape(message))
        return [output]

    def unauthorized(self, environ, start_response, message, reason):
        """
        Return a 401 Unauthorized error.
        """
        status = '401 Unauthorized'
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]
        if reason:
            response_headers.append(('X-IPA-Rejection-Reason', reason))

        self.info('%s: %s', status, message)

        start_response(status, response_headers)
        output = _unauthorized_template % dict(message=escape(message))
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


class wsgi_dispatch(Executioner, HTTP_Status):
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
        url = environ['SCRIPT_NAME'] + environ['PATH_INFO']
        return self.not_found(environ, start_response, url,
                              'URL fragment "%s" does not have a handler' % (key))

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
        if name and name in self.Command:
            try:
                params = self.Command[name].args_options_2_params(*args, **options)
            except Exception, e:
                self.info(
                   'exception %s caught when converting options: %s', e.__class__.__name__, str(e)
                )
                # get at least some context of what is going on
                params = options
            principal = getattr(context, 'principal', 'UNKNOWN')
            if error:
                self.info('%s: %s(%s): %s', principal, name, ', '.join(self.Command[name]._repr_iter(**params)), e.__class__.__name__)
            else:
                self.info('%s: %s(%s): SUCCESS', principal, name, ', '.join(self.Command[name]._repr_iter(**params)))
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
            status = HTTP_STATUS_SUCCESS
            response = self.wsgi_execute(environ)
            headers = [('Content-Type', self.content_type + '; charset=utf-8')]
        except StandardError, e:
            self.exception('WSGI %s.__call__():', self.name)
            status = HTTP_STATUS_SERVER_ERROR
            response = status
            headers = [('Content-Type', 'text/plain; charset=utf-8')]

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
            new_dict[k] = json_encode_binary(v)
        return new_dict
    elif isinstance(val, (list, tuple)):
        new_list = [json_encode_binary(v) for v in val]
        return new_list
    elif isinstance(val, str):
        return {'__base64__' : base64.b64encode(val)}
    elif isinstance(val, Decimal):
        return {'__base64__' : base64.b64encode(str(val))}
    elif isinstance(val, DN):
        return str(val)
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

class jsonserver(WSGIExecutioner, HTTP_Status):
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
        principal = getattr(context, 'principal', 'UNKNOWN')
        response = dict(
            result=result,
            error=error,
            id=_id,
            principal=unicode(principal),
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
            raise JSONError(error=_('Request must be a dict'))
        if 'method' not in d:
            raise JSONError(error=_('Request is missing "method"'))
        if 'params' not in d:
            raise JSONError(error=_('Request is missing "params"'))
        d = json_decode_binary(d)
        method = d['method']
        params = d['params']
        _id = d.get('id')
        if not isinstance(params, (list, tuple)):
            raise JSONError(error=_('params must be a list'))
        if len(params) != 2:
            raise JSONError(error=_('params must contain [args, options]'))
        args = params[0]
        if not isinstance(args, (list, tuple)):
            raise JSONError(error=_('params[0] (aka args) must be a list'))
        options = params[1]
        if not isinstance(options, dict):
            raise JSONError(error=_('params[1] (aka options) must be a dict'))
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


class KerberosSession(object):
    '''
    Functionally shared by all RPC handlers using both sessions and
    Kerberos.  This class must be implemented as a mixin class rather
    than the more obvious technique of subclassing because the classes
    needing this do not share a common base class.
    '''

    def kerb_session_on_finalize(self):
        '''
        Initialize values from the Env configuration.

        Why do it this way and not simply reference
        api.env.session_auth_duration? Because that config item cannot
        be used directly, it must be parsed and converted to an
        integer. It would be inefficient to reparse it on every
        request. So we parse it once and store the result in the class
        instance.
        '''
        # Set the session expiration time
        try:
            seconds = parse_time_duration(self.api.env.session_auth_duration)
            self.session_auth_duration = int(seconds)
            self.debug("session_auth_duration: %s", datetime.timedelta(seconds=self.session_auth_duration))
        except Exception, e:
            self.session_auth_duration = default_max_session_duration
            self.error('unable to parse session_auth_duration, defaulting to %d: %s',
                       self.session_auth_duration, e)

    def update_session_expiration(self, session_data, krb_endtime):
        '''
        Each time a session is created or accessed we need to update
        it's expiration time. The expiration time is set inside the
        session_data.

        :parameters:
          session_data
            The session data whose expiration is being updatded.
          krb_endtime
            The UNIX timestamp for when the Kerberos credentials expire.
        :returns:
          None
        '''

        # Account for clock skew and/or give us some time leeway
        krb_expiration = krb_endtime - krb_ticket_expiration_threshold

        # Set the session expiration time
        session_mgr.set_session_expiration_time(session_data,
                                                duration=self.session_auth_duration,
                                                max_age=krb_expiration,
                                                duration_type=self.api.env.session_duration_type)


    def finalize_kerberos_acquisition(self, who, ccache_name, environ, start_response, headers=None):
        if headers is None:
            headers = []

        # Retrieve the session data (or newly create)
        session_data = session_mgr.load_session_data(environ.get('HTTP_COOKIE'))
        session_id = session_data['session_id']

        self.debug('finalize_kerberos_acquisition: %s ccache_name="%s" session_id="%s"',
                   who, ccache_name, session_id)

        # Copy the ccache file contents into the session data
        session_data['ccache_data'] = load_ccache_data(ccache_name)

        # Set when the session will expire
        cc = KRB5_CCache(ccache_name)
        endtime = cc.endtime(self.api.env.host, self.api.env.realm)
        self.update_session_expiration(session_data, endtime)

        # Store the session data now that it's been updated with the ccache
        session_mgr.store_session_data(session_data)

        # The request is finished with the ccache, destroy it.
        release_ipa_ccache(ccache_name)

        # Return success and set session cookie
        session_cookie = session_mgr.generate_cookie('/ipa', session_id)
        headers.append(('Set-Cookie', session_cookie))

        start_response(HTTP_STATUS_SUCCESS, headers)
        return ['']


class xmlserver(WSGIExecutioner, HTTP_Status, KerberosSession):
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
        self.kerb_session_on_finalize()

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI xmlserver.__call__:')
        user_ccache=environ.get('KRB5CCNAME')
        if user_ccache is None:
            self.internal_error(environ, start_response,
                                'xmlserver.__call__: KRB5CCNAME not defined in HTTP request environment')
            return self.marshal(None, CCacheError())
        try:
            self.create_context(ccache=user_ccache)
            response = super(xmlserver, self).__call__(environ, start_response)
            if getattr(context, 'session_data', None) is None and \
              self.env.context != 'lite':
                self.finalize_kerberos_acquisition('xmlserver', user_ccache, environ, start_response)
        except PublicError, e:
            status = HTTP_STATUS_SUCCESS
            response = status
            headers = [('Content-Type', 'text/plain; charset=utf-8')]
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


class jsonserver_session(jsonserver, KerberosSession):
    """
    JSON RPC server protected with session auth.
    """

    key = '/session/json'

    def __init__(self):
        super(jsonserver_session, self).__init__()
        auth_mgr = AuthManagerKerb(self.__class__.__name__)
        session_mgr.auth_mgr.register(auth_mgr.name, auth_mgr)

    def _on_finalize(self):
        super(jsonserver_session, self)._on_finalize()
        self.kerb_session_on_finalize()

    def need_login(self, start_response):
        status = '401 Unauthorized'
        headers = []
        response = ''

        self.debug('jsonserver_session: %s need login', status)

        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI jsonserver_session.__call__:')

        # Load the session data
        session_data = session_mgr.load_session_data(environ.get('HTTP_COOKIE'))
        session_id = session_data['session_id']

        self.debug('jsonserver_session.__call__: session_id=%s start_timestamp=%s access_timestamp=%s expiration_timestamp=%s',
                   session_id,
                   fmt_time(session_data['session_start_timestamp']),
                   fmt_time(session_data['session_access_timestamp']),
                   fmt_time(session_data['session_expiration_timestamp']))

        ccache_data = session_data.get('ccache_data')

        # Redirect to login if no Kerberos credentials
        if ccache_data is None:
            self.debug('no ccache, need login')
            return self.need_login(start_response)

        ipa_ccache_name = bind_ipa_ccache(ccache_data)

        # Redirect to login if Kerberos credentials are expired
        cc = KRB5_CCache(ipa_ccache_name)
        if not cc.valid(self.api.env.host, self.api.env.realm):
            self.debug('ccache expired, deleting session, need login')
            # The request is finished with the ccache, destroy it.
            release_ipa_ccache(ipa_ccache_name)
            return self.need_login(start_response)

        # Update the session expiration based on the Kerberos expiration
        endtime = cc.endtime(self.api.env.host, self.api.env.realm)
        self.update_session_expiration(session_data, endtime)

        # Store the session data in the per-thread context
        setattr(context, 'session_data', session_data)

        self.create_context(ccache=ipa_ccache_name)

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
                session_data['ccache_data'] = load_ccache_data(ipa_ccache_name)

            # The request is finished with the ccache, destroy it.
            release_ipa_ccache(ipa_ccache_name)
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

        user_ccache=environ.get('KRB5CCNAME')
        if user_ccache is None:
            self.internal_error(environ, start_response,
                                'jsonserver_kerb.__call__: KRB5CCNAME not defined in HTTP request environment')
            return self.marshal(None, CCacheError())
        self.create_context(ccache=user_ccache)

        try:
            response = super(jsonserver_kerb, self).__call__(environ, start_response)
        finally:
            destroy_context()

        return response


class login_kerberos(Backend, KerberosSession, HTTP_Status):
    key = '/session/login_kerberos'

    def __init__(self):
        super(login_kerberos, self).__init__()

    def _on_finalize(self):
        super(login_kerberos, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)
        self.kerb_session_on_finalize()

    def __call__(self, environ, start_response):
        self.debug('WSGI login_kerberos.__call__:')

        # Get the ccache created by mod_auth_kerb
        user_ccache_name=environ.get('KRB5CCNAME')
        if user_ccache_name is None:
            return self.internal_error(environ, start_response,
                                       'login_kerberos: KRB5CCNAME not defined in HTTP request environment')

        return self.finalize_kerberos_acquisition('login_kerberos', user_ccache_name, environ, start_response)

class login_password(Backend, KerberosSession, HTTP_Status):

    content_type = 'text/plain'
    key = '/session/login_password'

    def __init__(self):
        super(login_password, self).__init__()

    def _on_finalize(self):
        super(login_password, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)
        self.kerb_session_on_finalize()

    def __call__(self, environ, start_response):
        self.debug('WSGI login_password.__call__:')

        # Get the user and password parameters from the request
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(environ, start_response, "Content-Type must be application/x-www-form-urlencoded")

        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(environ, start_response, "HTTP request method must be POST")

        try:
            query_dict = urlparse.parse_qs(query_string)
        except Exception, e:
            return self.bad_request(environ, start_response, "cannot parse query data")

        user = query_dict.get('user', None)
        if user is not None:
            if len(user) == 1:
                user = user[0]
            else:
                return self.bad_request(environ, start_response, "more than one user parameter")
        else:
            return self.bad_request(environ, start_response, "no user specified")

        password = query_dict.get('password', None)
        if password is not None:
            if len(password) == 1:
                password = password[0]
            else:
                return self.bad_request(environ, start_response, "more than one password parameter")
        else:
            return self.bad_request(environ, start_response, "no password specified")

        # Get the ccache we'll use and attempt to get credentials in it with user,password
        ipa_ccache_name = get_ipa_ccache_name()
        reason = 'invalid-password'
        try:
            self.kinit(user, self.api.env.realm, password, ipa_ccache_name)
        except InvalidSessionPassword, e:
            # Ok, now why is this bad. Is the password simply bad or is the
            # password expired?
            try:
                dn = DN(('uid', user),
                        self.api.env.container_user,
                        self.api.env.basedn)
                conn = ldap2(shared_instance=False,
                             ldap_uri=self.api.env.ldap_uri)
                conn.connect(bind_dn=dn, bind_pw=password)

                # password is ok, must be expired, lets double-check
                (userdn, entry_attrs) = conn.get_entry(dn,
                    ['krbpasswordexpiration'])
                if 'krbpasswordexpiration' in entry_attrs:
                    expiration = entry_attrs['krbpasswordexpiration'][0]
                    try:
                        exp = time.strptime(expiration, '%Y%m%d%H%M%SZ')
                        if exp <= time.gmtime():
                            reason = 'password-expired'
                    except ValueError, v:
                        self.error('Unable to convert %s to a time string'
                            % expiration)

            except Exception:
                # It doesn't really matter how we got here but the user's
                # password is not accepted or the user is unknown.
                pass
            finally:
                if conn.isconnected():
                    conn.destroy_connection()

            return self.unauthorized(environ, start_response, str(e), reason)

        return self.finalize_kerberos_acquisition('login_password', ipa_ccache_name, environ, start_response)

    def kinit(self, user, realm, password, ccache_name):
        # Format the user as a kerberos principal
        principal = krb5_format_principal_name(user, realm)

        (stdout, stderr, returncode) = ipautil.run(['/usr/bin/kinit', principal],
                                                   env={'KRB5CCNAME':ccache_name},
                                                   stdin=password, raiseonerr=False)
        self.debug('kinit: principal=%s returncode=%s, stderr="%s"',
                   principal, returncode, stderr)

        if returncode != 0:
            raise InvalidSessionPassword(principal=principal, message=unicode(stderr))

class change_password(Backend, HTTP_Status):

    content_type = 'text/plain'
    key = '/session/change_password'

    def __init__(self):
        super(change_password, self).__init__()

    def _on_finalize(self):
        super(change_password, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        self.info('WSGI change_password.__call__:')

        # Get the user and password parameters from the request
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(environ, start_response, "Content-Type must be application/x-www-form-urlencoded")

        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(environ, start_response, "HTTP request method must be POST")

        try:
            query_dict = urlparse.parse_qs(query_string)
        except Exception, e:
            return self.bad_request(environ, start_response, "cannot parse query data")

        data = {}
        for field in ('user', 'old_password', 'new_password'):
            value = query_dict.get(field, None)
            if value is not None:
                if len(value) == 1:
                    data[field] = value[0]
                else:
                    return self.bad_request(environ, start_response, "more than one %s parameter"
                                            % field)
            else:
                return self.bad_request(environ, start_response, "no %s specified" % field)

        # start building the response
        self.info("WSGI change_password: start password change of user '%s'", data['user'])
        status = HTTP_STATUS_SUCCESS
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]
        title = 'Password change rejected'
        result = 'error'
        policy_error = None

        bind_dn = DN((self.api.Object.user.primary_key.name, data['user']),
                     self.api.env.container_user, self.api.env.basedn)

        try:
            conn = ldap2(shared_instance=False,
                         ldap_uri=self.api.env.ldap_uri)
            conn.connect(bind_dn=bind_dn, bind_pw=data['old_password'])
        except (NotFound, ACIError):
            result = 'invalid-password'
            message = 'The old password or username is not correct.'
        except Exception, e:
            message = "Could not connect to LDAP server."
            self.error("change_password: cannot authenticate '%s' to LDAP server: %s",
                    data['user'], str(e))
        else:
            try:
                conn.modify_password(bind_dn, data['new_password'], data['old_password'])
            except ExecutionError, e:
                result = 'policy-error'
                policy_error = escape(str(e))
                message = "Password change was rejected: %s" % escape(str(e))
            except Exception, e:
                message = "Could not change the password"
                self.error("change_password: cannot change password of '%s': %s",
                        data['user'], str(e))
            else:
                result = 'ok'
                title = "Password change successful"
                message = "Password was changed."
            finally:
                if conn.isconnected():
                    conn.destroy_connection()

        self.info('%s: %s', status, message)

        response_headers.append(('X-IPA-Pwchange-Result', result))
        if policy_error:
            response_headers.append(('X-IPA-Pwchange-Policy-Error', policy_error))

        start_response(status, response_headers)
        output = _pwchange_template % dict(title=str(title),
                                           message=str(message))
        return [output]


class xmlserver_session(xmlserver, KerberosSession):
    """
    XML RPC server protected with session auth.
    """

    key = '/session/xml'

    def __init__(self):
        super(xmlserver_session, self).__init__()
        auth_mgr = AuthManagerKerb(self.__class__.__name__)
        session_mgr.auth_mgr.register(auth_mgr.name, auth_mgr)

    def _on_finalize(self):
        super(xmlserver_session, self)._on_finalize()
        self.kerb_session_on_finalize()

    def need_login(self, start_response):
        status = '401 Unauthorized'
        headers = []
        response = ''

        self.debug('xmlserver_session: %s need login', status)

        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI xmlserver_session.__call__:')

        # Load the session data
        session_data = session_mgr.load_session_data(environ.get('HTTP_COOKIE'))
        session_id = session_data['session_id']

        self.debug('xmlserver_session.__call__: session_id=%s start_timestamp=%s access_timestamp=%s expiration_timestamp=%s',
                   session_id,
                   fmt_time(session_data['session_start_timestamp']),
                   fmt_time(session_data['session_access_timestamp']),
                   fmt_time(session_data['session_expiration_timestamp']))

        ccache_data = session_data.get('ccache_data')

        # Redirect to /ipa/xml if no Kerberos credentials
        if ccache_data is None:
            self.debug('xmlserver_session.__call_: no ccache, need TGT')
            return self.need_login(start_response)

        ipa_ccache_name = bind_ipa_ccache(ccache_data)

        # Redirect to /ipa/xml if Kerberos credentials are expired
        cc = KRB5_CCache(ipa_ccache_name)
        if not cc.valid(self.api.env.host, self.api.env.realm):
            self.debug('xmlserver_session.__call_: ccache expired, deleting session, need login')
            # The request is finished with the ccache, destroy it.
            release_ipa_ccache(ipa_ccache_name)
            return self.need_login(start_response)

        # Update the session expiration based on the Kerberos expiration
        endtime = cc.endtime(self.api.env.host, self.api.env.realm)
        self.update_session_expiration(session_data, endtime)

        # Store the session data in the per-thread context
        setattr(context, 'session_data', session_data)

        environ['KRB5CCNAME'] = ipa_ccache_name

        try:
            response = super(xmlserver_session, self).__call__(environ, start_response)
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
                session_data['ccache_data'] = load_ccache_data(ipa_ccache_name)

            # The request is finished with the ccache, destroy it.
            release_ipa_ccache(ipa_ccache_name)
            # Store the session data.
            session_mgr.store_session_data(session_data)
            destroy_context()

        return response
