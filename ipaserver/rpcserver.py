# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008-2016  Red Hat
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

from xml.sax.saxutils import escape
import os
import datetime
import json
import traceback
import gssapi
import time

import ldap.controls
from pyasn1.type import univ, namedtype
from pyasn1.codec.ber import encoder
import six
# pylint: disable=import-error
from six.moves.urllib.parse import parse_qs
from six.moves.xmlrpc_client import Fault
# pylint: enable=import-error

from ipalib import plugable, errors
from ipalib.capabilities import VERSION_WITHOUT_CAPABILITIES
from ipalib.frontend import Local
from ipalib.install.kinit import kinit_keytab, kinit_password
from ipalib.backend import Executioner
from ipalib.errors import (PublicError, InternalError, JSONError,
    CCacheError, RefererError, InvalidSessionPassword, NotFound, ACIError,
    ExecutionError, PasswordExpired, KrbPrincipalExpired, UserLocked)
from ipalib.request import context, destroy_context
from ipalib.rpc import (xml_dumps, xml_loads,
    json_encode_binary, json_decode_binary)
from ipalib.util import parse_time_duration, normalize_name
from ipapython.dn import DN
from ipaserver.plugins.ldap2 import ldap2
from ipaserver.session import (
    get_session_mgr, AuthManager, get_ipa_ccache_name,
    load_ccache_data, bind_ipa_ccache, release_ipa_ccache, fmt_time,
    default_max_session_duration, krbccache_dir, krbccache_prefix)
from ipalib.backend import Backend
from ipalib.krb_utils import (
    krb_ticket_expiration_threshold, krb5_format_principal_name,
    krb5_format_service_principal_name, get_credentials, get_credentials_if_valid)
from ipapython import ipautil
from ipaplatform.paths import paths
from ipapython.version import VERSION
from ipalib.text import _

if six.PY3:
    unicode = str

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

_success_template = """<html>
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
        return [output.encode('utf-8')]

    def bad_request(self, environ, start_response, message):
        """
        Return a 400 Bad Request error.
        """
        status = '400 Bad Request'
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        self.info('%s: %s', status, message)

        start_response(status, response_headers)
        output = _bad_request_template % dict(message=escape(message))
        return [output.encode('utf-8')]

    def internal_error(self, environ, start_response, message):
        """
        Return a 500 Internal Server Error.
        """
        status = HTTP_STATUS_SERVER_ERROR
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        self.error('%s: %s', status, message)

        start_response(status, response_headers)
        output = _internal_error_template % dict(message=escape(message))
        return [output.encode('utf-8')]

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
        return [output.encode('utf-8')]

def read_input(environ):
    """
    Read the request body from environ['wsgi.input'].
    """
    try:
        length = int(environ.get('CONTENT_LENGTH'))
    except (ValueError, TypeError):
        return
    return environ['wsgi.input'].read(length).decode('utf-8')


def params_2_args_options(params):
    if len(params) == 0:
        return (tuple(), dict())
    if len(params) == 1:
        return (params[0], dict())
    return (params[0], params[1])


def nicify_query(query, encoding='utf-8'):
    if not query:
        return
    for (key, value) in query.items():
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
        query = dict(nicify_query(parse_qs(qstr)))  # keep_blank_values=True)
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

    def __init__(self, api):
        super(wsgi_dispatch, self).__init__(api)
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
#            raise Exception('%s.mount(): locked, cannot mount %r at %r' % (
#                self.name, app, key)
#            )
        if key in self.__apps:
            raise Exception('%s.mount(): cannot replace %r with %r at %r' % (
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

    _system_commands = {}

    def _on_finalize(self):
        self.url = self.env.mount_ipa + self.key
        super(WSGIExecutioner, self)._on_finalize()
        if 'wsgi_dispatch' in self.api.Backend:
            self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def _get_command(self, name):
        try:
            # assume version 1 for unversioned command calls
            command = self.api.Command[name, '1']
        except KeyError:
            try:
                command = self.api.Command[name]
            except KeyError:
                command = None

        if command is None or isinstance(command, Local):
            raise errors.CommandError(name=name)

        return command

    def wsgi_execute(self, environ):
        result = None
        error = None
        _id = None
        lang = os.environ['LANG']
        name = None
        args = ()
        options = {}
        command = None

        e = None
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
                    reg = lang_reg.split('-')[1].upper()
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
            if name in self._system_commands:
                result = self._system_commands[name](self, *args, **options)
            else:
                command = self._get_command(name)
                result = command(*args, **options)
        except PublicError as e:
            if self.api.env.debug:
                self.debug('WSGI wsgi_execute PublicError: %s', traceback.format_exc())
            error = e
        except Exception as e:
            self.exception(
                'non-public: %s: %s', e.__class__.__name__, str(e)
            )
            error = InternalError()
        finally:
            os.environ['LANG'] = lang

        principal = getattr(context, 'principal', 'UNKNOWN')
        if command is not None:
            try:
                params = command.args_options_2_params(*args, **options)
            except Exception as e:
                self.info(
                   'exception %s caught when converting options: %s', e.__class__.__name__, str(e)
                )
                # get at least some context of what is going on
                params = options
                error = e
            if error:
                result_string = type(error).__name__
            else:
                result_string = 'SUCCESS'
            self.info('[%s] %s: %s(%s): %s',
                      type(self).__name__,
                      principal,
                      name,
                      ', '.join(command._repr_iter(**params)),
                      result_string)
        else:
            self.info('[%s] %s: %s: %s',
                      type(self).__name__,
                      principal,
                      name,
                      type(error).__name__)

        version = options.get('version', VERSION_WITHOUT_CAPABILITIES)
        return self.marshal(result, error, _id, version)

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
        except Exception:
            self.exception('WSGI %s.__call__():', self.name)
            status = HTTP_STATUS_SERVER_ERROR
            response = status.encode('utf-8')
            headers = [('Content-Type', 'text/plain; charset=utf-8')]

        session_data = getattr(context, 'session_data', None)
        if session_data is not None:
            # Send session cookie back and store session data
            # FIXME: the URL path should be retreived from somewhere (but where?), not hardcoded
            session_mgr = get_session_mgr()
            session_cookie = session_mgr.generate_cookie('/ipa', session_data['session_id'],
                                                         session_data['session_expiration_timestamp'])
            headers.append(('Set-Cookie', session_cookie))

        start_response(status, headers)
        return [response]

    def unmarshal(self, data):
        raise NotImplementedError('%s.unmarshal()' % type(self).__name__)

    def marshal(self, result, error, _id=None,
                version=VERSION_WITHOUT_CAPABILITIES):
        raise NotImplementedError('%s.marshal()' % type(self).__name__)


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

    def marshal(self, result, error, _id=None,
                version=VERSION_WITHOUT_CAPABILITIES):
        if error:
            assert isinstance(error, PublicError)
            error = dict(
                code=error.errno,
                message=error.strerror,
                data=error.kw,
                name=unicode(error.__class__.__name__),
            )
        principal = getattr(context, 'principal', 'UNKNOWN')
        response = dict(
            result=result,
            error=error,
            id=_id,
            principal=unicode(principal),
            version=unicode(VERSION),
        )
        response = json_encode_binary(response, version)
        dump = json.dumps(response, sort_keys=True, indent=4)
        return dump.encode('utf-8')

    def unmarshal(self, data):
        try:
            d = json.loads(data)
        except ValueError as e:
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
        options = dict((str(k), v) for (k, v) in options.items())
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

        if 'ccache_data' in session_data:
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
        except Exception as e:
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
        session_mgr = get_session_mgr()
        session_mgr.set_session_expiration_time(session_data,
                                                duration=self.session_auth_duration,
                                                max_age=krb_expiration,
                                                duration_type=self.api.env.session_duration_type)


    def finalize_kerberos_acquisition(self, who, ccache_name, environ, start_response, headers=None):
        if headers is None:
            headers = []

        # Retrieve the session data (or newly create)
        session_mgr = get_session_mgr()
        session_data = session_mgr.load_session_data(environ.get('HTTP_COOKIE'))
        session_id = session_data['session_id']

        self.debug('finalize_kerberos_acquisition: %s ccache_name="%s" session_id="%s"',
                   who, ccache_name, session_id)

        # Copy the ccache file contents into the session data
        session_data['ccache_data'] = load_ccache_data(ccache_name)

        # Set when the session will expire
        creds = get_credentials(ccache_name=ccache_name)
        endtime = creds.lifetime + time.time()
        self.update_session_expiration(session_data, endtime)

        # Store the session data now that it's been updated with the ccache
        session_mgr.store_session_data(session_data)

        # The request is finished with the ccache, destroy it.
        release_ipa_ccache(ccache_name)

        # Return success and set session cookie
        session_cookie = session_mgr.generate_cookie('/ipa', session_id,
                                                     session_data['session_expiration_timestamp'])
        headers.append(('Set-Cookie', session_cookie))

        start_response(HTTP_STATUS_SUCCESS, headers)
        return ['']


class KerberosWSGIExecutioner(WSGIExecutioner, HTTP_Status, KerberosSession):
    """Base class for xmlserver and jsonserver_kerb
    """

    def _on_finalize(self):
        super(KerberosWSGIExecutioner, self)._on_finalize()
        self.kerb_session_on_finalize()

    def __call__(self, environ, start_response):
        self.debug('KerberosWSGIExecutioner.__call__:')
        user_ccache=environ.get('KRB5CCNAME')

        headers = [('Content-Type', '%s; charset=utf-8' % self.content_type)]

        if user_ccache is None:

            status = HTTP_STATUS_SERVER_ERROR

            self.log.error(
                '%s: %s', status,
                'KerberosWSGIExecutioner.__call__: '
                'KRB5CCNAME not defined in HTTP request environment')

            return self.marshal(None, CCacheError())
        try:
            self.create_context(ccache=user_ccache)
            response = super(KerberosWSGIExecutioner, self).__call__(
                environ, start_response)
            session_data = getattr(context, 'session_data', None)
            if (session_data is None and self.env.context != 'lite'):
                self.finalize_kerberos_acquisition(
                    'xmlserver', user_ccache, environ, start_response, headers)
        except PublicError as e:
            status = HTTP_STATUS_SUCCESS
            response = status.encode('utf-8')
            start_response(status, headers)
            return self.marshal(None, e)
        finally:
            destroy_context()
        return response


class xmlserver(KerberosWSGIExecutioner):
    """
    Execution backend plugin for XML-RPC server.

    Also see the `ipalib.rpc.xmlclient` plugin.
    """

    content_type = 'text/xml'
    key = '/xml'

    def listMethods(self, *params):
        """list methods for XML-RPC introspection"""
        if params:
            raise errors.ZeroArgumentError(name='system.listMethods')
        return (tuple(unicode(cmd.name) for cmd in self.Command()
                      if cmd is self.Command[cmd.name]) +
                tuple(unicode(name) for name in self._system_commands))

    def _get_method_name(self, name, *params):
        """Get a method name for XML-RPC introspection commands"""
        if not params:
            raise errors.RequirementError(name='method name')
        elif len(params) > 1:
            raise errors.MaxArgumentError(name=name, count=1)
        [method_name] = params
        return method_name

    def methodSignature(self, *params):
        """get method signature for XML-RPC introspection"""
        method_name = self._get_method_name('system.methodSignature', *params)
        if method_name in self._system_commands:
            # TODO
            # for now let's not go out of our way to document standard XML-RPC
            return u'undef'
        else:
            self._get_command(method_name)

            # All IPA commands return a dict (struct),
            # and take a params, options - list and dict (array, struct)
            return [[u'struct', u'array', u'struct']]

    def methodHelp(self, *params):
        """get method docstring for XML-RPC introspection"""
        method_name = self._get_method_name('system.methodHelp', *params)
        if method_name in self._system_commands:
            return u''
        else:
            command = self._get_command(method_name)
            return unicode(command.doc or '')

    _system_commands = {
        'system.listMethods': listMethods,
        'system.methodSignature': methodSignature,
        'system.methodHelp': methodHelp,
    }

    def unmarshal(self, data):
        (params, name) = xml_loads(data)
        if name in self._system_commands:
            # For XML-RPC introspection, return params directly
            return (name, params, {}, None)
        (args, options) = params_2_args_options(params)
        if 'version' not in options:
            # Keep backwards compatibility with client containing
            # bug https://fedorahosted.org/freeipa/ticket/3294:
            # If `version` is not given in XML-RPC, assume an old version
            options['version'] = VERSION_WITHOUT_CAPABILITIES
        return (name, args, options, None)

    def marshal(self, result, error, _id=None,
                version=VERSION_WITHOUT_CAPABILITIES):
        if error:
            self.debug('response: %s: %s', error.__class__.__name__, str(error))
            response = Fault(error.errno, error.strerror)
        else:
            if isinstance(result, dict):
                self.debug('response: entries returned %d', result.get('count', 1))
            response = (result,)
        dump = xml_dumps(response, version, methodresponse=True)
        return dump.encode('utf-8')


class jsonserver_session(jsonserver, KerberosSession):
    """
    JSON RPC server protected with session auth.
    """

    key = '/session/json'

    def __init__(self, api):
        super(jsonserver_session, self).__init__(api)
        name = '{0}_{1}'.format(self.__class__.__name__, id(self))
        auth_mgr = AuthManagerKerb(name)
        session_mgr = get_session_mgr()
        session_mgr.auth_mgr.register(auth_mgr.name, auth_mgr)

    def _on_finalize(self):
        super(jsonserver_session, self)._on_finalize()
        self.kerb_session_on_finalize()

    def need_login(self, start_response):
        status = '401 Unauthorized'
        headers = []
        response = b''

        self.debug('jsonserver_session: %s need login', status)

        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI jsonserver_session.__call__:')

        # Load the session data
        session_mgr = get_session_mgr()
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
        creds = get_credentials_if_valid(ccache_name=ipa_ccache_name)
        if not creds:
            self.debug('ccache expired, deleting session, need login')
            # The request is finished with the ccache, destroy it.
            release_ipa_ccache(ipa_ccache_name)
            return self.need_login(start_response)

        # Update the session expiration based on the Kerberos expiration
        endtime = creds.lifetime + time.time()
        self.update_session_expiration(session_data, endtime)

        # Store the session data in the per-thread context
        setattr(context, 'session_data', session_data)

        # This may fail if a ticket from wrong realm was handled via browser
        try:
            self.create_context(ccache=ipa_ccache_name)
        except ACIError as e:
            return self.unauthorized(environ, start_response, str(e), 'denied')

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

            if 'ccache_data' in session_data:
                session_data['ccache_data'] = load_ccache_data(ipa_ccache_name)

            # The request is finished with the ccache, destroy it.
            release_ipa_ccache(ipa_ccache_name)
            # Store the session data.
            session_mgr.store_session_data(session_data)
            destroy_context()

        return response


class jsonserver_kerb(jsonserver, KerberosWSGIExecutioner):
    """
    JSON RPC server protected with kerberos auth.
    """

    key = '/json'


class KerberosLogin(Backend, KerberosSession, HTTP_Status):
    key = None

    def _on_finalize(self):
        super(KerberosLogin, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)
        self.kerb_session_on_finalize()

    def __call__(self, environ, start_response):
        self.debug('WSGI KerberosLogin.__call__:')

        # Get the ccache created by mod_auth_gssapi
        user_ccache_name=environ.get('KRB5CCNAME')
        if user_ccache_name is None:
            return self.internal_error(environ, start_response,
                                       'login_kerberos: KRB5CCNAME not defined in HTTP request environment')

        return self.finalize_kerberos_acquisition('login_kerberos', user_ccache_name, environ, start_response)


class login_kerberos(KerberosLogin):
    key = '/session/login_kerberos'


class login_x509(KerberosLogin):
    key = '/session/login_x509'


class login_password(Backend, KerberosSession, HTTP_Status):

    content_type = 'text/plain'
    key = '/session/login_password'

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
            query_dict = parse_qs(query_string)
        except Exception as e:
            return self.bad_request(environ, start_response, "cannot parse query data")

        user = query_dict.get('user', None)
        if user is not None:
            if len(user) == 1:
                user = user[0]
            else:
                return self.bad_request(environ, start_response, "more than one user parameter")
        else:
            return self.bad_request(environ, start_response, "no user specified")

        # allows login in the form user@SERVER_REALM or user@server_realm
        # FIXME: uppercasing may be removed when better handling of UPN
        #        is introduced

        parts = normalize_name(user)

        if "domain" in parts:
            # username is of the form user@SERVER_REALM or user@server_realm

            # check whether the realm is server's realm
            # Users from other realms are not supported
            # (they do not have necessary LDAP entry, LDAP connect will fail)

            if parts["domain"].upper()==self.api.env.realm:
                user=parts["name"]
            else:
                return self.unauthorized(environ, start_response, '', 'denied')

        elif "flatname" in parts:
            # username is of the form NetBIOS\user
            return self.unauthorized(environ, start_response, '', 'denied')

        else:
            # username is of the form user or of some wild form, e.g.
            # user@REALM1@REALM2 or NetBIOS1\NetBIOS2\user (see normalize_name)

            # wild form username will fail at kinit, so nothing needs to be done
            pass

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
        try:
            self.kinit(user, self.api.env.realm, password, ipa_ccache_name)
        except PasswordExpired as e:
            return self.unauthorized(environ, start_response, str(e), 'password-expired')
        except InvalidSessionPassword as e:
            return self.unauthorized(environ, start_response, str(e), 'invalid-password')
        except KrbPrincipalExpired as e:
            return self.unauthorized(environ,
                                     start_response,
                                     str(e),
                                     'krbprincipal-expired')
        except UserLocked as e:
            return self.unauthorized(environ,
                                     start_response,
                                     str(e),
                                     'user-locked')

        return self.finalize_kerberos_acquisition('login_password', ipa_ccache_name, environ, start_response)

    def kinit(self, user, realm, password, ccache_name):
        # get http service ccache as an armor for FAST to enable OTP authentication
        armor_principal = str(krb5_format_service_principal_name(
            'HTTP', self.api.env.host, realm))
        keytab = paths.IPA_KEYTAB
        armor_name = "%sA_%s" % (krbccache_prefix, user)
        armor_path = os.path.join(krbccache_dir, armor_name)

        self.debug('Obtaining armor ccache: principal=%s keytab=%s ccache=%s',
                   armor_principal, keytab, armor_path)

        try:
            kinit_keytab(armor_principal, paths.IPA_KEYTAB, armor_path)
        except gssapi.exceptions.GSSError as e:
            raise CCacheError(message=unicode(e))

        # Format the user as a kerberos principal
        principal = krb5_format_principal_name(user, realm)

        try:
            kinit_password(principal, password, ccache_name,
                           armor_ccache_name=armor_path)

            self.debug('Cleanup the armor ccache')
            ipautil.run(
                [paths.KDESTROY, '-A', '-c', armor_path],
                env={'KRB5CCNAME': armor_path},
                raiseonerr=False)
        except RuntimeError as e:
            if ('kinit: Cannot read password while '
                    'getting initial credentials') in str(e):
                raise PasswordExpired(principal=principal, message=unicode(e))
            elif ('kinit: Client\'s entry in database'
                  ' has expired while getting initial credentials') in str(e):
                raise KrbPrincipalExpired(principal=principal,
                                          message=unicode(e))
            elif ('kinit: Clients credentials have been revoked '
                  'while getting initial credentials') in str(e):
                raise UserLocked(principal=principal,
                                 message=unicode(e))
            raise InvalidSessionPassword(principal=principal,
                                         message=unicode(e))


class change_password(Backend, HTTP_Status):

    content_type = 'text/plain'
    key = '/session/change_password'

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
            query_dict = parse_qs(query_string)
        except Exception as e:
            return self.bad_request(environ, start_response, "cannot parse query data")

        data = {}
        for field in ('user', 'old_password', 'new_password', 'otp'):
            value = query_dict.get(field, None)
            if value is not None:
                if len(value) == 1:
                    data[field] = value[0]
                else:
                    return self.bad_request(environ, start_response, "more than one %s parameter"
                                            % field)
            elif field != 'otp':  # otp is optional
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
            pw = data['old_password']
            if data.get('otp'):
                pw = data['old_password'] + data['otp']
            conn = ldap2(self.api)
            conn.connect(bind_dn=bind_dn, bind_pw=pw)
        except (NotFound, ACIError):
            result = 'invalid-password'
            message = 'The old password or username is not correct.'
        except Exception as e:
            message = "Could not connect to LDAP server."
            self.error("change_password: cannot authenticate '%s' to LDAP server: %s",
                    data['user'], str(e))
        else:
            try:
                conn.modify_password(bind_dn, data['new_password'], data['old_password'], skip_bind=True)
            except ExecutionError as e:
                result = 'policy-error'
                policy_error = escape(str(e))
                message = "Password change was rejected: %s" % escape(str(e))
            except Exception as e:
                message = "Could not change the password"
                self.error("change_password: cannot change password of '%s': %s",
                        data['user'], str(e))
            else:
                result = 'ok'
                title = "Password change successful"
                message = "Password was changed."
            finally:
                if conn.isconnected():
                    conn.disconnect()

        self.info('%s: %s', status, message)

        response_headers.append(('X-IPA-Pwchange-Result', result))
        if policy_error:
            response_headers.append(('X-IPA-Pwchange-Policy-Error', policy_error))

        start_response(status, response_headers)
        output = _success_template % dict(title=str(title),
                                          message=str(message))
        return [output]

class sync_token(Backend, HTTP_Status):
    content_type = 'text/plain'
    key = '/session/sync_token'

    class OTPSyncRequest(univ.Sequence):
        OID = "2.16.840.1.113730.3.8.10.6"

        componentType = namedtype.NamedTypes(
            namedtype.NamedType('firstCode', univ.OctetString()),
            namedtype.NamedType('secondCode', univ.OctetString()),
            namedtype.OptionalNamedType('tokenDN', univ.OctetString())
        )

    def _on_finalize(self):
        super(sync_token, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        # Make sure this is a form request.
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(environ, start_response, "Content-Type must be application/x-www-form-urlencoded")

        # Make sure this is a POST request.
        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(environ, start_response, "HTTP request method must be POST")

        # Parse the query string to a dictionary.
        try:
            query_dict = parse_qs(query_string)
        except Exception as e:
            return self.bad_request(environ, start_response, "cannot parse query data")
        data = {}
        for field in ('user', 'password', 'first_code', 'second_code', 'token'):
            value = query_dict.get(field, None)
            if value is not None:
                if len(value) == 1:
                    data[field] = value[0]
                else:
                    return self.bad_request(environ, start_response, "more than one %s parameter"
                                            % field)
            elif field != 'token':
                return self.bad_request(environ, start_response, "no %s specified" % field)

        # Create the request control.
        sr = self.OTPSyncRequest()
        sr.setComponentByName('firstCode', data['first_code'])
        sr.setComponentByName('secondCode', data['second_code'])
        if 'token' in data:
            try:
                token_dn = DN(data['token'])
            except ValueError:
                token_dn = DN((self.api.Object.otptoken.primary_key.name, data['token']),
                              self.api.env.container_otp, self.api.env.basedn)

            sr.setComponentByName('tokenDN', str(token_dn))
        rc = ldap.controls.RequestControl(sr.OID, True, encoder.encode(sr))

        # Resolve the user DN
        bind_dn = DN((self.api.Object.user.primary_key.name, data['user']),
                     self.api.env.container_user, self.api.env.basedn)

        # Start building the response.
        status = HTTP_STATUS_SUCCESS
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]
        title = 'Token sync rejected'

        # Perform the synchronization.
        conn = ldap2(self.api)
        try:
            conn.connect(bind_dn=bind_dn,
                         bind_pw=data['password'],
                         serverctrls=[rc,])
            result = 'ok'
            title = "Token sync successful"
            message = "Token was synchronized."
        except (NotFound, ACIError):
            result = 'invalid-credentials'
            message = 'The username, password or token codes are not correct.'
        except Exception as e:
            result = 'error'
            message = "Could not connect to LDAP server."
            self.error("token_sync: cannot authenticate '%s' to LDAP server: %s",
                       data['user'], str(e))
        finally:
            if conn.isconnected():
                conn.disconnect()

        # Report status and return.
        response_headers.append(('X-IPA-TokenSync-Result', result))
        start_response(status, response_headers)
        output = _success_template % dict(title=str(title),
                                          message=str(message))
        return [output]

class xmlserver_session(xmlserver, KerberosSession):
    """
    XML RPC server protected with session auth.
    """

    key = '/session/xml'

    def __init__(self, api):
        super(xmlserver_session, self).__init__(api)
        name = '{0}_{1}'.format(self.__class__.__name__, id(self))
        auth_mgr = AuthManagerKerb(name)
        session_mgr = get_session_mgr()
        session_mgr.auth_mgr.register(auth_mgr.name, auth_mgr)

    def _on_finalize(self):
        super(xmlserver_session, self)._on_finalize()
        self.kerb_session_on_finalize()

    def need_login(self, start_response):
        status = '401 Unauthorized'
        headers = []
        response = b''

        self.debug('xmlserver_session: %s need login', status)

        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        '''
        '''

        self.debug('WSGI xmlserver_session.__call__:')

        # Load the session data
        session_mgr = get_session_mgr()
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
        creds = get_credentials_if_valid(ccache_name=ipa_ccache_name)
        if not creds:
            self.debug('xmlserver_session.__call_: ccache expired, deleting session, need login')
            # The request is finished with the ccache, destroy it.
            release_ipa_ccache(ipa_ccache_name)
            return self.need_login(start_response)

        # Update the session expiration based on the Kerberos expiration
        endtime = creds.lifetime + time.time()
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

            if 'ccache_data' in session_data:
                session_data['ccache_data'] = load_ccache_data(ipa_ccache_name)

            # The request is finished with the ccache, destroy it.
            release_ipa_ccache(ipa_ccache_name)
            # Store the session data.
            session_mgr.store_session_data(session_data)
            destroy_context()

        return response
