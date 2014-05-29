# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

import sys
sys.stdout = sys.stderr

import cherrypy
import os
import json
from functools import wraps
import traceback as tb_internal
from cherrypy import response
from ipalib import api
from ipalib import errors
from ipaplatform.paths import paths
from ipalib.request import context
from ipalib.rpc import json_encode_binary
from ipapython.version import VERSION, API_VERSION
from ipapython.ipa_log_manager import root_logger


def jsonout(func):
    '''JSON output decorator'''
    @wraps(func)
    def wrapper(*args, **kw):
        value = func(*args, **kw)
        response.headers["Content-Type"] = "application/json;charset=utf-8"
        data = json_encode_binary(value, version=API_VERSION)
        return json.dumps(data, sort_keys=True, indent=2)

    return wrapper


def handle_error(status, message, traceback, version):
    """
    Return basic messages to user and log backtrace in case of 500
    error.
    """
    if status.startswith('500'):
        root_logger.error(message)
        root_logger.error(tb_internal.format_exc())

    resp = cherrypy.response
    resp.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': status, 'message': message})


def convert_unicode(value):
    """
    IPA requires all incoming values to be unicode. Recursively
    convert the values.
    """
    if not isinstance(value, basestring):
        return value

    if value is not None:
        return unicode(value)
    else:
        return None


def raise_rest_exception(e):
    """
    Raise a REST-specific exception.
    """
    try:
        raise e
    except (errors.DuplicateEntry, errors.DNSNotARecordError,
            errors.ValidationError, errors.ConversionError,) as e:
        raise IPAError(
            status=400,
            message=e
        )
    except errors.ACIError as e:
        raise IPAError(
            status=401,
            message=e
        )
    except errors.NotFound as e:
        raise IPAError(
            status=404,
            message=e
        )
    except Exception as e:
        raise IPAError(
            status=500,
            message=e
        )


def popifnone(params, option):
    """
    If option, a string, exists in params, a dict, and is None then
    remove it from the dict.

    No return value. The dict is updated in-place if necessary.
    """
    if params.get(option) is None:
        params.pop(option, None)


def Command(command, *args, **options):
    """
    Execute an IPA command with the given arguments and options.

    This doesn't care what the options are, it passes them along to
    the IPA API. The exceptions are:

    :param nomaskexceptions: boolean to decide if we raise the real IPA
                             exception or a REST-specific exceptioon.
    """
    if (cherrypy.request.config.get('local_only', False) and
       cherrypy.request.remote.ip not in ['::1', '127.0.0.1']):
        raise IPAError(
            status=401,
            message="Not a local request"
        )

    try:
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()
    except errors.CCacheError as e:
        root_logger.info('Connection failed: %s', e)
        raise IPAError(
            status=401,
            message=e
        )

    # IPA wants all its strings as unicode
    args = map(lambda v: convert_unicode(v), args)
    options = dict(zip(options, map(convert_unicode, options.values())))

    nomaskexception = options.pop('nomaskexception', False)

    api.Command[command].args_options_2_params(*args, **options)
    try:
        return api.Command[command](*args, **options)['result']
    except Exception as e:
        if not nomaskexception:
            raise_rest_exception(e)
        else:
            # The caller needs to be able to handle IPA-specific
            # exceptions.
            raise e


@jsonout
def GET(command, *args, **options):
    return Command(command, *args, **options)


@jsonout
def POST(status, command, *args, **options):
    cherrypy.response.status = status
    return Command(command, *args, **options)


@jsonout
def DELETE(command, *args, **options):
    return Command(command, *args, **options)


class IPAError(cherrypy.HTTPError):
    """
    Return errors in IPA-style json.

    Local errors are treated as strings so do not include the code and
    name attributes within the error dict.

    This is not padded for IE.
    """

    def set_response(self):
        response = cherrypy.serving.response

        cherrypy._cperror.clean_headers(self.code)

        # In all cases, finalize will be called after this method,
        # so don't bother cleaning up response values here.
        response.status = self.status

        if isinstance(self._message, Exception):
            try:
                code = self._message.errno
            except AttributeError:
                code = 0
            error = {'code': code,
                     'message': self._message.message,
                     'name': self._message.__class__.__name__}
        elif isinstance(self._message, basestring):
            error = {'message': self._message}
        else:
            error = {'message':
                     'Unable to handle error message type %s' %
                     type(self._message)}

        principal = getattr(context, 'principal', None)
        response.headers["Content-Type"] = "application/json;charset=utf-8"
        response.body = json.dumps({'error': error,
                                    'id': 0,
                                    'principal': principal,
                                    'result': None,
                                    'version': VERSION},
                                    sort_keys=True, indent=2)


class Host(object):
    """
    Manage IPA host objects
    """

    exposed = True

    def GET(self, fqdn=None):

        if fqdn is None:
            command = 'host_find'
        else:
            command = 'host_show'

        return GET(command, fqdn)

    def POST(self, hostname, description=None,
             macaddress=None, userclass=None, ip_address=None,
             password=None, rebuild=None):
        cmd = 'host_add'

        if password is None:
            random = True
        else:
            random = False

        params = {'description' : description,
                  'random' : random,
                  'macaddress' : macaddress,
                  'userclass' : userclass,
                  'userpassword' : password}

        # If the host is being rebuilt, disable it in order to revoke
        # existing certs, keytabs, etc.
        try:
            Command('host_show', hostname, nomaskexception=True)
        except errors.NotFound:
            # Adding a new host
            status = 201
            params['ip_address'] = ip_address
            params['force'] = True
        except Exception as e:
            raise_rest_exception(e)
        else:
            if ip_address is not None:
                raise IPAError(
                    status=400,
                    message='IP address must be changed in DNS'
                )
            cmd = 'host_mod'

            # Foreman doesn't pass these in on update so drop them otherwise
            # IPA will consider these as being set to None which deletes them.
            popifnone(params, 'description')
            popifnone(params, 'macaddress')
            popifnone(params, 'userclass')
            popifnone(params, 'userpassword')
            status = 200
            if rebuild:
                root_logger.info("Attempting to disable %s", hostname)
                try:
                    Command('host_disable', hostname, nomaskexception=True)
                except errors.AlreadyInactive as e:
                    pass
                else:
                    raise e
        return POST(status, cmd, hostname, **params)

    def DELETE(self, fqdn):
        # The host-del behavior is a bit off due to
        # https://fedorahosted.org/freeipa/ticket/4329
        # A NotFound is returned if the user can't read DNS.
        # Do a GET to see if the host exists, then we can more blindly
        # try the delete.

        # If the GET is ok then we know there is a host, though this is a
        # bit racy.
        GET('host_show', fqdn)

        remove_dns = cherrypy.request.config.get('remove_dns', False)

        return DELETE('host_del', fqdn, updatedns=remove_dns)


class Hostgroup(object):
    """
    Manage IPA hostgroup objects
    """

    exposed = True

    def GET(self, name=None):

        if name is None:
            command = 'hostgroup_find'
        else:
            command = 'hostgroup_show'

        return GET(command, name)

    def POST(self, name=None, description=None):
        cherrypy.response.status = 201
        return POST(201, 'hostgroup_add', name,
                    description=description,)

    def DELETE(self, name):
        return DELETE('hostgroup_del', name)


class Features(object):
    exposed = True

    def GET(self):
        return '["realm"]'


def start(config=None):
    # Set the umask so only the owner can read the log files
    old_umask = os.umask(077)

    cherrypy.tree.mount(
        Features(), '/features',
        {'/':
            {'request.dispatch': cherrypy.dispatch.MethodDispatcher()}
        }
    )
    cherrypy.tree.mount(
        Host(), '/ipa/smartproxy/host',
        {'/':
            {'request.dispatch': cherrypy.dispatch.MethodDispatcher()}
        }
    )
    cherrypy.tree.mount(
        Hostgroup(), '/ipa/smartproxy/hostgroup',
        {'/':
            {'request.dispatch': cherrypy.dispatch.MethodDispatcher()}
        }
    )

    # Register the realm for requests from Foreman
    root_logger.info("Mounting /realm/%s", api.env.realm)
    cherrypy.tree.mount(
        Host(), '/realm/%s' % api.env.realm,
        {'/':
            {'request.dispatch': cherrypy.dispatch.MethodDispatcher()}
        }
    )

    for c in config or []:
        try:
            cherrypy.config.update(c)
        except (IOError, OSError) as e:
            root_logger.error("Exception trying to load %s: %s", c, e)
            return 1

    # Log files are created, reset umask
    os.umask(old_umask)

    cherrypy.config.update({'error_page.500': handle_error})

    return 0

def application(environ, start_response):
    root_logger.info("IPA smartproxy WSGI start")
    return cherrypy.tree(environ, start_response)

wsgi_config = {'environment': 'embedded',
               'log.screen': False,
               'show_tracebacks': False,
               'engine.autoreload_on': False
}

api.bootstrap(context='ipasmartproxy', log=paths.DEV_NULL)
api.finalize()

cherrypy.config.update(wsgi_config)
start([paths.IPA_SMARTPROXY_CONF])
