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
Package containing server backend.
"""

import traceback
from xmlrpclib import dumps, Fault
from ipalib import api


# This is a simple way to ensure that ipalib.api is only initialized
# when ipaserver is imported from within the Apache process:
try:
    from mod_python import apache
    api.bootstrap(context='server', debug=True, log=None)
    api.finalize()
    api.log.info('*** PROCESS START ***')
    import ipawebui
    ui = ipawebui.create_wsgi_app(api)
except ImportError:
    pass


# START code from paste
# Red Hat does not hold the copyright to the following code.  The following code
# is from paste:
#   http://pythonpaste.org/
# Which in turn was based on Robert Brewer's modpython_gateway:
#   http://projects.amor.org/misc/svn/modpython_gateway.py

class InputWrapper(object):

    def __init__(self, req):
        self.req = req

    def close(self):
        pass

    def read(self, size=-1):
        return self.req.read(size)

    def readline(self, size=-1):
        return self.req.readline(size)

    def readlines(self, hint=-1):
        return self.req.readlines(hint)

    def __iter__(self):
        line = self.readline()
        while line:
            yield line
            # Notice this won't prefetch the next line; it only
            # gets called if the generator is resumed.
            line = self.readline()


class ErrorWrapper(object):

    def __init__(self, req):
        self.req = req

    def flush(self):
        pass

    def write(self, msg):
        self.req.log_error(msg)

    def writelines(self, seq):
        self.write(''.join(seq))


bad_value = ("You must provide a PythonOption '%s', either 'on' or 'off', "
             "when running a version of mod_python < 3.1")


class Handler(object):

    def __init__(self, req):
        self.started = False

        options = req.get_options()

        # Threading and forking
        try:
            q = apache.mpm_query
            threaded = q(apache.AP_MPMQ_IS_THREADED)
            forked = q(apache.AP_MPMQ_IS_FORKED)
        except AttributeError:
            threaded = options.get('multithread', '').lower()
            if threaded == 'on':
                threaded = True
            elif threaded == 'off':
                threaded = False
            else:
                raise ValueError(bad_value % "multithread")

            forked = options.get('multiprocess', '').lower()
            if forked == 'on':
                forked = True
            elif forked == 'off':
                forked = False
            else:
                raise ValueError(bad_value % "multiprocess")

        env = self.environ = dict(apache.build_cgi_env(req))

        if 'SCRIPT_NAME' in options:
            # Override SCRIPT_NAME and PATH_INFO if requested.
            env['SCRIPT_NAME'] = options['SCRIPT_NAME']
            env['PATH_INFO'] = req.uri[len(options['SCRIPT_NAME']):]
        else:
            env['SCRIPT_NAME'] = ''
            env['PATH_INFO'] = req.uri

        env['wsgi.input'] = InputWrapper(req)
        env['wsgi.errors'] = ErrorWrapper(req)
        env['wsgi.version'] = (1, 0)
        env['wsgi.run_once'] = False
        if env.get("HTTPS") in ('yes', 'on', '1'):
            env['wsgi.url_scheme'] = 'https'
        else:
            env['wsgi.url_scheme'] = 'http'
        env['wsgi.multithread']  = threaded
        env['wsgi.multiprocess'] = forked

        self.request = req

    def run(self, application):
        try:
            result = application(self.environ, self.start_response)
            for data in result:
                self.write(data)
            if not self.started:
                self.request.set_content_length(0)
            if hasattr(result, 'close'):
                result.close()
        except:
            traceback.print_exc(None, self.environ['wsgi.errors'])
            if not self.started:
                self.request.status = 500
                self.request.content_type = 'text/plain'
                data = "A server error occurred. Please contact the administrator."
                self.request.set_content_length(len(data))
                self.request.write(data)

    def start_response(self, status, headers, exc_info=None):
        if exc_info:
            try:
                if self.started:
                    raise exc_info[0], exc_info[1], exc_info[2]
            finally:
                exc_info = None

        self.request.status = int(status[:3])

        for key, val in headers:
            if key.lower() == 'content-length':
                self.request.set_content_length(int(val))
            elif key.lower() == 'content-type':
                self.request.content_type = val
            else:
                self.request.headers_out.add(key, val)

        return self.write

    def write(self, data):
        if not self.started:
            self.started = True
        self.request.write(data)

# END code from paste


def adapter(req, app):
    if apache.mpm_query(apache.AP_MPMQ_IS_THREADED):
        response = dumps(
            Fault(3, 'Apache must use the forked model'),
            methodresponse=True,
        )
        req.content_type = 'text/xml'
        req.set_content_length(len(response))
        req.write(response)
    else:
        Handler(req).run(app)
    return apache.OK


def xmlrpc(req):
    """
    mod_python handler for XML-RPC requests.
    """
    return adapter(req, api.Backend.xmlserver)


def jsonrpc(req):
    """
    mod_python handler for JSON-RPC requests (place holder).
    """
    return adapter(req, api.Backend.jsonserver)


def webui(req):
    """
    mod_python handler for web-UI requests (place holder).
    """
    return adapter(req, ui)
