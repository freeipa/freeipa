#!/usr/bin/python

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
In-tree paste-based test server.

This uses the *Python Paste* WSGI server.  For more info, see:

    http://pythonpaste.org/

Unfortunately, SSL support is broken under Python 2.6 with paste 1.7.2, see:

    http://trac.pythonpaste.org/pythonpaste/ticket/314
"""

from os import path, getcwd
import optparse
from paste import httpserver
import paste.gzipper
from paste.urlmap import URLMap
from ipalib import api


class KRBCheater(object):
    def __init__(self, app):
        self.app = app
        self.url = app.url
        self.ccname = api.Backend.krb.default_ccname()

    def __call__(self, environ, start_response):
        environ['KRB5CCNAME'] = self.ccname
        return self.app(environ, start_response)


class WebUIApp(object):
    INDEX_FILE = 'index.html'
    EXTENSION_TO_MIME_MAP = {
        'xhtml': 'text/html',
        'html': 'text/html',
        'js': 'text/javascript',
        'inc': 'text/html',
        'css': 'text/css',
        'png': 'image/png',
        'json': 'text/javascript',
    }

    def __init__(self):
        self.url = '/ipa/ui'

    def __call__(self, environ, start_response):
        path_info = environ['PATH_INFO'].lstrip('/')
        if path_info == '':
            path_info = self.INDEX_FILE
        requested_file = path.join(getcwd(), 'install/ui/', path_info)
        extension = requested_file.rsplit('.', 1)[-1]

        if extension not in self.EXTENSION_TO_MIME_MAP:
            start_response('404 Not Found', [('Content-Type', 'text/plain')])
            return ['NOT FOUND']
        mime_type = self.EXTENSION_TO_MIME_MAP[extension]

        f = None
        try:
            f = open(requested_file, 'r')
            api.log.info('Request file %s' % requested_file)
            start_response('200 OK', [('Content-Type', mime_type)])
            return [f.read()]
        except IOError:
            start_response('404 Not Found', [('Content-Type', 'text/plain')])
            return ['NOT FOUND']
        finally:
            if f is not None:
                f.close()
            api.log.info('Request done')


if __name__ == '__main__':
    parser = optparse.OptionParser()

    parser.add_option('--dev',
        help='Run WebUI in development mode (requires FireBug)',
        default=True,
        action='store_false',
        dest='prod',
    )
    parser.add_option('--host',
        help='Listen on address HOST (default 127.0.0.1)',
        default='127.0.0.1',
    )
    parser.add_option('--port',
        help='Listen on PORT (default 8888)',
        default=8888,
        type='int',
    )

    api.env.in_server = True
    api.env.startup_traceback = True
    (options, args) = api.bootstrap_with_global_options(parser, context='lite')
    api.env._merge(
        lite_port=options.port,
        lite_host=options.host,
        webui_prod=options.prod,
        lite_pem=api.env._join('dot_ipa', 'lite.pem'),
    )
    api.finalize()

    urlmap = URLMap()
    apps = [
        ('IPA', KRBCheater(api.Backend.wsgi_dispatch)),
        ('webUI', KRBCheater(WebUIApp())),
    ]
    for (name, app) in apps:
        urlmap[app.url] = app
        api.log.info('Mounting %s at %s', name, app.url)

    if path.isfile(api.env.lite_pem):
        pem = api.env.lite_pem
    else:
        api.log.info('To enable SSL, place PEM file at %r', api.env.lite_pem)
        pem = None

    httpserver.serve(paste.gzipper.middleware(urlmap),
        host=api.env.lite_host,
        port=api.env.lite_port,
        ssl_pem=pem,
    )
