#!/usr/bin/env python

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
In-tree paste-based test server.

This uses the *Python Paste* WSGI server.  For more info, see:

    http://pythonpaste.org/

Unfortunately, SSL support is broken under Python 2.6 with paste 1.7.2, see:

    http://trac.pythonpaste.org/pythonpaste/ticket/314
"""

from os import path
import optparse
from paste import httpserver
import paste.gzipper
from paste.urlmap import URLMap
from assetslib.wsgi import AssetsApp
from ipalib import api
import ipawebui


class KRBCheater(object):
    def __init__(self, app):
        self.app = app
        self.url = app.url
        self.ccname = api.Backend.krb.default_ccname()

    def __call__(self, environ, start_response):
        environ['KRB5CCNAME'] = self.ccname
        return self.app(environ, start_response)


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

    ui = ipawebui.create_wsgi_app(api)
    ui.render_assets()

    urlmap = URLMap()
    apps = [
        ('IPA', KRBCheater(api.Backend.session)),
        ('Assets', AssetsApp(ui.assets)),
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
