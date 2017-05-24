# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Password migration script
"""

import cgi
import errno
import logging
import os.path
from wsgiref.util import request_uri

from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython import ipaldap
from ipalib import errors, create_api

logger = logging.getLogger(os.path.basename(__file__))


def wsgi_redirect(start_response, loc):
    start_response('302 Found', [('Location', loc)])
    return []

def get_ui_url(environ):
    full_url = request_uri(environ)
    index = full_url.rfind(environ.get('SCRIPT_NAME',''))
    if index == -1:
        raise ValueError('Cannot strip the script URL from full URL "%s"' % full_url)
    return full_url[:index] + "/ipa/ui"


def bind(ldap_uri, base_dn, username, password):
    if not base_dn:
        logger.error('migration unable to get base dn')
        raise IOError(errno.EIO, 'Cannot get Base DN')
    bind_dn = DN(('uid', username), ('cn', 'users'), ('cn', 'accounts'), base_dn)
    try:
        conn = ipaldap.LDAPClient(ldap_uri)
        conn.simple_bind(bind_dn, password)
    except (errors.ACIError, errors.DatabaseError, errors.NotFound) as e:
        logger.error(
            'migration invalid credentials for %s: %s', bind_dn, e)
        raise IOError(
            errno.EPERM, 'Invalid LDAP credentials for user %s' % username)
    except Exception as e:
        logger.error('migration bind failed: %s', e)
        raise IOError(errno.EIO, 'Bind error')
    finally:
        conn.unbind()


def application(environ, start_response):
    if environ.get('REQUEST_METHOD', None) != 'POST':
        return wsgi_redirect(start_response, 'index.html')

    form_data = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    if 'username' not in form_data or 'password' not in form_data:
        return wsgi_redirect(start_response, 'invalid.html')

    # API object only for configuration, finalize() not needed
    api = create_api(mode=None)
    api.bootstrap(context='server', confdir=paths.ETC_IPA, in_server=True)
    try:
        bind(api.env.ldap_uri, api.env.basedn,
             form_data['username'].value, form_data['password'].value)
    except IOError as err:
        if err.errno == errno.EPERM:
            return wsgi_redirect(start_response, 'invalid.html')
        if err.errno == errno.EIO:
            return wsgi_redirect(start_response, 'error.html')

    ui_url = get_ui_url(environ)
    return wsgi_redirect(start_response, ui_url)
