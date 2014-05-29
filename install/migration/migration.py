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
import glob
from wsgiref.util import request_uri

from ipapython.ipa_log_manager import root_logger
from ipapython.ipautil import get_ipa_basedn
from ipapython.dn import DN
from ipapython.ipaldap import IPAdmin
from ipalib import errors
from ipaplatform.paths import paths


def wsgi_redirect(start_response, loc):
    start_response('302 Found', [('Location', loc)])
    return []

def get_ui_url(environ):
    full_url = request_uri(environ)
    index = full_url.rfind(environ.get('SCRIPT_NAME',''))
    if index == -1:
        raise ValueError('Cannot strip the script URL from full URL "%s"' % full_url)
    return full_url[:index] + "/ipa/ui"


def get_base_dn(ldap_uri):
    """
    Retrieve LDAP server base DN.
    """
    try:
        conn = IPAdmin(ldap_uri=ldap_uri)
        conn.do_simple_bind(DN(), '')
        base_dn = get_ipa_basedn(conn)
    except Exception, e:
        root_logger.error('migration context search failed: %s' % e)
        return ''
    finally:
        conn.unbind()

    return base_dn


def bind(ldap_uri, base_dn, username, password):
    if not base_dn:
        root_logger.error('migration unable to get base dn')
        raise IOError(errno.EIO, 'Cannot get Base DN')
    bind_dn = DN(('uid', username), ('cn', 'users'), ('cn', 'accounts'), base_dn)
    try:
        conn = IPAdmin(ldap_uri=ldap_uri)
        conn.do_simple_bind(bind_dn, password)
    except (errors.ACIError, errors.DatabaseError, errors.NotFound), e:
        root_logger.error(
            'migration invalid credentials for %s: %s' % (bind_dn, e))
        raise IOError(
            errno.EPERM, 'Invalid LDAP credentials for user %s' % username)
    except Exception, e:
        root_logger.error('migration bind failed: %s' % e)
        raise IOError(errno.EIO, 'Bind error')
    finally:
        conn.unbind()


def application(environ, start_response):
    if environ.get('REQUEST_METHOD', None) != 'POST':
        return wsgi_redirect(start_response, 'index.html')

    form_data = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    if not form_data.has_key('username') or not form_data.has_key('password'):
        return wsgi_redirect(start_response, 'invalid.html')

    slapd_sockets = glob.glob(paths.ALL_SLAPD_INSTANCE_SOCKETS)
    if slapd_sockets:
        ldap_uri = 'ldapi://%s' % slapd_sockets[0].replace('/', '%2f')
    else:
        ldap_uri = 'ldaps://localhost:636'

    base_dn = get_base_dn(ldap_uri)

    try:
        bind(ldap_uri, base_dn,
             form_data['username'].value, form_data['password'].value)
    except IOError as err:
        if err.errno == errno.EPERM:
            return wsgi_redirect(start_response, 'invalid.html')
        if err.errno == errno.EIO:
            return wsgi_redirect(start_response, 'error.html')

    ui_url = get_ui_url(environ)
    return wsgi_redirect(start_response, ui_url)
