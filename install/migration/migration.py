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
import ldap
import wsgiref
from ipapython.ipa_log_manager import *
from ipapython.ipautil import get_ipa_basedn
from ipapython.dn import DN

BASE_DN = ''
LDAP_URI = 'ldaps://localhost:636'

def convert_exception(error):
    """
    Convert an LDAP exception into something more readable.
    """
    if not isinstance(error, ldap.TIMEOUT):
        desc = error.args[0]['desc'].strip()
        info = error.args[0].get('info', '').strip()
    else:
        desc = ''
        info = ''

    return '%s (%s)' % (desc, info)

def wsgi_redirect(start_response, loc):
    start_response('302 Found', [('Location', loc)])
    return []

def get_ui_url(environ):
    full_url = wsgiref.util.request_uri(environ)
    index = full_url.rfind(environ.get('SCRIPT_NAME',''))
    if index == -1:
        raise ValueError('Cannot strip the script URL from full URL "%s"' % full_url)
    return full_url[:index] + "/ipa/ui"

def get_base_dn():
    """
    Retrieve LDAP server base DN.
    """
    global BASE_DN

    if BASE_DN:
        return BASE_DN
    try:
        conn = ldap.initialize(LDAP_URI)
        conn.simple_bind_s('', '')
        BASE_DN = get_ipa_basedn(conn)
    except ldap.LDAPError, e:
        root_logger.error('migration context search failed: %s' % e)
        return ''
    finally:
        conn.unbind_s()

    return BASE_DN

def bind(username, password):
    base_dn = get_base_dn()
    if not base_dn:
        root_logger.error('migration unable to get base dn')
        raise IOError(errno.EIO, 'Cannot get Base DN')
    bind_dn = DN(('uid', username), ('cn', 'users'), ('cn', 'accounts'), base_dn)
    try:
        conn = ldap.initialize(LDAP_URI)
        conn.simple_bind_s(str(bind_dn), password)
    except (ldap.INVALID_CREDENTIALS, ldap.UNWILLING_TO_PERFORM,
            ldap.NO_SUCH_OBJECT), e:
        root_logger.error('migration invalid credentials for %s: %s' % (bind_dn, convert_exception(e)))
        raise IOError(errno.EPERM, 'Invalid LDAP credentials for user %s' % username)
    except ldap.LDAPError, e:
        root_logger.error('migration bind failed: %s' % convert_exception(e))
        raise IOError(errno.EIO, 'Bind error')
    finally:
        conn.unbind_s()

def application(environ, start_response):
    global LDAP_URI

    if environ.get('REQUEST_METHOD', None) != 'POST':
        return wsgi_redirect(start_response, 'index.html')

    form_data = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    if not form_data.has_key('username') or not form_data.has_key('password'):
        return wsgi_redirect(start_response, 'invalid.html')

    slapd_sockets = glob.glob('/var/run/slapd-*.socket')
    if slapd_sockets:
        LDAP_URI = 'ldapi://%s' % slapd_sockets[0].replace('/', '%2f')

    try:
        bind(form_data['username'].value, form_data['password'].value)
    except IOError as err:
        if err.errno == errno.EPERM:
            return wsgi_redirect(start_response, 'invalid.html')
        if err.errno == errno.EIO:
            return wsgi_redirect(start_response, 'error.html')

    ui_url = get_ui_url(environ)
    return wsgi_redirect(start_response, ui_url)
