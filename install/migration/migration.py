# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Password migration script
"""

import errno
import ldap
import cgi
import wsgiref

BASE_DN = ''
LDAP_URI = 'ldap://localhost:389'

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
    if BASE_DN:
        return BASE_DN
    try:
        conn = ldap.initialize(LDAP_URI)
        conn.simple_bind_s('', '')
        entries = conn.search_ext_s(
            '', scope=ldap.SCOPE_BASE, attrlist=['namingcontexts']
        )
    except ldap.LDAPError:
        return ''
    conn.unbind_s()
    try:
        return entries[0][1]['namingcontexts'][0]
    except (IndexError, KeyError):
        return ''

def bind(username, password):
    base_dn = get_base_dn()
    if not base_dn:
        raise IOError(errno.EIO, 'Cannot get Base DN')
    bind_dn = 'uid=%s,cn=users,cn=accounts,%s' % (username, base_dn)
    try:
        conn = ldap.initialize(LDAP_URI)
        conn.simple_bind_s(bind_dn, password)
    except (ldap.INVALID_CREDENTIALS, ldap.UNWILLING_TO_PERFORM,
            ldap.NO_SUCH_OBJECT):
        raise IOError(errno.EPERM, 'Invalid LDAP credentials for user %s' % username)
    except ldap.LDAPError:
        raise IOError(errno.EIO, 'Bind error')

    conn.unbind_s()

def application(environ, start_response):
    if environ.get('REQUEST_METHOD', None) != 'POST':
        return wsgi_redirect(start_response, 'index.html')

    form_data = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    if not form_data.has_key('username') or not form_data.has_key('password'):
        return wsgi_redirect(start_response, 'invalid.html')

    try:
        bind(form_data['username'].value, form_data['password'].value)
    except IOError as err:
        if err.errno == errno.EPERM:
            return wsgi_redirect(start_response, 'invalid.html')
        if err.errno == errno.EIO:
            return wsgi_redirect(start_response, 'error.html')

    ui_url = get_ui_url(environ)
    return wsgi_redirect(start_response, ui_url)

