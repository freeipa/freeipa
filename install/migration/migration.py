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

import ldap
from mod_python import apache, util


BASE_DN = ''
LDAP_URI = 'ldap://localhost:389'


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


def bind(req, username, password):
    base_dn = get_base_dn()
    if not base_dn:
        util.redirect(req, '/ipa/migration/error.html')
    bind_dn = 'uid=%s,cn=users,cn=accounts,%s' % (username, base_dn)
    try:
        conn = ldap.initialize(LDAP_URI)
        conn.simple_bind_s(bind_dn, password)
    except (ldap.INVALID_CREDENTIALS, ldap.UNWILLING_TO_PERFORM,
            ldap.NO_SUCH_OBJECT):
        util.redirect(req, '/ipa/migration/invalid.html')
    except ldap.LDAPError:
        util.redirect(req, '/ipa/migration/error.html')
    conn.unbind_s()
    util.redirect(req, '/ipa/ui')

