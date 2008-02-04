#!/usr/bin/python

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

# A test CGI that tests that the Kerberos credentials cache was created
# properly in Apache.

import ldap
import ldap.sasl
import os

sasl_auth = ldap.sasl.sasl({}, "GSSAPI")
conn = ldap.initialize("ldap://localhost:389/")
conn.protocol_version = 3

print "Content-type: text/plain"
print ""

try:
    print "KRB5CCNAME is", os.environ["KRB5CCNAME"]

    try:
        conn.sasl_interactive_bind_s("", sasl_auth)
    except ldap.LDAPError,e:
        print "Error using SASL mechanism", sasl_auth.mech, str(e)
    else:
        print "Sucessfully bound to LDAP using SASL mechanism", sasl_auth.mech
    conn.unbind()
except KeyError,e:
    print "not set."
