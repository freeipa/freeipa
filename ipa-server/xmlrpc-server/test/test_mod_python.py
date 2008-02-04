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
from mod_python import apache

def handler(req):
        req.content_type = "text/plain"
        req.send_http_header()
        do_request(req)
        return apache.OK

def do_request(req):
    sasl_auth = ldap.sasl.sasl({}, "GSSAPI")
    conn = ldap.initialize("ldap://localhost:389/")
    conn.protocol_version = 3

    req.add_common_vars()

    for e in req.subprocess_env:
        req.write("%s: %s<br>\n" % (e, req.subprocess_env[e]))

    try:
        req.write("KRB5CCNAME is %s<br>\n" % req.subprocess_env["KRB5CCNAME"])
        os.environ["KRB5CCNAME"] = req.subprocess_env["KRB5CCNAME"]
    
        try:
            conn.sasl_interactive_bind_s("", sasl_auth)
        except ldap.LDAPError,e:
            req.write("Error using SASL mechanism %s %s<br>\n" % (sasl_auth.mech, str(e)))
        else:
            req.write("Sucessfully bound to LDAP using SASL mechanism %s<br>\n" % sasl_auth.mech)
        conn.unbind()
    except KeyError,e:
        req.write("KRB5CCNAME is not set.")
