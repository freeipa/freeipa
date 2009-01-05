# Authors: Rob Crittenden <rcritten@redhat.com>
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
#

import krbV
import ldap
import ldap.dn
import ipaldap

class IPAConn:
    def __init__(self, host, port, krbccache, debug=None):
        self._conn = None

        # Save the arguments
        self._host = host
        self._port = port
        self._krbccache = krbccache
        self._debug = debug

        self._ctx = krbV.default_context()

        ccache = krbV.CCache(name=krbccache, context=self._ctx)
        cprinc = ccache.principal()

        self._conn = ipaldap.IPAdmin(host,port,None,None,None,debug)

        # This will bind the connection
        try:
            self._conn.set_krbccache(krbccache, cprinc.name)
        except ldap.UNWILLING_TO_PERFORM, e:
            raise e
        except Exception, e:
            raise e

    def __del__(self):
        # take no chances on unreleased connections
        self.releaseConn()

    def getConn(self):
        return self._conn

    def releaseConn(self):
        if self._conn is None:
            return

        self._conn.unbind_s()
        self._conn = None

        return

if __name__ == "__main__":
    ipaconn = IPAConn("localhost", 389, "FILE:/tmp/krb5cc_500")
    x = ipaconn.getConn().getEntry("dc=example,dc=com", ldap.SCOPE_SUBTREE, "uid=admin", ["cn"])
    print "%s" % x
