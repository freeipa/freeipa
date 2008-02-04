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

# Simple program to interrogate the XML-RPC server for information on what
# it can do.

import sys
import xmlrpclib
from ipa.krbtransport import KerbTransport
import ipa
from ipa import config

ipa.config.init_config()

url = "http://" + config.config.get_server() + "/ipa"
s = xmlrpclib.Server(url, KerbTransport())

print "A list of all methods available on the server."
print "system.listMethods: ", s.system.listMethods()
print ""

print "Signatures are not supported."
print "system.methodSignature: ", s.system.methodSignature("get_user_by_uid")
print ""

print "Help on a specific method"
print "system.methodHelp: ", s.system.methodHelp("get_user_by_uid")

print "The entire API:"
result = s._listapi()
for item in result:
    print item['name'],
    print "(",
    i = len(item['args'])
    p = 0
    for a in item['args']:
        if isinstance(a, list):
            print "%s=%s" % (a[0], a[1]),
        else:
            print a,
        if p < i - 1:
            print ",",
        p = p + 1
    print ")"
