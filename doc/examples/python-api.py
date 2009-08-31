#!/usr/bin/env python

from ipalib import api

# 1. Initialize ipalib
#
# Run ./python-api.py --help to see the global options.  Some useful options:
#
#   -v  Produce more verbose output
#   -d  Produce full debugging output
#   -e in_server=True  Force running in server mode
#   -e xmlrpc_uri=https://foo.com/ipa/xml  # Connect to a specific server

api.bootstrap_with_global_options(context='example')
api.finalize()

# You will need to create a connection.  If you're in_server, call
# Backend.ldap.connect(), otherwise Backend.xmlclient.connect().

if api.env.in_server:
    api.Backend.ldap2.connect(
        ccache=api.Backend.krb.default_ccname()
     )
else:
    api.Backend.xmlclient.connect()


# Now that you're connected, you can make calls to api.Command.whatever():
print 'The admin user:'
print api.Command.user_show(u'admin')
