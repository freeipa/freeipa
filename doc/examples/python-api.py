#!/usr/bin/python3
# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
#

from __future__ import print_function
from ipalib import api


def example():
    # 1. Initialize ipalib
    #
    # Run ./python-api.py --help to see the global options.  Some useful
    # options:
    #
    #   -v  Produce more verbose output
    #   -d  Produce full debugging output
    #   -e in_server=True  Force running in server mode
    #   -e xmlrpc_uri=https://foo.com/ipa/xml  # Connect to a specific server

    api.bootstrap_with_global_options(context='example')
    api.finalize()

    # You will need to create a connection.  If you're in_server, call
    # Backend.ldap.connect(), otherwise Backend.rpcclient.connect().

    if api.env.in_server:
        api.Backend.ldap2.connect()
    else:
        api.Backend.rpcclient.connect()

    # Now that you're connected, you can make calls to api.Command.whatever():
    print('The admin user:')
    print(api.Command.user_show(u'admin'))


if __name__ == '__main__':
    example()
