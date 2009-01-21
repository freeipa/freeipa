# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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

"""
Base class for all XML-RPC tests
"""

import sys
import socket
import nose
from ipalib import api
from ipalib import errors
from ipalib.cli import CLI

try:
    api.finalize()
except StandardError:
    pass

class XMLRPC_test:
    """
    Base class for all XML-RPC plugin tests
    """

    def setUp(self):
        # FIXME: changing Plugin.name from a property to an instance attribute
        # somehow broke this.
        raise nose.SkipTest
        try:
            res = api.Command['user_show']('notfound')
        except socket.error:
            raise nose.SkipTest
        except errors.NotFound:
            pass
