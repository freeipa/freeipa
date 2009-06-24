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
from ipalib import api, request
from ipalib import errors


def assert_attr_equal(entry_attrs, attr, value):
    assert value in entry_attrs.get(attr, [])

def assert_is_member(entry_attrs, value, member_attr='member'):
    for m in entry_attrs[member_attr]:
        if m.startswith(value):
            return
    assert False


# Initialize the API. We do this here so that one can run the tests
# individually instead of at the top-level. If API.bootstrap()
# has already been called we continue gracefully. Other errors will be
# raised.

class XMLRPC_test(object):
    """
    Base class for all XML-RPC plugin tests
    """

    def setUp(self):
        try:
            if not api.Backend.xmlclient.isconnected():
                api.Backend.xmlclient.connect()
            res = api.Command['user_show'](u'notfound')
        except errors.NetworkError:
            raise nose.SkipTest()
        except errors.NotFound:
            pass

    def tearDown(self):
        """
        nose tear-down fixture.
        """
        request.destroy_context()

