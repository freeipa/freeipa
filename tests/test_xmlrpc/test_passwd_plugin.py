# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Test the `ipalib/plugins/passwd.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_passwd(XMLRPC_test):
    """
    Test the `passwd` plugin.
    """
    uid = u'pwexample'
    givenname = u'Jim'
    sn = u'Example'
    home = u'/home/%s' % uid
    principalname = u'%s@%s' % (uid, api.env.realm)
    kw = {'givenname': givenname, 'sn': sn, 'uid': uid, 'homedirectory': home}

    def test_1_user_add(self):
        """
        Create a test user
        """
        (dn, res) = api.Command['user_add'](**self.kw)
        assert res
        assert_attr_equal(res, 'givenname', self.givenname)
        assert_attr_equal(res, 'sn', self.sn)
        assert_attr_equal(res, 'uid', self.uid)
        assert_attr_equal(res, 'homedirectory', self.home)
        assert_attr_equal(res, 'objectclass', 'ipaobject')

    def test_2_set_passwd(self):
        """
        Test the `xmlrpc.passwd` method.
        """
        res = api.Command['passwd'](self.uid, password=u'password1')
        assert res

    def test_3_user_del(self):
        """
        Remove the test user
        """
        res = api.Command['user_del'](self.uid)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['user_show'](self.uid)
        except errors.NotFound:
            pass
        else:
            assert False
