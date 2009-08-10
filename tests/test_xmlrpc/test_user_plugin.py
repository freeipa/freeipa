# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
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
Test the `ipalib/plugins/user.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_user(XMLRPC_test):
    """
    Test the `user` plugin.
    """
    uid = u'jexample'
    givenname = u'Jim'
    sn = u'Example'
    home = u'/home/%s' % uid
    principalname = u'%s@%s' % (uid, api.env.realm)
    kw = {'givenname': givenname, 'sn': sn, 'uid': uid, 'homedirectory': home}

    def test_1_user_add(self):
        """
        Test the `xmlrpc.user_add` method.
        """
        (dn, res) = api.Command['user_add'](**self.kw)
        assert res
        assert_attr_equal(res, 'givenname', self.givenname)
        assert_attr_equal(res, 'sn', self.sn)
        assert_attr_equal(res, 'uid', self.uid)
        assert_attr_equal(res, 'homedirectory', self.home)
        assert_attr_equal(res, 'objectclass', 'ipaobject')

    def test_2_user_add(self):
        """
        Test the `xmlrpc.user_add` method duplicate detection.
        """
        try:
            api.Command['user_add'](**self.kw)
        except errors.DuplicateEntry:
            pass

    def test_3_user_show(self):
        """
        Test the `xmlrpc.user_show` method.
        """
        kw = {'uid': self.uid, 'all': True}
        (dn, res) = api.Command['user_show'](**kw)
        assert res
        assert_attr_equal(res, 'givenname', self.givenname)
        assert_attr_equal(res, 'sn', self.sn)
        assert_attr_equal(res, 'uid', self.uid)
        assert_attr_equal(res, 'homedirectory', self.home)
        assert_attr_equal(res, 'krbprincipalname', self.principalname)

    def test_4_user_find(self):
        """
        Test the `xmlrpc.user_find` method with all attributes.
        """
        kw = {'all': True}
        (res, truncated) = api.Command['user_find'](self.uid, **kw)
        assert res
        assert_attr_equal(res[0][1], 'givenname', self.givenname)
        assert_attr_equal(res[0][1], 'sn', self.sn)
        assert_attr_equal(res[0][1], 'uid', self.uid)
        assert_attr_equal(res[0][1], 'homedirectory', self.home)
        assert_attr_equal(res[0][1], 'krbprincipalname', self.principalname)

    def test_5_user_find(self):
        """
        Test the `xmlrpc.user_find` method with minimal attributes.
        """
        (res, truncated) = api.Command['user_find'](self.uid)
        assert res
        assert_attr_equal(res[0][1], 'givenname', self.givenname)
        assert_attr_equal(res[0][1], 'sn', self.sn)
        assert_attr_equal(res[0][1], 'uid', self.uid)
        assert_attr_equal(res[0][1], 'homedirectory', self.home)
        assert 'krbprincipalname' not in res[0][1]

    def test_6_user_lock(self):
        """
        Test the `xmlrpc.user_lock` method.
        """
        res = api.Command['user_lock'](self.uid)
        assert res == True

    def test_7_user_unlock(self):
        """
        Test the `xmlrpc.user_unlock` method.
        """
        res = api.Command['user_unlock'](self.uid)
        assert res == True

    def test_8_user_mod(self):
        """
        Test the `xmlrpc.user_mod` method.
        """
        modkw = self.kw
        modkw['givenname'] = u'Finkle'
        (dn, res) = api.Command['user_mod'](**modkw)
        assert res
        assert_attr_equal(res, 'givenname', 'Finkle')
        assert_attr_equal(res, 'sn', self.sn)

        # Ok, double-check that it was changed
        (dn, res) = api.Command['user_show'](self.uid)
        assert res
        assert_attr_equal(res, 'givenname', 'Finkle')
        assert_attr_equal(res, 'sn', self.sn)
        assert_attr_equal(res, 'uid', self.uid)

    def test_9_user_del(self):
        """
        Test the `xmlrpc.user_del` method.
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

