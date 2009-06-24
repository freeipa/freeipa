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
Test the `ipalib/plugins/group.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_group(XMLRPC_test):
    """
    Test the `group` plugin.
    """
    cn = u'testgroup'
    cn2 = u'testgroup2'
    cnposix = u'posixgroup'
    description = u'This is a test'
    kw = {'description': description, 'cn': cn}

    def test_1_group_add(self):
        """
        Test the `xmlrpc.group_add` method: testgroup.
        """
        (dn, res) = api.Command['group_add'](**self.kw)
        assert res
        assert_attr_equal(res, 'description', self.description)
        assert_attr_equal(res, 'cn', self.cn)

    def test_2_group_add(self):
        """
        Test the `xmlrpc.group_add` method duplicate detection.
        """
        try:
            api.Command['group_add'](**self.kw)
        except errors.DuplicateEntry:
            pass

    def test_3_group_add(self):
        """
        Test the `xmlrpc.group_add` method: testgroup2.
        """
        self.kw['cn'] = self.cn2
        (dn, res) = api.Command['group_add'](**self.kw)
        assert res
        assert_attr_equal(res, 'description', self.description)
        assert_attr_equal(res, 'cn', self.cn2)

    def test_3_group_add_member(self):
        """
        Test the `xmlrpc.group_add_member` method.
        """
        kw = {}
        kw['groups'] = self.cn2
        (total, res) = api.Command['group_add_member'](self.cn, **kw)
        assert total == 1

    def test_4_group_add_member(self):
        """
        Test the `xmlrpc.group_add_member` with a non-existent member
        """
        kw = {}
        kw['groups'] = u'notfound'
        (total, res) = api.Command['group_add_member'](self.cn, **kw)
        assert total == 0

    def test_5_group_show(self):
        """
        Test the `xmlrpc.group_show` method.
        """
        (dn, res) = api.Command['group_show'](self.cn)
        assert res
        assert_attr_equal(res, 'description', self.description)
        assert_attr_equal(res, 'cn', self.cn)

    def test_6_group_find(self):
        """
        Test the `xmlrpc.group_find` method.
        """
        (res, truncated) = api.Command['group_find'](cn=self.cn)
        assert res
        assert_attr_equal(res[0][1], 'description', self.description)
        assert_attr_equal(res[0][1], 'cn', self.cn)

    def test_7_group_mod(self):
        """
        Test the `xmlrpc.group_mod` method.
        """
        modkw = self.kw
        modkw['cn'] = self.cn
        modkw['description'] = u'New description'
        (dn, res) = api.Command['group_mod'](**modkw)
        assert res
        assert_attr_equal(res, 'description', 'New description')
        # Ok, double-check that it was changed
        (dn, res) = api.Command['group_show'](self.cn)
        assert res
        assert_attr_equal(res, 'description', 'New description')
        assert_attr_equal(res, 'cn', self.cn)

    def test_8_group_mod(self):
        """
        Test the `xmlrpc.group_mod` method, promote a posix group
        """
        modkw = self.kw
        modkw['cn'] = self.cn
        modkw['posix'] = True
        (dn, res) = api.Command['group_mod'](**modkw)
        assert res
        assert_attr_equal(res, 'description', 'New description')
        assert_attr_equal(res, 'cn', self.cn)
        # Ok, double-check that it was changed
        (dn, res) = api.Command['group_show'](self.cn, all=True)
        assert res
        assert_attr_equal(res, 'description', 'New description')
        assert_attr_equal(res, 'cn', self.cn)
        assert res.get('gidnumber', '')

    def test_9_group_del_member(self):
        """
        Test the `xmlrpc.group_del_member` method.
        """
        kw = {}
        kw['groups'] = self.cn2
        (total, res) = api.Command['group_del_member'](self.cn, **kw)
        assert res
        assert total == 1

    def test_a_group_del_member(self):
        """
        Test the `xmlrpc.group_del_member` method with non-member
        """
        kw = {}
        kw['groups'] = u'notfound'
        # an error isn't thrown, the list of failed members is returned
        (total, res) = api.Command['group_del_member'](self.cn, **kw)
        assert total == 0

    def test_b_group_del(self):
        """
        Test the `xmlrpc.group_del` method: testgroup.
        """
        res = api.Command['group_del'](self.cn)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['group_show'](self.cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_c_group_del(self):
        """
        Test the `xmlrpc.group_del` method: testgroup2.
        """
        res = api.Command['group_del'](self.cn2)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['group_show'](self.cn2)
        except errors.NotFound:
            pass
        else:
            assert False

