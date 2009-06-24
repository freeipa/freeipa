# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
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
Test the `ipalib/plugins/taskgroup.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal, assert_is_member
from ipalib import api
from ipalib import errors


class test_taskgroup(XMLRPC_test):
    """
    Test the `taskgroup` plugin.
    """
    cn = u'testgroup'
    description = u'Test task group'
    kw = {'cn': cn, 'description': description}

    taskgroup_cn = u'ipatestgroup'
    taskgroup_description = u'Test group for taskgroups'

    rolegroup_cn = u'iparolegroup'
    rolegroup_description = u'Test rolegroup for taskgroups'

    def test_1_taskgroup_add(self):
        """
        Test the `xmlrpc.taskgroup_add` method.
        """
        (dn, res) = api.Command['taskgroup_add'](**self.kw)
        assert res
        assert_attr_equal(res, 'description', self.description)
        assert_attr_equal(res, 'cn', self.cn)

    def test_2_add_rolegroup(self):
        """
        Add a rolegroup to test add/remove member.
        """
        kw={'cn': self.rolegroup_cn, 'description': self.rolegroup_description}
        (dn, res) = api.Command['rolegroup_add'](**kw)
        assert res
        assert_attr_equal(res, 'description', self.rolegroup_description)
        assert_attr_equal(res, 'cn', self.rolegroup_cn)

    def test_3_add_taskgroup(self):
        """
        Add a group to test add/remove member.
        """
        kw = {'cn': self.taskgroup_cn, 'description': self.taskgroup_description}
        (dn, res) = api.Command['group_add'](**kw)
        assert res
        assert_attr_equal(res, 'description', self.taskgroup_description)
        assert_attr_equal(res, 'cn', self.taskgroup_cn)

    def test_4_taskgroup_add_member(self):
        """
        Test the `xmlrpc.taskgroup_add_member` method.
        """
        kw = {}
        kw['groups'] = self.taskgroup_cn
        kw['rolegroups'] = self.rolegroup_cn
        (total, res) = api.Command['taskgroup_add_member'](self.cn, **kw)
        assert total == 2

    def test_5_taskgroup_show(self):
        """
        Test the `xmlrpc.taskgroup_show` method.
        """
        (dn, res) = api.Command['taskgroup_show'](self.cn, all=True)
        assert res
        assert_attr_equal(res, 'description', self.description)
        assert_attr_equal(res, 'cn', self.cn)
        assert_is_member(res, 'cn=%s' % self.taskgroup_cn)
        assert_is_member(res, 'cn=%s' % self.rolegroup_cn)

    def test_6_taskgroup_find(self):
        """
        Test the `xmlrpc.taskgroup_find` method.
        """
        (res, truncated) = api.Command['taskgroup_find'](self.cn)
        assert res
        assert_attr_equal(res[0][1], 'description', self.description)
        assert_attr_equal(res[0][1], 'cn', self.cn)
        assert_is_member(res[0][1], 'cn=%s' % self.taskgroup_cn)
        assert_is_member(res[0][1], 'cn=%s' % self.rolegroup_cn)

    def test_7_taskgroup_mod(self):
        """
        Test the `xmlrpc.taskgroup_mod` method.
        """
        newdesc = u'Updated task group'
        modkw = {'cn': self.cn, 'description': newdesc}
        (dn, res) = api.Command['taskgroup_mod'](**modkw)
        assert res
        assert_attr_equal(res, 'description', newdesc)

        # Ok, double-check that it was changed
        (dn, res) = api.Command['taskgroup_show'](self.cn)
        assert res
        assert_attr_equal(res, 'description', newdesc)
        assert_attr_equal(res, 'cn', self.cn)

    def test_8_taskgroup_del_member(self):
        """
        Test the `xmlrpc.taskgroup_remove_member` method.
        """
        kw = {}
        kw['groups'] = self.taskgroup_cn
        (total, res) = api.Command['taskgroup_del_member'](self.cn, **kw)
        assert total == 1

    def test_9_taskgroup_del(self):
        """
        Test the `xmlrpc.taskgroup_del` method.
        """
        res = api.Command['taskgroup_del'](self.cn)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['taskgroup_show'](self.cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_a_del_taskgroup(self):
        """
        Remove the group we created for member testing.
        """
        res = api.Command['group_del'](self.taskgroup_cn)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['group_show'](self.taskgroup_cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_b_del_rolegroup(self):
        """
        Remove the rolegroup we created for member testing.
        """
        res = api.Command['rolegroup_del'](self.rolegroup_cn)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['rolegroup_show'](self.rolegroup_cn)
        except errors.NotFound:
            pass
        else:
            assert False

