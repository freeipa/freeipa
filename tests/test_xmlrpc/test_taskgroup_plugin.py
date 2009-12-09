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
    kw = {'cn': cn, 'description': description, 'raw': True}

    taskgroup_cn = u'ipatestgroup'
    taskgroup_description = u'Test group for taskgroups'

    rolegroup_cn = u'iparolegroup'
    rolegroup_description = u'Test rolegroup for taskgroups'

    def test_1_taskgroup_add(self):
        """
        Test the `xmlrpc.taskgroup_add` method.
        """
        ret = self.failsafe_add(
            api.Object.taskgroup, self.cn, description=self.description,
        )
        entry = ret['result']
        assert_attr_equal(entry, 'description', self.description)
        assert_attr_equal(entry, 'cn', self.cn)
        # FIXME: why is 'ipaobject' missing?
        #assert_attr_equal(entry, 'objectclass', 'ipaobject')

    def test_2_add_rolegroup(self):
        """
        Add a rolegroup to test add/remove member.
        """
        ret = self.failsafe_add(api.Object.rolegroup, self.rolegroup_cn,
            description=self.rolegroup_description,
        )
        entry = ret['result']
        assert_attr_equal(entry, 'description', self.rolegroup_description)
        assert_attr_equal(entry, 'cn', self.rolegroup_cn)

    def test_3_add_taskgroup(self):
        """
        Add a group to test add/remove member.
        """
        ret = self.failsafe_add(api.Object.group, self.taskgroup_cn,
            description=self.taskgroup_description,
        )
        entry = ret['result']
        assert_attr_equal(entry, 'description', self.taskgroup_description)
        assert_attr_equal(entry, 'cn', self.taskgroup_cn)

    def test_4_taskgroup_add_member(self):
        """
        Test the `xmlrpc.taskgroup_add_member` method.
        """
        kw = {}
        kw['group'] = self.taskgroup_cn
        kw['rolegroup'] = self.rolegroup_cn
        ret = api.Command['taskgroup_add_member'](self.cn, **kw)
        assert ret['completed'] == 2

    def test_5_taskgroup_show(self):
        """
        Test the `xmlrpc.taskgroup_show` method.
        """
        entry = api.Command['taskgroup_show'](self.cn, all=True)['result']
        assert_attr_equal(entry, 'description', self.description)
        assert_attr_equal(entry, 'cn', self.cn)
        #assert_is_member(entry, 'cn=%s' % self.taskgroup_cn)
        #assert_is_member(entry, 'cn=%s' % self.rolegroup_cn)

    def test_6_taskgroup_find(self):
        """
        Test the `xmlrpc.taskgroup_find` method.
        """
        ret = api.Command['taskgroup_find'](self.cn, all=True, raw=True)
        entry = ret['result'][0]
        assert_attr_equal(entry, 'description', self.description)
        assert_attr_equal(entry, 'cn', self.cn)
        #assert_is_member(entry, 'cn=%s' % self.taskgroup_cn)
        #assert_is_member(entry, 'cn=%s' % self.rolegroup_cn)

    def test_7_taskgroup_mod(self):
        """
        Test the `xmlrpc.taskgroup_mod` method.
        """
        newdesc = u'Updated task group'
        modkw = {'cn': self.cn, 'description': newdesc, 'raw': True}
        entry = api.Command['taskgroup_mod'](**modkw)['result']
        assert_attr_equal(entry, 'description', newdesc)

        # Ok, double-check that it was changed
        entry = api.Command['taskgroup_show'](self.cn, raw=True)['result']
        assert_attr_equal(entry, 'description', newdesc)
        assert_attr_equal(entry, 'cn', self.cn)

    def test_8_taskgroup_del_member(self):
        """
        Test the `xmlrpc.taskgroup_remove_member` method.
        """
        kw = {}
        kw['group'] = self.taskgroup_cn
        ret = api.Command['taskgroup_remove_member'](self.cn, **kw)
        assert ret['completed'] == 1

    def test_9_taskgroup_del(self):
        """
        Test the `xmlrpc.taskgroup_del` method.
        """
        assert api.Command['taskgroup_del'](self.cn)['result'] is True

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
        assert api.Command['group_del'](self.taskgroup_cn)['result'] is True

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
        assert api.Command['rolegroup_del'](self.rolegroup_cn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['rolegroup_show'](self.rolegroup_cn)
        except errors.NotFound:
            pass
        else:
            assert False
