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
Test the `ipalib/plugins/rolegroup.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal, assert_is_member
from ipalib import api
from ipalib import errors


class test_rolegroup(XMLRPC_test):
    """
    Test the `rolegroup` plugin.
    """
    cn = u'testgroup'
    description = u'Test role group'
    kw = {'cn': cn, 'description': description, 'raw': True}

    rolegroup_cn = u'ipatestgroup'
    rolegroup_description = u'Test group for rolegroups'

    def test_1_rolegroup_add(self):
        """
        Test the `xmlrpc.rolegroup_add` method.
        """
        entry = api.Command['rolegroup_add'](**self.kw)['result']
        assert_attr_equal(entry, 'description', self.description)
        assert_attr_equal(entry, 'cn', self.cn)
        # FIXME: Has the schema changed?  rolegroup doesn't have the 'ipaobject'
        # object class.
        #assert_attr_equal(entry, 'objectclass', 'ipaobject')

    def test_2_add_group(self):
        """
        Add a group to test add/remove member.
        """
        kw = {'cn': self.rolegroup_cn, 'description': self.rolegroup_description, 'raw': True}
        entry = api.Command['group_add'](**kw)['result']
        assert_attr_equal(entry, 'description', self.rolegroup_description)
        assert_attr_equal(entry, 'cn', self.rolegroup_cn)

    def test_3_rolegroup_add_member(self):
        """
        Test the `xmlrpc.rolegroup_add_member` method.
        """
        kw = {}
        kw['group'] = self.rolegroup_cn
        ret = api.Command['rolegroup_add_member'](self.cn, **kw)
        assert ret['completed'] == 1

    def test_4_rolegroup_show(self):
        """
        Test the `xmlrpc.rolegroup_show` method.
        """
        entry = api.Command['rolegroup_show'](self.cn, all=True, raw=True)['result']
        assert_attr_equal(entry, 'description', self.description)
        assert_attr_equal(entry, 'cn', self.cn)
        assert_is_member(entry, 'cn=%s' % self.rolegroup_cn)

    def test_5_rolegroup_find(self):
        """
        Test the `xmlrpc.rolegroup_find` method.
        """
        ret = api.Command['rolegroup_find'](self.cn, all=True, raw=True)
        assert ret['truncated'] is False
        entries = ret['result']
        assert_attr_equal(entries[0], 'description', self.description)
        assert_attr_equal(entries[0], 'cn', self.cn)
        assert_is_member(entries[0], 'cn=%s' % self.rolegroup_cn)

    def test_6_rolegroup_mod(self):
        """
        Test the `xmlrpc.rolegroup_mod` method.
        """
        newdesc = u'Updated role group'
        modkw = {'cn': self.cn, 'description': newdesc, 'raw': True}
        entry = api.Command['rolegroup_mod'](**modkw)['result']
        assert_attr_equal(entry, 'description', newdesc)

        # Ok, double-check that it was changed
        entry = api.Command['rolegroup_show'](self.cn, raw=True)['result']
        assert_attr_equal(entry, 'description', newdesc)
        assert_attr_equal(entry, 'cn', self.cn)

    def test_7_rolegroup_remove_member(self):
        """
        Test the `xmlrpc.rolegroup_remove_member` method.
        """
        kw = {}
        kw['group'] = self.rolegroup_cn
        ret = api.Command['rolegroup_remove_member'](self.cn, **kw)
        assert ret['completed'] == 1

    def test_8_rolegroup_del(self):
        """
        Test the `xmlrpc.rolegroup_del` method.
        """
        assert api.Command['rolegroup_del'](self.cn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['rolegroup_show'](self.cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_9_del_group(self):
        """
        Remove the group we created for member testing.
        """
        assert api.Command['group_del'](self.rolegroup_cn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['group_show'](self.rolegroup_cn)
        except errors.NotFound:
            pass
        else:
            assert False
