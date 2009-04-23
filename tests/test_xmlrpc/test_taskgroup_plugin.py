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
Test the `ipalib/plugins/taskgroup` module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors


class test_Taskgroup(XMLRPC_test):
    """
    Test the `taskgroup` plugin.
    """
    cn=u'testgroup'
    description=u'Test task group'
    kw={'cn': cn, 'description': description}

    taskgroup_cn = u'ipatestgroup'
    taskgroup_description = u'Test group for taskgroups'

    rolegroup_cn = u'iparolegroup'
    rolegroup_description = u'Test rolegroup for taskgroups'

    def test_add(self):
        """
        Test the `xmlrpc.taskgroup_add` method.
        """
        res = api.Command['taskgroup_add'](**self.kw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn

    def test_addrolegroup(self):
        """
        Add a rolegroup to test add/remove member.
        """
        kw={'cn': self.rolegroup_cn, 'description': self.rolegroup_description}
        res = api.Command['rolegroup_add'](**kw)
        assert res
        assert res.get('description','') == self.rolegroup_description
        assert res.get('cn','') == self.rolegroup_cn

    def test_addtaskgroup(self):
        """
        Add a group to test add/remove member.
        """
        kw={'cn': self.taskgroup_cn, 'description': self.taskgroup_description}
        res = api.Command['group_add'](**kw)
        assert res
        assert res.get('description','') == self.taskgroup_description
        assert res.get('cn','') == self.taskgroup_cn

    def test_addtaskgroupmember(self):
        """
        Test the `xmlrpc.taskgroup_add_member` method.
        """
        kw={}
        kw['groups'] = self.taskgroup_cn
        kw['rolegroups'] = self.rolegroup_cn
        res = api.Command['taskgroup_add_member'](self.cn, **kw)
        assert res == tuple()

    def test_doshow(self):
        """
        Test the `xmlrpc.taskgroup_show` method.
        """
        res = api.Command['taskgroup_show'](self.cn)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn
        foundrole = False
        foundtask = False
        members = res.get('member',[])
        for m in members:
            if m.startswith('cn=%s' % self.taskgroup_cn): foundtask=True
            if m.startswith('cn=%s' % self.rolegroup_cn): foundrole=True

        if not foundtask and foundrole:
            assert False

    def test_find(self):
        """
        Test the `xmlrpc.taskgroup_find` method.
        """
        res = api.Command['taskgroup_find'](self.cn)
        assert res
        assert len(res) == 2, res
        assert res[1].get('description','') == self.description
        assert res[1].get('cn','') == self.cn
        members = res[1].get('member',[])
        foundrole = False
        foundtask = False
        for m in members:
            if m.startswith('cn=%s' % self.taskgroup_cn): foundtask=True
            if m.startswith('cn=%s' % self.rolegroup_cn): foundrole=True

        if not foundtask and foundrole:
            assert False

    def test_mod(self):
        """
        Test the `xmlrpc.taskgroup_mod` method.
        """
        newdesc=u'Updated task group'
        modkw={'cn': self.cn, 'description': newdesc}
        res = api.Command['taskgroup_mod'](**modkw)
        assert res
        assert res.get('description','') == newdesc

        # Ok, double-check that it was changed
        res = api.Command['taskgroup_show'](self.cn)
        assert res
        assert res.get('description','') == newdesc
        assert res.get('cn','') == self.cn

    def test_member_remove(self):
        """
        Test the `xmlrpc.taskgroup_remove_member` method.
        """
        kw={}
        kw['tasks'] = self.taskgroup_cn
        res = api.Command['taskgroup_remove_member'](self.cn, **kw)
        assert res == tuple()

    def test_remove(self):
        """
        Test the `xmlrpc.taskgroup_del` method.
        """
        res = api.Command['taskgroup_del'](self.cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['taskgroup_show'](self.cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_removetask(self):
        """
        Remove the group we created for member testing
        """
        res = api.Command['group_del'](self.taskgroup_cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['group_show'](self.taskgroup_cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_removerolegroup(self):
        """
        Remove the rolegroup we created for member testing
        """
        res = api.Command['rolegroup_del'](self.rolegroup_cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['rolegroup_show'](self.rolegroup_cn)
        except errors.NotFound:
            pass
        else:
            assert False
