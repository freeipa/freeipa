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
Test the `ipalib/plugins/rolegroup` module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors2


class test_Rolegroup(XMLRPC_test):
    """
    Test the `rolegroup` plugin.
    """
    cn=u'testgroup'
    description=u'Test role group'
    kw={'cn': cn, 'description': description}

    rolegroup_cn = u'ipatestgroup'
    rolegroup_description = u'Test group for rolegroups'

    def test_add(self):
        """
        Test the `xmlrpc.rolegroup_add` method.
        """
        res = api.Command['rolegroup_add'](**self.kw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn

    def test_addrolegroup(self):
        """
        Add a group to test add/remove member.
        """
        kw={'cn': self.rolegroup_cn, 'description': self.rolegroup_description}
        res = api.Command['group_add'](**kw)
        assert res
        assert res.get('description','') == self.rolegroup_description
        assert res.get('cn','') == self.rolegroup_cn

    def test_addrolegroupmember(self):
        """
        Test the `xmlrpc.rolegroup_add_member` method.
        """
        kw={}
        kw['groups'] = self.rolegroup_cn
        res = api.Command['rolegroup_add_member'](self.cn, **kw)
        assert res == tuple()

    def test_doshow(self):
        """
        Test the `xmlrpc.rolegroup_show` method.
        """
        res = api.Command['rolegroup_show'](self.cn)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn
        assert res.get('member','').startswith('cn=%s' % self.rolegroup_cn)

    def test_find(self):
        """
        Test the `xmlrpc.rolegroup_find` method.
        """
        res = api.Command['rolegroup_find'](self.cn)
        assert res
        assert len(res) == 2, res
        assert res[1].get('description','') == self.description
        assert res[1].get('cn','') == self.cn
        assert res[1].get('member','').startswith('cn=%s' % self.rolegroup_cn)

    def test_mod(self):
        """
        Test the `xmlrpc.rolegroup_mod` method.
        """
        newdesc=u'Updated role group'
        modkw={'cn': self.cn, 'description': newdesc}
        res = api.Command['rolegroup_mod'](**modkw)
        assert res
        assert res.get('description','') == newdesc

        # Ok, double-check that it was changed
        res = api.Command['rolegroup_show'](self.cn)
        assert res
        assert res.get('description','') == newdesc
        assert res.get('cn','') == self.cn

    def test_member_remove(self):
        """
        Test the `xmlrpc.rolegroup_remove_member` method.
        """
        kw={}
        kw['roles'] = self.rolegroup_cn
        res = api.Command['rolegroup_remove_member'](self.cn, **kw)
        assert res == tuple()

    def test_remove(self):
        """
        Test the `xmlrpc.rolegroup_del` method.
        """
        res = api.Command['rolegroup_del'](self.cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['rolegroup_show'](self.cn)
        except errors2.NotFound:
            pass
        else:
            assert False

    def test_removerole(self):
        """
        Remove the group we created for member testing
        """
        res = api.Command['group_del'](self.rolegroup_cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['group_show'](self.rolegroup_cn)
        except errors2.NotFound:
            pass
        else:
            assert False
