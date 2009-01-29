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
Test the `ipalib/plugins/f_hostgroup` module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors


class test_Host(XMLRPC_test):
    """
    Test the `f_hostgroup` plugin.
    """
    cn='testgroup'
    description='Test host group'
    kw={'cn': cn, 'description': description}

    host_cn='ipaexample.%s' % api.env.domain
    host_description='Test host'
    host_localityname='Undisclosed location'

    def test_add(self):
        """
        Test the `xmlrpc.hostgroup_add` method.
        """
        res = api.Command['hostgroup_add'](**self.kw)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn

    def test_addhost(self):
        """
        Add a host to test add/remove member.
        """
        kw={'cn': self.host_cn, 'description': self.host_description, 'localityname': self.host_localityname}
        res = api.Command['host_add'](**kw)
        assert res
        assert res.get('description','') == self.host_description
        assert res.get('cn','') == self.host_cn

    def test_addmember(self):
        """
        Test the `xmlrpc.hostgroup_add_member` method.
        """
        kw={}
        kw['hosts'] = self.host_cn
        res = api.Command['hostgroup_add_member'](self.cn, **kw)
        assert res == tuple()

    def test_doshow(self):
        """
        Test the `xmlrpc.hostgroup_show` method.
        """
        res = api.Command['hostgroup_show'](self.cn)
        assert res
        assert res.get('description','') == self.description
        assert res.get('cn','') == self.cn
        assert res.get('member','').startswith('cn=%s' % self.host_cn)

    def test_find(self):
        """
        Test the `xmlrpc.hostgroup_find` method.
        """
        res = api.Command['hostgroup_find'](self.cn)
        assert res
        assert len(res) == 2
        assert res[1].get('description','') == self.description
        assert res[1].get('cn','') == self.cn
        assert res[1].get('member','').startswith('cn=%s' % self.host_cn)

    def test_mod(self):
        """
        Test the `xmlrpc.hostgroup_mod` method.
        """
        newdesc='Updated host group'
        modkw={'cn': self.cn, 'description': newdesc}
        res = api.Command['hostgroup_mod'](**modkw)
        assert res
        assert res.get('description','') == newdesc

        # Ok, double-check that it was changed
        res = api.Command['hostgroup_show'](self.cn)
        assert res
        assert res.get('description','') == newdesc
        assert res.get('cn','') == self.cn

    def test_member_remove(self):
        """
        Test the `xmlrpc.hostgroup_remove_member` method.
        """
        kw={}
        kw['hosts'] = self.host_cn
        res = api.Command['hostgroup_remove_member'](self.cn, **kw)
        assert res == tuple()

    def test_remove(self):
        """
        Test the `xmlrpc.hostgroup_del` method.
        """
        res = api.Command['hostgroup_del'](self.cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['hostgroup_show'](self.cn)
        except errors2.NotFound:
            pass
        else:
            assert False

    def test_removehost(self):
        """
        Test the `xmlrpc.host_del` method.
        """
        res = api.Command['host_del'](self.host_cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['host_show'](self.host_cn)
        except errors2.NotFound:
            pass
        else:
            assert False
