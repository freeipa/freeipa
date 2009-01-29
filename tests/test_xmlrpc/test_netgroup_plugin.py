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
Test the `ipalib/plugins/f_netgroup` module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors


def is_member_of(members, candidate):
    if isinstance(members, tuple):
        members = list(members)
    if not isinstance(members, list):
        members = [members]
    for m in members:
        if m.startswith(candidate):
            return True
    return False

class test_Netgroup(XMLRPC_test):
    """
    Test the `f_netgroup` plugin.
    """
    ng_cn='ng1'
    ng_description='Netgroup'
    ng_kw={'cn': ng_cn, 'description': ng_description}

    host_cn='ipaexample.%s' % api.env.domain
    host_description='Test host'
    host_localityname='Undisclosed location'
    host_kw={'cn': host_cn, 'description': host_description, 'localityname': host_localityname}

    hg_cn='ng1'
    hg_description='Netgroup'
    hg_kw={'cn': hg_cn, 'description': hg_description}

    user_uid='jexample'
    user_givenname='Jim'
    user_sn='Example'
    user_home='/home/%s' % user_uid
    user_kw={'givenname':user_givenname,'sn':user_sn,'uid':user_uid,'homedirectory':user_home}

    group_cn='testgroup'
    group_description='This is a test'
    group_kw={'description':group_description,'cn':group_cn}

    def test_add(self):
        """
        Test the `xmlrpc.netgroup_add` method.
        """
        res = api.Command['netgroup_add'](**self.ng_kw)
        assert res
        assert res.get('description','') == self.ng_description
        assert res.get('cn','') == self.ng_cn

    def test_adddata(self):
        """
        Add the data needed to do additional testing.
        """

        # Add a host
        res = api.Command['host_add'](**self.host_kw)
        assert res
        assert res.get('description','') == self.host_description
        assert res.get('cn','') == self.host_cn

        # Add a hostgroup
        res = api.Command['hostgroup_add'](**self.hg_kw)
        assert res
        assert res.get('description','') == self.hg_description
        assert res.get('cn','') == self.hg_cn

        # Add a user
        res = api.Command['user_add'](**self.user_kw)
        assert res
        assert res.get('givenname','') == self.user_givenname
        assert res.get('uid','') == self.user_uid

        # Add a group
        res = api.Command['group_add'](**self.group_kw)
        assert res
        assert res.get('description','') == self.group_description
        assert res.get('cn','') == self.group_cn

    def test_addmembers(self):
        """
        Test the `xmlrpc.netgroup_add_member` method.
        """
        kw={}
        kw['hosts'] = self.host_cn
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert res == tuple()

        kw={}
        kw['hostgroups'] = self.hg_cn
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert res == tuple()

        kw={}
        kw['users'] = self.user_uid
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert res == tuple()

        kw={}
        kw['groups'] = self.group_cn
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert res == tuple()

    def test_addmembers2(self):
        """
        Test the `xmlrpc.netgroup_add_member` method again to test dupes.
        """
        kw={}
        kw['hosts'] = self.host_cn
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert is_member_of(res, 'cn=%s' % self.host_cn)

        kw={}
        kw['hostgroups'] = self.hg_cn
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert is_member_of(res, 'cn=%s' % self.hg_cn)

        kw={}
        kw['users'] = self.user_uid
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert is_member_of(res, 'uid=%s' % self.user_uid)

        kw={}
        kw['groups'] = self.group_cn
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert is_member_of(res, 'cn=%s' % self.group_cn)

    def test_addexternalmembers(self):
        """
        Test adding external hosts
        """
        kw={}
        kw['hosts'] = "nosuchhost"
        res = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert res == tuple()
        res = api.Command['netgroup_show'](self.ng_cn)
        assert res
        assert is_member_of(res.get('externalhost',[]), kw['hosts'])

    def test_doshow(self):
        """
        Test the `xmlrpc.netgroup_show` method.
        """
        res = api.Command['netgroup_show'](self.ng_cn)
        assert res
        assert res.get('description','') == self.ng_description
        assert res.get('cn','') == self.ng_cn
        assert is_member_of(res.get('memberhost',[]), 'cn=%s' % self.host_cn)
        assert is_member_of(res.get('memberhost',[]), 'cn=%s' % self.hg_cn)
        assert is_member_of(res.get('memberuser',[]), 'uid=%s' % self.user_uid)
        assert is_member_of(res.get('memberuser',[]), 'cn=%s' % self.group_cn)

    def test_find(self):
        """
        Test the `xmlrpc.hostgroup_find` method.
        """
        res = api.Command['netgroup_find'](self.ng_cn)
        assert res
        assert len(res) == 2
        assert res[1].get('description','') == self.ng_description
        assert res[1].get('cn','') == self.ng_cn

    def test_mod(self):
        """
        Test the `xmlrpc.hostgroup_mod` method.
        """
        newdesc='Updated host group'
        modkw={'cn': self.ng_cn, 'description': newdesc}
        res = api.Command['netgroup_mod'](**modkw)
        assert res
        assert res.get('description','') == newdesc

        # Ok, double-check that it was changed
        res = api.Command['netgroup_show'](self.ng_cn)
        assert res
        assert res.get('description','') == newdesc
        assert res.get('cn','') == self.ng_cn

    def test_member_remove(self):
        """
        Test the `xmlrpc.hostgroup_remove_member` method.
        """
        kw={}
        kw['hosts'] = self.host_cn
        res = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert res == tuple()

        kw={}
        kw['hostgroups'] = self.hg_cn
        res = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert res == tuple()

        kw={}
        kw['users'] = self.user_uid
        res = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert res == tuple()

        kw={}
        kw['groups'] = self.group_cn
        res = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert res == tuple()

    def test_member_remove2(self):
        """
        Test the `xmlrpc.netgroup_remove_member` method again to test not found.
        """
        kw={}
        kw['hosts'] = self.host_cn
        res = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert is_member_of(res, 'cn=%s' % self.host_cn)

        kw={}
        kw['hostgroups'] = self.hg_cn
        res = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert is_member_of(res, 'cn=%s' % self.hg_cn)

        kw={}
        kw['users'] = self.user_uid
        res = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert is_member_of(res, 'uid=%s' % self.user_uid)

        kw={}
        kw['groups'] = self.group_cn
        res = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert is_member_of(res, 'cn=%s' % self.group_cn)

    def test_remove(self):
        """
        Test the `xmlrpc.netgroup_del` method.
        """
        res = api.Command['netgroup_del'](self.ng_cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['netgroup_show'](self.ng_cn)
        except errors2.NotFound:
            pass
        else:
            assert False

    def test_removedata(self):
        """
        Remove the test data we added
        """
        # Remove the host
        res = api.Command['host_del'](self.host_cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['host_show'](self.host_cn)
        except errors2.NotFound:
            pass
        else:
            assert False

        # Remove the hostgroup
        res = api.Command['hostgroup_del'](self.hg_cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['hostgroup_show'](self.hg_cn)
        except errors2.NotFound:
            pass
        else:
            assert False

        # Remove the user
        res = api.Command['user_del'](self.user_uid)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['user_show'](self.user_uid)
        except errors2.NotFound:
            pass
        else:
            assert False

        # Remove the group
        res = api.Command['group_del'](self.group_cn)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['group_show'](self.group_cn)
        except errors2.NotFound:
            pass
        else:
            assert False
