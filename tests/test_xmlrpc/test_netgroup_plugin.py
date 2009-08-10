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
Test the `ipalib/plugins/netgroup.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal, assert_is_member
from ipalib import api
from ipalib import errors


class test_netgroup(XMLRPC_test):
    """
    Test the `netgroup` plugin.
    """
    ng_cn = u'ng1'
    ng_description = u'Netgroup'
    ng_kw = {'cn': ng_cn, 'description': ng_description, 'nisdomainname': u'example.com'}

    host_fqdn = u'ipatesthost.%s' % api.env.domain
    host_description = u'Test host'
    host_localityname = u'Undisclosed location'
    host_kw = {'fqdn': host_fqdn, 'description': host_description, 'localityname': host_localityname}

    hg_cn = u'ng1'
    hg_description = u'Netgroup'
    hg_kw = {'cn': hg_cn, 'description': hg_description}

    user_uid = u'jexample'
    user_givenname = u'Jim'
    user_sn = u'Example'
    user_home = u'/home/%s' % user_uid
    user_kw = {'givenname': user_givenname,'sn': user_sn,'uid': user_uid,'homedirectory': user_home}

    group_cn = u'testgroup'
    group_description = u'This is a test'
    group_kw = {'description': group_description,'cn': group_cn}

    def test_1_netgroup_add(self):
        """
        Test the `xmlrpc.netgroup_add` method.
        """
        (dn, res) = api.Command['netgroup_add'](**self.ng_kw)
        assert res
        assert_attr_equal(res, 'description', self.ng_description)
        assert_attr_equal(res, 'cn', self.ng_cn)

    def test_2_add_data(self):
        """
        Add the data needed to do additional testing.
        """
        # Add a host
        (dn, res) = api.Command['host_add'](**self.host_kw)
        assert res
        assert_attr_equal(res, 'description', self.host_description)
        assert_attr_equal(res, 'fqdn', self.host_fqdn)

        # Add a hostgroup
        (dn, res) = api.Command['hostgroup_add'](**self.hg_kw)
        assert res
        assert_attr_equal(res, 'description', self.hg_description)
        assert_attr_equal(res, 'cn', self.hg_cn)

        # Add a user
        (dn, res) = api.Command['user_add'](**self.user_kw)
        assert res
        assert_attr_equal(res, 'givenname', self.user_givenname)
        assert_attr_equal(res, 'uid', self.user_uid)

        # Add a group
        (dn, res) = api.Command['group_add'](**self.group_kw)
        assert res
        assert_attr_equal(res, 'description', self.group_description)
        assert_attr_equal(res, 'cn', self.group_cn)

    def test_3_netgroup_add_member(self):
        """
        Test the `xmlrpc.netgroup_add_member` method.
        """
        kw = {}
        kw['hosts'] = self.host_fqdn
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 1
        assert_is_member(res[1], 'fqdn=%s' % self.host_fqdn)

        kw = {}
        kw['hostgroups'] = self.hg_cn
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 1
        assert_is_member(res[1], 'cn=%s' % self.hg_cn)

        kw = {}
        kw['users'] = self.user_uid
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 1
        assert_is_member(res[1], 'uid=%s' % self.user_uid)

        kw = {}
        kw['groups'] = self.group_cn
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 1
        assert_is_member(res[1], 'cn=%s' % self.group_cn)

    def test_4_netgroup_add_member(self):
        """
        Test the `xmlrpc.netgroup_add_member` method again to test dupes.
        """
        kw = {}
        kw['hosts'] = self.host_fqdn
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 0
        assert self.host_fqdn in failed

        kw = {}
        kw['hostgroups'] = self.hg_cn
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 0
        assert self.hg_cn in failed

        kw = {}
        kw['users'] = self.user_uid
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 0
        assert self.user_uid in failed

        kw = {}
        kw['groups'] = self.group_cn
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 0
        assert self.group_cn in failed

    def test_5_netgroup_add_member(self):
        """
        Test adding external hosts.
        """
        kw = {}
        kw['hosts'] = u'nosuchhost'
        (total, failed, res) = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert total == 1

        (dn, res) = api.Command['netgroup_show'](self.ng_cn)
        assert res
        assert_is_member(res, 'nosuchhost', 'externalhost')

    def test_6_netgroup_show(self):
        """
        Test the `xmlrpc.netgroup_show` method.
        """
        (dn, res) = api.Command['netgroup_show'](self.ng_cn, all=True)
        assert res
        assert_attr_equal(res, 'description', self.ng_description)
        assert_attr_equal(res, 'cn', self.ng_cn)
        assert_is_member(res, 'fqdn=%s' % self.host_fqdn)
        assert_is_member(res, 'cn=%s' % self.hg_cn)
        assert_is_member(res, 'uid=%s' % self.user_uid)
        assert_is_member(res, 'cn=%s' % self.group_cn)
        assert_attr_equal(res, 'objectclass', 'ipaobject')

    def test_7_netgroup_find(self):
        """
        Test the `xmlrpc.hostgroup_find` method.
        """
        (res, truncated) = api.Command.netgroup_find(self.ng_cn)
        assert res
        assert_attr_equal(res[0][1], 'description', self.ng_description)
        assert_attr_equal(res[0][1], 'cn', self.ng_cn)

    def test_8_netgroup_mod(self):
        """
        Test the `xmlrpc.hostgroup_mod` method.
        """
        newdesc = u'Updated host group'
        modkw = {'cn': self.ng_cn, 'description': newdesc}
        (dn, res) = api.Command['netgroup_mod'](**modkw)
        assert res
        assert_attr_equal(res, 'description', newdesc)

        # Ok, double-check that it was changed
        (dn, res) = api.Command['netgroup_show'](self.ng_cn)
        assert res
        assert_attr_equal(res, 'description', newdesc)
        assert_attr_equal(res, 'cn', self.ng_cn)

    def test_9_netgroup_remove_member(self):
        """
        Test the `xmlrpc.hostgroup_remove_member` method.
        """
        kw = {}
        kw['hosts'] = self.host_fqdn
        (total, failed, res) = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert total == 1

        kw = {}
        kw['hostgroups'] = self.hg_cn
        (total, failed, res) = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert total == 1

        kw = {}
        kw['users'] = self.user_uid
        (total, failed, res) = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert total == 1

        kw = {}
        kw['groups'] = self.group_cn
        (total, failed, res) = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert total == 1

    def test_a_netgroup_remove_member(self):
        """
        Test the `xmlrpc.netgroup_remove_member` method again to test not found.
        """
        kw = {}
        kw['hosts'] = self.host_fqdn
        (total, failed, res) = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert total == 0
        assert self.host_fqdn in failed

        kw = {}
        kw['hostgroups'] = self.hg_cn
        (total, failed, res) = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert total == 0
        assert self.hg_cn in failed

        kw = {}
        kw['users'] = self.user_uid
        (dn, res) = api.Command['netgroup_show'](self.ng_cn, all=True)
        (total, failed, res) = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert total == 0
        assert self.user_uid in failed

        kw = {}
        kw['groups'] = self.group_cn
        (total, failed, res) = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert total == 0
        assert self.group_cn in failed

    def test_b_netgroup_del(self):
        """
        Test the `xmlrpc.netgroup_del` method.
        """
        res = api.Command['netgroup_del'](self.ng_cn)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['netgroup_show'](self.ng_cn)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_c_del_data(self):
        """
        Remove the test data we added.
        """
        # Remove the host
        res = api.Command['host_del'](self.host_fqdn)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['host_show'](self.host_fqdn)
        except errors.NotFound:
            pass
        else:
            assert False

        # Remove the hostgroup
        res = api.Command['hostgroup_del'](self.hg_cn)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['hostgroup_show'](self.hg_cn)
        except errors.NotFound:
            pass
        else:
            assert False

        # Remove the user
        res = api.Command['user_del'](self.user_uid)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['user_show'](self.user_uid)
        except errors.NotFound:
            pass
        else:
            assert False

        # Remove the group
        res = api.Command['group_del'](self.group_cn)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['group_show'](self.group_cn)
        except errors.NotFound:
            pass
        else:
            assert False

