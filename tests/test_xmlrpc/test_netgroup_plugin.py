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
    ng_kw = {'cn': ng_cn, 'description': ng_description, 'nisdomainname': u'example.com', 'raw': True}

    host_fqdn = u'ipatesthost.%s' % api.env.domain
    host_description = u'Test host'
    host_localityname = u'Undisclosed location'
    host_kw = {'fqdn': host_fqdn, 'description': host_description, 'localityname': host_localityname, 'raw': True}

    hg_cn = u'ng1'
    hg_description = u'Netgroup'
    hg_kw = {'cn': hg_cn, 'description': hg_description, 'raw': True}

    user_uid = u'jexample'
    user_givenname = u'Jim'
    user_sn = u'Example'
    user_home = u'/home/%s' % user_uid
    user_kw = {'givenname': user_givenname,'sn': user_sn,'uid': user_uid,'homedirectory': user_home, 'raw': True}

    group_cn = u'testgroup'
    group_description = u'This is a test'
    group_kw = {'description': group_description,'cn': group_cn}

    def test_1_netgroup_add(self):
        """
        Test the `xmlrpc.netgroup_add` method.
        """
        entry = api.Command['netgroup_add'](**self.ng_kw)['result']
        assert_attr_equal(entry, 'description', self.ng_description)
        assert_attr_equal(entry, 'cn', self.ng_cn)

    def test_2_add_data(self):
        """
        Add the data needed to do additional testing.
        """
        # Add a host
        entry = api.Command['host_add'](**self.host_kw)['result']
        assert_attr_equal(entry, 'description', self.host_description)
        assert_attr_equal(entry, 'fqdn', self.host_fqdn)

        # Add a hostgroup
        entry= api.Command['hostgroup_add'](**self.hg_kw)['result']
        assert_attr_equal(entry, 'description', self.hg_description)
        assert_attr_equal(entry, 'cn', self.hg_cn)

        # Add a user
        entry = api.Command['user_add'](**self.user_kw)['result']
        assert_attr_equal(entry, 'givenname', self.user_givenname)
        assert_attr_equal(entry, 'uid', self.user_uid)

        # Add a group
        entry = api.Command['group_add'](**self.group_kw)['result']
        assert_attr_equal(entry, 'description', self.group_description)
        assert_attr_equal(entry, 'cn', self.group_cn)

    def test_3_netgroup_add_member(self):
        """
        Test the `xmlrpc.netgroup_add_member` method.
        """
        kw = {'raw': True}
        kw['host'] = self.host_fqdn
        entry = api.Command['netgroup_add_member'](self.ng_cn, **kw)['result']
        assert_is_member(entry, 'fqdn=%s' % self.host_fqdn)

        kw = {'raw': True}
        kw['hostgroup'] = self.hg_cn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1
        assert_is_member(ret['result'], 'cn=%s' % self.hg_cn)

        kw = {'raw': True}
        kw['user'] = self.user_uid
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1
        assert_is_member(ret['result'], 'uid=%s' % self.user_uid)

        kw = {'raw': True}
        kw['group'] = self.group_cn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1
        assert_is_member(ret['result'], 'cn=%s' % self.group_cn)

    def test_4_netgroup_add_member(self):
        """
        Test the `xmlrpc.netgroup_add_member` method again to test dupes.
        """
        kw = {'raw': True}
        kw['host'] = self.host_fqdn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'member' in failed
        assert 'host' in failed['member']
        assert self.host_fqdn in failed['member']['host']

        kw = {'raw': True}
        kw['hostgroup'] = self.hg_cn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'member' in failed
        assert 'hostgroup' in failed['member']
        assert self.hg_cn in failed['member']['hostgroup']

        kw = {'raw': True}
        kw['user'] = self.user_uid
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'member' in failed
        assert 'user' in failed['member']
        assert self.user_uid in failed['member']['user']

        kw = {'raw': True}
        kw['group'] = self.group_cn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'member' in failed
        assert 'group' in failed['member']
        assert self.group_cn in failed['member']['group']

    def test_5_netgroup_add_member(self):
        """
        Test adding external hosts.
        """
        kw = {'raw': True}
        kw['host'] = u'nosuchhost'
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1, ret
        entry = api.Command['netgroup_show'](self.ng_cn, all=True, raw=True)['result']
        assert_is_member(entry, 'nosuchhost', 'externalhost')

    def test_6_netgroup_show(self):
        """
        Test the `xmlrpc.netgroup_show` method.
        """
        entry = api.Command['netgroup_show'](self.ng_cn, all=True, raw=True)['result']
        assert_attr_equal(entry, 'description', self.ng_description)
        assert_attr_equal(entry, 'cn', self.ng_cn)
        assert_is_member(entry, 'fqdn=%s' % self.host_fqdn)
        assert_is_member(entry, 'cn=%s' % self.hg_cn)
        assert_is_member(entry, 'uid=%s' % self.user_uid)
        assert_is_member(entry, 'cn=%s' % self.group_cn)
        assert_attr_equal(entry, 'objectclass', 'ipaobject')

    def test_7_netgroup_find(self):
        """
        Test the `xmlrpc.hostgroup_find` method.
        """
        entries = api.Command.netgroup_find(self.ng_cn, raw=True)['result']
        assert_attr_equal(entries[0], 'description', self.ng_description)
        assert_attr_equal(entries[0], 'cn', self.ng_cn)

    def test_8_netgroup_mod(self):
        """
        Test the `xmlrpc.hostgroup_mod` method.
        """
        newdesc = u'Updated host group'
        modkw = {'cn': self.ng_cn, 'description': newdesc, 'raw': True}
        entry = api.Command['netgroup_mod'](**modkw)['result']
        assert_attr_equal(entry, 'description', newdesc)

        # Ok, double-check that it was changed
        entry = api.Command['netgroup_show'](self.ng_cn, raw=True)['result']
        assert_attr_equal(entry, 'description', newdesc)
        assert_attr_equal(entry, 'cn', self.ng_cn)

    def test_9_netgroup_remove_member(self):
        """
        Test the `xmlrpc.hostgroup_remove_member` method.
        """
        kw = {'raw': True}
        kw['host'] = self.host_fqdn
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1

        kw = {'raw': True}
        kw['hostgroup'] = self.hg_cn
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1

        kw = {'raw': True}
        kw['user'] = self.user_uid
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1

        kw = {'raw': True}
        kw['group'] = self.group_cn
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1

    def test_a_netgroup_remove_member(self):
        """
        Test the `xmlrpc.netgroup_remove_member` method again to test not found.
        """
        kw = {'raw': True}
        kw['host'] = self.host_fqdn
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'member' in failed
        assert 'host' in failed['member']
        assert self.host_fqdn in failed['member']['host']

        kw = {'raw': True}
        kw['hostgroup'] = self.hg_cn
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'member' in failed
        assert 'hostgroup' in failed['member']
        assert self.hg_cn in failed['member']['hostgroup']

        kw = {'raw': True}
        kw['user'] = self.user_uid
        api.Command['netgroup_show'](self.ng_cn, all=True)
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'member' in failed
        assert 'user' in failed['member']
        assert self.user_uid in failed['member']['user']

        kw = {'raw': True}
        kw['group'] = self.group_cn
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'member' in failed
        assert 'group' in failed['member']
        assert self.group_cn in failed['member']['group']

    def test_b_netgroup_del(self):
        """
        Test the `xmlrpc.netgroup_del` method.
        """
        assert api.Command['netgroup_del'](self.ng_cn)['result'] is True

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
        assert api.Command['host_del'](self.host_fqdn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['host_show'](self.host_fqdn)
        except errors.NotFound:
            pass
        else:
            assert False

        # Remove the hostgroup
        assert api.Command['hostgroup_del'](self.hg_cn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['hostgroup_show'](self.hg_cn)
        except errors.NotFound:
            pass
        else:
            assert False

        # Remove the user
        assert api.Command['user_del'](self.user_uid)['result'] is True

        # Verify that it is gone
        try:
            api.Command['user_show'](self.user_uid)
        except errors.NotFound:
            pass
        else:
            assert False

        # Remove the group
        assert api.Command['group_del'](self.group_cn)['result'] is True

        # Verify that it is gone
        try:
            api.Command['group_show'](self.group_cn)
        except errors.NotFound:
            pass
        else:
            assert False
