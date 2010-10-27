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
import nose
import krbV
from xmlrpc_test import XMLRPC_test, assert_attr_equal, assert_is_member
from ipalib import api
from ipalib import errors
from ipaserver.plugins.ldap2 import ldap2

# Global so we can save the value between tests
netgroup_dn = None

# See if our LDAP server is up and we can talk to it over GSSAPI
ccache = krbV.default_context().default_ccache().name

def entry_in_failed(entry, failed):
    """
    entry is what we're looking for
    failed is a tuple of tuples of the form (failure, exception)
    """
    for f in failed:
        if entry == f[0]:
            return True
    return False

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
    host_kw = {'fqdn': host_fqdn, 'description': host_description, 'localityname': host_localityname, 'raw': True, 'force': True}

    hg_cn = u'hg1'
    hg_description = u'Netgroup'
    hg_kw = {'cn': hg_cn, 'description': hg_description, 'raw': True}

    user_uid = u'jexample'
    user_givenname = u'Jim'
    user_sn = u'Example'
    user_home = u'/home/%s' % user_uid
    user_kw = {'givenname': user_givenname,'sn': user_sn,'uid': user_uid,'homedirectory': user_home, 'raw': True}

    # user2 is a member of testgroup
    user2_uid = u'pexample'
    user2_givenname = u'Pete'
    user2_sn = u'Example'
    user2_home = u'/home/%s' % user2_uid
    user2_kw = {'givenname': user2_givenname,'sn': user2_sn,'uid': user2_uid,'homedirectory': user2_home, 'raw': True}

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

        # Add our second user
        entry = api.Command['user_add'](**self.user2_kw)['result']
        assert_attr_equal(entry, 'givenname', self.user2_givenname)
        assert_attr_equal(entry, 'uid', self.user2_uid)

        # Add a group
        entry = api.Command['group_add'](**self.group_kw)['result']
        assert_attr_equal(entry, 'description', self.group_description)
        assert_attr_equal(entry, 'cn', self.group_cn)

        # Add a user to the group
        kw = {'raw': True}
        kw['user'] = self.user2_uid
        res = api.Command['group_add_member'](self.group_cn, **kw)
        assert res['completed'] == 1

    def test_3_netgroup_add_member(self):
        """
        Test the `xmlrpc.netgroup_add_member` method.
        """
        kw = {'raw': True}
        kw['host'] = self.host_fqdn
        entry = api.Command['netgroup_add_member'](self.ng_cn, **kw)['result']
        assert_is_member(entry, 'fqdn=%s' % self.host_fqdn, 'memberhost')

        kw = {'raw': True}
        kw['hostgroup'] = self.hg_cn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1
        assert_is_member(ret['result'], 'cn=%s' % self.hg_cn, 'memberhost')

        kw = {'raw': True}
        kw['user'] = self.user_uid
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1
        assert_is_member(ret['result'], 'uid=%s' % self.user_uid, 'memberuser')

        kw = {'raw': True}
        kw['group'] = self.group_cn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 1
        assert_is_member(ret['result'], 'cn=%s' % self.group_cn, 'memberuser')

    def test_4_netgroup_add_member(self):
        """
        Test the `xmlrpc.netgroup_add_member` method again to test dupes.
        """
        kw = {'raw': True}
        kw['host'] = self.host_fqdn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'memberhost' in failed
        assert 'host' in failed['memberhost']
        assert entry_in_failed(self.host_fqdn, failed['memberhost']['host'])

        kw = {'raw': True}
        kw['hostgroup'] = self.hg_cn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'memberhost' in failed
        assert 'hostgroup' in failed['memberhost']
        assert entry_in_failed(self.hg_cn, failed['memberhost']['hostgroup'])

        kw = {'raw': True}
        kw['user'] = self.user_uid
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'memberuser' in failed
        assert 'user' in failed['memberuser']
        assert entry_in_failed(self.user_uid, failed['memberuser']['user'])

        kw = {'raw': True}
        kw['group'] = self.group_cn
        ret = api.Command['netgroup_add_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'memberuser' in failed
        assert 'group' in failed['memberuser']
        assert entry_in_failed(self.group_cn, failed['memberuser']['group'])

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
        Test the `xmlrpc.netgroup_show` method with --all.
        """
        entry = api.Command['netgroup_show'](self.ng_cn, all=True, raw=True)['result']
        assert_attr_equal(entry, 'description', self.ng_description)
        assert_attr_equal(entry, 'cn', self.ng_cn)
        assert_is_member(entry, 'fqdn=%s' % self.host_fqdn, 'memberhost')
        assert_is_member(entry, 'cn=%s' % self.hg_cn, 'memberhost')
        assert_is_member(entry, 'uid=%s' % self.user_uid, 'memberuser')
        assert_is_member(entry, 'cn=%s' % self.group_cn, 'memberuser')
        assert_attr_equal(entry, 'objectclass', 'ipaobject')
        assert_attr_equal(entry, 'objectclass', 'ipanisnetgroup')
        assert_attr_equal(entry, 'objectclass', 'ipaassociation')

    def test_6a_netgroup_show(self):
        """
        Test the `xmlrpc.netgroup_show` method.
        """
        global netgroup_dn
        entry = api.Command['netgroup_show'](self.ng_cn, all=False, raw=True)['result']
        assert_attr_equal(entry, 'description', self.ng_description)
        assert_attr_equal(entry, 'cn', self.ng_cn)
        assert_is_member(entry, 'fqdn=%s' % self.host_fqdn, 'memberhost')
        assert_is_member(entry, 'cn=%s' % self.hg_cn, 'memberhost')
        assert_is_member(entry, 'uid=%s' % self.user_uid, 'memberuser')
        assert_is_member(entry, 'cn=%s' % self.group_cn, 'memberuser')
        netgroup_dn = entry['dn']

    def test_6b_netgroup_show(self):
        """
        Confirm the underlying triples
        """
        # Do an LDAP query to the compat area and verify that the entry
        # is correct
        conn = ldap2(shared_instance=False, ldap_uri=api.env.ldap_uri, base_dn=api.env.basedn)
        conn.connect(ccache=ccache)
        try:
            entries = conn.find_entries('cn=%s' % self.ng_cn,
                      base_dn='cn=ng,cn=compat,%s' % api.env.basedn)
        except errors.NotFound:
            raise nose.SkipTest('compat and nis are not enabled, skipping test')
        finally:
            conn.disconnect()
        triples = entries[0][0][1]['nisnetgrouptriple']

        # This may not prove to be reliable since order is not guaranteed
        # and even which user gets into which triple can be random.
        assert '(nosuchhost,jexample,example.com)' in triples
        assert '(ipatesthost.%s,pexample,example.com)' % api.env.domain in triples

    def test_7_netgroup_find(self):
        """
        Test the `xmlrpc.netgroup_find` method.
        """
        result = api.Command.netgroup_find(self.ng_cn, raw=True)
        entries = result['result']

        assert(result['count'] == 1)
        assert_attr_equal(entries[0], 'description', self.ng_description)
        assert_attr_equal(entries[0], 'cn', self.ng_cn)

    def test_8_netgroup_mod(self):
        """
        Test the `xmlrpc.netgroup_mod` method.
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
        Test the `xmlrpc.netgroup_remove_member` method.
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
        assert 'memberhost' in failed
        assert 'host' in failed['memberhost']
        assert entry_in_failed(self.host_fqdn, failed['memberhost']['host'])

        kw = {'raw': True}
        kw['hostgroup'] = self.hg_cn
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'memberhost' in failed
        assert 'hostgroup' in failed['memberhost']
        assert entry_in_failed(self.hg_cn, failed['memberhost']['hostgroup'])

        kw = {'raw': True}
        kw['user'] = self.user_uid
        api.Command['netgroup_show'](self.ng_cn, all=True)
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'memberuser' in failed
        assert 'user' in failed['memberuser']
        assert entry_in_failed(self.user_uid, failed['memberuser']['user'])

        kw = {'raw': True}
        kw['group'] = self.group_cn
        ret = api.Command['netgroup_remove_member'](self.ng_cn, **kw)
        assert ret['completed'] == 0
        failed = ret['failed']
        assert 'memberuser' in failed
        assert 'group' in failed['memberuser']
        assert entry_in_failed(self.group_cn, failed['memberuser']['group'])

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

        # Remove the users
        assert api.Command['user_del'](self.user_uid)['result'] is True
        assert api.Command['user_del'](self.user2_uid)['result'] is True

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
