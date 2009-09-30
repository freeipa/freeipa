# Authors:
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
Test the `ipalib/plugins/hbac.py` module.
"""

from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_hbac(XMLRPC_test):
    """
    Test the `hbac` plugin.
    """
    rule_name = u'testing_rule1234'
    rule_type = u'allow'
    rule_type_fail = u'value not allowed'
    rule_service = u'ssh'
    rule_time = u'absolute 20081010000000 ~ 20081015120000'
    # wrong time, has 30th day in February in first date
    rule_time_fail = u'absolute 20080230000000 ~ 20081015120000'
    rule_desc = u'description'
    rule_desc_mod = u'description modified'

    test_user = u'hbac_test_user'
    test_group = u'hbac_test_group'
    test_host = u'hbac._test_netgroup'
    test_hostgroup = u'hbac_test_hostgroup'
    test_sourcehost = u'hbac._test_src_host'
    test_sourcehostgroup = u'hbac_test_src_hostgroup'

    def test_0_hbac_add(self):
        """
        Test adding a new HBAC rule using `xmlrpc.hbac_add`.
        """
        (dn, res) = api.Command['hbac_add'](
            self.rule_name, accessruletype=self.rule_type,
            servicename=self.rule_service, accesstime=self.rule_time,
            description=self.rule_desc
        )
        assert res
        assert_attr_equal(res, 'cn', self.rule_name)
        assert_attr_equal(res, 'accessruletype', self.rule_type)
        assert_attr_equal(res, 'servicename', self.rule_service)
        assert_attr_equal(res, 'ipaenabledflag', 'enabled')
        assert_attr_equal(res, 'accesstime', self.rule_time)
        assert_attr_equal(res, 'description', self.rule_desc)

    def test_1_hbac_add(self):
        """
        Test adding an existing HBAC rule using `xmlrpc.hbac_add'.
        """
        try:
            (dn, res) = api.Command['hbac_add'](
                self.rule_name, accessruletype=self.rule_type
            )
        except errors.DuplicateEntry:
            pass
        else:
            assert False

    def test_2_hbac_show(self):
        """
        Test displaying a HBAC rule using `xmlrpc.hbac_show`.
        """
        (dn, res) = api.Command['hbac_show'](self.rule_name)
        assert res
        assert_attr_equal(res, 'cn', self.rule_name)
        assert_attr_equal(res, 'accessruletype', self.rule_type)
        assert_attr_equal(res, 'servicename', self.rule_service)
        assert_attr_equal(res, 'ipaenabledflag', 'enabled')
        assert_attr_equal(res, 'accesstime', self.rule_time)
        assert_attr_equal(res, 'description', self.rule_desc)

    def test_3_hbac_mod(self):
        """
        Test modifying a HBAC rule using `xmlrpc.hbac_mod`.
        """
        (dn, res) = api.Command['hbac_mod'](
            self.rule_name, description=self.rule_desc_mod
        )
        assert res
        assert_attr_equal(res, 'description', self.rule_desc_mod)

    def test_4_hbac_mod(self):
        """
        Test setting invalid type of HBAC rule using `xmlrpc.hbac_mod`.
        """
        try:
            (dn, res) = api.Command['hbac_mod'](
                self.rule_name, accessruletype=self.rule_type_fail
            )
        except errors.ValidationError:
            pass
        else:
            assert False

    def test_5_hbac_mod(self):
        """
        Test setting invalid time in HBAC rule using `xmlrpc.hbac_mod`.
        """
        try:
            (dn, res) = api.Command['hbac_mod'](
                self.rule_name, accesstime=self.rule_time_fail
            )
        except errors.ValidationError:
            pass
        else:
            assert False

    def test_6_hbac_find(self):
        """
        Test searching for HBAC rules using `xmlrpc.hbac_find`.
        """
        (res, truncated) = api.Command['hbac_find'](
            name=self.rule_name, accessruletype=self.rule_type,
            description=self.rule_desc_mod
        )
        assert res
        assert res[0]
        assert_attr_equal(res[0][1], 'cn', self.rule_name)
        assert_attr_equal(res[0][1], 'accessruletype', self.rule_type)
        assert_attr_equal(res[0][1], 'description', self.rule_desc_mod)

    def test_7_hbac_init_testing_data(self):
        """
        Initialize data for more HBAC plugin testing.
        """
        api.Command['user_add'](self.test_user, givenname=u'first', sn=u'last')
        api.Command['group_add'](self.test_group, description=u'description')
        api.Command['host_add'](self.test_host)
        api.Command['hostgroup_add'](
            self.test_hostgroup, description=u'description'
        )
        api.Command['host_add'](self.test_sourcehost)
        api.Command['hostgroup_add'](
            self.test_sourcehostgroup, description=u'desc'
        )

    def test_8_hbac_add_user(self):
        """
        Test adding user and group to HBAC rule using `xmlrpc.hbac_add_user`.
        """
        (completed, failed, res) = api.Command['hbac_add_user'](
            self.rule_name, user=self.test_user, group=self.test_group
        )
        assert completed == 2
        assert 'memberuser' in failed
        assert 'user' in failed['memberuser']
        assert not failed['memberuser']['user']
        assert 'group' in failed['memberuser']
        assert not failed['memberuser']['group']
        assert res
        assert_attr_equal(res[1], 'memberuser user', self.test_user)
        assert_attr_equal(res[1], 'memberuser group', self.test_group)

    def test_9_hbac_remove_user(self):
        """
        Test removing user and group from HBAC rule using `xmlrpc.hbac_remove_user'.
        """
        (completed, failed, res) = api.Command['hbac_remove_user'](
            self.rule_name, user=self.test_user, group=self.test_group
        )
        assert completed == 2
        assert 'memberuser' in failed
        assert 'user' in failed['memberuser']
        assert not failed['memberuser']['user']
        assert 'group' in failed['memberuser']
        assert not failed['memberuser']['group']
        assert res
        assert 'memberuser user' not in res[1]
        assert 'memberuser group' not in res[1]

    def test_a_hbac_add_host(self):
        """
        Test adding host and hostgroup to HBAC rule using `xmlrpc.hbac_add_host`.
        """
        (completed, failed, res) = api.Command['hbac_add_host'](
            self.rule_name, host=self.test_host, hostgroup=self.test_hostgroup
        )
        assert completed == 2
        assert 'memberhost' in failed
        assert 'host' in failed['memberhost']
        assert not failed['memberhost']['host']
        assert 'hostgroup' in failed['memberhost']
        assert not failed['memberhost']['hostgroup']
        assert res
        assert_attr_equal(res[1], 'memberhost host', self.test_host)
        assert_attr_equal(res[1], 'memberhost hostgroup', self.test_hostgroup)

    def test_b_hbac_remove_host(self):
        """
        Test removing host and hostgroup from HBAC rule using `xmlrpc.hbac_remove_host`.
        """
        (completed, failed, res) = api.Command['hbac_remove_host'](
            self.rule_name, host=self.test_host, hostgroup=self.test_hostgroup
        )
        assert completed == 2
        assert 'memberhost' in failed
        assert 'host' in failed['memberhost']
        assert not failed['memberhost']['host']
        assert 'hostgroup' in failed['memberhost']
        assert not failed['memberhost']['hostgroup']
        assert res
        assert 'memberhost host' not in res[1]
        assert 'memberhost hostgroup' not in res[1]

    def test_a_hbac_add_sourcehost(self):
        """
        Test adding source host and hostgroup to HBAC rule using `xmlrpc.hbac_add_host`.
        """
        (completed, failed, res) = api.Command['hbac_add_sourcehost'](
            self.rule_name, host=self.test_host, hostgroup=self.test_hostgroup
        )
        assert completed == 2
        assert 'sourcehost' in failed
        assert 'host' in failed['sourcehost']
        assert not failed['sourcehost']['host']
        assert 'hostgroup' in failed['sourcehost']
        assert not failed['sourcehost']['hostgroup']
        assert res
        assert_attr_equal(res[1], 'sourcehost host', self.test_host)
        assert_attr_equal(res[1], 'sourcehost hostgroup', self.test_hostgroup)

    def test_b_hbac_remove_host(self):
        """
        Test removing source host and hostgroup from HBAC rule using `xmlrpc.hbac_remove_host`.
        """
        (completed, failed, res) = api.Command['hbac_remove_sourcehost'](
            self.rule_name, host=self.test_host, hostgroup=self.test_hostgroup
        )
        assert completed == 2
        assert 'sourcehost' in failed
        assert 'host' in failed['sourcehost']
        assert not failed['sourcehost']['host']
        assert 'hostgroup' in failed['sourcehost']
        assert not failed['sourcehost']['hostgroup']
        assert res
        assert 'sourcehost host' not in res[1]
        assert 'sourcehost hostgroup' not in res[1]

    def test_c_hbac_clear_testing_data(self):
        """
        Clear data for HBAC plugin testing.
        """
        api.Command['user_del'](self.test_user)
        api.Command['group_del'](self.test_group)
        api.Command['host_del'](self.test_host)
        api.Command['hostgroup_del'](self.test_hostgroup)
        api.Command['host_del'](self.test_sourcehost)
        api.Command['hostgroup_del'](self.test_sourcehostgroup)

    def test_d_hbac_disable(self):
        """
        Test disabling HBAC rule using `xmlrpc.hbac_disable`.
        """
        res = api.Command['hbac_disable'](self.rule_name)
        assert res == True
        # check it's really disabled
        (dn, res) = api.Command['hbac_show'](self.rule_name)
        assert res
        assert_attr_equal(res, 'ipaenabledflag', 'disabled')

    def test_e_hbac_enabled(self):
        """
        Test enabling HBAC rule using `xmlrpc.hbac_enable`.
        """
        res = api.Command['hbac_enable'](self.rule_name)
        assert res == True
        # check it's really enabled
        (dn, res) = api.Command['hbac_show'](self.rule_name)
        assert res
        assert_attr_equal(res, 'ipaenabledflag', 'enabled')

    def test_f_hbac_del(self):
        """
        Test deleting a HBAC rule using `xmlrpc.hbac_remove_sourcehost`.
        """
        res = api.Command['hbac_del'](self.rule_name)
        assert res == True
        # verify that it's gone
        try:
            api.Command['hbac_show'](self.rule_name)
        except errors.NotFound:
            pass
        else:
            assert False

