# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Test the `ipalib/plugins/sudorule.py` module.
"""

from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_sudorule(XMLRPC_test):
    """
    Test the `sudorule` plugin.
    """
    rule_name = u'testing_sudorule1'
    rule_type = u'allow'
    rule_type_fail = u'value not allowed'
    rule_command = u'/usr/bin/testsudocmd1'
    rule_desc = u'description'
    rule_desc_mod = u'description modified'

    test_user = u'sudorule_test_user'
    test_group = u'sudorule_test_group'
    test_host = u'sudorule._test_host'
    test_hostgroup = u'sudorule_test_hostgroup'
    test_sudocmdgroup = u'sudorule_test_cmdgroup'
    test_command = u'/usr/bin/testsudocmd1'

    def test_0_sudorule_add(self):
        """
        Test adding a new Sudo rule using `xmlrpc.sudorule_add`.
        """
        ret = self.failsafe_add(api.Object.sudorule,
            self.rule_name,
            accessruletype=self.rule_type,
            description=self.rule_desc,
        )
        entry = ret['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert_attr_equal(entry, 'accessruletype', self.rule_type)
        assert_attr_equal(entry, 'description', self.rule_desc)

    def test_1_sudorule_add(self):
        """
        Test adding an duplicate Sudo rule using `xmlrpc.sudorule_add'.
        """
        try:
            api.Command['sudorule_add'](
                self.rule_name, accessruletype=self.rule_type
            )
        except errors.DuplicateEntry:
            pass
        else:
            assert False

    def test_2_sudorule_show(self):
        """
        Test displaying a Sudo rule using `xmlrpc.sudorule_show`.
        """
        entry = api.Command['sudorule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert_attr_equal(entry, 'accessruletype', self.rule_type)
        assert_attr_equal(entry, 'description', self.rule_desc)

    def test_3_sudorule_mod(self):
        """
        Test modifying a Sudo rule using `xmlrpc.sudorule_mod`.
        """
        ret = api.Command['sudorule_mod'](
            self.rule_name, description=self.rule_desc_mod
        )
        entry = ret['result']
        assert_attr_equal(entry, 'description', self.rule_desc_mod)

    def test_6_sudorule_find(self):
        """
        Test searching for Sudo rules using `xmlrpc.sudorule_find`.
        """
        ret = api.Command['sudorule_find'](
            name=self.rule_name, accessruletype=self.rule_type,
            description=self.rule_desc_mod
        )
        assert ret['truncated'] is False
        entries = ret['result']
        assert_attr_equal(entries[0], 'cn', self.rule_name)
        assert_attr_equal(entries[0], 'accessruletype', self.rule_type)
        assert_attr_equal(entries[0], 'description', self.rule_desc_mod)

    def test_7_sudorule_init_testing_data(self):
        """
        Initialize data for more Sudo rule plugin testing.
        """
        self.failsafe_add(api.Object.user,
            self.test_user, givenname=u'first', sn=u'last'
        )
        self.failsafe_add(api.Object.group,
            self.test_group, description=u'description'
        )
        self.failsafe_add(api.Object.host,
            self.test_host, force=True
        )
        self.failsafe_add(api.Object.hostgroup,
            self.test_hostgroup, description=u'description'
        )
        self.failsafe_add(api.Object.sudocmdgroup,
            self.test_sudocmdgroup, description=u'desc'
        )
        self.failsafe_add(api.Object.sudocmd,
            self.test_command, description=u'desc', force=True
        )

    def test_8_sudorule_add_user(self):
        """
        Test adding user and group to Sudo rule using
        `xmlrpc.sudorule_add_user`.
        """
        ret = api.Command['sudorule_add_user'](
            self.rule_name, user=self.test_user, group=self.test_group
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'memberuser' in failed
        assert 'user' in failed['memberuser']
        assert not failed['memberuser']['user']
        assert 'group' in failed['memberuser']
        assert not failed['memberuser']['group']
        entry = ret['result']
        assert_attr_equal(entry, 'memberuser_user', self.test_user)
        assert_attr_equal(entry, 'memberuser_group', self.test_group)

    def test_9_sudorule_remove_user(self):
        """
        Test removing user and group from Sudo rule using
        `xmlrpc.sudorule_remove_user'.
        """
        ret = api.Command['sudorule_remove_user'](
            self.rule_name, user=self.test_user, group=self.test_group
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'memberuser' in failed
        assert 'user' in failed['memberuser']
        assert not failed['memberuser']['user']
        assert 'group' in failed['memberuser']
        assert not failed['memberuser']['group']
        entry = ret['result']
        assert 'memberuser_user' not in entry
        assert 'memberuser_group' not in entry

    def test_a_sudorule_add_host(self):
        """
        Test adding host and hostgroup to Sudo rule using
        `xmlrpc.sudorule_add_host`.
        """
        ret = api.Command['sudorule_add_host'](
            self.rule_name, host=self.test_host, hostgroup=self.test_hostgroup
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'memberhost' in failed
        assert 'host' in failed['memberhost']
        assert not failed['memberhost']['host']
        assert 'hostgroup' in failed['memberhost']
        assert not failed['memberhost']['hostgroup']
        entry = ret['result']
        assert_attr_equal(entry, 'memberhost_host', self.test_host)
        assert_attr_equal(entry, 'memberhost_hostgroup', self.test_hostgroup)

    def test_b_sudorule_remove_host(self):
        """
        Test removing host and hostgroup from Sudo rule using
        `xmlrpc.sudorule_remove_host`.
        """
        ret = api.Command['sudorule_remove_host'](
            self.rule_name, host=self.test_host, hostgroup=self.test_hostgroup
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'memberhost' in failed
        assert 'host' in failed['memberhost']
        assert not failed['memberhost']['host']
        assert 'hostgroup' in failed['memberhost']
        assert not failed['memberhost']['hostgroup']
        entry = ret['result']
        assert 'memberhost_host' not in entry
        assert 'memberhost_hostgroup' not in entry

    def test_a_sudorule_add_command(self):
        """
        Test adding command and cmdgroup to Sudo rule using
        `xmlrpc.sudorule_add_command`.
        """
        ret = api.Command['sudorule_add_command'](
            self.rule_name, sudocmd=self.test_command,
            sudocmdgroup=self.test_sudocmdgroup
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'membercmd' in failed
        assert 'sudocmd' in failed['membercmd']
        assert not failed['membercmd']['sudocmd']
        assert 'sudocmdgroup' in failed['membercmd']
        assert not failed['membercmd']['sudocmdgroup']
        entry = ret['result']
        assert_attr_equal(entry, 'membercmd_sudocmd', self.test_command)
        assert_attr_equal(entry, 'membercmd_sudocmdgroup',
            self.test_sudocmdgroup)

    def test_a_sudorule_remove_command(self):
        """
        Test removing command and sudocmdgroup from Sudo rule using
        `xmlrpc.sudorule_remove_command`.
        """
        ret = api.Command['sudorule_remove_command'](
            self.rule_name, sudocmd=self.test_command,
            sudocmdgroup=self.test_sudocmdgroup
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'membercmd' in failed
        assert 'sudocmd' in failed['membercmd']
        assert not failed['membercmd']['sudocmd']
        assert 'sudocmdgroup' in failed['membercmd']
        assert not failed['membercmd']['sudocmdgroup']
        entry = ret['result']
        assert 'membercmd_sudocmd' not in entry
        assert 'membercmd_sudocmdgroup' not in entry

    def test_c_sudorule_clear_testing_data(self):
        """
        Clear data for Sudo rule plugin testing.
        """
        api.Command['user_del'](self.test_user)
        api.Command['group_del'](self.test_group)
        api.Command['host_del'](self.test_host)
        api.Command['hostgroup_del'](self.test_hostgroup)
        api.Command['sudocmd_del'](self.test_command)
        api.Command['sudocmdgroup_del'](self.test_sudocmdgroup)

    def test_f_sudorule_del(self):
        """
        Test deleting a Sudo rule using `xmlrpc.sudorule_del`.
        """
        assert api.Command['sudorule_del'](self.rule_name)['result'] is True
        # verify that it's gone
        try:
            api.Command['sudorule_show'](self.rule_name)
        except errors.NotFound:
            pass
        else:
            assert False
