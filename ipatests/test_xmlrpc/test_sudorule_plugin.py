# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2010  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Test the `ipaserver/plugins/sudorule.py` module.
"""

from nose.tools import raises, assert_raises  # pylint: disable=E0611
import six

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors
import pytest

# pylint: disable=unused-variable

if six.PY3:
    unicode = str


@pytest.mark.tier1
class test_sudorule(XMLRPC_test):
    """
    Test the `sudorule` plugin.
    """
    rule_name = u'testing_sudorule1'
    rule_name2 = u'testing_sudorule2'
    rule_renamed = u'testing_mega_sudorule'
    rule_command = u'/usr/bin/testsudocmd1'
    rule_desc = u'description'
    rule_desc_mod = u'description modified'

    test_user = u'sudorule_test_user'
    test_external_user = u'external_test_user'
    test_group = u'sudorule_test_group'
    test_external_group = u'external_test_group'
    test_host = u'sudorule.testhost'
    test_external_host = u'external.testhost'
    test_hostgroup = u'sudorule_test_hostgroup'
    test_sudoallowcmdgroup = u'sudorule_test_allowcmdgroup'
    test_sudodenycmdgroup = u'sudorule_test_denycmdgroup'
    test_command = u'/usr/bin/testsudocmd1'
    test_denycommand = u'/usr/bin/testdenysudocmd1'
    test_runasuser = u'manager'
    test_runasgroup = u'manager'
    test_category = u'all'
    test_option = u'authenticate'

    test_invalid_user = u'+invalid#user'
    test_invalid_host = u'+invalid&host.nonexist.com'
    test_invalid_group = u'+invalid#group'

    def test_0_sudorule_add(self):
        """
        Test adding a new Sudo rule using `xmlrpc.sudorule_add`.
        """
        ret = self.failsafe_add(api.Object.sudorule,
            self.rule_name,
            description=self.rule_desc,
        )
        entry = ret['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert_attr_equal(entry, 'description', self.rule_desc)

    @raises(errors.DuplicateEntry)
    def test_1_sudorule_add(self):
        """
        Test adding an duplicate Sudo rule using `xmlrpc.sudorule_add'.
        """
        api.Command['sudorule_add'](
            self.rule_name
        )

    def test_2_sudorule_show(self):
        """
        Test displaying a Sudo rule using `xmlrpc.sudorule_show`.
        """
        entry = api.Command['sudorule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
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
            cn=self.rule_name,
            description=self.rule_desc_mod
        )
        assert ret['truncated'] is False
        entries = ret['result']
        assert_attr_equal(entries[0], 'cn', self.rule_name)
        assert_attr_equal(entries[0], 'description', self.rule_desc_mod)

    def test_7_sudorule_init_testing_data(self):
        """
        Initialize data for more Sudo rule plugin testing.
        """
        self.failsafe_add(api.Object.user,
            self.test_user, givenname=u'first', sn=u'last'
        )
        self.failsafe_add(api.Object.user,
            self.test_runasuser, givenname=u'first', sn=u'last'
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
            self.test_sudoallowcmdgroup, description=u'desc'
        )
        self.failsafe_add(api.Object.sudocmdgroup,
            self.test_sudodenycmdgroup, description=u'desc'
        )
        self.failsafe_add(api.Object.sudocmd,
            self.test_command, description=u'desc'
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

    def test_9_a_show_user(self):
        """
        Test showing a user to verify Sudo rule membership
        `xmlrpc.user_show`.
        """
        ret = api.Command['user_show'](self.test_user, all=True)
        entry = ret['result']
        assert_attr_equal(entry, 'memberof_sudorule', self.rule_name)

    def test_9_b_show_group(self):
        """
        Test showing a group to verify Sudo rule membership
        `xmlrpc.group_show`.
        """
        ret = api.Command['group_show'](self.test_group, all=True)
        entry = ret['result']
        assert_attr_equal(entry, 'memberof_sudorule', self.rule_name)

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

    def test_a_sudorule_add_runasuser(self):
        """
        Test adding run as user to Sudo rule using
        `xmlrpc.sudorule_add_runasuser`.
        """
        ret = api.Command['sudorule_add_runasuser'](
            self.rule_name, user=self.test_runasuser
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        assert 'ipasudorunas' in failed
        assert 'user' in failed['ipasudorunas']
        assert not failed['ipasudorunas']['user']
        entry = ret['result']
        assert_attr_equal(entry, 'ipasudorunas_user', self.test_runasuser)

    def test_a_sudorule_add_runasuser_invalid(self):
        """
        Test adding run as invalid user to Sudo rule using
        `xmlrpc.sudorule_add_runasuser`.
        """
        try:
            api.Command['sudorule_add_runasuser'](
                self.rule_name, user=self.test_invalid_user
            )
        except errors.ValidationError:
            pass
        else:
            assert False

    def test_b_sudorule_remove_runasuser(self):
        """
        Test removing run as user to Sudo rule using
        `xmlrpc.sudorule_remove_runasuser'.
        """
        ret = api.Command['sudorule_remove_runasuser'](
            self.rule_name, user=self.test_runasuser
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        assert 'ipasudorunas' in failed
        assert 'user' in failed['ipasudorunas']
        assert not failed['ipasudorunas']['user']
        entry = ret['result']
        assert 'ipasudorunas_user' not in entry

    def test_a_sudorule_add_runasgroup(self):
        """
        Test adding run as group to Sudo rule using
        `xmlrpc.sudorule_add_runasgroup`.
        """
        ret = api.Command['sudorule_add_runasgroup'](
            self.rule_name, group=self.test_runasgroup
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        assert 'ipasudorunasgroup' in failed
        assert 'group' in failed['ipasudorunasgroup']
        assert not failed['ipasudorunasgroup']['group']
        entry = ret['result']
        assert_attr_equal(entry, 'ipasudorunasgroup_group',
            self.test_runasgroup)

    def test_a_sudorule_add_runasgroup_invalid(self):
        """
        Test adding run as invalid user to Sudo rule using
        `xmlrpc.sudorule_add_runasuser`.
        """
        try:
            api.Command['sudorule_add_runasgroup'](
                self.rule_name, group=self.test_invalid_group
            )
        except errors.ValidationError:
            pass
        else:
            assert False

    def test_b_sudorule_remove_runasgroup(self):
        """
        Test removing run as group to Sudo rule using
        `xmlrpc.sudorule_remove_runasgroup'.
        """
        ret = api.Command['sudorule_remove_runasgroup'](
            self.rule_name, group=self.test_runasgroup
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        assert 'ipasudorunasgroup' in failed
        assert 'group' in failed['ipasudorunasgroup']
        assert not failed['ipasudorunasgroup']['group']
        entry = ret['result']
        assert 'ipasudorunasgroup_group' not in entry

    def test_a_sudorule_add_externaluser(self):
        """
        Test adding an external user to Sudo rule using
        `xmlrpc.sudorule_add_user`.
        """
        ret = api.Command['sudorule_add_user'](
            self.rule_name, user=self.test_external_user
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        entry = ret['result']
        assert_attr_equal(entry, 'externaluser', self.test_external_user)

    def test_a_sudorule_add_externaluser_invalid(self):
        """
        Test adding an invalid external user to Sudo rule using
        `xmlrpc.sudorule_add_user`.
        """
        try:
            api.Command['sudorule_add_user'](
                self.rule_name, user=self.test_invalid_user
            )
        except errors.ValidationError:
            pass
        else:
            assert False

    def test_b_sudorule_remove_externaluser(self):
        """
        Test removing an external user from Sudo rule using
        `xmlrpc.sudorule_remove_user'.
        """
        ret = api.Command['sudorule_remove_user'](
            self.rule_name, user=self.test_external_user
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        entry = ret['result']
        assert entry['externaluser'] == ()

    def test_a_sudorule_add_runasexternaluser(self):
        """
        Test adding an external runasuser to Sudo rule using
        `xmlrpc.sudorule_add_runasuser`.
        """
        ret = api.Command['sudorule_add_runasuser'](
            self.rule_name, user=self.test_external_user
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        entry = ret['result']
        assert_attr_equal(entry, 'ipasudorunasextuser', self.test_external_user)

    def test_b_sudorule_remove_runasexternaluser(self):
        """
        Test removing an external runasuser from Sudo rule using
        `xmlrpc.sudorule_remove_runasuser'.
        """
        ret = api.Command['sudorule_remove_runasuser'](
            self.rule_name, user=self.test_external_user
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        entry = ret['result']
        assert entry['ipasudorunasextuser'] == ()

    def test_a_sudorule_add_runasexternalgroup(self):
        """
        Test adding an external runasgroup to Sudo rule using
        `xmlrpc.sudorule_add_runasgroup`.
        """
        ret = api.Command['sudorule_add_runasgroup'](
            self.rule_name, group=self.test_external_group
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        entry = ret['result']
        assert_attr_equal(entry, 'ipasudorunasextgroup', self.test_external_group)

    def test_b_sudorule_remove_runasexternalgroup(self):
        """
        Test removing an external runasgroup from Sudo rule using
        `xmlrpc.sudorule_remove_runasgroup'.
        """
        ret = api.Command['sudorule_remove_runasgroup'](
            self.rule_name, group=self.test_external_group
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        entry = ret['result']
        assert entry['ipasudorunasextgroup'] == ()

    def test_a_sudorule_add_option(self):
        """
        Test adding an option to Sudo rule using
        `xmlrpc.sudorule_add_option`.
        """
        # Add a user and group to the sudorule so we can test that
        # membership is properly translated in add_option.
        ret = api.Command['sudorule_add_user'](
            self.rule_name, user=self.test_user, group=self.test_group
        )
        assert ret['completed'] == 2
        ret = api.Command['sudorule_add_option'](
            self.rule_name, ipasudoopt=self.test_option
        )
        entry = ret['result']
        assert_attr_equal(entry, 'ipasudoopt', self.test_option)
        assert_attr_equal(entry, 'memberuser_user', self.test_user)
        assert_attr_equal(entry, 'memberuser_group', self.test_group)

    def test_b_sudorule_remove_option(self):
        """
        Test removing an option from Sudo rule using
        `xmlrpc.sudorule_remove_option'.
        """
        ret = api.Command['sudorule_remove_option'](
            self.rule_name, ipasudoopt=self.test_option
        )
        entry = ret['result']
        assert 'ipasudoopt' not in entry
        # Verify that membership is properly converted in remove_option
        assert_attr_equal(entry, 'memberuser_user', self.test_user)
        assert_attr_equal(entry, 'memberuser_group', self.test_group)
        # Clean up by removing the user and group added in add_option
        ret = api.Command['sudorule_remove_user'](
            self.rule_name, user=self.test_user, group=self.test_group
        )
        assert ret['completed'] == 2

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

    def test_a_sudorule_show_host(self):
        """
        Test showing host to verify Sudo rule membership
        `xmlrpc.host_show`.
        """
        ret = api.Command['host_show'](self.test_host, all=True)
        entry = ret['result']
        assert_attr_equal(entry, 'memberof_sudorule', self.rule_name)

    def test_a_sudorule_show_hostgroup(self):
        """
        Test showing hostgroup to verify Sudo rule membership
        `xmlrpc.hostgroup_show`.
        """
        ret = api.Command['hostgroup_show'](self.test_hostgroup, all=True)
        entry = ret['result']
        assert_attr_equal(entry, 'memberof_sudorule', self.rule_name)

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

    def test_a_sudorule_add_externalhost(self):
        """
        Test adding an external host to Sudo rule using
        `xmlrpc.sudorule_add_host`.
        """
        ret = api.Command['sudorule_add_host'](
            self.rule_name, host=self.test_external_host
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        entry = ret['result']
        assert_attr_equal(entry, 'externalhost', self.test_external_host)

    def test_a_sudorule_add_externalhost_invalid(self):
        """
        Test adding an invalid external host to Sudo rule using
        `xmlrpc.sudorule_add_host`.
        """
        try:
            api.Command['sudorule_add_host'](
                self.rule_name, host=self.test_invalid_host
            )
        except errors.ValidationError:
            pass
        else:
            assert False

    def test_a_sudorule_mod_externalhost_invalid_addattr(self):
        """
        Test adding an invalid external host to Sudo rule using
        `xmlrpc.sudorule_mod --addattr`.
        """
        try:
            api.Command['sudorule_mod'](
                self.rule_name,
                addattr='externalhost=%s' % self.test_invalid_host
            )
        except errors.ValidationError as e:
            assert unicode(e) == ("invalid 'externalhost': only letters, " +
                "numbers, '_', '-' are allowed. " +
                "DNS label may not start or end with '-'")
        else:
            assert False

    def test_b_sudorule_remove_externalhost(self):
        """
        Test removing an external host from Sudo rule using
        `xmlrpc.sudorule_remove_host`.
        """
        ret = api.Command['sudorule_remove_host'](
            self.rule_name, host=self.test_external_host
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        entry = ret['result']
        assert len(entry['externalhost']) == 0

    def test_a_sudorule_add_allow_command(self):
        """
        Test adding allow command and cmdgroup to Sudo rule using
        `xmlrpc.sudorule_add_allow_command`.
        """
        ret = api.Command['sudorule_add_allow_command'](
            self.rule_name, sudocmd=self.test_command,
            sudocmdgroup=self.test_sudoallowcmdgroup
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'memberallowcmd' in failed
        assert 'sudocmd' in failed['memberallowcmd']
        assert not failed['memberallowcmd']['sudocmd']
        assert 'sudocmdgroup' in failed['memberallowcmd']
        assert not failed['memberallowcmd']['sudocmdgroup']
        entry = ret['result']
        assert_attr_equal(entry, 'memberallowcmd_sudocmd', self.test_command)
        assert_attr_equal(entry, 'memberallowcmd_sudocmdgroup',
            self.test_sudoallowcmdgroup)

    def test_a_sudorule_remove_allow_command(self):
        """
        Test removing allow command and sudocmdgroup from Sudo rule using
        `xmlrpc.sudorule_remove_command`.
        """
        ret = api.Command['sudorule_remove_allow_command'](
            self.rule_name, sudocmd=self.test_command,
            sudocmdgroup=self.test_sudoallowcmdgroup
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'memberallowcmd' in failed
        assert 'sudocmd' in failed['memberallowcmd']
        assert not failed['memberallowcmd']['sudocmd']
        assert 'sudocmdgroup' in failed['memberallowcmd']
        assert not failed['memberallowcmd']['sudocmdgroup']
        entry = ret['result']
        assert 'memberallowcmd_sudocmd' not in entry
        assert 'memberallowcmd_sudocmdgroup' not in entry

    def test_b_sudorule_add_deny_command(self):
        """
        Test adding deny command and cmdgroup to Sudo rule using
        `xmlrpc.sudorule_add_deny_command`.
        """
        ret = api.Command['sudorule_add_deny_command'](
            self.rule_name, sudocmd=self.test_command,
            sudocmdgroup=self.test_sudodenycmdgroup
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'memberdenycmd' in failed
        assert 'sudocmd' in failed['memberdenycmd']
        assert not failed['memberdenycmd']['sudocmd']
        assert 'sudocmdgroup' in failed['memberdenycmd']
        assert not failed['memberdenycmd']['sudocmdgroup']
        entry = ret['result']
        assert_attr_equal(entry, 'memberdenycmd_sudocmd', self.test_command)
        assert_attr_equal(entry, 'memberdenycmd_sudocmdgroup',
            self.test_sudodenycmdgroup)

    def test_b_sudorule_remove_deny_command(self):
        """
        Test removing deny command and sudocmdgroup from Sudo rule using
        `xmlrpc.sudorule_remove_deny_command`.
        """
        ret = api.Command['sudorule_remove_deny_command'](
            self.rule_name, sudocmd=self.test_command,
            sudocmdgroup=self.test_sudodenycmdgroup
        )
        assert ret['completed'] == 2
        failed = ret['failed']
        assert 'memberdenycmd' in failed
        assert 'sudocmd' in failed['memberdenycmd']
        assert not failed['memberdenycmd']['sudocmd']
        assert 'sudocmdgroup' in failed['memberdenycmd']
        assert not failed['memberdenycmd']['sudocmdgroup']
        entry = ret['result']
        assert 'memberdenycmd_sudocmd' not in entry
        assert 'memberdenycmd_sudocmdgroup' not in entry

    @raises(errors.MutuallyExclusiveError)
    def test_c_sudorule_exclusiveuser(self):
        """
        Test adding a user to an Sudo rule when usercat='all'
        """
        api.Command['sudorule_mod'](self.rule_name, usercategory=u'all')
        try:
            api.Command['sudorule_add_user'](self.rule_name, user=u'admin')
        finally:
            api.Command['sudorule_mod'](self.rule_name, usercategory=u'')

    @raises(errors.MutuallyExclusiveError)
    def test_d_sudorule_exclusiveuser(self):
        """
        Test setting usercat='all' in an Sudo rule when there are users
        """
        api.Command['sudorule_add_user'](self.rule_name, user=u'admin')
        try:
            api.Command['sudorule_mod'](self.rule_name, usercategory=u'all')
        finally:
            api.Command['sudorule_remove_user'](self.rule_name, user=u'admin')

    @raises(errors.MutuallyExclusiveError)
    def test_e_sudorule_exclusivehost(self):
        """
        Test adding a host to an Sudo rule when hostcat='all'
        """
        api.Command['sudorule_mod'](self.rule_name, hostcategory=u'all')
        try:
            api.Command['sudorule_add_host'](self.rule_name, host=self.test_host)
        finally:
            api.Command['sudorule_mod'](self.rule_name, hostcategory=u'')

    @raises(errors.MutuallyExclusiveError)
    def test_f_sudorule_exclusivehost(self):
        """
        Test setting hostcat='all' in an Sudo rule when there are hosts
        """
        api.Command['sudorule_add_host'](self.rule_name, host=self.test_host)
        try:
            api.Command['sudorule_mod'](self.rule_name, hostcategory=u'all')
        finally:
            api.Command['sudorule_remove_host'](self.rule_name, host=self.test_host)

    @raises(errors.MutuallyExclusiveError)
    def test_g_sudorule_exclusivecommand(self):
        """
        Test adding a command to an Sudo rule when cmdcategory='all'
        """
        api.Command['sudorule_mod'](self.rule_name, cmdcategory=u'all')
        try:
            api.Command['sudorule_add_allow_command'](self.rule_name, sudocmd=self.test_command)
        finally:
            api.Command['sudorule_mod'](self.rule_name, cmdcategory=u'')

    @raises(errors.MutuallyExclusiveError)
    def test_h_sudorule_exclusivecommand(self):
        """
        Test setting cmdcategory='all' in an Sudo rule when there are commands
        """
        api.Command['sudorule_add_allow_command'](self.rule_name, sudocmd=self.test_command)
        try:
            api.Command['sudorule_mod'](self.rule_name, cmdcategory=u'all')
        finally:
            api.Command['sudorule_remove_allow_command'](self.rule_name, sudocmd=self.test_command)

    @raises(errors.MutuallyExclusiveError)
    def test_i_sudorule_exclusiverunas(self):
        """
        Test adding a runasuser to an Sudo rule when ipasudorunasusercategory='all'
        """
        api.Command['sudorule_mod'](self.rule_name, ipasudorunasusercategory=u'all')
        try:
            api.Command['sudorule_add_runasuser'](self.rule_name, user=self.test_user)
        finally:
            api.Command['sudorule_mod'](self.rule_name, ipasudorunasusercategory=u'')

    @raises(errors.MutuallyExclusiveError)
    def test_j_1_sudorule_exclusiverunas(self):
        """
        Test setting ipasudorunasusercategory='all' in an Sudo rule when there are runas users
        """
        api.Command['sudorule_add_runasuser'](self.rule_name, user=self.test_user)
        try:
            api.Command['sudorule_mod'](self.rule_name, ipasudorunasusercategory=u'all')
        finally:
            api.Command['sudorule_remove_runasuser'](self.rule_name, user=self.test_command)

    def test_j_2_sudorule_referential_integrity(self):
        """
        Test adding various links to Sudo rule
        """
        api.Command['sudorule_add_user'](self.rule_name, user=self.test_user)
        api.Command['sudorule_add_runasuser'](self.rule_name, user=self.test_runasuser,
                                              group=self.test_group)
        api.Command['sudorule_add_runasgroup'](self.rule_name, group=self.test_group)
        api.Command['sudorule_add_host'](self.rule_name, host=self.test_host)
        api.Command['sudorule_add_allow_command'](self.rule_name,
                                                  sudocmd=self.test_command)
        api.Command['sudorule_add_deny_command'](self.rule_name,
                                                 sudocmdgroup=self.test_sudodenycmdgroup)
        entry = api.Command['sudorule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert_attr_equal(entry, 'memberuser_user', self.test_user)
        assert_attr_equal(entry, 'memberallowcmd_sudocmd', self.test_command)
        assert_attr_equal(entry, 'memberdenycmd_sudocmdgroup',
            self.test_sudodenycmdgroup)
        assert_attr_equal(entry, 'memberhost_host', self.test_host)
        assert_attr_equal(entry, 'ipasudorunas_user', self.test_runasuser)
        assert_attr_equal(entry, 'ipasudorunas_group', self.test_group)
        assert_attr_equal(entry, 'ipasudorunasgroup_group', self.test_group)


    def test_k_1_sudorule_clear_testing_data(self):
        """
        Clear data for Sudo rule plugin testing.
        """
        api.Command['user_del'](self.test_user)
        api.Command['user_del'](self.test_runasuser)
        api.Command['group_del'](self.test_group)
        api.Command['host_del'](self.test_host)
        api.Command['hostgroup_del'](self.test_hostgroup)
        api.Command['sudorule_remove_allow_command'](self.rule_name,
                                                     sudocmd=self.test_command)
        api.Command['sudocmd_del'](self.test_command)
        api.Command['sudocmdgroup_del'](self.test_sudoallowcmdgroup)
        api.Command['sudocmdgroup_del'](self.test_sudodenycmdgroup)

    def test_k_2_sudorule_referential_integrity(self):
        """
        Test that links in Sudo rule were removed by referential integrity plugin
        """
        entry = api.Command['sudorule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert 'memberuser_user' not in entry
        assert 'memberallowcmd_sudocmd' not in entry
        assert 'memberdenycmd_sudocmdgroup' not in entry
        assert 'memberhost_host' not in entry
        assert 'ipasudorunas_user' not in entry
        assert 'ipasudorunas_group' not in entry
        assert 'ipasudorunasgroup_group' not in entry

    def test_l_sudorule_order(self):
        """
        Test that order uniqueness is maintained
        """
        api.Command['sudorule_mod'](self.rule_name, sudoorder=1)

        api.Command['sudorule_add'](self.rule_name2)

        # mod of rule that has no order and set a duplicate
        try:
            api.Command['sudorule_mod'](self.rule_name2, sudoorder=1)
        except errors.ValidationError:
            pass

        # Remove the rule so we can re-add it
        api.Command['sudorule_del'](self.rule_name2)

        # add a new rule with a duplicate order
        with assert_raises(errors.ValidationError):
            api.Command['sudorule_add'](self.rule_name2, sudoorder=1)

        # add a new rule with a unique order
        api.Command['sudorule_add'](self.rule_name2, sudoorder=2)
        with assert_raises(errors.ValidationError):
            api.Command['sudorule_mod'](self.rule_name2, sudoorder=1)

        # Try setting both to 0
        api.Command['sudorule_mod'](self.rule_name2, sudoorder=0)
        with assert_raises(errors.ValidationError):
            api.Command['sudorule_mod'](self.rule_name, sudoorder=0)

        # Try unsetting sudoorder from both rules
        api.Command['sudorule_mod'](self.rule_name, sudoorder=None)
        api.Command['sudorule_mod'](self.rule_name2, sudoorder=None)

    def test_l_1_sudorule_rename(self):
        """
        Test renaming an HBAC rule, rename it back afterwards
        """
        api.Command['sudorule_mod'](
            self.rule_name, rename=self.rule_renamed
        )
        entry = api.Command['sudorule_show'](self.rule_renamed)['result']
        assert_attr_equal(entry, 'cn', self.rule_renamed)
        # clean up by renaming the rule back
        api.Command['sudorule_mod'](
            self.rule_renamed, rename=self.rule_name
        )

    def test_m_sudorule_del(self):
        """
        Test deleting a Sudo rule using `xmlrpc.sudorule_del`.
        """
        api.Command['sudorule_del'](self.rule_name)
        # verify that it's gone
        with assert_raises(errors.NotFound):
            api.Command['sudorule_show'](self.rule_name)
        api.Command['sudorule_del'](self.rule_name2)
