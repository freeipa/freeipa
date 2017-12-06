# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipaserver/plugins/hbacrule.py` module.
"""
import pytest

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


@pytest.mark.tier1
class test_hbac(XMLRPC_test):
    """
    Test the `hbacrule` plugin.
    """
    rule_name = u'testing_rule1234'
    rule_renamed = u'mega_testing_rule'
    rule_type = u'allow'
    rule_type_fail = u'value not allowed'
    rule_service = u'ssh'
    rule_time = u'absolute 20081010000000 ~ 20081015120000'
    rule_time2 = u'absolute 20081010000000 ~ 20081016120000'
    # wrong time, has 30th day in February in first date
    rule_time_fail = u'absolute 20080230000000 ~ 20081015120000'
    rule_desc = u'description'
    rule_desc_mod = u'description modified'

    test_user = u'hbacrule_test_user'
    test_group = u'hbacrule_test_group'
    test_host = u'hbacrule.testnetgroup'
    test_hostgroup = u'hbacrule_test_hostgroup'
    test_service = u'sshd'
    test_host_external = u'notfound.example.com'

    test_invalid_sourcehost = u'inv+alid#srchost.nonexist.com'

    def test_0_hbacrule_add(self):
        """
        Test adding a new HBAC rule using `xmlrpc.hbacrule_add`.
        """
        ret = self.failsafe_add(api.Object.hbacrule,
            self.rule_name,
            accessruletype=self.rule_type,
            description=self.rule_desc,
        )
        entry = ret['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert_attr_equal(entry, 'accessruletype', self.rule_type)
        assert_attr_equal(entry, 'ipaenabledflag', 'TRUE')
        assert_attr_equal(entry, 'description', self.rule_desc)

    def test_1_hbacrule_add(self):
        """
        Test adding an existing HBAC rule using `xmlrpc.hbacrule_add'.
        """
        with pytest.raises(errors.DuplicateEntry):
            api.Command['hbacrule_add'](
                    self.rule_name, accessruletype=self.rule_type
                )

    def test_2_hbacrule_show(self):
        """
        Test displaying a HBAC rule using `xmlrpc.hbacrule_show`.
        """
        entry = api.Command['hbacrule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert_attr_equal(entry, 'ipaenabledflag', 'TRUE')
        assert_attr_equal(entry, 'description', self.rule_desc)

    def test_3_hbacrule_mod(self):
        """
        Test modifying a HBAC rule using `xmlrpc.hbacrule_mod`.
        """
        ret = api.Command['hbacrule_mod'](
            self.rule_name, description=self.rule_desc_mod
        )
        entry = ret['result']
        assert_attr_equal(entry, 'description', self.rule_desc_mod)

#    def test_4_hbacrule_add_accesstime(self):
#        """
#        Test adding access time to HBAC rule using `xmlrpc.hbacrule_add_accesstime`.
#        """
#        return
#        ret = api.Command['hbacrule_add_accesstime'](
#            self.rule_name, accesstime=self.rule_time2
#        )
#        entry = ret['result']
#        assert_attr_equal(entry, 'accesstime', self.rule_time);
#        assert_attr_equal(entry, 'accesstime', self.rule_time2);

#    def test_5_hbacrule_add_accesstime(self):
#        """
#        Test adding invalid access time to HBAC rule using `xmlrpc.hbacrule_add_accesstime`.
#        """
#        try:
#            api.Command['hbacrule_add_accesstime'](
#                self.rule_name, accesstime=self.rule_time_fail
#            )
#        except errors.ValidationError:
#            pass
#        else:
#            assert False

    def test_6_hbacrule_find(self):
        """
        Test searching for HBAC rules using `xmlrpc.hbacrule_find`.
        """
        ret = api.Command['hbacrule_find'](
            cn=self.rule_name, accessruletype=self.rule_type,
            description=self.rule_desc_mod
        )
        assert ret['truncated'] is False
        entries = ret['result']
        assert_attr_equal(entries[0], 'cn', self.rule_name)
        assert_attr_equal(entries[0], 'accessruletype', self.rule_type)
        assert_attr_equal(entries[0], 'description', self.rule_desc_mod)

    def test_7_hbacrule_init_testing_data(self):
        """
        Initialize data for more HBAC plugin testing.
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
        self.failsafe_add(api.Object.hbacsvc,
            self.test_service, description=u'desc',
        )

    def test_8_hbacrule_add_user(self):
        """
        Test adding user and group to HBAC rule using `xmlrpc.hbacrule_add_user`.
        """
        ret = api.Command['hbacrule_add_user'](
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
        Test showing a user to verify HBAC rule membership
        `xmlrpc.user_show`.
        """
        ret = api.Command['user_show'](self.test_user, all=True)
        entry = ret['result']
        assert_attr_equal(entry, 'memberof_hbacrule', self.rule_name)

    def test_9_b_show_group(self):
        """
        Test showing a group to verify HBAC rule membership
        `xmlrpc.group_show`.
        """
        ret = api.Command['group_show'](self.test_group, all=True)
        entry = ret['result']
        assert_attr_equal(entry, 'memberof_hbacrule', self.rule_name)

    def test_9_hbacrule_remove_user(self):
        """
        Test removing user and group from HBAC rule using `xmlrpc.hbacrule_remove_user'.
        """
        ret = api.Command['hbacrule_remove_user'](
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

    def test_a_hbacrule_add_host(self):
        """
        Test adding host and hostgroup to HBAC rule using `xmlrpc.hbacrule_add_host`.
        """
        ret = api.Command['hbacrule_add_host'](
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

    def test_a_hbacrule_show_host(self):
        """
        Test showing host to verify HBAC rule membership
        `xmlrpc.host_show`.
        """
        ret = api.Command['host_show'](self.test_host, all=True)
        entry = ret['result']
        assert_attr_equal(entry, 'memberof_hbacrule', self.rule_name)

    def test_a_hbacrule_show_hostgroup(self):
        """
        Test showing hostgroup to verify HBAC rule membership
        `xmlrpc.hostgroup_show`.
        """
        ret = api.Command['hostgroup_show'](self.test_hostgroup, all=True)
        entry = ret['result']
        assert_attr_equal(entry, 'memberof_hbacrule', self.rule_name)

    def test_b_hbacrule_remove_host(self):
        """
        Test removing host and hostgroup from HBAC rule using `xmlrpc.hbacrule_remove_host`.
        """
        ret = api.Command['hbacrule_remove_host'](
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

    def test_a_hbacrule_add_sourcehost_deprecated(self):
        """
        Test deprecated command hbacrule_add_sourcehost.
        """
        with pytest.raises(errors.DeprecationError):
            api.Command['hbacrule_add_sourcehost'](
                self.rule_name, host=self.test_host,
                hostgroup=self.test_hostgroup
            )

    def test_a_hbacrule_add_service(self):
        """
        Test adding service to HBAC rule using `xmlrpc.hbacrule_add_service`.
        """
        ret = api.Command['hbacrule_add_service'](
            self.rule_name, hbacsvc=self.test_service
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        assert 'memberservice' in failed
        assert 'hbacsvc' in failed['memberservice']
        assert not failed['memberservice']['hbacsvc']
        entry = ret['result']
        assert_attr_equal(entry, 'memberservice_hbacsvc', self.test_service)

    def test_a_hbacrule_remove_service(self):
        """
        Test removing service to HBAC rule using `xmlrpc.hbacrule_remove_service`.
        """
        ret = api.Command['hbacrule_remove_service'](
            self.rule_name, hbacsvc=self.test_service
        )
        assert ret['completed'] == 1
        failed = ret['failed']
        assert 'memberservice' in failed
        assert 'hbacsvc' in failed['memberservice']
        assert not failed['memberservice']['hbacsvc']
        entry = ret['result']
        assert 'memberservice service' not in entry

    def test_b_hbacrule_remove_sourcehost_deprecated(self):
        """
        Test deprecated command hbacrule_remove_sourcehost.
        """
        with pytest.raises(errors.DeprecationError):
            api.Command['hbacrule_remove_sourcehost'](
                self.rule_name, host=self.test_host,
                hostgroup=self.test_hostgroup
            )

    def test_c_hbacrule_mod_invalid_external_setattr(self):
        """
        Test adding the same external host using `xmlrpc.hbacrule_add_host`.
        """
        with pytest.raises(errors.ValidationError):
            api.Command['hbacrule_mod'](
                self.rule_name, setattr=self.test_invalid_sourcehost
            )

    def test_d_hbacrule_disable(self):
        """
        Test disabling HBAC rule using `xmlrpc.hbacrule_disable`.
        """
        assert api.Command['hbacrule_disable'](self.rule_name)['result'] is True
        entry = api.Command['hbacrule_show'](self.rule_name)['result']
        # FIXME: Should this be 'disabled' or 'FALSE'?
        assert_attr_equal(entry, 'ipaenabledflag', 'FALSE')

    def test_e_hbacrule_enabled(self):
        """
        Test enabling HBAC rule using `xmlrpc.hbacrule_enable`.
        """
        assert api.Command['hbacrule_enable'](self.rule_name)['result'] is True
        # check it's really enabled
        entry = api.Command['hbacrule_show'](self.rule_name)['result']
         # FIXME: Should this be 'enabled' or 'TRUE'?
        assert_attr_equal(entry, 'ipaenabledflag', 'TRUE')

    def test_ea_hbacrule_disable_setattr(self):
        """
        Test disabling HBAC rule using setattr
        """
        command_result = api.Command['hbacrule_mod'](
            self.rule_name, setattr=u'ipaenabledflag=false')
        assert command_result['result']['ipaenabledflag'] == (u'FALSE',)
        entry = api.Command['hbacrule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'ipaenabledflag', 'FALSE')

    def test_eb_hbacrule_enable_setattr(self):
        """
        Test enabling HBAC rule using setattr
        """
        command_result = api.Command['hbacrule_mod'](
            self.rule_name, setattr=u'ipaenabledflag=1')
        assert command_result['result']['ipaenabledflag'] == (u'TRUE',)
        # check it's really enabled
        entry = api.Command['hbacrule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'ipaenabledflag', 'TRUE')

    def test_f_hbacrule_exclusiveuser(self):
        """
        Test adding a user to an HBAC rule when usercat='all'
        """
        api.Command['hbacrule_mod'](self.rule_name, usercategory=u'all')
        try:
            with pytest.raises(errors.MutuallyExclusiveError):
                api.Command['hbacrule_add_user'](
                    self.rule_name, user=u'admin'
                )
        finally:
            api.Command['hbacrule_mod'](self.rule_name, usercategory=u'')

    def test_g_hbacrule_exclusiveuser(self):
        """
        Test setting usercat='all' in an HBAC rule when there are users
        """
        api.Command['hbacrule_add_user'](self.rule_name, user=u'admin')
        try:
            with pytest.raises(errors.MutuallyExclusiveError):
                api.Command['hbacrule_mod'](
                    self.rule_name, usercategory=u'all'
                )
        finally:
            api.Command['hbacrule_remove_user'](self.rule_name, user=u'admin')

    def test_h_hbacrule_exclusivehost(self):
        """
        Test adding a host to an HBAC rule when hostcat='all'
        """
        api.Command['hbacrule_mod'](self.rule_name, hostcategory=u'all')
        try:
            with pytest.raises(errors.MutuallyExclusiveError):
                api.Command['hbacrule_add_host'](
                    self.rule_name, host=self.test_host
                )
        finally:
            api.Command['hbacrule_mod'](self.rule_name, hostcategory=u'')

    def test_i_hbacrule_exclusivehost(self):
        """
        Test setting hostcat='all' in an HBAC rule when there are hosts
        """
        api.Command['hbacrule_add_host'](self.rule_name, host=self.test_host)
        try:
            with pytest.raises(errors.MutuallyExclusiveError):
                api.Command['hbacrule_mod'](
                    self.rule_name, hostcategory=u'all'
                )
        finally:
            api.Command['hbacrule_remove_host'](
                self.rule_name, host=self.test_host
            )

    def test_j_hbacrule_exclusiveservice(self):
        """
        Test adding a service to an HBAC rule when servicecat='all'
        """
        api.Command['hbacrule_mod'](self.rule_name, servicecategory=u'all')
        try:
            with pytest.raises(errors.MutuallyExclusiveError):
                api.Command['hbacrule_add_service'](
                    self.rule_name, hbacsvc=self.test_service
                )
        finally:
            api.Command['hbacrule_mod'](self.rule_name, servicecategory=u'')

    def test_k_hbacrule_exclusiveservice(self):
        """
        Test setting servicecat='all' in an HBAC rule when there are services
        """
        api.Command['hbacrule_add_service'](
            self.rule_name, hbacsvc=self.test_service
        )
        try:
            with pytest.raises(errors.MutuallyExclusiveError):
                api.Command['hbacrule_mod'](
                    self.rule_name, servicecategory=u'all'
                )
        finally:
            api.Command['hbacrule_remove_service'](
                self.rule_name, hbacsvc=self.test_service
            )

    def test_l_hbacrule_add(self):
        """
        Test adding a new HBAC rule with a deny type.
        """
        with pytest.raises(errors.ValidationError):
            api.Command['hbacrule_add'](
                u'denyrule',
                accessruletype=u'deny',
                description=self.rule_desc,
            )

    def test_m_hbacrule_add(self):
        """
        Test changing an HBAC rule to the deny type
        """
        with pytest.raises(errors.ValidationError):
            api.Command['hbacrule_mod'](
                self.rule_name,
                accessruletype=u'deny',
            )

    def test_n_hbacrule_links(self):
        """
        Test adding various links to HBAC rule
        """
        api.Command['hbacrule_add_service'](
            self.rule_name, hbacsvc=self.test_service
        )

        entry = api.Command['hbacrule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert_attr_equal(entry, 'memberservice_hbacsvc', self.test_service)

    def test_o_hbacrule_rename(self):
        """
        Test renaming an HBAC rule, rename it back afterwards
        """
        api.Command['hbacrule_mod'](
            self.rule_name, rename=self.rule_renamed
        )
        entry = api.Command['hbacrule_show'](self.rule_renamed)['result']
        assert_attr_equal(entry, 'cn', self.rule_renamed)
        # clean up by renaming the rule back
        api.Command['hbacrule_mod'](
            self.rule_renamed, rename=self.rule_name
        )

    def test_y_hbacrule_zap_testing_data(self):
        """
        Clear data for HBAC plugin testing.
        """
        api.Command['hbacrule_remove_host'](self.rule_name, host=self.test_host)
        api.Command['hbacrule_remove_host'](self.rule_name, hostgroup=self.test_hostgroup)
        api.Command['user_del'](self.test_user)
        api.Command['group_del'](self.test_group)
        api.Command['host_del'](self.test_host)
        api.Command['hostgroup_del'](self.test_hostgroup)
        api.Command['hbacsvc_del'](self.test_service)

    def test_k_2_sudorule_referential_integrity(self):
        """
        Test that links in HBAC rule were removed by referential integrity plugin
        """
        entry = api.Command['hbacrule_show'](self.rule_name)['result']
        assert_attr_equal(entry, 'cn', self.rule_name)
        assert 'sourcehost_host' not in entry
        assert 'sourcehost_hostgroup' not in entry
        assert 'memberservice_hbacsvc' not in entry

    def test_z_hbacrule_del(self):
        """
        Test deleting a HBAC rule using `xmlrpc.hbacrule_del`.
        """
        api.Command['hbacrule_del'](self.rule_name)
        # verify that it's gone
        with pytest.raises(errors.NotFound):
            api.Command['hbacrule_show'](self.rule_name)

    def test_zz_hbacrule_add_with_deprecated_option(self):
        """
        Test using a deprecated command option 'sourcehostcategory' with 'hbacrule_add'.
        """
        with pytest.raises(errors.ValidationError):
            api.Command['hbacrule_add'](
                self.rule_name, sourcehostcategory=u'all'
            )
