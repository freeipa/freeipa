# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#   Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2009-2011  Red Hat
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
Test the `ipaserver/plugins/hbactest.py` module.
"""

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors
import pytest

# Test strategy:
# 1. Create few allow rules: with user categories, with explicit users, with user groups, with groups, with services
# 2. Create users for test
# 3. Run detailed and non-detailed tests for explicitly specified rules, check expected result
#


@pytest.mark.tier1
class test_hbactest(XMLRPC_test):
    """
    Test the `hbactest` plugin.
    """
    rule_names = [u'testing_rule1234_%d' % (d) for d in [1,2,3,4]]
    rule_type = u'allow'
    rule_service = u'ssh'
    rule_descs = [u'description %d' % (d) for d in [1,2,3,4]]

    test_user = u'hbacrule_test_user'
    test_group = u'hbacrule_test_group'
    test_host = u'hbacrule.testhost'
    test_hostgroup = u'hbacrule_test_hostgroup'
    test_sourcehost = u'hbacrule.testsrchost'
    test_sourcehostgroup = u'hbacrule_test_src_hostgroup'
    test_service = u'ssh'

    # Auxiliary funcion for checking existence of warning for specified rule
    def check_rule_presence(self,rule_name,warnings):
        for warning in warnings:
            if rule_name in warning:
                return True
        return False

    def test_0_hbactest_addrules(self):
        """
        Prepare data by adding test HBAC rules using `xmlrpc.hbacrule_add'.
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
        self.failsafe_add(api.Object.host,
            self.test_sourcehost, force=True
        )
        self.failsafe_add(api.Object.hostgroup,
            self.test_sourcehostgroup, description=u'desc'
        )
        self.failsafe_add(api.Object.hbacsvc,
            self.test_service, description=u'desc'
        )

        for i in [0,1,2,3]:
            api.Command['hbacrule_add'](
                self.rule_names[i], accessruletype=self.rule_type, description=self.rule_descs[i],
            )

            api.Command['hbacrule_add_user'](
                self.rule_names[i], user=self.test_user, group=self.test_group
            )

            api.Command['hbacrule_add_host'](
                self.rule_names[i], host=self.test_host, hostgroup=self.test_hostgroup
            )

            api.Command['hbacrule_add_service'](
                self.rule_names[i], hbacsvc=self.test_service
            )

            if i & 1:
                api.Command['hbacrule_disable'](self.rule_names[i])

    def test_a_hbactest_check_rules_detail(self):
        """
        Test 'ipa hbactest --rules' (explicit IPA rules, detailed output)
        """
        ret = api.Command['hbactest'](
            user=self.test_user,
            targethost=self.test_host,
            service=self.test_service,
            rules=self.rule_names
        )
        assert ret['value'] == True
        assert ret['error'] is None
        for i in [0,1,2,3]:
            assert self.rule_names[i] in ret['matched']

    def test_b_hbactest_check_rules_nodetail(self):
        """
        Test 'ipa hbactest --rules --nodetail' (explicit IPA rules, no detailed output)
        """
        ret = api.Command['hbactest'](
            user=self.test_user,
            targethost=self.test_host,
            service=self.test_service,
            rules=self.rule_names,
            nodetail=True
        )
        assert ret['value'] == True
        assert ret['error'] is None
        assert ret['matched'] is None
        assert ret['notmatched'] is None

    def test_c_hbactest_check_rules_enabled_detail(self):
        """
        Test 'ipa hbactest --enabled' (all enabled IPA rules, detailed output)
        """
        ret = api.Command['hbactest'](
            user=self.test_user,
            targethost=self.test_host,
            service=self.test_service,
            enabled=True
        )
        # --enabled will try to work with _all_ enabled rules in IPA database
        # It means we could have matched something else (unlikely but possible)
        # Thus, check that our two enabled rules are in matched, nothing more
        for i in [0,2]:
            assert self.rule_names[i] in ret['matched']

    def test_d_hbactest_check_rules_disabled_detail(self):
        """
        Test 'ipa hbactest --disabled' (all disabled IPA rules, detailed output)
        """
        ret = api.Command['hbactest'](
            user=self.test_user,
            targethost=self.test_host,
            service=self.test_service,
            disabled=True
        )
        # --disabled will try to work with _all_ disabled rules in IPA database
        # It means we could have matched something else (unlikely but possible)
        # Thus, check that our two disabled rules are in matched, nothing more
        for i in [1,3]:
            assert self.rule_names[i] in ret['matched']

    def test_e_hbactest_check_non_existing_rule_detail(self):
        """
        Test running 'ipa hbactest' with non-existing rule in --rules
        """
        ret = api.Command['hbactest'](
            user=self.test_user,
            targethost=self.test_host,
            service=self.test_service,
            rules=[u'%s_1x1' % (rule) for rule in self.rule_names],
            nodetail=True
        )

        assert ret['value'] == False
        assert ret['matched'] is None
        assert ret['notmatched'] is None
        for rule in self.rule_names:
            assert u'%s_1x1' % (rule) in ret['error']

    def test_f_hbactest_check_sourcehost_option_is_deprecated(self):
        """
        Test running 'ipa hbactest' with --srchost option raises ValidationError
        """
        with pytest.raises(errors.ValidationError):
            api.Command['hbactest'](
                user=self.test_user,
                targethost=self.test_host,
                sourcehost=self.test_sourcehost,
                service=self.test_service,
                rules=[u'%s_1x1' % rule for rule in self.rule_names],
                nodetail=True
            )

    def test_g_hbactest_clear_testing_data(self):
        """
        Clear data for HBAC test plugin testing.
        """
        for i in [0,1,2,3]:
            api.Command['hbacrule_remove_host'](self.rule_names[i], host=self.test_host)
            api.Command['hbacrule_remove_host'](self.rule_names[i], hostgroup=self.test_hostgroup)
            api.Command['hbacrule_del'](self.rule_names[i])

        api.Command['user_del'](self.test_user)
        api.Command['group_del'](self.test_group)
        api.Command['host_del'](self.test_host)
        api.Command['hostgroup_del'](self.test_hostgroup)
        api.Command['host_del'](self.test_sourcehost)
        api.Command['hostgroup_del'](self.test_sourcehostgroup)
        api.Command['hbacsvc_del'](self.test_service)
