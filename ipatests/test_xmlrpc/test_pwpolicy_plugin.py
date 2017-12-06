# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Test the `ipaserver/plugins/pwpolicy.py` module.
"""

import pytest

from ipalib import api
from ipalib import errors
from ipapython.dn import DN
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (XMLRPC_test, assert_attr_equal,
                                              Declarative)


@pytest.mark.tier1
class test_pwpolicy(XMLRPC_test):
    """
    Test the `pwpolicy` plugin.
    """
    group = u'testgroup12'
    group2 = u'testgroup22'
    group3 = u'testgroup32'
    user = u'testuser12'
    kw = {'cospriority': 1, 'krbminpwdlife': 30, 'krbmaxpwdlife': 40, 'krbpwdhistorylength': 5, 'krbpwdminlength': 6 }
    kw2 = {'cospriority': 2, 'krbminpwdlife': 40, 'krbmaxpwdlife': 60, 'krbpwdhistorylength': 8, 'krbpwdminlength': 9 }
    kw3 = {'cospriority': 10, 'krbminpwdlife': 50, 'krbmaxpwdlife': 30, 'krbpwdhistorylength': 3, 'krbpwdminlength': 4 }
    global_policy = u'global_policy'

    def test_1_pwpolicy_add(self):
        """
        Test adding a per-group policy using the `xmlrpc.pwpolicy_add` method.
        """
        # First set up a group and user that will use this policy
        self.failsafe_add(
            api.Object.group, self.group, description=u'pwpolicy test group',
        )
        self.failsafe_add(
            api.Object.user, self.user, givenname=u'Test', sn=u'User'
        )
        api.Command.group_add_member(self.group, user=self.user)

        entry = api.Command['pwpolicy_add'](self.group, **self.kw)['result']
        assert_attr_equal(entry, 'krbminpwdlife', '30')
        assert_attr_equal(entry, 'krbmaxpwdlife', '40')
        assert_attr_equal(entry, 'krbpwdhistorylength', '5')
        assert_attr_equal(entry, 'krbpwdminlength', '6')
        assert_attr_equal(entry, 'cospriority', '1')

    def test_2_pwpolicy_add(self):
        """
        Add a policy with a already used priority.

        The priority validation is done first, so it's OK that the group
        is the same here.
        """
        try:
            api.Command['pwpolicy_add'](self.group, **self.kw)
        except errors.ValidationError:
            pass
        else:
            assert False

    def test_3_pwpolicy_add(self):
        """
        Add a policy that already exists.
        """
        try:
            # cospriority needs to be unique
            self.kw['cospriority'] = 3
            api.Command['pwpolicy_add'](self.group, **self.kw)
        except errors.DuplicateEntry:
            pass
        else:
            assert False

    def test_4_pwpolicy_add(self):
        """
        Test adding another per-group policy using the `xmlrpc.pwpolicy_add` method.
        """
        self.failsafe_add(
            api.Object.group, self.group2, description=u'pwpolicy test group 2'
        )
        entry = api.Command['pwpolicy_add'](self.group2, **self.kw2)['result']
        assert_attr_equal(entry, 'krbminpwdlife', '40')
        assert_attr_equal(entry, 'krbmaxpwdlife', '60')
        assert_attr_equal(entry, 'krbpwdhistorylength', '8')
        assert_attr_equal(entry, 'krbpwdminlength', '9')
        assert_attr_equal(entry, 'cospriority', '2')

    def test_5_pwpolicy_add(self):
        """
        Add a pwpolicy for a non-existent group
        """
        try:
            api.Command['pwpolicy_add'](u'nopwpolicy', cospriority=1, krbminpwdlife=1)
        except errors.NotFound:
            pass
        else:
            assert False

    def test_6_pwpolicy_show(self):
        """
        Test the `xmlrpc.pwpolicy_show` method with global policy.
        """
        entry = api.Command['pwpolicy_show']()['result']
        # Note that this assumes an unchanged global policy
        assert_attr_equal(entry, 'krbminpwdlife', '1')
        assert_attr_equal(entry, 'krbmaxpwdlife', '90')
        assert_attr_equal(entry, 'krbpwdhistorylength', '0')
        assert_attr_equal(entry, 'krbpwdminlength', '8')

    def test_7_pwpolicy_show(self):
        """
        Test the `xmlrpc.pwpolicy_show` method.
        """
        entry = api.Command['pwpolicy_show'](self.group)['result']
        assert_attr_equal(entry, 'krbminpwdlife', '30')
        assert_attr_equal(entry, 'krbmaxpwdlife', '40')
        assert_attr_equal(entry, 'krbpwdhistorylength', '5')
        assert_attr_equal(entry, 'krbpwdminlength', '6')
        assert_attr_equal(entry, 'cospriority', '1')

    def test_8_pwpolicy_mod(self):
        """
        Test the `xmlrpc.pwpolicy_mod` method for global policy.
        """
        entry = api.Command['pwpolicy_mod'](krbminpwdlife=50)['result']
        assert_attr_equal(entry, 'krbminpwdlife', '50')

        # Great, now change it back
        entry = api.Command['pwpolicy_mod'](krbminpwdlife=1)['result']
        assert_attr_equal(entry, 'krbminpwdlife', '1')

    def test_9_pwpolicy_mod(self):
        """
        Test the `xmlrpc.pwpolicy_mod` method.
        """
        entry = api.Command['pwpolicy_mod'](self.group, krbminpwdlife=50)['result']
        assert_attr_equal(entry, 'krbminpwdlife', '50')

    def test_a_pwpolicy_managed(self):
        """
        Test adding password policy to a managed group.
        """
        try:
            api.Command['pwpolicy_add'](
                self.user, krbminpwdlife=50, cospriority=2)
        except errors.ManagedPolicyError:
            pass
        else:
            assert False

    def test_b_pwpolicy_add(self):
        """
        Test adding a third per-group policy using the `xmlrpc.pwpolicy_add` method.
        """
        self.failsafe_add(
            api.Object.group, self.group3, description=u'pwpolicy test group 3'
        )
        entry = api.Command['pwpolicy_add'](self.group3, **self.kw3)['result']
        assert_attr_equal(entry, 'krbminpwdlife', '50')
        assert_attr_equal(entry, 'krbmaxpwdlife', '30')
        assert_attr_equal(entry, 'krbpwdhistorylength', '3')
        assert_attr_equal(entry, 'krbpwdminlength', '4')
        assert_attr_equal(entry, 'cospriority', '10')

    def test_c_pwpolicy_find(self):
        """Test that password policies are sorted and reported properly"""
        result = api.Command['pwpolicy_find']()['result']
        assert len(result) == 4

        # Test that policies are sorted in numerical order
        assert result[0]['cn'] == (self.group,)
        assert result[1]['cn'] == (self.group2,)
        assert result[2]['cn'] == (self.group3,)
        assert result[3]['cn'] == ('global_policy',)

        # Test that returned values match the arguments
        # Only test the second and third results; the first one was modified
        for entry, expected in (result[1], self.kw2), (result[2], self.kw3):
            for name, value in expected.items():
                assert_attr_equal(entry, name, str(value))

    def test_c_pwpolicy_find_pkey_only(self):
        """Test that password policies are sorted properly with --pkey-only"""
        result = api.Command['pwpolicy_find'](pkey_only=True)['result']
        assert len(result) == 4
        assert result[0]['cn'] == (self.group,)
        assert result[1]['cn'] == (self.group2,)
        assert result[2]['cn'] == (self.group3,)
        assert result[3]['cn'] == ('global_policy',)

    def test_d_pwpolicy_show(self):
        """Test that deleting a group removes its pwpolicy"""
        api.Command['group_del'](self.group3)
        with pytest.raises(errors.NotFound):
            api.Command['pwpolicy_show'](self.group3)

    def test_e_pwpolicy_del(self):
        """
        Test the `xmlrpc.pwpolicy_del` method.
        """
        api.Command['pwpolicy_del'](self.group)
        # Verify that it is gone
        try:
            api.Command['pwpolicy_show'](self.group)
        except errors.NotFound:
            pass
        else:
            assert False

        # Verify that global policy cannot be deleted
        try:
            api.Command['pwpolicy_del'](self.global_policy)
        except errors.ValidationError:
            pass
        else:
            assert False
        try:
            api.Command['pwpolicy_show'](self.global_policy)
        except errors.NotFound:
            assert False

        # Remove the groups we created
        api.Command['group_del'](self.group)
        api.Command['group_del'](self.group2)

        # Remove the user we created
        api.Command['user_del'](self.user)


@pytest.mark.tier1
class test_pwpolicy_mod_cospriority(Declarative):
    """Tests for cospriority modifications"""
    cleanup_commands = [
        ('pwpolicy_del', [u'ipausers'], {}),
    ]

    tests = [
        dict(
            desc='Create a password policy',
            command=('pwpolicy_add', [u'ipausers'], dict(
                krbmaxpwdlife=90,
                krbminpwdlife=1,
                krbpwdhistorylength=10,
                krbpwdmindiffchars=3,
                krbpwdminlength=8,
                cospriority=10,
            )),
            expected=dict(
                result=dict(
                    cn=[u'ipausers'],
                    cospriority=[u'10'],
                    dn=DN('cn=ipausers', ('cn', api.env.realm),
                          'cn=kerberos', api.env.basedn),
                    krbmaxpwdlife=[u'90'],
                    krbminpwdlife=[u'1'],
                    krbpwdhistorylength=[u'10'],
                    krbpwdmindiffchars=[u'3'],
                    krbpwdminlength=[u'8'],
                    objectclass=objectclasses.pwpolicy,
                ),
                summary=None,
                value=u'ipausers',
            ),
        ),

        dict(
            # https://fedorahosted.org/freeipa/ticket/4309
            desc="Try no-op modification of password policy's cospriority",
            command=('pwpolicy_mod', [u'ipausers'], dict(
                cospriority=10,
            )),
            expected=errors.EmptyModlist(),
        ),

        dict(
            desc="Modify the password policy's cospriority",
            command=('pwpolicy_mod', [u'ipausers'], dict(
                cospriority=20,
            )),
            expected=dict(
                result=dict(
                    cn=[u'ipausers'],
                    cospriority=[u'20'],
                    krbmaxpwdlife=[u'90'],
                    krbminpwdlife=[u'1'],
                    krbpwdhistorylength=[u'10'],
                    krbpwdmindiffchars=[u'3'],
                    krbpwdminlength=[u'8'],
                ),
                summary=None,
                value=u'ipausers',
            ),
        ),
    ]
