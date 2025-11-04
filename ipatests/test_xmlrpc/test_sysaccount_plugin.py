# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information

"""
Test the `ipaserver/plugins/sysaccounts.py` module.
"""

from __future__ import print_function

import pytest

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.util import change_principal, unlock_principal_password
from ipatests.test_xmlrpc.xmlrpc_test import assert_attr_equal
from ipatests.test_xmlrpc.tracker.sysaccount_plugin import SysaccountTracker

NORMAL_USER = u'test-normal-user'
NORMAL_USER_PASSWORD = u'Secret123'
SECURITY_ARCHITECT_USER = u'test-security-architect'
SECURITY_ARCHITECT_PASSWORD = u'Secret123'
SECURITY_ARCHITECT_ROLE = u'Security Architect'

TEST_SYSACCOUNT_1 = u'test-sysaccount-1'
TEST_SYSACCOUNT_2 = u'test-sysaccount-2'
TEST_SYSACCOUNT_3 = u'test-sysaccount-3'


@pytest.fixture(scope='class')
def sysaccount_1(request, xmlrpc_setup):
    """Fixture for TEST_SYSACCOUNT_1"""
    tracker = SysaccountTracker(name=TEST_SYSACCOUNT_1)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def sysaccount_2(request, xmlrpc_setup):
    """Fixture for TEST_SYSACCOUNT_2"""
    tracker = SysaccountTracker(name=TEST_SYSACCOUNT_2)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def sysaccount_3(request, xmlrpc_setup):
    """Fixture for TEST_SYSACCOUNT_3"""
    tracker = SysaccountTracker(name=TEST_SYSACCOUNT_3)
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestSysaccountPermissions(XMLRPC_test):
    """
    Test system account permissions with different user roles.
    """

    def test_setup(self):
        api.Command.user_add(
            NORMAL_USER,
            givenname=u'Normal',
            sn=u'User',
            userpassword=NORMAL_USER_PASSWORD
        )
        unlock_principal_password(NORMAL_USER, NORMAL_USER_PASSWORD,
                                  NORMAL_USER_PASSWORD)

        # Create Security Architect user
        api.Command.user_add(
            SECURITY_ARCHITECT_USER,
            givenname=u'Security',
            sn=u'Architect',
            userpassword=SECURITY_ARCHITECT_PASSWORD
        )
        unlock_principal_password(SECURITY_ARCHITECT_USER,
                                  SECURITY_ARCHITECT_PASSWORD,
                                  SECURITY_ARCHITECT_PASSWORD)

        # Add Security Architect user to Security Architect role
        api.Command.role_add_member(SECURITY_ARCHITECT_ROLE,
                                    user=SECURITY_ARCHITECT_USER)

    def test_normal_user_cannot_add_sysaccount(self):
        """Test that a normal user cannot add a system account"""
        with change_principal(NORMAL_USER, NORMAL_USER_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command.sysaccount_add(TEST_SYSACCOUNT_1, random=True)

    def test_normal_user_cannot_modify_sysaccount(self, sysaccount_1):
        """Test that a normal user cannot modify a system account"""
        # Create the sysaccount as admin
        sysaccount_1.create()

        with change_principal(NORMAL_USER, NORMAL_USER_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command.sysaccount_mod(
                    TEST_SYSACCOUNT_1,
                    description=u'Modified description'
                )

    def test_normal_user_cannot_delete_sysaccount(self, sysaccount_1):
        """Test that a normal user cannot delete a system account"""
        # Create the sysaccount as admin
        sysaccount_1.create()

        with change_principal(NORMAL_USER, NORMAL_USER_PASSWORD):
            with pytest.raises(errors.ACIError):
                api.Command.sysaccount_del(TEST_SYSACCOUNT_1)

    def test_security_architect_can_add_sysaccount(self):
        """Test that a Security Architect user can add a system account"""
        with change_principal(SECURITY_ARCHITECT_USER,
                              SECURITY_ARCHITECT_PASSWORD):
            result = api.Command.sysaccount_add(
                TEST_SYSACCOUNT_2,
                random=True
            )
            assert result['value'] == TEST_SYSACCOUNT_2
            assert 'result' in result

        # Clean up
        try:
            api.Command.sysaccount_del(TEST_SYSACCOUNT_2)
        except Exception:
            pass

    def test_security_architect_can_modify_sysaccount(self, sysaccount_3):
        """Test that a Security Architect user can modify a system account"""
        # First create the sysaccount
        sysaccount_3.create()

        try:
            with change_principal(SECURITY_ARCHITECT_USER,
                                  SECURITY_ARCHITECT_PASSWORD):
                result = api.Command.sysaccount_mod(
                    TEST_SYSACCOUNT_3,
                    description=u'Modified by Security Architect'
                )
                assert result['value'] == TEST_SYSACCOUNT_3

                # Verify the modification
                show_result = api.Command.sysaccount_show(TEST_SYSACCOUNT_3)
                assert_attr_equal(
                    show_result['result'], 'description',
                    'Modified by Security Architect'
                )
        finally:
            # Clean up
            try:
                api.Command.sysaccount_del(TEST_SYSACCOUNT_3)
            except Exception:
                pass

    def test_security_architect_can_delete_sysaccount(self, sysaccount_3):
        """Test that a Security Architect user can delete a system account"""
        # First create the sysaccount
        sysaccount_3.create()

        with change_principal(SECURITY_ARCHITECT_USER,
                              SECURITY_ARCHITECT_PASSWORD):
            result = api.Command.sysaccount_del(TEST_SYSACCOUNT_3)
            assert TEST_SYSACCOUNT_3 in result['value']

        # Verify it's deleted
        with pytest.raises(errors.NotFound):
            api.Command.sysaccount_show(TEST_SYSACCOUNT_3)

    def test_security_architect_can_show_sysaccount(self):
        """Test that a Security Architect user can show a system account"""
        # First create the sysaccount as admin
        api.Command.sysaccount_add(
            TEST_SYSACCOUNT_2,
            random=True,
            description=u'Test system account for show'
        )

        try:
            with change_principal(SECURITY_ARCHITECT_USER,
                                  SECURITY_ARCHITECT_PASSWORD):
                result = api.Command.sysaccount_show(TEST_SYSACCOUNT_2)
                assert_attr_equal(
                    result['result'], 'description',
                    'Test system account for show'
                )
        finally:
            # Clean up
            try:
                api.Command.sysaccount_del(TEST_SYSACCOUNT_2)
            except Exception:
                pass

    def test_security_architect_can_find_sysaccount(self):
        """Test that a Security Architect user can find system accounts"""
        # First create a test sysaccount as admin
        api.Command.sysaccount_add(
            TEST_SYSACCOUNT_2,
            random=True,
            description=u'Test system account for find'
        )

        try:
            with change_principal(SECURITY_ARCHITECT_USER,
                                  SECURITY_ARCHITECT_PASSWORD):
                # Test find all sysaccounts
                result = api.Command.sysaccount_find()
                assert 'result' in result
                # Should find at least our test sysaccount
                found = False
                for entry in result['result']:
                    if TEST_SYSACCOUNT_2 in entry.get('uid'):
                        found = True
                        assert_attr_equal(
                            entry, 'description',
                            'Test system account for find'
                        )
                        break
                assert found, f"Test sysaccount {TEST_SYSACCOUNT_2} not found"

                # Test find with specific criteria
                result = api.Command.sysaccount_find(TEST_SYSACCOUNT_2)
                # Should find our test sysaccount
                found = False
                for entry in result['result']:
                    if TEST_SYSACCOUNT_2 in entry.get('uid'):
                        found = True
                        break
                assert found, f"Test sysaccount {TEST_SYSACCOUNT_2} not found"
        finally:
            # Clean up
            try:
                api.Command.sysaccount_del(TEST_SYSACCOUNT_2)
            except Exception:
                pass

    def test_security_architect_can_disable_sysaccount(self, sysaccount_2):
        """Test that a Security Architect user can disable a system account"""
        # First create the sysaccount as admin
        sysaccount_2.create()

        try:
            with change_principal(SECURITY_ARCHITECT_USER,
                                  SECURITY_ARCHITECT_PASSWORD):
                # Disable the sysaccount
                result = api.Command.sysaccount_disable(TEST_SYSACCOUNT_2)
                assert result['value'] == TEST_SYSACCOUNT_2
                assert result['result'] is True

                # Verify it's disabled
                show_result = api.Command.sysaccount_show(TEST_SYSACCOUNT_2)
                assert show_result['result']['nsaccountlock'] is True
        finally:
            # Clean up
            try:
                api.Command.sysaccount_del(TEST_SYSACCOUNT_2)
            except Exception:
                pass

    def test_security_architect_can_enable_sysaccount(self, sysaccount_2):
        """Test that a Security Architect user can enable a system account"""
        # First create and disable the sysaccount as admin
        sysaccount_2.create()
        api.Command.sysaccount_disable(TEST_SYSACCOUNT_2)

        try:
            with change_principal(SECURITY_ARCHITECT_USER,
                                  SECURITY_ARCHITECT_PASSWORD):
                # Enable the sysaccount
                result = api.Command.sysaccount_enable(TEST_SYSACCOUNT_2)
                assert result['value'] == TEST_SYSACCOUNT_2
                assert result['result'] is True

                # Verify it's enabled
                show_result = api.Command.sysaccount_show(TEST_SYSACCOUNT_2)
                assert show_result['result']['nsaccountlock'] is False
        finally:
            # Clean up
            try:
                api.Command.sysaccount_del(TEST_SYSACCOUNT_2)
            except Exception:
                pass

    def test_security_architect_can_set_sysaccount_policy(self, sysaccount_2):
        """Test that a Security Architect user can set sysaccount policy"""
        # First create the sysaccount as admin
        sysaccount_2.create()

        try:
            with change_principal(SECURITY_ARCHITECT_USER,
                                  SECURITY_ARCHITECT_PASSWORD):
                # Set privileged policy to True
                result = api.Command.sysaccount_policy(
                    TEST_SYSACCOUNT_2,
                    privileged=True
                )
                assert result['value'] == TEST_SYSACCOUNT_2

                # Verify the policy is set
                show_result = api.Command.sysaccount_show(TEST_SYSACCOUNT_2)
                assert show_result['result'].get('privileged') is True

                # Set privileged policy to False
                result = api.Command.sysaccount_policy(
                    TEST_SYSACCOUNT_2,
                    privileged=False
                )
                assert result['value'] == TEST_SYSACCOUNT_2

                # Verify the policy is unset
                show_result = api.Command.sysaccount_show(TEST_SYSACCOUNT_2)
                # privileged=False means the attribute should not be present
                # or should be False
                assert show_result['result'].get('privileged') is not True
        finally:
            # Clean up
            try:
                api.Command.sysaccount_del(TEST_SYSACCOUNT_2)
            except Exception:
                pass
