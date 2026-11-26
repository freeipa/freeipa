# Authors:
#   Anuja More <amore@redhat.com>
#
# Copyright (C) 2026  Red Hat
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
Test the `ipaserver/plugins/hbacsvc.py` module.
"""

from ipalib import api, errors
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
import pytest


@pytest.fixture(scope='class')
def hbacsvc1(request, xmlrpc_setup):
    name = 'testhbacsvc_del_dep'
    api.Command['hbacsvc_add'](name, description='Test HBAC service')

    def fin():
        try:
            api.Command['hbacsvc_del'](name)
        except errors.NotFound:
            pass
    request.addfinalizer(fin)
    return name


@pytest.fixture(scope='class')
def hbacrule1(request, xmlrpc_setup):
    name = 'test_hbacsvc_hbacrule1'
    api.Command['hbacrule_add'](name)

    def fin():
        try:
            api.Command['hbacrule_del'](name)
        except errors.NotFound:
            pass
    request.addfinalizer(fin)
    return name


@pytest.mark.tier1
class TestHBACsvcInHBACRule(XMLRPC_test):
    def test_add_hbacsvc_to_hbacrule(self, hbacsvc1, hbacrule1):
        """ Add hbacsvc to hbacrule memberservice """
        result = api.Command['hbacrule_add_service'](
            hbacrule1, hbacsvc=hbacsvc1
        )
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                memberservice=dict(hbacsvcgroup=(), hbacsvc=())),
            result=lambda result: True,
        ), result)

    def test_del_dependent_hbacsvc(self, hbacsvc1, hbacrule1):
        """ Try to delete hbacsvc that is still used by an hbacrule """
        # Self-contained: ensure the rule references the service first.
        api.Command['hbacrule_add_service'](hbacrule1, hbacsvc=hbacsvc1)
        with raises_exact(errors.DependentEntry(
                key=hbacsvc1,
                label='hbacrule',
                dependent=hbacrule1)):
            api.Command['hbacsvc_del'](hbacsvc1)

    def test_remove_hbacsvc_from_hbacrule(self, hbacsvc1, hbacrule1):
        """ Remove hbacsvc from hbacrule memberservice """
        # Self-contained: ensure membership exists before remove.
        api.Command['hbacrule_add_service'](hbacrule1, hbacsvc=hbacsvc1)
        result = api.Command['hbacrule_remove_service'](
            hbacrule1, hbacsvc=hbacsvc1
        )
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                memberservice=dict(hbacsvcgroup=(), hbacsvc=())),
            result=lambda result: True),
            result)

    def test_del_hbacsvc_after_remove(self, hbacsvc1, hbacrule1):
        """ Delete hbacsvc after removing it from hbacrule """
        # Self-contained: drop any remaining rule reference first.
        api.Command['hbacrule_remove_service'](hbacrule1, hbacsvc=hbacsvc1)
        result = api.Command['hbacsvc_del'](hbacsvc1)
        assert_deepequal(dict(
            value=[hbacsvc1],
            summary='Deleted HBAC service "%s"' % hbacsvc1,
            result=dict(failed=[]),
        ), result)


@pytest.fixture(scope='class')
def hbacsvc_via_group(request, xmlrpc_setup):
    name = 'testhbacsvc_del_via_grp'
    api.Command['hbacsvc_add'](name, description='Test HBAC service via group')

    def fin():
        try:
            api.Command['hbacsvc_del'](name)
        except errors.NotFound:
            pass
    request.addfinalizer(fin)
    return name


@pytest.fixture(scope='class')
def hbacsvcgroup_via_group(request, xmlrpc_setup):
    name = 'testhbacsvcgrp_del_via'
    api.Command['hbacsvcgroup_add'](
        name, description='Test HBAC service group for svc del')

    def fin():
        try:
            api.Command['hbacsvcgroup_del'](name)
        except errors.NotFound:
            pass
    request.addfinalizer(fin)
    return name


@pytest.fixture(scope='class')
def hbacrule_via_group(request, xmlrpc_setup):
    name = 'test_hbacsvc_hbacrule_via_grp'
    api.Command['hbacrule_add'](name)

    def fin():
        try:
            api.Command['hbacrule_del'](name)
        except errors.NotFound:
            pass
    request.addfinalizer(fin)
    return name


@pytest.mark.tier1
class TestHBACsvcInHBACRuleViaGroup(XMLRPC_test):
    def test_del_hbacsvc_via_hbacsvcgroup_on_rule(
            self, hbacsvc_via_group, hbacsvcgroup_via_group,
            hbacrule_via_group):
        """ Refuse hbacsvc-del when reached only via hbacsvcgroup on a rule """
        api.Command['hbacsvcgroup_add_member'](
            hbacsvcgroup_via_group, hbacsvc=hbacsvc_via_group)
        api.Command['hbacrule_add_service'](
            hbacrule_via_group, hbacsvcgroup=hbacsvcgroup_via_group)

        with raises_exact(errors.DependentEntry(
                key=hbacsvc_via_group,
                label='hbacrule',
                dependent=hbacrule_via_group)):
            api.Command['hbacsvc_del'](hbacsvc_via_group)

        # Cleanup so the service can be deleted afterwards / by fixtures.
        api.Command['hbacrule_remove_service'](
            hbacrule_via_group, hbacsvcgroup=hbacsvcgroup_via_group)
        api.Command['hbacsvcgroup_remove_member'](
            hbacsvcgroup_via_group, hbacsvc=hbacsvc_via_group)

    def test_del_hbacsvc_after_group_rule_cleanup(
            self, hbacsvc_via_group, hbacsvcgroup_via_group,
            hbacrule_via_group):
        """ Delete hbacsvc after dropping group-from-rule and svc-from-group """
        # Self-contained: drop any remaining indirect dependency first.
        api.Command['hbacrule_remove_service'](
            hbacrule_via_group, hbacsvcgroup=hbacsvcgroup_via_group)
        api.Command['hbacsvcgroup_remove_member'](
            hbacsvcgroup_via_group, hbacsvc=hbacsvc_via_group)

        result = api.Command['hbacsvc_del'](hbacsvc_via_group)
        assert_deepequal(dict(
            value=[hbacsvc_via_group],
            summary='Deleted HBAC service "%s"' % hbacsvc_via_group,
            result=dict(failed=[]),
        ), result)
