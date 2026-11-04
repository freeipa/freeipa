# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Test the `ipalib.plugins.hbacsvcgroup` module.
"""

from ipalib import api, errors
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.xmlrpc_test import (
    Declarative, XMLRPC_test, fuzzy_uuid, raises_exact)
from ipatests.test_xmlrpc import objectclasses
from ipapython.dn import DN
import pytest

hbacsvcgroup1 = 'testhbacsvcgroup1'
dn1 = DN(('cn',hbacsvcgroup1),('cn','hbacservicegroups'),('cn','hbac'),
         api.env.basedn)

hbacsvc1 = 'sshd'
hbacsvc_dn1 = DN(('cn',hbacsvc1),('cn','hbacservices'),('cn','hbac'),
                 api.env.basedn)


@pytest.mark.tier1
class test_hbacsvcgroup(Declarative):

    cleanup_commands = [
        ('hbacsvcgroup_del', [hbacsvcgroup1], {}),
        ('hbacsvc_del', [hbacsvc1], {}),
    ]

    tests = [
        dict(
            desc='Try to retrieve non-existent %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_show', [hbacsvcgroup1], {}),
            expected=errors.NotFound(
                reason='%s: HBAC service group not found' % hbacsvcgroup1
            ),
        ),
        dict(
            desc='Try to update non-existent %r' % hbacsvcgroup1,
            command=(
                'hbacsvcgroup_mod',
                [hbacsvcgroup1],
                dict(description='Updated hbacsvcgroup 1'),
            ),
            expected=errors.NotFound(
                reason='%s: HBAC service group not found' % hbacsvcgroup1
            ),
        ),
        dict(
            desc='Try to delete non-existent %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_del', [hbacsvcgroup1], {}),
            expected=errors.NotFound(
                reason='%s: HBAC service group not found' % hbacsvcgroup1
            ),
        ),
        dict(
            desc='Create %r' % hbacsvcgroup1,
            command=(
                'hbacsvcgroup_add',
                [hbacsvcgroup1],
                dict(description='Test hbacsvcgroup 1'),
            ),
            expected=dict(
                value=hbacsvcgroup1,
                summary='Added HBAC service group "testhbacsvcgroup1"',
                result=dict(
                    dn=dn1,
                    cn=[hbacsvcgroup1],
                    objectclass=objectclasses.hbacsvcgroup,
                    description=['Test hbacsvcgroup 1'],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),
        dict(
            desc='Try to create duplicate %r' % hbacsvcgroup1,
            command=(
                'hbacsvcgroup_add',
                [hbacsvcgroup1],
                dict(description='Test hbacsvcgroup 1'),
            ),
            expected=errors.DuplicateEntry(
                message='HBAC service group with name "%s" already exists'
                % hbacsvcgroup1
            ),
        ),
        dict(
            desc='Create service %r' % hbacsvc1,
            command=(
                'hbacsvc_add',
                [hbacsvc1],
                dict(
                    description='Test service 1',
                ),
            ),
            expected=dict(
                value=hbacsvc1,
                summary='Added HBAC service "%s"' % hbacsvc1,
                result=dict(
                    dn=hbacsvc_dn1,
                    cn=[hbacsvc1],
                    description=['Test service 1'],
                    objectclass=objectclasses.hbacsvc,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),
        dict(
            desc='Add service %r to %r' % (hbacsvc1, hbacsvcgroup1),
            command=(
                'hbacsvcgroup_add_member',
                [hbacsvcgroup1],
                dict(hbacsvc=hbacsvc1),
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        hbacsvc=tuple(),
                    ),
                ),
                result={
                    'dn': dn1,
                    'cn': [hbacsvcgroup1],
                    'description': ['Test hbacsvcgroup 1'],
                    'member_hbacsvc': [hbacsvc1],
                },
            ),
        ),
        dict(
            desc='Retrieve %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_show', [hbacsvcgroup1], {}),
            expected=dict(
                value=hbacsvcgroup1,
                summary=None,
                result={
                    'dn': dn1,
                    'member_hbacsvc': [hbacsvc1],
                    'cn': [hbacsvcgroup1],
                    'description': ['Test hbacsvcgroup 1'],
                },
            ),
        ),
        dict(
            desc='Search for %r with members' % hbacsvcgroup1,
            command=(
                'hbacsvcgroup_find',
                [],
                dict(cn=hbacsvcgroup1, no_members=False),
            ),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 HBAC service group matched',
                result=[
                    {
                        'dn': dn1,
                        'member_hbacsvc': [hbacsvc1],
                        'cn': [hbacsvcgroup1],
                        'description': ['Test hbacsvcgroup 1'],
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_find', [], dict(cn=hbacsvcgroup1)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 HBAC service group matched',
                result=[
                    {
                        'dn': dn1,
                        'cn': [hbacsvcgroup1],
                        'description': ['Test hbacsvcgroup 1'],
                    },
                ],
            ),
        ),
        dict(
            desc='Update %r' % hbacsvcgroup1,
            command=(
                'hbacsvcgroup_mod',
                [hbacsvcgroup1],
                dict(description='Updated hbacsvcgroup 1'),
            ),
            expected=dict(
                value=hbacsvcgroup1,
                summary='Modified HBAC service group "testhbacsvcgroup1"',
                result=dict(
                    cn=[hbacsvcgroup1],
                    description=['Updated hbacsvcgroup 1'],
                    member_hbacsvc=[hbacsvc1],
                ),
            ),
        ),
        dict(
            desc='Retrieve %r to verify update' % hbacsvcgroup1,
            command=('hbacsvcgroup_show', [hbacsvcgroup1], {}),
            expected=dict(
                value=hbacsvcgroup1,
                summary=None,
                result={
                    'dn': dn1,
                    'member_hbacsvc': [hbacsvc1],
                    'cn': [hbacsvcgroup1],
                    'description': ['Updated hbacsvcgroup 1'],
                },
            ),
        ),
        dict(
            desc='Remove service %r from %r' % (hbacsvc1, hbacsvcgroup1),
            command=(
                'hbacsvcgroup_remove_member',
                [hbacsvcgroup1],
                dict(hbacsvc=hbacsvc1),
            ),
            expected=dict(
                failed=dict(
                    member=dict(
                        hbacsvc=tuple(),
                    ),
                ),
                completed=1,
                result={
                    'dn': dn1,
                    'cn': [hbacsvcgroup1],
                    'description': ['Updated hbacsvcgroup 1'],
                },
            ),
        ),
        dict(
            desc='Delete %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_del', [hbacsvcgroup1], {}),
            expected=dict(
                value=[hbacsvcgroup1],
                summary='Deleted HBAC service group "testhbacsvcgroup1"',
                result=dict(failed=[]),
            ),
        ),
        dict(
            desc='Delete service %r' % hbacsvc1,
            command=('hbacsvc_del', [hbacsvc1], {}),
            expected=dict(
                value=[hbacsvc1],
                summary='Deleted HBAC service "%s"' % hbacsvc1,
                result=dict(failed=[]),
            ),
        ),
    ]


@pytest.fixture(scope='class')
def hbacsvcgroup_dep(request, xmlrpc_setup):
    name = 'testhbacsvcgroup_del_dep'
    api.Command['hbacsvcgroup_add'](
        name, description='Test HBAC service group')

    def fin():
        try:
            api.Command['hbacsvcgroup_del'](name)
        except errors.NotFound:
            pass
    request.addfinalizer(fin)
    return name


@pytest.fixture(scope='class')
def hbacrule_svcgroup(request, xmlrpc_setup):
    name = 'test_hbacsvcgroup_hbacrule1'
    api.Command['hbacrule_add'](name)

    def fin():
        try:
            api.Command['hbacrule_del'](name)
        except errors.NotFound:
            pass
    request.addfinalizer(fin)
    return name


@pytest.mark.tier1
class TestHBACsvcGroupInHBACRule(XMLRPC_test):
    def test_add_hbacsvcgroup_to_hbacrule(
            self, hbacsvcgroup_dep, hbacrule_svcgroup):
        """ Add hbacsvcgroup to hbacrule memberservice """
        result = api.Command['hbacrule_add_service'](
            hbacrule_svcgroup, hbacsvcgroup=hbacsvcgroup_dep
        )
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                memberservice=dict(hbacsvcgroup=(), hbacsvc=())),
            result=lambda result: True,
        ), result)

    def test_del_dependent_hbacsvcgroup(
            self, hbacsvcgroup_dep, hbacrule_svcgroup):
        """ Try to delete hbacsvcgroup that is still used by an hbacrule """
        # Self-contained: ensure the rule references the group first.
        api.Command['hbacrule_add_service'](
            hbacrule_svcgroup, hbacsvcgroup=hbacsvcgroup_dep)
        with raises_exact(errors.DependentEntry(
                key=hbacsvcgroup_dep,
                label='hbacrule',
                dependent=hbacrule_svcgroup)):
            api.Command['hbacsvcgroup_del'](hbacsvcgroup_dep)

    def test_remove_hbacsvcgroup_from_hbacrule(
            self, hbacsvcgroup_dep, hbacrule_svcgroup):
        """ Remove hbacsvcgroup from hbacrule memberservice """
        # Self-contained: ensure membership exists before remove.
        api.Command['hbacrule_add_service'](
            hbacrule_svcgroup, hbacsvcgroup=hbacsvcgroup_dep)
        result = api.Command['hbacrule_remove_service'](
            hbacrule_svcgroup, hbacsvcgroup=hbacsvcgroup_dep
        )
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                memberservice=dict(hbacsvcgroup=(), hbacsvc=())),
            result=lambda result: True),
            result)

    def test_del_hbacsvcgroup_after_remove(
            self, hbacsvcgroup_dep, hbacrule_svcgroup):
        """ Delete hbacsvcgroup after removing it from hbacrule """
        # Self-contained: drop any remaining rule reference first.
        api.Command['hbacrule_remove_service'](
            hbacrule_svcgroup, hbacsvcgroup=hbacsvcgroup_dep)
        result = api.Command['hbacsvcgroup_del'](hbacsvcgroup_dep)
        assert_deepequal(dict(
            value=[hbacsvcgroup_dep],
            summary='Deleted HBAC service group "%s"' % hbacsvcgroup_dep,
            result=dict(failed=[]),
        ), result)
