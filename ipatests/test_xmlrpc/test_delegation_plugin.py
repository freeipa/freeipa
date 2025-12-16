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
Test the `ipaserver/plugins/delegation.py` module.
"""

from ipalib import api, errors
from ipapython.dn import DN
from ipatests.test_xmlrpc.xmlrpc_test import Declarative

import pytest

delegation1 = "testdelegation"
member1 = "admins"
testgroup1 = "testgroup1"
testgroup2 = "testgroup2"
testdel_positive = "testdel_positive"
testdel_negative = "testdel_negative"


@pytest.mark.tier1
class test_delegation(Declarative):

    cleanup_commands = [
        ("delegation_del", [delegation1], {}),
    ]

    tests = [
        dict(
            desc="retrieve non-existent %r" % delegation1,
            command=("delegation_show", [delegation1], {}),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % delegation1
            ),
        ),
        dict(
            desc="update non-existent %r" % delegation1,
            command=("delegation_mod", [delegation1], dict(group="admins")),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % delegation1
            ),
        ),
        dict(
            desc="delete non-existent %r" % delegation1,
            command=("delegation_del", [delegation1], {}),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % delegation1
            ),
        ),
        dict(
            desc="Search for non-existent %r" % delegation1,
            command=("delegation_find", [delegation1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary="0 delegations matched",
                result=[],
            ),
        ),
        dict(
            desc="create %r for non-existing member group" % delegation1,
            command=(
                "delegation_add",
                [delegation1],
                dict(
                    attrs="street,c,l,st,postalCode",
                    permissions="write",
                    group="editors",
                    memberof="nonexisting",
                ),
            ),
            expected=errors.NotFound(reason="nonexisting: group not found"),
        ),
        # Note that we add postalCode but expect postalcode. This tests
        # the attrs normalizer.
        dict(
            desc="Create %r" % delegation1,
            command=(
                "delegation_add",
                [delegation1],
                dict(
                    attrs=["street", "c", "l", "st", "postalCode"],
                    permissions="write",
                    group="editors",
                    memberof="admins",
                ),
            ),
            expected=dict(
                value=delegation1,
                summary='Added delegation "%s"' % delegation1,
                result=dict(
                    attrs=["street", "c", "l", "st", "postalcode"],
                    permissions=["write"],
                    aciname=delegation1,
                    group="editors",
                    memberof=member1,
                ),
            ),
        ),
        dict(
            desc="create duplicate %r" % delegation1,
            command=(
                "delegation_add",
                [delegation1],
                dict(
                    attrs=["street", "c", "l", "st", "postalCode"],
                    permissions="write",
                    group="editors",
                    memberof="admins",
                ),
            ),
            expected=errors.DuplicateEntry(),
        ),
        dict(
            desc="Retrieve %r" % delegation1,
            command=("delegation_show", [delegation1], {}),
            expected=dict(
                value=delegation1,
                summary=None,
                result={
                    "attrs": ["street", "c", "l", "st", "postalcode"],
                    "permissions": ["write"],
                    "aciname": delegation1,
                    "group": "editors",
                    "memberof": member1,
                },
            ),
        ),
        dict(
            desc="Retrieve %r with --raw" % delegation1,
            command=("delegation_show", [delegation1], {"raw": True}),
            expected=dict(
                value=delegation1,
                summary=None,
                result={
                    "aci": (
                        '(targetattr = "street || c || l || st || postalcode")'
                        '(targetfilter = "(memberOf=%s)")'
                        '(version 3.0;acl "delegation:testdelegation";'
                        'allow (write) groupdn = "ldap:///%s";)'
                    )
                    % (
                        DN(
                            ("cn", "admins"),
                            ("cn", "groups"),
                            ("cn", "accounts"),
                            api.env.basedn,
                        ),
                        DN(
                            ("cn", "editors"),
                            ("cn", "groups"),
                            ("cn", "accounts"),
                            api.env.basedn,
                        ),
                    )
                },
            ),
        ),
        dict(
            desc="Search for %r" % delegation1,
            command=("delegation_find", [delegation1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary="1 delegation matched",
                result=[
                    {
                        "attrs": ["street", "c", "l", "st", "postalcode"],
                        "permissions": ["write"],
                        "aciname": delegation1,
                        "group": "editors",
                        "memberof": member1,
                    },
                ],
            ),
        ),
        dict(
            desc="Search for %r using --group filter" % delegation1,
            command=("delegation_find", [delegation1], {"group": "editors"}),
            expected=dict(
                count=1,
                truncated=False,
                summary="1 delegation matched",
                result=[
                    {
                        "attrs": ["street", "c", "l", "st", "postalcode"],
                        "permissions": ["write"],
                        "aciname": delegation1,
                        "group": "editors",
                        "memberof": member1,
                    },
                ],
            ),
        ),
        dict(
            desc="Search for %r using --membergroup filter" % delegation1,
            command=("delegation_find", [delegation1], {"memberof": member1}),
            expected=dict(
                count=1,
                truncated=False,
                summary="1 delegation matched",
                result=[
                    {
                        "attrs": ["street", "c", "l", "st", "postalcode"],
                        "permissions": ["write"],
                        "aciname": delegation1,
                        "group": "editors",
                        "memberof": member1,
                    },
                ],
            ),
        ),
        dict(
            desc="Search for %r with --pkey-only" % delegation1,
            command=("delegation_find", [delegation1], {"pkey_only": True}),
            expected=dict(
                count=1,
                truncated=False,
                summary="1 delegation matched",
                result=[
                    {
                        "aciname": delegation1,
                    },
                ],
            ),
        ),
        dict(
            desc="Search for %r with --raw" % delegation1,
            command=("delegation_find", [delegation1], {"raw": True}),
            expected=dict(
                count=1,
                truncated=False,
                summary="1 delegation matched",
                result=[
                    {
                        "aci": (
                            '(targetattr = "street || c || l || st '
                            '|| postalcode")'
                            '(targetfilter = "(memberOf=%s)")'
                            '(version 3.0;acl "delegation:testdelegation";'
                            'allow (write) groupdn = "ldap:///%s";)'
                        )
                        % (
                            DN(
                                ("cn", "admins"),
                                ("cn", "groups"),
                                ("cn", "accounts"),
                                api.env.basedn,
                            ),
                            DN(
                                ("cn", "editors"),
                                ("cn", "groups"),
                                ("cn", "accounts"),
                                api.env.basedn,
                            ),
                        ),
                    },
                ],
            ),
        ),
        dict(
            desc="Update %r" % delegation1,
            command=(
                "delegation_mod",
                [delegation1],
                dict(permissions="read"),
            ),
            expected=dict(
                value=delegation1,
                summary='Modified delegation "%s"' % delegation1,
                result=dict(
                    attrs=["street", "c", "l", "st", "postalcode"],
                    permissions=["read"],
                    aciname=delegation1,
                    group="editors",
                    memberof=member1,
                ),
            ),
        ),
        dict(
            desc="Retrieve %r to verify update" % delegation1,
            command=("delegation_show", [delegation1], {}),
            expected=dict(
                value=delegation1,
                summary=None,
                result={
                    "attrs": ["street", "c", "l", "st", "postalcode"],
                    "permissions": ["read"],
                    "aciname": delegation1,
                    "group": "editors",
                    "memberof": member1,
                },
            ),
        ),
        dict(
            desc="Delete %r" % delegation1,
            command=("delegation_del", [delegation1], {}),
            expected=dict(
                result=True,
                value=delegation1,
                summary='Deleted delegation "%s"' % delegation1,
            ),
        ),
        dict(
            desc="Create %r with duplicate attrs & perms" % delegation1,
            command=(
                "delegation_add",
                [delegation1],
                dict(
                    attrs=["street", "street"],
                    permissions=["write", "write"],
                    group="editors",
                    memberof="admins",
                ),
            ),
            expected=dict(
                value=delegation1,
                summary='Added delegation "%s"' % delegation1,
                result=dict(
                    attrs=["street"],
                    permissions=["write"],
                    aciname=delegation1,
                    group="editors",
                    memberof=member1,
                ),
            ),
        ),
        dict(
            desc="Delete %r" % delegation1,
            command=("delegation_del", [delegation1], {}),
            expected=dict(
                result=True,
                value=delegation1,
                summary='Deleted delegation "%s"' % delegation1,
            ),
        ),
    ]


class test_delegation_add_positive(Declarative):
    """
    Test delegation-add positive scenarios.
    Tests successful delegation creation with
    various options and output formats.
    """

    cleanup_commands = [
        ("group_del", [testgroup1], {}),
        ("group_del", [testgroup2], {}),
        ("delegation_del", ["test_add_no_permissions"], {}),
        ("delegation_del", ["test_add_with_write"], {}),
        ("delegation_del", ["test_add_with_all"], {}),
        ("delegation_del", ["test_add_with_raw"], {}),
        ("delegation_del", ["test_add_with_all_raw"], {}),
    ]

    tests = [
        # Setup: Create test groups
        dict(
            desc="Create test group 1 for positive tests",
            command=(
                "group_add",
                [testgroup1],
                dict(description="Test group 1"),
            ),
            expected=dict(
                value=testgroup1,
                summary='Added group "%s"' % testgroup1,
                result=dict(
                    cn=[testgroup1],
                    description=["Test group 1"],
                    objectclass=[
                        "top",
                        "groupofnames",
                        "nestedgroup",
                        "ipausergroup",
                        "ipaobject",
                    ],
                    ipauniqueid=[lambda v: True],
                    dn=lambda v: True,
                ),
            ),
        ),
        dict(
            desc="Create test group 2 for positive tests",
            command=(
                "group_add",
                [testgroup2],
                dict(description="Test group 2"),
            ),
            expected=dict(
                value=testgroup2,
                summary='Added group "%s"' % testgroup2,
                result=dict(
                    cn=[testgroup2],
                    description=["Test group 2"],
                    objectclass=[
                        "top",
                        "groupofnames",
                        "nestedgroup",
                        "ipausergroup",
                        "ipaobject",
                    ],
                    ipauniqueid=[lambda v: True],
                    dn=lambda v: True,
                ),
            ),
        ),
        # Positive Test 1: Add delegation with no explicit permissions
        dict(
            desc="Add delegation with no explicit perm(defaults to read)",
            command=(
                "delegation_add",
                ["test_add_no_permissions"],
                dict(
                    attrs="mobile",
                    group=testgroup1,
                    memberof=testgroup2,
                ),
            ),
            expected=dict(
                value="test_add_no_permissions",
                summary='Added delegation "test_add_no_permissions"',
                result=dict(
                    attrs=["mobile"],
                    permissions=[
                        "read",
                        "search",
                        "compare",
                    ],  # Default permissions
                    aciname="test_add_no_permissions",
                    group=testgroup1,
                    memberof=testgroup2,
                ),
            ),
        ),
        # Positive Test 2: Add delegation with write permissions
        dict(
            desc="Add delegation with write permissions",
            command=(
                "delegation_add",
                ["test_add_with_write"],
                dict(
                    attrs="mobile",
                    permissions="write",
                    group=testgroup1,
                    memberof=testgroup2,
                ),
            ),
            expected=dict(
                value="test_add_with_write",
                summary='Added delegation "test_add_with_write"',
                result=dict(
                    attrs=["mobile"],
                    permissions=["write"],
                    aciname="test_add_with_write",
                    group=testgroup1,
                    memberof=testgroup2,
                ),
            ),
        ),
        # Positive Test 3: Add delegation with --all option
        dict(
            desc="Add delegation with --all option",
            command=(
                "delegation_add",
                ["test_add_with_all"],
                dict(
                    attrs="mobile",
                    group=testgroup1,
                    memberof=testgroup2,
                    all=True,
                ),
            ),
            expected=dict(
                value="test_add_with_all",
                summary='Added delegation "test_add_with_all"',
                result=dict(
                    attrs=["mobile"],
                    permissions=["read", "search", "compare"],
                    aciname="test_add_with_all",
                    group=testgroup1,
                    memberof=testgroup2,
                    dn=lambda v: True,  # --all includes DN
                ),
            ),
        ),
        # Positive Test 4: Add delegation with --raw option
        dict(
            desc="Add delegation with --raw option",
            command=(
                "delegation_add",
                ["test_add_with_raw"],
                dict(
                    attrs="mobile",
                    group=testgroup1,
                    memberof=testgroup2,
                    raw=True,
                ),
            ),
            expected=dict(
                value="test_add_with_raw",
                summary='Added delegation "test_add_with_raw"',
                result=dict(
                    aci=lambda v: isinstance(v, str)
                    and "mobile" in v,  # Raw ACI syntax
                ),
            ),
        ),
        # Positive Test 5: Add delegation with --all and --raw options
        dict(
            desc="Add delegation with --all and --raw options",
            command=(
                "delegation_add",
                ["test_add_with_all_raw"],
                dict(
                    attrs="mobile",
                    group=testgroup1,
                    memberof=testgroup2,
                    all=True,
                    raw=True,
                ),
            ),
            expected=dict(
                value="test_add_with_all_raw",
                summary='Added delegation "test_add_with_all_raw"',
                result=dict(
                    aci=lambda v: isinstance(v, str)
                    and "mobile" in v,  # Raw ACI syntax
                ),
            ),
        ),
    ]
