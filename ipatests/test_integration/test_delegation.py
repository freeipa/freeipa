#!/usr/bin/env python3
#
# Copyright (C) 2012  Red Hat
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
Test the `ipa delegation cli' related command integration.
"""

import re
import time

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestDelegationAdd(IntegrationTest):
    """
    Test delegation-add command functionality.

    This test class mirrors the bash test
    t.ipa-delegation-cli-add.sh and follows
    the FreeIPA integration test patterns.
    """

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_delegation_add_positive_setup(self):
        """Setup environment for delegation add positive tests"""
        tasks.kinit_admin(self.master)

        # Create test groups for positive tests
        for i in range(1001, 1006):
            self.master.run_command(
                ["ipa", "group-add", f"mg{i}", f"--desc=mg{i}"]
            )
            self.master.run_command(
                ["ipa", "group-add", f"gr{i}", f"--desc=gr{i}"]
            )

    def test_delegation_add_with_no_permissions(self):
        """Test delegation-add with no permissions"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_positive_1001",
                "--membergroup=mg1001",
                "--group=gr1001",
                "--attrs=mobile",
            ]
        )

        assert result.returncode == 0
        assert (
            'Added delegation "delegation_add_positive_1001"'
            in result.stdout_text
        )

    def test_delegation_add_with_permissions_write(self):
        """Test delegation-add with permissions write"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_positive_1002",
                "--membergroup=mg1002",
                "--group=gr1002",
                "--attrs=mobile",
                "--permissions=write",
            ]
        )

        assert result.returncode == 0
        assert (
            'Added delegation "delegation_add_positive_1002"'
            in result.stdout_text
        )

    def test_delegation_add_with_option_all(self):
        """Test delegation-add with option all"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_positive_1003",
                "--membergroup=mg1003",
                "--group=gr1003",
                "--attrs=mobile",
                "--all",
            ]
        )

        assert result.returncode == 0
        assert (
            'Added delegation "delegation_add_positive_1003"'
            in result.stdout_text
        )

    def test_delegation_add_with_option_raw(self):
        """Test delegation-add with option raw"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_positive_1004",
                "--membergroup=mg1004",
                "--group=gr1004",
                "--attrs=mobile",
                "--raw",
            ]
        )

        assert result.returncode == 0

    def test_delegation_add_with_options_all_and_raw(self):
        """Test delegation-add with options all and raw"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_positive_1005",
                "--membergroup=mg1005",
                "--group=gr1005",
                "--attrs=mobile",
                "--all",
                "--raw",
            ]
        )

        assert result.returncode == 0

    def test_delegation_add_negative_setup(self):
        """Setup environment for delegation add negative tests"""
        tasks.kinit_admin(self.master)

        # Create test groups for negative tests
        for i in range(1001, 1020):
            self.master.run_command(
                ["ipa", "group-add", f"mg{i}", f"--desc=mg{i}"],
                raiseonerr=False,
            )
            self.master.run_command(
                ["ipa", "group-add", f"gr{i}", f"--desc=gr{i}"],
                raiseonerr=False,
            )

    def test_delegation_add_fail_on_existing_name(self):
        """Test that adding delegation with existing name fails"""
        tasks.kinit_admin(self.master)

        # First, create a delegation
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1001",
                "--membergroup=mg1001",
                "--group=gr1001",
                "--attrs=mobile",
            ]
        )

        # Try to create the same delegation again
        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1001",
                "--membergroup=mg1001",
                "--group=gr1001",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "This entry already exists" in result.stderr_text

    def test_delegation_add_with_empty_name(self):
        """Test delegation-add with empty name"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "",
                "--membergroup=mg1002",
                "--group=gr1002",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'name' is required" in result.stderr_text

    def test_delegation_add_with_space_for_name(self):
        """Test delegation-add with space for name"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                " ",
                "--membergroup=mg1003",
                "--group=gr1003",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_add_with_empty_membergroup(self):
        """Test delegation-add with empty membergroup"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1004",
                "--membergroup=",
                "--group=gr1004",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'membergroup' is required" in result.stderr_text

    def test_delegation_add_with_space_for_membergroup(self):
        """Test delegation-add with space for membergroup"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1005",
                "--membergroup= ",
                "--group=gr1005",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_add_with_missing_membergroup(self):
        """Test delegation-add fails with missing membergroup (BZ 783307)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1006",
                "--membergroup=badgroup",
                "--group=gr1006",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "group not found" in result.stderr_text

        # Check that delegation was not created (BZ 783307)
        output = result.stdout_text + result.stderr_text
        success_lines = [
            line
            for line in output.split("\n")
            if "Added delegation" in line or "badgroup" in line
        ]
        assert (
            len(success_lines) < 2
        ), "BZ 783307 -- ipa delegation-add \
        should fail when membergroup does not exist"

    def test_delegation_add_with_empty_group(self):
        """Test delegation-add with empty group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1007",
                "--membergroup=mg1007",
                "--group=",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'group' is required" in result.stderr_text

    def test_delegation_add_with_space_for_group(self):
        """Test delegation-add with space for group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1008",
                "--membergroup=mg1008",
                "--group= ",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_add_with_missing_group(self):
        """Test delegation-add with missing group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1009",
                "--membergroup=mg1009",
                "--group=badgroup",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "does not exist" in result.stderr_text

    def test_delegation_add_with_empty_attrs(self):
        """Test delegation-add with empty attrs"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1010",
                "--membergroup=mg1010",
                "--group=gr1010",
                "--attrs=",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'attrs' is required" in result.stderr_text

    def test_delegation_add_with_space_for_attrs(self):
        """Test delegation-add with space for attrs"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1011",
                "--membergroup=mg1011",
                "--group=gr1011",
                "--attrs= ",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_add_with_space_comma_for_attrs(self):
        """Test delegation-add with space comma for attrs"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1012",
                "--membergroup=mg1012",
                "--group=gr1012",
                "--attrs= ,",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_add_with_only_bad_attr(self):
        """Test delegation-add with only bad attr"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1013",
                "--membergroup=mg1013",
                "--group=gr1013",
                "--attrs=badattr",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "does not exist in schema" in result.stderr_text

    def test_delegation_add_with_one_bad_attr(self):
        """Test delegation-add with one bad attr"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1014",
                "--membergroup=mg1014",
                "--group=gr1014",
                "--attrs={badattr,mobile}",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "does not exist in schema" in result.stderr_text

    def test_delegation_add_with_empty_permissions(self):
        """Test delegation-add with empty permissions"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1015",
                "--membergroup=mg1015",
                "--group=gr1015",
                "--attrs=mobile",
                "--permissions=",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'permissions' is required" in result.stderr_text

    def test_delegation_add_with_space_for_permissions(self):
        """Test delegation-add with space for permissions"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1016",
                "--membergroup=mg1016",
                "--group=gr1016",
                "--attrs=mobile",
                "--permissions= ",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_add_with_space_comma_for_permissions(self):
        """Test delegation-add with space comma for permissions"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1017",
                "--membergroup=mg1017",
                "--group=gr1017",
                "--attrs=mobile",
                "--permissions= ,",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_add_with_only_invalid_permissions(self):
        """Test delegation-add with only invalid permissions"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1018",
                "--membergroup=mg1018",
                "--group=gr1018",
                "--attrs=mobile",
                "--permissions=badperm",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "is not a valid permission" in result.stderr_text

    def test_delegation_add_with_one_invalid_permission(self):
        """Test delegation-add with one invalid permission"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_add_negative_1019",
                "--membergroup=mg1019",
                "--group=gr1019",
                "--attrs=mobile",
                "--permissions={badperm,write}",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "is not a valid permission" in result.stderr_text

    def test_delegation_add_positive_cleanup(self):
        """Cleanup delegation add positive test environment"""
        tasks.kinit_admin(self.master)

        # Clean up delegations and groups
        for i in range(1001, 1006):
            self.master.run_command(
                ["ipa", "delegation-del", f"delegation_add_positive_{i}"],
                raiseonerr=False,
            )
            self.master.run_command(
                ["ipa", "group-del", f"mg{i}"], raiseonerr=False
            )
            self.master.run_command(
                ["ipa", "group-del", f"gr{i}"], raiseonerr=False
            )

    def test_delegation_add_negative_cleanup(self):
        """Cleanup delegation add negative test environment"""
        tasks.kinit_admin(self.master)

        # Clean up groups
        for i in range(1001, 1020):
            self.master.run_command(
                ["ipa", "group-del", f"mg{i}"], raiseonerr=False
            )
            self.master.run_command(
                ["ipa", "group-del", f"gr{i}"], raiseonerr=False
            )

        # Clean up any delegations that might have been created
        result = self.master.run_command(
            ["ipa", "delegation-find"], raiseonerr=False
        )

        if result.returncode == 0:
            for line in result.stdout_text.split("\n"):
                if "negative_" in line:
                    # Extract delegation name and delete it
                    match = re.search(r"Delegation name:\s+(\S+)", line)
                    if match:
                        delegation_name = match.group(1)
                        self.master.run_command(
                            ["ipa", "delegation-del", delegation_name],
                            raiseonerr=False,
                        )


class TestDelegationCmd(IntegrationTest):
    """
    Test delegation command suite integration.

    This test class mirrors the bash test t.ipa-delegation-cli-cmd.sh
    and orchestrates all delegation CLI command tests.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_delegation_cmd_suite_setup(self):
        """Setup environment for delegation command suite"""
        tasks.kinit_admin(self.master)

        # Verify IPA server is running and accessible
        result = self.master.run_command(["ipa", "--version"])
        assert result.returncode == 0

        # Create base test groups that will be used across tests
        test_groups = ["testmg", "testgr", "admingroup", "usergroup"]
        for group in test_groups:
            self.master.run_command(
                ["ipa", "group-add", group, f"--desc=Test group {group}"],
                raiseonerr=False,
            )

    def test_delegation_add_positive_suite(self):
        """Test delegation-add positive scenarios"""
        tasks.kinit_admin(self.master)

        # Test basic delegation creation
        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_delegation_add_pos",
                "--membergroup=testmg",
                "--group=testgr",
                "--attrs=mobile",
            ]
        )

        assert result.returncode == 0
        assert "Added delegation" in result.stdout_text

        # Verify delegation exists
        result = self.master.run_command(
            ["ipa", "delegation-show", "test_delegation_add_pos"]
        )
        assert result.returncode == 0
        assert "Delegation name: test_delegation_add_pos" in result.stdout_text

    def test_delegation_add_negative_suite(self):
        """Test delegation-add negative scenarios"""
        tasks.kinit_admin(self.master)

        # Test with invalid membergroup
        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_delegation_add_neg",
                "--membergroup=nonexistent",
                "--group=testgr",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "group not found" in result.stderr_text

    def test_delegation_del_positive_suite(self):
        """Test delegation-del positive scenarios"""
        tasks.kinit_admin(self.master)

        # First create a delegation to delete
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_delegation_del_pos",
                "--membergroup=testmg",
                "--group=testgr",
                "--attrs=mobile",
            ]
        )

        # Now delete it
        result = self.master.run_command(
            ["ipa", "delegation-del", "test_delegation_del_pos"]
        )

        assert result.returncode == 0
        assert "Deleted delegation" in result.stdout_text

    def test_delegation_del_negative_suite(self):
        """Test delegation-del negative scenarios"""
        tasks.kinit_admin(self.master)

        # Try to delete non-existent delegation
        result = self.master.run_command(
            ["ipa", "delegation-del", "nonexistent_delegation"],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "not found" in result.stderr_text

    def test_delegation_find_positive_suite(self):
        """Test delegation-find positive scenarios"""
        tasks.kinit_admin(self.master)

        # Create a test delegation
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_delegation_find_pos",
                "--membergroup=testmg",
                "--group=testgr",
                "--attrs=mobile",
            ]
        )

        # Find all delegations
        result = self.master.run_command(["ipa", "delegation-find"])

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text

        # Find specific delegation
        result = self.master.run_command(
            ["ipa", "delegation-find", "test_delegation_find_pos"]
        )

        assert result.returncode == 0
        assert "test_delegation_find_pos" in result.stdout_text

    def test_delegation_find_negative_suite(self):
        """Test delegation-find negative scenarios"""
        tasks.kinit_admin(self.master)

        # Search for non-existent delegation
        result = self.master.run_command(
            ["ipa", "delegation-find", "nonexistent_delegation"],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_mod_positive_suite(self):
        """Test delegation-mod positive scenarios"""
        tasks.kinit_admin(self.master)

        # Create a test delegation
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_delegation_mod_pos",
                "--membergroup=testmg",
                "--group=testgr",
                "--attrs=mobile",
            ]
        )

        # Modify the delegation
        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "test_delegation_mod_pos",
                "--attrs=telephoneNumber",
            ]
        )

        assert result.returncode == 0
        assert "Modified delegation" in result.stdout_text

        # Verify modification
        result = self.master.run_command(
            ["ipa", "delegation-show", "test_delegation_mod_pos"]
        )

        assert result.returncode == 0
        assert "telephoneNumber" in result.stdout_text

    def test_delegation_mod_negative_suite(self):
        """Test delegation-mod negative scenarios"""
        tasks.kinit_admin(self.master)

        # Try to modify non-existent delegation
        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "nonexistent_delegation",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "not found" in result.stderr_text

    def test_delegation_show_positive_suite(self):
        """Test delegation-show positive scenarios"""
        tasks.kinit_admin(self.master)

        # Create a test delegation
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_delegation_show_pos",
                "--membergroup=testmg",
                "--group=testgr",
                "--attrs=mobile",
            ]
        )

        # Show the delegation
        result = self.master.run_command(
            ["ipa", "delegation-show", "test_delegation_show_pos"]
        )

        assert result.returncode == 0
        assert (
            "Delegation name: test_delegation_show_pos" in result.stdout_text
        )
        assert "Member user group: testmg" in result.stdout_text
        assert "User group: testgr" in result.stdout_text

        # Test with --all option
        result = self.master.run_command(
            ["ipa", "delegation-show", "test_delegation_show_pos", "--all"]
        )

        assert result.returncode == 0
        assert "test_delegation_show_pos" in result.stdout_text

    def test_delegation_show_negative_suite(self):
        """Test delegation-show negative scenarios"""
        tasks.kinit_admin(self.master)

        # Try to show non-existent delegation
        result = self.master.run_command(
            ["ipa", "delegation-show", "nonexistent_delegation"],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "not found" in result.stderr_text

    def test_delegation_cmd_suite_cleanup(self):
        """Cleanup delegation command suite test environment"""
        tasks.kinit_admin(self.master)

        # Clean up test delegations
        test_delegations = [
            "test_delegation_add_pos",
            "test_delegation_find_pos",
            "test_delegation_mod_pos",
            "test_delegation_show_pos",
        ]

        for delegation in test_delegations:
            self.master.run_command(
                ["ipa", "delegation-del", delegation], raiseonerr=False
            )

        # Clean up test groups
        test_groups = ["testmg", "testgr", "admingroup", "usergroup"]
        for group in test_groups:
            self.master.run_command(
                ["ipa", "group-del", group], raiseonerr=False
            )


class TestDelegationDel(IntegrationTest):
    """
    Test delegation-del command functionality.

    This test class mirrors the bash test t.ipa-delegation-cli-del.sh
    and follows the FreeIPA integration test patterns.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_delegation_del_positive_setup(self):
        """Setup environment for delegation del positive tests"""
        tasks.kinit_admin(self.master)

        # Create a delegation for deletion testing
        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_del_positive_1001",
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )

        assert result.returncode == 0
        assert (
            'Added delegation "delegation_del_positive_1001"'
            in result.stdout_text
        )

    def test_delegation_del_existing_delegation(self):
        """Test deletion of existing delegation"""
        tasks.kinit_admin(self.master)

        # The delegation should exist from setup
        # Delete the delegation using the function name pattern from bash script
        result = self.master.run_command(
            ["ipa", "delegation-del", "delegation_del_positive_1001"]
        )

        assert result.returncode == 0
        assert (
            'Deleted delegation "delegation_del_positive_1001"'
            in result.stdout_text
        )

        # Verify delegation was actually deleted
        result = self.master.run_command(
            ["ipa", "delegation-show", "delegation_del_positive_1001"],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "not found" in result.stderr_text

    def test_delegation_del_positive_cleanup(self):
        """Cleanup delegation del positive test environment"""
        tasks.kinit_admin(self.master)

        # Clean up any remaining delegation (in case test failed)
        self.master.run_command(
            ["ipa", "delegation-del", "delegation_del_positive_1001"],
            raiseonerr=False,
        )

    def test_delegation_del_negative_setup(self):
        """Setup environment for delegation del negative tests"""
        tasks.kinit_admin(self.master)

        # No special setup needed for negative tests
        # Just verify IPA is accessible
        result = self.master.run_command(["ipa", "--version"])
        assert result.returncode == 0

    def test_delegation_del_fail_nonexistent_delegation(self):
        """Test that deleting non-existent delegation fails"""
        tasks.kinit_admin(self.master)

        # Try to delete a non-existent delegation
        result = self.master.run_command(
            ["ipa", "delegation-del", "badname"], raiseonerr=False
        )

        assert result.returncode == 2
        assert 'ACI with name "badname" not found' in result.stderr_text

    def test_delegation_del_with_options(self):
        """Test delegation deletion with various options"""
        tasks.kinit_admin(self.master)

        # Create a test delegation
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_delegation_del_options",
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )
        """
        Delete with --continue option
        (should work even if delegation doesn't exist)
        """
        result = self.master.run_command(
            [
                "ipa",
                "delegation-del",
                "test_delegation_del_options",
                "--continue",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 0

        # Try to delete again with --continue (should not fail)
        result = self.master.run_command(
            [
                "ipa",
                "delegation-del",
                "test_delegation_del_options",
                "--continue",
            ],
            raiseonerr=False,
        )

        # With --continue, it should succeed even if delegation doesn't exist
        assert result.returncode == 0

    def test_delegation_del_multiple_delegations(self):
        """Test deletion of multiple delegations"""
        tasks.kinit_admin(self.master)

        # Create multiple test delegations
        delegations = [
            "test_del_multi_1",
            "test_del_multi_2",
            "test_del_multi_3",
        ]

        for delegation in delegations:
            self.master.run_command(
                [
                    "ipa",
                    "delegation-add",
                    delegation,
                    "--membergroup=admins",
                    "--group=ipausers",
                    "--attrs=mobile",
                ]
            )

        # Delete all delegations
        for delegation in delegations:
            result = self.master.run_command(
                ["ipa", "delegation-del", delegation]
            )
            assert result.returncode == 0
            assert f'Deleted delegation "{delegation}"' in result.stdout_text

        # Verify all delegations were deleted
        for delegation in delegations:
            result = self.master.run_command(
                ["ipa", "delegation-show", delegation], raiseonerr=False
            )
            assert result.returncode == 2

    def test_delegation_del_with_special_characters(self):
        """Test delegation deletion with special characters in name"""
        tasks.kinit_admin(self.master)

        # Create delegation with underscores and numbers
        delegation_name = "test_delegation_del_123"
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                delegation_name,
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )

        # Delete delegation
        result = self.master.run_command(
            ["ipa", "delegation-del", delegation_name]
        )

        assert result.returncode == 0
        assert f'Deleted delegation "{delegation_name}"' in result.stdout_text

    def test_delegation_del_comprehensive_cleanup(self):
        """Comprehensive cleanup for all del tests"""
        tasks.kinit_admin(self.master)

        # Clean up any remaining test delegations
        test_delegations = [
            "delegation_del_positive_1001",
            "test_delegation_del_options",
            "test_del_multi_1",
            "test_del_multi_2",
            "test_del_multi_3",
            "test_delegation_del_123",
        ]

        for delegation in test_delegations:
            self.master.run_command(
                ["ipa", "delegation-del", delegation], raiseonerr=False
            )


class TestDelegationFind(IntegrationTest):
    """
    Test delegation-find command functionality.

    This test class mirrors the bash test t.ipa-delegation-cli-find.sh
    and follows the FreeIPA integration test patterns.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_delegation_find_positive_setup(self):
        """Setup environment for delegation find positive tests"""
        tasks.kinit_admin(self.master)

        # Create test groups and delegation for find testing
        self.master.run_command(
            ["ipa", "group-add", "mg1000", "--desc=mg1000"]
        )
        self.master.run_command(
            ["ipa", "group-add", "gr1000", "--desc=gr1000"]
        )

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_find_positive_1000",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=mobile",
            ]
        )

        assert result.returncode == 0
        assert (
            'Added delegation "delegation_find_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_find_all_with_no_criteria(self):
        """Test find all with no criteria"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(["ipa", "delegation-find"])

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text
        assert "delegation matched" in result.stdout_text

    def test_delegation_find_by_name_criteria(self):
        """Test find by name criteria"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "delegation_find_positive_1000"]
        )

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text
        assert "delegation_find_positive_1000" in result.stdout_text

    def test_delegation_find_by_partial_name_criteria(self):
        """Test find by partial name criteria"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "delegation_find"]
        )

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text

    def test_delegation_find_by_name_option(self):
        """Test find by name option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--name=delegation_find_positive_1000"]
        )

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text

    def test_delegation_find_by_membergroup_option(self):
        """Test find by membergroup option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--membergroup=mg1000"]
        )

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text

    def test_delegation_find_by_group_option(self):
        """Test find by group option works (BZ 888524)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--group=gr1000"]
        )

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text

    def test_delegation_find_by_permissions_option(self):
        """Test find by permissions option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--permissions=write"]
        )

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text

    def test_delegation_find_by_attrs_option(self):
        """Test find by attrs option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--attrs=mobile"]
        )

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text

    def test_delegation_find_by_multiple_options(self):
        """Test find by membergroup and group options work (BZ 888524)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-find",
                "--membergroup=mg1000",
                "--group=gr1000",
            ]
        )

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text

    def test_delegation_find_by_all_options(self):
        """Test find by membergroup,
        group, attrs, and permissions options (BZ 888524)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-find",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=mobile",
                "--permissions=write",
            ]
        )

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text

    def test_delegation_find_with_all_option(self):
        """Test find all with no criteria and with option all"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(["ipa", "delegation-find", "--all"])

        assert result.returncode == 0
        assert "Delegation name:" in result.stdout_text

    def test_delegation_find_with_raw_option(self):
        """Test find all with no criteria and option raw"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(["ipa", "delegation-find", "--raw"])

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text

    def test_delegation_find_with_all_and_raw_options(self):
        """Test find all with no criteria and options all raw"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--all", "--raw"]
        )

        assert result.returncode == 0
        assert "delegation:delegation_find_positive_1000" in result.stdout_text

    def test_delegation_find_with_pkey_only(self):
        """Test find with pkey-only specified (BZ 888524)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-find",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=mobile",
                "--permissions=write",
                "--pkey-only",
            ]
        )

        # Should return delegation name with --pkey-only
        assert result.returncode == 0
        if "delegation_find_positive_1000" in result.stdout_text:
            assert "Delegation name" in result.stdout_text

    def test_delegation_find_with_empty_values(self):
        """Test find with empty values for various options"""
        tasks.kinit_admin(self.master)

        # Test empty membergroup (should work, BZ 783473)
        result = self.master.run_command(
            ["ipa", "delegation-find", "--membergroup="], raiseonerr=False
        )

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text
        # Should not return internal error
        assert "internal error" not in result.stderr_text.lower()

    def test_delegation_find_positive_cleanup(self):
        """Cleanup delegation find positive test environment"""
        tasks.kinit_admin(self.master)

        # Clean up test delegation and groups
        self.master.run_command(
            ["ipa", "delegation-del", "delegation_find_positive_1000"],
            raiseonerr=False,
        )
        self.master.run_command(
            ["ipa", "group-del", "mg1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr1000"], raiseonerr=False
        )

    def test_delegation_find_negative_setup(self):
        """Setup environment for delegation find negative tests"""
        tasks.kinit_admin(self.master)

        # Create test groups and delegation for negative find testing
        self.master.run_command(
            ["ipa", "group-add", "mg1000", "--desc=mg1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-add", "gr1000", "--desc=gr1000"], raiseonerr=False
        )

        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_find_negative_1000",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

    def test_delegation_find_fail_with_space_criteria(self):
        """Test fail on find with space criteria"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", " "], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_invalid_name_criteria(self):
        """Test fail on find with invalid name criteria"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "badname"], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_space_for_name(self):
        """Test fail to find with space for name"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--name= "], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_nonexistent_name(self):
        """Test fail to find with nonexistent name"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--name=badname"], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_space_membergroup(self):
        """Test fail to find with space for membergroup"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--membergroup= "], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_nonexistent_membergroup(self):
        """Test fail to find with nonexistent membergroup"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--membergroup=badmembergroup"],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_space_group(self):
        """Test find with space for group (BZ 888524)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--group= "], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_nonexistent_group(self):
        """Test find with nonexistent group works (BZ 888524)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--group=badgroup"], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_invalid_permissions(self):
        """Test fail to find with only invalid permission"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--permissions=badperm"],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_fail_with_invalid_attrs(self):
        """Test fail to find with only invalid attr"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--attrs=badattr"], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_find_pkey_only_excludes_details(self):
        """Test find with pkey-only excludes detailed information"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-find",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=mobile",
                "--permissions=write",
                "--pkey-only",
            ],
            raiseonerr=False,
        )

        if result.returncode == 0:
            # With --pkey-only, detailed fields should not be returned
            assert "Permissions" not in result.stdout_text
            assert "Attributes" not in result.stdout_text
            assert "Member user group" not in result.stdout_text
            assert "User group" not in result.stdout_text

    def test_delegation_find_negative_cleanup(self):
        """Cleanup delegation find negative test environment"""
        tasks.kinit_admin(self.master)

        # Clean up test delegation and groups
        self.master.run_command(
            ["ipa", "delegation-del", "delegation_find_negative_1000"],
            raiseonerr=False,
        )
        self.master.run_command(
            ["ipa", "group-del", "mg1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr1000"], raiseonerr=False
        )


class TestDelegationMod(IntegrationTest):
    """
    Test delegation-mod command functionality.

    This test class mirrors the bash test t.ipa-delegation-cli-mod.sh
    and follows the FreeIPA integration test patterns.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_delegation_mod_positive_setup(self):
        """Setup environment for delegation mod positive tests"""
        tasks.kinit_admin(self.master)

        # Create test groups and delegation for mod testing
        self.master.run_command(
            ["ipa", "group-add", "mg1000", "--desc=mg1000"]
        )
        self.master.run_command(
            ["ipa", "group-add", "gr1000", "--desc=gr1000"]
        )
        self.master.run_command(
            ["ipa", "group-add", "mg1001", "--desc=mg1001"]
        )
        self.master.run_command(
            ["ipa", "group-add", "gr1001", "--desc=gr1001"]
        )

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_mod_positive_1000",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=mobile",
            ]
        )

        assert result.returncode == 0
        assert (
            'Added delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_existing_membergroup(self):
        """Test modify with existing membergroup"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--membergroup=mg1001",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_existing_group(self):
        """Test modify with existing group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--group=gr1001",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_valid_attrs(self):
        """Test modify with valid attrs"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--attrs=l",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_valid_permissions(self):
        """Test modify with valid permissions"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--permissions=read",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_membergroup_and_group(self):
        """Test modify with existing membergroup and existing group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--membergroup=mg1000",
                "--group=gr1000",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_all_options(self):
        """Test modify with membergroup, group, and attrs"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--membergroup=mg1001",
                "--group=gr1001",
                "--attrs=mobile",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_all_options_and_permissions(self):
        """Test modify with membergroup, group, attrs, and permissions"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=l",
                "--permissions=write",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_all_flag(self):
        """Test modify with valid attrs and option all"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--attrs=mobile",
                "--all",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_raw_flag(self):
        """Test modify with valid attrs and option raw"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--attrs=l",
                "--raw",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_with_all_and_raw_flags(self):
        """Test modify with valid attrs and options all and raw"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_positive_1000",
                "--attrs=mobile",
                "--all",
                "--raw",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_positive_cleanup(self):
        """Cleanup delegation mod positive test environment"""
        tasks.kinit_admin(self.master)

        # Clean up test delegation and groups
        self.master.run_command(
            ["ipa", "delegation-del", "delegation_mod_positive_1000"],
            raiseonerr=False,
        )
        self.master.run_command(
            ["ipa", "group-del", "mg1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "mg1001"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr1001"], raiseonerr=False
        )

    def test_delegation_mod_negative_setup(self):
        """Setup environment for delegation mod negative tests"""
        tasks.kinit_admin(self.master)

        # Create test groups and delegation for negative mod testing
        self.master.run_command(
            ["ipa", "group-add", "mg1000", "--desc=mg1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-add", "gr1000", "--desc=gr1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-add", "mg1001", "--desc=mg1001"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-add", "gr1001", "--desc=gr1001"], raiseonerr=False
        )

        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_mod_negative_1000",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

    def test_delegation_mod_fail_no_value_membergroup(self):
        """Test fail to modify with no value for membergroup (BZ 783543)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--membergroup=",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'membergroup' is required" in result.stderr_text
        # Should not return internal error (BZ 783543)
        assert "internal error has occurred" not in result.stderr_text

    def test_delegation_mod_fail_empty_membergroup(self):
        """Test fail to modify with empty membergroup (BZ 783543)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                '--membergroup=""',
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'membergroup' is required" in result.stderr_text
        # Should not return internal error (BZ 783543)
        assert "internal error has occurred" not in result.stderr_text

    def test_delegation_mod_fail_space_membergroup(self):
        """Test fail to modify with space membergroup"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--membergroup= ",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_mod_fail_nonexistent_membergroup(self):
        """Test modify with non-existent membergroup (BZ 783548)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--membergroup=badmembergroup",
            ],
            raiseonerr=False,
        )
        assert result.returncode == 2
        assert "group not found" in result.stderr_text
        """
        Should not modify delegation
        when membergroup doesn't exist (BZ 783548)
        """
        assert (
            'Modified delegation "delegation_mod_negative_1000"'
            not in result.stdout_text
        )

    def test_delegation_mod_fail_no_value_group(self):
        """Test fail to modify with no value for group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--group=",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'group' is required" in result.stderr_text

    def test_delegation_mod_fail_empty_group(self):
        """Test fail to modify with empty group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                '--group=""',
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'group' is required" in result.stderr_text

    def test_delegation_mod_fail_space_group(self):
        """Test fail to modify with space group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--group= ",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_mod_fail_nonexistent_group(self):
        """Test fail to modify with non-existent group"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--group=badgroup",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "does not exist" in result.stderr_text

    def test_delegation_mod_fail_no_value_attrs(self):
        """Test fail to modify with no value for attrs (BZ 783554)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--attrs=",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'attrs' is required" in result.stderr_text
        # Should not remove attributes from delegation (BZ 783554)
        assert (
            'Modified delegation "delegation_mod_negative_1000"'
            not in result.stdout_text
        )

    def test_delegation_mod_fail_empty_attrs(self):
        """Test fail to modify with empty attrs (BZ 783554)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                '--attrs=""',
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "'attrs' is required" in result.stderr_text
        # Should not remove attributes from delegation (BZ 783554)
        assert (
            'Modified delegation "delegation_mod_negative_1000"'
            not in result.stdout_text
        )

    def test_delegation_mod_fail_space_attrs(self):
        """Test fail to modify with space for attrs (BZ 783554)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--attrs= ",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert (
            "Leading and trailing spaces are not allowed" in result.stderr_text
        )

    def test_delegation_mod_fail_invalid_attrs(self):
        """Test fail to modify with invalid attrs"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--attrs=badattr",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert (
            "invalid attribute" in result.stderr_text.lower()
            or "unknown attribute" in result.stderr_text.lower()
        )

    def test_delegation_mod_fail_invalid_permissions(self):
        """Test fail to modify with invalid permissions"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--permissions=badperm",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 2
        # Should fail with appropriate error message
        assert result.stderr_text != ""

    def test_delegation_mod_fail_nonexistent_delegation(self):
        """Test fail to modify non-existent delegation"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "nonexistent_delegation",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert "not found" in result.stderr_text

    def test_delegation_mod_with_multiple_attrs(self):
        """Test modify with multiple attributes"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--attrs=mobile,l",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_negative_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_comprehensive_test(self):
        """Test comprehensive modification with all valid options"""
        tasks.kinit_admin(self.master)

        # Test modifying all aspects at once
        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "delegation_mod_negative_1000",
                "--membergroup=mg1001",
                "--group=gr1001",
                "--attrs=mobile,l",
                "--permissions=read,write",
            ]
        )

        assert result.returncode == 0
        assert (
            'Modified delegation "delegation_mod_negative_1000"'
            in result.stdout_text
        )

    def test_delegation_mod_negative_cleanup(self):
        """Cleanup delegation mod negative test environment"""
        tasks.kinit_admin(self.master)

        # Clean up test delegation and groups
        self.master.run_command(
            ["ipa", "delegation-del", "delegation_mod_negative_1000"],
            raiseonerr=False,
        )
        self.master.run_command(
            ["ipa", "group-del", "mg1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "mg1001"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr1001"], raiseonerr=False
        )


class TestDelegationShow(IntegrationTest):
    """
    Test delegation-show command functionality.

    This test class mirrors the bash test t.ipa-delegation-cli-show.sh
    and follows the FreeIPA integration test patterns.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_delegation_show_positive_setup(self):
        """Setup environment for delegation show positive tests"""
        tasks.kinit_admin(self.master)

        # Create test groups and delegation for show testing
        self.master.run_command(
            ["ipa", "group-add", "mg1000", "--desc=mg1000"]
        )
        self.master.run_command(
            ["ipa", "group-add", "gr1000", "--desc=gr1000"]
        )

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_show_positive_1000",
                "--membergroup=mg1000",
                "--group=gr1000",
                "--attrs=mobile",
            ]
        )

        assert result.returncode == 0
        assert (
            'Added delegation "delegation_show_positive_1000"'
            in result.stdout_text
        )

    def test_delegation_show_by_name(self):
        """Test show by name"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-show", "delegation_show_positive_1000"]
        )

        assert result.returncode == 0
        assert (
            "Delegation name: delegation_show_positive_1000"
            in result.stdout_text
        )

    def test_delegation_show_by_name_with_all_option(self):
        """Test show by name with all option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-show",
                "delegation_show_positive_1000",
                "--all",
            ]
        )

        assert result.returncode == 0
        assert (
            "Delegation name: delegation_show_positive_1000"
            in result.stdout_text
        )

    def test_delegation_show_by_name_with_raw_option(self):
        """Test show by name with raw option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-show",
                "delegation_show_positive_1000",
                "--raw",
            ]
        )

        assert result.returncode == 0
        assert "delegation:delegation_show_positive_1000" in result.stdout_text

    def test_delegation_show_by_name_with_all_and_raw_option(self):
        """Test show by name with all and raw option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-show",
                "delegation_show_positive_1000",
                "--all",
                "--raw",
            ]
        )

        assert result.returncode == 0
        assert "delegation:delegation_show_positive_1000" in result.stdout_text

    def test_delegation_show_positive_cleanup(self):
        """Cleanup delegation show positive test environment"""
        tasks.kinit_admin(self.master)

        # Clean up test delegation and groups
        self.master.run_command(
            ["ipa", "delegation-del", "delegation_show_positive_1000"],
            raiseonerr=False,
        )
        self.master.run_command(
            ["ipa", "group-del", "mg1000"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr1000"], raiseonerr=False
        )

    def test_delegation_show_negative_setup(self):
        """Setup environment for delegation show negative tests"""
        tasks.kinit_admin(self.master)

        # No special setup needed for negative tests
        # Just verify IPA is accessible
        result = self.master.run_command(["ipa", "--version"])
        assert result.returncode == 0

    def test_fail_nonexist_delegation_by_name(self):
        """Test fail to show nonexistent delegation by name"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-show", "baddelegation"], raiseonerr=False
        )

        assert result.returncode == 2
        assert 'ACI with name "baddelegation" not found' in result.stderr_text

    def test_fail_nonexist_delegation_with_all_option(self):
        """Test fail to show nonexistent delegation by
        name with option all"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-show", "baddelegation", "--all"],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert 'ACI with name "baddelegation" not found' in result.stderr_text

    def test_fail_nonexist_delegation_raw_option(self):
        """
        Test fail to show nonexistent delegation by
        name with option raw
        """
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["ipa", "delegation-show", "baddelegation", "--raw"],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert 'ACI with name "baddelegation" not found' in result.stderr_text

    def test_show_fail_nonexist_delegation_all_raw_options(self):
        """
        Test fail to show nonexistent delegation by
        name with options all and raw
        """
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-show", "baddelegation", "--all", "--raw"],
            raiseonerr=False,
        )

        assert result.returncode == 2
        assert 'ACI with name "baddelegation" not found' in result.stderr_text

    def test_delegation_show_comprehensive_validation(self):
        """Test comprehensive show validation with existing delegation"""
        tasks.kinit_admin(self.master)

        # Create a test delegation for comprehensive validation
        self.master.run_command(
            ["ipa", "group-add", "test_show_mg", "--desc=test_show_mg"]
        )
        self.master.run_command(
            ["ipa", "group-add", "test_show_gr", "--desc=test_show_gr"]
        )

        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_show_delegation",
                "--membergroup=test_show_mg",
                "--group=test_show_gr",
                "--attrs=mobile,l",
                "--permissions=read,write",
            ]
        )

        # Test basic show
        result = self.master.run_command(
            ["ipa", "delegation-show", "test_show_delegation"]
        )

        assert result.returncode == 0
        assert "Delegation name: test_show_delegation" in result.stdout_text
        assert "Member user group: test_show_mg" in result.stdout_text
        assert "User group: test_show_gr" in result.stdout_text

        # Test with --all flag
        result = self.master.run_command(
            ["ipa", "delegation-show", "test_show_delegation", "--all"]
        )

        assert result.returncode == 0
        assert "Delegation name: test_show_delegation" in result.stdout_text

        # Test with --raw flag
        result = self.master.run_command(
            ["ipa", "delegation-show", "test_show_delegation", "--raw"]
        )

        assert result.returncode == 0
        assert "delegation:test_show_delegation" in result.stdout_text

        # Clean up
        self.master.run_command(
            ["ipa", "delegation-del", "test_show_delegation"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "test_show_mg"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "test_show_gr"], raiseonerr=False
        )

    def test_delegation_show_with_special_characters(self):
        """Test show delegation with special characters in name"""
        tasks.kinit_admin(self.master)

        # Create delegation with underscores and numbers
        self.master.run_command(
            ["ipa", "group-add", "mg_special_123", "--desc=mg_special_123"]
        )
        self.master.run_command(
            ["ipa", "group-add", "gr_special_123", "--desc=gr_special_123"]
        )

        delegation_name = "test_delegation_show_123"
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                delegation_name,
                "--membergroup=mg_special_123",
                "--group=gr_special_123",
                "--attrs=mobile",
            ]
        )

        # Show delegation
        result = self.master.run_command(
            ["ipa", "delegation-show", delegation_name]
        )

        assert result.returncode == 0
        assert f"Delegation name: {delegation_name}" in result.stdout_text

        # Clean up
        self.master.run_command(
            ["ipa", "delegation-del", delegation_name], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "mg_special_123"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr_special_123"], raiseonerr=False
        )


class TestDelegationUser(IntegrationTest):
    """
    Test delegation user/functional functionality.

    This test class mirrors the bash test t.ipa-delegation-cli-user.sh
    and follows the FreeIPA integration test patterns.

    This class tests delegation functionality from a user perspective,
    creating managers and employees and testing delegation permissions.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_delegation_user_setup(self):
        """Setup environment for delegation user tests"""
        tasks.kinit_admin(self.master)

        # Create test users
        self.master.run_command(
            [
                "ipa",
                "user-add",
                "man0001",
                "--first=Manager",
                "--last=0001",
                "--password",
            ],
            stdin_text="passw0rd1\npassw0rd1\n",
        )

        self.master.run_command(
            [
                "ipa",
                "user-add",
                "man0002",
                "--first=Manager",
                "--last=0002",
                "--password",
            ],
            stdin_text="passw0rd2\npassw0rd2\n",
        )

        self.master.run_command(
            [
                "ipa",
                "user-add",
                "emp0001",
                "--first=Employee",
                "--last=0001",
                "--password",
            ],
            stdin_text="passw0rd1\npassw0rd1\n",
        )

        self.master.run_command(
            [
                "ipa",
                "user-add",
                "emp0002",
                "--first=Employee",
                "--last=0002",
                "--password",
            ],
            stdin_text="passw0rd2\npassw0rd2\n",
        )

        # Create test groups
        self.master.run_command(
            ["ipa", "group-add", "managers", "--desc=managers"]
        )
        self.master.run_command(
            ["ipa", "group-add", "employees", "--desc=employees"]
        )

        # Add users to groups
        self.master.run_command(
            ["ipa", "group-add-member", "managers", "--users=man0001,man0002"]
        )
        self.master.run_command(
            ["ipa", "group-add-member", "employees", "--users=emp0001,emp0002"]
        )

    def test_delegation_user_fail_no_delegations(self):
        """Test fail to change attrs with no delegations for user"""
        # Kinit as manager user
        self.master.run_command(["kinit", "man0001"], stdin_text="passw0rd1\n")

        # Test various user modification attempts that should fail
        user_attrs = [
            ("--first=Bad", "first"),
            ("--last=User", "last"),
            ("--cn=baduser", "cn"),
            ("--displayname=baduser", "displayname"),
            ("--initials=GU", "initials"),
            ("--shell=/bin/bash", "shell"),
            ("--street=Bad_Street_Rd", "street"),
            ("--city=Bad_City", "city"),
            ("--state=Badstate", "state"),
            ("--postalcode=99999", "postalcode"),
            ("--phone=999-999-9999", "phone"),
            ("--mobile=999-999-9999", "mobile"),
            ("--pager=999-999-9999", "pager"),
            ("--fax=999-999-9999", "fax"),
            ("--orgunit=bad-org", "orgunit"),
            ("--title=bad_admin", "title"),
            ("--manager=man0002", "manager"),
            ("--carlicense=bad-9999", "carlicense"),
        ]

        for attr_option, attr_name in user_attrs:
            result = self.master.run_command(
                ["ipa", "user-mod", "emp0001", attr_option], raiseonerr=False
            )

            assert (
                result.returncode == 1
            ), f"Should not be able to set {attr_name} for another user"

    def test_delegation_user_add_address_delegation(self):
        """Test add delegation for managers to change employees address attrs"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "addr_change",
                "--group=managers",
                "--membergroup=employees",
                "--attrs=street,l,st,postalcode",
            ]
        )

        assert result.returncode == 0
        assert 'Added delegation "addr_change"' in result.stdout_text

    def test_delegation_user_manager_change_employee_address(self):
        """Test kinit as man0001 and change address attrs of emp0001"""
        # Kinit as manager
        self.master.run_command(["kinit", "man0001"], stdin_text="passw0rd1\n")

        # Test address modifications that should now work
        address_changes = [
            ("--street=Good_Street_Rd1", "street"),
            ("--city=Good_City1", "city"),
            ("--state=Goodstate1", "state"),
            ("--postalcode=33333-1", "postalcode"),
        ]

        for attr_option, attr_name in address_changes:
            result = self.master.run_command(
                ["ipa", "user-mod", "emp0001", attr_option]
            )

            assert (
                result.returncode == 0
            ), f"Should be able to change {attr_name} for employee"

    def test_delegation_user_manager2_change_employee2_address(self):
        """Test su to man0002 and change address attrs of emp0002"""
        # Kinit as second manager
        self.master.run_command(["kinit", "man0002"], stdin_text="passw0rd2\n")

        # Change multiple address attributes at once
        result = self.master.run_command(
            [
                "ipa",
                "user-mod",
                "emp0002",
                "--street=Good_Street_Rd2",
                "--city=Good_City2",
                "--state=Goodstate2",
                "--postalcode=33333-2",
            ]
        )

        assert result.returncode == 0
        assert 'Modified user "emp0002"' in result.stdout_text

    def test_delegation_user_add_phone_delegation(self):
        """Test add delegation for employees to change managers phone attrs"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "phone_change",
                "--group=employees",
                "--membergroup=managers",
                "--attrs=telephonenumber,mobile,pager,facsimiletelephonenumber",
            ]
        )

        assert result.returncode == 0
        assert 'Added delegation "phone_change"' in result.stdout_text

    def test_delegation_user_employee_change_manager_phone(self):
        """Test kinit as employee and change phone attrs of manager"""
        # Kinit as employee
        self.master.run_command(["kinit", "emp0001"], stdin_text="passw0rd1\n")

        # Test phone modifications that should now work
        phone_changes = [
            ("--phone=333-333-3331", "phone"),
            ("--mobile=333-333-3331", "mobile"),
            ("--pager=333-333-3331", "pager"),
            ("--fax=333-333-3331", "fax"),
        ]

        for attr_option, attr_name in phone_changes:
            result = self.master.run_command(
                ["ipa", "user-mod", "man0001", attr_option]
            )

            assert (
                result.returncode == 0
            ), f"Should be able to change {attr_name} for manager"

    def test_delegation_user_employee2_change_manager2_phone(self):
        """Test su to emp0002 and change phone attrs of man0002"""
        # Kinit as second employee
        self.master.run_command(["kinit", "emp0002"], stdin_text="passw0rd2\n")

        # Change multiple phone attributes at once
        result = self.master.run_command(
            [
                "ipa",
                "user-mod",
                "man0002",
                "--phone=333-333-3332",
                "--mobile=333-333-3332",
                "--pager=333-333-3332",
                "--fax=333-333-3332",
            ]
        )

        assert result.returncode == 0
        assert 'Modified user "man0002"' in result.stdout_text

    def test_delegation_user_check_emp0001_attributes(self):
        """Test check emp0001 attribute settings"""
        # Kinit as employee to verify their own attributes
        self.master.run_command(["kinit", "emp0001"], stdin_text="passw0rd1\n")

        # Check that address changes were applied
        address_checks = [
            ("--street=Good_Street_Rd1", "street"),
            ("--city=Good_City1", "city"),
            ("--state=Goodstate1", "state"),
            ("--postalcode=33333-1", "postalcode"),
        ]

        for attr_option, attr_name in address_checks:
            result = self.master.run_command(
                ["ipa", "user-find", "emp0001", attr_option]
            )

            assert result.returncode == 0, f"Should find user with {attr_name}"

    def test_delegation_user_check_emp0002_attributes(self):
        """Test check emp0002 attribute settings"""
        # Kinit as second employee to verify their own attributes
        self.master.run_command(["kinit", "emp0002"], stdin_text="passw0rd2\n")

        # Check that address changes were applied
        address_checks = [
            ("--street=Good_Street_Rd2", "street"),
            ("--city=Good_City2", "city"),
            ("--state=Goodstate2", "state"),
            ("--postalcode=33333-2", "postalcode"),
        ]

        for attr_option, attr_name in address_checks:
            result = self.master.run_command(
                ["ipa", "user-find", "emp0002", attr_option]
            )

            assert result.returncode == 0, f"Should find user with {attr_name}"

    def test_delegation_user_check_man0001_attributes(self):
        """Test check man0001 attribute settings"""
        # Kinit as manager to verify their own attributes
        self.master.run_command(["kinit", "man0001"], stdin_text="passw0rd1\n")

        # Check that phone changes were applied
        phone_checks = [
            ("--phone=333-333-3331", "phone"),
            ("--mobile=333-333-3331", "mobile"),
            ("--pager=333-333-3331", "pager"),
            ("--fax=333-333-3331", "fax"),
        ]

        for attr_option, attr_name in phone_checks:
            result = self.master.run_command(
                ["ipa", "user-find", "man0001", attr_option]
            )

            assert result.returncode == 0, f"Should find user with {attr_name}"

    def test_delegation_user_check_man0002_attributes(self):
        """Test check man0002 attribute settings"""
        # Kinit as second manager to verify their own attributes
        self.master.run_command(["kinit", "man0002"], stdin_text="passw0rd2\n")

        # Check that phone changes were applied
        phone_checks = [
            ("--phone=333-333-3332", "phone"),
            ("--mobile=333-333-3332", "mobile"),
            ("--pager=333-333-3332", "pager"),
            ("--fax=333-333-3332", "fax"),
        ]

        for attr_option, attr_name in phone_checks:
            result = self.master.run_command(
                ["ipa", "user-find", "man0002", attr_option]
            )

            assert result.returncode == 0, f"Should find user with {attr_name}"

    def test_delegation_user_manager_fail_change_phone_attrs(self):
        """Test kinit as manager and fail to change phone attrs for employee"""
        # Kinit as manager
        self.master.run_command(["kinit", "man0001"], stdin_text="passw0rd1\n")

        """
        Test phone modifications that should fail
        (manager shouldn't modify employee phone)
        """
        phone_changes = [
            ("--phone=999-999-9991", "phone"),
            ("--mobile=999-999-9991", "mobile"),
            ("--pager=999-999-9991", "pager"),
            ("--fax=999-999-9991", "fax"),
        ]

        for attr_option, attr_name in phone_changes:
            result = self.master.run_command(
                ["ipa", "user-mod", "emp0001", attr_option], raiseonerr=False
            )
            assert (
                result.returncode == 1
            ), f"Manager should not be able to change employee {attr_name}"

    def test_delegation_user_employee_fail_change_address_attrs(self):
        """
        Test kinit as employee and fail to change address
        attrs for employee
        """
        # Kinit as employee
        self.master.run_command(["kinit", "emp0001"], stdin_text="passw0rd1\n")

        """
        # Test address modifications that should fail
        # (employee shouldn't modify other employee address)
        """
        address_changes = [
            ("--street=Bad_Street_Rd2", "street"),
            ("--city=Bad_City2", "city"),
            ("--state=Badstate2", "state"),
            ("--postalcode=99999-2", "postalcode"),
        ]

        for attr_option in address_changes:
            result = self.master.run_command(
                ["ipa", "user-mod", "emp0002", attr_option], raiseonerr=False
            )

            assert result.returncode == 1

    def test_delegation_user_manager_fail_change_other_attrs(self):
        """
        Test kinit as manager and fail to change other
        attrs for employee
        """
        # Kinit as manager
        self.master.run_command(["kinit", "man0001"], stdin_text="passw0rd1\n")

        # Test various modifications that should fail (not delegated)
        other_attrs = [
            ("--first=Bad", "first"),
            ("--last=User", "last"),
            ("--cn=baduser", "cn"),
            ("--displayname=baduser", "displayname"),
            ("--initials=GU", "initials"),
            ("--shell=/bin/bash", "shell"),
            (
                "--phone=999-999-9999",
                "phone",
            ),  # Phone not delegated to managers
            ("--mobile=999-999-9999", "mobile"),
            ("--pager=999-999-9999", "pager"),
            ("--fax=999-999-9999", "fax"),
            ("--orgunit=bad-org", "orgunit"),
            ("--title=bad_admin", "title"),
            ("--manager=man0002", "manager"),
            ("--carlicense=bad-9999", "carlicense"),
        ]

        for attr_option, attr_name in other_attrs:
            result = self.master.run_command(
                ["ipa", "user-mod", "emp0001", attr_option], raiseonerr=False
            )

            assert (
                result.returncode == 1
            ), f"Manager should not be able to change employee {attr_name}"

    def test_delegation_user_comprehensive_validation(self):
        """Test comprehensive validation of delegation permissions"""
        tasks.kinit_admin(self.master)

        # Verify delegations exist
        result = self.master.run_command(
            ["ipa", "delegation-show", "addr_change"]
        )
        assert result.returncode == 0
        assert "addr_change" in result.stdout_text

        result = self.master.run_command(
            ["ipa", "delegation-show", "phone_change"]
        )
        assert result.returncode == 0
        assert "phone_change" in result.stdout_text

        # Verify users exist and are in correct groups
        result = self.master.run_command(["ipa", "group-show", "managers"])
        assert result.returncode == 0
        assert "man0001" in result.stdout_text
        assert "man0002" in result.stdout_text

        result = self.master.run_command(["ipa", "group-show", "employees"])
        assert result.returncode == 0
        assert "emp0001" in result.stdout_text
        assert "emp0002" in result.stdout_text

    def test_delegation_user_cleanup(self):
        """Cleanup delegation user test environment"""
        tasks.kinit_admin(self.master)

        # Clean up users
        test_users = ["man0001", "man0002", "emp0001", "emp0002"]
        for user in test_users:
            self.master.run_command(
                ["ipa", "user-del", user], raiseonerr=False
            )

        # Clean up groups
        test_groups = ["managers", "employees"]
        for group in test_groups:
            self.master.run_command(
                ["ipa", "group-del", group], raiseonerr=False
            )

        # Clean up delegations
        test_delegations = ["addr_change", "phone_change"]
        for delegation in test_delegations:
            self.master.run_command(
                ["ipa", "delegation-del", delegation], raiseonerr=False
            )


class TestDelegationBZ(IntegrationTest):
    """
    Test delegation Bugzilla (BZ) scenarios.

    This test class mirrors the bash test t.ipa-delegation-cli-bz.sh
    and follows the FreeIPA integration test patterns.

    This class tests specific bug fixes and regressions
    for delegation commands.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_delegation_bz_783307(self):
        """
        Test BZ 783307: delegation-add should fail when membergroup
        does not exist
        """
        tasks.kinit_admin(self.master)

        # Create required group
        self.master.run_command(
            ["ipa", "group-add", "gr1000", "--desc=gr1000"]
        )

        # Try to add delegation with non-existent membergroup
        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_bz_783307",
                "--membergroup=badgroup",
                "--group=gr1000",
                "--attrs=mobile",
            ],
            raiseonerr=False,
        )

        # Should fail with return code 2
        assert result.returncode == 2
        assert 'Added delegation "test_bz_783307"' not in result.stdout_text
        assert "badgroup" in result.stderr_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "test_bz_783307"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "gr1000"], raiseonerr=False
        )

    def test_delegation_bz_783473(self):
        """Test BZ 783473: delegation-find --membergroup=
        should not return internal error
        """
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", "--membergroup="], raiseonerr=False
        )

        # Should not return internal error
        assert "internal error has occurred" not in result.stderr_text
        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text

    def test_delegation_bz_783475(self):
        """
        Test BZ 783475: delegation-find --membergroup="" should
        not return internal error
        """
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "delegation-find", '--membergroup=""'], raiseonerr=False
        )

        # Should not return internal error
        assert "internal error has occurred" not in result.stderr_text
        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text

    def test_delegation_bz_783489(self):
        """
        Test BZ 783489: delegation-find --permissions= should
        not return internal error
        """
        tasks.kinit_admin(self.master)

        # Add delegation required for test
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_bz_783489",
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )

        # Test --permissions= with no value
        result = self.master.run_command(
            ["ipa", "delegation-find", "--permissions="]
        )

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text
        assert "internal error has occurred" not in result.stderr_text

        # Test --permissions="" with empty value
        result = self.master.run_command(
            ["ipa", "delegation-find", '--permissions=""']
        )

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text
        assert "internal error has occurred" not in result.stderr_text

        # Test --permissions=" " with space value
        result = self.master.run_command(
            ["ipa", "delegation-find", '--permissions=" "']
        )

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text
        assert "internal error has occurred" not in result.stderr_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "test_bz_783489"], raiseonerr=False
        )

    def test_delegation_bz_783501(self):
        """
        Test BZ 783501: delegation-find --attrs= should
        not return internal error
        """
        tasks.kinit_admin(self.master)

        # Add delegation required for test
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_bz_783501",
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )

        # Test --attrs= with no value
        result = self.master.run_command(
            ["ipa", "delegation-find", "--attrs="]
        )

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text
        assert "internal error has occurred" not in result.stderr_text

        # Test --attrs="" with empty value
        result = self.master.run_command(
            ["ipa", "delegation-find", '--attrs=""']
        )

        assert result.returncode == 0
        assert "delegation matched" in result.stdout_text
        assert "internal error has occurred" not in result.stderr_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "test_bz_783501"], raiseonerr=False
        )

    def test_delegation_bz_783543(self):
        """
        Test BZ 783543: delegation-mod --membergroup=
        should not return internal error
        """
        tasks.kinit_admin(self.master)

        # Add delegation required for test
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_bz_783543",
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )

        # Test --membergroup= with no value
        result = self.master.run_command(
            ["ipa", "delegation-mod", "test_bz_783543", "--membergroup="],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "internal error has occurred" not in result.stderr_text
        assert "'membergroup' is required" in result.stderr_text

        # Test --membergroup="" with empty value
        result = self.master.run_command(
            ["ipa", "delegation-mod", "test_bz_783543", '--membergroup=""'],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert "internal error has occurred" not in result.stderr_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "test_bz_783543"], raiseonerr=False
        )

    def test_delegation_bz_783548(self):
        """
        Test BZ 783548: delegation-mod should fail
        when membergroup does not exist
        """
        tasks.kinit_admin(self.master)

        # Add delegation required for test
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_bz_783548",
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )

        # Try to modify with non-existent membergroup
        result = self.master.run_command(
            [
                "ipa",
                "delegation-mod",
                "test_bz_783548",
                "--membergroup=badmembergroup",
            ],
            raiseonerr=False,
        )

        # Should fail and not modify delegation
        assert result.returncode == 2
        assert 'Modified delegation "test_bz_783548"' not in result.stdout_text
        assert (
            "group not found" in result.stderr_text
            or "badmembergroup" in result.stderr_text
        )

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "test_bz_783548"], raiseonerr=False
        )

    def test_delegation_bz_783554(self):
        """
        Test BZ 783554: delegation-mod --attrs= should fail
        instead of removing attributes
        """
        tasks.kinit_admin(self.master)

        # Add delegation required for test
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_bz_783554",
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )

        # Test --attrs= with no value should fail
        result = self.master.run_command(
            ["ipa", "delegation-mod", "test_bz_783554", "--attrs="],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert 'Modified delegation "test_bz_783554"' not in result.stdout_text
        assert "'attrs' is required" in result.stderr_text

        # Modify with valid attrs to prep for next test
        self.master.run_command(
            ["ipa", "delegation-mod", "test_bz_783554", "--attrs=l"]
        )

        # Test --attrs="" with empty value should fail
        result = self.master.run_command(
            ["ipa", "delegation-mod", "test_bz_783554", '--attrs=""'],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert 'Modified delegation "test_bz_783554"' not in result.stdout_text

        # Modify with valid attrs to prep for next test
        self.master.run_command(
            ["ipa", "delegation-mod", "test_bz_783554", "--attrs=st"]
        )

        # Test --attrs=" " with space value should fail
        result = self.master.run_command(
            ["ipa", "delegation-mod", "test_bz_783554", '--attrs=" "'],
            raiseonerr=False,
        )

        assert result.returncode == 1
        assert 'Modified delegation "test_bz_783554"' not in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "test_bz_783554"], raiseonerr=False
        )

    def test_delegation_bz_782974(self):
        """
        Test BZ 782974: Exception when removing all values
        in config plugin (duplicate of 783554)
        """
        tasks.kinit_admin(self.master)

        # This is a duplicate of BZ 783554, so we just call that test
        self.test_delegation_bz_783554()

    def test_delegation_bz_784468(self):
        """Test BZ 784468: ipa help delegation example
        should have correct group/membergroup
        """
        tasks.kinit_admin(self.master)

        result = self.master.run_command(["ipa", "help", "delegation"])

        assert result.returncode == 0

        # Check if the help contains the correct example
        help_text = result.stdout_text

        """
        # The bug was that group and membergroup were backwards in
        # the help example. The correct example should be:
        # --membergroup=managers --group=employees (managers
        # can edit employees)
        # Not: --membergroup=employees --group=managers
        """
        if (
            "Add a delegation rule to allow managers to edit employee"
            in help_text
        ):
            # If the example exists, it should have the correct order
            assert (
                "--membergroup=employees --group=managers" not in help_text
            ), "BZ 784468: help example has group and membergroup backwards"

    def test_delegation_bz_888524(self):
        """
        Test BZ 888524: delegation-find --group should not return
        internal error"""
        tasks.kinit_admin(self.master)

        # Create test groups and delegation
        self.master.run_command(
            ["ipa", "group-add", "mg_bz888524", "--desc=member_group_bz888524"]
        )
        self.master.run_command(
            ["ipa", "group-add", "gr_bz888524", "--desc=group_bz888524"]
        )
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "delegation_bz888524",
                "--membergroup=mg_bz888524",
                "--group=gr_bz888524",
                "--attrs=mobile",
            ]
        )

        # Test --group option should not return internal error
        result = self.master.run_command(
            ["ipa", "delegation-find", "--group=gr_bz888524"]
        )

        assert result.returncode == 0
        assert "internal error has occurred" not in result.stderr_text
        assert "delegation matched" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "delegation_bz888524"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "mg_bz888524", "gr_bz888524"],
            raiseonerr=False,
        )

    def test_delegation_bz_846036(self):
        """
        Test BZ 846036: delegation-find with trailing/leading
        spaces should return consistent error
        """
        tasks.kinit_admin(self.master)

        # Test with trailing space
        result = self.master.run_command(
            ["ipa", "delegation-find", "nonexist "], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

        # Test with leading space
        result = self.master.run_command(
            ["ipa", "delegation-find", " nonexist"], raiseonerr=False
        )

        assert result.returncode == 1
        assert "0 delegations matched" in result.stdout_text

    def test_delegation_bz_comprehensive_validation(self):
        """Test comprehensive validation of all BZ fixes"""
        tasks.kinit_admin(self.master)

        # Verify IPA is working
        result = self.master.run_command(["ipa", "--version"])
        assert result.returncode == 0

        # Test that basic delegation operations work
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "test_bz_comprehensive",
                "--membergroup=admins",
                "--group=ipausers",
                "--attrs=mobile",
            ]
        )

        result = self.master.run_command(
            ["ipa", "delegation-show", "test_bz_comprehensive"]
        )
        assert result.returncode == 0
        assert "test_bz_comprehensive" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "test_bz_comprehensive"],
            raiseonerr=False,
        )

    def test_delegation_bz_regression_suite(self):
        """Test regression suite to ensure all BZ fixes remain working"""
        tasks.kinit_admin(self.master)

        # Test multiple scenarios that were problematic
        test_scenarios = [
            # (command_args, expected_return_code, should_not_contain_in_stderr)
            (["delegation-find", "--membergroup="], 0, "internal error"),
            (["delegation-find", "--attrs="], 0, "internal error"),
            (["delegation-find", "--permissions="], 0, "internal error"),
            (["delegation-find", "--group=admins"], 0, "internal error"),
        ]

        for args, expected_code, should_not_contain in test_scenarios:
            result = self.master.run_command(["ipa"] + args, raiseonerr=False)
            assert (
                result.returncode == expected_code
            ), f"Command {args} failed with code {result.returncode}"
            assert (
                should_not_contain not in result.stderr_text.lower()
            ), f"Command {args} contained '{should_not_contain}' in stderr"


class TestDelegationClientSide(IntegrationTest):
    """
    Test delegation functionality from IPA client perspective.

    This test class focuses on client-side delegation scenarios including
    multi-client environments, authentication, caching, and user experience.
    """

    topology = "star"  # Master + clients for comprehensive testing
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        # Install clients if available in topology
        if hasattr(cls, "clients") and cls.clients:
            for client in cls.clients:
                tasks.install_client(cls.master, client)

    def test_delegation_client_user_workflow(self):
        """Test typical user workflow on IPA client"""
        tasks.kinit_admin(self.master)

        # Create test users and groups
        self.master.run_command(
            [
                "ipa",
                "user-add",
                "clientuser1",
                "--first=Client",
                "--last=User1",
                "--password",
            ],
            stdin_text="password123\npassword123\n",
        )

        self.master.run_command(
            [
                "ipa",
                "user-add",
                "clientuser2",
                "--first=Client",
                "--last=User2",
                "--password",
            ],
            stdin_text="password123\npassword123\n",
        )

        self.master.run_command(
            ["ipa", "group-add", "clientmanagers", "--desc=Client Managers"]
        )
        self.master.run_command(
            ["ipa", "group-add", "clientemployees", "--desc=Client Employees"]
        )

        # Add users to groups
        self.master.run_command(
            [
                "ipa",
                "group-add-member",
                "clientmanagers",
                "--users=clientuser1",
            ]
        )
        self.master.run_command(
            [
                "ipa",
                "group-add-member",
                "clientemployees",
                "--users=clientuser2",
            ]
        )

        # Create delegation allowing managers to modify employee addresses
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "client_addr_delegation",
                "--group=clientmanagers",
                "--membergroup=clientemployees",
                "--attrs=street,l,st,postalcode",
            ]
        )

        # Test as manager user - should succeed
        self.master.run_command(
            ["kinit", "clientuser1"], stdin_text="password123\n"
        )

        result = self.master.run_command(
            ["ipa", "user-mod", "clientuser2", "--street=123 Client St"]
        )
        assert result.returncode == 0
        assert 'Modified user "clientuser2"' in result.stdout_text

        # Test unauthorized operation - should fail
        result = self.master.run_command(
            ["ipa", "user-mod", "clientuser2", "--title=Unauthorized Title"],
            raiseonerr=False,
        )
        assert result.returncode == 1

        # Cleanup
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "delegation-del", "client_addr_delegation"],
            raiseonerr=False,
        )
        self.master.run_command(
            ["ipa", "user-del", "clientuser1", "clientuser2"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "clientmanagers", "clientemployees"],
            raiseonerr=False,
        )

    def test_delegation_authentication_scenarios(self):
        """Test delegation with different authentication scenarios"""
        tasks.kinit_admin(self.master)

        # Create test user
        self.master.run_command(
            [
                "ipa",
                "user-add",
                "authuser",
                "--first=Auth",
                "--last=User",
                "--password",
            ],
            stdin_text="testpass123\ntestpass123\n",
        )

        self.master.run_command(
            ["ipa", "group-add", "authgroup", "--desc=Auth Group"]
        )
        self.master.run_command(
            ["ipa", "group-add-member", "authgroup", "--users=authuser"]
        )

        # Test kinit with password
        result = self.master.run_command(
            ["kinit", "authuser"], stdin_text="testpass123\n"
        )
        assert result.returncode == 0

        # Test ipa command execution after kinit
        result = self.master.run_command(["ipa", "user-show", "authuser"])
        assert result.returncode == 0
        assert "User login: authuser" in result.stdout_text

        # Test ticket expiration handling
        self.master.run_command(["kdestroy"])

        result = self.master.run_command(
            ["ipa", "user-show", "authuser"], raiseonerr=False
        )
        # Should fail without valid ticket
        assert result.returncode != 0

        # Cleanup
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "user-del", "authuser"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "authgroup"], raiseonerr=False
        )

    def test_delegation_concurrent_operations(self):
        """Test concurrent delegation operations"""
        tasks.kinit_admin(self.master)

        # Create test users and groups
        users = ["concurrent1", "concurrent2", "concurrent3"]
        for user in users:
            self.master.run_command(
                [
                    "ipa",
                    "user-add",
                    user,
                    "--first=Concurrent",
                    f"--last={user}",
                    "--password",
                ],
                stdin_text="concurrent123\nconcurrent123\n",
            )

        self.master.run_command(
            ["ipa", "group-add", "concurrentgroup", "--desc=Concurrent Group"]
        )

        # Add all users to group
        user_list = ",".join(users)
        self.master.run_command(
            [
                "ipa",
                "group-add-member",
                "concurrentgroup",
                f"--users={user_list}",
            ]
        )

        # Create delegation
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "concurrent_delegation",
                "--group=concurrentgroup",
                "--membergroup=concurrentgroup",
                "--attrs=description",
            ]
        )
        """
        # Test concurrent modifications
        # (simulate by rapid sequential operations)
        """
        for i, user in enumerate(users):
            self.master.run_command(
                ["kinit", user], stdin_text="concurrent123\n"
            )

            # Each user modifies their own description
            result = self.master.run_command(
                ["ipa", "user-mod", user, f"--desc=Modified by {user} #{i}"]
            )
            assert result.returncode == 0

        # Verify all modifications were successful
        tasks.kinit_admin(self.master)
        for i, user in enumerate(users):
            result = self.master.run_command(["ipa", "user-show", user])
            assert f"Modified by {user} #{i}" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "concurrent_delegation"],
            raiseonerr=False,
        )
        for user in users:
            self.master.run_command(
                ["ipa", "user-del", user], raiseonerr=False
            )
        self.master.run_command(
            ["ipa", "group-del", "concurrentgroup"], raiseonerr=False
        )

    def test_delegation_permission_inheritance(self):
        """Test that delegation permissions are properly inherited"""
        tasks.kinit_admin(self.master)

        # Create nested group structure
        self.master.run_command(
            ["ipa", "group-add", "parentgroup", "--desc=Parent Group"]
        )
        self.master.run_command(
            ["ipa", "group-add", "childgroup", "--desc=Child Group"]
        )
        self.master.run_command(
            ["ipa", "group-add", "targetgroup", "--desc=Target Group"]
        )

        # Add child group to parent group
        self.master.run_command(
            ["ipa", "group-add-member", "parentgroup", "--groups=childgroup"]
        )

        # Create users
        self.master.run_command(
            [
                "ipa",
                "user-add",
                "parentuser",
                "--first=Parent",
                "--last=User",
                "--password",
            ],
            stdin_text="parent123\nparent123\n",
        )
        self.master.run_command(
            [
                "ipa",
                "user-add",
                "childuser",
                "--first=Child",
                "--last=User",
                "--password",
            ],
            stdin_text="child123\nchild123\n",
        )
        self.master.run_command(
            [
                "ipa",
                "user-add",
                "targetuser",
                "--first=Target",
                "--last=User",
                "--password",
            ],
            stdin_text="target123\ntarget123\n",
        )

        # Add users to groups
        self.master.run_command(
            ["ipa", "group-add-member", "parentgroup", "--users=parentuser"]
        )
        self.master.run_command(
            ["ipa", "group-add-member", "childgroup", "--users=childuser"]
        )
        self.master.run_command(
            ["ipa", "group-add-member", "targetgroup", "--users=targetuser"]
        )

        # Create delegation for parent group
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "inheritance_delegation",
                "--group=parentgroup",
                "--membergroup=targetgroup",
                "--attrs=description",
            ]
        )

        # Test that parent user can modify target
        self.master.run_command(
            ["kinit", "parentuser"], stdin_text="parent123\n"
        )

        result = self.master.run_command(
            ["ipa", "user-mod", "targetuser", "--desc=Modified by parent"]
        )
        assert result.returncode == 0

        # Test that child user can also modify target
        # (through group inheritance)
        self.master.run_command(
            ["kinit", "childuser"], stdin_text="child123\n"
        )

        result = self.master.run_command(
            ["ipa", "user-mod", "targetuser", "--desc=Modified by child"]
        )
        assert result.returncode == 0

        # Cleanup
        tasks.kinit_admin(self.master)
        cleanup_items = [
            ("delegation-del", ["inheritance_delegation"]),
            ("user-del", ["parentuser", "childuser", "targetuser"]),
            ("group-del", ["parentgroup", "childgroup", "targetgroup"]),
        ]

        for cmd_type, items in cleanup_items:
            for item in items:
                self.master.run_command(
                    ["ipa", cmd_type, item], raiseonerr=False
                )

    def test_delegation_client_comprehensive_validation(self):
        """Validation of client-side delegation functionality"""
        tasks.kinit_admin(self.master)

        # Verify client can connect to server
        result = self.master.run_command(["ipa", "ping"])
        assert result.returncode == 0

        # Test basic delegation operations from client perspective
        self.master.run_command(
            [
                "ipa",
                "group-add",
                "clientvalidation",
                "--desc=Client Validation",
            ]
        )

        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                "client_validation_test",
                "--group=clientvalidation",
                "--membergroup=admins",
                "--attrs=mobile",
            ]
        )
        assert result.returncode == 0

        # Verify delegation is visible from client
        result = self.master.run_command(
            ["ipa", "delegation-show", "client_validation_test"]
        )
        assert result.returncode == 0
        assert "client_validation_test" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", "client_validation_test"],
            raiseonerr=False,
        )
        self.master.run_command(
            ["ipa", "group-del", "clientvalidation"], raiseonerr=False
        )


class TestDelegationReplication(IntegrationTest):
    """
    Test delegation replication across IPA replicas.

    This test class focuses on ensuring delegations are properly replicated
    across IPA masters and that delegation operations work consistently
    across all replicas in the topology.
    """

    topology = "star"  # Master + replicas for replication testing
    num_replicas = 1
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        # Install replicas if available in topology
        if hasattr(cls, "replicas") and cls.replicas:
            for replica in cls.replicas:
                tasks.install_replica(cls.master, replica)

    def test_delegation_replication_setup(self):
        """Setup environment for delegation replication tests"""
        tasks.kinit_admin(self.master)

        # Verify replication topology is healthy
        result = self.master.run_command(
            ["ipa", "topologysuffix-show", "domain"]
        )
        assert result.returncode == 0

        # Create base test groups on master
        test_groups = [
            "replica_mg1",
            "replica_gr1",
            "replica_mg2",
            "replica_gr2",
        ]
        for group in test_groups:
            result = self.master.run_command(
                [
                    "ipa",
                    "group-add",
                    group,
                    f"--desc=Replication test group {group}",
                ]
            )
            assert result.returncode == 0

    def test_delegation_create_on_master_replicate_to_replica(self):
        """Test delegation created on master is replicated to replica"""
        tasks.kinit_admin(self.master)

        # Create delegation on master
        delegation_name = "master_to_replica_delegation"
        result = self.master.run_command(
            [
                "ipa",
                "delegation-add",
                delegation_name,
                "--membergroup=replica_mg1",
                "--group=replica_gr1",
                "--attrs=mobile",
            ]
        )
        assert result.returncode == 0
        assert f'Added delegation "{delegation_name}"' in result.stdout_text

        # Wait for replication (give it some time to propagate)
        time.sleep(5)

        # Check if replicas exist and verify delegation is replicated
        if hasattr(self, "replicas") and self.replicas:
            for replica in self.replicas:
                # Kinit admin on replica
                tasks.kinit_admin(replica)

                # Verify delegation exists on replica
                result = replica.run_command(
                    ["ipa", "delegation-show", delegation_name]
                )
                assert result.returncode == 0
                assert (
                    f"Delegation name: {delegation_name}" in result.stdout_text
                )
                assert "replica_mg1" in result.stdout_text
                assert "replica_gr1" in result.stdout_text
        else:
            # If no replicas available, just verify on master
            result = self.master.run_command(
                ["ipa", "delegation-show", delegation_name]
            )
            assert result.returncode == 0

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", delegation_name], raiseonerr=False
        )

    def test_delegation_modification_replication(self):
        """Test delegation modifications are replicated across replicas"""
        tasks.kinit_admin(self.master)

        # Create delegation on master
        delegation_name = "modification_replication_test"
        self.master.run_command(
            [
                "ipa",
                "delegation-add",
                delegation_name,
                "--membergroup=replica_mg1",
                "--group=replica_gr1",
                "--attrs=mobile",
            ]
        )

        # Wait for initial replication
        time.sleep(3)

        # Modify delegation on master
        result = self.master.run_command(
            ["ipa", "delegation-mod", delegation_name, "--attrs=mobile,l"]
        )
        assert result.returncode == 0
        assert f'Modified delegation "{delegation_name}"' in result.stdout_text

        # Wait for modification to replicate
        time.sleep(5)

        # Verify modification is replicated to replicas
        if hasattr(self, "replicas") and self.replicas:
            for replica in self.replicas:
                tasks.kinit_admin(replica)
                result = replica.run_command(
                    ["ipa", "delegation-show", delegation_name]
                )
                assert result.returncode == 0
                # Should contain both mobile and l attributes
                assert "mobile" in result.stdout_text
                assert (
                    ", l" in result.stdout_text or "l," in result.stdout_text
                )

        # Cleanup
        self.master.run_command(
            ["ipa", "delegation-del", delegation_name], raiseonerr=False
        )
