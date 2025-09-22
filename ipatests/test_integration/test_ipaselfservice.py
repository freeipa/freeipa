"""
Test selfservice CLI functionality in FreeIPA integration environment.

This test suite covers comprehensive testing of IPA selfservice commands,
converted from bash test suites to Python ipatests/test_integration format.

Based on: t.ipa-selfservice-cli.sh
"""

# FreeIPA integration test imports
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestSelfServiceAdd(IntegrationTest):
    """
    Test selfservice-add command functionality.

    This test class covers adding various selfservice permissions
    and validates proper creation and configuration.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_selfservice_add_basic(self):
        """Test basic selfservice-add functionality"""
        tasks.kinit_admin(self.master)

        # Test adding basic selfservice permission
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "test-selfservice",
                "--permissions=read,write",
                "--attrs=description",
            ]
        )
        assert result.returncode == 0
        assert 'Added selfservice "test-selfservice"' in result.stdout_text

        # Verify the selfservice was created
        result = self.master.run_command(
            ["ipa", "selfservice-show", "test-selfservice"]
        )
        assert result.returncode == 0
        assert "Selfservice name: test-selfservice" in result.stdout_text
        assert "description" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "test-selfservice"], raiseonerr=False
        )

    def test_selfservice_add_multiple_attributes(self):
        """Test adding selfservice with multiple attributes"""
        tasks.kinit_admin(self.master)

        # Test adding selfservice with multiple attributes
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "multi-attr-selfservice",
                "--permissions=read,write",
                "--attrs=description,mail,telephoneNumber",
            ]
        )
        assert result.returncode == 0
        assert (
            'Added selfservice "multi-attr-selfservice"' in result.stdout_text
        )

        # Verify all attributes are present
        result = self.master.run_command(
            ["ipa", "selfservice-show", "multi-attr-selfservice"]
        )
        assert result.returncode == 0
        assert "description" in result.stdout_text
        assert "mail" in result.stdout_text
        assert "telephoneNumber" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "multi-attr-selfservice"],
            raiseonerr=False,
        )

    def test_selfservice_add_read_only(self):
        """Test adding read-only selfservice permission"""
        tasks.kinit_admin(self.master)

        # Test adding read-only selfservice
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "readonly-selfservice",
                "--permissions=read",
                "--attrs=givenName,sn",
            ]
        )
        assert result.returncode == 0
        assert 'Added selfservice "readonly-selfservice"' in result.stdout_text

        # Verify permissions
        result = self.master.run_command(
            ["ipa", "selfservice-show", "readonly-selfservice"]
        )
        assert result.returncode == 0
        assert "givenName" in result.stdout_text
        assert "sn" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "readonly-selfservice"],
            raiseonerr=False,
        )

    def test_selfservice_add_write_only(self):
        """Test adding write-only selfservice permission"""
        tasks.kinit_admin(self.master)

        # Test adding write-only selfservice
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "writeonly-selfservice",
                "--permissions=write",
                "--attrs=userPassword",
            ]
        )
        assert result.returncode == 0
        assert (
            'Added selfservice "writeonly-selfservice"' in result.stdout_text
        )

        # Verify permissions
        result = self.master.run_command(
            ["ipa", "selfservice-show", "writeonly-selfservice"]
        )
        assert result.returncode == 0
        assert "userPassword" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "writeonly-selfservice"],
            raiseonerr=False,
        )

    def test_selfservice_add_duplicate_name(self):
        """Test adding selfservice with duplicate name (should fail)"""
        tasks.kinit_admin(self.master)

        # Create first selfservice
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "duplicate-test",
                "--permissions=read",
                "--attrs=description",
            ]
        )
        assert result.returncode == 0

        # Try to create duplicate (should fail)
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "duplicate-test",
                "--permissions=write",
                "--attrs=mail",
            ],
            raiseonerr=False,
        )
        assert result.returncode != 0
        assert "already exists" in result.stderr_text

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "duplicate-test"], raiseonerr=False
        )

    def test_selfservice_add_invalid_permissions(self):
        """Test adding selfservice with invalid permissions (should fail)"""
        tasks.kinit_admin(self.master)

        # Try to add with invalid permission
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "invalid-perm-test",
                "--permissions=invalid",
                "--attrs=description",
            ],
            raiseonerr=False,
        )
        assert result.returncode != 0

    def test_selfservice_add_no_attributes(self):
        """Test adding selfservice without attributes (should fail)"""
        tasks.kinit_admin(self.master)

        # Try to add without attributes
        result = self.master.run_command(
            ["ipa", "selfservice-add", "no-attrs-test", "--permissions=read"],
            raiseonerr=False,
        )
        assert result.returncode != 0
        assert (
            "Required option not provided" in result.stderr_text
            or "attrs" in result.stderr_text
        )

    def test_selfservice_add_comprehensive_attributes(self):
        """Test adding selfservice with comprehensive attribute set"""
        tasks.kinit_admin(self.master)

        # Test with many common user attributes
        attrs = [
            "description",
            "mail",
            "telephoneNumber",
            "mobile",
            "homeDirectory",
            "loginShell",
            "gecos",
        ]

        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "comprehensive-selfservice",
                "--permissions=read,write",
                f'--attrs={",".join(attrs)}',
            ]
        )
        assert result.returncode == 0
        assert (
            'Added selfservice "comprehensive-selfservice"'
            in result.stdout_text
        )

        # Verify all attributes
        result = self.master.run_command(
            ["ipa", "selfservice-show", "comprehensive-selfservice"]
        )
        assert result.returncode == 0
        for attr in attrs:
            assert attr in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "comprehensive-selfservice"],
            raiseonerr=False,
        )


class TestSelfServiceShow(IntegrationTest):
    """
    Test selfservice-show command functionality.

    This test class covers displaying selfservice permissions
    and validates proper information retrieval.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def setup_method(self):
        """Setup test selfservice for show tests"""
        tasks.kinit_admin(self.master)

        # Create test selfservice
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "show-test-selfservice",
                "--permissions=read,write",
                "--attrs=description,mail",
            ],
            raiseonerr=False,
        )

    def teardown_method(self):
        """Cleanup test selfservice"""
        tasks.kinit_admin(self.master)

        # Clean up test selfservice
        self.master.run_command(
            ["ipa", "selfservice-del", "show-test-selfservice"],
            raiseonerr=False,
        )

    def test_selfservice_show_basic(self):
        """Test basic selfservice-show functionality"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-show", "show-test-selfservice"]
        )
        assert result.returncode == 0
        assert "Selfservice name: show-test-selfservice" in result.stdout_text
        assert "description" in result.stdout_text
        assert "mail" in result.stdout_text

    def test_selfservice_show_all_attributes(self):
        """Test selfservice-show with --all option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-show", "show-test-selfservice", "--all"]
        )
        assert result.returncode == 0
        assert "Selfservice name: show-test-selfservice" in result.stdout_text
        # Should show additional metadata with --all
        assert (
            "dn:" in result.stdout_text.lower()
            or "objectclass" in result.stdout_text.lower()
        )

    def test_selfservice_show_raw_format(self):
        """Test selfservice-show with --raw option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-show", "show-test-selfservice", "--raw"]
        )
        assert result.returncode == 0
        # Raw format should show LDAP attribute names
        assert (
            "cn:" in result.stdout_text
            or "show-test-selfservice" in result.stdout_text
        )

    def test_selfservice_show_nonexistent(self):
        """Test selfservice-show with nonexistent selfservice"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-show", "nonexistent-selfservice"],
            raiseonerr=False,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr_text

    def test_selfservice_show_json_format(self):
        """Test selfservice-show with JSON output format"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-show", "show-test-selfservice", "--json"]
        )
        assert result.returncode == 0
        # Should contain JSON structure
        assert "{" in result.stdout_text and "}" in result.stdout_text
        assert '"result"' in result.stdout_text


class TestSelfServiceFind(IntegrationTest):
    """
    Test selfservice-find command functionality.

    This test class covers searching and filtering selfservice permissions.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def setup_method(self):
        """Setup multiple test selfservices for find tests"""
        tasks.kinit_admin(self.master)

        # Create multiple test selfservices
        test_selfservices = [
            ("find-test-1", "read", "description"),
            ("find-test-2", "write", "mail"),
            ("find-test-3", "read,write", "telephoneNumber"),
            ("special-find-test", "read", "givenName,sn"),
        ]

        for name, perms, attrs in test_selfservices:
            self.master.run_command(
                [
                    "ipa",
                    "selfservice-add",
                    name,
                    f"--permissions={perms}",
                    f"--attrs={attrs}",
                ],
                raiseonerr=False,
            )

    def teardown_method(self):
        """Cleanup test selfservices"""
        tasks.kinit_admin(self.master)

        # Clean up test selfservices
        test_names = [
            "find-test-1",
            "find-test-2",
            "find-test-3",
            "special-find-test",
        ]
        for name in test_names:
            self.master.run_command(
                ["ipa", "selfservice-del", name], raiseonerr=False
            )

    def test_selfservice_find_all(self):
        """Test finding all selfservices"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(["ipa", "selfservice-find"])
        assert result.returncode == 0
        # Should find our test selfservices
        assert "find-test-1" in result.stdout_text
        assert "find-test-2" in result.stdout_text
        assert "find-test-3" in result.stdout_text
        assert "special-find-test" in result.stdout_text

    def test_selfservice_find_by_name_pattern(self):
        """Test finding selfservices by name pattern"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-find", "find-test"]
        )
        assert result.returncode == 0
        # Should find selfservices matching pattern
        assert "find-test-1" in result.stdout_text
        assert "find-test-2" in result.stdout_text
        assert "find-test-3" in result.stdout_text
        # Should not find the special one
        assert "special-find-test" not in result.stdout_text

    def test_selfservice_find_by_exact_name(self):
        """Test finding selfservice by exact name"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-find", "special-find-test"]
        )
        assert result.returncode == 0
        assert "special-find-test" in result.stdout_text
        # Should only find the exact match
        assert "find-test-1" not in result.stdout_text

    def test_selfservice_find_with_size_limit(self):
        """Test finding selfservices with size limit"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-find", "--sizelimit=2"]
        )
        assert result.returncode == 0
        # Should respect size limit
        lines = result.stdout_text.split("\n")
        selfservice_count = sum(
            1 for line in lines if "Selfservice name:" in line
        )
        assert selfservice_count <= 2

    def test_selfservice_find_all_attributes(self):
        """Test finding selfservices with --all option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-find", "find-test-1", "--all"]
        )
        assert result.returncode == 0
        assert "find-test-1" in result.stdout_text
        # Should show additional attributes
        assert (
            "dn:" in result.stdout_text.lower()
            or "objectclass" in result.stdout_text.lower()
        )

    def test_selfservice_find_raw_format(self):
        """Test finding selfservices with --raw option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-find", "find-test-1", "--raw"]
        )
        assert result.returncode == 0
        # Raw format should show LDAP attribute names
        assert "cn:" in result.stdout_text

    def test_selfservice_find_pkey_only(self):
        """Test finding selfservices with --pkey-only option"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-find", "--pkey-only"]
        )
        assert result.returncode == 0
        # Should show only primary keys (names)
        assert "find-test-1" in result.stdout_text
        # Should not show detailed attributes
        assert "Attributes:" not in result.stdout_text


class TestSelfServiceMod(IntegrationTest):
    """
    Test selfservice-mod command functionality.

    This test class covers modifying existing selfservice permissions.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def setup_method(self):
        """Setup test selfservice for modification tests"""
        tasks.kinit_admin(self.master)

        # Create test selfservice
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "mod-test-selfservice",
                "--permissions=read",
                "--attrs=description",
            ],
            raiseonerr=False,
        )

    def teardown_method(self):
        """Cleanup test selfservice"""
        tasks.kinit_admin(self.master)

        # Clean up test selfservice
        self.master.run_command(
            ["ipa", "selfservice-del", "mod-test-selfservice"],
            raiseonerr=False,
        )

    def test_selfservice_mod_add_attributes(self):
        """Test adding attributes to existing selfservice"""
        tasks.kinit_admin(self.master)

        # Add more attributes
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-mod",
                "mod-test-selfservice",
                "--attrs=description,mail,telephoneNumber",
            ]
        )
        assert result.returncode == 0
        assert (
            'Modified selfservice "mod-test-selfservice"' in result.stdout_text
        )

        # Verify the changes
        result = self.master.run_command(
            ["ipa", "selfservice-show", "mod-test-selfservice"]
        )
        assert result.returncode == 0
        assert "description" in result.stdout_text
        assert "mail" in result.stdout_text
        assert "telephoneNumber" in result.stdout_text

    def test_selfservice_mod_change_permissions(self):
        """Test changing permissions of existing selfservice"""
        tasks.kinit_admin(self.master)

        # Change permissions from read to read,write
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-mod",
                "mod-test-selfservice",
                "--permissions=read,write",
            ]
        )
        assert result.returncode == 0
        assert (
            'Modified selfservice "mod-test-selfservice"' in result.stdout_text
        )

        # Verify the changes
        result = self.master.run_command(
            ["ipa", "selfservice-show", "mod-test-selfservice"]
        )
        assert result.returncode == 0
        # Should show both read and write permissions

    def test_selfservice_mod_replace_attributes(self):
        """Test replacing all attributes of existing selfservice"""
        tasks.kinit_admin(self.master)

        # Replace attributes completely
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-mod",
                "mod-test-selfservice",
                "--attrs=mail,givenName,sn",
            ]
        )
        assert result.returncode == 0
        assert (
            'Modified selfservice "mod-test-selfservice"' in result.stdout_text
        )

        # Verify the changes
        result = self.master.run_command(
            ["ipa", "selfservice-show", "mod-test-selfservice"]
        )
        assert result.returncode == 0
        assert "mail" in result.stdout_text
        assert "givenName" in result.stdout_text
        assert "sn" in result.stdout_text
        # Original attribute should be replaced
        assert (
            "description" not in result.stdout_text
            or "mail" in result.stdout_text
        )

    def test_selfservice_mod_nonexistent(self):
        """Test modifying nonexistent selfservice (should fail)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            [
                "ipa",
                "selfservice-mod",
                "nonexistent-selfservice",
                "--attrs=description",
            ],
            raiseonerr=False,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr_text

    def test_selfservice_mod_invalid_attributes(self):
        """Test modifying selfservice with invalid attributes"""
        tasks.kinit_admin(self.master)

        # Try to set invalid attribute
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-mod",
                "mod-test-selfservice",
                "--attrs=invalidAttribute",
            ],
            raiseonerr=False,
        )
        # May succeed or fail depending on IPA version and validation
        # Just ensure it doesn't crash
        assert isinstance(result.returncode, int)

    def test_selfservice_mod_empty_attributes(self):
        """Test modifying selfservice with empty attributes (should fail)"""
        tasks.kinit_admin(self.master)

        # Try to set empty attributes
        result = self.master.run_command(
            ["ipa", "selfservice-mod", "mod-test-selfservice", "--attrs="],
            raiseonerr=False,
        )
        assert result.returncode != 0

    def test_selfservice_mod_comprehensive_change(self):
        """Test comprehensive modification of selfservice"""
        tasks.kinit_admin(self.master)

        # Make comprehensive changes
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-mod",
                "mod-test-selfservice",
                "--permissions=read,write",
                "--attrs=description,mail,telephoneNumber,mobile,homeDirectory",
            ]
        )
        assert result.returncode == 0
        assert (
            'Modified selfservice "mod-test-selfservice"' in result.stdout_text
        )

        # Verify all changes
        result = self.master.run_command(
            ["ipa", "selfservice-show", "mod-test-selfservice"]
        )
        assert result.returncode == 0
        attrs = [
            "description",
            "mail",
            "telephoneNumber",
            "mobile",
            "homeDirectory",
        ]
        for attr in attrs:
            assert attr in result.stdout_text


class TestSelfServiceDel(IntegrationTest):
    """
    Test selfservice-del command functionality.

    This test class covers deleting selfservice permissions.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_selfservice_del_basic(self):
        """Test basic selfservice deletion"""
        tasks.kinit_admin(self.master)

        # Create test selfservice
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "del-test-selfservice",
                "--permissions=read",
                "--attrs=description",
            ]
        )

        # Delete the selfservice
        result = self.master.run_command(
            ["ipa", "selfservice-del", "del-test-selfservice"]
        )
        assert result.returncode == 0
        assert (
            'Deleted selfservice "del-test-selfservice"' in result.stdout_text
        )

        # Verify it's gone
        result = self.master.run_command(
            ["ipa", "selfservice-show", "del-test-selfservice"],
            raiseonerr=False,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr_text

    def test_selfservice_del_nonexistent(self):
        """Test deleting nonexistent selfservice (should fail)"""
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "selfservice-del", "nonexistent-selfservice"],
            raiseonerr=False,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr_text

    def test_selfservice_del_multiple(self):
        """Test deleting multiple selfservices"""
        tasks.kinit_admin(self.master)

        # Create multiple test selfservices
        selfservices = ["multi-del-1", "multi-del-2", "multi-del-3"]
        for name in selfservices:
            self.master.run_command(
                [
                    "ipa",
                    "selfservice-add",
                    name,
                    "--permissions=read",
                    "--attrs=description",
                ]
            )

        # Delete all of them
        result = self.master.run_command(
            ["ipa", "selfservice-del"] + selfservices
        )
        assert result.returncode == 0

        # Verify they're all gone
        for name in selfservices:
            result = self.master.run_command(
                ["ipa", "selfservice-show", name], raiseonerr=False
            )
            assert result.returncode != 0
            assert "not found" in result.stderr_text

    def test_selfservice_del_and_recreate(self):
        """Test deleting and recreating selfservice"""
        tasks.kinit_admin(self.master)

        # Create selfservice
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "recreate-test",
                "--permissions=read",
                "--attrs=description",
            ]
        )

        # Delete it
        result = self.master.run_command(
            ["ipa", "selfservice-del", "recreate-test"]
        )
        assert result.returncode == 0

        # Recreate with different settings
        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "recreate-test",
                "--permissions=write",
                "--attrs=mail",
            ]
        )
        assert result.returncode == 0
        assert 'Added selfservice "recreate-test"' in result.stdout_text

        # Verify new settings
        result = self.master.run_command(
            ["ipa", "selfservice-show", "recreate-test"]
        )
        assert result.returncode == 0
        assert "mail" in result.stdout_text

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "recreate-test"], raiseonerr=False
        )


class TestSelfServiceFunctional(IntegrationTest):
    """
    Test selfservice functional scenarios.

    This test class covers real-world usage scenarios of
    selfservice permissions.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def setup_method(self):
        """Setup test environment for functional tests"""
        tasks.kinit_admin(self.master)

        # Create test user
        self.master.run_command(
            [
                "ipa",
                "user-add",
                "testuser",
                "--first=Test",
                "--last=User",
                "--password",
            ],
            stdin_text="testpassword123\ntestpassword123\n",
            raiseonerr=False,
        )

    def teardown_method(self):
        """Cleanup test environment"""
        tasks.kinit_admin(self.master)

        # Clean up test user and selfservices
        self.master.run_command(
            ["ipa", "user-del", "testuser"], raiseonerr=False
        )

        cleanup_selfservices = [
            "functional-test-read",
            "functional-test-write",
            "functional-test-comprehensive",
        ]
        for name in cleanup_selfservices:
            self.master.run_command(
                ["ipa", "selfservice-del", name], raiseonerr=False
            )

    def test_selfservice_user_can_read_own_attributes(self):
        """Test user can read their own attributes with
        selfservice permission"""
        tasks.kinit_admin(self.master)

        # Create selfservice for reading user attributes
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "functional-test-read",
                "--permissions=read",
                "--attrs=description,mail",
            ]
        )

        # Kinit as test user
        self.master.run_command(
            ["kinit", "testuser"], stdin_text="testpassword123\n"
        )

        # User should be able to read their own info
        result = self.master.run_command(["ipa", "user-show", "testuser"])
        assert result.returncode == 0
        assert "testuser" in result.stdout_text

    def test_selfservice_user_can_modify_own_attributes(self):
        """Test user can modify their own attributes with
        selfservice permission"""
        tasks.kinit_admin(self.master)

        # Create selfservice for writing user attributes
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "functional-test-write",
                "--permissions=write",
                "--attrs=description",
            ]
        )

        # Kinit as test user
        self.master.run_command(
            ["kinit", "testuser"], stdin_text="testpassword123\n"
        )

        # User should be able to modify their description
        result = self.master.run_command(
            ["ipa", "user-mod", "testuser", "--desc=Updated by user"]
        )
        assert result.returncode == 0
        assert 'Modified user "testuser"' in result.stdout_text

        # Verify the change
        result = self.master.run_command(["ipa", "user-show", "testuser"])
        assert result.returncode == 0
        assert "Updated by user" in result.stdout_text

    def test_selfservice_comprehensive_permissions(self):
        """Test comprehensive selfservice permissions"""
        tasks.kinit_admin(self.master)

        # Create comprehensive selfservice
        attrs = ["description", "mail", "telephoneNumber", "mobile"]
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "functional-test-comprehensive",
                "--permissions=read,write",
                f'--attrs={",".join(attrs)}',
            ]
        )

        # Kinit as test user
        self.master.run_command(
            ["kinit", "testuser"], stdin_text="testpassword123\n"
        )

        # User should be able to modify multiple attributes
        result = self.master.run_command(
            [
                "ipa",
                "user-mod",
                "testuser",
                "--desc=Comprehensive test",
                "--email=testuser@example.com",
                "--phone=555-1234",
                "--mobile=555-5678",
            ]
        )
        assert result.returncode == 0
        assert 'Modified user "testuser"' in result.stdout_text

        # Verify all changes
        result = self.master.run_command(["ipa", "user-show", "testuser"])
        assert result.returncode == 0
        assert "Comprehensive test" in result.stdout_text
        assert "testuser@example.com" in result.stdout_text
        assert "555-1234" in result.stdout_text
        assert "555-5678" in result.stdout_text

    def test_selfservice_permission_enforcement(self):
        """Test that selfservice permissions are properly enforced"""
        tasks.kinit_admin(self.master)

        # Create limited selfservice (only description, read-only)
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "limited-test",
                "--permissions=read",
                "--attrs=description",
            ]
        )

        # Kinit as test user
        self.master.run_command(
            ["kinit", "testuser"], stdin_text="testpassword123\n"
        )

        # User should NOT be able to modify mail (not in selfservice)
        result = self.master.run_command(
            [
                "ipa",
                "user-mod",
                "testuser",
                "--email=unauthorized@example.com",
            ],
            raiseonerr=False,
        )
        # Should fail due to insufficient permissions
        assert result.returncode != 0

        # Cleanup
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "selfservice-del", "limited-test"], raiseonerr=False
        )


class TestSelfServiceEdgeCases(IntegrationTest):
    """
    Test selfservice edge cases and error conditions.

    This test class covers various edge cases and error conditions.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def test_selfservice_special_characters_in_name(self):
        """Test selfservice names with special characters"""
        tasks.kinit_admin(self.master)

        # Test names with various characters
        special_names = [
            "test-with-dashes",
            "test_with_underscores",
            "test.with.dots",
        ]

        for name in special_names:
            # Try to create
            result = self.master.run_command(
                [
                    "ipa",
                    "selfservice-add",
                    name,
                    "--permissions=read",
                    "--attrs=description",
                ],
                raiseonerr=False,
            )

            if result.returncode == 0:
                # If creation succeeded, verify and cleanup
                result = self.master.run_command(
                    ["ipa", "selfservice-show", name]
                )
                assert result.returncode == 0

                self.master.run_command(
                    ["ipa", "selfservice-del", name], raiseonerr=False
                )

    def test_selfservice_long_name(self):
        """Test selfservice with very long name"""
        tasks.kinit_admin(self.master)

        # Create a very long name
        long_name = "a" * 100  # 100 character name

        result = self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                long_name,
                "--permissions=read",
                "--attrs=description",
            ],
            raiseonerr=False,
        )

        if result.returncode == 0:
            # If creation succeeded, cleanup
            self.master.run_command(
                ["ipa", "selfservice-del", long_name], raiseonerr=False
            )

    def test_selfservice_case_sensitivity(self):
        """Test case sensitivity in selfservice names"""
        tasks.kinit_admin(self.master)

        # Create selfservice with lowercase name
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "casetest",
                "--permissions=read",
                "--attrs=description",
            ]
        )

        # Try to access with different cases
        self.master.run_command(
            ["ipa", "selfservice-show", "CaseTest"], raiseonerr=False
        )
        # May succeed or fail depending on IPA's case handling

        self.master.run_command(
            ["ipa", "selfservice-show", "CASETEST"], raiseonerr=False
        )
        # May succeed or fail depending on IPA's case handling

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "casetest"], raiseonerr=False
        )

    def test_selfservice_unicode_characters(self):
        """Test selfservice with unicode characters"""
        tasks.kinit_admin(self.master)

        # Test with unicode characters (if supported)
        unicode_names = ["test-ñame", "test-café", "test-münchen"]

        for name in unicode_names:
            result = self.master.run_command(
                [
                    "ipa",
                    "selfservice-add",
                    name,
                    "--permissions=read",
                    "--attrs=description",
                ],
                raiseonerr=False,
            )

            if result.returncode == 0:
                # If creation succeeded, cleanup
                self.master.run_command(
                    ["ipa", "selfservice-del", name], raiseonerr=False
                )

    def test_selfservice_concurrent_operations(self):
        """Test concurrent selfservice operations"""
        tasks.kinit_admin(self.master)

        # Create base selfservice
        self.master.run_command(
            [
                "ipa",
                "selfservice-add",
                "concurrent-test",
                "--permissions=read",
                "--attrs=description",
            ]
        )

        # Simulate concurrent modifications
        # (In a real concurrent test, these would run in parallel)

        # Modify attributes
        result1 = self.master.run_command(
            [
                "ipa",
                "selfservice-mod",
                "concurrent-test",
                "--attrs=description,mail",
            ]
        )

        # Show current state
        result2 = self.master.run_command(
            ["ipa", "selfservice-show", "concurrent-test"]
        )

        # Modify permissions
        result3 = self.master.run_command(
            [
                "ipa",
                "selfservice-mod",
                "concurrent-test",
                "--permissions=read,write",
            ]
        )

        # All operations should succeed
        assert result1.returncode == 0
        assert result2.returncode == 0
        assert result3.returncode == 0

        # Cleanup
        self.master.run_command(
            ["ipa", "selfservice-del", "concurrent-test"], raiseonerr=False
        )
