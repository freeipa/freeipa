#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for ipa-idrange-fix CLI.
"""

import logging
import re

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


logger = logging.getLogger(__name__)


class TestIpaIdrangeFix(IntegrationTest):
    @classmethod
    def install(cls, mh):
        super(TestIpaIdrangeFix, cls).install(mh)
        tasks.kinit_admin(cls.master)

    def test_no_issues(self):
        """Test ipa-idrange-fix command with no issues."""
        result = self.master.run_command(["ipa-idrange-fix", "--unattended"])

        expected_under1000 = "No IDs under 1000 found"
        expected_nochanges = "No changes proposed for existing ranges"
        expected_newrange = "No new ranges proposed"
        expected_noissues = "No changes proposed, nothing to do."
        assert expected_under1000 in result.stderr_text
        assert expected_nochanges in result.stderr_text
        assert expected_newrange in result.stderr_text
        assert expected_noissues in result.stderr_text

    def test_idrange_no_rid_bases(self):
        """Test ipa-idrange-fix command with IDrange with no RID bases."""
        self.master.run_command([
            "ipa",
            "idrange-add",
            "idrange_no_rid_bases",
            "--base-id", '10000',
            "--range-size", '20000',
        ])

        result = self.master.run_command(["ipa-idrange-fix", "--unattended"])
        expected_text = "RID bases updated for range 'idrange_no_rid_bases'"

        # Remove IDrange with no rid bases
        self.master.run_command(["ipa", "idrange-del", "idrange_no_rid_bases"])

        assert expected_text in result.stderr_text

    def test_idrange_no_rid_bases_reversed(self):
        """
        Test ipa-idrange-fix command with IDrange with no RID bases, but we
        previously had a range with RID bases reversed - secondary lower than
        primary. It is a valid configuration, so we should fix no-RID range.
        """
        self.master.run_command([
            "ipa",
            "idrange-add",
            "idrange_no_rid_bases",
            "--base-id", '10000',
            "--range-size", '20000',
        ])
        self.master.run_command([
            "ipa",
            "idrange-add",
            "idrange_reversed",
            "--base-id", '50000',
            "--range-size", '20000',
            "--rid-base", '100300000',
            "--secondary-rid-base", '301000'
        ])

        result = self.master.run_command(["ipa-idrange-fix", "--unattended"])
        expected_text = "RID bases updated for range 'idrange_no_rid_bases'"

        # Remove test IDranges
        self.master.run_command(["ipa", "idrange-del", "idrange_no_rid_bases"])
        self.master.run_command(["ipa", "idrange-del", "idrange_reversed"])

        assert expected_text in result.stderr_text

    def test_users_outofrange(self):
        """Test ipa-idrange-fix command with users out of range."""
        for i in range(1, 20):
            self.master.run_command([
                "ipa",
                "user-add",
                "testuser{}".format(i),
                "--first", "Test",
                "--last", "User {}".format(i),
                "--uid", str(100000 + i * 10),
            ])

        result = self.master.run_command(["ipa-idrange-fix", "--unattended"])
        expected_text = r"Range '[\w\.]+_id_range_\d{3}' created successfully"
        match = re.search(expected_text, result.stderr_text)

        # Remove users out of range and created IDrange
        for i in range(1, 20):
            self.master.run_command([
                "ipa",
                "user-del",
                "testuser{}".format(i)
            ])
        if match is not None:
            self.master.run_command([
                "ipa",
                "idrange-del",
                match.group(0).split(" ")[1].replace("'", "")
            ])

        assert match is not None

    def test_user_outlier(self):
        """Test ipa-idrange-fix command with outlier user."""
        self.master.run_command([
            "ipa",
            "user-add",
            "testuser_outlier",
            "--first", "Outlier",
            "--last", "User",
            "--uid", '500000',
        ])

        result = self.master.run_command(["ipa-idrange-fix", "--unattended"])
        expected_text = "Identities that don't fit the criteria to get a new \
range found!"
        expected_user = "user 'Outlier User', uid=500000"

        # Remove outlier user
        self.master.run_command(["ipa", "user-del", "testuser_outlier"])

        assert expected_text in result.stderr_text
        assert expected_user in result.stderr_text

    def test_user_under1000(self):
        """Test ipa-idrange-fix command with user under 1000."""
        self.master.run_command([
            "ipa",
            "user-add",
            "testuser_under1000",
            "--first", "Under",
            "--last", "1000",
            "--uid", '999',
        ])

        result = self.master.run_command(["ipa-idrange-fix", "--unattended"])
        expected_text = "IDs under 1000:"
        expected_user = "user 'Under 1000', uid=999"

        # Remove user under 1000
        self.master.run_command(["ipa", "user-del", "testuser_under1000"])

        assert expected_text in result.stderr_text
        assert expected_user in result.stderr_text

    def test_user_preserved(self):
        """Test ipa-idrange-fix command with preserved user."""
        self.master.run_command([
            "ipa",
            "user-add",
            "testuser_preserved",
            "--first", "Preserved",
            "--last", "User",
            "--uid", '9999',
        ])
        self.master.run_command([
            "ipa",
            "user-del",
            "testuser_preserved",
            "--preserve"
        ])

        result = self.master.run_command(["ipa-idrange-fix", "--unattended"])
        expected_text = "Identities that don't fit the criteria to get a new \
range found!"
        expected_user = "user 'Preserved User', uid=9999"

        # Remove preserved user
        self.master.run_command(["ipa", "user-del", "testuser_preserved"])

        assert expected_text in result.stderr_text
        assert expected_user in result.stderr_text
