#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Tests for ipa-join command functionality.

This module tests various combinations of ipa-join options including:
- hostname
- server
- keytab
- bindpw (OTP/enrollment password)
- unenroll

Ported from the shell-based test suite (t.ipajoin.sh and t.ipaotp.sh).
"""

from __future__ import absolute_import

from ipapython.ipautil import ipa_generate_password
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


# Constants
OTP = ipa_generate_password(special=None)
INVALID_PASSWORD = "WrongPassword"
INVALID_SERVER = "No.Such.IPA.Server.Domain.com"
TEST_KEYTAB = "/tmp/ipajoin.test.keytab"

# Error messages
ERR_SASL_BIND_FAILED = "SASL Bind failed"
ERR_UNAUTHENTICATED_BIND = "Unauthenticated binds are not allowed"
ERR_COULD_NOT_RESOLVE = "JSON-RPC call failed: Could not resolve hostname"
ERR_UNABLE_ROOT_DN = "Unable to determine root DN"
ERR_NO_CONFIG = "Unable to determine IPA server from /etc/ipa/default.conf"
ERR_PREAUTH_FAILED = "Generic preauthentication failure"

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_PREAUTH_ERROR = 19
EXIT_ROOT_DN_ERROR = 14
EXIT_SASL_BIND_FAILED = 15
EXIT_RESOLVE_ERROR = 17


class TestIPAJoin(IntegrationTest):
    """Tests for ipa-join command functionality.

    This test class covers various ipa-join scenarios including:
    - Basic enrollment and unenrollment
    - Using hostname, server, keytab, and bindpw options
    - Positive and negative test cases
    - OTP (one-time password) enrollment tests

    Tests require one master and one client.
    """

    topology = 'line'
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])

    @classmethod
    def uninstall(cls, mh):
        # Cleanup test keytab if exists
        cls.clients[0].run_command(
            ['rm', '-f', TEST_KEYTAB],
            raiseonerr=False
        )
        tasks.uninstall_client(cls.clients[0])
        tasks.uninstall_master(cls.master)

    # =========================================================================
    # ipa-join basic tests
    # =========================================================================

    def test_unenroll(self):
        """Test ipa-join --unenroll option."""
        result = tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)
        assert result.returncode == EXIT_SUCCESS

    def test_unenroll_already_unenrolled(self):
        """Test ipa-join -u on an already unenrolled client.

        When trying to unenroll a client that is not enrolled,
        ipa-join should fail with a preauthentication error.
        """
        # Client is already unenrolled from previous test
        result = tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

        assert result.returncode == EXIT_PREAUTH_ERROR
        assert ERR_PREAUTH_FAILED in result.stderr_text

    def test_hostname_with_kerberos(self):
        """Test ipa-join with --hostname using Kerberos auth."""
        tasks.kinit_admin(self.clients[0])
        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--hostname={self.clients[0].hostname}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_hostname_bindpw_invalid(self):
        """Test ipa-join with hostname and invalid bindpw."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--bindpw={INVALID_PASSWORD}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        assert ERR_SASL_BIND_FAILED in result.stderr_text

    def test_hostname_bindpw_valid(self):
        """Test ipa-join with hostname and valid OTP."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--bindpw={OTP}'
        )
        assert result.returncode == EXIT_SUCCESS
        tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_hostname_keytab_with_kerberos(self):
        """Test ipa-join with hostname and keytab using Kerberos."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)

        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--hostname={self.clients[0].hostname}',
                f'--keytab={TEST_KEYTAB}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_hostname_keytab_bindpw_invalid(self):
        """Test ipa-join with hostname, keytab, and invalid bindpw."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--keytab={TEST_KEYTAB}',
            f'--bindpw={INVALID_PASSWORD}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        assert ERR_SASL_BIND_FAILED in result.stderr_text

    def test_hostname_keytab_bindpw_valid(self):
        """Test ipa-join with hostname, keytab, and valid OTP."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--keytab={TEST_KEYTAB}',
            f'--bindpw={OTP}'
        )
        assert result.returncode == EXIT_SUCCESS
        tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_hostname_server_invalid_with_kerberos(self):
        """Test ipa-join with hostname and invalid server."""
        tasks.kinit_admin(self.clients[0])
        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--hostname={self.clients[0].hostname}',
                f'--server={INVALID_SERVER}',
                raiseonerr=False
            )

            assert result.returncode == EXIT_RESOLVE_ERROR
            assert ERR_COULD_NOT_RESOLVE in result.stderr_text
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)

    def test_hostname_server_invalid_bindpw_valid(self):
        """Test ipa-join with hostname, invalid server, and valid OTP."""
        tasks.kinit_admin(self.clients[0])
        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--server={INVALID_SERVER}',
            f'--bindpw={OTP}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_ROOT_DN_ERROR
        assert ERR_UNABLE_ROOT_DN in result.stderr_text

    def test_hostname_server_invalid_keytab_with_kerberos(self):
        """Test ipa-join with hostname, invalid server, keytab."""
        tasks.kinit_admin(self.clients[0])
        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--hostname={self.clients[0].hostname}',
                f'--server={INVALID_SERVER}',
                f'--keytab={TEST_KEYTAB}',
                raiseonerr=False
            )

            assert result.returncode == EXIT_RESOLVE_ERROR
            assert ERR_COULD_NOT_RESOLVE in result.stderr_text
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)

    def test_hostname_server_invalid_keytab_bindpw_valid(self):
        """Test ipa-join with hostname, invalid server, keytab, valid OTP."""
        tasks.kinit_admin(self.clients[0])
        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--server={INVALID_SERVER}',
            f'--keytab={TEST_KEYTAB}',
            f'--bindpw={OTP}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_ROOT_DN_ERROR
        assert ERR_UNABLE_ROOT_DN in result.stderr_text

    def test_hostname_server_valid_with_kerberos(self):
        """Test ipa-join with hostname and valid server."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)

        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--hostname={self.clients[0].hostname}',
                f'--server={self.master.hostname}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_hostname_server_valid_bindpw_invalid(self):
        """Test ipa-join with hostname, valid server, invalid bindpw."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--server={self.master.hostname}',
            f'--bindpw={INVALID_PASSWORD}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        assert ERR_SASL_BIND_FAILED in result.stderr_text

    def test_hostname_server_valid_bindpw_valid(self):
        """Test ipa-join with hostname, valid server, valid OTP."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--server={self.master.hostname}',
            f'--bindpw={OTP}'
        )
        assert result.returncode == EXIT_SUCCESS
        tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_hostname_server_valid_keytab_with_kerberos(self):
        """Test ipa-join with hostname, valid server, keytab."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname)

        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--hostname={self.clients[0].hostname}',
                f'--server={self.master.hostname}',
                f'--keytab={TEST_KEYTAB}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_hostname_server_valid_keytab_bindpw_invalid(self):
        """Test ipa-join with hostname, valid server, keytab, bad bindpw."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--server={self.master.hostname}',
            f'--keytab={TEST_KEYTAB}',
            f'--bindpw={INVALID_PASSWORD}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        # Note: Original test had "SASL Bind Failed" (capital F), checking both
        assert "SASL Bind" in result.stderr_text
        assert "ailed" in result.stderr_text

    def test_hostname_server_valid_keytab_bindpw_valid(self):
        """Test ipa-join with hostname, valid server, keytab, valid OTP."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--server={self.master.hostname}',
            f'--keytab={TEST_KEYTAB}',
            f'--bindpw={OTP}'
        )
        assert result.returncode == EXIT_SUCCESS
        tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_keytab_only_with_kerberos(self):
        """Test ipa-join with keytab only using Kerberos."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname)

        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--keytab={TEST_KEYTAB}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_keytab_bindpw_invalid(self):
        """Test ipa-join with keytab and invalid bindpw."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--keytab={TEST_KEYTAB}',
            f'--bindpw={INVALID_PASSWORD}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        assert ERR_SASL_BIND_FAILED in result.stderr_text

    def test_keytab_bindpw_valid(self):
        """Test ipa-join with keytab and valid OTP."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--keytab={TEST_KEYTAB}',
            f'--bindpw={OTP}'
        )
        assert result.returncode == EXIT_SUCCESS
        tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_server_invalid_only_with_kerberos(self):
        """Test ipa-join with invalid server only."""
        tasks.kinit_admin(self.clients[0])
        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--server={INVALID_SERVER}',
                raiseonerr=False
            )

            assert result.returncode == EXIT_RESOLVE_ERROR
            assert ERR_COULD_NOT_RESOLVE in result.stderr_text
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)

    def test_server_invalid_bindpw_valid(self):
        """Test ipa-join with invalid server and valid OTP."""
        tasks.kinit_admin(self.clients[0])
        result = tasks.ipa_join(
            self.clients[0],
            f'--server={INVALID_SERVER}',
            f'--bindpw={OTP}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_ROOT_DN_ERROR
        assert ERR_UNABLE_ROOT_DN in result.stderr_text

    def test_server_invalid_keytab_with_kerberos(self):
        """Test ipa-join with invalid server and keytab."""
        tasks.kinit_admin(self.clients[0])
        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--server={INVALID_SERVER}',
                f'--keytab={TEST_KEYTAB}',
                raiseonerr=False
            )

            assert result.returncode == EXIT_RESOLVE_ERROR
            assert ERR_COULD_NOT_RESOLVE in result.stderr_text
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)

    def test_server_valid_only_with_kerberos(self):
        """Test ipa-join with valid server only."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname)

        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--server={self.master.hostname}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_server_valid_bindpw_invalid(self):
        """Test ipa-join with valid server and invalid bindpw."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--server={self.master.hostname}',
            f'--bindpw={INVALID_PASSWORD}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        assert ERR_SASL_BIND_FAILED in result.stderr_text

    def test_server_valid_bindpw_valid(self):
        """Test ipa-join with valid server and valid OTP."""
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--server={self.master.hostname}',
            f'--bindpw={OTP}'
        )
        assert result.returncode == EXIT_SUCCESS
        tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_server_valid_keytab_with_kerberos(self):
        """Test ipa-join with valid server and keytab."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname)

        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--server={self.master.hostname}',
                f'--keytab={TEST_KEYTAB}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_bindpw_invalid_only(self):
        """Test ipa-join with invalid bindpw only."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--bindpw={INVALID_PASSWORD}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        assert ERR_SASL_BIND_FAILED in result.stderr_text

    # =========================================================================
    # OTP (One-Time Password) tests
    # =========================================================================

    def test_otp_empty_password(self):
        """Test ipa-join with empty OTP password (ipa_otp_1001)."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            '--bindpw=',
            raiseonerr=False
        )

        assert result.returncode == EXIT_ROOT_DN_ERROR
        assert ERR_UNAUTHENTICATED_BIND in result.stderr_text

    def test_otp_wrong_password(self):
        """Test ipa-join with wrong OTP password (ipa_otp_1002)."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)

        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--bindpw={INVALID_PASSWORD}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        assert ERR_SASL_BIND_FAILED in result.stderr_text

    def test_otp_valid_password(self):
        """Test ipa-join with valid OTP password (ipa_otp_1003)."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)
        try:
            result = tasks.ipa_join(
                self.clients[0],
                f'--hostname={self.clients[0].hostname}',
                f'--bindpw={OTP}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

    def test_otp_reuse_fails(self):
        """Test that reusing the same OTP fails (ipa_otp_1004)."""
        tasks.kinit_admin(self.clients[0])
        tasks.kinit_admin(self.master)
        tasks.host_del(self.master, self.clients[0].hostname, raiseonerr=False)
        tasks.host_add(self.master, self.clients[0].hostname, password=OTP)
        try:
            # First use should succeed
            result = tasks.ipa_join(
                self.clients[0],
                f'--hostname={self.clients[0].hostname}',
                f'--bindpw={OTP}'
            )
            assert result.returncode == EXIT_SUCCESS
        finally:
            self.clients[0].run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.ipa_join(self.clients[0], '-u', raiseonerr=False)

        # Second use of same OTP should fail
        result = tasks.ipa_join(
            self.clients[0],
            f'--hostname={self.clients[0].hostname}',
            f'--bindpw={OTP}',
            raiseonerr=False
        )

        assert result.returncode == EXIT_SASL_BIND_FAILED
        assert ERR_SASL_BIND_FAILED in result.stderr_text
