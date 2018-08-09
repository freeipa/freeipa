#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests to verify that the authselect code works.
"""

from __future__ import absolute_import

import pytest

import ipaplatform.paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

default_profile = 'sssd'
preconfigured_profile = 'winbind'
preconfigured_options = ('with-fingerprint',)


def check_authselect_profile(host, expected_profile, expected_options=()):
    """
    Checks that the current authselect profile on the host
    matches expected one
    """
    cmd = host.run_command(
        ['cat', '/etc/authselect/authselect.conf'])
    lines = cmd.stdout_text.splitlines()
    assert lines[0] == expected_profile
    options = lines[1::]
    for option in expected_options:
        assert option in options


def apply_authselect_profile(host, profile, options=()):
    """
    Apply the specified authselect profile and options with --force
    """
    cmd = ['authselect', 'select', profile]
    cmd.extend(options)
    cmd.append('--force')
    host.run_command(cmd)


@pytest.mark.skipif(
    ipaplatform.paths.paths.AUTHSELECT is None,
    reason="Authselect is only available in fedora-like distributions")
class TestClientInstallation(IntegrationTest):
    """
    Tests the client installation with authselect profile.

    When the system is a fresh installation, authselect tool is available
    and the default profile 'sssd' without any option is set by default.
    But when the system has been upgraded from older version, even though
    authselect tool is available, no profile is set (authselect current would
    return 'No existing configuration detected').
    This test ensures that both scenarios are properly handled by the client
    installer.
    """
    num_clients = 1
    msg_warn_install = (
        "WARNING: The configuration pre-client installation "
        "is not managed by authselect and cannot be backed up. "
        "Uninstallation may not be able to revert to the original state.")
    msg_warn_uninstall = (
        "WARNING: Unable to revert to the pre-installation "
        "state ('authconfig' tool has been deprecated in favor of "
        "'authselect'). The default sssd profile will be used instead.")

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)
        cls.client = cls.clients[0]

    def _install_client(self, extraargs=[]):
        cmd = ['ipa-client-install', '-U',
               '--domain', self.client.domain.name,
               '--realm', self.client.domain.realm,
               '-p', self.client.config.admin_name,
               '-w', self.client.config.admin_password,
               '--server', self.master.hostname]
        cmd.extend(extraargs)
        return self.client.run_command(cmd, raiseonerr=False)

    def _uninstall_client(self):
        return self.client.run_command(
            ['ipa-client-install', '--uninstall', '-U'],
            raiseonerr=False)

    @pytest.mark.skip(reason="Option --no-sssd has been removed")
    def test_install_client_no_sssd(self):
        """
        Test client installation with --no-sssd option.
        This must be rejected as this option is incompatible with authselect.
        """
        result = self._install_client(extraargs=['--no-sssd'])
        assert result.returncode == 1
        msg = "Option '--no-sssd' is incompatible with the 'authselect' tool"
        assert msg in result.stderr_text

    @pytest.mark.skip(reason="Option --noac has been removed")
    def test_install_client_no_ac(self):
        """
        Test client installation with --noac option.
        This must be rejected as this option is incompatible with authselect.
        """
        result = self._install_client(extraargs=['--noac'])
        assert result.returncode == 1
        msg = "Option '--noac' is incompatible with the 'authselect' tool"
        assert msg in result.stderr_text

    def test_install_client_no_preconfigured_profile(self):
        """
        Test client installation on an upgraded system.
        """
        # On a machine upgraded from authconfig, there is no profile
        # To simulate this use case, remove /etc/authselect/authselect.conf
        # before launching client installation
        self.client.run_command(
            ['rm', '-f', '/etc/authselect/authselect.conf'])
        result = self._install_client()
        assert result.returncode == 0
        assert self.msg_warn_install in result.stderr_text
        # Client installation must configure the 'sssd' profile
        # with sudo
        check_authselect_profile(self.client, default_profile, ('with-sudo',))

    def test_uninstall_client_no_preconfigured_profile(self):
        """
        Test client un-installation when there was no authselect profile
        """
        # As the client did not have any authselect profile before install,
        # uninstall must print a warning about restoring 'sssd' profile
        # by default
        result = self._uninstall_client()
        assert result.returncode == 0
        assert self.msg_warn_uninstall in result.stderr_text
        check_authselect_profile(self.client, default_profile)

    def test_install_client_preconfigured_profile(self):
        """
        Test client installation when a different profile was present
        before client configuration
        """
        # Configure a profile winbind with feature with-fingerprint
        apply_authselect_profile(
            self.client, preconfigured_profile, preconfigured_options)
        # Make sure that oddjobd is disabled and stopped
        self.client.run_command(["systemctl", "disable", "oddjobd", "--now"])

        # Call the installer, must succeed and store the winbind profile
        # in the statestore, but install sssd profile with-mkhomedir
        result = self._install_client(extraargs=['-f', '--mkhomedir'])
        assert result.returncode == 0
        assert self.msg_warn_install not in result.stderr_text
        # Client installation must configure the 'sssd' profile
        # with mkhomedir (because of extraargs) and with sudo
        check_authselect_profile(
            self.client, default_profile, ('with-mkhomedir', 'with-sudo'))

        # Test for ticket 7604:
        # ipa-client-install --mkhomedir doesn't enable oddjobd
        # Check that oddjobd has been enabled and started
        # because --mkhomedir was used
        status = self.client.run_command(["systemctl", "status", "oddjobd"])
        assert "active (running)" in status.stdout_text

    def test_uninstall_client_preconfigured_profile(self):
        """
        Test client un-installation when a different profile was present
        before client configuration
        """
        # Uninstall must revert to the preconfigured profile with options
        result = self._uninstall_client()
        assert result.returncode == 0
        assert self.msg_warn_uninstall not in result.stderr_text
        check_authselect_profile(
            self.client, preconfigured_profile, preconfigured_options)

    def test_install_client_no_sudo(self):
        """
        Test client installation with --no-sudo option
        """
        result = self._install_client(extraargs=['-f', '--no-sudo'])
        assert result.returncode == 0
        assert self.msg_warn_install not in result.stderr_text
        # Client installation must configure the 'sssd' profile
        # but not with sudo (because of extraargs)
        check_authselect_profile(self.client, default_profile, ())

    @classmethod
    def uninstall(cls, mh):
        super(TestClientInstallation, cls).uninstall(mh)
        # Clean-up the authselect profile and re-use the default 'sssd'
        apply_authselect_profile(cls.client, default_profile)


@pytest.mark.skipif(
    ipaplatform.paths.paths.AUTHSELECT is None,
    reason="Authselect is only available in fedora-like distributions")
class TestServerInstallation(IntegrationTest):
    """
    Tests the server installation with authselect profile.

    When the system is a fresh installation, authselect tool is available
    and the default profile 'sssd' without any option is set by default.
    But when the system has been upgraded from older version, even though
    authselect tool is available, no profile is set (authselect current would
    return 'No existing configuration detected').
    This test ensures that both scenarios are properly handled by the server
    installer.
    """

    @classmethod
    def install(cls, mh):
        pass

    def test_install(self):
        """
        Test server installation when a different profile was present
        before server configuration
        """
        # Configure a profile winbind with feature with-fingerprint
        apply_authselect_profile(
            self.master, preconfigured_profile, preconfigured_options)
        tasks.install_master(self.master, setup_dns=False)
        check_authselect_profile(self.master, default_profile, ('with-sudo',))

    def test_uninstall(self):
        """
        Test server uninstallation when a different profile was present
        before server installation
        """
        # uninstall must revert to the preconfigured profile
        tasks.uninstall_master(self.master)
        check_authselect_profile(
            self.master, preconfigured_profile, preconfigured_options)

    @classmethod
    def uninstall(cls, mh):
        # Clean-up the authselect profile and re-use the default 'sssd'
        apply_authselect_profile(cls.master, default_profile)
