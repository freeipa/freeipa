#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for the ipa-crlgen-manage command.
"""

from __future__ import absolute_import

import os
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

CRLGEN_STATUS_ENABLED = 'enabled'
CRLGEN_STATUS_DISABLED = 'disabled'
CRL_FILENAME = os.path.join(paths.PKI_CA_PUBLISH_DIR, 'MasterCRL.bin')


def check_crlgen_status(host, rc=0, msg=None, enabled=True, check_crl=False):
    """Checks that CRLGen is configured as expected

    :param host: The host where ;ipa-crlgen-manage status' command is run
    :param rc: the expected result code
    :param msg: the expected msg in stderr
    :param enabled: the expected status
    :param check_crl: if True we expect a Master.bin CRL file

    If enabled:
    ipa-crlgen-manage status must return 'CRL generation: enabled'
    and print the last CRL update date and number if crl_present=True.
    If disabled:
    ipa-crlgen-manage status must return 'CRL generation: disabled'
    """
    result = host.run_command(['ipa-crlgen-manage', 'status'],
                              raiseonerr=False)

    assert result.returncode == rc
    if msg:
        assert msg in result.stderr_text

    if rc == 0:
        status = CRLGEN_STATUS_ENABLED if enabled else CRLGEN_STATUS_DISABLED
        assert 'CRL generation: {}'.format(status) in result.stdout_text

        if check_crl and enabled:
            # We expect CRL generation to be enabled and need to check for
            # MasterCRL.bin
            crl_content = host.get_file_contents(CRL_FILENAME)
            crl = x509.load_der_x509_crl(crl_content, default_backend())
            last_update_msg = 'Last CRL update: {}'.format(crl.last_update)
            assert last_update_msg in result.stdout_text

            for ext in crl.extensions:
                if ext.oid == x509.oid.ExtensionOID.CRL_NUMBER:
                    number_msg = "Last CRL Number: {}".format(
                        ext.value.crl_number)
                    assert number_msg in result.stdout_text


def check_crlgen_enable(host, rc=0, msg=None, check_crl=False):
    """Check ipa-crlgen-manage enable command

    Launch ipa-crlgen-manage command and check the result code and output
    """
    result = host.run_command(['ipa-crlgen-manage', 'enable'],
                              raiseonerr=False)
    assert result.returncode == rc
    if msg:
        assert msg in result.stderr_text
    if rc == 0:
        # check ipa-crlgen-manage status is consistent
        check_crlgen_status(host, enabled=True, check_crl=check_crl)


def check_crlgen_disable(host, rc=0, msg=None):
    """Check ipa-crlgen-manage disable command

    Launch ipa-crlgen-manage command and check the result code and output
    """
    result = host.run_command(['ipa-crlgen-manage', 'disable'],
                              raiseonerr=False)
    assert result.returncode == rc
    if msg:
        assert msg in result.stderr_text
    if rc == 0:
        # check ipa-crlgen-manage status is consistent
        check_crlgen_status(host, enabled=False)


def break_crlgen_with_rewriterule(host):
    """Create an inconsistent configuration on a CRL master

    In the file /etc/httpd/conf.d/ipa-pki-proxy.conf, add a RewriteRule that
    should be present only on non-CRL master"""
    content = host.get_file_contents(paths.HTTPD_IPA_PKI_PROXY_CONF,
                                     encoding='utf-8')
    new_content = content + "\nRewriteRule ^/ipa/crl/MasterCRL.bin " \
        "https://{}/ca/ee/ca/getCRL?op=getCRL&crlIssuingPoint=MasterCRL " \
        "[L,R=301,NC]".format(host.hostname)
    host.put_file_contents(paths.HTTPD_IPA_PKI_PROXY_CONF, new_content)

    check_crlgen_status(host, rc=1, msg="Configuration is inconsistent")


def break_crlgen_with_CS_cfg(host):
    """Create an inconsistent configuration on a CRL master

    Add a enableCRLUpdates=false directive that should be present only on
    non-CRL master"""
    content = host.get_file_contents(paths.CA_CS_CFG_PATH,
                                     encoding='utf-8')
    new_lines = []
    for line in content.split('\n'):
        if line.startswith('ca.crl.MasterCRL.enableCRLCache'):
            new_lines.append("ca.crl.MasterCRL.enableCRLCache=false")
        else:
            new_lines.append(line)
    host.put_file_contents(paths.CA_CS_CFG_PATH, '\n'.join(new_lines))

    check_crlgen_status(host, rc=1, msg="Configuration is inconsistent")


class TestCRLGenManage(IntegrationTest):
    """Tests the ipa-crlgen-manage command.

    ipa-crlgen-manage can be used to enable, disable or check
    the status of CRL generation.
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        # Install a master and check CRL status (=enabled)
        tasks.install_master(cls.master)
        # We don't check for MasterCRL.bin presence because it may not
        # be generated right after the install
        check_crlgen_status(cls.master, enabled=True)

    def test_master_enable_crlgen_already_enabled(self):
        """Test ipa-crlgen-manage enable on an already enabled instance"""
        # We don't check for MasterCRL.bin presence because it may not
        # be generated right after the install
        check_crlgen_enable(
            self.master, rc=0,
            msg="Nothing to do, CRL generation already enabled")

    def test_master_disable_crlgen(self):
        """Test ipa-crlgen-manage disable on an enabled instance"""
        check_crlgen_disable(
            self.master, rc=0,
            msg="make sure to configure CRL generation on another master")

    def test_master_disable_crlgen_already_disabled(self):
        """Test ipa-crlgen-manage disable on an enabled instance"""
        check_crlgen_disable(
            self.master, rc=0,
            msg="Nothing to do, CRL generation already disabled")

    def test_master_enable_crlgen(self):
        """Test ipa-crlgen-manage enable on a disabled instance"""
        # This time we check that MasterCRL.bin is present
        check_crlgen_enable(
            self.master, rc=0,
            msg="make sure to have only a single CRL generation master",
            check_crl=True)

    def test_crlgen_status_on_replica(self):
        """Test crlgen status on a replica without CA

        Install a replica without CA
        then call ipa-crlgen-manage status.
        """
        tasks.install_replica(self.master, self.replicas[0], setup_ca=False)
        check_crlgen_status(self.replicas[0], enabled=False)

    def test_crlgen_disable_on_caless_replica(self):
        """Test crlgen disable on a replica without CA"""
        check_crlgen_disable(
            self.replicas[0], rc=0,
            msg="Warning: Dogtag CA is not installed on this server")

    def test_crlgen_enable_on_caless_replica(self):
        """Test crlgen enable on a replica without CA"""
        check_crlgen_enable(
            self.replicas[0], rc=1,
            msg="Dogtag CA is not installed. Please install a CA first")

    def test_crlgen_enable_on_ca_replica(self):
        """Test crlgen enable on a replica with CA

        Install a CA clone and enable CRLgen"""
        tasks.install_ca(self.replicas[0])
        check_crlgen_enable(
            self.replicas[0], rc=0,
            msg="make sure to have only a single CRL generation master",
            check_crl=True)

    def test_crlgen_enable_on_broken_master(self):
        """Test crlgen enable on master with inconsistent config

        Break the (enabled) master config by setting the rewriterule
        and call enable"""
        # Make sure the config is enabled
        check_crlgen_enable(self.master)
        # Break the config with RewriteRule
        break_crlgen_with_rewriterule(self.master)
        # Call enable to repair
        check_crlgen_enable(
            self.master, rc=0,
            msg="CRL generation is partially enabled, repairing...",
            check_crl=True)

    def test_crlgen_disable_on_broken_master(self):
        """Test crlgen disable on master with inconsistent config

        Break the (enabled) master config by setting the rewriterule
        and call disable"""
        # Make sure the config is enabled
        check_crlgen_enable(self.master)
        # Break the config with RewriteRule
        break_crlgen_with_rewriterule(self.master)
        # Call disable to repair
        check_crlgen_disable(
            self.master, rc=0,
            msg="CRL generation is partially enabled, repairing...")

    def test_crlgen_enable_on_broken_replica(self):
        """Test crlgen enable on replica with inconsistent config

        Break the (enabled) replica config by setting enableCRLUpdates=false
        and call enable"""
        # Make sure the config is enabled
        check_crlgen_enable(self.replicas[0])
        # Break the config with RewriteRule
        break_crlgen_with_CS_cfg(self.replicas[0])
        # Call enable to repair
        check_crlgen_enable(
            self.replicas[0], rc=0,
            msg="CRL generation is partially enabled, repairing...",
            check_crl=True)

    def test_crlgen_disable_on_broken_replica(self):
        """Test crlgen disable on replica with inconsistent config

        Break the (enabled) replica config by setting enableCRLUpdates=false
        and call disable"""
        # Make sure the config is enabled
        check_crlgen_enable(self.replicas[0])
        # Break the config with RewriteRule
        break_crlgen_with_CS_cfg(self.replicas[0])
        # Call disable to repair
        check_crlgen_disable(
            self.replicas[0], rc=0,
            msg="CRL generation is partially enabled, repairing...")

    def test_uninstall_without_ignore_last_of_role(self):
        """Test uninstallation of the CRL generation master

        If --ignore-last-of-role is not provided, uninstall prints a msg
        and exits on error.
        """
        # Make sure CRL gen is enabled on the master
        check_crlgen_enable(self.master)
        # call uninstall without --ignore-last-of-role, should be refused
        result = self.master.run_command(
            ['ipa-server-install', '--uninstall', '-U'], raiseonerr=False)
        assert result.returncode == 1
        expected_msg = "Deleting this server will leave your installation " \
                       "without a CRL generation master"
        assert expected_msg in result.stdout_text

    def test_uninstall_with_ignore_last_of_role(self):
        """Test uninstallation of the CRL generation master

        When --ignore-last-of-role is provided, uninstall prints a msg but
        gets executed.
        """
        # Make sure CRL gen is enabled on the master
        check_crlgen_enable(self.master)
        # call uninstall with --ignore-last-of-role, should be OK
        result = self.master.run_command(
            ['ipa-server-install', '--uninstall', '-U',
             '--ignore-last-of-role'])
        expected_msg = "Deleting this server will leave your installation " \
                       "without a CRL generation master"
        assert expected_msg in result.stdout_text

    def test_uninstall_last_master_does_not_require_ignore_last_of_role(self):
        """Test uninstallation of the last master

        Even if the host is CRL generation master, uninstall must proceed
        even without --ignore-last-of-role because we are removing the last
        master.
        """
        # Make sure CRL gen is enabled on the replica
        check_crlgen_enable(self.replicas[0])
        # call uninstall without --ignore-last-of-role, should be OK
        self.master.run_command(['ipa-server-install', '--uninstall', '-U'])
