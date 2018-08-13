#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests that uninstallation is successful.

It is important not to leave the remote system in an inconsistent
state. Every failed uninstall should successfully remove remaining
pieces if possible.
"""

from __future__ import absolute_import

import os

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths
from ipaserver.install.installutils import realm_to_serverid
from ipaserver.install import dsinstance


class TestUninstallBase(IntegrationTest):

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_uninstall_client_invalid_hostname(self):

        # using replica as client just for convenience
        client = self.replicas[0]
        client_inv_hostname = '{}.nonexistent'.format(client.hostname)
        tasks.install_client(self.master, client,
                             extra_args=['--hostname', client_inv_hostname])

        client.run_command(['ipa-client-install', '--uninstall', '-U'])
        client_uninstall_log = client.get_file_contents(
            paths.IPACLIENT_UNINSTALL_LOG, encoding='utf-8'
        )
        assert "exception: ScriptError:" not in client_uninstall_log

        restore_state_path = os.path.join(paths.IPA_CLIENT_SYSRESTORE,
                                          'sysrestore.state')
        result = client.run_command(
            ['ls', restore_state_path], raiseonerr=False)
        assert 'No such file or directory' in result.stderr_text

    def test_failed_uninstall(self):
        self.master.run_command(['ipactl', 'stop'])

        serverid = realm_to_serverid(self.master.domain.realm)
        instance_name = ''.join([dsinstance.DS_INSTANCE_PREFIX, serverid])

        try:
            # Moving the DS instance out of the way will cause the
            # uninstaller to raise an exception and return with a
            # non-zero return code.
            self.master.run_command([
                '/usr/bin/mv',
                '%s/%s' % (paths.ETC_DIRSRV, instance_name),
                '%s/%s.test' % (paths.ETC_DIRSRV, instance_name)
            ])

            cmd = self.master.run_command([
                'ipa-server-install',
                '--uninstall', '-U'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
        finally:
            # Be paranoid. If something really went wrong then DS may
            # be marked as uninstalled so server cert will still be
            # tracked and the instances may remain. This can cause
            # subsequent installations to fail so be thorough.
            ds = dsinstance.DsInstance()
            ds_running = ds.is_running()
            if ds_running:
                ds.stop(serverid)

            # Moving it back should allow the uninstall to finish
            # successfully.
            self.master.run_command([
                '/usr/bin/mv',
                '%s/%s.test' % (paths.ETC_DIRSRV, instance_name),
                '%s/%s' % (paths.ETC_DIRSRV, instance_name)
            ])

            # DS has been marked as uninstalled so force the issue
            ds.stop_tracking_certificates(serverid)

            self.master.run_command([
                paths.REMOVE_DS_PL,
                '-i', instance_name
            ])

            cmd = self.master.run_command([
                'ipa-server-install',
                '--uninstall', '-U'],
                raiseonerr=False
            )
            assert cmd.returncode == 0
