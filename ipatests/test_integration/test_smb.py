#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for SMB-related features like
   configuring Samba file server and mounting SMB file system
"""

from __future__ import absolute_import

from functools import partial
import textwrap
import re

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths


def wait_smbd_functional(host):
    """Wait smbd is functional after (re)start

    After start of smbd there is a 2-3 seconds delay before daemon is
    fully functional and clients can successfuly mount a share.
    The ping command effectively blocks until the daemon is ready.
    """
    host.run_command(['smbcontrol', 'smbd', 'ping'])


class TestSMB(IntegrationTest):
    topology = 'star'
    num_clients = 2
    num_ad_domains = 1

    ipa_user1 = 'user1'
    ipa_user1_password = 'SecretUser1'
    ipa_user2 = 'user2'
    ipa_user2_password = 'SecretUser2'
    ad_user_login = 'testuser'
    ad_user_password = 'Secret123'
    ipa_test_group = 'ipa_testgroup'
    ad_test_group = 'testgroup'

    @classmethod
    def install(cls, mh):
        if cls.domain_level is not None:
            domain_level = cls.domain_level
        else:
            domain_level = cls.master.config.domain_level
        tasks.install_topo(cls.topology,
                           cls.master, cls.replicas,
                           cls.clients, domain_level,
                           clients_extra_args=('--mkhomedir',))

        cls.ad = cls.ads[0]  # pylint: disable=no-member
        cls.smbserver = cls.clients[0]
        cls.smbclient = cls.clients[1]
        cls.ad_user = '{}@{}'.format(cls.ad_user_login, cls.ad.domain.name)

        tasks.config_host_resolvconf_with_master_data(cls.master,
                                                      cls.smbclient)
        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.configure_windows_dns_for_trust(cls.ad, cls.master)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name,
                                      extra_args=['--two-way=true'])

        tasks.create_active_user(cls.master, cls.ipa_user1,
                                 password=cls.ipa_user1_password)
        tasks.create_active_user(cls.master, cls.ipa_user2,
                                 password=cls.ipa_user2_password)
        # Trigger creation of home directories on the SMB server
        for user in [cls.ipa_user1, cls.ipa_user2, cls.ad_user]:
            tasks.run_command_as_user(cls.smbserver, user, ['stat', '.'])

    @pytest.yield_fixture
    def enable_smb_client_dns_lookup_kdc(self):
        smbclient = self.smbclient
        with tasks.FileBackup(smbclient, paths.KRB5_CONF):
            krb5_conf = smbclient.get_file_contents(
                paths.KRB5_CONF, encoding='utf-8')
            krb5_conf = krb5_conf.replace(
                'dns_lookup_kdc = false', 'dns_lookup_kdc = true')
            smbclient.put_file_contents(paths.KRB5_CONF, krb5_conf)
            yield

    @pytest.yield_fixture
    def samba_share_public(self):
        """Setup share outside /home on samba server."""
        share_name = 'shared'
        share_path = '/srv/samba_shared'
        smbserver = self.smbserver

        smbserver.run_command(['mkdir', share_path])
        smbserver.run_command(['chmod', '777', share_path])
        # apply selinux context only if selinux is enabled
        if tasks.is_selinux_enabled(smbserver):
            smbserver.run_command(['chcon', '-t', 'samba_share_t', share_path])
        with tasks.FileBackup(smbserver, paths.SMB_CONF):
            smb_conf = smbserver.get_file_contents(
                paths.SMB_CONF, encoding='utf-8')
            smb_conf += textwrap.dedent('''
            [{name}]
                path = {path}
                writable = yes
                browsable=yes
            '''.format(name=share_name, path=share_path))
            smbserver.put_file_contents(paths.SMB_CONF, smb_conf)
            smbserver.run_command(['systemctl', 'restart', 'smb'])
            wait_smbd_functional(smbserver)
            yield {
                'name': share_name,
                'server_path': share_path,
                'unc': '//{}/{}'.format(smbserver.hostname, share_name)
            }
        smbserver.run_command(['systemctl', 'restart', 'smb'])
        wait_smbd_functional(smbserver)
        smbserver.run_command(['rmdir', share_path])

    def mount_smb_share(self, user, password, share, mountpoint):
        tasks.kdestroy_all(self.smbclient)
        tasks.kinit_as_user(self.smbclient, user, password)
        self.smbclient.run_command(['mkdir', '-p', mountpoint])
        self.smbclient.run_command([
            'mount', '-t', 'cifs', share['unc'], mountpoint,
            '-o', 'sec=krb5i,multiuser'
        ])
        tasks.kdestroy_all(self.smbclient)

    def smb_sanity_check(self, user, client_mountpoint, share):
        test_dir = 'testdir_{}'.format(user)
        test_file = 'testfile_{}'.format(user)
        test_file_path = '{}/{}'.format(test_dir, test_file)
        test_string = 'Hello, world!'

        run_smb_client = partial(tasks.run_command_as_user, self.smbclient,
                                 user, cwd=client_mountpoint)
        run_smb_server = partial(self.smbserver.run_command,
                                 cwd=share['server_path'])

        try:
            # check creation of directory from client side
            run_smb_client(['mkdir', test_dir])
            # check dir properties at client side
            res = run_smb_client(['stat', '-c', '%n %U %G', test_dir])
            assert res.stdout_text == '{0} {1} {1}\n'.format(test_dir, user)
            # check dir properties at server side
            res = run_smb_server(['stat', '-c', '%n %U %G', test_dir])
            assert res.stdout_text == '{0} {1} {1}\n'.format(test_dir, user)

            # check creation of file from client side
            run_smb_client('printf "{}" > {}'.format(
                test_string, test_file_path))
            # check file is listed at client side
            res = run_smb_client(['ls', test_dir])
            assert res.stdout_text == test_file + '\n'
            # check file is listed at server side
            res = run_smb_server(['ls', test_dir])
            assert res.stdout_text == test_file + '\n'
            # check file properties at server side
            res = run_smb_server(['stat', '-c', '%n %s %U %G', test_file_path])
            assert res.stdout_text == '{0} {1} {2} {2}\n'.format(
                test_file_path, len(test_string), user)
            # check file properties at client side
            res = run_smb_client(['stat', '-c', '%n %s %U %G', test_file_path])
            assert res.stdout_text == '{0} {1} {2} {2}\n'.format(
                test_file_path, len(test_string), user)
            # check file contents at client side
            res = run_smb_client(['cat', test_file_path])
            assert res.stdout_text == test_string
            # check file contents at server side
            file_contents_at_server = self.smbserver.get_file_contents(
                '{}/{}'.format(share['server_path'], test_file_path),
                encoding='utf-8')
            assert file_contents_at_server == test_string

            # check access using smbclient utility
            res = run_smb_client(
                ['smbclient', '-k', share['unc'], '-c', 'dir'])
            assert test_dir in res.stdout_text

            # check file and dir removal from client side
            run_smb_client(['rm', test_file_path])
            run_smb_client(['rmdir', test_dir])
            # check dir does not exist at client side
            res = run_smb_client(['stat', test_dir], raiseonerr=False)
            assert res.returncode == 1
            assert 'No such file or directory' in res.stderr_text
            # check dir does not exist at server side
            res = run_smb_server(['stat', test_dir], raiseonerr=False)
            assert res.returncode == 1
            assert 'No such file or directory' in res.stderr_text
        finally:
            run_smb_server(['rm', '-rf', test_dir], raiseonerr=False)

    def smb_installation_check(self, result):
        domain_regexp_tpl = r'''
            Domain\ name:\s*{domain}\n
            \s*NetBIOS\ name:\s*{netbios}\n
            \s*SID:\s*S-1-5-21-\d+-\d+-\d+\n
            \s+ID\ range:\s*\d+\s*-\s*\d+
        '''
        # pylint: disable=no-member
        ipa_regexp = domain_regexp_tpl.format(
            domain=re.escape(self.master.domain.name),
            netbios=self.master.netbios)
        ad_regexp = domain_regexp_tpl.format(
            domain=re.escape(self.ad.domain.name), netbios=self.ad.netbios)
        # pylint: enable=no-member
        output_regexp = r'''
            Discovered\ domains.*
            {}
            .*
            {}
            .*
            Samba.+configured.+check.+/etc/samba/smb\.conf
        '''.format(ipa_regexp, ad_regexp)
        assert re.search(output_regexp, result.stdout_text,
                         re.VERBOSE | re.DOTALL)

    def cleanup_mount(self, mountpoint):
        self.smbclient.run_command(['umount', mountpoint], raiseonerr=False)
        self.smbclient.run_command(['rmdir', mountpoint], raiseonerr=False)

    def test_samba_uninstallation_without_installation(self):
        res = self.smbserver.run_command(
            ['ipa-client-samba', '--uninstall', '-U'])
        assert res.stdout_text == 'Samba domain member is not configured yet\n'

    def test_install_samba(self):
        samba_install_result = self.smbserver.run_command(
            ['ipa-client-samba', '-U'])
        # smb and winbind are expected to be not running
        for service in ['smb', 'winbind']:
            result = self.smbserver.run_command(
                ['systemctl', 'status', service], raiseonerr=False)
            assert result.returncode == 3
        self.smbserver.run_command([
            'systemctl', 'enable', '--now', 'smb', 'winbind'
        ])
        wait_smbd_functional(self.smbserver)
        # check that smb and winbind started successfully
        for service in ['smb', 'winbind']:
            self.smbserver.run_command(['systemctl', 'status', service])
        # print status for debugging purposes
        self.smbserver.run_command(['smbstatus'])
        # checks postponed till the end of method to be sure services are
        # started - this way we prevent other tests from failing
        self.smb_installation_check(samba_install_result)

    def test_samba_service_listed(self):
        """Check samba service is listed.

        Regression test for https://bugzilla.redhat.com/show_bug.cgi?id=1731433
        """
        service_name = 'cifs/{}@{}'.format(
            self.smbserver.hostname, self.smbserver.domain.name.upper())
        tasks.kinit_admin(self.master)
        res = self.master.run_command(
            ['ipa', 'service-show', '--raw', service_name])
        expected_output = 'krbprincipalname: {}\n'.format(service_name)
        assert expected_output in res.stdout_text
        res = self.master.run_command(
            ['ipa', 'service-find', '--raw', service_name])
        assert expected_output in res.stdout_text

    def check_smb_access_at_ipa_client(self, user, password, samba_share):
        mount_point = '/mnt/smb'

        self.mount_smb_share(user, password, samba_share, mount_point)
        try:
            tasks.run_command_as_user(self.smbclient, user, ['kdestroy', '-A'])
            tasks.run_command_as_user(self.smbclient, user, ['kinit', user],
                                      stdin_text=password + '\n')
            self.smb_sanity_check(user, mount_point, samba_share)
        finally:
            self.cleanup_mount(mount_point)

    def test_smb_access_for_ipa_user_at_ipa_client(self):
        samba_share = {
            'name': 'homes',
            'server_path': '/home/{}'.format(self.ipa_user1),
            'unc': '//{}/homes'.format(self.smbserver.hostname)
        }
        self.check_smb_access_at_ipa_client(
            self.ipa_user1, self.ipa_user1_password, samba_share)

    def test_smb_access_for_ad_user_at_ipa_client(
            self, enable_smb_client_dns_lookup_kdc):
        samba_share = {
            'name': 'homes',
            'server_path': '/home/{}/{}'.format(self.ad.domain.name,
                                                self.ad_user_login),
            'unc': '//{}/homes'.format(self.smbserver.hostname)
        }
        self.check_smb_access_at_ipa_client(
            self.ad_user, self.ad_user_password, samba_share)

    def test_smb_mount_and_access_by_different_users(self, samba_share_public):
        user1 = self.ipa_user1
        password1 = self.ipa_user1_password
        user2 = self.ipa_user2
        password2 = self.ipa_user2_password
        mount_point = '/mnt/smb'

        try:
            self.mount_smb_share(user1, password1, samba_share_public,
                                 mount_point)
            tasks.run_command_as_user(self.smbclient, user2,
                                      ['kdestroy', '-A'])
            tasks.run_command_as_user(self.smbclient, user2, ['kinit', user2],
                                      stdin_text=password2 + '\n')
            self.smb_sanity_check(user2, mount_point, samba_share_public)
        finally:
            self.cleanup_mount(mount_point)

    def test_smb_mount_fails_without_kerberos_ticket(self, samba_share_public):
        mountpoint = '/mnt/smb'
        try:
            tasks.kdestroy_all(self.smbclient)
            self.smbclient.run_command(['mkdir', '-p', mountpoint])
            res = self.smbclient.run_command([
                'mount', '-t', 'cifs', samba_share_public['unc'], mountpoint,
                '-o', 'sec=krb5i,multiuser'
            ], raiseonerr=False)
            assert res.returncode == 32
        finally:
            self.cleanup_mount(mountpoint)

    def test_uninstall_samba(self):
        self.smbserver.run_command(['ipa-client-samba', '--uninstall', '-U'])
        res = self.smbserver.run_command(
            ['systemctl', 'status', 'winbind'], raiseonerr=False)
        assert res.returncode == 3
        res = self.smbserver.run_command(
            ['systemctl', 'status', 'smb'], raiseonerr=False)
        assert res.returncode == 3

    def test_repeated_uninstall_samba(self):
        """Test samba uninstallation after successful uninstallation.

        Test for bug https://pagure.io/freeipa/issue/8019.
        """
        self.smbserver.run_command(['ipa-client-samba', '--uninstall', '-U'])

    def test_samba_reinstall(self):
        """Test samba can be reinstalled.

        Test installation after uninstallation and do some sanity checks.
        Test for bug https://pagure.io/freeipa/issue/8021
        """
        self.test_install_samba()
        self.test_smb_access_for_ipa_user_at_ipa_client()

    def test_cleanup(self):
        tasks.unconfigure_windows_dns_for_trust(self.ad, self.master)
