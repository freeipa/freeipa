#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for SMB-related features like
   configuring Samba file server and mounting SMB file system
"""

from __future__ import absolute_import

import time
import os

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths

# give some time for units to stabilize
# otherwise we get transient errors
WAIT_AFTER_INSTALL = 5
WAIT_AFTER_UNINSTALL = WAIT_AFTER_INSTALL
user_password = "Secret123"
users = {
    "athena": "p",
    "euripides": "s"
}


class TestSMB(IntegrationTest):

    num_replicas = 1
    num_clients = 1

    @classmethod
    def fix_resolv_conf(cls, client, server):

        contents = client.get_file_contents(paths.RESOLV_CONF,
                                            encoding='utf-8')
        nameserver = 'nameserver %s\n' % server.ip
        if not contents.startswith(nameserver):
            contents = nameserver + contents.replace(nameserver, '')
            client.run_command([
                '/usr/bin/cp', paths.RESOLV_CONF,
                '%s.sav' % paths.RESOLV_CONF
            ])
            client.put_file_contents(paths.RESOLV_CONF, contents)

    @classmethod
    def restore_resolv_conf(cls, client):
        client.run_command([
            '/usr/bin/cp',
            '%s.sav' % paths.RESOLV_CONF,
            paths.RESOLV_CONF
        ])

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_adtrust(cls.master)

        for client in cls.replicas + cls.clients:
            cls.fix_resolv_conf(client, cls.master)
            tasks.install_client(cls.master, client,
                                 extra_args=['--mkhomedir'])

        cls.replicas[0].collect_log('/var/log/samba/')
        cls.master.collect_log('/var/log/samba/')

    @classmethod
    def uninstall(cls, mh):
        for client in cls.clients + cls.replicas:
            tasks.uninstall_client(client)
            cls.restore_resolv_conf(client)
        tasks.uninstall_master(cls.master)

    def test_prepare_users(self):
        smbsrv = self.replicas[0]

        temp_pass = "t3mp!p4ss"
        user_kinit = "%s\n%s\n%s\n" % (temp_pass,
                                       user_password, user_password)
        user_addpass = "%s\n%s\n" % (temp_pass, temp_pass)
        for user in users:
            self.master.run_command([
                "ipa", "user-add",
                "%s" % user, "--first", "%s" % user,
                "--last", "%s" % users[user],
                '--password'], stdin_text=user_addpass
            )
            self.master.run_command(['kdestroy', '-A'])
            self.master.run_command(
                ['kinit', user], stdin_text=user_kinit
            )
            # Force creation of home directories on the SMB server
            smbsrv.run_command(['su', '-l', '-', user, '-c', 'stat .'])

            # Switch back to admin
            self.master.run_command(['kdestroy', '-A'])
            tasks.kinit_admin(self.master)

    def test_install_samba(self):

        smbsrv = self.replicas[0]

        smbsrv.run_command([
            "ipa-client-samba", "-U"
        ])

        smbsrv.run_command([
            "systemctl", "enable", "--now", "smb", "winbind"
        ])
        time.sleep(WAIT_AFTER_INSTALL)

        smbsrv.run_command(['smbstatus'])

    def test_access_homes_smbclient(self):
        """Access user home directory via smb3.ko and smbclient
           Test checks that both kernel SMB3 driver and userspace
           smbclient utility work against IPA-enrolled Samba server
        """
        smbsrv = self.replicas[0]
        smbclt = self.clients[0]

        remote_uri = '//{smbsrv}/homes'.format(smbsrv=smbsrv.hostname)

        for user in users:
            smbclt.run_command(['kinit', user], stdin_text=user_password)
            mntpoint = '/mnt/{user}'.format(user=user)
            userfile = '{user}.dat'.format(user=user)

            smbclt.run_command(['mkdir', '-p', mntpoint])
            smbclt.run_command(['mount', '-t', 'cifs',
                                remote_uri, mntpoint, '-o',
                                'user={user},sec=krb5i'.format(user=user)])
            smbclt.run_command(['dd', 'count=1024', 'bs=1K', 'if=/dev/zero',
                                'of={path}'.format(
                                    path=os.path.join(mntpoint, userfile))])
            smbclt.run_command(['findmnt', '-t', 'cifs'])
            smbclt.run_command(['ls', '-laZ',
                                os.path.join(mntpoint, userfile)])
            smbsrv.run_command(['smbstatus'])
            smbclt.run_command(['umount', '-a', '-t', 'cifs'])
            smbclt.run_command(['smbclient', '-k', remote_uri,
                                '-c', 'allinfo {path}'.format(path=userfile)])
            smbclt.run_command(['kdestroy', '-A'])

    def test_uninstall_samba(self):
        for user in users:
            self.master.run_command(['ipa', 'user-del', user])

        smbsrv = self.replicas[0]
        smbsrv.run_command(['ipa-client-samba', '--uninstall', '-U'])
        # test for https://pagure.io/freeipa/issue/8019
        # try another uninstall after the first one:
        smbsrv.run_command(['ipa-client-samba', '--uninstall', '-U'])
        # test for https://pagure.io/freeipa/issue/8021
        # try to install again:
        smbsrv.run_command(["ipa-client-samba", "-U"])
        # cleanup:
        smbsrv.run_command(['ipa-client-samba', '--uninstall', '-U'])
