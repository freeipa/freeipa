#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for NFS-related features like
   krb5 NFS and automount locations.

   Wishlist
   * add automount direct and indirect maps
   * add automount /home for the "seattle" location only
   * validate it is not available in another location
   * krb5 /home for IdM users in test_automount
   * store nfs configuration in a single place
"""

from __future__ import absolute_import

import os
import pytest
import re
import time

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

# give some time for units to stabilize
# otherwise we get transient errors
WAIT_AFTER_INSTALL = 5
WAIT_AFTER_UNINSTALL = WAIT_AFTER_INSTALL


class TestNFS(IntegrationTest):

    num_clients = 3
    topology = 'line'

    def cleanup(self):

        nfssrv = self.clients[0]
        nfsclt = self.clients[1]
        automntclt = self.clients[2]

        nfsclt.run_command(["umount", "-a", "-t", "nfs4"])
        nfsclt.run_command(["systemctl", "stop", "rpc-gssd"])

        nfssrv.run_command(["systemctl", "stop", "nfs-server"])
        nfssrv.run_command(["systemctl", "disable", "nfs-server"])
        nfssrv.run_command([
            "rm", "-f", "/etc/exports.d/krbnfs.exports",
            "/etc/exports.d/stdnfs.exports"
        ])

        nfssrv.run_command(["rm", "-rf", "/exports"])

        self.master.run_command([
            "ipa", "host-mod", automntclt.hostname,
            "--location", "''"
        ])
        # not strictly necessary, but this exercises automountlocation-del
        self.master.run_command([
            "ipa", "automountlocation-del", "seattle"
        ])
        nfsclt.run_command(["systemctl", "restart", "nfs-utils"])
        nfssrv.run_command(["systemctl", "restart", "nfs-utils"])

    def test_prepare_users(self):

        users = {
            "athena": "p",
            "euripides": "s"
        }
        temp_pass = 'temppass'
        for user in users:
            self.master.run_command([
                "ipa", "user-add",
                "%s" % user, "--first", "%s" % user,
                "--last", "%s" % users[user],
                '--password'], stdin_text="%s\n%s\n" % (temp_pass, temp_pass)
            )
            self.master.run_command(["kdestroy", "-A"])
            password = "Secret123"
            user_kinit = "%s\n%s\n%s\n" % (temp_pass, password, password)
            self.master.run_command(
                ['kinit', user], stdin_text=user_kinit
            )
            self.master.run_command(["kdestroy", "-A"])
            tasks.kinit_admin(self.master)

    def test_krb5_nfsd(self):

        nfssrv = self.clients[0]

        # NFS keytab management
        self.master.run_command([
            "ipa", "service-add", "nfs/%s" % nfssrv.hostname
        ])
        nfssrv.run_command([
            "ipa-getkeytab", "-p", "nfs/%s" % nfssrv.hostname,
            "-k", "/etc/krb5.keytab"
        ])
        nfssrv.run_command(["systemctl", "restart", "nfs-server"])
        nfssrv.run_command(["systemctl", "enable", "nfs-server"])
        time.sleep(WAIT_AFTER_INSTALL)

        basedir = "exports"
        exports = {
            "krbnfs": "*(sec=krb5p,rw)",
            "stdnfs": "*(ro)",
            "home": "*(sec=krb5p,rw)"
        }
        for export in exports:
            exportpath = os.sep.join(('', basedir, export))
            exportfile = os.sep.join((
                '', 'etc', 'exports.d', "%s.exports" % export
            ))
            exportline = " ".join((exportpath, exports[export]))
            nfssrv.run_command(["mkdir", "-p", exportpath])
            nfssrv.run_command(["chmod", "770", exportpath])
            nfssrv.put_file_contents(exportfile, exportline)
            nfssrv.run_command(["cat", exportfile])
        nfssrv.run_command(["exportfs", "-r"])
        nfssrv.run_command(["exportfs", "-s"])

    def test_krb5_nfs_manual_configuration(self):

        nfssrv = self.clients[0]
        nfsclt = self.clients[1]

        nfsclt.run_command(["systemctl", "restart", "rpc-gssd"])
        time.sleep(WAIT_AFTER_INSTALL)
        mountpoints = ("/mnt/krb", "/mnt/std", "/home")
        for mountpoint in mountpoints:
            nfsclt.run_command(["mkdir", "-p", mountpoint])
        nfsclt.run_command([
            "systemctl", "status", "gssproxy"
        ])
        nfsclt.run_command([
            "systemctl", "status", "rpc-gssd"
        ])
        nfsclt.run_command([
            "mount", "-t", "nfs4", "-o", "sec=krb5p,vers=4.0",
            "%s:/exports/krbnfs" % nfssrv.hostname, "/mnt/krb", "-v"
        ])
        nfsclt.run_command([
            "mount", "-t", "nfs4", "-o", "sec=krb5p,vers=4.0",
            "%s:/exports/home" % nfssrv.hostname, "/home", "-v"
        ])

    def test_automount(self):
        """
        Test if ipa-client-automount behaves as expected
        """

        nfssrv = self.clients[0]
        automntclt = self.clients[2]

        self.master.run_command([
            "ipa", "automountlocation-add", "seattle"
        ])
        self.master.run_command([
            "ipa", "automountmap-add", "seattle", "auto.home"
        ])
        self.master.run_command([
            "ipa", "automountkey-add", "seattle", "auto.home",
            "--key='*'", "--info=sec=krb5p,vers=4"
            " 'rhel8-nfsserver0.laptop.example.org:/export/home/&'"
        ])
        self.master.run_command([
            "ipa", "automountkey-add", "seattle", "auto.master",
            "--key=/home", "--info=auto.home"
        ])

        self.master.run_command([
            "ipa", "host-mod", automntclt.hostname,
            "--location", "seattle"
        ])

        # systemctl non-fatal errors will only be displayed
        # if ipa-client-automount is launched with --debug
        result1 = automntclt.run_command([
            'ipa-client-automount', '--location', 'seattle',
            '-U', '--debug'
        ])

        time.sleep(WAIT_AFTER_INSTALL)

        # systemctl non-fatal errors will show up like this:
        # stderr=Failed to restart nfs-secure.service: \
        #        Unit nfs-secure.service not found.
        # normal output:
        # stderr=
        m1 = re.search(r'(?<=stderr\=Failed).+', result1.stderr_text)
        # maybe re-use m1.group(0) if it exists.
        assert m1 is None

        # https://pagure.io/freeipa/issue/7918
        # check whether idmapd.conf was setup using the IPA domain
        automntclt.run_command([
            "grep", "Domain = %s" % self.master.domain.name, "/etc/idmapd.conf"
        ])

        automntclt.run_command([
            "mount", "-t", "nfs4", "-o", "sec=krb5p,vers=4.0",
            "%s:/exports/home" % nfssrv.hostname, "/home", "-v"
        ])

        # TODO leverage users

        automntclt.run_command(["umount", "-a", "-t", "nfs4"])

        result2 = automntclt.run_command([
            'ipa-client-automount', '--uninstall', '-U', '--debug'
        ])
        m2 = re.search(r'(?<=stderr\=Failed).+', result2.stderr_text)
        assert m2 is None

        time.sleep(WAIT_AFTER_UNINSTALL)

        # https://pagure.io/freeipa/issue/7918
        # test for --idmap-domain DNS
        automntclt.run_command([
            'ipa-client-automount', '--location', 'default',
            '-U', '--debug', "--idmap-domain", "DNS"
        ])

        time.sleep(WAIT_AFTER_INSTALL)

        # check whether idmapd.conf was setup properly:
        # grep must not find any configured Domain.
        result = automntclt.run_command(
            ["grep", "^Domain =", "/etc/idmapd.conf"], raiseonerr=False
        )
        assert result.returncode == 1

        automntclt.run_command([
            'ipa-client-automount', '--uninstall', '-U', '--debug'
        ])

        time.sleep(WAIT_AFTER_UNINSTALL)

        # https://pagure.io/freeipa/issue/7918
        # test for --idmap-domain exampledomain.net
        nfs_domain = "exampledomain.net"
        automntclt.run_command([
            'ipa-client-automount', '--location', 'default',
            '-U', '--debug', "--idmap-domain", nfs_domain
        ])
        # check whether idmapd.conf was setup using nfs_domain
        automntclt.run_command([
            "grep", "Domain = %s" % nfs_domain, "/etc/idmapd.conf"
        ])

        time.sleep(WAIT_AFTER_INSTALL)

        automntclt.run_command([
            'ipa-client-automount', '--uninstall', '-U', '--debug'
        ])

        time.sleep(WAIT_AFTER_UNINSTALL)

        self.cleanup()


class TestIpaClientAutomountFileRestore(IntegrationTest):

    num_clients = 1
    topology = 'line'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def teardown_method(self, method):
        tasks.uninstall_client(self.clients[0])

    def nsswitch_backup_restore(
        self,
        no_sssd=False,
        clear_automount_entry=False,
        remove_sss_from_automount_entry=False,
        invert_arguments_in_automount_entry=False
    ):

        sha256nsswitch_cmd = ["sha256sum", "/etc/nsswitch.conf"]
        cmd = self.clients[0].run_command(sha256nsswitch_cmd)
        print("Original sha256 of nsswitch.conf: %s" % cmd.stdout_text)

        if remove_sss_from_automount_entry:
            self.clients[0].run_command([
                "sed", "-i", "-e",
                "s/sss files/files/g",
                "/etc/nsswitch.conf"
            ])
        elif invert_arguments_in_automount_entry:
            self.clients[0].run_command([
                "sed", "-i", "-e",
                "s/sss files/files sss/g",
                "/etc/nsswitch.conf"
            ])

        cmd = self.clients[0].run_command(sha256nsswitch_cmd)
        orig_sha256 = cmd.stdout_text

        grep_automount_command = \
            "grep automount /etc/nsswitch.conf | cut -d: -f2"

        tasks.install_client(self.master, self.clients[0])
        if clear_automount_entry:
            self.clients[0].run_command([
                "sed", "-i", "-e", "s/automount:.*//", "/etc/nsswitch.conf"
            ])
        cmd = self.clients[0].run_command(grep_automount_command)
        after_ipa_client_install = cmd.stdout_text.split()
        print(
            "After ipa-client-install, automount database contains: %s" %
            after_ipa_client_install
        )

        if no_sssd:
            ipa_client_automount_command = [
                "ipa-client-automount", "--no-sssd", "-U"
            ]
        else:
            ipa_client_automount_command = [
                "ipa-client-automount", "-U"
            ]
        self.clients[0].run_command(ipa_client_automount_command)
        cmd = self.clients[0].run_command(grep_automount_command)
        after_ipa_client_automount = cmd.stdout_text.split()
        print(
            "After ipa-client-automount, automount database contains: %s" %
            after_ipa_client_automount
        )
        if no_sssd:
            assert after_ipa_client_automount == ['files', 'ldap']
        elif clear_automount_entry:
            # empty because user forced it to be empty. We don't add
            # sssd options.
            assert after_ipa_client_automount == []
        else:
            assert after_ipa_client_automount == ['sss', 'files']

        self.clients[0].run_command([
            "ipa-client-automount", "--uninstall", "-U"
        ])
        cmd = self.clients[0].run_command(grep_automount_command)
        assert cmd.stdout_text.split() == after_ipa_client_install

        tasks.uninstall_client(self.clients[0])
        cmd = self.clients[0].run_command(sha256nsswitch_cmd)
        assert cmd.stdout_text == orig_sha256

    def test_nsswitch_backup_restore_no_sssd(self):
        self.nsswitch_backup_restore(
            no_sssd=True, remove_sss_from_automount_entry=True
        )

    @pytest.mark.xfail(reason="freeipa ticket 8042", strict=True)
    def test_nsswitch_backup_restore_invert_automount_arguments(self):
        self.nsswitch_backup_restore(invert_arguments_in_automount_entry=True)

    def test_nsswitch_backup_restore_no_automount_entry(self):
        self.nsswitch_backup_restore(clear_automount_entry=True)
