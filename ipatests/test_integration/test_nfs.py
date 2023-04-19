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
import re
import time

import pytest

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

        time.sleep(WAIT_AFTER_UNINSTALL)

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
        for user, last in users.items():
            self.master.run_command([
                "ipa", "user-add",
                user, "--first", user,
                "--last", last,
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
        for export, options in exports.items():
            exportpath = os.sep.join(('', basedir, export))
            exportfile = os.sep.join((
                '', 'etc', 'exports.d', "%s.exports" % export
            ))
            exportline = " ".join((exportpath, options))
            nfssrv.run_command(["mkdir", "-p", exportpath])
            nfssrv.run_command(["chmod", "770", exportpath])
            nfssrv.put_file_contents(exportfile, exportline)
            nfssrv.run_command(["cat", exportfile])
        nfssrv.run_command(["exportfs", "-r"])
        nfssrv.run_command(["exportfs", "-s"])

    def test_krb5_nfs_manual_configuration(self):

        nfssrv = self.clients[0]
        nfsclt = self.clients[1]

        # for journalctl --since
        since = time.strftime('%Y-%m-%d %H:%M:%S')
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
        error = "Unspecified GSS failure"
        check_log = [
            'journalctl', '-u', 'gssproxy', '--since={}'.format(since)]
        result = nfsclt.run_command(check_log)
        assert error not in (result.stdout_text, result.stderr_text)

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

        time.sleep(WAIT_AFTER_UNINSTALL)

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

    @pytest.fixture(autouse=True)
    def automountfile_restore_setup(self, request):
        def fin():
            tasks.uninstall_client(self.clients[0])
        request.addfinalizer(fin)

    def nsswitch_backup_restore(self):

        # In order to get a more pure sum, one that ignores the Generated
        # header and any whitespace we have to do a bit of work...
        sha256nsswitch_cmd = \
            'egrep -v "Generated|^$" /etc/nsswitch.conf | sed "s/\\s//g" ' \
            '| sort | sha256sum'

        cmd = self.clients[0].run_command(sha256nsswitch_cmd)
        orig_sha256 = cmd.stdout_text

        grep_automount_command = \
            "grep automount /etc/nsswitch.conf | cut -d: -f2"

        tasks.install_client(self.master, self.clients[0])
        cmd = self.clients[0].run_command(grep_automount_command)
        after_ipa_client_install = cmd.stdout_text.split()

        ipa_client_automount_command = [
            "ipa-client-automount", "-U"
        ]
        self.clients[0].run_command(ipa_client_automount_command)
        cmd = self.clients[0].run_command(grep_automount_command)
        after_ipa_client_automount = cmd.stdout_text.split()
        # The default order depends on the authselect version
        # but we only care about the list of sources, not their order
        assert sorted(after_ipa_client_automount) == ['files', 'sss']

        cmd = self.clients[0].run_command(grep_automount_command)
        assert cmd.stdout_text.split() == after_ipa_client_automount

        self.clients[0].run_command([
            "ipa-client-automount", "--uninstall", "-U"
        ])

        # https://pagure.io/freeipa/issue/8190
        # check that no ipa_automount_location is left in sssd.conf
        # also check for autofs_provider for good measure
        grep_automount_in_sssdconf_cmd = \
            "egrep ipa_automount_location\\|autofs_provider " \
            "/etc/sssd/sssd.conf"
        cmd = self.clients[0].run_command(
            grep_automount_in_sssdconf_cmd, raiseonerr=False
        )
        assert cmd.returncode == 1, \
            "PG8190 regression found: ipa_automount_location still " \
            "present in sssd.conf"

        cmd = self.clients[0].run_command(grep_automount_command)
        assert cmd.stdout_text.split() == after_ipa_client_install

        self.verify_checksum_after_ipaclient_uninstall(
            sha256nsswitch_cmd=sha256nsswitch_cmd,
            orig_sha256=orig_sha256
        )

    def verify_checksum_after_ipaclient_uninstall(
        self,
        sha256nsswitch_cmd,
        orig_sha256
    ):
        tasks.uninstall_client(self.clients[0])
        cmd = self.clients[0].run_command(sha256nsswitch_cmd)
        assert cmd.stdout_text == orig_sha256

    def test_nsswitch_backup_restore_sssd(self):
        self.nsswitch_backup_restore()


class TestIpaAutomountLocation(IntegrationTest):

    num_clients = 1
    topology = 'line'

    AUTOMOUNT_LOCATION1 = 'baltimore'
    AUTOMOUNT_LOCATION2 = 'raleigh'
    LOCATION1_DESCRIPTION = 'AUTOMOUNT_LOCATION_BALTIMORE'
    INVALID_AUTOMOUNT_LOCATION = ''
    INVALID_AUTOMOUNT_MAP = ''
    AUTOMOUNT_DEFAULT_LOCATION = 'default'
    AUTOMOUNT_CUSTOM_MAP_NAME1 = 'auto.share1'
    AUTOMOUNT_CUSTOM_MAP_NAME2 = 'auto.share2'
    AUTOMOUNT_DEFAULT_MAP1 = 'auto.master'
    AUTOMOUNT_DEFAULT_MAP2 = 'auto.direct'
    AUTOMOUNT_CUSTOM_KEY = '/share'
    INVALID_MAP_KEY = ''
    MOUNT_LOCATION = '/usr/share/man'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])

    def test_default_automount_location_exists(self):
        """
        This testcase checks that default automount
        location exists upon IPA server installation.
        """
        cmd = self.clients[0].run_command(
            ["ipa", "automountlocation-find",
             self.AUTOMOUNT_DEFAULT_LOCATION]
        )
        assert '1 automount location matched' in cmd.stdout_text
        assert 'Location: {}'.format(self.AUTOMOUNT_DEFAULT_LOCATION) \
               in cmd.stdout_text

    def test_default_automount_maps(self):
        """
        This testcase checks that default automount location
        has auto.direct and auto.master maps
        """
        cmd = self.master.run_command(
            ["ipa", "automountmap-find",
             self.AUTOMOUNT_DEFAULT_LOCATION]
        )
        assert '2 automount maps matched' in cmd.stdout_text
        assert 'Map: auto.direct' in cmd.stdout_text
        assert 'Map: auto.master' in cmd.stdout_text

    def test_default_automount_location_show(self):
        """
        This testcase checks that automount location
        added on IPA server is shown on the IPA clients[0]
        using automountlocation-show command.
        """
        cmd = self.clients[0].run_command(
            ["ipa", "automountlocation-show",
             self.AUTOMOUNT_DEFAULT_LOCATION]
        )
        assert "Location: {}".format(
            self.AUTOMOUNT_DEFAULT_LOCATION) in cmd.stdout_text

    def test_automount_invalid_location_show(self):
        """
        This testcase checks that proper message is displayed
        when invalid automount location is lookedup on
        an IPA clients.
        """
        cmd = self.clients[0].run_command(
            ["ipa","automountlocation-show",
             self.INVALID_AUTOMOUNT_LOCATION], raiseonerr=False
        )
        assert cmd.returncode == 1
        assert "ipa: ERROR: 'location' is required" in cmd.stderr_text

    def test_automount_invalid_location_find(self):
        """
        This testcase checks that proper message is displayed
        when invalid automount location is lookedup on
        an IPA clients[0].
        """
        cmd = self.clients[0].run_command(
            ["ipa", "automountlocation-find",
             self.INVALID_AUTOMOUNT_LOCATION], raiseonerr=False
        )
        assert '1 automount location matched' in cmd.stdout_text
        assert 'Location: {}'.format(self.AUTOMOUNT_DEFAULT_LOCATION) \
            in cmd.stdout_text

    def test_automount_location_show_all(self):
        """
        This testcase checks automount location show command works
        will --all option
        """
        basedn = self.master.domain.basedn
        cmd = self.clients[0].run_command(
            ["ipa", "automountlocation-show",
             self.AUTOMOUNT_DEFAULT_LOCATION, "--all"]
        )
        assert 'dn: cn={},cn=automount,{}'.format(
            self.AUTOMOUNT_DEFAULT_LOCATION, basedn) in cmd.stdout_text
        assert 'Location: {}'.format(
            self.AUTOMOUNT_DEFAULT_LOCATION) in cmd.stdout_text
        assert 'objectclass: nsContainer, top' in cmd.stdout_text

    def test_automount_location_show_raw(self):
        """
        This testcase checks automount location show command works
        with --raw option
        """
        cmd = self.clients[0].run_command(
            ["ipa", "automountlocation-show",
             self.AUTOMOUNT_DEFAULT_LOCATION, "--raw"]
        )
        assert "cn: {}".format(
            self.AUTOMOUNT_DEFAULT_LOCATION) in cmd.stdout_text

    def test_automount_location_show_rights_all(self):
        """
        This testcase checks automount location show command
        works with --rights and --all option
        """
        basedn = self.master.domain.basedn
        cmd = self.clients[0].run_command(
            ["ipa", "automountlocation-show",
             self.AUTOMOUNT_DEFAULT_LOCATION,
             "--rights", "--all"]
        )
        assert 'dn: cn={},cn=automount,{}'.format(
            self.AUTOMOUNT_DEFAULT_LOCATION, basedn) in cmd.stdout_text
        assert 'Location: {}'.format(
            self.AUTOMOUNT_DEFAULT_LOCATION) in cmd.stdout_text
        assert "attributelevelrights: {'cn': 'rscwo', " \
            "'objectclass': 'rscwo', 'aci': 'rscwo', " \
            "'nsaccountlock': 'rscwo'}" in cmd.stdout_text
        assert 'objectclass: nsContainer, top' in cmd.stdout_text

    def test_automountmap_add_custom_location(self):
        """
        This testcase checks that new automountmap is added
        to default automount location.
        """
        cmd = self.master.run_command(
            ["ipa", "automountmap-add",
             self.AUTOMOUNT_DEFAULT_LOCATION,
             self.AUTOMOUNT_CUSTOM_MAP_NAME1]
        )
        assert 'Added automount map "{}"'.format(
            self.AUTOMOUNT_CUSTOM_MAP_NAME1) in cmd.stdout_text
        assert 'Map: {}'.format(
            self.AUTOMOUNT_CUSTOM_MAP_NAME1) in cmd.stdout_text

    def test_add_existing_map_to_location(self):
        """
        This testcase checks that error is displayed on
        the console when similar map name is added to
        location.
        """
        cmd = self.master.run_command(
            ["ipa", "automountmap-add",
             self.AUTOMOUNT_DEFAULT_LOCATION,
             self.AUTOMOUNT_CUSTOM_MAP_NAME1], raiseonerr=False
        )
        assert 'ipa: ERROR: automount map with name "{}" already exists'.format(
            self.AUTOMOUNT_CUSTOM_MAP_NAME1) in cmd.stderr_text

    def test_modify_automount_map_description(self):
        """
        This testcase checks that description is
        modified for the automountmap
        """
        cmd = self.master.run_command(
            ["ipa", "automountmap-mod",
             self.AUTOMOUNT_DEFAULT_LOCATION,
             self.AUTOMOUNT_DEFAULT_MAP1,
             "--desc=" + self.LOCATION1_DESCRIPTION]
        )
        assert 'Modified automount map "{}"'.format(
            self.AUTOMOUNT_DEFAULT_MAP1) in cmd.stdout_text
        assert 'Map: {}'.format(
            self.AUTOMOUNT_DEFAULT_MAP1) in cmd.stdout_text
        assert 'Description: {}'.format(
            self.LOCATION1_DESCRIPTION) in cmd.stdout_text

    def test_automountmap_find_with_desc(self):
        """
        This test checks that automountmap is located
        with description
        """
        cmd = self.master.run_command(
            ["ipa", "automountmap-find",
             self.AUTOMOUNT_DEFAULT_LOCATION,
             "--desc=" + self.LOCATION1_DESCRIPTION]
        )
        assert '1 automount map matched' in cmd.stdout_text
        assert 'Map: {}'.format(
            self.AUTOMOUNT_DEFAULT_MAP1) in cmd.stdout_text
        assert 'Description: {}'.format(
            self.LOCATION1_DESCRIPTION) in cmd.stdout_text

    def test_automountmap_doesnt_get_added_with_returncode_1(self):
        """
        This testcase checks that automountmap doesnt
        get added when the returncode is 1
        https://fedorahosted.org/freeipa/ticket/1520
        """
        msg = (
            'ipa: ERROR: automount map with name "{}" already exists'
            .format(self.AUTOMOUNT_CUSTOM_MAP_NAME2)
        )
        self.master.run_command(
            ["ipa", "automountlocation-add",
             self.AUTOMOUNT_LOCATION1]
        )
        self.master.run_command(
            ["ipa", "automountlocation-add",
             self.AUTOMOUNT_LOCATION2]
        )
        self.master.run_command(
            ["ipa","automountmap-add", self.AUTOMOUNT_LOCATION2,
             self.AUTOMOUNT_CUSTOM_MAP_NAME2]
        )
        self.master.run_command(
            ["ipa", "automountkey-add", self.AUTOMOUNT_LOCATION2,
             self.AUTOMOUNT_CUSTOM_MAP_NAME2,
             "--key=" + self.AUTOMOUNT_CUSTOM_KEY,
             "--info=auto.share1"]
        )
        cmd = self.master.run_command(
            ["ipa", "automountmap-add-indirect",
             self.AUTOMOUNT_LOCATION2, self.AUTOMOUNT_CUSTOM_MAP_NAME2,
             "--mount=" + self.MOUNT_LOCATION], raiseonerr=False
        )
        assert cmd.returncode == 1
        assert msg in cmd.stderr_text

    def test_correct_message_with_empty_automountlocation_name(self):
        """
        Test case checkc correct message is displayed
        when no location is specified.

        """
        msg = "ipa: ERROR: 'location' is required"
        cmd = self.clients[0].run_command(
            ["ipa", "automountlocation-add",
             ""], raiseonerr=False
        )
        assert cmd.returncode == 1
        assert msg in cmd.stderr_text

    def test_correct_message_with_empty_automountmap_name(self):
        """
        This testcase checks correct message is displayed when
        empty mapname is added
        https://fedorahosted.org/freeipa/ticket/1549
        """
        msg = "ipa: ERROR: 'map' is required"
        cmd = self.master.run_command(
            ["ipa", "automountmap-add", self.AUTOMOUNT_LOCATION1,
             self.INVALID_AUTOMOUNT_MAP], raiseonerr=False
        )
        assert cmd.returncode == 1
        assert msg in cmd.stderr_text

    def test_correct_message_with_empty_automountkey_name(self):
        """
        This testcase checks correct message is displayed when
        empty keyname is deleted
        https://pagure.io/freeipa/issue/1550
        """
        msg = "ipa: ERROR: 'key' is required"
        cmd = self.master.run_command(
            ["ipa", "automountmap-add",
             self.AUTOMOUNT_LOCATION1,
             self.AUTOMOUNT_CUSTOM_MAP_NAME1]
        )
        cmd = self.master.run_command(
            ["ipa", "automountkey-add",
             self.AUTOMOUNT_LOCATION1,
             self.AUTOMOUNT_CUSTOM_MAP_NAME1,
             "--key=" + self.INVALID_MAP_KEY,
             "--info=-ro,soft {}:{}".format(
                 self.master.hostname, self.MOUNT_LOCATION)], raiseonerr=False
        )
        assert cmd.returncode == 1
        assert msg in cmd.stderr_text

    def test_automount_find_pkey_only_option(self):
        """
        This testcase checks that pkey only
        option works without any error
        """
        msg1 = "3 automount locations matched"
        msg2 = "Location: {}".format(self.AUTOMOUNT_LOCATION1)
        msg3 = "Location: {}".format(self.AUTOMOUNT_DEFAULT_LOCATION)
        msg4 = "Location: {}".format(self.AUTOMOUNT_LOCATION2)
        cmd = self.clients[0].run_command(
            ["ipa", "automountlocation-find",
             "--pkey-only"]
        )
        assert cmd.returncode == 0
        assert msg1 in cmd.stdout_text
        assert msg2 in cmd.stdout_text
        assert msg3 in cmd.stdout_text
        assert msg4 in cmd.stdout_text

    def test_delete_default_automount_map(self):
        """
        This testcase deletes default automount location
        and checks that the maps are deleted.
        https://fedorahosted.org/freeipa/ticket/1509
        """
        cmd = self.master.run_command(
            ["ipa", "automountlocation-del",
             self.AUTOMOUNT_DEFAULT_LOCATION]
        )
        assert 'Deleted automount location "{}"'.format(
            self.AUTOMOUNT_DEFAULT_LOCATION) in cmd.stdout_text
        cmd1 = self.master.run_command(
            ["ipa", "automountmap-show", self.AUTOMOUNT_DEFAULT_LOCATION,
             self.AUTOMOUNT_DEFAULT_MAP1], raiseonerr=False
        )
        assert 'ipa: ERROR: {}: automount map not found'.format(
            self.AUTOMOUNT_DEFAULT_MAP1) in cmd1.stderr_text
