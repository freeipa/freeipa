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

from ipaplatform.paths import paths
from ipatests.test_integration.base import (
    IntegrationTest, MultiDomainIntegrationTest)
from ipatests.pytest_ipa.integration import tasks
# give some time for units to stabilize
# otherwise we get transient errors
WAIT_AFTER_INSTALL = 5
WAIT_AFTER_UNINSTALL = WAIT_AFTER_INSTALL


def remove_automount(host):
    time.sleep(WAIT_AFTER_INSTALL)
    host.run_command([
        'ipa-client-automount', '--uninstall', '-U'
    ], raiseonerr=False)
    time.sleep(WAIT_AFTER_UNINSTALL)


def add_automount(host, extra_args, raiseonerr=False):
    time.sleep(WAIT_AFTER_UNINSTALL)
    args = [
        "ipa-client-automount",
    ]
    args.extend(extra_args)
    ret = host.run_command(args, raiseonerr=raiseonerr)
    time.sleep(WAIT_AFTER_INSTALL)
    return ret


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


class TestIpaClientAutomountDiscovery(MultiDomainIntegrationTest):

    num_replicas = 0
    num_trusted_replicas = 0
    num_clients = 1
    num_trusted_clients = 1
    topology = "line"

    def test_automount_valid_domain(self):
        """Test that --domain option controls which domain is used
        for DNS SRV record lookup.

        Without --domain: client searches in its local domain (fails if no
        IPA records) With --domain: client searches in the specified
        domain (succeeds for IPA domain)
        """
        testdomain1 = self.master.domain.name
        client2 = self.trusted_clients[0]
        tasks.uninstall_client(client2)
        client2.run_command(["ipa-client-install", "--domain", testdomain1,
                             "--realm", self.master.domain.realm,
                             "--server", self.master.hostname,
                             "-p", client2.config.admin_name, "-w",
                             client2.config.admin_password, "-U"]
                            )
        result = add_automount(
            client2, extra_args=['--debug', '-U']
        )
        msg = "Search DNS for SRV record of _ldap._tcp.{0}"
        assert msg.format(client2.domain.name) in result.stderr_text
        remove_automount(client2)
        result2 = add_automount(
            client2, extra_args=['--debug', '--domain', testdomain1, '-U']
        )
        assert msg.format(testdomain1) in result2.stderr_text

    @pytest.mark.parametrize(
        "domain_input,expected_success,test_description", [
            ("{ipa_domain}", True, "valid IPA domain should succeed"),
            ("client.test", False, "non-IPA domain should fail discovery"),
            ("  example.com  ", True, "whitespace should be trimmed"),
            ("EXAMPLE.COM", True, "uppercase should work"),

        ])
    def test_automount_domain_option_integration(
            self, domain_input, expected_success, test_description):
        """Test for --domain affects DNS discovery and system integration.

        This test verifies that the --domain option actually changes the DNS
        discovery behavior and system configuration, not just input validation.

        Test cases:
        - Valid IPA domain: Should successfully discover IPA services and
          configure automount correctly
        - Non-IPA domain: Should fail discovery since no IPA DNS records
          exist in that domain
        """
        client = self.clients[0]
        ipa_domain = self.master.domain.name

        # Replace placeholders in domain_input
        domain_to_test = domain_input.format(ipa_domain=ipa_domain)

        if expected_success:
            # Should succeed
            add_automount(
                client, extra_args=['--domain', domain_to_test,
                                    '--debug', '-U']
            )
            # Verify configuration if successful
            sssd_conf = client.get_file_contents(
                paths.SSSD_CONF).decode()
            assert "autofs_provider = ipa" in sssd_conf, \
                "Autofs provider should be set to ipa"
            # Clean up
            remove_automount(client)
        else:
            # Should fail
            result = client.run_command([
                'ipa-client-automount', '--domain', domain_to_test,
                '--debug'
            ], stdin_text="n", raiseonerr=False)
            assert (
                result.returncode != 0
                or "Autodiscovery did not find LDAP server" in
                result.stderr_text
                or "Invalid domain" in result.stderr_text
            ), f"Should have failed: {test_description}"

    def test_automount_domain_option_overrides_discovery(self):
        """Test that explicit --domain option overrides automatic discovery."""
        client = self.clients[0]
        ipa_domain = self.master.domain.name

        # First install without domain to establish baseline
        result_auto = add_automount(client, extra_args=['--debug', '-U'])
        assert "Search DNS for SRV record" in result_auto.stderr_text
        remove_automount(client)

        # Now with explicit domain
        result_explicit = add_automount(
            client, extra_args=['--domain', ipa_domain, '--debug', '-U']
        )
        explicit_domain_msg = (
            f"Using domain '{ipa_domain}'" in result_explicit.stderr_text
            or f"Search DNS for SRV record of _ldap._tcp.{ipa_domain}"
            in result_explicit.stderr_text
        )

        assert explicit_domain_msg, \
            "Explicit domain should override automatic discovery"

        # Final cleanup
        remove_automount(client)

    def test_automount_domain_hint_for_cross_domain_discovery(self):
        """Test that --domain option enables discovery when client is in
           a different domain than the IPA domain.
        """
        client = self.clients[0]
        other_domain = self.trusted_master.domain.name
        tasks.uninstall_client(client)
        # Add DNS forwarder
        self.master.run_command([
            "ipa", "dnsforwardzone-add", self.trusted_master.domain.name,
            "--forwarder", self.trusted_master.ip,
            "--forward-policy=only"
        ])
        self.trusted_master.run_command([
            "ipa", "dnsforwardzone-add", self.master.domain.name,
            "--forwarder", self.master.ip,
            "--forward-policy=only"
        ])
        # Backup original resolv.conf
        client.resolver.backup()

        try:
            # Install client in a domain other than the IPA domain
            client.resolver.setup_resolver(self.trusted_master.ip,
                                           searchdomains=other_domain)

            # Ensure client is installed for the test
            client.run_command(["ipa-client-install", "--domain", other_domain,
                                "--realm", self.trusted_master.domain.realm,
                                "--server", self.trusted_master.hostname,
                                "-p", client.config.admin_name, "-w",
                                client.config.admin_password, "-U"]
                               )
            # Verify DNS discovery will fail when client is in Non-IPA domain
            # Attempt automount with --domain hint (should succeed)
            nodomain = add_automount(
                client, extra_args=['--debug', '-U']
            )
            # Verify discovery fails.
            assert "DNS record not found" in nodomain.stderr_text
            remove_automount(client)

            # Attempt automount with --domain hint (should succeed)
            withdomain = add_automount(
                client, extra_args=['--domain', other_domain,
                                    '--debug', '-U']
            )
            # Verify discovery finds a IPA server.
            assert "DNS record found" in withdomain.stderr_text
            ipa_discovery = (
                f"Validated servers: {self.trusted_master.hostname}"
                in withdomain.stderr_text
            )
            assert ipa_discovery, \
                "Autodiscovery success"
            # Verify configuration was applied correctly
            sssd_conf = client.get_file_contents(paths.SSSD_CONF).decode()
            assert "autofs_provider = ipa" in sssd_conf, \
                "Autofs provider should be configured"
        finally:
            # Cleanup: restore original resolv.conf and uninstall
            client.resolver.restore()
            remove_automount(client)
