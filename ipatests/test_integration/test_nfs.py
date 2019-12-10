#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for NFS-related features like
   krb5 NFS and automount locations.

   Wishlist
   * add automount /home for the "seattle" location only
   * validate it is not available in another location
"""

from __future__ import absolute_import

import os
import re
import time

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipaplatform import services
from ipaplatform.paths import paths

# give some time for units to stabilize
# otherwise we get transient errors
WAIT_AFTER_INSTALL = 5
WAIT_AFTER_UNINSTALL = WAIT_AFTER_INSTALL

LOCATION = "seattle"
IPA_USER = "athena"
IPA_PASSWORD = "Secret123"

NFS_EXPORTS = {
    'krbnfs_manual': {
        'export_options': '*(sec=krb5p,no_subtree_check,rw)',
        'export_rpath': 'krbnfs_manual',
        'exposed_path': '/krbnfs_manual',
        'mount_path': '/mnt/krbnfs_manual',
    },
    'krbnfs_autofs': {
        'export_options': '*(sec=krb5p,no_subtree_check,rw)',
        'export_rpath': 'krbnfs_autofs',
        'exposed_path': '/krbnfs_autofs',
        'mount_path': '/mnt/krbnfs_autofs',
    },
    'krbnfs_home': {
        'export_options': '*(sec=krb5p,no_subtree_check,rw)',
        'export_rpath': os.path.join('krbnfs_home', IPA_USER),
        'exposed_path': os.path.join(os.sep, 'krbnfs_home', IPA_USER),
        'mount_path': os.path.join('/home', IPA_USER),
    },
}


@pytest.fixture(scope="class")
def krb5_nfs_client(request, mh):
    """Set up NFS client."""
    cls = request.cls
    clients = [cls.nfs_manual, cls.nfs_autofs]
    # nfs-utils has a one way dependency on
    # ConsistsOf='rpc-statd.service rpc-gssd.service rpc-statd-notify.service
    # nfs-blkmap.service'
    # But even though 'rpc-gssd' is the 'PartOf' nfs-utils, it is not restarted
    # due to ConditionPathExists which may initially be in the Failed state.
    # Therefore, rpc-gssd is restarted manually.
    rpcgssd_name = services.knownservices["rpcgssd"].systemd_name
    nfs_utils_name = services.knownservices["nfs-utils"].systemd_name

    for client in clients:
        client.run_command([
            "sed", "-i.sav",
            r"s@/sbin/key\.dns_resolver@& -vv@g",
            paths.REQUEST_KEY_CONF
        ])
        client.run_command(["cat", paths.REQUEST_KEY_CONF])

        # verbosity for rpc-gssd
        client.run_command(
            ["sed", "-i.sav",
             "-e", r"s/^\(# \)\?verbosity=0.*$/verbosity=4/g",
             "-e", r"s/^\(# \)\?rpc-verbosity=0.*$/rpc-verbosity=4/g",
             # we don't want gssproxy for NFS clients (default is '=0')
             "-e", r"s/^use-gss-proxy=1.*$/# &/g",
             paths.SYSCONFIG_NFS])

        # verbosity for nfs-idmapd/nfsidmap
        client.run_command(
            ["sed", "-i.sav",
             "-e", r"s/^\(#\)\?Verbosity = 0.*$/Verbosity = 2/g",
             paths.IDMAPD_CONF])

        client.run_command(["systemctl", "restart", rpcgssd_name])
        client.run_command(["systemctl", "restart", nfs_utils_name])

    # actually, this is a fallback if nfsidmap fails, for example,
    # if kernel keyrings are not available
    nfs_idmapd_name = services.knownservices["rpcidmapd"].systemd_name
    cls.nfs_autofs.run_command(["systemctl", "restart", nfs_idmapd_name])

    # clear nfs idmapping cache if exists
    cls.nfs_autofs.run_command(["nfsidmap", "-l"], raiseonerr=False)
    cls.nfs_autofs.run_command(["nfsidmap", "-c"], raiseonerr=False)
    time.sleep(WAIT_AFTER_INSTALL)

    def fin():
        for client in clients:
            modified_paths = [
                paths.SYSCONFIG_NFS,
                paths.REQUEST_KEY_CONF,
                paths.IDMAPD_CONF,
            ]
            for path in modified_paths:
                client.run_command(["mv", f"{path}.sav", path])
    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def krb5_nfs_server(request, mh):
    """Set up NFS server."""
    cls = request.cls

    # NFS keytab management
    cls.master.run_command([
        "ipa", "service-add", f"nfs/{cls.nfs_server.hostname}"
    ])
    cls.nfs_server.run_command([
        "ipa-getkeytab", "-p", f"nfs/{cls.nfs_server.hostname}",
        "-k", paths.KRB5_KEYTAB
    ])

    # disable NFSv3
    cls.nfs_server.run_command(
        ["sed", "-i.sav",
         "-e", r"s/^\(# \)\?vers3=y.*$/vers3=n/g",
         paths.SYSCONFIG_NFS])

    # verbosity for nfs-idmapd
    cls.nfs_server.run_command(
        ["sed", "-i.sav",
         "-e", r"s/^\(#\)\?Verbosity = 0.*$/Verbosity = 2/g",
         paths.IDMAPD_CONF])

    # gssproxy debugging
    cls.nfs_server.run_command([
        "cp", paths.GSSPROXY_SYSTEM_CONF,
        f"{paths.GSSPROXY_SYSTEM_CONF}.sav"
    ])
    cmd = ("[ -f '{0}' ] && {{ "
           r"sed -i 's/^debug_level\(\|[ ]\+\)=.*$/# &/g' '{0}' ; "
           "echo 'debug_level = 2' >> '{0}' ; "
           "}}"
           ).format(paths.GSSPROXY_SYSTEM_CONF)
    cls.nfs_server.run_command(["/bin/sh", "-c", cmd])

    # manual restart is needed due to
    # nfsdopenone: Opening /proc/net/rpc/nfs4.nametoid/channel failed
    # errno 2 (No such file or directory)
    nfs_idmapd_name = services.knownservices["rpcidmapd"].systemd_name
    cls.nfs_server.run_command(["systemctl", "restart", nfs_idmapd_name])

    nfs_utils_name = services.knownservices["nfs-utils"].systemd_name
    cls.nfs_server.run_command(["systemctl", "restart", nfs_utils_name])

    nfs_server_name = services.knownservices["nfs-server"].systemd_name
    cls.nfs_server.run_command(["systemctl", "enable", nfs_server_name])
    cls.nfs_server.run_command(["systemctl", "restart", nfs_server_name])
    time.sleep(WAIT_AFTER_INSTALL)

    # NFS gssproxy's status
    cls.nfs_server.run_command(["cat", "/proc/net/rpc/use-gss-proxy"],
                               raiseonerr=False)

    # setup exports
    rootdir = "/exports"
    exports_root = f"{rootdir} *(rw,no_subtree_check,sec=krb5p,fsid=0)"
    sys_exportfile = "/etc/exports"
    sub_exportdir = "/etc/exports.d"
    # backup system-wide exports config
    cls.nfs_server.run_command([
        "cp", sys_exportfile, f"{sys_exportfile}.sav"
    ])
    cls.nfs_server.put_file_contents(sys_exportfile, exports_root)
    cls.nfs_server.run_command(["cat", sys_exportfile])
    cls.nfs_server.run_command(["mkdir", "-p", sub_exportdir],
                               raiseonerr=False)

    for export, options in NFS_EXPORTS.items():
        exportpath = os.path.join(rootdir, export)
        exportfile = os.path.join(sub_exportdir, f"{export}.exports")
        exportline = f"{exportpath} {options['export_options']}"
        cls.nfs_server.run_command(["mkdir", "-m", "1777", "-p", exportpath])
        cls.nfs_server.put_file_contents(exportfile, exportline)
        cls.nfs_server.run_command(["cat", exportfile])
    cls.nfs_server.run_command(["exportfs", "-r"])
    cls.nfs_server.run_command(["exportfs", "-s"])

    def fin():
        time.sleep(WAIT_AFTER_UNINSTALL)
        cls.nfs_manual.run_command(["umount", "-a", "-t", "nfs4"])
        cls.nfs_server.run_command(["systemctl", "stop", nfs_server_name])
        cls.nfs_server.run_command(["systemctl", "disable", nfs_server_name])

        # restore modified configs
        modified_paths = [
            paths.SYSCONFIG_NFS,
            paths.GSSPROXY_SYSTEM_CONF,
            paths.IDMAPD_CONF,
            sys_exportfile,
        ]
        for path in modified_paths:
            cls.nfs_server.run_command(["mv", f"{path}.sav", path])

        # clean up exports
        for export in NFS_EXPORTS:
            cls.nfs_server.run_command([
                "rm", "-f", os.path.join(sub_exportdir, f"{export}.exports"),
            ])
        cls.nfs_server.run_command(["rm", "-rf", rootdir], raiseonerr=False)

        cls.master.run_command([
            "ipa", "service-del", f"nfs/{cls.nfs_server.hostname}"
        ])
    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def users(request, mh):
    """Create test user and its home directory."""
    cls = request.cls
    tasks.create_active_user(cls.master, IPA_USER, IPA_PASSWORD)
    tasks.kinit_admin(cls.master)

    # make home dirs
    cls.nfs_server.run_command(["mkhomedir_helper", IPA_USER])
    export_home_path = os.path.join(
        "/exports", NFS_EXPORTS['krbnfs_home']['export_rpath'])
    cls.nfs_server.run_command(
        ["mv", os.path.join("/home", IPA_USER), export_home_path])

    # due nfs root squash, su -l fails (chdir)
    # grant +x as workaround
    cls.nfs_server.run_command(["chmod", "o+x", export_home_path])

    def fin():
        cls.master.run_command(['ipa', 'user-del', IPA_USER])
        cls.master.run_command(
            ["rm", "-rf", export_home_path])
    request.addfinalizer(fin)


@pytest.fixture
def automount_client(request):
    cls = request.cls
    cls.master.run_command([
        "ipa", "automountlocation-add", LOCATION
    ])

    # direct rules
    cls.master.run_command([
        "ipa", "automountmap-add", LOCATION, "auto.share"
    ])
    mount_path = NFS_EXPORTS['krbnfs_autofs']['mount_path']
    exposed_path = NFS_EXPORTS['krbnfs_autofs']['exposed_path']
    cls.master.run_command([
        "ipa", "automountkey-add", LOCATION, "auto.share",
        f"--key={mount_path}",
        ("--info=-fstype=nfs4,rw,sec=krb5p "
         f"{cls.nfs_server.hostname}:{exposed_path}")
    ])
    cls.master.run_command([
        "ipa", "automountkey-add", LOCATION, "auto.master",
        "--key=/-", "--info=auto.share"
    ])

    # indirect rules
    mount_path = os.path.dirname(NFS_EXPORTS['krbnfs_home']['mount_path'])
    exposed_path = os.path.join(
        os.path.dirname(NFS_EXPORTS['krbnfs_home']['exposed_path']), "&")
    cls.master.run_command([
        "ipa", "automountmap-add", LOCATION, "auto.home"
    ])
    cls.master.run_command([
        "ipa", "automountkey-add", LOCATION, "auto.home",
        "--key=*",
        ("--info=-fstype=nfs4,rw,sec=krb5p "
         f"{cls.nfs_server.hostname}:{exposed_path}")
    ])
    cls.master.run_command([
        "ipa", "automountkey-add", LOCATION, "auto.master",
        f"--key={mount_path}", "--info=auto.home"
    ])

    # set autofs logging
    cls.nfs_autofs.run_command(
        ["sed", "-i.sav", r"s/^\(#\)\?logging.*$/logging = debug/g",
         paths.AUTOFS_CONF])

    # systemctl non-fatal errors will only be displayed
    # if ipa-client-automount is launched with --debug
    cls.nfs_autofs.run_command([
        "ipa-client-automount", "--location", LOCATION,
        "-U", "--debug"
    ])
    time.sleep(WAIT_AFTER_INSTALL)

    def fin():
        time.sleep(WAIT_AFTER_UNINSTALL)
        cls.nfs_autofs.run_command(["umount", "-a", "-t", "nfs4"])
        cls.nfs_autofs.run_command(
            ["mv", f"{paths.AUTOFS_CONF}.sav", paths.AUTOFS_CONF])
        cls.nfs_autofs.run_command([
            "ipa-client-automount", "--uninstall", "-U", "--debug"
        ], raiseonerr=False)
        time.sleep(WAIT_AFTER_UNINSTALL)

        cls.master.run_command([
            "ipa", "automountlocation-del", LOCATION
        ])
    request.addfinalizer(fin)


@pytest.mark.usefixtures("users")
@pytest.mark.usefixtures("krb5_nfs_client")
@pytest.mark.usefixtures("krb5_nfs_server")
class TestNFS(IntegrationTest):

    num_clients = 3
    topology = "line"

    @classmethod
    def install(cls, mh):
        cls.nfs_server = cls.clients[0]
        cls.nfs_manual = cls.clients[1]
        cls.nfs_autofs = cls.clients[2]

        super(TestNFS, cls).install(mh)
        Firewall(cls.nfs_server).enable_service("nfs")

    def test_krb5_nfs_manual(self):
        """
        Manual mount NFS share using Kerberos
        """
        # AUTH_SYS should fail on Kerberos only share
        exposed_path = NFS_EXPORTS['krbnfs_manual']['exposed_path']
        mount_path = NFS_EXPORTS['krbnfs_manual']['mount_path']
        self.nfs_manual.run_command(["mkdir", "-p", mount_path])

        result = self.nfs_manual.run_command([
            "mount", "-t", "nfs4", "-o", "sec=sys", "-v",
            f"{self.nfs_server.hostname}:{exposed_path}", mount_path,
        ], raiseonerr=False)
        MOUNT_FAILURE = 32
        assert result.returncode == MOUNT_FAILURE

        self.nfs_manual.run_command([
            "mount", "-t", "nfs4", "-o", "sec=krb5p", "-v",
            f"{self.nfs_server.hostname}:{exposed_path}", mount_path,
        ])

    @pytest.mark.parametrize("nfs_domain", [None, "DNS", "exampledomain.net"])
    def test_automount_nfs_domain(self, nfs_domain):
        automount_args = [
            "ipa-client-automount", "--location", "default",
            "-U", "--debug",
        ]
        idmap_args = []
        if nfs_domain is not None:
            # https://pagure.io/freeipa/issue/7918
            idmap_args = ["--idmap-domain", nfs_domain]
        automount_args += idmap_args

        result = self.nfs_autofs.run_command(automount_args)

        time.sleep(WAIT_AFTER_INSTALL)
        # systemctl non-fatal errors will show up like this:
        # stderr=Failed to restart nfs-secure.service: \
        #        Unit nfs-secure.service not found.
        # normal output:
        # stderr=
        m = re.search(r"(?<=stderr\=Failed).+", result.stderr_text)
        assert m is None

        # check whether idmapd.conf was setup properly
        if nfs_domain is None:
            self.nfs_autofs.run_command([
                "grep", f"Domain = {self.master.domain.name}",
                paths.IDMAPD_CONF
            ])
        # in case of magic value ("DNS")
        # grep must not find any configured Domain.
        elif nfs_domain == "DNS":
            result = self.nfs_autofs.run_command(
                ["grep", "^Domain =", paths.IDMAPD_CONF], raiseonerr=False
            )
            assert result.returncode == 1
        else:
            self.nfs_autofs.run_command([
                "grep", f"Domain = {nfs_domain}", paths.IDMAPD_CONF
            ])

        result = self.nfs_autofs.run_command([
            "ipa-client-automount", "--uninstall", "-U", "--debug"
        ])
        m = re.search(r"(?<=stderr\=Failed).+", result.stderr_text)
        assert m is None

        time.sleep(WAIT_AFTER_UNINSTALL)

    @pytest.mark.parametrize(
        "nfs_share", ["krbnfs_home", "krbnfs_autofs"])
    def test_nfs_autofs(self, automount_client, nfs_share):
        """
        Test if NFS shares are mounted via Autofs as expected
        """
        export = NFS_EXPORTS[nfs_share]
        self.nfs_autofs.run_command(["kdestroy", "-A"])
        tasks.run_command_as_user(
            self.nfs_autofs, IPA_USER, ["kinit", IPA_USER],
            stdin_text=f"{IPA_PASSWORD}\n",
        )
        result = tasks.run_command_as_user(
            self.nfs_autofs, IPA_USER, ["klist"])
        expected_principal = ("Default principal: "
                              f"{IPA_USER}@{self.nfs_autofs.domain.realm}")
        assert expected_principal in result.stdout_text

        result = self.nfs_server.run_command(["id", "-u", IPA_USER])
        user_id = result.stdout_text.rstrip("\n")

        result = self.nfs_server.run_command(["id", "-g", IPA_USER])
        group_id = result.stdout_text.rstrip("\n")

        test_dir = f"{IPA_USER}_dir"
        dir_mod = "755"
        mount_path = export['mount_path']
        export_rpath = export['export_rpath']
        exposed_path = export['exposed_path']

        tasks.run_command_as_user(
            self.nfs_autofs, IPA_USER,
            ["mkdir", "-m", dir_mod, os.path.join(mount_path, test_dir)])

        # check mount options
        result = self.nfs_autofs.run_command(
            ["/bin/sh", "-c", f"mount | grep {mount_path}"])
        mount_pattern = (
            rf"{self.nfs_server.hostname}:{exposed_path} on {mount_path}"
            r" type nfs4 \(rw,(.*)?,vers=4\.2,(.*)?,sec=krb5p,.*\)"
        )
        m = re.search(mount_pattern, result.stdout_text)
        assert m is not None

        stats_pattern = ("owner=%U,owner_id=%u,owner_group=%G,"
                         "owner_group_id=%g,mod=%a")
        # check the owner on the client side
        result = tasks.run_command_as_user(
            self.nfs_autofs, IPA_USER,
            ["stat", "--printf", stats_pattern,
             os.path.join(mount_path, test_dir)],
        )

        expected_stats = (
            f"owner={IPA_USER},owner_id={user_id},owner_group={IPA_USER},"
            f"owner_group_id={group_id},mod={dir_mod}"
        )
        assert result.stdout_text == expected_stats

        # check the owner on the server side
        result = self.nfs_server.run_command([
            "stat", "--printf", stats_pattern,
            os.path.join("/exports", export_rpath, test_dir)
        ])
        actual_stats = result.stdout_text

        assert actual_stats == expected_stats

        # try access as a local root, should fail due to NFS root squash
        result = self.nfs_autofs.run_command(
            ["mkdir", os.path.join(mount_path, test_dir, "rootdir")],
            raiseonerr=False)
        assert result.returncode == 1
        assert "Permission denied" in result.stderr_text


class TestIpaClientAutomountFileRestore(IntegrationTest):

    num_clients = 1
    topology = 'line'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def teardown_method(self, method):
        tasks.uninstall_client(self.clients[0])

    @pytest.mark.parametrize('no_sssd', [False, True])
    def test_nsswitch_backup_restore(self, no_sssd):
        # In order to get a more pure sum, one that ignores the Generated
        # header and any white space we have to do a bit of work...
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
        if no_sssd:
            assert after_ipa_client_automount == ['files', 'ldap']
        else:
            assert after_ipa_client_automount == ['sss', 'files']

        cmd = self.clients[0].run_command(grep_automount_command)
        assert cmd.stdout_text.split() == after_ipa_client_automount

        self.clients[0].run_command([
            "ipa-client-automount", "--uninstall", "-U"
        ])

        cmd = self.clients[0].run_command(grep_automount_command)
        assert cmd.stdout_text.split() == after_ipa_client_install

        tasks.uninstall_client(self.clients[0])
        cmd = self.clients[0].run_command(sha256nsswitch_cmd)
        assert cmd.stdout_text == orig_sha256
