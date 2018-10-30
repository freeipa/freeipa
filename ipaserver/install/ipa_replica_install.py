#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipapython.install import cli
from ipapython.install.core import knob, extend_knob
from ipaplatform.paths import paths
from ipaserver.install.server import ServerReplicaInstall


class CompatServerReplicaInstall(ServerReplicaInstall):
    ca_cert_files = None
    all_ip_addresses = False
    no_wait_for_dns = True
    nisdomain = None
    no_nisdomain = False
    no_sudo = False
    request_cert = False
    ca_file = None
    zonemgr = None
    replica_install = True  # Used in ServerInstallInterface.__init__

    auto_password = knob(
        str, None,
        description="Password to join the IPA realm. Assumes bulk password "
                    "unless principal is also set. (domain level 1+) "
                    "Directory Manager (existing master) password. (domain "
                    "level 0)",
        sensitive=True,
        cli_names=['--password', '-p'],
        cli_metavar='PASSWORD',
    )

    @property
    def dm_password(self):
        try:
            return self.__dm_password
        except AttributeError:
            pass

        return super(CompatServerReplicaInstall, self).dm_password

    @dm_password.setter
    def dm_password(self, value):
        self.__dm_password = value

    ip_addresses = extend_knob(
        ServerReplicaInstall.ip_addresses,  # pylint: disable=no-member
        description="Replica server IP Address. This option can be used "
                    "multiple times",
    )

    admin_password = (
        ServerReplicaInstall.admin_password     # pylint: disable=no-member
    )
    admin_password = extend_knob(
        admin_password,
        cli_names=list(admin_password.cli_names) + ['-w'],
    )

    @admin_password.default_getter
    def admin_password(self):
        if self.principal:
            return self.auto_password

        return super(CompatServerReplicaInstall, self).admin_password

    @property
    def host_password(self):
        admin_password = (
            super(CompatServerReplicaInstall, self).admin_password)
        if not self.principal or admin_password:
            return self.auto_password

        return super(CompatServerReplicaInstall, self).host_password


ReplicaInstall = cli.install_tool(
    CompatServerReplicaInstall,
    command_name='ipa-replica-install',
    log_file_name=paths.IPAREPLICA_INSTALL_LOG,
    console_format='%(message)s',
    debug_option=True,
    verbose=True,
)


def run():
    ReplicaInstall.run_cli()
