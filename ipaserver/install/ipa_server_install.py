#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipapython.install import cli
from ipapython.install.core import knob
from ipaplatform.paths import paths
from ipaserver.install.server import ServerMasterInstall


class CompatServerMasterInstall(ServerMasterInstall):
    all_ip_addresses = False
    nisdomain = None
    no_nisdomain = False
    no_sudo = False
    request_cert = False

    dm_password = knob(
        # pylint: disable=no-member
        bases=ServerMasterInstall.dm_password,
        cli_names=['--ds-password', '-p'],
    )

    admin_password = knob(
        # pylint: disable=no-member
        bases=ServerMasterInstall.admin_password,
        cli_names=(list(ServerMasterInstall.admin_password.cli_names) +
                   ['-a']),
    )

    ip_addresses = knob(
        # pylint: disable=no-member
        bases=ServerMasterInstall.ip_addresses,
        description="Master Server IP Address. This option can be used "
                    "multiple times",
    )


ServerInstall = cli.install_tool(
    CompatServerMasterInstall,
    command_name='ipa-server-install',
    log_file_name=paths.IPASERVER_INSTALL_LOG,
    debug_option=True,
    uninstall_log_file_name=paths.IPASERVER_UNINSTALL_LOG,
)


def run():
    ServerInstall.run_cli()
