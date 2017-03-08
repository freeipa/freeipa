#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipapython.install import cli
from ipapython.install.core import extend_knob
from ipaplatform.paths import paths
from ipaserver.install.server import ServerMasterInstall


class CompatServerMasterInstall(ServerMasterInstall):
    all_ip_addresses = False
    nisdomain = None
    no_nisdomain = False
    no_sudo = False
    request_cert = False

    dm_password = extend_knob(
        ServerMasterInstall.dm_password,    # pylint: disable=no-member
        cli_names=['--ds-password', '-p'],
    )

    admin_password = ServerMasterInstall.admin_password
    admin_password = extend_knob(
        admin_password,
        # pylint: disable=no-member
        cli_names=list(admin_password.cli_names) + ['-a'],
    )

    ip_addresses = extend_knob(
        ServerMasterInstall.ip_addresses,   # pylint: disable=no-member
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
