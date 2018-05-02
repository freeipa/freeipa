#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipaclient.install import client
from ipaplatform.paths import paths
from ipapython.install import cli
from ipapython.install.core import knob, extend_knob


class StandaloneClientInstall(client.ClientInstall):
    no_host_dns = False
    no_wait_for_dns = False

    principal = client.ClientInstall.principal
    principal = extend_knob(
        principal,
        cli_names=list(principal.cli_names) + ['-p'],
    )

    password = knob(
        str, None,
        sensitive=True,
        description="password to join the IPA realm (assumes bulk password "
                    "unless principal is also set)",
        cli_names=[None, '-w'],
    )

    @property
    def admin_password(self):
        if self.principal:
            return self.password

        return super(StandaloneClientInstall, self).admin_password

    @property
    def host_password(self):
        if not self.principal:
            return self.password

        return super(StandaloneClientInstall, self).host_password

    prompt_password = knob(
        None,
        description="Prompt for a password to join the IPA realm",
        cli_names='-W',
    )

    on_master = knob(
        None,
        deprecated=True,
    )


ClientInstall = cli.install_tool(
    StandaloneClientInstall,
    command_name='ipa-client-install',
    log_file_name=paths.IPACLIENT_INSTALL_LOG,
    debug_option=True,
    verbose=True,
    console_format='%(message)s',
    uninstall_log_file_name=paths.IPACLIENT_UNINSTALL_LOG,
    ignore_return_codes=(client.CLIENT_NOT_CONFIGURED,),
)


def run():
    ClientInstall.run_cli()
