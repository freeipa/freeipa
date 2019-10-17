#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

from ipalib import api
from ipalib.install import sysrestore
from ipapython.install import cli
from ipapython.install.common import step, Installable, Interactive
from ipapython.install.core import group, knob, Composite
from ipapython.install import typing
from ipaplatform.paths import paths
from ipaserver.install import gc

IPAGC_INSTALL_LOG = "/var/log/ipa/gc-install.log"
IPAGC_UNINSTALL_LOG = "/var/log/ipa/gc-uninstall.log"


@group
class GCInstallInterface(Installable,
                         Interactive,
                         Composite):
    """
    Interface for the Global Catalog installer
    """
    description = "Global Catalog"

    gc_password = knob(
        str, None,
        sensitive=True,
        description="Directory Manager password for the Global Catalog",
    )

    gc_cert_files = knob(
        # pylint: disable=invalid-sequence-index
        typing.List[str], None,
        description=("File containing the Global Catalog SSL certificate and "
                     "private key"),
        cli_names='--gc-cert-file',
        cli_metavar='FILE',
    )

    gc_pin = knob(
        str, None,
        sensitive=True,
        description="The password to unlock the Global Catalog private key",
        cli_deprecated_names='--gc_pin',
        cli_metavar='PIN',
    )


class GCServerInstall(GCInstallInterface):
    @step()
    def main(self):
        # Initialize the ipalib api
        api.bootstrap(in_server=True,
                      context='installer',
                      confdir=paths.ETC_IPA)
        api.finalize()
        fstore = sysrestore.FileStore(paths.SYSRESTORE)

        gc.install_check(api, self)
        yield
        gc.install(api, fstore, self)

    @main.uninstaller
    def main(self):
        # Initialize the ipalib api
        api.bootstrap(in_server=True,
                      context='installer',
                      confdir=paths.ETC_IPA)
        api.finalize()
        fstore = sysrestore.FileStore(paths.SYSRESTORE)

        gc.uninstall_check()
        yield
        gc.uninstall(fstore)


ServerInstall = cli.install_tool(
    GCServerInstall,
    command_name="ipa-gc-install",
    log_file_name=IPAGC_INSTALL_LOG,
    uninstall_log_file_name=IPAGC_UNINSTALL_LOG,
    console_format='%(message)s',
    verbose=True,
    use_private_ccache=False
)


def run():
    ServerInstall.run_cli()
