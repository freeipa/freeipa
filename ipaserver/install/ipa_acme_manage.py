#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import enum
import pathlib

from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipapython.directivesetter import DirectiveSetter
from ipaserver.install import cainstance
from ipaserver.install.installutils import is_ipa_configured

# Manages the FreeIPA ACME service on a per-server basis.
#
# This program is a stop-gap until the deployment-wide management of
# the ACME service is implemented.  So we will eventually have API
# calls for managing the ACME service, e.g. `ipa acme-enable'.
# After that is implemented, we can either deprecate and eventually
# remove this program, or make it a wrapper for the API commands.


class Command(enum.Enum):
    ENABLE = 'enable'
    DISABLE = 'disable'


class IPAACMEManage(AdminTool):
    command_name = "ipa-acme-manage"
    usage = "%prog [enable|disable]"
    description = "Manage the IPA ACME service"

    def validate_options(self):
        # needs root now - if/when this program changes to an API
        # wrapper we will no longer need root.
        super(IPAACMEManage, self).validate_options(needs_root=True)

        if len(self.args) < 1:
            self.option_parser.error(f'missing command argument')
        else:
            try:
                self.command = Command(self.args[0])
            except ValueError:
                self.option_parser.error(f'unknown command "{self.args[0]}"')

    def run(self):
        if not is_ipa_configured():
            print("IPA is not configured.")
            return 2

        if not cainstance.is_ca_installed_locally():
            print("CA is not installed on this server.")
            return 1

        if self.command == Command.ENABLE:
            directive = 'enabled'
            value = 'true'
        elif self.command == Command.DISABLE:
            directive = 'enabled'
            value = 'false'
        else:
            raise RuntimeError('programmer error: unhandled enum case')

        with DirectiveSetter(
            paths.PKI_ACME_ENGINE_CONF,
            separator='=',
            quotes=False,
        ) as ds:
            ds.set(directive, value)

        # Work around a limitation in PKI ACME service file watching
        # where renames (what DirectiveSetter does) are not detected.
        # It will be fixed, but keeping the workaround will do no harm.
        pathlib.Path(paths.PKI_ACME_ENGINE_CONF).touch()

        # Nothing else to do; the Dogtag ACME service monitors engine.conf
        # for updates and reconfigures itself as required.

        return 0
