#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import sys

import krbV

from ipalib import api
from ipaplatform.paths import paths
from ipapython import admintool, ipautil
from ipaserver.install import installutils
from ipaserver.install.upgradeinstance import IPAUpgrade


class ServerUpgrade(admintool.AdminTool):
    log_file_name = paths.IPAUPGRADE_LOG
    command_name = 'ipa-server-upgrade'

    usage = "%prog [options]"

    @classmethod
    def add_options(cls, parser):
        super(ServerUpgrade, cls).add_options(parser, debug_option=True)

    def validate_options(self):
        super(ServerUpgrade, self).validate_options(needs_root=True)

        try:
            installutils.check_server_configuration()
        except RuntimeError as e:
            print unicode(e)
            sys.exit(1)

    def setup_logging(self):
        super(ServerUpgrade, self).setup_logging(log_file_mode='a')

    def run(self):
        super(ServerUpgrade, self).run()

        api.bootstrap(in_server=True, context='updates')
        api.finalize()

        options = self.options

        realm = krbV.default_context().default_realm
        data_upgrade = IPAUpgrade(realm)
        data_upgrade.create_instance()

        if data_upgrade.badsyntax:
            raise admintool.ScriptError(
                'Bad syntax detected in upgrade file(s).', 1)
        elif data_upgrade.upgradefailed:
            raise admintool.ScriptError('IPA upgrade failed.', 1)
        elif data_upgrade.modified:
            self.log.info('Data update complete')
        else:
            self.log.info('Data update complete, no data were modified')

        # FIXME: remove this when new installer will be ready
        # execute upgrade of configuration
        cmd = ['ipa-upgradeconfig', ]
        if options.verbose:
            cmd.append('--debug')
        if options.quiet:
            cmd.append('--quiet')

        self.log.info('Executing ipa-upgradeconfig, please wait')
        ipautil.run(cmd)

    def handle_error(self, exception):
        return installutils.handle_error(exception, self.log_file_name)
