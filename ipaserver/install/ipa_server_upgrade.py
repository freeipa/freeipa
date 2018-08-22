#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging

from ipalib import api
from ipaplatform.paths import paths
from ipapython import admintool
from ipaserver.install import installutils
from ipaserver.install import server

logger = logging.getLogger(__name__)


class ServerUpgrade(admintool.AdminTool):
    log_file_name = paths.IPAUPGRADE_LOG
    command_name = 'ipa-server-upgrade'

    usage = "%prog [options]"

    @classmethod
    def add_options(cls, parser):
        super(ServerUpgrade, cls).add_options(parser)
        parser.add_option("--force", action="store_true",
                          dest="force", default=False,
                          help="force upgrade (alias for --skip-version-check)")
        parser.add_option("--skip-version-check", action="store_true",
                          dest="skip_version_check", default=False,
                          help="skip version check. WARNING: this may break "
                               "your system")

    def validate_options(self):
        super(ServerUpgrade, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        if self.options.force:
            self.options.skip_version_check = True

    def setup_logging(self):
        super(ServerUpgrade, self).setup_logging(log_file_mode='a')

    def run(self):
        super(ServerUpgrade, self).run()

        api.bootstrap(in_server=True, context='updates', confdir=paths.ETC_IPA)
        api.finalize()

        try:
            server.upgrade_check(self.options)
            server.upgrade()
        except RuntimeError as e:
            raise admintool.ScriptError(str(e))

    def handle_error(self, exception):
        if not isinstance(exception, SystemExit):
            # do not log this message when ipa is not installed
            logger.error("IPA server upgrade failed: Inspect "
                         "/var/log/ipaupgrade.log and run command "
                         "ipa-server-upgrade manually.")
        return installutils.handle_error(exception, self.log_file_name)
