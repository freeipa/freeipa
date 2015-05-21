#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import os
import sys

import krbV

from ipalib import api
from ipaplatform.paths import paths
from ipapython import admintool, ipautil
from ipaserver.install import dsinstance
from ipaserver.install import installutils
from ipaserver.install.upgradeinstance import IPAUpgrade
from ipaserver.install.ldapupdate import BadSyntax


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

        if self.options.force:
            self.options.skip_version_check = True

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

        if not options.skip_version_check:
            # check IPA version and data version
            try:
                installutils.check_version()
            except (installutils.UpgradePlatformError,
                    installutils.UpgradeDataNewerVersionError) as e:
                raise admintool.ScriptError(
                    'Unable to execute IPA upgrade: %s' % e, 1)
            except installutils.UpgradeMissingVersionError as e:
                self.log.info("Missing version: %s", e)
            except installutils.UpgradeVersionError:
                # Ignore other errors
                pass
        else:
            self.log.info("Skipping version check")
            self.log.warning("Upgrade without version check may break your "
                             "system")

        realm = krbV.default_context().default_realm
        schema_files = [os.path.join(ipautil.SHARE_DIR, f) for f
                        in dsinstance.ALL_SCHEMA_FILES]
        data_upgrade = IPAUpgrade(realm, schema_files=schema_files)

        try:
            data_upgrade.create_instance()
        except BadSyntax:
            raise admintool.ScriptError(
                'Bad syntax detected in upgrade file(s).', 1)
        except RuntimeError:
            raise admintool.ScriptError('IPA upgrade failed.', 1)
        else:
            if data_upgrade.modified:
                self.log.info('Update complete')
            else:
                self.log.info('Update complete, no data were modified')

        # store new data version after upgrade
        installutils.store_version()

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
