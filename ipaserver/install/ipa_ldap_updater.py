# Authors: Rob Crittenden <rcritten@redhat.com>
#          Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Documentation can be found at http://freeipa.org/page/LdapUpdate

# TODO
# save undo files?

import os
import sys

import krbV

from ipalib import api
from ipapython import ipautil, admintool
from ipaplatform.paths import paths
from ipaserver.install import installutils, dsinstance, schemaupdate
from ipaserver.install.ldapupdate import LDAPUpdate, UPDATES_DIR
from ipaserver.install.upgradeinstance import IPAUpgrade


class LDAPUpdater(admintool.AdminTool):
    command_name = 'ipa-ldap-updater'

    usage = "%prog [options] input_file(s)\n"
    usage += "%prog [options]\n"

    @classmethod
    def add_options(cls, parser):
        super(LDAPUpdater, cls).add_options(parser, debug_option=True)
        parser.add_option("-u", '--upgrade', action="store_true",
            dest="upgrade", default=False,
            help="upgrade an installed server in offline mode")
        parser.add_option("-s", '--schema', action="store_true",
            dest="update_schema", default=False,
            help="update the schema "
                "(implied when no input files are given)")
        parser.add_option("-S", '--schema-file', action="append",
            dest="schema_files",
            help="custom schema ldif file to use (implies -s)")

    @classmethod
    def get_command_class(cls, options, args):
        if options.upgrade:
            return LDAPUpdater_Upgrade
        else:
            return LDAPUpdater_NonUpgrade

    def validate_options(self):
        options = self.options
        super(LDAPUpdater, self).validate_options(needs_root=True)

        self.files = self.args

        for filename in self.files:
            if not os.path.exists(filename):
                raise admintool.ScriptError("%s: file not found" % filename)

        try:
            installutils.check_server_configuration()
        except RuntimeError, e:
            print unicode(e)
            sys.exit(1)

        if options.schema_files or not self.files:
            options.update_schema = True
        if not options.schema_files:
            options.schema_files = [os.path.join(ipautil.SHARE_DIR, f) for f
                                    in dsinstance.ALL_SCHEMA_FILES]

    def setup_logging(self):
        super(LDAPUpdater, self).setup_logging(log_file_mode='a')

    def run(self):
        super(LDAPUpdater, self).run()

        api.bootstrap(in_server=True, context='updates')
        api.finalize()

    def handle_error(self, exception):
        return installutils.handle_error(exception, self.log_file_name)


class LDAPUpdater_Upgrade(LDAPUpdater):
    log_file_name = paths.IPAUPGRADE_LOG

    def run(self):
        super(LDAPUpdater_Upgrade, self).run()
        options = self.options

        realm = krbV.default_context().default_realm
        upgrade = IPAUpgrade(realm, self.files,
                             schema_files=options.schema_files)
        upgrade.create_instance()

        if upgrade.badsyntax:
            raise admintool.ScriptError(
                'Bad syntax detected in upgrade file(s).', 1)
        elif upgrade.upgradefailed:
            raise admintool.ScriptError('IPA upgrade failed.', 1)
        elif upgrade.modified:
            self.log.info('Update complete')
        else:
            self.log.info('Update complete, no data were modified')


class LDAPUpdater_NonUpgrade(LDAPUpdater):
    log_file_name = paths.IPAUPGRADE_LOG

    def run(self):
        super(LDAPUpdater_NonUpgrade, self).run()
        options = self.options

        modified = False

        if options.update_schema:
            modified = schemaupdate.update_schema(
                options.schema_files,
                ldapi=True) or modified

        ld = LDAPUpdate(
            sub_dict={},
            ldapi=True)

        if not self.files:
            self.files = ld.get_all_files(UPDATES_DIR)

        modified = ld.update(self.files) or modified

        if modified:
            self.log.info('Update complete')
        else:
            self.log.info('Update complete, no data were modified')
