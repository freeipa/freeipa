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

from __future__ import print_function, absolute_import

import logging
import os

import six

from ipalib import api
from ipapython import admintool
from ipaplatform.paths import paths
from ipaserver.install import installutils, schemaupdate
from ipaserver.install.ldapupdate import LDAPUpdate, UPDATES_DIR, BadSyntax
from ipaserver.install.upgradeinstance import IPAUpgrade

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)


class LDAPUpdater(admintool.AdminTool):
    command_name = 'ipa-ldap-updater'

    usage = "%prog [options] input_file(s)\n"

    @classmethod
    def add_options(cls, parser):
        super(LDAPUpdater, cls).add_options(parser, debug_option=True)
        parser.add_option("-u", '--upgrade', action="store_true",
            dest="upgrade", default=False,
            help="upgrade an installed server in offline mode")
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

        if not (self.files or options.schema_files):
            logger.info("To execute overall IPA upgrade please use "
                        "'ipa-server-upgrade' command")
            raise admintool.ScriptError("No update files or schema file were "
                                        "specified")

        for filename in self.files:
            if not os.path.exists(filename):
                raise admintool.ScriptError("%s: file not found" % filename)

        try:
            installutils.check_server_configuration()
        except RuntimeError as e:
            raise admintool.ScriptError(e)

    def setup_logging(self):
        super(LDAPUpdater, self).setup_logging(log_file_mode='a')

    def run(self):
        super(LDAPUpdater, self).run()

        api.bootstrap(in_server=True, context='updates', confdir=paths.ETC_IPA)
        api.finalize()

    def handle_error(self, exception):
        return installutils.handle_error(exception, self.log_file_name)


class LDAPUpdater_Upgrade(LDAPUpdater):
    log_file_name = paths.IPAUPGRADE_LOG

    def run(self):
        super(LDAPUpdater_Upgrade, self).run()
        api.Backend.ldap2.connect()
        options = self.options

        realm = api.env.realm
        upgrade = IPAUpgrade(realm, self.files,
                             schema_files=options.schema_files)

        try:
            upgrade.create_instance()
        except BadSyntax:
            raise admintool.ScriptError(
                'Bad syntax detected in upgrade file(s).', 1)
        except RuntimeError:
            raise admintool.ScriptError('IPA upgrade failed.', 1)
        else:
            if upgrade.modified:
                logger.info('Update complete')
            else:
                logger.info('Update complete, no data were modified')

        api.Backend.ldap2.disconnect()


class LDAPUpdater_NonUpgrade(LDAPUpdater):
    log_file_name = paths.IPAUPGRADE_LOG

    def run(self):
        super(LDAPUpdater_NonUpgrade, self).run()
        api.Backend.ldap2.connect()
        options = self.options

        modified = False

        if options.schema_files:
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
            logger.info('Update complete')
        else:
            logger.info('Update complete, no data were modified')

        api.Backend.ldap2.disconnect()
