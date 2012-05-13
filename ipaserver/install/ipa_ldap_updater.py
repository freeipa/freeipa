#!/usr/bin/python
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
from ipaserver.install import installutils
from ipaserver.install.ldapupdate import LDAPUpdate, UPDATES_DIR
from ipaserver.install.upgradeinstance import IPAUpgrade
from ipapython import ipa_log_manager


class LDAPUpdater(admintool.AdminTool):
    command_name = 'ipa-ldap-updater'

    usage = "%prog [options] input_file(s)\n"
    usage += "%prog [options]\n"

    @classmethod
    def add_options(cls, parser):
        super(LDAPUpdater, cls).add_options(parser)

        parser.add_option("-t", "--test", action="store_true", dest="test",
            default=False,
            help="Run through the update without changing anything")
        parser.add_option("-y", dest="password",
            help="File containing the Directory Manager password")
        parser.add_option("-l", '--ldapi', action="store_true", dest="ldapi",
            default=False,
            help="Connect to the LDAP server using the ldapi socket")
        parser.add_option("-u", '--upgrade', action="store_true",
            dest="upgrade", default=False,
            help="Upgrade an installed server in offline mode")
        parser.add_option("-p", '--plugins', action="store_true",
            dest="plugins", default=False,
            help="Execute update plugins. " +
                "Always true when applying all update files.")
        parser.add_option("-W", '--password', action="store_true",
            dest="ask_password",
            help="Prompt for the Directory Manager password")

    @classmethod
    def get_command_class(cls, options, args):
        if options.upgrade:
            return LDAPUpdater_Upgrade
        else:
            return LDAPUpdater_NonUpgrade

    def validate_options(self):
        options = self.options
        super(LDAPUpdater, self).validate_options()

        self.files = self.args

        for filename in self.files:
            if not os.path.exists(filename):
                raise admintool.ScriptError("%s: file not found" % filename)

        if os.getegid() == 0:
            try:
                installutils.check_server_configuration()
            except RuntimeError, e:
                print unicode(e)
                sys.exit(1)
        elif not os.path.exists('/etc/ipa/default.conf'):
            print "IPA is not configured on this system."
            sys.exit(1)

        if options.password:
            pw = ipautil.template_file(options.password, [])
            self.dirman_password = pw.strip()
        else:
            self.dirman_password = None

    def setup_logging(self):
        ipa_log_manager.standard_logging_setup(self.log_file_name,
            console_format='%(levelname)s: %(message)s',
            debug=self.options.debug, filemode='a')
        ipa_log_manager.log_mgr.get_logger(self, True)

    def run(self):
        super(LDAPUpdater, self).run()

        api.bootstrap(
                in_server=True,
                context='updates',
                debug=self.options.debug,
            )
        api.finalize()

    def handle_error(self, exception):
        return installutils.handle_error(exception, self.log_file_name)


class LDAPUpdater_Upgrade(LDAPUpdater):
    needs_root = True
    log_file_name = '/var/log/ipaupgrade.log'

    def validate_options(self):
        if os.getegid() != 0:
            raise admintool.ScriptError('Must be root to do an upgrade.', 1)

        super(LDAPUpdater_Upgrade, self).validate_options()

    def run(self):
        super(LDAPUpdater_Upgrade, self).run()
        options = self.options

        updates = None
        realm = krbV.default_context().default_realm
        upgrade = IPAUpgrade(realm, self.files, live_run=not options.test)
        upgrade.create_instance()
        upgradefailed = upgrade.upgradefailed

        if upgrade.badsyntax:
            raise admintool.ScriptError(
                'Bad syntax detected in upgrade file(s).', 1)
        elif upgrade.upgradefailed:
            raise admintool.ScriptError('IPA upgrade failed.', 1)
        elif upgrade.modified and options.test:
            self.info('Update complete, changes to be made, test mode')
            return 2


class LDAPUpdater_NonUpgrade(LDAPUpdater):
    log_file_name = '/var/log/ipaupgrade.log'

    def validate_options(self):
        super(LDAPUpdater_NonUpgrade, self).validate_options()
        options = self.options

        # Only run plugins if no files are given
        self.run_plugins = not self.files or options.plugins

        # Need root for running plugins
        if self.run_plugins and os.getegid() != 0:
            raise admintool.ScriptError('Plugins can only be run as root.', 1)

    def ask_for_options(self):
        super(LDAPUpdater_NonUpgrade, self).ask_for_options()
        options = self.options
        if not self.dirman_password:
            if options.ask_password or not options.ldapi:
                password = installutils.read_password("Directory Manager",
                    confirm=False, validate=False)
                if password is None:
                    raise admintool.ScriptError(
                        "Directory Manager password required")
                self.dirman_password = password

    def run(self):
        super(LDAPUpdater_NonUpgrade, self).run()
        options = self.options

        ld = LDAPUpdate(
            dm_password=self.dirman_password,
            sub_dict={},
            live_run=not options.test,
            ldapi=options.ldapi,
            plugins=options.plugins or self.run_plugins)

        if not self.files:
            self.files = ld.get_all_files(UPDATES_DIR)

        modified = ld.update(self.files)

        if modified and options.test:
            self.info('Update complete, changes to be made, test mode')
            return 2
