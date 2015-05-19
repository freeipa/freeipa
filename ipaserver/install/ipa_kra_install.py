#! /usr/bin/python2 -E
# Authors: Ade Lee <alee@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from ConfigParser import RawConfigParser
from textwrap import dedent
from ipalib import api
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython import admintool
from ipapython import dogtag
from ipapython import ipautil
from ipaserver.install import cainstance
from ipaserver.install import dogtaginstance
from ipaserver.install import krainstance
from ipaserver.install import dsinstance
from ipaserver.install import installutils
from ipaserver.install import service
from ipaserver.install.installutils import (
    read_replica_info_kra_enabled, create_replica_config)


class KRAInstall(admintool.AdminTool):

    command_name = 'ipa-kra-install'

    usage = "%prog [options] [replica_file]"

    description = "Install a master or replica KRA."

    @classmethod
    def add_options(cls, parser, debug_option=True):
        super(KRAInstall, cls).add_options(parser, debug_option=True)

        parser.add_option(
            "--no-host-dns", dest="no_host_dns", action="store_true",
            default=False,
            help="Do not use DNS for hostname lookup during installation")

        parser.add_option(
            "-p", "--password",
            dest="password", sensitive=True,
            help="Directory Manager (existing master) password")

        parser.add_option(
            "-U", "--unattended",
            dest="unattended", action="store_true", default=False,
            help="unattended installation never prompts the user")

        parser.add_option(
            "--uninstall",
            dest="uninstall", action="store_true", default=False,
            help="uninstall an existing installation. The uninstall can "
                 "be run with --unattended option")

    def validate_options(self, needs_root=True):
        super(KRAInstall, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        api.bootstrap(in_server=True)
        api.finalize()

    @classmethod
    def get_command_class(cls, options, args):
        if options.uninstall:
            return KRAUninstaller
        else:
            return KRAInstaller


class KRAUninstaller(KRAInstall):
    log_file_name = paths.PKI_KRA_UNINSTALL_LOG

    def validate_options(self, needs_root=True):
        super(KRAUninstaller, self).validate_options(needs_root=True)

        if self.args:
            self.option_parser.error("Too many parameters provided.")

        if not api.env.enable_kra:
            self.option_parser.error(
                "Cannot uninstall.  There is no KRA installed on this system."
            )

    def run(self):
        super(KRAUninstaller, self).run()
        dogtag_constants = dogtag.configured_constants()

        kra_instance = krainstance.KRAInstance(
            api.env.realm, dogtag_constants=dogtag_constants)
        kra_instance.stop_tracking_certificates()
        if kra_instance.is_installed():
            kra_instance.uninstall()

        # Update config file
        parser = RawConfigParser()
        parser.read(paths.IPA_DEFAULT_CONF)
        parser.set('global', 'enable_kra', 'False')

        with open(paths.IPA_DEFAULT_CONF, 'w') as f:
            parser.write(f)


class KRAInstaller(KRAInstall):
    log_file_name = paths.PKI_KRA_INSTALL_LOG

    INSTALLER_START_MESSAGE = '''
        ===================================================================
        This program will setup Dogtag KRA for the FreeIPA Server.

    '''

    FAIL_MESSAGE = '''
        Your system may be partly configured.
        Run ipa-kra-install --uninstall to clean up.
    '''

    def validate_options(self, needs_root=True):
        super(KRAInstaller, self).validate_options(needs_root=True)

        if self.options.unattended and self.options.password is None:
            self.option_parser.error(
                "Directory Manager password must be specified using -p"
                " in unattended mode"
            )

        dogtag_version = int(api.env.dogtag_version)
        enable_kra = api.env.enable_kra

        if enable_kra:
            self.option_parser.error("KRA is already installed.")

        ca_installed = cainstance.is_ca_installed_locally()

        if ca_installed:
            if dogtag_version >= 10:
                # correct dogtag version of CA installed
                pass
            else:
                self.option_parser.error(
                    "Dogtag must be version 10.2 or above to install KRA")
        else:
            self.option_parser.error(
                "Dogtag CA is not installed.  Please install the CA first")

        self.installing_replica = dogtaginstance.is_installing_replica("KRA")
        if self.installing_replica:
            if not self.args:
                self.option_parser.error("A replica file is required.")
            if len(self.args) > 1:
                self.option_parser.error("Too many arguments provided")

            self.replica_file = self.args[0]
            if not ipautil.file_exists(self.replica_file):
                self.option_parser.error(
                    "Replica file %s does not exist" % self.replica_file)
        else:
            if self.args:
                self.option_parser.error("Too many parameters provided.  "
                                         "No replica file is required.")

    def ask_for_options(self):
        super(KRAInstaller, self).ask_for_options()

        if not self.options.unattended and self.options.password is None:
            self.options.password = installutils.read_password(
                "Directory Manager", confirm=False,
                validate=False, retry=False)
            if self.options.password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

    def _run(self):
        super(KRAInstaller, self).run()
        print dedent(self.INSTALLER_START_MESSAGE)

        subject = dsinstance.DsInstance().find_subject_base()
        if not self.installing_replica:
            kra = krainstance.KRAInstance(
                api.env.realm,
                dogtag_constants=dogtag.install_constants)

            kra.configure_instance(
                api.env.host, api.env.domain, self.options.password,
                self.options.password, subject_base=subject)
        else:
            replica_config = create_replica_config(
                self.options.password,
                self.replica_file,
                self.options)

            if not read_replica_info_kra_enabled(replica_config.dir):
                raise admintool.ScriptError(
                    "Either KRA is not installed on the master system or "
                    "your replica file is out of date"
                )

            kra = krainstance.install_replica_kra(replica_config)
            service.print_msg("Restarting the directory server")

            ds = dsinstance.DsInstance()
            ds.restart()

        kra.enable_client_auth_to_db(kra.dogtag_constants.KRA_CS_CFG_PATH)

        # Restart apache for new proxy config file
        services.knownservices.httpd.restart(capture_output=True)

        # Update config file
        parser = RawConfigParser()
        parser.read(paths.IPA_DEFAULT_CONF)
        parser.set('global', 'enable_kra', 'True')

        with open(paths.IPA_DEFAULT_CONF, 'w') as f:
            parser.write(f)

    def run(self):
        try:
            self._run()
        except:
            self.log.error(dedent(self.FAIL_MESSAGE))
            raise

