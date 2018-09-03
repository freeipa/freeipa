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

from __future__ import print_function, absolute_import

import logging
import sys
import tempfile
from optparse import SUPPRESS_HELP  # pylint: disable=deprecated-module

from textwrap import dedent
from ipalib import api
from ipalib.constants import DOMAIN_LEVEL_1
from ipaplatform.paths import paths
from ipapython import admintool
from ipaserver.install import service
from ipaserver.install import cainstance
from ipaserver.install import custodiainstance
from ipaserver.install import krainstance
from ipaserver.install import dsinstance
from ipaserver.install import installutils
from ipaserver.install import dogtaginstance
from ipaserver.install import kra
from ipaserver.install.installutils import ReplicaConfig
from ipaserver.masters import find_providing_server

logger = logging.getLogger(__name__)


class KRAInstall(admintool.AdminTool):

    command_name = 'ipa-kra-install'

    usage = "%prog [options]"

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
            help=SUPPRESS_HELP)

        parser.add_option(
            "--pki-config-override", dest="pki_config_override",
            default=None,
            help="Path to ini file with config overrides.")

    def validate_options(self, needs_root=True):
        super(KRAInstall, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()

    @classmethod
    def get_command_class(cls, options, args):
        if options.uninstall:
            sys.exit(
                'ERROR: Standalone KRA uninstallation was removed in '
                'FreeIPA 4.5 as it had never worked properly and only caused '
                'issues.')
        else:
            return KRAInstaller


class KRAInstaller(KRAInstall):
    log_file_name = paths.IPASERVER_KRA_INSTALL_LOG

    INSTALLER_START_MESSAGE = '''
        ===================================================================
        This program will setup Dogtag KRA for the FreeIPA Server.

    '''

    FAIL_MESSAGE = '''
        Your system may be partly configured.
        If you run into issues, you may have to re-install IPA on this server.
    '''

    def validate_options(self, needs_root=True):
        super(KRAInstaller, self).validate_options(needs_root=True)

        if self.options.unattended and self.options.password is None:
            self.option_parser.error(
                "Directory Manager password must be specified using -p"
                " in unattended mode"
            )

        if len(self.args) > 0:
            self.option_parser.error("Too many arguments provided")

    def ask_for_options(self):
        super(KRAInstaller, self).ask_for_options()

        if not self.options.unattended and self.options.password is None:
            self.options.password = installutils.read_password(
                "Directory Manager", confirm=False,
                validate=False, retry=False)
            if self.options.password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

    def run(self):
        super(KRAInstaller, self).run()

        # Verify DM password. This has to be called after ask_for_options(),
        # so it can't be placed in validate_options().
        try:
            installutils.validate_dm_password_ldap(self.options.password)
        except ValueError:
            raise admintool.ScriptError(
                "Directory Manager password is invalid")

        if not cainstance.is_ca_installed_locally():
            raise RuntimeError("Dogtag CA is not installed. "
                               "Please install a CA first with the "
                               "`ipa-ca-install` command.")

        # check if KRA is not already installed
        _kra = krainstance.KRAInstance(api)
        if _kra.is_installed():
            raise admintool.ScriptError("KRA already installed")

        # this check can be done only when CA is installed
        self.installing_replica = dogtaginstance.is_installing_replica("KRA")

        if self.installing_replica:
            domain_level = dsinstance.get_domain_level(api)
            if domain_level < DOMAIN_LEVEL_1:
                raise RuntimeError(
                    "Unsupported domain level %d." % domain_level)

        if self.args:
            raise RuntimeError("Too many parameters provided.")

        self.options.dm_password = self.options.password
        self.options.setup_ca = False
        self.options.setup_kra = True

        api.Backend.ldap2.connect()

        if self.installing_replica:
            config = ReplicaConfig()
            config.kra_host_name = None
            config.realm_name = api.env.realm
            config.host_name = api.env.host
            config.domain_name = api.env.domain
            config.dirman_password = self.options.password
            config.ca_ds_port = 389
            config.top_dir = tempfile.mkdtemp("ipa")
            config.dir = config.top_dir

            config.setup_kra = True

            if config.subject_base is None:
                attrs = api.Backend.ldap2.get_ipa_config()
                config.subject_base = attrs.get('ipacertificatesubjectbase')[0]

            if config.kra_host_name is None:
                config.kra_host_name = find_providing_server(
                    'KRA', api.Backend.ldap2, [api.env.ca_host]
                )
                if config.kra_host_name is None:
                    # all CA/KRA servers are down or unreachable.
                    raise admintool.ScriptError(
                        "Failed to find an active KRA server!"
                    )
            custodia = custodiainstance.get_custodia_instance(
                config, custodiainstance.CustodiaModes.KRA_PEER)
        else:
            config = None
            custodia = None

        try:
            kra.install_check(api, config, self.options)
        except RuntimeError as e:
            raise admintool.ScriptError(str(e))

        print(dedent(self.INSTALLER_START_MESSAGE))

        try:
            kra.install(api, config, self.options, custodia=custodia)
        except:
            logger.error('%s', dedent(self.FAIL_MESSAGE))
            raise

        # pki-spawn restarts 389-DS, reconnect
        api.Backend.ldap2.close()
        api.Backend.ldap2.connect()

        # Enable configured services and update DNS SRV records
        service.sync_services_state(api.env.host)
        api.Command.dns_update_system_records()
        api.Backend.ldap2.disconnect()
