#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import logging

from ipalib import api
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipaserver.install import installutils
from ipaserver.install.krbinstance import KrbInstance, is_pkinit_enabled

logger = logging.getLogger(__name__)


class PKINITManage(AdminTool):
    command_name = "ipa-pkinit-manage"
    usage = "%prog <enable|disable|status>"
    description = "Manage PKINIT."

    def validate_options(self):
        super(PKINITManage, self).validate_options(needs_root=True)
        installutils.check_server_configuration()

        option_parser = self.option_parser

        if not self.args:
            option_parser.error("action not specified")
        elif len(self.args) > 1:
            option_parser.error("too many arguments")

        action = self.args[0]
        if action not in {'enable', 'disable', 'status'}:
            option_parser.error("unrecognized action '{}'".format(action))

    def run(self):
        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()

        api.Backend.ldap2.connect()
        try:
            action = self.args[0]
            if action == 'enable':
                self.enable()
            elif action == 'disable':
                self.disable()
            elif action == 'status':
                self.status()
        finally:
            api.Backend.ldap2.disconnect()

        return 0

    def _setup(self, setup_pkinit):
        config = api.Command.config_show()['result']
        ca_enabled = api.Command.ca_is_enabled()['result']

        krb = KrbInstance()
        krb.init_info(
            realm_name=api.env.realm,
            host_name=api.env.host,
            setup_pkinit=setup_pkinit,
            subject_base=config['ipacertificatesubjectbase'][0],
        )

        if bool(is_pkinit_enabled()) is not bool(setup_pkinit):
            try:
                krb.stop_tracking_certs()
            except RuntimeError as e:
                if ca_enabled:
                    logger.warning(
                        "Failed to stop tracking certificates: %s", e)

            krb.enable_ssl()

        if setup_pkinit:
            krb.pkinit_enable()
        else:
            krb.pkinit_disable()

    def enable(self):
        if not api.Command.ca_is_enabled()['result']:
            logger.error("Cannot enable PKINIT in CA-less deployment")
            logger.error("Use ipa-server-certinstall to install KDC "
                         "certificate manually")
            raise RuntimeError("Cannot enable PKINIT in CA-less deployment")

        self._setup(True)

    def disable(self):
        self._setup(False)

    def status(self):
        if is_pkinit_enabled():
            print("PKINIT is enabled")
        else:
            print("PKINIT is disabled")
