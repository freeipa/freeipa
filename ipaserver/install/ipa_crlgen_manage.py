#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import os
import logging
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from ipalib import api
from ipalib.errors import NetworkError
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipaserver.install import cainstance
from ipaserver.install import installutils

logger = logging.getLogger(__name__)


class CRLGenManage(AdminTool):
    command_name = "ipa-crlgen-manage"
    usage = "%prog <enable|disable|status>"
    description = "Manage CRL Generation Master."

    def validate_options(self):
        super(CRLGenManage, self).validate_options(needs_root=True)
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

        try:
            api.Backend.ldap2.connect()
        except NetworkError as e:
            logger.debug("Unable to connect to the local instance: %s", e)
            raise RuntimeError("IPA must be running, please run ipactl start")
        ca = cainstance.CAInstance(api.env.realm)

        try:
            action = self.args[0]
            if action == 'enable':
                self.enable(ca)
            elif action == 'disable':
                self.disable(ca)
            elif action == 'status':
                self.status(ca)
        finally:
            api.Backend.ldap2.disconnect()

        return 0

    def check_local_ca_instance(self, raiseOnErr=False):
        if not api.Command.ca_is_enabled()['result'] or \
           not cainstance.is_ca_installed_locally():
            if raiseOnErr:
                raise RuntimeError("Dogtag CA is not installed. "
                                   "Please install a CA first with the "
                                   "`ipa-ca-install` command.")
            else:
                logger.warning(
                    "Warning: Dogtag CA is not installed on this server.")
                return False
        return True

    def enable(self, ca):
        # When the local node is not a CA, raise an Exception
        self.check_local_ca_instance(raiseOnErr=True)
        ca.setup_crlgen(True)
        logger.info("CRL generation enabled on the local host. "
                    "Please make sure to have only a single CRL generation "
                    "master.")

    def disable(self, ca):
        # When the local node is not a CA, nothing to do
        if not self.check_local_ca_instance():
            return
        ca.setup_crlgen(False)
        logger.info("CRL generation disabled on the local host. "
                    "Please make sure to configure CRL generation on another "
                    "master with %s enable", self.command_name)

    def status(self, ca):
        # When the local node is not a CA, return "disabled"
        if not self.check_local_ca_instance():
            print("CRL generation: disabled")
            return

        # Local node is a CA, check its configuration
        if ca.is_crlgen_enabled():
            print("CRL generation: enabled")
            try:
                crl_filename = os.path.join(paths.PKI_CA_PUBLISH_DIR,
                                            'MasterCRL.bin')
                with open(crl_filename, 'rb') as f:
                    crl = x509.load_der_x509_crl(f.read(), default_backend())
                    print("Last CRL update: {}".format(crl.last_update))
                    for ext in crl.extensions:
                        if ext.oid == x509.oid.ExtensionOID.CRL_NUMBER:
                            print("Last CRL Number: {}".format(
                                ext.value.crl_number))
            except IOError:
                logger.error("Unable to find last CRL")
        else:
            print("CRL generation: disabled")
