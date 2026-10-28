#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#


from __future__ import print_function, absolute_import

import logging

from ipalib import api
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool, ScriptError
from ipapython.dn import DN
from ipapython.ipautil import CalledProcessError
from ipaserver.install import installutils

logger = logging.getLogger(__name__)


class IPATrustEnableAgent(AdminTool):
    command_name = "ipa-trust-enable-agent"
    log_file_name = paths.IPATRUSTENABLEAGENT_LOG
    usage = "%prog"
    description = "Enable this server as a trust agent"

    @classmethod
    def add_options(cls, parser):
        super(IPATrustEnableAgent, cls).add_options(parser)

        parser.add_option(
            "--enable-compat",
            dest="enable_compat", default=False, action="store_true",
            help="Enable support for trusted domains for old clients")

    def validate_options(self):
        super(IPATrustEnableAgent, self).validate_options(needs_root=True)
        installutils.check_server_configuration()

    def _enable_compat_tree(self):
        logger.info("Enabling Schema Compatibility plugin")
        compat_plugin_dn = DN("cn=Schema Compatibility,cn=plugins,cn=config")
        lookup_nsswitch_name = "schema-compat-lookup-nsswitch"
        for config in (("cn=users", "user"), ("cn=groups", "group")):
            entry_dn = DN(config[0], compat_plugin_dn)
            current = api.Backend.ldap2.get_entry(entry_dn)
            lookup_nsswitch = current.get(lookup_nsswitch_name, [])
            if not(config[1] in lookup_nsswitch):
                logger.debug("Enabling Schema Compatibility plugin "
                             "for %s", config[0])
                current[lookup_nsswitch_name] = [config[1]]
                api.Backend.ldap2.update_entry(current)
            else:
                logger.debug("Schema Compatibility plugin already enabled "
                             "for %s", config[0])

    def run(self):
        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()

        try:
            api.Backend.ldap2.connect()  # ensure DS is up

            # If required, enable Schema compat plugin on users/groups
            if self.options.enable_compat:
                try:
                    self._enable_compat_tree()
                except Exception as e:
                    raise ScriptError(
                        "Enabling Schema Compatibility plugin "
                        "failed: {}".format(e))

            # Restart 389-ds and sssd
            logger.info("Restarting Directory Server")
            try:
                services.knownservices.dirsrv.restart()
            except Exception as e:
                raise ScriptError(
                    "Directory Server restart was unsuccessful: {}".format(e))

            logger.info("Restarting SSSD service")
            try:
                sssd = services.service('sssd', api)
                sssd.restart()
            except CalledProcessError as e:
                raise ScriptError(
                    "SSSD service restart was unsuccessful: {}".format(e))

        finally:
            if api.Backend.ldap2.isconnected():
                api.Backend.ldap2.disconnect()

        return 0
