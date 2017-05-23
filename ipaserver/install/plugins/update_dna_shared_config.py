#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import logging
import time
import ldap

from ipalib.plugable import Registry
from ipalib import errors
from ipalib import Updater
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_dna_shared_config(Updater):
    def execute(self, **options):
        method = options.get('method', "SASL/GSSAPI")
        protocol = options.get('protocol', "LDAP")

        dna_bind_method = "dnaRemoteBindMethod"
        dna_conn_protocol = "dnaRemoteConnProtocol"
        dna_plugin = DN(('cn', 'Distributed Numeric Assignment Plugin'),
                        ('cn', 'plugins'),
                        ('cn', 'config'))
        dna_config_base = DN(('cn', 'posix IDs'), dna_plugin)

        conn = self.api.Backend.ldap2

        # Check the plugin is enabled else it is useless to update
        # the shared entry
        try:
            entry = conn.get_entry(dna_plugin)
            if entry.single_value.get('nsslapd-pluginenabled') == 'off':
                return False, ()
        except errors.NotFound:
            logger.error("Could not find DNA plugin entry: %s",
                         dna_config_base)
            return False, ()

        try:
            entry = conn.get_entry(dna_config_base)
        except errors.NotFound:
            logger.error("Could not find DNA config entry: %s",
                         dna_config_base)
            return False, ()

        sharedcfgdn = entry.single_value.get("dnaSharedCfgDN")
        if sharedcfgdn is not None:
            sharedcfgdn = DN(sharedcfgdn)
        else:
            logger.error(
                "Could not find DNA shared config DN in entry: %s",
                dna_config_base)
            return False, ()

        #
        # Update the shared config entry related to that host
        #
        # If the shared config entry already exists (like upgrade)
        # the update occurs immediately without sleep.
        #
        # If the shared config entry does not exist (fresh install)
        # DS server waits for 30s after its startup to create it.
        # Startup likely occurred few sec before this function is
        # called so this loop will wait for 30s max.
        #
        # In case the server is not able to create the entry
        # The loop gives a grace period of 60s before logging
        # the failure to update the shared config entry and return
        #
        max_wait = 30
        fqdn = self.api.env.host
        for _i in range(0, max_wait + 1):
            try:
                entries = conn.get_entries(
                    sharedcfgdn, scope=ldap.SCOPE_ONELEVEL,
                    filter='dnaHostname=%s' % fqdn
                )
                break
            except errors.NotFound:
                logger.debug(
                    "Unable to find DNA shared config entry for "
                    "dnaHostname=%s (under %s) so far. Retry in 2 sec.",
                    fqdn, sharedcfgdn
                )
                time.sleep(2)
        else:
            logger.error(
                "Could not get dnaHostname entries in %s seconds",
                max_wait * 2
            )
            return False, ()

        # If there are several entries, all of them will be updated
        # just log a debug msg. This is likely the result of #5510
        if len(entries) != 1:
            logger.debug(
                "%d entries dnaHostname=%s under %s. One expected",
                len(entries), fqdn, sharedcfgdn
            )

        # time to set the bind method and the protocol in the
        # shared config entries
        for entry in entries:
            update = False
            if entry.single_value.get(dna_bind_method) != method:
                entry[dna_bind_method] = method
                update = True

            if entry.single_value.get(dna_conn_protocol) != protocol:
                entry[dna_conn_protocol] = protocol
                update = True

            if update:
                try:
                    conn.update_entry(entry)
                except Exception as e:
                    logger.error(
                        "Failed to set SASL/GSSAPI bind method/protocol "
                        "in entry %s: %s", entry, e
                    )
        # no restart, no update
        return False, ()
