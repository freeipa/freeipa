#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import logging

from ipalib import Registry, errors
from ipalib import Updater
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_pwpolicy(Updater):
    """
    Add new ipapwdpolicy objectclass to all password policies

    Otherwise pwpolicy-find will not find them.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        base_dn = DN(('cn', self.api.env.realm), ('cn', 'kerberos'),
                     self.api.env.basedn)
        search_filter = (
            "(&(objectClass=krbpwdpolicy)(!(objectclass=ipapwdpolicy)))"
        )

        while True:
            # Run the search in loop to avoid issues when LDAP limits are hit
            # during update

            try:
                (entries, truncated) = ldap.find_entries(
                    search_filter, ['objectclass'], base_dn, time_limit=0,
                    size_limit=0)

            except errors.EmptyResult:
                logger.debug("update_pwpolicy: no policies without "
                             "objectclass set")
                return False, []

            except errors.ExecutionError as e:
                logger.error("update_pwpolicy: cannot retrieve list "
                             "of policies missing an objectclass: %s", e)
                return False, []

            logger.debug("update_pwpolicy: found %d "
                         "policies to update, truncated: %s",
                         len(entries), truncated)

            error = False

            for entry in entries:
                entry['objectclass'].append('ipapwdpolicy')
                try:
                    ldap.update_entry(entry)
                except (errors.EmptyModlist, errors.NotFound):
                    pass
                except errors.ExecutionError as e:
                    logger.debug("update_pwpolicy: cannot "
                                 "update policy: %s", e)
                    error = True

            if error:
                # Exit loop to avoid infinite cycles
                logger.error("update_pwpolicy: error(s) "
                             "detected during pwpolicy update")
                return False, []

            elif not truncated:
                # All affected entries updated, exit the loop
                logger.debug("update_pwpolicy: all policies updated")
                return False, []

        return False, []
