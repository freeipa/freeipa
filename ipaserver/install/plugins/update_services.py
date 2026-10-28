# Authors:
#   Martin Kosek <mkosek@redhat.com>
#
# Copyright (C) 2012  Red Hat
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

import logging

from ipalib import Registry, errors
from ipalib import Updater
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_service_principalalias(Updater):
    """
    Update all services which do not have ipakrbprincipalalias attribute
    used for case-insensitive principal searches filled. This applies for
    all services created prior IPA 3.0.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        base_dn = DN(self.api.env.container_service, self.api.env.basedn)
        search_filter = ("(&(objectclass=krbprincipal)(objectclass=ipaservice)"
                         "(!(objectclass=ipakrbprincipal)))")
        logger.debug("update_service_principalalias: search for affected "
                     "services")

        while True:
            # run the search in loop to avoid issues when LDAP limits are hit
            # during update
            try:
                (entries, truncated) = ldap.find_entries(search_filter,
                    ['objectclass', 'krbprincipalname'], base_dn,
                    time_limit=0, size_limit=0)
            except errors.NotFound:
                logger.debug("update_service_principalalias: no service "
                             "to update found")
                return False, []
            except errors.ExecutionError as e:
                logger.error("update_service_principalalias: cannot "
                             "retrieve list of affected services: %s", e)
                return False, []
            if not entries:
                # no entry was returned, rather break than continue cycling
                logger.debug("update_service_principalalias: no service "
                             "was returned")
                return False, []
            logger.debug("update_service_principalalias: found %d "
                         "services to update, truncated: %s",
                         len(entries), truncated)

            error = False
            for entry in entries:
                entry['objectclass'] = (entry['objectclass'] +
                                        ['ipakrbprincipal'])
                entry['ipakrbprincipalalias'] = entry['krbprincipalname']
                try:
                    ldap.update_entry(entry)
                except (errors.EmptyModlist, errors.NotFound):
                    pass
                except errors.ExecutionError as e:
                    logger.debug("update_service_principalalias: cannot "
                                 "update service: %s", e)
                    error = True

            if error:
                # exit loop to avoid infinite cycles
                logger.error("update_service_principalalias: error(s)"
                             "detected during service update")
                return False, []
            elif not truncated:
                # all affected entries updated, exit the loop
                logger.debug("update_service_principalalias: all affected"
                             " services updated")
                return False, []
        return False, []
