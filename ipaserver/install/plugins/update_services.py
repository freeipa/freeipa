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

from ipaserver.install.plugins import MIDDLE
from ipaserver.install.plugins.baseupdate import PostUpdate
from ipalib import api, errors
from ipapython.dn import DN
from ipapython.ipa_log_manager import *


class update_service_principalalias(PostUpdate):
    """
    Update all services which do not have ipakrbprincipalalias attribute
    used for case-insensitive principal searches filled. This applies for
    all services created prior IPA 3.0.
    """
    order = MIDDLE

    def execute(self, **options):
        ldap = self.obj.backend

        base_dn = DN(api.env.container_service, api.env.basedn)
        search_filter = ("(&(objectclass=krbprincipal)(objectclass=ipaservice)"
                         "(!(objectclass=ipakrbprincipal)))")
        root_logger.debug("update_service_principalalias: search for affected "
                          "services")

        while True:
            # run the search in loop to avoid issues when LDAP limits are hit
            # during update
            try:
                (entries, truncated) = ldap.find_entries(search_filter,
                    ['objectclass', 'krbprincipalname'], base_dn,
                    time_limit=0, size_limit=0)
            except errors.NotFound:
                root_logger.debug("update_service_principalalias: no service "
                                  "to update found")
                return (False, False, [])
            except errors.ExecutionError, e:
                root_logger.error("update_service_principalalias: cannot "
                                  "retrieve list of affected services: %s", e)
                return (False, False, [])
            if not entries:
                # no entry was returned, rather break than continue cycling
                root_logger.debug("update_service_principalalias: no service "
                                  "was returned")
                return (False, False, [])
            root_logger.debug("update_service_principalalias: found %d "
                              "services to update, truncated: %s",
                              len(entries), truncated)

            error = False
            for dn, entry in entries:
                update = {}
                update['objectclass'] = (entry['objectclass'] +
                                         ['ipakrbprincipal'])
                update['ipakrbprincipalalias'] = entry['krbprincipalname']
                try:
                    ldap.update_entry(dn, update)
                except (errors.EmptyModlist, errors.NotFound):
                    pass
                except errors.ExecutionError, e:
                    root_logger.debug("update_service_principalalias: cannot "
                                      "update service: %s", e)
                    error = True

            if error:
                # exit loop to avoid infinite cycles
                root_logger.error("update_service_principalalias: error(s)"
                                  "detected during service update")
                return (False, False, [])
            elif not truncated:
                # all affected entries updated, exit the loop
                root_logger.debug("update_service_principalalias: all affected"
                                  " services updated")
                return (False, False, [])
        return (False, False, [])

api.register(update_service_principalalias)
