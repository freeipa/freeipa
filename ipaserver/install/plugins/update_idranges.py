# Authors:
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2013  Red Hat
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


class update_idrange_type(PostUpdate):
    """
    Update all ID ranges that do not have ipaRangeType attribute filled.
    This applies to all ID ranges prior to IPA 3.3.
    """

    order = MIDDLE

    def execute(self, **options):
        ldap = self.obj.backend

        base_dn = DN(api.env.container_ranges, api.env.basedn)
        search_filter = ("(&(objectClass=ipaIDrange)(!(ipaRangeType=*)))")
        root_logger.debug("update_idrange_type: search for ID ranges with no "
                          "type set")

        while True:
            # Run the search in loop to avoid issues when LDAP limits are hit
            # during update

            try:
                (entries, truncated) = ldap.find_entries(search_filter,
                    ['objectclass'], base_dn, time_limit=0, size_limit=0)

            except errors.NotFound:
                root_logger.debug("update_idrange_type: no ID range without "
                                  "type set found")
                return (False, False, [])

            except errors.ExecutionError, e:
                root_logger.error("update_idrange_type: cannot retrieve list "
                                  "of ranges with no type set: %s", e)
                return (False, False, [])

            if not entries:
                # No entry was returned, rather break than continue cycling
                root_logger.debug("update_idrange_type: no ID range was "
                                  "returned")
                return (False, False, [])

            root_logger.debug("update_idrange_type: found %d "
                              "idranges to update, truncated: %s",
                              len(entries), truncated)

            error = False

            # Set the range type
            for dn, entry in entries:
                update = {}

                objectclasses = [o.lower() for o
                                           in entry.get('objectclass', [])]

                if 'ipatrustedaddomainrange' in objectclasses:
                    # NOTICE: assumes every AD range does not use POSIX
                    #         attributes
                    update['ipaRangeType'] = 'ipa-ad-trust'
                elif 'ipadomainidrange' in objectclasses:
                    update['ipaRangeType'] = 'ipa-local'
                else:
                    update['ipaRangeType'] = 'unknown'
                    root_logger.error("update_idrange_type: could not detect "
                                      "range type for entry: %s" % str(dn))
                    root_logger.error("update_idrange_type: ID range type set "
                                      "to 'unknown' for entry: %s" % str(dn))

                try:
                    ldap.update_entry(dn, update)
                except (errors.EmptyModlist, errors.NotFound):
                    pass
                except errors.ExecutionError, e:
                    root_logger.debug("update_idrange_type: cannot "
                                      "update idrange type: %s", e)
                    error = True

            if error:
                # Exit loop to avoid infinite cycles
                root_logger.error("update_idrange_type: error(s) "
                                  "detected during idrange type update")
                return (False, False, [])

            elif not truncated:
                # All affected entries updated, exit the loop
                root_logger.debug("update_idrange_type: all affected idranges "
                                  "were assigned types")
                return (False, False, [])

        return (False, False, [])

api.register(update_idrange_type)
