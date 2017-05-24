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

import logging

from ipalib import Registry, errors
from ipalib import Updater
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_idrange_type(Updater):
    """
    Update all ID ranges that do not have ipaRangeType attribute filled.
    This applies to all ID ranges prior to IPA 3.3.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        base_dn = DN(self.api.env.container_ranges, self.api.env.basedn)
        search_filter = ("(&(objectClass=ipaIDrange)(!(ipaRangeType=*)))")
        logger.debug("update_idrange_type: search for ID ranges with no "
                     "type set")

        while True:
            # Run the search in loop to avoid issues when LDAP limits are hit
            # during update

            try:
                (entries, truncated) = ldap.find_entries(search_filter,
                    ['objectclass'], base_dn, time_limit=0, size_limit=0)

            except errors.NotFound:
                logger.debug("update_idrange_type: no ID range without "
                             "type set found")
                return False, []

            except errors.ExecutionError as e:
                logger.error("update_idrange_type: cannot retrieve list "
                             "of ranges with no type set: %s", e)
                return False, []

            if not entries:
                # No entry was returned, rather break than continue cycling
                logger.debug("update_idrange_type: no ID range was returned")
                return False, []

            logger.debug("update_idrange_type: found %d "
                         "idranges to update, truncated: %s",
                         len(entries), truncated)

            error = False

            # Set the range type
            for entry in entries:
                objectclasses = [o.lower() for o
                                           in entry.get('objectclass', [])]

                if 'ipatrustedaddomainrange' in objectclasses:
                    # NOTICE: assumes every AD range does not use POSIX
                    #         attributes
                    entry['ipaRangeType'] = ['ipa-ad-trust']
                elif 'ipadomainidrange' in objectclasses:
                    entry['ipaRangeType'] = ['ipa-local']
                else:
                    entry['ipaRangeType'] = ['unknown']
                    logger.error("update_idrange_type: could not detect "
                                 "range type for entry: %s", str(entry.dn))
                    logger.error("update_idrange_type: ID range type set "
                                 "to 'unknown' for entry: %s", str(entry.dn))

                try:
                    ldap.update_entry(entry)
                except (errors.EmptyModlist, errors.NotFound):
                    pass
                except errors.ExecutionError as e:
                    logger.debug("update_idrange_type: cannot "
                                 "update idrange type: %s", e)
                    error = True

            if error:
                # Exit loop to avoid infinite cycles
                logger.error("update_idrange_type: error(s) "
                             "detected during idrange type update")
                return False, []

            elif not truncated:
                # All affected entries updated, exit the loop
                logger.debug("update_idrange_type: all affected idranges "
                             "were assigned types")
                return False, []

        return False, []


@register()
class update_idrange_baserid(Updater):
    """
    Update ipa-ad-trust-posix ranges' base RID to 0. This applies to AD trust
    posix ranges prior to IPA 4.1.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        base_dn = DN(self.api.env.container_ranges, self.api.env.basedn)
        search_filter = ("(&(objectClass=ipaTrustedADDomainRange)"
                         "(ipaRangeType=ipa-ad-trust-posix)"
                         "(!(ipaBaseRID=0)))")
        logger.debug(
            "update_idrange_baserid: search for ipa-ad-trust-posix ID ranges "
            "with ipaBaseRID != 0"
        )

        try:
            (entries, _truncated) = ldap.find_entries(
                search_filter, ['ipabaserid'], base_dn,
                paged_search=True, time_limit=0, size_limit=0)

        except errors.NotFound:
            logger.debug("update_idrange_baserid: no AD domain "
                         "range with posix attributes found")
            return False, []

        except errors.ExecutionError as e:
            logger.error("update_idrange_baserid: cannot retrieve "
                         "list of affected ranges: %s", e)
            return False, []

        logger.debug("update_idrange_baserid: found %d "
                     "idranges possible to update",
                     len(entries))

        error = False

        # Set the range type
        for entry in entries:
            entry['ipabaserid'] = 0
            try:
                logger.debug("Updating existing idrange: %s", entry.dn)
                ldap.update_entry(entry)
                logger.info("Done")
            except (errors.EmptyModlist, errors.NotFound):
                pass
            except errors.ExecutionError as e:
                logger.debug("update_idrange_type: cannot "
                             "update idrange: %s", e)
                error = True

        if error:
            logger.error("update_idrange_baserid: error(s) "
                         "detected during idrange baserid update")
        else:
            # All affected entries updated, exit the loop
            logger.debug("update_idrange_baserid: all affected "
                         "idranges updated")

        return False, []
