# Authors:
#   Florence Blanc-Renaud <flo@redhat.com>
#
# Copyright (C) 2017  Red Hat
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
from ipalib.install import certstore
from ipapython.dn import DN
from ipapython.certdb import get_ca_nickname

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_fix_duplicate_cacrt_in_ldap(Updater):
    """
    When multiple entries exist for IPA CA cert in ldap, remove the duplicate

    After this plugin, ds needs to be restarted. This ensures that
    the attribute uniqueness plugin is working and prevents
    other plugins from adding duplicates.
    """

    def execute(self, **options):
        # If CA is disabled, no need to check for duplicates of IPA CA
        ca_enabled = self.api.Command.ca_is_enabled()['result']
        if not ca_enabled:
            return True, []

        # Look for the IPA CA cert subject
        ldap = self.api.Backend.ldap2
        cacert_subject = certstore.get_ca_subject(
            ldap,
            self.api.env.container_ca,
            self.api.env.basedn)

        # Find if there are other certificates with the same subject
        # They are duplicates resulting of BZ 1480102
        base_dn = DN(('cn', 'certificates'), ('cn', 'ipa'), ('cn', 'etc'),
                     self.api.env.basedn)
        try:
            filter = ldap.make_filter({'ipaCertSubject': cacert_subject})
            result, _truncated = ldap.find_entries(
                base_dn=base_dn,
                filter=filter,
                attrs_list=[])
        except errors.NotFound:
            # No duplicate, we're good
            logger.debug("No duplicates for IPA CA in LDAP")
            return True, []

        logger.debug("Found %d entrie(s) for IPA CA in LDAP", len(result))
        cacert_dn = DN(('cn', get_ca_nickname(self.api.env.realm)), base_dn)
        for entry in result:
            if entry.dn == cacert_dn:
                continue
            # Remove the duplicate
            try:
                ldap.delete_entry(entry)
                logger.debug("Removed the duplicate %s", entry.dn)
            except Exception as e:
                logger.warning("Failed to remove the duplicate %s: %s",
                               entry.dn, e)

        return True, []
