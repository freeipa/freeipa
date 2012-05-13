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

DEFAULT_ID_RANGE_SIZE = 200000

class update_default_range(PostUpdate):
    """
    Create default ID range for upgraded servers.
    """
    order=MIDDLE

    def execute(self, **options):
        ldap = self.obj.backend

        dn = DN(api.env.container_ranges, api.env.basedn)
        search_filter = "objectclass=ipaDomainIDRange"
        try:
            (entries, truncated) = ldap.find_entries(search_filter, [], dn)
        except errors.NotFound:
            pass
        else:
            root_logger.debug("default_range: ipaDomainIDRange entry found, skip plugin")
            return (False, False, [])

        dn = DN(('cn', 'admins'), api.env.container_group, api.env.basedn)
        try:
            (dn, admins_entry) = ldap.get_entry(dn, ['gidnumber'])
        except errors.NotFound:
            root_logger.error("default_range: No local ID range and no admins "
                              "group found. Cannot create default ID range")
            return (False, False, [])

        id_range_base_id = admins_entry['gidnumber'][0]
        id_range_name = '%s_id_range' % api.env.realm
        id_range_size = DEFAULT_ID_RANGE_SIZE

        range_entry = ['objectclass:top',
                       'objectclass:ipaIDrange',
                       'objectclass:ipaDomainIDRange',
                       'cn:%s' % id_range_name,
                       'ipabaseid:%s' % id_range_base_id,
                       'ipaidrangesize:%s' % id_range_size,
                      ]

        updates = {}
        dn = DN(('cn', '%s_id_range' % api.env.realm),
                api.env.container_ranges, api.env.basedn)

        updates[dn] = {'dn': dn, 'default': range_entry}

        # Default range entry has a hard-coded range size to 200000 which is
        # a default range size in ipa-server-install. This could cause issues
        # if user did not use a default range, but rather defined an own,
        # bigger range (option --idmax).
        # We should make our best to check if this is the case and provide
        # user with an information how to fix it.
        dn = DN(api.env.container_dna_posix_ids, api.env.basedn)
        search_filter = "objectclass=dnaSharedConfig"
        attrs = ['dnaHostname', 'dnaRemainingValues']
        try:
            (entries, truncated) = ldap.find_entries(search_filter, attrs, dn)
        except errors.NotFound:
            root_logger.warning("default_range: no dnaSharedConfig object found. "
                                "Cannot check default range size.")
        else:
            masters = set()
            remaining_values_sum = 0
            for entry_dn, entry in entries:
                hostname = entry.get('dnahostname', [None])[0]
                if hostname is None or hostname in masters:
                    continue
                remaining_values = entry.get('dnaremainingvalues', [''])[0]
                try:
                    remaining_values = int(remaining_values)
                except ValueError:
                    root_logger.warning("default_range: could not parse "
                        "remaining values from '%s'", remaining_values)
                    continue
                else:
                    remaining_values_sum += remaining_values

                masters.add(hostname)

            if remaining_values_sum > DEFAULT_ID_RANGE_SIZE:
                msg = ['could not verify default ID range size',
                       'Please use the following command to set correct ID range size',
                       '  $ ipa range-mod %s --range-size=RANGE_SIZE' % id_range_name,
                       'RANGE_SIZE may be computed from --idstart and --idmax options '
                       'used during IPA server installation:',
                       '  RANGE_SIZE = (--idmax) - (--idstart) + 1'
                      ]

                root_logger.error("default_range: %s", "\n".join(msg))

        return (False, True, [updates])

api.register(update_default_range)
