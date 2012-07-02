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
from ipalib.dn import DN
from ipapython.ipa_log_manager import *

class update_default_range(PostUpdate):
    """
    Create default ID range for upgraded servers.
    """
    order=MIDDLE

    def execute(self, **options):
        ldap = self.obj.backend

        dn = str(DN(api.env.container_ranges, api.env.basedn))
        search_filter = "objectclass=ipaDomainIDRange"
        try:
            (entries, truncated) = ldap.find_entries(search_filter, [], dn)
        except errors.NotFound:
            pass
        else:
            root_logger.debug("default_range: ipaDomainIDRange entry found, skip plugin")
            return (False, False, [])

        dn = str(DN(('cn', 'admins'), api.env.container_group, api.env.basedn))
        try:
            (dn, admins_entry) = ldap.get_entry(dn, ['gidnumber'])
        except errors.NotFound:
            root_logger.error("No local ID range and no admins group found. "
                              "Cannot create default ID range")
            return (False, False, [])

        base_id = admins_entry['gidnumber'][0]
        id_range_size = 200000

        range_entry = ['objectclass:top',
                       'objectclass:ipaIDrange',
                       'objectclass:ipaDomainIDRange',
                       'cn:%s_id_range' % api.env.realm,
                       'ipabaseid:%s' % base_id,
                       'ipaidrangesize:%s' % id_range_size,
                      ]

        updates = {}
        dn = str(DN(('cn', '%s_id_range' % api.env.realm),
                 api.env.container_ranges, api.env.basedn))

        # make sure everything is str or otherwise python-ldap would complain
        range_entry = map(str, range_entry)
        updates[dn] = {'dn' : dn, 'default' : range_entry}

        return (False, True, [updates])

api.register(update_default_range)
