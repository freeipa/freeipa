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


class update_pacs(PostUpdate):
    """
    Includes default nfs:None only if no nfs: PAC present in ipakrbauthzdata.
    """

    order = MIDDLE

    def execute(self, **options):
        if not options.get('live_run'):
            self.log.info("Test mode: skipping 'update_pacs'")
            return False, False, ()

        ldap = self.obj.backend

        try:
            dn = DN('cn=ipaConfig', 'cn=etc', api.env.basedn)
            entry = ldap.get_entry(dn, ['ipakrbauthzdata'])
            pacs = entry.get('ipakrbauthzdata', [])
        except errors.NotFound:
            self.log.warning('Error retrieving: %s' % str(dn))
            return (False, False, [])

        nfs_pac_set = any(pac.startswith('nfs:') for pac in pacs)

        if not nfs_pac_set:
            self.log.debug('Adding nfs:NONE to default PAC types')

            updated_pacs = pacs + [u'nfs:NONE']
            entry['ipakrbauthzdata'] = updated_pacs
            ldap.update_entry(entry)
        else:
            self.log.debug('PAC for nfs is already set, not adding nfs:NONE.')

        return (False, False, [])

api.register(update_pacs)
