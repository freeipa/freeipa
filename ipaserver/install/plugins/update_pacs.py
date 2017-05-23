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
class update_pacs(Updater):
    """
    Includes default nfs:None only if no nfs: PAC present in ipakrbauthzdata.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        try:
            dn = DN('cn=ipaConfig', 'cn=etc', self.api.env.basedn)
            entry = ldap.get_entry(dn, ['ipakrbauthzdata'])
            pacs = entry.get('ipakrbauthzdata', [])
        except errors.NotFound:
            logger.warning('Error retrieving: %s', str(dn))
            return False, []

        nfs_pac_set = any(pac.startswith('nfs:') for pac in pacs)

        if not nfs_pac_set:
            logger.debug('Adding nfs:NONE to default PAC types')

            updated_pacs = pacs + [u'nfs:NONE']
            entry['ipakrbauthzdata'] = updated_pacs
            ldap.update_entry(entry)
        else:
            logger.debug('PAC for nfs is already set, not adding nfs:NONE.')

        return False, []
