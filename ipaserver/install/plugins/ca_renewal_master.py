# Authors:
#   Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from __future__ import absolute_import

import logging

from ipaserver.install import cainstance
from ipalib import errors
from ipalib import Updater
from ipalib.install import certmonger
from ipalib.plugable import Registry
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython import directivesetter

logger = logging.getLogger(__name__)

register = Registry()

@register()
class update_ca_renewal_master(Updater):
    """
    Set CA renewal master in LDAP.
    """

    def execute(self, **options):
        ca = cainstance.CAInstance(self.api.env.realm)
        if not ca.is_configured():
            logger.debug("CA is not configured on this host")
            return False, []

        ldap = self.api.Backend.ldap2
        base_dn = DN(self.api.env.container_masters, self.api.env.basedn)
        dn = DN(('cn', 'CA'), ('cn', self.api.env.host), base_dn)
        filter = '(&(cn=CA)(ipaConfigString=caRenewalMaster))'
        try:
            entries = ldap.get_entries(base_dn=base_dn, filter=filter,
                                       attrs_list=[])
        except errors.NotFound:
            pass
        else:
            logger.debug("found CA renewal master %s", entries[0].dn[1].value)

            master = False
            updates = []

            for entry in entries:
                if entry.dn == dn:
                    master = True
                    continue

                updates.append({
                    'dn': entry.dn,
                    'updates': [
                        dict(action='remove', attr='ipaConfigString',
                             value='caRenewalMaster')
                    ],
                })

            if master:
                return False, updates
            else:
                return False, []

        criteria = {
            'cert-file': paths.RA_AGENT_PEM,
        }
        request_id = certmonger.get_request_id(criteria)
        if request_id is not None:
            logger.debug("found certmonger request for RA cert")

            ca_name = certmonger.get_request_value(request_id, 'ca-name')
            if ca_name is None:
                logger.warning(
                    "certmonger request for RA cert is missing ca_name, "
                    "assuming local CA is renewal slave")
                return False, []
            ca_name = ca_name.strip()

            if ca_name == 'dogtag-ipa-renew-agent':
                pass
            elif ca_name == 'dogtag-ipa-retrieve-agent-submit':
                return False, []
            elif ca_name == 'dogtag-ipa-ca-renew-agent':
                return False, []
            else:
                logger.warning(
                    "certmonger request for RA cert has unknown ca_name '%s', "
                    "assuming local CA is renewal slave", ca_name)
                return False, []
        else:
            logger.debug("certmonger request for RA cert not found")

            config = directivesetter.get_directive(
                paths.CA_CS_CFG_PATH, 'subsystem.select', '=')

            if config == 'New':
                pass
            elif config == 'Clone':
                return False, []
            else:
                logger.warning(
                    "CS.cfg has unknown subsystem.select value '%s', "
                    "assuming local CA is renewal slave", config)
                return (False, False, [])

        update = {
                'dn': dn,
                'updates': [
                    dict(action='add', attr='ipaConfigString',
                         value='caRenewalMaster')
                ],
        }

        return False, [update]
