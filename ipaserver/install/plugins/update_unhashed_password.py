# Authors:
#   Thierry Bordaz <tbordaz@redhat.com>
#
# Copyright (C) 2019  Red Hat
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
class update_unhashed_password(Updater):
    """
    DS
    """
    def __remove_update(self, update, key, value):
        statement = dict(action='remove', attr=key, value=value)
        update.setdefault('updates', []).append(statement)

    def __add_update(self, update, key, value):
        statement = dict(action='add', attr=key, value=value)
        update.setdefault('updates', []).append(statement)

    def execute(self, **options):
        logger.debug("Upgrading unhashed password configuration")
        ldap = self.api.Backend.ldap2
        base_config = DN(('cn', 'config'))
        try:
            entry = ldap.get_entry(base_config,
                                   ['nsslapd-unhashed-pw-switch'])
        except errors.NotFound:
            logger.error("Unhashed password configuration not found")
            return False, []

        config_dn = entry.dn

        toggle = entry.single_value.get("nsslapd-unhashed-pw-switch")
        if toggle.lower() not in ['off', 'on', 'nolog']:
            logger.error("Unhashed password had invalid value '%s'", toggle)

        # Check if it exists winsync agreements
        searchfilter = '(objectclass=nsDSWindowsReplicationAgreement)'
        try:
            winsync_agmts, _truncated = ldap.find_entries(
                base_dn=base_config,
                filter=searchfilter,
                attrs_list=[]
            )
        except errors.NotFound:
            logger.debug("Unhashed password this is not a winsync deployment")
            winsync_agmts = []

        update = {
            'dn': config_dn,
            'updates': [],
        }
        if len(winsync_agmts) > 0:
            # We are running in a winsync environment
            # Log a warning that changelog will contain sensitive data
            try:
                cldb_e = ldap.get_entry(
                    DN(('cn', 'changelog5'),
                       ('cn', 'config')),
                    ['nsslapd-changelogdir'])
                cldb = cldb_e.single_value.get("nsslapd-changelogdir")
                logger.warning("This server is configured for winsync, "
                               "the changelog files under %s "
                               "may contain clear text passwords.\n"
                               "Please ensure that these files can be accessed"
                               " only by trusted accounts.\n", cldb)
            except errors.NotFound:
                logger.warning("This server is configured for winsync, "
                               "the changelog files may contain "
                               "clear text passwords.\n"
                               "Please ensure that these files can be accessed"
                               " only by trusted accounts.\n")
            if toggle.lower() == 'on':
                # The current DS configuration already logs the
                # unhashed password
                updates = []
            else:
                self.__remove_update(update, 'nsslapd-unhashed-pw-switch',
                                     toggle)
                self.__add_update(update, 'nsslapd-unhashed-pw-switch', 'on')
                updates = [update]
        else:
            if toggle.lower() == 'nolog':
                updates = []
            else:
                self.__remove_update(update, 'nsslapd-unhashed-pw-switch',
                                     toggle)
                self.__add_update(update, 'nsslapd-unhashed-pw-switch',
                                  'nolog')
                updates = [update]

        return False, updates
