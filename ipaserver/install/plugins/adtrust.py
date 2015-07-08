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

from ipalib import api, errors
from ipalib import Updater
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.ipa_log_manager import *
from ipapython import sysrestore
from ipaserver.install import installutils

DEFAULT_ID_RANGE_SIZE = 200000

class update_default_range(Updater):
    """
    Create default ID range for upgraded servers.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        dn = DN(self.api.env.container_ranges, self.api.env.basedn)
        search_filter = "objectclass=ipaDomainIDRange"
        try:
            (entries, truncated) = ldap.find_entries(search_filter, [], dn)
        except errors.NotFound:
            pass
        else:
            root_logger.debug("default_range: ipaDomainIDRange entry found, skip plugin")
            return False, []

        dn = DN(('cn', 'admins'), self.api.env.container_group,
                self.api.env.basedn)
        try:
            admins_entry = ldap.get_entry(dn, ['gidnumber'])
        except errors.NotFound:
            root_logger.error("default_range: No local ID range and no admins "
                              "group found. Cannot create default ID range")
            return False, []

        id_range_base_id = admins_entry['gidnumber'][0]
        id_range_name = '%s_id_range' % self.api.env.realm
        id_range_size = DEFAULT_ID_RANGE_SIZE

        range_entry = [
            dict(attr='objectclass', value='top'),
            dict(attr='objectclass', value='ipaIDrange'),
            dict(attr='objectclass', value='ipaDomainIDRange'),
            dict(attr='cn', value=id_range_name),
            dict(attr='ipabaseid', value=id_range_base_id),
            dict(attr='ipaidrangesize', value=id_range_size),
            dict(attr='iparangetype', value='ipa-local'),
        ]

        dn = DN(('cn', '%s_id_range' % self.api.env.realm),
                self.api.env.container_ranges, self.api.env.basedn)

        update = {'dn': dn, 'default': range_entry}

        # Default range entry has a hard-coded range size to 200000 which is
        # a default range size in ipa-server-install. This could cause issues
        # if user did not use a default range, but rather defined an own,
        # bigger range (option --idmax).
        # We should make our best to check if this is the case and provide
        # user with an information how to fix it.
        dn = DN(self.api.env.container_dna_posix_ids, self.api.env.basedn)
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
            for entry in entries:
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

        return False, [update]


class update_default_trust_view(Updater):
    """
    Create Default Trust View for upgraded servers.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        default_trust_view_dn = DN(('cn', 'Default Trust View'),
                                   self.api.env.container_views,
                                   self.api.env.basedn)

        default_trust_view_entry = [
            dict(attr='objectclass', value='top'),
            dict(attr='objectclass', value='ipaIDView'),
            dict(attr='cn', value='Default Trust View'),
            dict(attr='description', value='Default Trust View for AD users. '
                 'Should not be deleted.'),
        ]

        # First, see if trusts are enabled on the server
        if not self.api.Command.adtrust_is_enabled()['result']:
            self.log.debug('AD Trusts are not enabled on this server')
            return False, []

        # Second, make sure the Default Trust View does not exist yet
        try:
            ldap.get_entry(default_trust_view_dn)
        except errors.NotFound:
            pass
        else:
            self.log.debug('Default Trust View already present on this server')
            return False, []

        # We have a server with AD trust support without Default Trust View.
        # Create the Default Trust View entry.

        update = {
            'dn': default_trust_view_dn,
            'default': default_trust_view_entry
        }

        return False, [update]


class update_oddjobd_for_adtrust(Updater):
    """
    Enables and starts oddjobd daemon if ipa-adtrust-install has been run
    on this system.
    """

    def execute(self, **options):
        adtrust_is_enabled = self.api.Command['adtrust_is_enabled']()['result']

        if adtrust_is_enabled:
            self.log.debug('Try to enable and start oddjobd')
            sstore = sysrestore.StateFile(paths.SYSRESTORE)
            installutils.enable_and_start_oddjobd(sstore)
        else:
            self.log.debug('ADTrust not configured on this server, do not '
                           'start and enable oddjobd')

        return False, []

api.register(update_default_range)
api.register(update_default_trust_view)
api.register(update_oddjobd_for_adtrust)
