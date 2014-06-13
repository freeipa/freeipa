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
from ipalib import api, errors, util
from ipapython.dn import DN
from ipalib.plugins.dns import dns_container_exists
from ipapython.ipa_log_manager import *

class update_dnszones(PostUpdate):
    """
    Update all zones to meet requirements in the new FreeIPA versions

    1) AllowQuery and AllowTransfer
    Set AllowQuery and AllowTransfer ACLs in all zones that may be configured
    in an upgraded FreeIPA instance.

    Upgrading to new version of bind-dyndb-ldap and having these ACLs empty
    would result in a leak of potentially sensitive DNS information as
    zone transfers are enabled for all hosts if not disabled in named.conf
    or LDAP.

    This plugin disables the zone transfer by default so that it needs to be
    explicitly enabled by FreeIPA Administrator.

    2) Update policy
    SSH public key support includes a feature to automatically add/update
    client SSH fingerprints in SSHFP records. However, the update won't
    work for zones created before this support was added as they don't allow
    clients to update SSHFP records in their update policies.

    This module extends the original policy to allow the SSHFP updates.
    """
    order=MIDDLE

    def execute(self, **options):
        ldap = self.obj.backend

        try:
            zones = api.Command.dnszone_find(all=True)['result']
        except errors.NotFound:
            self.log.info('No DNS zone to update found')
            return (False, False, [])

        for zone in zones:
            update = {}
            if not zone.get('idnsallowquery'):
                # allow query from any client by default
                update['idnsallowquery'] = u'any;'

            if not zone.get('idnsallowtransfer'):
                # do not open zone transfers by default
                update['idnsallowtransfer'] = u'none;'

            old_policy = util.get_dns_forward_zone_update_policy(api.env.realm, ('A', 'AAAA'))
            if zone.get('idnsupdatepolicy', [''])[0] == old_policy:
                update['idnsupdatepolicy'] = util.get_dns_forward_zone_update_policy(\
                        api.env.realm)

            if update:
                api.Command.dnszone_mod(zone[u'idnsname'][0], **update)

        return (False, False, [])

api.register(update_dnszones)


class update_dns_limits(PostUpdate):
    """
    bind-dyndb-ldap persistent search queries LDAP for all DNS records.
    The LDAP connection must have no size or time limits to work
    properly. This plugin updates limits of the existing DNS service
    principal to match there requirements.
    """
    limit_attributes = ['nsTimeLimit', 'nsSizeLimit', 'nsIdleTimeout', 'nsLookThroughLimit']
    limit_value = '-1'

    def execute(self, **options):
        ldap = self.obj.backend

        if not dns_container_exists(ldap):
            return (False, False, [])

        dns_principal = 'DNS/%s@%s' % (self.env.host, self.env.realm)
        dns_service_dn = DN(('krbprincipalname', dns_principal),
                            self.env.container_service,
                            self.env.basedn)

        try:
            entry = ldap.get_entry(dns_service_dn, self.limit_attributes)
        except errors.NotFound:
            # this host may not have DNS service set
            root_logger.debug("DNS: service %s not found, no need to update limits" % dns_service_dn)
            return (False, False, [])

        if all(entry.get(limit.lower(), [None])[0] == self.limit_value for limit in self.limit_attributes):
            root_logger.debug("DNS: limits for service %s already set" % dns_service_dn)
            # service is already updated
            return (False, False, [])

        limit_updates = []

        for limit in self.limit_attributes:
            limit_updates.append('only:%s:%s' % (limit, self.limit_value))

        dnsupdates = {}
        dnsupdates[dns_service_dn] = {'dn': dns_service_dn,
                                      'updates': limit_updates}
        root_logger.debug("DNS: limits for service %s will be updated" % dns_service_dn)


        return (False, True, [dnsupdates])

api.register(update_dns_limits)
