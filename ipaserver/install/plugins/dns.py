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
from ipaserver.install.plugins import baseupdate
from ipalib import api, errors, util
from ipalib.dn import DN
from ipalib.plugins.dns import dns_container_exists

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

            old_policy = util.gen_dns_update_policy(api.env.realm, ('A', 'AAAA'))
            if zone.get('idnsupdatepolicy', [''])[0] == old_policy:
                update['idnsupdatepolicy'] = util.gen_dns_update_policy(\
                        api.env.realm)

            if update:
                api.Command.dnszone_mod(zone[u'idnsname'][0], **update)

        return (False, False, [])

api.register(update_dnszones)

class update_dns_permissions(PostUpdate):
    """
    New DNS permissions need to be added only for updated machines with
    enabled DNS. LDIF loaded by DNS installer would fail because of duplicate
    entries otherwise.
    """

    _write_dns_perm_dn = DN('cn=Write DNS Configuration',
                            api.env.container_permission,
                            api.env.basedn)
    _write_dns_perm_entry = ['objectClass:groupofnames',
                             'objectClass:top',
                             'cn:Write DNS Configuration',
                             'description:Write DNS Configuration',
                             'member:cn=DNS Administrators,cn=privileges,cn=pbac,%s' \
                                     % api.env.basedn,
                             'member:cn=DNS Servers,cn=privileges,cn=pbac,%s' \
                                     % api.env.basedn]

    _read_dns_perm_dn = DN('cn=Read DNS Entries',
                            api.env.container_permission,
                            api.env.basedn)
    _read_dns_perm_entry = ['objectClass:top',
                            'objectClass:groupofnames',
                            'objectClass:ipapermission',
                            'cn:Read DNS Entries',
                            'description:Read DNS entries',
                            'ipapermissiontype:SYSTEM',
                            'member:cn=DNS Administrators,cn=privileges,cn=pbac,%s' \
                                     % api.env.basedn,
                            'member:cn=DNS Servers,cn=privileges,cn=pbac,%s' \
                                     % api.env.basedn,]

    _write_dns_aci_dn = DN(api.env.basedn)
    _write_dns_aci_entry = ['add:aci:\'(targetattr = "idnsforwardpolicy || idnsforwarders || idnsallowsyncptr || idnszonerefresh || idnspersistentsearch")(target = "ldap:///cn=dns,%(realm)s")(version 3.0;acl "permission:Write DNS Configuration";allow (write) groupdn = "ldap:///cn=Write DNS Configuration,cn=permissions,cn=pbac,%(realm)s";)\'' % dict(realm=api.env.basedn)]

    _read_dns_aci_dn = DN(api.env.container_dns, api.env.basedn)
    _read_dns_aci_entry = ['add:aci:\'(targetattr = "*")(version 3.0; acl "No access to DNS tree without a permission"; deny (read,search,compare) (groupdn != "ldap:///cn=admins,cn=groups,cn=accounts,%(realm)s") and (groupdn != "ldap:///cn=Read DNS Entries,cn=permissions,cn=pbac,%(realm)s");)\''  % dict(realm=api.env.basedn) ]

    def execute(self, **options):
        ldap = self.obj.backend

        if not dns_container_exists(ldap):
            return (False, False, [])

        dnsupdates = {}

        # add default and updated entries
        for dn, container, entry in ((self._write_dns_perm_dn, 'default', self._write_dns_perm_entry),
                                     (self._read_dns_perm_dn, 'default', self._read_dns_perm_entry),
                                     (self._write_dns_aci_dn, 'updates', self._write_dns_aci_entry),
                                     (self._read_dns_aci_dn, 'updates', self._read_dns_aci_entry)):

            dn = str(dn)
            # make sure everything is str or otherwise python-ldap would complain
            entry = map(str, entry)
            dnsupdates[dn] = {'dn' : dn, container : entry}

        return (False, True, [dnsupdates])

api.register(update_dns_permissions)
