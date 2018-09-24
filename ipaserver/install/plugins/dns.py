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

from __future__ import absolute_import

import logging

import dns.exception
import re
import traceback
import time

from ldif import LDIFWriter

from ipalib import Registry, errors, util
from ipalib import Updater
from ipapython.dn import DN
from ipapython import dnsutil
from ipaserver.install import sysupgrade
from ipaserver.install.bindinstance import ensure_dnsserver_container_exists
from ipaserver.plugins.dns import dns_container_exists

logger = logging.getLogger(__name__)

register = Registry()


class DNSUpdater(Updater):
    backup_dir = u'/var/lib/ipa/backup/'
    # override backup_filename in subclass, it will be mangled by strftime
    backup_filename = None

    def __init__(self, api):
        super(DNSUpdater, self).__init__(api)
        backup_path = u'%s%s' % (self.backup_dir, self.backup_filename)
        self.backup_path = time.strftime(backup_path)
        self._ldif_writer = None
        self._saved_privileges = set()  # store privileges only once
        self.saved_zone_to_privilege = {}

    def version_update_needed(self, target_version):
        """Test if IPA DNS version is smaller than target version."""
        assert isinstance(target_version, int)

        try:
            return int(self.api.Command['dnsconfig_show'](
                all=True)['result']['ipadnsversion'][0]) < target_version
        except errors.NotFound:
            # IPA DNS is not configured
            return False

    @property
    def ldif_writer(self):
        if not self._ldif_writer:
            logger.info('Original zones will be saved in LDIF format in '
                        '%s file', self.backup_path)
            self._ldif_writer = LDIFWriter(open(self.backup_path, 'w'))
        return self._ldif_writer

    def backup_zone(self, zone):
        """Backup zone object, its records, permissions, and privileges.

        Mapping from zone to privilege (containing zone's permissions)
        will be stored in saved_zone_to_privilege dict for further usage.
        """
        dn = str(zone['dn'])
        del zone['dn']  # dn shouldn't be as attribute in ldif
        self.ldif_writer.unparse(dn, zone)

        ldap = self.api.Backend.ldap2
        if 'managedBy' in zone:
            permission = ldap.get_entry(DN(zone['managedBy'][0]))
            self.ldif_writer.unparse(str(permission.dn), dict(permission.raw))
            for privilege_dn in permission.get('member', []):
                # privileges can be shared by multiples zones
                if privilege_dn not in self._saved_privileges:
                    self._saved_privileges.add(privilege_dn)
                    privilege = ldap.get_entry(privilege_dn)
                    self.ldif_writer.unparse(str(privilege.dn),
                                             dict(privilege.raw))

            # remember privileges referened by permission
            if 'member' in permission:
                self.saved_zone_to_privilege[
                    zone['idnsname'][0]
                ] = permission['member']

        if 'idnszone' in zone['objectClass']:
            # raw values are required to store into ldif
            records = self.api.Command['dnsrecord_find'](zone['idnsname'][0],
                                                         all=True,
                                                         raw=True,
                                                         sizelimit=0)['result']
            for record in records:
                if record['idnsname'][0] == u'@':
                    # zone record was saved before
                    continue
                dn = str(record['dn'])
                del record['dn']
                self.ldif_writer.unparse(dn, record)


@register()
class update_ipaconfigstring_dnsversion_to_ipadnsversion(Updater):
    """
    IPA <= 4.3.1 used ipaConfigString "DNSVersion 1" on DNS container.
    This was hard to deal with in API so from IPA 4.3.2 we are using
    new ipaDNSVersion attribute with integer syntax.
    Old ipaConfigString is left there for now so if someone accidentally
    executes upgrade on an old replica again it will not re-upgrade the data.
    """
    def execute(self, **options):
        ldap = self.api.Backend.ldap2
        dns_container_dn = DN(self.api.env.container_dns, self.api.env.basedn)
        try:
            container_entry = ldap.get_entry(dns_container_dn)
        except errors.NotFound:
            # DNS container not found, nothing to upgrade
            return False, []

        if 'ipadnscontainer' in [
            o.lower() for o in container_entry['objectclass']
        ]:
            # version data are already migrated
            return False, []

        logger.debug('Migrating DNS ipaConfigString to ipaDNSVersion')
        container_entry['objectclass'].append('ipadnscontainer')
        version = 0
        for config_option in container_entry.get("ipaConfigString", []):
            matched = re.match(r"^DNSVersion\s+(?P<version>\d+)$",
                               config_option, flags=re.I)
            if matched:
                version = int(matched.group("version"))
            else:
                logger.error(
                    'Failed to parse DNS version from ipaConfigString, '
                    'defaulting to version %s', version)
        container_entry['ipadnsversion'] = version
        ldap.update_entry(container_entry)
        logger.debug('ipaDNSVersion = %s', version)
        return False, []


@register()
class update_dnszones(Updater):
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

    def execute(self, **options):
        ldap = self.api.Backend.ldap2
        if not dns_container_exists(ldap):
            return False, []

        try:
            zones = self.api.Command.dnszone_find(all=True)['result']
        except errors.NotFound:
            logger.debug('No DNS zone to update found')
            return False, []

        for zone in zones:
            update = {}
            if not zone.get('idnsallowquery'):
                # allow query from any client by default
                update['idnsallowquery'] = u'any;'

            if not zone.get('idnsallowtransfer'):
                # do not open zone transfers by default
                update['idnsallowtransfer'] = u'none;'

            old_policy = util.get_dns_forward_zone_update_policy(
                self.api.env.realm, ('A', 'AAAA'))
            if zone.get('idnsupdatepolicy', [''])[0] == old_policy:
                update['idnsupdatepolicy'] = util.get_dns_forward_zone_update_policy(\
                        self.api.env.realm)

            if update:
                # FIXME: https://fedorahosted.org/freeipa/ticket/4722
                self.api.Command.dnszone_mod(zone[u'idnsname'][0].make_absolute(),
                                        **update)

        return False, []


@register()
class update_dns_limits(Updater):
    """
    bind-dyndb-ldap persistent search queries LDAP for all DNS records.
    The LDAP connection must have no size or time limits to work
    properly. This plugin updates limits of the existing DNS service
    principal to match there requirements.
    """
    limit_attributes = ['nsTimeLimit', 'nsSizeLimit', 'nsIdleTimeout', 'nsLookThroughLimit']
    limit_value = '-1'

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        if not dns_container_exists(ldap):
            return False, []

        dns_principal = 'DNS/%s@%s' % (self.env.host, self.env.realm)
        dns_service_dn = DN(('krbprincipalname', dns_principal),
                            self.env.container_service,
                            self.env.basedn)

        try:
            entry = ldap.get_entry(dns_service_dn, self.limit_attributes)
        except errors.NotFound:
            # this host may not have DNS service set
            logger.debug("DNS: service %s not found, no need to update limits",
                         dns_service_dn)
            return False, []

        if all(entry.get(limit.lower(), [None])[0] == self.limit_value for limit in self.limit_attributes):
            logger.debug("DNS: limits for service %s already set",
                         dns_service_dn)
            # service is already updated
            return False, []

        limit_updates = []

        for limit in self.limit_attributes:
            limit_updates.append(dict(action='only', attr=limit,
                                      value=self.limit_value))

        dnsupdate = {'dn': dns_service_dn, 'updates': limit_updates}
        logger.debug("DNS: limits for service %s will be updated",
                     dns_service_dn)


        return False, [dnsupdate]


@register()
class update_master_to_dnsforwardzones(DNSUpdater):
    """
    Update all zones to meet requirements in the new FreeIPA versions

    All masters zones with specified forwarders, and forward-policy different
    than none, will be tranformed to forward zones.
    Original masters zone will be backed up to ldif file.

    This should be applied only once,
    and only if original version was lower than 4.0
    """
    backup_filename = u'dns-master-to-forward-zones-%Y-%m-%d-%H-%M-%S.ldif'

    def execute(self, **options):
        # check LDAP if forwardzones already uses new semantics
        if not self.version_update_needed(target_version=1):
            # forwardzones already uses new semantics,
            # no upgrade is required
            return False, []

        logger.debug('Updating forward zones')
        # update the DNSVersion, following upgrade can be executed only once
        self.api.Command['dnsconfig_mod'](ipadnsversion=1)

        # Updater in IPA version from 4.0 to 4.1.2 doesn't work well, this
        # should detect if update in past has been executed, and set proper
        # DNSVersion into LDAP
        try:
            fwzones = self.api.Command.dnsforwardzone_find()['result']
        except errors.NotFound:
            # No forwardzones found, update probably has not been executed yet
            pass
        else:
            if fwzones:
                # fwzones exist, do not execute upgrade again
                return False, []

        zones = []
        try:
            # raw values are required to store into ldif
            zones = self.api.Command.dnszone_find(all=True,
                                             raw=True,
                                             sizelimit=0)['result']
        except errors.NotFound:
            pass

        if not zones:
            logger.debug('No DNS zone to update found')
            return False, []

        zones_to_transform = []

        for zone in zones:
            if (
                zone.get('idnsforwardpolicy', [u'first'])[0] == u'none' or
                zone.get('idnsforwarders', []) == []
            ):
                continue  # don't update zone

            zones_to_transform.append(zone)

        if zones_to_transform:
            logger.info('Zones with specified forwarders with policy '
                        'different than none will be transformed to forward '
                        'zones.')
            # update
            for zone in zones_to_transform:
                try:
                    self.backup_zone(zone)
                except Exception:
                    logger.error('Unable to create backup for zone, '
                                 'terminating zone upgrade')
                    logger.error("%s", traceback.format_exc())
                    return False, []

                # delete master zone
                try:
                    self.api.Command['dnszone_del'](zone['idnsname'])
                except Exception as e:
                    logger.error('Transform to forwardzone terminated: '
                                 'removing zone %s failed (%s)',
                                 zone['idnsname'][0], e)
                    logger.error("%s", traceback.format_exc())
                    continue

                # create forward zone
                try:
                    kw = {
                        'idnsforwarders': zone.get('idnsforwarders', []),
                        'idnsforwardpolicy': zone.get('idnsforwardpolicy',
                                                      [u'first'])[0],
                        'skip_overlap_check': True,
                    }
                    self.api.Command['dnsforwardzone_add'](zone['idnsname'][0], **kw)
                except Exception:
                    logger.error('Transform to forwardzone terminated: '
                                 'creating forwardzone %s failed',
                                 zone['idnsname'][0])
                    logger.error("%s", traceback.format_exc())
                    continue

                # create permission if original zone has one
                if 'managedBy' in zone:
                    try:
                        perm_name = self.api.Command['dnsforwardzone_add_permission'](
                                        zone['idnsname'][0])['value']
                    except Exception:
                        logger.error('Transform to forwardzone terminated: '
                                     'Adding managed by permission to forward '
                                     'zone %s failed', zone['idnsname'])
                        logger.error("%s", traceback.format_exc())
                        logger.info('Zone %s was transformed to forward zone '
                                    ' without managed permissions',
                                    zone['idnsname'][0])
                        continue

                    else:
                        if zone['idnsname'][0] in self.saved_zone_to_privilege:
                            privileges = [
                                dn[0].value for dn in self.saved_zone_to_privilege[zone['idnsname'][0]]
                            ]
                            try:
                                self.api.Command['permission_add_member'](perm_name,
                                                    privilege=privileges)
                            except Exception:
                                logger.error('Unable to restore privileges '
                                             'for permission %s, for zone %s',
                                             perm_name, zone['idnsname'])
                                logger.error("%s", traceback.format_exc())
                                logger.info('Zone %s was transformed to '
                                            'forward zone without restored '
                                            'privileges',
                                            zone['idnsname'][0])
                                continue

                logger.debug('Zone %s was sucessfully transformed to forward '
                             'zone',
                             zone['idnsname'][0])

        return False, []


@register()
class update_dnsforward_emptyzones(DNSUpdater):
    """
    Migrate forward policies which conflict with automatic empty zones
    (RFC 6303) to use forward policy = only.

    BIND ignores conflicting forwarding configuration
    when forwarding policy != only.
    bind-dyndb-ldap 9.0+ will do the same so we have to adjust FreeIPA zones
    accordingly.
    """
    backup_filename = u'dns-forwarding-empty-zones-%Y-%m-%d-%H-%M-%S.ldif'

    def update_zones(self):
        try:
            fwzones = self.api.Command.dnsforwardzone_find(all=True,
                                                           raw=True)['result']
        except errors.NotFound:
            # No forwardzones found, we are done
            return

        logged_once = False
        for zone in fwzones:
            if not (
                dnsutil.related_to_auto_empty_zone(
                    dnsutil.DNSName(zone.get('idnsname')[0]))
                and zone.get('idnsforwardpolicy', [u'first'])[0] != u'only'
                and zone.get('idnsforwarders', []) != []
            ):
                # this zone does not conflict with automatic empty zone
                continue

            if not logged_once:
                logger.info('Forward policy for zones conflicting with '
                            'automatic empty zones will be changed to "only"')
                logged_once = True

            # backup
            try:
                self.backup_zone(zone)
            except Exception:
                logger.error('Unable to create backup for zone %s, '
                             'terminating zone upgrade',
                             zone['idnsname'][0])
                logger.error("%s", traceback.format_exc())
                continue

            # change forward policy
            try:
                self.api.Command['dnsforwardzone_mod'](
                    zone['idnsname'][0],
                    idnsforwardpolicy=u'only'
                )
            except Exception as e:
                logger.error('Forward policy update for zone %s failed '
                             '(%s)', zone['idnsname'][0], e)
                logger.error("%s", traceback.format_exc())
                continue

            logger.debug('Zone %s was sucessfully modified to use forward '
                         'policy "only"', zone['idnsname'][0])

    def update_global_ldap_forwarder(self):
        config = self.api.Command['dnsconfig_show'](all=True,
                                                    raw=True)['result']
        if (
            config.get('idnsforwardpolicy', [u'first'])[0] == u'first'
            and config.get('idnsforwarders', [])
        ):
            logger.info('Global forward policy in LDAP for all servers will '
                        'be changed to "only" to avoid conflicts with '
                        'automatic empty zones')
            self.backup_zone(config)
            self.api.Command['dnsconfig_mod'](idnsforwardpolicy=u'only')

    def execute(self, **options):
        # check LDAP if DNS subtree already uses new semantics
        if not self.version_update_needed(target_version=2):
            # forwardzones already use new semantics, no upgrade is required
            return False, []

        logger.debug('Updating forwarding policies in LDAP '
                     'to avoid conflicts with automatic empty zones')
        # update the DNSVersion, following upgrade can be executed only once
        self.api.Command['dnsconfig_mod'](ipadnsversion=2)

        self.update_zones()
        try:
            if dnsutil.has_empty_zone_addresses(self.api.env.host):
                self.update_global_ldap_forwarder()
        except dns.exception.DNSException as ex:
            logger.error('Skipping update of global DNS forwarder in LDAP: '
                         'Unable to determine if local server is using an '
                         'IP address belonging to an automatic empty zone. '
                         'Consider changing forwarding policy to "only". '
                         'DNS exception: %s', ex)

        return False, []


@register()
class update_dnsserver_configuration_into_ldap(DNSUpdater):
    """
    DNS Locations feature requires to have DNS configuration stored in LDAP DB.
    Create DNS server configuration in LDAP for each old server
    """
    def execute(self, **options):
        ldap = self.api.Backend.ldap2
        if sysupgrade.get_upgrade_state('dns', 'server_config_to_ldap'):
            logger.debug('upgrade is not needed')
            return False, []

        dns_container_dn = DN(self.api.env.container_dns, self.api.env.basedn)
        try:
            ldap.get_entry(dns_container_dn)
        except errors.NotFound:
            logger.debug('DNS container not found, nothing to upgrade')
            sysupgrade.set_upgrade_state('dns', 'server_config_to_ldap', True)
            return False, []

        result = self.api.Command.server_show(self.api.env.host)['result']
        if not 'DNS server' in result.get('enabled_role_servrole', []):
            logger.debug('This server is not DNS server, nothing to upgrade')
            sysupgrade.set_upgrade_state('dns', 'server_config_to_ldap', True)
            return False, []

        # create container first, if doesn't exist
        ensure_dnsserver_container_exists(ldap, self.api)

        try:
            self.api.Command.dnsserver_add(self.api.env.host)
        except errors.DuplicateEntry:
            logger.debug("DNS server configuration already exists "
                         "in LDAP database")
        else:
            logger.debug("DNS server configuration has been sucessfully "
                         "created in LDAP database")
        sysupgrade.set_upgrade_state('dns', 'server_config_to_ldap', True)
        return False, []
