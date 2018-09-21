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

import logging

from ipalib import Registry, errors
from ipalib import Updater
from ipapython.dn import DN
from ipaserver.install import sysupgrade
from ipaserver.install.adtrustinstance import (
    ADTRUSTInstance, map_Guests_to_nobody)

logger = logging.getLogger(__name__)

register = Registry()

DEFAULT_ID_RANGE_SIZE = 200000


@register()
class update_default_range(Updater):
    """
    Create default ID range for upgraded servers.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        dn = DN(self.api.env.container_ranges, self.api.env.basedn)
        search_filter = "objectclass=ipaDomainIDRange"
        try:
            ldap.find_entries(search_filter, [], dn)
        except errors.NotFound:
            pass
        else:
            logger.debug("default_range: ipaDomainIDRange entry found, skip "
                         "plugin")
            return False, []

        dn = DN(('cn', 'admins'), self.api.env.container_group,
                self.api.env.basedn)
        try:
            admins_entry = ldap.get_entry(dn, ['gidnumber'])
        except errors.NotFound:
            logger.error("default_range: No local ID range and no admins "
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
            (entries, _truncated) = ldap.find_entries(search_filter, attrs, dn)
        except errors.NotFound:
            logger.warning("default_range: no dnaSharedConfig object found. "
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
                    logger.warning("default_range: could not parse "
                                   "remaining values from '%s'",
                                   remaining_values)
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

                logger.error("default_range: %s", "\n".join(msg))

        return False, [update]


@register()
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
            logger.debug('AD Trusts are not enabled on this server')
            return False, []

        # Second, make sure the Default Trust View does not exist yet
        try:
            ldap.get_entry(default_trust_view_dn)
        except errors.NotFound:
            pass
        else:
            logger.debug('Default Trust View already present on this server')
            return False, []

        # We have a server with AD trust support without Default Trust View.
        # Create the Default Trust View entry.

        update = {
            'dn': default_trust_view_dn,
            'default': default_trust_view_entry
        }

        return False, [update]


@register()
class update_sigden_extdom_broken_config(Updater):
    """Fix configuration of sidgen and extdom plugins

    Upgrade to IPA 4.2+ cause that sidgen and extdom plugins have improperly
    configured basedn.

    All trusts which have been added when config was broken must to be
    re-added manually.

    https://fedorahosted.org/freeipa/ticket/5665
    """

    sidgen_config_dn = DN("cn=IPA SIDGEN,cn=plugins,cn=config")
    extdom_config_dn = DN("cn=ipa_extdom_extop,cn=plugins,cn=config")

    def _fix_config(self):
        """Due upgrade error configuration of sidgen and extdom plugins may
        contain literally "$SUFFIX" value instead of real DN in nsslapd-basedn
        attribute

        :return: True if config was fixed, False if fix is not needed
        """
        ldap = self.api.Backend.ldap2
        basedn_attr = 'nsslapd-basedn'
        modified = False

        for dn in (self.sidgen_config_dn, self.extdom_config_dn):
            try:
                entry = ldap.get_entry(dn, attrs_list=[basedn_attr])
            except errors.NotFound:
                logger.debug("configuration for %s not found, skipping", dn)
            else:
                configured_suffix = entry.single_value.get(basedn_attr)
                if configured_suffix is None:
                    raise RuntimeError(
                        "Missing attribute {attr} in {dn}".format(
                            attr=basedn_attr, dn=dn
                        )
                    )
                elif configured_suffix == "$SUFFIX":
                    # configured value is wrong, fix it
                    entry.single_value[basedn_attr] = str(self.api.env.basedn)
                    logger.debug("updating attribute %s of %s to correct "
                                 "value %s",
                                 basedn_attr, dn, self.api.env.basedn)
                    ldap.update_entry(entry)
                    modified = True
                else:
                    logger.debug("configured basedn for %s is okay", dn)

        return modified

    def execute(self, **options):
        if sysupgrade.get_upgrade_state('sidgen', 'config_basedn_updated'):
            logger.debug("Already done, skipping")
            return False, ()

        restart = False
        if self._fix_config():
            sysupgrade.set_upgrade_state('sidgen', 'update_sids', True)
            restart = True  # DS has to be restarted to apply changes

        sysupgrade.set_upgrade_state('sidgen', 'config_basedn_updated', True)
        return restart, ()


@register()
class update_sids(Updater):
    """SIDs may be not created properly if bug with wrong configuration for
    sidgen and extdom plugins is effective

    This must be run after "update_sigden_extdom_broken_config"
    https://fedorahosted.org/freeipa/ticket/5665
    """
    sidgen_config_dn = DN("cn=IPA SIDGEN,cn=plugins,cn=config")

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        if sysupgrade.get_upgrade_state('sidgen', 'update_sids') is not True:
            logger.debug("SIDs do not need to be generated")
            return False, ()

        # check if IPA domain for AD trust has been created, and if we need to
        # regenerate missing SIDs if attribute 'ipaNTSecurityIdentifier'
        domain_IPA_AD_dn = DN(
            ('cn', self.api.env.domain),
            self.api.env.container_cifsdomains,
            self.api.env.basedn)
        attr_name = 'ipaNTSecurityIdentifier'

        try:
            entry = ldap.get_entry(domain_IPA_AD_dn, attrs_list=[attr_name])
        except errors.NotFound:
            logger.debug("IPA domain object %s is not configured",
                         domain_IPA_AD_dn)
            sysupgrade.set_upgrade_state('sidgen', 'update_sids', False)
            return False, ()
        else:
            if not entry.single_value.get(attr_name):
                # we need to run sidgen task
                sidgen_task_dn = DN(
                    "cn=generate domain sid,cn=ipa-sidgen-task,cn=tasks,"
                    "cn=config")
                sidgen_tasks_attr = {
                    "objectclass": ["top", "extensibleObject"],
                    "cn": ["sidgen"],
                    "delay": [0],
                    "nsslapd-basedn": [self.api.env.basedn],
                }

                task_entry = ldap.make_entry(sidgen_task_dn,
                                             **sidgen_tasks_attr)
                try:
                    ldap.add_entry(task_entry)
                except errors.DuplicateEntry:
                    logger.debug("sidgen task already created")
                else:
                    logger.debug("sidgen task has been created")

        # we have to check all trusts domains which may been affected by the
        # bug. Symptom is missing 'ipaNTSecurityIdentifier' attribute

        base_dn = DN(self.api.env.container_adtrusts, self.api.env.basedn)
        try:
            trust_domain_entries, truncated = ldap.find_entries(
                base_dn=base_dn,
                scope=ldap.SCOPE_ONELEVEL,
                attrs_list=["cn"],
                # more types of trusts can be stored under cn=trusts, we need
                # the type with ipaNTTrustPartner attribute
                filter="(&(ipaNTTrustPartner=*)(!(%s=*)))" % attr_name
            )
        except errors.NotFound:
            pass
        else:
            if truncated:
                logger.warning("update_sids: Search results were truncated")

            for entry in trust_domain_entries:
                domain = entry.single_value["cn"]
                logger.error(
                    "Your trust to %s is broken. Please re-create it by "
                    "running 'ipa trust-add' again.", domain)

        sysupgrade.set_upgrade_state('sidgen', 'update_sids', False)
        return False, ()


@register()
class update_tdo_gidnumber(Updater):
    """
    Create a gidNumber attribute for Trusted Domain Objects.

    The value is taken from the fallback group defined in cn=Default SMB Group.
    """
    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        # First, see if trusts are enabled on the server
        if not self.api.Command.adtrust_is_enabled()['result']:
            logger.debug('AD Trusts are not enabled on this server')
            return False, []

        # Read the gidnumber of the fallback group
        dn = DN(('cn', ADTRUSTInstance.FALLBACK_GROUP_NAME),
                self.api.env.container_group,
                self.api.env.basedn)

        try:
            entry = ldap.get_entry(dn, ['gidnumber'])
            gidNumber = entry.get('gidnumber')
        except errors.NotFound:
            logger.error("%s not found",
                         ADTRUSTInstance.FALLBACK_GROUP_NAME)
            return False, ()

        if not gidNumber:
            logger.error("%s does not have a gidnumber",
                         ADTRUSTInstance.FALLBACK_GROUP_NAME)
            return False, ()

        # For each trusted domain object, add gidNumber
        try:
            tdos = ldap.get_entries(
                DN(self.api.env.container_adtrusts, self.api.env.basedn),
                scope=ldap.SCOPE_ONELEVEL,
                filter="(objectclass=ipaNTTrustedDomain)",
                attrs_list=['gidnumber'])
            for tdo in tdos:
                # if the trusted domain object does not contain gidnumber,
                # add the default fallback group gidnumber
                if not tdo.get('gidnumber'):
                    try:
                        tdo['gidnumber'] = gidNumber
                        ldap.update_entry(tdo)
                        logger.debug("Added gidnumber %s to %s",
                                     gidNumber, tdo.dn)
                    except Exception:
                        logger.warning(
                            "Failed to add gidnumber to %s", tdo.dn)

        except errors.NotFound:
            logger.debug("No trusted domain object to update")
            return False, ()

        return False, ()


@register()
class update_mapping_Guests_to_nobody(Updater):
    """
    Map BUILTIN\\Guests group to nobody

    Samba 4.9 became more strict on availability of builtin Guests group
    """
    def execute(self, **options):
        # First, see if trusts are enabled on the server
        if not self.api.Command.adtrust_is_enabled()['result']:
            logger.debug('AD Trusts are not enabled on this server')
            return False, []

        map_Guests_to_nobody()
        return False, []
