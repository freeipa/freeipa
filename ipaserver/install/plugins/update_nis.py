#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging

from ipalib.plugable import Registry
from ipalib import errors
from ipalib import Updater
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipaserver.install import sysupgrade
from ipaserver.install.ldapupdate import LDAPUpdate

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_nis_configuration(Updater):
    """Update NIS configuration

    NIS configuration can be updated only if NIS Server was configured via
    ipa-nis-manage command.
    """

    def __recover_from_missing_maps(self, ldap):
        # https://fedorahosted.org/freeipa/ticket/5507
        # if all following DNs are missing, but 'NIS Server' container exists
        # we are experiencig bug and maps should be fixed

        if sysupgrade.get_upgrade_state('nis',
                                        'done_recover_from_missing_maps'):
            # this recover must be done only once, a user may deleted some
            # maps, we do not want to restore them again
            return

        logger.debug("Recovering from missing NIS maps bug")

        suffix = "cn=NIS Server,cn=plugins,cn=config"
        domain = self.api.env.domain
        missing_dn_list = [
            DN(nis_map.format(domain=domain, suffix=suffix)) for nis_map in [
                "nis-domain={domain}+nis-map=passwd.byname,{suffix}",
                "nis-domain={domain}+nis-map=passwd.byuid,{suffix}",
                "nis-domain={domain}+nis-map=group.byname,{suffix}",
                "nis-domain={domain}+nis-map=group.bygid,{suffix}",
                "nis-domain={domain}+nis-map=netid.byname,{suffix}",
                "nis-domain={domain}+nis-map=netgroup,{suffix}",
            ]
        ]

        for dn in missing_dn_list:
            try:
                ldap.get_entry(dn, attrs_list=['cn'])
            except errors.NotFound:
                pass
            else:
                # bug is not effective, at least one of 'possible missing'
                # maps was detected
                return

        sysupgrade.set_upgrade_state('nis', 'done_recover_from_missing_maps',
                                     True)

        # bug is effective run update to recreate missing maps
        ld = LDAPUpdate(sub_dict={}, ldapi=True)
        ld.update([paths.NIS_ULDIF])

    def execute(self, **options):
        ldap = self.api.Backend.ldap2
        dn = DN(('cn', 'NIS Server'), ('cn', 'plugins'), ('cn', 'config'))
        try:
            ldap.get_entry(dn, attrs_list=['cn'])
        except errors.NotFound:
            # NIS is not configured on system, do not execute update
            logger.debug("Skipping NIS update, NIS Server is not configured")

            # container does not exist, bug #5507 is not effective
            sysupgrade.set_upgrade_state(
                'nis', 'done_recover_from_missing_maps', True)
        else:
            self.__recover_from_missing_maps(ldap)

            logger.debug("Executing NIS Server update")
            ld = LDAPUpdate(sub_dict={}, ldapi=True)
            ld.update([paths.NIS_UPDATE_ULDIF])

        return False, ()
