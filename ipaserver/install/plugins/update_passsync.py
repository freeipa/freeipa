#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

import logging

from ipalib import Registry, errors
from ipalib import Updater
from ipapython.dn import DN
from ipaserver.install import sysupgrade

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_passync_privilege_check(Updater):

    def execute(self, **options):
        update_done = sysupgrade.get_upgrade_state('winsync', 'passsync_privilege_updated')
        if update_done:
            logger.debug("PassSync privilege update pre-check not needed")
            return False, []

        logger.debug("Check if there is existing PassSync privilege")

        passsync_privilege_dn = DN(('cn','PassSync Service'),
                self.api.env.container_privilege,
                self.api.env.basedn)

        ldap = self.api.Backend.ldap2
        try:
            ldap.get_entry(passsync_privilege_dn, [''])
        except errors.NotFound:
            logger.debug("PassSync privilege not found, this is a new update")
            sysupgrade.set_upgrade_state('winsync', 'passsync_privilege_updated', False)
        else:
            logger.debug("PassSync privilege found, skip updating PassSync")
            sysupgrade.set_upgrade_state('winsync', 'passsync_privilege_updated', True)

        return False, []


@register()
class update_passync_privilege_update(Updater):
    """
        Add PassSync user as a member of PassSync privilege, if it exists
    """

    def execute(self, **options):
        update_done = sysupgrade.get_upgrade_state('winsync', 'passsync_privilege_updated')
        if update_done:
            logger.debug("PassSync privilege update not needed")
            return False, []

        logger.debug("Add PassSync user as a member of PassSync privilege")
        ldap = self.api.Backend.ldap2
        passsync_dn = DN(('uid','passsync'), ('cn', 'sysaccounts'), ('cn', 'etc'),
            self.api.env.basedn)
        passsync_privilege_dn = DN(('cn','PassSync Service'),
                self.api.env.container_privilege,
                self.api.env.basedn)

        try:
            ldap.get_entry(passsync_dn, [''])
        except errors.NotFound:
            logger.debug("PassSync user not found, no update needed")
            sysupgrade.set_upgrade_state('winsync', 'passsync_privilege_updated', True)
            return False, []
        else:
            logger.debug("PassSync user found, do update")

        update = {'dn': passsync_privilege_dn,
                  'updates': [
                      dict(action='add', attr='member', value=passsync_dn),
                  ]
        }

        sysupgrade.set_upgrade_state('winsync', 'passsync_privilege_updated', True)
        return False, [update]
