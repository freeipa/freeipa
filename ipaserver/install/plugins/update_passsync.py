#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from ipaserver.install.plugins import MIDDLE, LAST
from ipaserver.install.plugins.baseupdate import PreUpdate, PostUpdate
from ipalib import api, errors
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger
from ipaserver.install import sysupgrade

class update_passync_privilege_check(PreUpdate):
    order = MIDDLE

    def execute(self, **options):
        update_done = sysupgrade.get_upgrade_state('winsync', 'passsync_privilege_updated')
        if update_done:
            root_logger.debug("PassSync privilege update pre-check not needed")
            return False, False, []

        root_logger.debug("Check if there is existing PassSync privilege")

        passsync_privilege_dn = DN(('cn','PassSync Service'),
                self.api.env.container_privilege,
                self.api.env.basedn)

        ldap = self.obj.backend
        try:
            ldap.get_entry(passsync_privilege_dn, [''])
        except errors.NotFound:
            root_logger.debug("PassSync privilege not found, this is a new update")
            sysupgrade.set_upgrade_state('winsync', 'passsync_privilege_updated', False)
        else:
            root_logger.debug("PassSync privilege found, skip updating PassSync")
            sysupgrade.set_upgrade_state('winsync', 'passsync_privilege_updated', True)

        return False, False, []

api.register(update_passync_privilege_check)

class update_passync_privilege_update(PostUpdate):
    """
        Add PassSync user as a member of PassSync privilege, if it exists
    """

    order = LAST

    def execute(self, **options):
        update_done = sysupgrade.get_upgrade_state('winsync', 'passsync_privilege_updated')
        if update_done:
            root_logger.debug("PassSync privilege update not needed")
            return False, False, []

        root_logger.debug("Add PassSync user as a member of PassSync privilege")
        ldap = self.obj.backend
        passsync_dn = DN(('uid','passsync'), ('cn', 'sysaccounts'), ('cn', 'etc'),
            api.env.basedn)
        passsync_privilege_dn = DN(('cn','PassSync Service'),
                self.api.env.container_privilege,
                self.api.env.basedn)

        try:
            entry = ldap.get_entry(passsync_dn, [''])
        except errors.NotFound:
            root_logger.debug("PassSync user not found, no update needed")
            sysupgrade.set_upgrade_state('winsync', 'passsync_privilege_updated', True)
            return False, False, []
        else:
            root_logger.debug("PassSync user found, do update")

        update = {'dn': passsync_privilege_dn,
                  'updates': ["add:member:'%s'" % passsync_dn]}
        updates = {passsync_privilege_dn: update}

        sysupgrade.set_upgrade_state('winsync', 'passsync_privilege_updated', True)
        return (False, True, [updates])

api.register(update_passync_privilege_update)
