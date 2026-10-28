#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging

from ipalib import errors
from ipalib import Registry
from ipalib import Updater
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()


@register()
class add_admin_krbcanonicalname(Updater):
    """
    Ensures that only the admin user has the krbCanonicalName of
    admin@$REALM.
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        search_filter = (
            "(krbcanonicalname=admin@{})".format(self.api.env.realm))
        try:
            (entries, _truncated) = ldap.find_entries(
                filter=search_filter, base_dn=self.api.env.basedn,
                time_limit=0, size_limit=0)
        except errors.EmptyResult:
            logger.debug("add_admin_krbcanonicalname: No user set with "
                         "admin krbcanonicalname")
            entries = []
            # fall through
        except errors.ExecutionError as e:
            logger.error("add_admin_krbcanonicalname: Can not get list "
                         "of krbcanonicalname: %s", e)
            return False, []

        admin_set = False
        # admin should be only user with admin@ as krbcanonicalname
        # It has a uniquness setting so there can be only one, we
        # just didn't automatically set it for admin.
        for entry in entries:
            if entry.single_value.get('uid') != 'admin':
                logger.critical(
                    "add_admin_krbcanonicalname: "
                    "entry %s has a krbcanonicalname of admin. Removing.",
                    entry.dn)
                del entry['krbcanonicalname']
                ldap.update_entry(entry)
            else:
                admin_set = True

        if not admin_set:
            dn = DN(
                ('uid', 'admin'),
                self.api.env.container_user,
                self.api.env.basedn)
            entry = ldap.get_entry(dn)
            entry['krbcanonicalname'] = 'admin@%s' % self.api.env.realm
            try:
                ldap.update_entry(entry)
            except errors.DuplicateEntry:
                logger.critical(
                    "add_admin_krbcanonicalname: "
                    "Failed to set krbcanonicalname on admin. It is set "
                    "on another entry.")
            except errors.ExecutionError as e:
                logger.critical(
                    "add_admin_krbcanonicalname: "
                    "Failed to set krbcanonicalname on admin: %s", e)

        return False, []
