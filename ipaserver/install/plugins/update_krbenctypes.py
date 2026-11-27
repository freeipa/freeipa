#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging

from ipalib import Registry
from ipalib import Updater
from ipalib import errors
from ipaplatform.tasks import tasks
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_krbenctypes(Updater):
    """
    Ensures that krbSupportedEncSaltTypes and krbDefaultEncSaltTypes
    are correct.
    """

    def execute(self, **options):
        dn = DN(('cn', self.api.env.realm), ('cn', 'kerberos'),
                self.api.env.basedn)

        ldap = self.api.Backend.ldap2
        try:
            realm_entry = ldap.get_entry(
                dn, ['krbsupportedencsalttypes', 'krbdefaultencsalttypes'])
        except errors.NotFound:
            logger.error("update_krbenctypes: no realm entry found. "
                         "Cannot update encryption types")
            return False, []

        updates = []
        for supported in tasks.get_supported_enctypes():
            updates.append(dict(
                action='add', attr='krbSupportedEncSaltTypes',
                value=supported
            ))
        for rm_supported in tasks.get_removed_supported_enctypes():
            updates.append(dict(
                action='remove', attr='krbSupportedEncSaltTypes',
                value=rm_supported
            ))
        for default in tasks.get_default_enctypes():
            updates.append(dict(
                action='add', attr='krbDefaultEncSaltTypes',
                value=default
            ))
        for rm_default in tasks.get_removed_default_enctypes():
            updates.append(dict(
                action='remove', attr='krbDefaultEncSaltTypes',
                value=rm_default
            ))

        # The plugin must also remove bad values resulting from bug
        # https://codeberg.org/freeipa/freeipa/issues/10131
        for val in realm_entry.get('krbSupportedEncSaltTypes'):
            if '\n' in val:
                updates.append(dict(
                    action='remove', attr='krbSupportedEncSaltTypes',
                    value=val
                ))

        update = {
            'dn': dn,
            'updates': updates,
        }

        return False, [update]
