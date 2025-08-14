#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipalib import Registry
from ipalib import Updater
from ipaplatform.tasks import tasks
from ipapython.dn import DN

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

        update = {
            'dn': dn,
            'updates': updates,
        }

        return False, [update]
