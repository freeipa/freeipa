#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#
import logging
from ipalib import Registry, Updater, errors
from ipaserver.install import ldapupdate
from ipaplatform.paths import paths
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_subid_support(Updater):
    """
    Conditionally add SubID ranges when subID support is enabled
    """

    dna_plugin_dn = DN(
        ('cn', 'Distributed Numeric Assignment Plugin'),
        ('cn', 'plugins'),
        ('cn', 'config')
    )

    def execute(self, **options):
        subid_disabled = self.api.Object.config.is_config_option_present(
            'SubID:Disable')
        if not subid_disabled:
            ld = ldapupdate.LDAPUpdate(api=self.api)
            ld.update([paths.SUBID_GENERATORS_ULDIF])
        else:
            # make sure to remove DNA configuration
            conn = self.api.Backend.ldap2
            try:
                subid_dna_config = DN(
                    ('cn', 'Subordinate IDs'), self.dna_plugin_dn
                )
                entry = conn.get_entry(subid_dna_config)
                conn.delete_entry(entry)
            except errors.NotFound:
                pass

        return False, []
