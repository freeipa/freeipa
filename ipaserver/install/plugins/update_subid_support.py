#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
import logging
from ipalib import Registry
from ipalib import Updater
from ipaserver.install import ldapupdate
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_subid_support(Updater):
    """
    Conditionally add SubID ranges when subID support is enabled
    """

    def execute(self, **options):
        subid_disabled = self.api.Object.config.is_config_option_present(
            'SubID:Disable')
        if not subid_disabled:
            ld = ldapupdate.LDAPUpdate(api=self.api)
            ld.update([paths.SUBID_GENERATORS_ULDIF])

        return False, []
