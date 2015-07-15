#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipalib import api
from ipalib import Updater
from ipaserver.install import certs, cainstance
from ipaserver.install import ldapupdate
from ipaplatform.paths import paths


class update_ca_topology(Updater):
    """
    Updates CA topology configuration entries
    """

    def execute(self, **options):

        ca = cainstance.CAInstance(self.api.env.realm, certs.NSS_DIR)
        if not ca.is_configured():
            self.log.debug("CA is not configured on this host")
            return False, []

        ld = ldapupdate.LDAPUpdate(ldapi=True, sub_dict={
            'SUFFIX': self.api.env.basedn,
            'FQDN': self.api.env.host,
        })
        rv = ld.update([paths.CA_TOPOLOGY_ULDIF])
        if not rv:
            self.log.error("Failed to update CA topology configuration")

        return False, []

api.register(update_ca_topology)
