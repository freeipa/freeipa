#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
import logging
from ipalib import Registry, errors
from ipalib import Updater
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_changelog_maxage(Updater):
    """
    Update the changelog maxage if it is not set
    """

    def update_entry(self, cl_entry, conn):
        maxage = cl_entry.single_value.get('nsslapd-changelogmaxage')
        if maxage is None:
            cl_entry['nsslapd-changelogmaxage'] = '7d'
            conn.update_entry(cl_entry)

    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        for backend in ('userroot', 'ipaca'):
            dn = DN(
                ('cn', 'changelog'),
                ('cn', backend),
                ('cn', 'ldbm database'),
                ('cn', 'plugins'),
                ('cn', 'config'))
            try:
                cl_entry = ldap.get_entry(dn, ['nsslapd-changelogmaxage'])
                self.update_entry(cl_entry, ldap)
            except errors.NotFound:
                # Try the old global changelog, and return
                dn = DN(
                    ('cn', 'changelog5'),
                    ('cn', 'config'))
                try:
                    cl_entry = ldap.get_entry(dn, ['nsslapd-changelogmaxage'])
                    self.update_entry(cl_entry, ldap)
                except errors.NotFound:
                    logger.debug('Error retrieving: %s', str(dn))
                return False, []

        return False, []
