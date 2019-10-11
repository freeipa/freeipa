#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

import logging

from ipalib import Registry, Updater, x509
from ipapython.dn import DN
from ipaplatform.paths import paths
from ipaserver.install import krainstance

logger = logging.getLogger(__name__)

register = Registry()


@register()
class fix_kra_people_entry(Updater):
    """
    Update the KRA uid=ipakra agent user entry.

    There was a bug where this was created with an incorrect
    'description' attribute, breaking authentication:
    https://pagure.io/freeipa/issue/8084.

    """
    def execute(self, **options):
        kra = krainstance.KRAInstance(self.api.env.realm)
        if not kra.is_installed():
            return False, []

        cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
        entry = self.api.Backend.ldap2.get_entry(krainstance.KRA_AGENT_DN)

        # check description attribute
        description_values = entry.get('description', [])
        if len(description_values) < 1:
            # missing 'description' attribute is unexpected, but we can
            # add it
            do_fix = True
        else:
            # There should only be one value, so we will take the first value.
            # But ignore the serial number when comparing, just in case.
            description = description_values[0]
            parts = description.split(';', 2)  # see below for syntax

            if len(parts) < 3:
                do_fix = True  # syntax error (not expected)
            elif parts[2] != '{};{}'.format(DN(cert.issuer), DN(cert.subject)):
                # issuer/subject does not match cert.  THIS is the condition
                # caused by issue 8084, which we want to fix.
                do_fix = True
            else:
                do_fix = False  # everything is fine

        if do_fix:
            # If other replicas have a different iteration of the IPA RA
            # cert (e.g. renewal was triggered prematurely on some master
            # and not on others) then authentication on those replicas will
            # fail.  But the 'description' attribute needed fixing because
            # the issuer value was wrong, meaning authentication was broken
            # on ALL replicas.  So even for the corner case where different
            # replicas have different IPA RA certs, updating the attribute
            # will at least mean THIS replica can authenticate to the KRA.

            logger.debug("Fixing KRA user entry 'description' attribute")
            entry['description'] = [
                '2;{};{};{}'.format(
                    cert.serial_number,
                    DN(cert.issuer),
                    DN(cert.subject)
                )
            ]
            self.api.Backend.ldap2.update_entry(entry)

        return False, []  # don't restart DS; no LDAP updates to perform
