#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging
import os
import tempfile

from ipalib import Registry
from ipalib import Updater
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipapython.certdb import NSSDatabase
from ipaserver.install import cainstance

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_ra_cert_store(Updater):
    """
    Moves the ipaCert store from /etc/httpd/alias RA_AGENT_PEM, RA_AGENT_KEY
    files
    """

    def execute(self, **options):
        ra_nick = 'ipaCert'
        ca_enabled = self.api.Command.ca_is_enabled()['result']
        if not ca_enabled:
            return False, []

        certdb = NSSDatabase(nssdir=paths.HTTPD_ALIAS_DIR)
        if not certdb.has_nickname(ra_nick):
            # Nothign to do
            return False, []
        elif os.path.exists(paths.RA_AGENT_PEM):
            # even though the certificate file exists, we will overwrite it
            # as it's probabably something wrong anyway
            logger.warning(
                "A certificate with the nickname 'ipaCert' exists in "
                "the old '%s' NSS database as well as in the new "
                "PEM file '%s'",
                paths.HTTPD_ALIAS_DIR, paths.RA_AGENT_PEM)

        _fd, p12file = tempfile.mkstemp(dir=certdb.secdir)
        # no password is necessary as we will be saving it in clear anyway
        certdb.export_pkcs12(ra_nick, p12file, pkcs12_passwd='')

        # stop tracking the old cert and remove it
        certmonger.stop_tracking(paths.HTTPD_ALIAS_DIR, nickname=ra_nick)
        certdb.delete_key_and_cert(ra_nick)
        if os.path.exists(paths.OLD_KRA_AGENT_PEM):
            os.remove(paths.OLD_KRA_AGENT_PEM)

        # get the private key and certificate from the file and start
        # tracking it in certmonger
        ca = cainstance.CAInstance()
        ca.import_ra_cert(p12file)

        os.remove(p12file)

        return False, []
