#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import binascii
import os

from ipalib import Registry
from ipalib import Updater
from ipalib.install import certmonger
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipapython import certdb

register = Registry()


@register()
class update_ra_cert_store(Updater):
    """
    Moves the cert store from /etc/httpd/alias to /var/lib/ipa/radb
    """

    def execute(self, **options):
        olddb = certdb.NSSDatabase(nssdir=paths.HTTPD_ALIAS_DIR)
        if not olddb.has_nickname('ipaCert'):
            # Nothign to do
            return False, []

        newdb = certdb.NSSDatabase(nssdir=paths.IPA_RADB_DIR)
        if os.path.exists(paths.IPA_RADB_DIR):
            if newdb.has_nickname('ipaCert'):
                self.log.warning(
                    "An 'ipaCert' nickname exists in both the old {} and the "
                    "new {} NSS Databases!".format(paths.HTTPD_ALIAS_DIR,
                                                   paths.IPA_RADB_DIR))
                return False, []
        else:
            # Create the DB
            newdb.create_db(os.path.join(paths.IPA_RADB_DIR, 'pwdfile.txt'),
                            user=constants.HTTPD_USER,
                            group=constants.HTTPD_GROUP,
                            mode=0o751, backup=True)

        # Import cert chain (ignore errors, as certs may already be imported)
        certlist = olddb.list_certs()
        certflags = {}
        for name, flags in certlist:
            certflags[name] = flags
        for name in olddb.get_trust_chain('ipaCert'):
            if name == 'ipaCert':
                continue
            try:
                cert = olddb.get_cert(name, pem=True)
                newdb.add_cert(cert, name, certflags[name], pem=True)
            except Exception as e:  # pylint disable=broad-except
                self.log.warning("Failed to import '{}' from trust "
                                 "chain: {}".format(name, str(e)))

        # As the last step export/import/delete the RA Cert
        ipa_httpd_pwdfile = os.path.join(paths.HTTPD_ALIAS_DIR, 'pwdfile.txt')
        ipa_radb_pwdfile = os.path.join(paths.IPA_RADB_DIR, 'pwdfile.txt')
        pw = binascii.hexlify(os.urandom(10))
        p12file = os.path.join(paths.IPA_RADB_DIR, 'ipaCert.p12')
        olddb.export_pkcs12('ipaCert', p12file, ipa_httpd_pwdfile, pw)
        newdb.import_pkcs12(p12file, ipa_radb_pwdfile, pw)

        certmonger.stop_tracking(secdir=olddb.secdir,
                                 nickname='ipaCert')
        certmonger.start_tracking(secdir=newdb.secdir,
                                  nickname='ipaCert',
                                  password_file=ipa_radb_pwdfile)

        olddb.delete_cert('ipaCert')

        return False, []
