# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2007-2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import os.path
import pwd
import tempfile
import optparse  # pylint: disable=deprecated-module

from ipalib.install import certmonger
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipapython import admintool, x509
from ipapython.certdb import (get_ca_nickname,
                              NSSDatabase,
                              verify_kdc_cert_validity)
from ipapython.dn import DN
from ipalib import api, errors
from ipaserver.install import certs, dsinstance, installutils, krbinstance


class ServerCertInstall(admintool.AdminTool):
    command_name = 'ipa-server-certinstall'

    usage = "%prog <-d|-w|-k> [options] <file> ..."

    description = "Install new SSL server certificates."

    @classmethod
    def add_options(cls, parser):
        super(ServerCertInstall, cls).add_options(parser)

        parser.add_option(
            "-d", "--dirsrv",
            dest="dirsrv", action="store_true", default=False,
            help="install certificate for the directory server")
        parser.add_option(
            "-w", "--http",
            dest="http", action="store_true", default=False,
            help="install certificate for the http server")
        parser.add_option(
            "-k", "--kdc",
            dest="kdc", action="store_true", default=False,
            help="install PKINIT certificate for the KDC")
        parser.add_option(
            "--pin",
            dest="pin", metavar="PIN", sensitive=True,
            help="The password of the PKCS#12 file")
        parser.add_option(
            "--dirsrv_pin", "--http_pin",
            dest="pin",
            help=optparse.SUPPRESS_HELP)
        parser.add_option(
            "--cert-name",
            dest="cert_name", metavar="NAME",
            help="Name of the certificate to install")
        parser.add_option(
            "-p", "--dirman-password",
            dest="dirman_password",
            help="Directory Manager password")

    def validate_options(self):
        super(ServerCertInstall, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        if not any((self.options.dirsrv, self.options.http, self.options.kdc)):
            self.option_parser.error(
                "you must specify dirsrv, http and/or kdc")

        if not self.args:
            self.option_parser.error("you must provide certificate filename")

    def ask_for_options(self):
        super(ServerCertInstall, self).ask_for_options()

        if not self.options.dirman_password:
            self.options.dirman_password = installutils.read_password(
                "Directory Manager", confirm=False, validate=False, retry=False)
            if self.options.dirman_password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

        if self.options.pin is None:
            self.options.pin = installutils.read_password(
                "Enter private key unlock",
                confirm=False, validate=False, retry=False)
            if self.options.pin is None:
                raise admintool.ScriptError(
                    "Private key unlock password required")

    def run(self):
        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        api.Backend.ldap2.connect(bind_pw=self.options.dirman_password)

        if self.options.dirsrv:
            self.install_dirsrv_cert()

        if self.options.http:
            self.install_http_cert()

        if self.options.kdc:
            self.install_kdc_cert()

        api.Backend.ldap2.disconnect()

    def install_dirsrv_cert(self):
        serverid = installutils.realm_to_serverid(api.env.realm)
        dirname = dsinstance.config_dirname(serverid)

        conn = api.Backend.ldap2
        entry = conn.get_entry(DN(('cn', 'RSA'), ('cn', 'encryption'),
                                  ('cn', 'config')),
                               ['nssslpersonalityssl'])
        old_cert = entry.single_value['nssslpersonalityssl']

        server_cert = self.import_cert(dirname, self.options.pin,
                                       old_cert, 'ldap/%s' % api.env.host,
                                       'restart_dirsrv %s' % serverid)

        entry['nssslpersonalityssl'] = [server_cert]
        try:
            conn.update_entry(entry)
        except errors.EmptyModlist:
            pass

    def install_http_cert(self):
        dirname = paths.HTTPD_ALIAS_DIR

        old_cert = installutils.get_directive(paths.HTTPD_NSS_CONF,
                                              'NSSNickname')

        unquoted_cert = installutils.unquote_directive_value(
            old_cert, quote_char="'")

        server_cert = self.import_cert(dirname, self.options.pin,
                                       unquoted_cert, 'HTTP/%s' % api.env.host,
                                       'restart_httpd')

        quoted_server_cert = installutils.quote_directive_value(
            server_cert, quote_char="'")
        installutils.set_directive(
            paths.HTTPD_NSS_CONF,
            'NSSNickname',
            quoted_server_cert,
            quotes=False)

        # Fix the database permissions
        os.chmod(os.path.join(dirname, 'cert8.db'), 0o640)
        os.chmod(os.path.join(dirname, 'key3.db'), 0o640)
        os.chmod(os.path.join(dirname, 'secmod.db'), 0o640)

        pent = pwd.getpwnam(constants.HTTPD_USER)
        os.chown(os.path.join(dirname, 'cert8.db'), 0, pent.pw_gid)
        os.chown(os.path.join(dirname, 'key3.db'), 0, pent.pw_gid)
        os.chown(os.path.join(dirname, 'secmod.db'), 0, pent.pw_gid)

    def install_kdc_cert(self):
        ca_cert_file = paths.CA_BUNDLE_PEM
        pkcs12_file, pin, ca_cert = installutils.load_pkcs12(
            cert_files=self.args,
            key_password=self.options.pin,
            key_nickname=self.options.cert_name,
            ca_cert_files=[ca_cert_file],
            realm_name=api.env.realm)

        cdb = certs.CertDB(api.env.realm, nssdir=paths.IPA_NSSDB_DIR)

        # Check that the ca_cert is known and trusted
        with tempfile.NamedTemporaryFile() as temp:
            certs.install_pem_from_p12(pkcs12_file.name, pin, temp.name)

            kdc_cert = x509.load_certificate_from_file(temp.name)
            ca_certs = x509.load_certificate_list_from_file(ca_cert_file)

            try:
                verify_kdc_cert_validity(kdc_cert, ca_certs, api.env.realm)
            except ValueError as e:
                raise admintool.ScriptError(
                    "Peer's certificate issuer is not trusted (%s). "
                    "Please run ipa-cacert-manage install and ipa-certupdate "
                    "to install the CA certificate." % str(e))

        try:
            ca_enabled = api.Command.ca_is_enabled()['result']
            if ca_enabled:
                certmonger.stop_tracking(certfile=paths.KDC_CERT)

            certs.install_pem_from_p12(pkcs12_file.name, pin, paths.KDC_CERT)
            certs.install_key_from_p12(pkcs12_file.name, pin, paths.KDC_KEY)

            if ca_enabled:
                # Start tracking only if the cert was issued by IPA CA
                # Retrieve IPA CA
                ipa_ca_cert = cdb.get_cert_from_db(
                    get_ca_nickname(api.env.realm))
                # And compare with the CA which signed this certificate
                if ca_cert == ipa_ca_cert:
                    certmonger.start_tracking(
                        (paths.KDC_CERT, paths.KDC_KEY),
                        storage='FILE',
                        profile='KDCs_PKINIT_Certs')
        except RuntimeError as e:
            raise admintool.ScriptError(str(e))

        krb = krbinstance.KrbInstance()
        krb.init_info(
            realm_name=api.env.realm,
            host_name=api.env.host,
        )
        krb.pkinit_enable()

    def check_chain(self, pkcs12_filename, pkcs12_pin, nssdb):
        # create a temp nssdb
        with NSSDatabase() as tempnssdb:
            tempnssdb.create_db()

            # import the PKCS12 file, then delete all CA certificates
            # this leaves only the server certs in the temp db
            tempnssdb.import_pkcs12(pkcs12_filename, pkcs12_pin)
            for nickname, flags in tempnssdb.list_certs():
                if not flags.has_key:
                    while tempnssdb.has_nickname(nickname):
                        tempnssdb.delete_cert(nickname)

            # import all the CA certs from nssdb into the temp db
            for nickname, flags in nssdb.list_certs():
                if not flags.has_key:
                    cert = nssdb.get_cert_from_db(nickname)
                    tempnssdb.add_cert(cert, nickname, flags)

            # now get the server certs from tempnssdb and check their validity
            try:
                for nick, flags in tempnssdb.find_server_certs():
                    tempnssdb.verify_server_cert_validity(nick, api.env.host)
            except ValueError as e:
                raise admintool.ScriptError(
                    "Peer's certificate issuer is not trusted (%s). "
                    "Please run ipa-cacert-manage install and ipa-certupdate "
                    "to install the CA certificate." % str(e))

    def import_cert(self, dirname, pkcs12_passwd, old_cert, principal, command):
        pkcs12_file, pin, ca_cert = installutils.load_pkcs12(
            cert_files=self.args,
            key_password=pkcs12_passwd,
            key_nickname=self.options.cert_name,
            ca_cert_files=[paths.IPA_CA_CRT],
            host_name=api.env.host)

        dirname = os.path.normpath(dirname)
        cdb = certs.CertDB(api.env.realm, nssdir=dirname)

        # Check that the ca_cert is known and trusted
        self.check_chain(pkcs12_file.name, pin, cdb)

        try:
            ca_enabled = api.Command.ca_is_enabled()['result']
            if ca_enabled:
                cdb.untrack_server_cert(old_cert)

            cdb.delete_cert(old_cert)
            prevs = cdb.find_server_certs()
            cdb.import_pkcs12(pkcs12_file.name, pin)
            news = cdb.find_server_certs()
            server_certs = [item for item in news if item not in prevs]
            server_cert = server_certs[0][0]

            if ca_enabled:
                # Start tracking only if the cert was issued by IPA CA
                # Retrieve IPA CA
                ipa_ca_cert = cdb.get_cert_from_db(
                    get_ca_nickname(api.env.realm))
                # And compare with the CA which signed this certificate
                if ca_cert == ipa_ca_cert:
                    cdb.track_server_cert(server_cert,
                                          principal,
                                          cdb.passwd_fname,
                                          command)
        except RuntimeError as e:
            raise admintool.ScriptError(str(e))

        return server_cert
