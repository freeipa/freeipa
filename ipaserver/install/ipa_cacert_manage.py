# Authors: Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2014  Red Hat
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
import time
from optparse import OptionGroup
import base64
from nss import nss
from nss.error import NSPRError
import krbV

from ipapython import admintool, certmonger, ipautil
from ipapython.dn import DN
from ipaplatform.paths import paths
from ipalib import api, errors, x509, certstore
from ipaserver.install import certs, cainstance, installutils
from ipaserver.plugins.ldap2 import ldap2


class CACertManage(admintool.AdminTool):
    command_name = 'ipa-cacert-manage'

    usage = "%prog {renew|install} [options]"

    description = "Manage CA certificates."

    cert_nickname = 'caSigningCert cert-pki-ca'

    @classmethod
    def add_options(cls, parser):
        super(CACertManage, cls).add_options(parser)

        parser.add_option(
            "-p", "--password", dest='password',
            help="Directory Manager password")

        renew_group = OptionGroup(parser, "Renew options")
        renew_group.add_option(
            "--self-signed", dest='self_signed',
            action='store_true',
            help="Sign the renewed certificate by itself")
        renew_group.add_option(
            "--external-ca", dest='self_signed',
            action='store_false',
            help="Sign the renewed certificate by external CA")
        renew_group.add_option(
            "--external-cert-file", dest="external_cert_files",
            action="append", metavar="FILE",
            help="File containing the IPA CA certificate and the external CA "
                 "certificate chain")
        parser.add_option_group(renew_group)

        install_group = OptionGroup(parser, "Install options")
        install_group.add_option(
            "-n", "--nickname", dest='nickname',
            help="Nickname for the certificate")
        install_group.add_option(
            "-t", "--trust-flags", dest='trust_flags', default='C,,',
            help="Trust flags for the certificate in certutil format")
        parser.add_option_group(install_group)

    def validate_options(self):
        super(CACertManage, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        parser = self.option_parser

        if not self.args:
            parser.error("command not provided")

        command = self.command = self.args[0]
        options = self.options

        if command == 'renew':
            pass
        elif command == 'install':
            if len(self.args) < 2:
                parser.error("certificate file name not provided")
        else:
            parser.error("unknown command \"%s\"" % command)

    def run(self):
        command = self.command
        options = self.options

        api.bootstrap(in_server=True)
        api.finalize()

        if ((command == 'renew' and options.external_cert_files) or
            command == 'install'):
            self.conn = self.ldap_connect()
        else:
            self.conn = None

        try:
            if command == 'renew':
                rc = self.renew()
            elif command == 'install':
                rc = self.install()
        finally:
            if self.conn is not None:
                self.conn.disconnect()

        return rc

    def ldap_connect(self):
        conn = ldap2(api)

        password = self.options.password
        if not password:
            try:
                ccache = krbV.default_context().default_ccache()
                conn.connect(ccache=ccache)
            except (krbV.Krb5Error, errors.ACIError):
                pass
            else:
                return conn

            password = installutils.read_password(
                "Directory Manager", confirm=False, validate=False)
            if password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

        conn.connect(bind_dn=DN(('cn', 'Directory Manager')), bind_pw=password)

        return conn

    def renew(self):
        ca = cainstance.CAInstance(api.env.realm, certs.NSS_DIR)
        if not ca.is_configured():
            raise admintool.ScriptError("CA is not configured on this system")

        nss_dir = ca.dogtag_constants.ALIAS_DIR
        criteria = {
            'cert-database': nss_dir,
            'cert-nickname': self.cert_nickname,
            'ca-name': 'dogtag-ipa-ca-renew-agent',
        }
        self.request_id = certmonger.get_request_id(criteria)
        if self.request_id is None:
            raise admintool.ScriptError(
                "CA certificate is not tracked by certmonger")
        self.log.debug(
            "Found certmonger request id %r", self.request_id)

        db = certs.CertDB(api.env.realm, nssdir=nss_dir)
        cert = db.get_cert_from_db(self.cert_nickname, pem=False)

        options = self.options
        if options.external_cert_files:
            return self.renew_external_step_2(ca, cert)

        if options.self_signed is not None:
            self_signed = options.self_signed
        else:
            self_signed = x509.is_self_signed(cert, x509.DER)

        if self_signed:
            return self.renew_self_signed(ca)
        else:
            return self.renew_external_step_1(ca)

    def renew_self_signed(self, ca):
        print "Renewing CA certificate, please wait"

        try:
            ca.set_renewal_master()
        except errors.NotFound:
            raise admintool.ScriptError("CA renewal master not found")

        self.resubmit_request(ca, 'caCACert')

        print "CA certificate successfully renewed"

    def renew_external_step_1(self, ca):
        print "Exporting CA certificate signing request, please wait"

        self.resubmit_request(ca, 'ipaCSRExport')

        print("The next step is to get %s signed by your CA and re-run "
              "ipa-cacert-manage as:" % paths.IPA_CA_CSR)
        print("ipa-cacert-manage renew "
              "--external-cert-file=/path/to/signed_certificate "
              "--external-cert-file=/path/to/external_ca_certificate")

    def renew_external_step_2(self, ca, old_cert):
        print "Importing the renewed CA certificate, please wait"

        options = self.options
        cert_file, ca_file = installutils.load_external_cert(
            options.external_cert_files, x509.subject_base())

        nss_cert = None
        nss.nss_init(ca.dogtag_constants.ALIAS_DIR)
        try:
            nss_cert = x509.load_certificate(old_cert, x509.DER)
            subject = nss_cert.subject
            der_subject = x509.get_der_subject(old_cert, x509.DER)
            #pylint: disable=E1101
            pkinfo = nss_cert.subject_public_key_info.format()
            #pylint: enable=E1101

            nss_cert = x509.load_certificate_from_file(cert_file.name)
            cert = nss_cert.der_data
            if nss_cert.subject != subject:
                raise admintool.ScriptError(
                    "Subject name mismatch (visit "
                    "http://www.freeipa.org/page/Troubleshooting for "
                    "troubleshooting guide)")
            if x509.get_der_subject(cert, x509.DER) != der_subject:
                raise admintool.ScriptError(
                    "Subject name encoding mismatch (visit "
                    "http://www.freeipa.org/page/Troubleshooting for "
                    "troubleshooting guide)")
            #pylint: disable=E1101
            if nss_cert.subject_public_key_info.format() != pkinfo:
                raise admintool.ScriptError(
                    "Subject public key info mismatch (visit "
                    "http://www.freeipa.org/page/Troubleshooting for "
                    "troubleshooting guide)")
            #pylint: enable=E1101
        finally:
            del nss_cert
            nss.nss_shutdown()

        with certs.NSSDatabase() as tmpdb:
            pw = ipautil.write_tmp_file(ipautil.ipa_generate_password())
            tmpdb.create_db(pw.name)
            tmpdb.add_cert(old_cert, 'IPA CA', 'C,,')

            try:
                tmpdb.add_cert(cert, 'IPA CA', 'C,,')
            except ipautil.CalledProcessError, e:
                raise admintool.ScriptError(
                    "Not compatible with the current CA certificate: %s" % e)

            ca_certs = x509.load_certificate_list_from_file(ca_file.name)
            for ca_cert in ca_certs:
                tmpdb.add_cert(ca_cert.der_data, str(ca_cert.subject), 'C,,')
            del ca_certs
            del ca_cert

            try:
                tmpdb.verify_ca_cert_validity('IPA CA')
            except ValueError, e:
                raise admintool.ScriptError(
                    "Not a valid CA certificate: %s (visit "
                    "http://www.freeipa.org/page/Troubleshooting for "
                    "troubleshooting guide)" % e)

            trust_chain = tmpdb.get_trust_chain('IPA CA')[:-1]
            for nickname in trust_chain:
                try:
                    ca_cert = tmpdb.get_cert(nickname)
                except RuntimeError:
                    break
                certstore.put_ca_cert_nss(
                    self.conn, api.env.basedn, ca_cert, nickname, ',,')

        dn = DN(('cn', self.cert_nickname), ('cn', 'ca_renewal'),
                ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
        try:
            entry = self.conn.get_entry(dn, ['usercertificate'])
            entry['usercertificate'] = [cert]
            self.conn.update_entry(entry)
        except errors.NotFound:
            entry = self.conn.make_entry(
                dn,
                objectclass=['top', 'pkiuser', 'nscontainer'],
                cn=[self.cert_nickname],
                usercertificate=[cert])
            self.conn.add_entry(entry)
        except errors.EmptyModlist:
            pass

        try:
            ca.set_renewal_master()
        except errors.NotFound:
            raise admintool.ScriptError("CA renewal master not found")

        self.resubmit_request(ca, 'ipaRetrieval')

        print "CA certificate successfully renewed"

    def resubmit_request(self, ca, profile):
        timeout = api.env.startup_timeout + 60

        self.log.debug("resubmitting certmonger request '%s'", self.request_id)
        certmonger.resubmit_request(self.request_id, profile=profile)
        try:
            state = certmonger.wait_for_request(self.request_id, timeout)
        except RuntimeError:
            raise admintool.ScriptError(
                "Resubmitting certmonger request '%s' timed out, "
                "please check the request manually" % self.request_id)
        ca_error = certmonger.get_request_value(self.request_id, 'ca-error')
        if state != 'MONITORING' or ca_error:
            raise admintool.ScriptError(
                "Error resubmitting certmonger request '%s', "
                "please check the request manually" % self.request_id)

        self.log.debug("modifying certmonger request '%s'", self.request_id)
        certmonger.modify(self.request_id, profile='ipaCACertRenewal')

    def install(self):
        print "Installing CA certificate, please wait"

        options = self.options
        cert_filename = self.args[1]

        nss_cert = None
        try:
            try:
                nss_cert = x509.load_certificate_from_file(cert_filename)
            except IOError, e:
                raise admintool.ScriptError(
                    "Can't open \"%s\": %s" % (cert_filename, e))
            except (TypeError, NSPRError), e:
                raise admintool.ScriptError("Not a valid certificate: %s" % e)
            subject = nss_cert.subject
            cert = nss_cert.der_data
        finally:
            del nss_cert

        nickname = options.nickname or str(subject)

        with certs.NSSDatabase() as tmpdb:
            pw = ipautil.write_tmp_file(ipautil.ipa_generate_password())
            tmpdb.create_db(pw.name)
            tmpdb.add_cert(cert, nickname, 'C,,')

            try:
                tmpdb.verify_ca_cert_validity(nickname)
            except ValueError, e:
                raise admintool.ScriptError(
                    "Not a valid CA certificate: %s (visit "
                    "http://www.freeipa.org/page/Troubleshooting for "
                    "troubleshooting guide)" % e)

        trust_flags = options.trust_flags
        if ((set(trust_flags) - set(',CPTcgpuw')) or
            len(trust_flags.split(',')) != 3):
            raise admintool.ScriptError("Invalid trust flags")

        try:
            certstore.put_ca_cert_nss(
                self.conn, api.env.basedn, cert, nickname, trust_flags)
        except ValueError, e:
            raise admintool.ScriptError(
                "Failed to install the certificate: %s" % e)

        print "CA certificate successfully installed"
