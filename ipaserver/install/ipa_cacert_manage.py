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
from ipalib import api, errors, x509, util
from ipaserver.install import certs, cainstance, installutils
from ipaserver.plugins.ldap2 import ldap2


class CACertManage(admintool.AdminTool):
    command_name = 'ipa-cacert-manage'

    usage = "%prog renew [options]"

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
            "--external-cert-file", dest='external_cert_file',
            help="PEM file containing a certificate signed by the external CA")
        renew_group.add_option(
            "--external-ca-file", dest='external_ca_file',
            help="PEM file containing the external CA chain")
        parser.add_option_group(renew_group)

    def validate_options(self):
        super(CACertManage, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        parser = self.option_parser

        if not self.args:
            parser.error("command not provided")

        command = self.command = self.args[0]
        options = self.options

        if command == 'renew':
            if options.external_cert_file and not options.external_ca_file:
                parser.error("--external-ca-file not specified")
            elif not options.external_cert_file and options.external_ca_file:
                parser.error("--external-cert-file not specified")
        else:
            parser.error("unknown command \"%s\"" % command)

    def run(self):
        command = self.command
        options = self.options

        api.bootstrap(in_server=True)
        api.finalize()

        if command == 'renew' and options.external_cert_file:
            self.conn = self.ldap_connect()
        else:
            self.conn = None

        try:
            if command == 'renew':
                rc = self.renew()
        finally:
            if self.conn is not None:
                self.conn.disconnect()

        return rc

    def ldap_connect(self):
        conn = ldap2()

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
        criteria = (('cert_storage_location', nss_dir, certmonger.NPATH),
                    ('cert_nickname', self.cert_nickname, None))
        self.request_id = certmonger.get_request_id(criteria)
        if self.request_id is None:
            raise admintool.ScriptError(
                "CA certificate is not tracked by certmonger")
        self.log.debug(
            "Found certmonger request id %r", self.request_id)

        db = certs.CertDB(api.env.realm, nssdir=nss_dir)
        cert = db.get_cert_from_db(self.cert_nickname, pem=False)

        options = self.options
        if options.external_cert_file:
            return self.renew_external_step_2(ca, cert)

        if x509.is_self_signed(cert, x509.DER):
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
              "--external-ca-file=/path/to/external_ca_certificate")

    def renew_external_step_2(self, ca, old_cert):
        print "Importing the renewed CA certificate, please wait"

        options = self.options
        cert_filename = options.external_cert_file
        ca_filename = options.external_ca_file

        nss_cert = None
        nss.nss_init(ca.dogtag_constants.ALIAS_DIR)
        try:
            try:
                installutils.validate_external_cert(
                    cert_filename, ca_filename, x509.subject_base())
            except ValueError, e:
                raise admintool.ScriptError(e)

            nss_cert = x509.load_certificate(old_cert, x509.DER)
            subject = nss_cert.subject
            issuer = nss_cert.issuer
            #pylint: disable=E1101
            pkinfo = nss_cert.subject_public_key_info.format()
            #pylint: enable=E1101

            nss_cert = x509.load_certificate_from_file(cert_filename)
            if not nss_cert.is_ca_cert():
                raise admintool.ScriptError("Not a CA certificate")
            if nss_cert.subject != subject:
                raise admintool.ScriptError("Subject name mismatch")
            if nss_cert.issuer != issuer:
                raise admintool.ScriptError("Issuer mismatch")
            #pylint: disable=E1101
            if nss_cert.subject_public_key_info.format() != pkinfo:
                raise admintool.ScriptError("Subject public key info mismatch")
            #pylint: enable=E1101
            cert = nss_cert.der_data
        finally:
            del nss_cert
            nss.nss_shutdown()

        with certs.NSSDatabase() as tmpdb:
            pw = ipautil.write_tmp_file(ipautil.ipa_generate_password())
            tmpdb.create_db(pw.name)
            tmpdb.add_single_pem_cert(
                'IPA CA', 'C,,', x509.make_pem(base64.b64encode(old_cert)))

            try:
                tmpdb.add_single_pem_cert(
                    'IPA CA', 'C,,', x509.make_pem(base64.b64encode(cert)))
            except ipautil.CalledProcessError, e:
                raise admintool.ScriptError(
                    "Not compatible with the current CA certificate: %s", e)

            ca_certs = x509.load_certificate_chain_from_file(ca_filename)
            for ca_cert in ca_certs:
                tmpdb.add_single_pem_cert(
                    str(ca_cert.subject), 'C,,',
                    x509.make_pem(base64.b64encode(ca_cert.der_data)))
            del ca_certs
            del ca_cert

            try:
                tmpdb.verify_ca_cert_validity('IPA CA')
            except ValueError, e:
                raise admintool.ScriptError(
                    "Not a valid CA certificate: %s" % e)

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
        if state != 'MONITORING':
            raise admintool.ScriptError(
                "Error resubmitting certmonger request '%s', "
                "please check the request manually" % self.request_id)

        self.log.debug("modifying certmonger request '%s'", self.request_id)
        certmonger.modify(self.request_id, profile='ipaCACertRenewal')
