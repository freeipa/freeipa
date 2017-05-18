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

from __future__ import print_function

import os
from optparse import OptionGroup  # pylint: disable=deprecated-module
from cryptography.hazmat.primitives import serialization
import gssapi

from ipalib.install import certmonger, certstore
from ipapython import admintool, ipautil
from ipapython.certdb import (EMPTY_TRUST_FLAGS,
                              EXTERNAL_CA_TRUST_FLAGS,
                              TrustFlags,
                              parse_trust_flags)
from ipapython.dn import DN
from ipaplatform.paths import paths
from ipalib import api, errors, x509
from ipaserver.install import certs, cainstance, installutils


class CACertManage(admintool.AdminTool):
    command_name = 'ipa-cacert-manage'

    usage = "%prog renew [options]\n%prog install [options] CERTFILE"

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
        ext_cas = tuple(x.value for x in cainstance.ExternalCAType)
        renew_group.add_option(
            "--external-ca-type", dest="external_ca_type",
            type="choice", choices=ext_cas,
            metavar="{{{0}}}".format(",".join(ext_cas)),
            help="Type of the external CA. Default: generic")
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

        if command == 'renew':
            pass
        elif command == 'install':
            if len(self.args) < 2:
                parser.error("certificate file name not provided")
        else:
            parser.error("unknown command \"%s\"" % command)

    def run(self):
        command = self.command

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()

        self.ldap_connect()

        try:
            if command == 'renew':
                rc = self.renew()
            elif command == 'install':
                rc = self.install()
        finally:
            api.Backend.ldap2.disconnect()

        return rc

    def ldap_connect(self):
        password = self.options.password
        if not password:
            try:
                api.Backend.ldap2.connect(ccache=os.environ.get('KRB5CCNAME'))
            except (gssapi.exceptions.GSSError, errors.ACIError):
                pass
            else:
                return

            password = installutils.read_password(
                "Directory Manager", confirm=False, validate=False)
            if password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

        api.Backend.ldap2.connect(bind_pw=password)

    def renew(self):
        ca = cainstance.CAInstance(api.env.realm)
        if not ca.is_configured():
            raise admintool.ScriptError("CA is not configured on this system")

        criteria = {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': self.cert_nickname,
            'ca-name': 'dogtag-ipa-ca-renew-agent',
        }
        self.request_id = certmonger.get_request_id(criteria)
        if self.request_id is None:
            raise admintool.ScriptError(
                "CA certificate is not tracked by certmonger")
        self.log.debug(
            "Found certmonger request id %r", self.request_id)

        db = certs.CertDB(api.env.realm, nssdir=paths.PKI_TOMCAT_ALIAS_DIR)
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
        print("Renewing CA certificate, please wait")

        try:
            ca.set_renewal_master()
        except errors.NotFound:
            raise admintool.ScriptError("CA renewal master not found")

        self.resubmit_request()

        print("CA certificate successfully renewed")

    def renew_external_step_1(self, ca):
        print("Exporting CA certificate signing request, please wait")

        if self.options.external_ca_type \
                == cainstance.ExternalCAType.MS_CS.value:
            profile = 'SubCA'
        else:
            profile = ''

        self.resubmit_request('dogtag-ipa-ca-renew-agent-reuse', profile)

        print(("The next step is to get %s signed by your CA and re-run "
              "ipa-cacert-manage as:" % paths.IPA_CA_CSR))
        print("ipa-cacert-manage renew "
              "--external-cert-file=/path/to/signed_certificate "
              "--external-cert-file=/path/to/external_ca_certificate")

    def renew_external_step_2(self, ca, old_cert_der):
        print("Importing the renewed CA certificate, please wait")

        options = self.options
        conn = api.Backend.ldap2

        old_cert_obj = x509.load_certificate(old_cert_der, x509.DER)
        old_der_subject = x509.get_der_subject(old_cert_der, x509.DER)
        old_spki = old_cert_obj.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        cert_file, ca_file = installutils.load_external_cert(
            options.external_cert_files, DN(old_cert_obj.subject))

        with open(cert_file.name) as f:
            new_cert_data = f.read()
        new_cert_der = x509.normalize_certificate(new_cert_data)
        new_cert_obj = x509.load_certificate(new_cert_der, x509.DER)
        new_der_subject = x509.get_der_subject(new_cert_der, x509.DER)
        new_spki = new_cert_obj.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if new_cert_obj.subject != old_cert_obj.subject:
            raise admintool.ScriptError(
                "Subject name mismatch (visit "
                "http://www.freeipa.org/page/Troubleshooting for "
                "troubleshooting guide)")
        if new_der_subject != old_der_subject:
            raise admintool.ScriptError(
                "Subject name encoding mismatch (visit "
                "http://www.freeipa.org/page/Troubleshooting for "
                "troubleshooting guide)")
        if new_spki != old_spki:
            raise admintool.ScriptError(
                "Subject public key info mismatch (visit "
                "http://www.freeipa.org/page/Troubleshooting for "
                "troubleshooting guide)")

        with certs.NSSDatabase() as tmpdb:
            tmpdb.create_db()
            tmpdb.add_cert(old_cert_der, 'IPA CA', EXTERNAL_CA_TRUST_FLAGS)

            try:
                tmpdb.add_cert(new_cert_der, 'IPA CA', EXTERNAL_CA_TRUST_FLAGS)
            except ipautil.CalledProcessError as e:
                raise admintool.ScriptError(
                    "Not compatible with the current CA certificate: %s" % e)

            ca_certs = x509.load_certificate_list_from_file(ca_file.name)
            for ca_cert in ca_certs:
                data = ca_cert.public_bytes(serialization.Encoding.DER)
                tmpdb.add_cert(
                    data, str(DN(ca_cert.subject)), EXTERNAL_CA_TRUST_FLAGS)

            try:
                tmpdb.verify_ca_cert_validity('IPA CA')
            except ValueError as e:
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
                    conn,
                    api.env.basedn,
                    ca_cert,
                    nickname,
                    EMPTY_TRUST_FLAGS)

        dn = DN(('cn', self.cert_nickname), ('cn', 'ca_renewal'),
                ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
        try:
            entry = conn.get_entry(dn, ['usercertificate'])
            entry['usercertificate'] = [new_cert_der]
            conn.update_entry(entry)
        except errors.NotFound:
            entry = conn.make_entry(
                dn,
                objectclass=['top', 'pkiuser', 'nscontainer'],
                cn=[self.cert_nickname],
                usercertificate=[new_cert_der])
            conn.add_entry(entry)
        except errors.EmptyModlist:
            pass

        try:
            ca.set_renewal_master()
        except errors.NotFound:
            raise admintool.ScriptError("CA renewal master not found")

        self.resubmit_request('dogtag-ipa-ca-renew-agent-reuse')

        print("CA certificate successfully renewed")

    def resubmit_request(self, ca='dogtag-ipa-ca-renew-agent', profile=''):
        timeout = api.env.startup_timeout + 60

        self.log.debug("resubmitting certmonger request '%s'", self.request_id)
        certmonger.resubmit_request(self.request_id, ca=ca, profile=profile)
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
        certmonger.modify(self.request_id,
                          ca='dogtag-ipa-ca-renew-agent',
                          profile='')

    def install(self):
        print("Installing CA certificate, please wait")

        options = self.options
        cert_filename = self.args[1]

        try:
            cert_obj = x509.load_certificate_from_file(cert_filename)
        except IOError as e:
            raise admintool.ScriptError(
                "Can't open \"%s\": %s" % (cert_filename, e))
        except (TypeError, ValueError) as e:
            raise admintool.ScriptError("Not a valid certificate: %s" % e)
        cert = cert_obj.public_bytes(serialization.Encoding.DER)

        nickname = options.nickname or str(DN(cert_obj.subject))

        ca_certs = certstore.get_ca_certs_nss(api.Backend.ldap2,
                                              api.env.basedn,
                                              api.env.realm,
                                              False)

        with certs.NSSDatabase() as tmpdb:
            tmpdb.create_db()
            tmpdb.add_cert(cert, nickname, EXTERNAL_CA_TRUST_FLAGS)
            for ca_cert, ca_nickname, ca_trust_flags in ca_certs:
                tmpdb.add_cert(ca_cert, ca_nickname, ca_trust_flags)

            try:
                tmpdb.verify_ca_cert_validity(nickname)
            except ValueError as e:
                raise admintool.ScriptError(
                    "Not a valid CA certificate: %s (visit "
                    "http://www.freeipa.org/page/Troubleshooting for "
                    "troubleshooting guide)" % e)

        trust_flags = options.trust_flags.split(',')
        if (set(options.trust_flags) - set(',CPTcgpuw') or
                len(trust_flags) not in [3, 4]):
            raise admintool.ScriptError("Invalid trust flags")

        extra_flags = trust_flags[3:]
        extra_usages = set()
        if extra_flags:
            if 'C' in extra_flags[0]:
                extra_usages.add(x509.EKU_PKINIT_KDC)
            if 'T' in extra_flags[0]:
                extra_usages.add(x509.EKU_PKINIT_CLIENT_AUTH)

        trust_flags = parse_trust_flags(','.join(trust_flags[:3]))
        trust_flags = TrustFlags(trust_flags.has_key,
                                 trust_flags.trusted,
                                 trust_flags.ca,
                                 trust_flags.usages | extra_usages)

        try:
            certstore.put_ca_cert_nss(
                api.Backend.ldap2, api.env.basedn, cert, nickname, trust_flags)
        except ValueError as e:
            raise admintool.ScriptError(
                "Failed to install the certificate: %s" % e)

        print("CA certificate successfully installed")
