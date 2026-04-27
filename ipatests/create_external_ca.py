#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
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
from __future__ import absolute_import, print_function

import argparse
import datetime
import os

import synta
import synta.ext
import synta.oids

ISSUER_CN = 'example.test'


class ExternalCA:
    """Provide external CA for testing
    """

    def __init__(self, days=365, key_size=None):
        self.now = datetime.datetime.now(tz=datetime.timezone.utc)
        self.delta = datetime.timedelta(days=days)
        self.ca_key = None
        self.ca_public_key = None
        self.issuer = None          # bytes: DER-encoded Name
        self.key_size = key_size or 2048

    def create_ca_key(self):
        """Create private and public key for CA

        Note: The test still creates 2048 although IPA CA uses 3072 bit RSA
        by default. This also tests that IPA supports an external signing CA
        with weaker keys than the IPA base CA.
        """
        self.ca_key = synta.PrivateKey.generate_rsa(self.key_size)
        self.ca_public_key = self.ca_key.public_key

    def sign(self, builder):
        return builder.sign(self.ca_key, "sha256")

    def create_ca(self, cn=ISSUER_CN, path_length=None, extensions=()):
        """Create root CA.

        :param extensions: iterable of (oid_str, critical, value_der) tuples
        :returns: bytes -- Root CA in PEM format.
        """
        if self.ca_key is None:
            self.create_ca_key()
        name_der = synta.NameBuilder().common_name(str(cn)).build()
        self.issuer = name_der

        ku_bits = synta.ext.KU_KEY_CERT_SIGN | synta.ext.KU_CRL_SIGN
        spki_der = self.ca_public_key.to_der()

        builder = (
            synta.CertificateBuilder()
            .subject_name(name_der)
            .issuer_name(name_der)
            .public_key(self.ca_public_key)
            .serial_number(int.from_bytes(os.urandom(20), 'big'))
            .not_valid_before_utc(self.now)
            .not_valid_after_utc(self.now + self.delta)
            .add_extension(str(synta.oids.KEY_USAGE), True,
                           synta.ext.key_usage(ku_bits))
            .add_extension(str(synta.oids.BASIC_CONSTRAINTS), True,
                           synta.ext.basic_constraints(ca=True,
                                                       path_length=path_length))
            .add_extension(str(synta.oids.SUBJECT_KEY_IDENTIFIER), False,
                           synta.ext.subject_key_identifier(spki_der))
            .add_extension(str(synta.oids.AUTHORITY_KEY_IDENTIFIER), False,
                           synta.ext.authority_key_identifier(spki_der))
        )

        for oid, critical, value_der in extensions:
            builder = builder.add_extension(oid, critical, value_der)

        cert = builder.sign(self.ca_key, "sha256")
        return synta.Certificate.to_pem(cert)

    def sign_csr(self, ipa_csr, path_length=1):
        """Sign certificate CSR.

        :param ipa_csr: CSR in PEM format.
        :type ipa_csr: bytes.
        :returns: bytes -- Signed CA in PEM format.
        """
        csr_tbs = synta.CertificationRequest.from_pem(ipa_csr)

        csr_subject = csr_tbs.subject_raw_der
        spki_der = csr_tbs.subject_public_key_info_der
        csr_public_key = synta.PublicKey.from_der(spki_der)
        ca_spki_der = self.ca_public_key.to_der()

        ku_bits = synta.ext.KU_KEY_CERT_SIGN | synta.ext.KU_CRL_SIGN
        builder = (
            synta.CertificateBuilder()
            .public_key(csr_public_key)
            .subject_name(csr_subject)
            .serial_number(int.from_bytes(os.urandom(20), 'big'))
            .issuer_name(self.issuer)
            .not_valid_before_utc(self.now)
            .not_valid_after_utc(self.now + self.delta)
            .add_extension(str(synta.oids.KEY_USAGE), True,
                           synta.ext.key_usage(ku_bits))
            .add_extension(str(synta.oids.SUBJECT_KEY_IDENTIFIER), False,
                           synta.ext.subject_key_identifier(spki_der))
            .add_extension(str(synta.oids.AUTHORITY_KEY_IDENTIFIER), False,
                           synta.ext.authority_key_identifier(ca_spki_der))
            .add_extension(str(synta.oids.BASIC_CONSTRAINTS), True,
                           synta.ext.basic_constraints(ca=True,
                                                       path_length=path_length))
        )

        cert = self.sign(builder)
        return synta.Certificate.to_pem(cert)


def main():
    IPA_CSR = '/root/ipa.csr'
    ROOT_CA = '/tmp/rootca.pem'
    IPA_CA = '/tmp/ipaca.pem'
    parser = argparse.ArgumentParser("Create external CA")
    parser.add_argument(
        '--csr',
        type=argparse.FileType('rb'),
        default=IPA_CSR,
        help="Path to ipa.csr (default: {})".format(IPA_CSR)
    )
    parser.add_argument(
        '--rootca',
        type=argparse.FileType('wb'),
        default=ROOT_CA,
        help="New root CA file (default: {})".format(ROOT_CA)
    )
    parser.add_argument(
        '--ipaca',
        type=argparse.FileType('wb'),
        default=IPA_CA,
        help="New IPA CA file (default: {})".format(ROOT_CA)
    )

    args = parser.parse_args()

    with args.csr as f:
        ipa_csr = f.read()

    external_ca = ExternalCA()
    root_ca = external_ca.create_ca()
    ipa_ca = external_ca.sign_csr(ipa_csr)

    with args.rootca as f:
        f.write(root_ca)

    with args.ipaca as f:
        f.write(ipa_ca)

    o = "ipa-server-install --external-cert-file={} --external-cert-file={}"
    print(o.format(args.rootca.name, args.ipaca.name))


if __name__ == '__main__':
    main()
