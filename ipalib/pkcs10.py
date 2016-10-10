# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from __future__ import print_function

import sys
import base64
from cryptography.hazmat.backends import default_backend
import cryptography.x509
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import decoder
import six

if six.PY3:
    unicode = str

PEM = 0
DER = 1


# Unfortunately, NSS can only parse the extension request attribute, so
# we have to parse friendly name ourselves (see RFC 2986)
class _Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('values', univ.Set()),
        )

class _Attributes(univ.SetOf):
    componentType = _Attribute()

class _CertificationRequestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('subject', univ.Sequence()),
        namedtype.NamedType('subjectPublicKeyInfo', univ.Sequence()),
        namedtype.OptionalNamedType('attributes', _Attributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
        )

class _CertificationRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificationRequestInfo',
                            _CertificationRequestInfo()),
        namedtype.NamedType('signatureAlgorithm', univ.Sequence()),
        namedtype.NamedType('signatureValue', univ.BitString()),
        )

_FRIENDLYNAME = univ.ObjectIdentifier('1.2.840.113549.1.9.20')

def get_friendlyname(csr, datatype=PEM):
    """
    Given a CSR return the value of the friendlyname attribute, if any.

    The return value is a string.
    """
    if datatype == PEM:
        csr = strip_header(csr)
        csr = base64.b64decode(csr)

    csr = decoder.decode(csr, asn1Spec=_CertificationRequest())[0]
    for attribute in csr['certificationRequestInfo']['attributes']:
        if attribute['type'] == _FRIENDLYNAME:
            return unicode(attribute['values'][0])

    return None

def strip_header(csr):
    """
    Remove the header and footer from a CSR.
    """
    headerlen = 40
    s = csr.find("-----BEGIN NEW CERTIFICATE REQUEST-----")
    if s == -1:
        headerlen = 36
        s = csr.find("-----BEGIN CERTIFICATE REQUEST-----")
    if s >= 0:
        e = csr.find("-----END")
        csr = csr[s+headerlen:e]

    return csr


def load_certificate_request(data, datatype=PEM):
    """
    Load a PKCS #10 certificate request.

    :param datatype: PEM for base64-encoded data (with or without header),
                     or DER
    :return: a python-cryptography ``Certificate`` object.
    :raises: ``ValueError`` if unable to load the request

    """
    if (datatype == PEM):
        data = strip_header(data)
        data = base64.b64decode(data)

    return cryptography.x509.load_der_x509_csr(data, default_backend())


if __name__ == '__main__':
    # Read PEM request from stdin and print out its components

    csrlines = sys.stdin.readlines()
    csr = ''.join(csrlines)

    print(load_certificate_request(csr))
    print(get_friendlyname(csr))
