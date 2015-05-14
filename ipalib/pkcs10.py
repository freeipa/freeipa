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

import os
import sys
import base64
import nss.nss as nss
from pyasn1.type import univ, char, namedtype, tag
from pyasn1.codec.der import decoder
from ipapython import ipautil
from ipalib import api

PEM = 0
DER = 1

SAN_DNSNAME = 'DNS name'
SAN_RFC822NAME = 'RFC822 Name'
SAN_OTHERNAME_UPN = 'Other Name (OID.1.3.6.1.4.1.311.20.2.3)'
SAN_OTHERNAME_KRB5PRINCIPALNAME = 'Other Name (OID.1.3.6.1.5.2.2)'

def get_subject(csr, datatype=PEM):
    """
    Given a CSR return the subject value.

    This returns an nss.DN object.
    """
    request = load_certificate_request(csr, datatype)
    try:
        return request.subject
    finally:
        del request

def get_extensions(csr, datatype=PEM):
    """
    Given a CSR return OIDs of certificate extensions.

    The return value is a tuple of strings
    """
    request = load_certificate_request(csr, datatype)
    return tuple(nss.oid_dotted_decimal(ext.oid_tag)[4:]
                 for ext in request.extensions)

class _PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name-type', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType('name-string', univ.SequenceOf(char.GeneralString()).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        ),
    )

class _KRB5PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('realm', char.GeneralString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType('principalName', _PrincipalName().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        ),
    )

def _decode_krb5principalname(data):
    principal = decoder.decode(data, asn1Spec=_KRB5PrincipalName())[0]
    realm = (str(principal['realm']).replace('\\', '\\\\')
                                    .replace('@', '\\@'))
    name = principal['principalName']['name-string']
    name = '/'.join(str(n).replace('\\', '\\\\')
                          .replace('/', '\\/')
                          .replace('@', '\\@') for n in name)
    name = '%s@%s' % (name, realm)
    return name

class _AnotherName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type-id', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
    )

class _GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('otherName', _AnotherName().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType('rfc822Name', char.IA5String().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        ),
        namedtype.NamedType('dNSName', char.IA5String().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        ),
        namedtype.NamedType('x400Address', univ.Sequence().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        ),
        namedtype.NamedType('directoryName', univ.Choice().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))
        ),
        namedtype.NamedType('ediPartyName', univ.Sequence().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))
        ),
        namedtype.NamedType('uniformResourceIdentifier', char.IA5String().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
        ),
        namedtype.NamedType('iPAddress', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
        ),
        namedtype.NamedType('registeredID', univ.ObjectIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))
        ),
    )

class _SubjectAltName(univ.SequenceOf):
    componentType = _GeneralName()

def get_subjectaltname(csr, datatype=PEM):
    """
    Given a CSR return the subjectaltname value, if any.

    The return value is a tuple of strings or None
    """
    request = load_certificate_request(csr, datatype)
    for extension in request.extensions:
        if extension.oid_tag == nss.SEC_OID_X509_SUBJECT_ALT_NAME:
            break
    else:
        return None
    del request

    nss_names = nss.x509_alt_name(extension.value, nss.AsObject)
    asn1_names = decoder.decode(extension.value.data,
                                asn1Spec=_SubjectAltName())[0]
    names = []
    for nss_name, asn1_name in zip(nss_names, asn1_names):
        name_type = nss_name.type_string
        if name_type == SAN_OTHERNAME_KRB5PRINCIPALNAME:
            name = _decode_krb5principalname(asn1_name['otherName']['value'])
        else:
            name = nss_name.name
        names.append((name_type, name))

    return tuple(names)

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

def load_certificate_request(csr, datatype=PEM):
    """
    Given a base64-encoded certificate request, with or without the
    header/footer, return a request object.
    """
    if datatype == PEM:
        csr = strip_header(csr)
        csr = base64.b64decode(csr)

    # A fail-safe so we can always read a CSR. python-nss/NSS will segfault
    # otherwise
    if not nss.nss_is_initialized():
        nss.nss_init_nodb()

    return nss.CertificateRequest(csr)

if __name__ == '__main__':
    nss.nss_init_nodb()

    # Read PEM request from stdin and print out its components

    csrlines = sys.stdin.readlines()
    csr = ''.join(csrlines)

    print load_certificate_request(csr)
    print get_subject(csr)
    print get_subjectaltname(csr)
    print get_friendlyname(csr)
