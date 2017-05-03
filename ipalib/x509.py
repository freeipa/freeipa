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

# Certificates should be stored internally DER-encoded. We can be passed
# a certificate several ways: read if from LDAP, read it from a 3rd party
# app (dogtag, candlepin, etc) or as user input. The normalize_certificate()
# function will convert an incoming certificate to DER-encoding.

# Conventions
#
# Where possible the following naming conventions are used:
#
# cert: the certificate is a PEM-encoded certificate
# dercert: the certificate is DER-encoded
# rawcert: the cert is in an unknown format

from __future__ import print_function

import binascii
import datetime
import ipaddress
import base64
import re

from cryptography.hazmat.backends import default_backend
import cryptography.x509
from pyasn1.type import univ, char, namedtype, tag
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2315, rfc2459
import six

from ipalib import api
from ipalib import util
from ipalib import errors
from ipapython.dn import DN

if six.PY3:
    unicode = str

PEM = 0
DER = 1

PEM_REGEX = re.compile(
    r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
    re.DOTALL)

EKU_SERVER_AUTH = '1.3.6.1.5.5.7.3.1'
EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'
EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
EKU_EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4'
EKU_PKINIT_CLIENT_AUTH = '1.3.6.1.5.2.3.4'
EKU_PKINIT_KDC = '1.3.6.1.5.2.3.5'
EKU_ANY = '2.5.29.37.0'
EKU_PLACEHOLDER = '1.3.6.1.4.1.3319.6.10.16'

SAN_UPN = '1.3.6.1.4.1.311.20.2.3'
SAN_KRB5PRINCIPALNAME = '1.3.6.1.5.2.2'

_subject_base = None

def subject_base():
    global _subject_base

    if _subject_base is None:
        config = api.Command['config_show']()['result']
        _subject_base = DN(config['ipacertificatesubjectbase'][0])

    return _subject_base

def strip_header(pem):
    """
    Remove the header and footer from a certificate.
    """
    regexp = (
        u"^-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
    )
    if isinstance(pem, bytes):
        regexp = regexp.encode('ascii')
    s = re.search(regexp, pem, re.MULTILINE | re.DOTALL)
    if s is not None:
        return s.group(1)
    else:
        return pem


def load_certificate(data, datatype=PEM):
    """
    Load an X.509 certificate.

    :param datatype: PEM for base64-encoded data (with or without header),
                     or DER
    :return: a python-cryptography ``CertificateSigningRequest`` object.
    :raises: ``ValueError`` if unable to load the certificate.

    """
    if type(data) in (tuple, list):
        data = data[0]

    if (datatype == PEM):
        data = strip_header(data)
        data = base64.b64decode(data)

    return cryptography.x509.load_der_x509_certificate(data, default_backend())


def load_certificate_from_file(filename, dbdir=None):
    """
    Load a certificate from a PEM file.

    Returns a python-cryptography ``Certificate`` object.

    """
    with open(filename, mode='rb') as f:
        return load_certificate(f.read(), PEM)


def load_certificate_list(data):
    """
    Load a certificate list from a sequence of concatenated PEMs.

    Return a list of python-cryptography ``Certificate`` objects.

    """
    certs = PEM_REGEX.findall(data)
    certs = [load_certificate(cert, PEM) for cert in certs]
    return certs


def load_certificate_list_from_file(filename):
    """
    Load a certificate list from a PEM file.

    Return a list of python-cryptography ``Certificate`` objects.

    """
    with open(filename) as f:
        return load_certificate_list(f.read())


def pkcs7_to_pems(data, datatype=PEM):
    """
    Extract certificates from a PKCS #7 object.

    Return a ``list`` of X.509 PEM strings.
    """
    if datatype == PEM:
        match = re.match(
            r'-----BEGIN PKCS7-----(.*?)-----END PKCS7-----',
            data,
            re.DOTALL)
        if not match:
            raise ValueError("not a valid PKCS#7 PEM")

        data = base64.b64decode(match.group(1))

    content_info, tail = decoder.decode(data, rfc2315.ContentInfo())
    if tail:
        raise ValueError("not a valid PKCS#7 message")

    if content_info['contentType'] != rfc2315.signedData:
        raise ValueError("not a PKCS#7 signed data message")

    signed_data, tail = decoder.decode(bytes(content_info['content']),
                                       rfc2315.SignedData())
    if tail:
        raise ValueError("not a valid PKCS#7 signed data message")

    result = []

    for certificate in signed_data['certificates']:
        certificate = encoder.encode(certificate)
        certificate = base64.b64encode(certificate)
        certificate = make_pem(certificate)
        result.append(certificate)

    return result


def is_self_signed(certificate, datatype=PEM):
    cert = load_certificate(certificate, datatype)
    return cert.issuer == cert.subject


def _get_der_field(cert, datatype, dbdir, field):
    cert = normalize_certificate(cert)
    cert = decoder.decode(cert, rfc2459.Certificate())[0]
    field = cert['tbsCertificate'][field]
    field = encoder.encode(field)
    return field

def get_der_subject(cert, datatype=PEM, dbdir=None):
    return _get_der_field(cert, datatype, dbdir, 'subject')

def get_der_issuer(cert, datatype=PEM, dbdir=None):
    return _get_der_field(cert, datatype, dbdir, 'issuer')

def get_der_serial_number(cert, datatype=PEM, dbdir=None):
    return _get_der_field(cert, datatype, dbdir, 'serialNumber')

def get_der_public_key_info(cert, datatype=PEM, dbdir=None):
    return _get_der_field(cert, datatype, dbdir, 'subjectPublicKeyInfo')


def get_ext_key_usage(certificate, datatype=PEM):
    cert = load_certificate(certificate, datatype)
    try:
        eku = cert.extensions.get_extension_for_oid(
            cryptography.x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
    except cryptography.x509.ExtensionNotFound:
        return None

    return set(oid.dotted_string for oid in eku)


def make_pem(data):
    """
    Convert a raw base64-encoded blob into something that looks like a PE
    file with lines split to 64 characters and proper headers.
    """
    if isinstance(data, bytes):
        data = data.decode('ascii')
    pemcert = '\r\n'.join([data[x:x+64] for x in range(0, len(data), 64)])
    return '-----BEGIN CERTIFICATE-----\n' + \
    pemcert + \
    '\n-----END CERTIFICATE-----'

def normalize_certificate(rawcert):
    """
    Incoming certificates should be DER-encoded. If not it is converted to
    DER-format.

    Note that this can't be a normalizer on a Param because only unicode
    variables are normalized.
    """
    if not rawcert:
        return None

    rawcert = strip_header(rawcert)

    try:
        if isinstance(rawcert, bytes):
            # base64 must work with utf-8, otherwise it is raw bin certificate
            decoded_cert = rawcert.decode('utf-8')
        else:
            decoded_cert = rawcert
    except UnicodeDecodeError:
        dercert = rawcert
    else:
        if util.isvalid_base64(decoded_cert):
            try:
                dercert = base64.b64decode(decoded_cert)
            except Exception as e:
                raise errors.Base64DecodeError(reason=str(e))
        else:
            dercert = rawcert

    # At this point we should have a DER certificate.
    # Attempt to decode it.
    validate_certificate(dercert, datatype=DER)

    return dercert


def validate_certificate(cert, datatype=PEM):
    """
    Perform cert validation by trying to load it via python-cryptography.
    """
    try:
        load_certificate(cert, datatype=datatype)
    except ValueError as e:
        raise errors.CertificateFormatError(error=str(e))


def write_certificate(rawcert, filename):
    """
    Write the certificate to a file in PEM format.

    The cert value can be either DER or PEM-encoded, it will be normalized
    to DER regardless, then back out to PEM.
    """
    dercert = normalize_certificate(rawcert)

    try:
        fp = open(filename, 'w')
        fp.write(make_pem(base64.b64encode(dercert)))
        fp.close()
    except (IOError, OSError) as e:
        raise errors.FileError(reason=str(e))

def write_certificate_list(rawcerts, filename):
    """
    Write a list of certificates to a file in PEM format.

    The cert values can be either DER or PEM-encoded, they will be normalized
    to DER regardless, then back out to PEM.
    """
    dercerts = [normalize_certificate(rawcert) for rawcert in rawcerts]

    try:
        with open(filename, 'w') as f:
            for cert in dercerts:
                cert = base64.b64encode(cert)
                cert = make_pem(cert)
                f.write(cert + '\n')
    except (IOError, OSError) as e:
        raise errors.FileError(reason=str(e))


def _encode_extension(oid, critical, value):
    ext = rfc2459.Extension()
    ext['extnID'] = univ.ObjectIdentifier(oid)
    ext['critical'] = univ.Boolean(critical)
    ext['extnValue'] = univ.Any(encoder.encode(univ.OctetString(value)))
    ext = encoder.encode(ext)
    return ext


def encode_ext_key_usage(ext_key_usage):
    eku = rfc2459.ExtKeyUsageSyntax()
    for i, oid in enumerate(ext_key_usage):
        eku[i] = univ.ObjectIdentifier(oid)
    eku = encoder.encode(eku)
    return _encode_extension('2.5.29.37', EKU_ANY not in ext_key_usage, eku)


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
    realm = (unicode(principal['realm']).replace('\\', '\\\\')
                                        .replace('@', '\\@'))
    name = principal['principalName']['name-string']
    name = u'/'.join(unicode(n).replace('\\', '\\\\')
                               .replace('/', '\\/')
                               .replace('@', '\\@') for n in name)
    name = u'%s@%s' % (name, realm)
    return name


class KRB5PrincipalName(cryptography.x509.general_name.OtherName):
    def __init__(self, type_id, value):
        super(KRB5PrincipalName, self).__init__(type_id, value)
        self.name = _decode_krb5principalname(value)


class UPN(cryptography.x509.general_name.OtherName):
    def __init__(self, type_id, value):
        super(UPN, self).__init__(type_id, value)
        self.name = unicode(
            decoder.decode(value, asn1Spec=char.UTF8String())[0])


OTHERNAME_CLASS_MAP = {
    SAN_KRB5PRINCIPALNAME: KRB5PrincipalName,
    SAN_UPN: UPN,
}


def process_othernames(gns):
    """
    Process python-cryptography GeneralName values, yielding
    OtherName values of more specific type if type is known.

    """
    for gn in gns:
        if isinstance(gn, cryptography.x509.general_name.OtherName):
            cls = OTHERNAME_CLASS_MAP.get(
                gn.type_id.dotted_string,
                cryptography.x509.general_name.OtherName)
            yield cls(gn.type_id, gn.value)
        else:
            yield gn


def get_san_general_names(cert):
    """
    Return SAN general names from a python-cryptography
    certificate object.  If the SAN extension is not present,
    return an empty sequence.

    Because python-cryptography does not yet provide a way to
    handle unrecognised critical extensions (which may occur),
    we must parse the certificate and extract the General Names.
    For uniformity with other code, we manually construct values
    of python-crytography GeneralName subtypes.

    python-cryptography does not yet provide types for
    ediPartyName or x400Address, so we drop these name types.

    otherNames are NOT instantiated to more specific types where
    the type is known.  Use ``process_othernames`` to do that.

    When python-cryptography can handle certs with unrecognised
    critical extensions and implements ediPartyName and
    x400Address, this function (and helpers) will be redundant
    and should go away.

    """
    tbs = decoder.decode(
        cert.tbs_certificate_bytes,
        asn1Spec=rfc2459.TBSCertificate()
    )[0]
    OID_SAN = univ.ObjectIdentifier('2.5.29.17')
    # One would expect KeyError or empty iterable when the key ('extensions'
    # in this particular case) is not pressent in the certificate but pyasn1
    # returns None here
    extensions = tbs['extensions'] or []
    gns = []
    for ext in extensions:
        if ext['extnID'] == OID_SAN:
            der = decoder.decode(
                ext['extnValue'], asn1Spec=univ.OctetString())[0]
            gns = decoder.decode(der, asn1Spec=rfc2459.SubjectAltName())[0]
            break

    GENERAL_NAME_CONSTRUCTORS = {
        'rfc822Name': lambda x: cryptography.x509.RFC822Name(unicode(x)),
        'dNSName': lambda x: cryptography.x509.DNSName(unicode(x)),
        'directoryName': _pyasn1_to_cryptography_directoryname,
        'registeredID': _pyasn1_to_cryptography_registeredid,
        'iPAddress': _pyasn1_to_cryptography_ipaddress,
        'uniformResourceIdentifier':
            lambda x: cryptography.x509.UniformResourceIdentifier(unicode(x)),
        'otherName': _pyasn1_to_cryptography_othername,
    }

    result = []

    for gn in gns:
        gn_type = gn.getName()
        if gn_type in GENERAL_NAME_CONSTRUCTORS:
            result.append(
                GENERAL_NAME_CONSTRUCTORS[gn_type](gn.getComponent()))

    return result


def _pyasn1_to_cryptography_directoryname(dn):
    attrs = []

    # Name is CHOICE { RDNSequence } (only one possibility)
    for rdn in dn.getComponent():
        for ava in rdn:
            attr = cryptography.x509.NameAttribute(
                _pyasn1_to_cryptography_oid(ava['type']),
                unicode(decoder.decode(ava['value'])[0])
            )
            attrs.append(attr)

    return cryptography.x509.DirectoryName(cryptography.x509.Name(attrs))


def _pyasn1_to_cryptography_registeredid(oid):
    return cryptography.x509.RegisteredID(_pyasn1_to_cryptography_oid(oid))


def _pyasn1_to_cryptography_ipaddress(octet_string):
    return cryptography.x509.IPAddress(
        ipaddress.ip_address(bytes(octet_string)))


def _pyasn1_to_cryptography_othername(on):
    return cryptography.x509.OtherName(
        _pyasn1_to_cryptography_oid(on['type-id']),
        bytes(on['value'])
    )


def _pyasn1_to_cryptography_oid(oid):
    return cryptography.x509.ObjectIdentifier(str(oid))


def chunk(size, s):
    """Yield chunks of the specified size from the given string.

    The input must be a multiple of the chunk size (otherwise
    trailing characters are dropped).

    Works on character strings only.

    """
    return (u''.join(span) for span in six.moves.zip(*[iter(s)] * size))


def add_colons(s):
    """Add colons between each nibble pair in a hex string."""
    return u':'.join(chunk(2, s))


def to_hex_with_colons(bs):
    """Convert bytes to a hex string with colons."""
    return add_colons(binascii.hexlify(bs).decode('utf-8'))


class UTC(datetime.tzinfo):
    ZERO = datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def utcoffset(self, dt):
        return self.ZERO

    def dst(self, dt):
        return self.ZERO


def format_datetime(t):
    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC())
    return unicode(t.strftime("%a %b %d %H:%M:%S %Y %Z"))
