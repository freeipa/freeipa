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
# nsscert: the certificate is an NSS Certificate object
# rawcert: the cert is in an unknown format

from __future__ import print_function

import binascii
import collections
import os
import sys
import base64
import re

import cryptography.x509
import nss.nss as nss
from nss.error import NSPRError
from pyasn1.type import univ, char, namedtype, tag
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459
import six

from ipalib import api
from ipalib import _
from ipalib import util
from ipalib import errors
from ipaplatform.paths import paths
from ipapython.dn import DN

if six.PY3:
    unicode = str

PEM = 0
DER = 1

PEM_REGEX = re.compile(r'(?<=-----BEGIN CERTIFICATE-----).*?(?=-----END CERTIFICATE-----)', re.DOTALL)

EKU_SERVER_AUTH = '1.3.6.1.5.5.7.3.1'
EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'
EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
EKU_EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4'
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
    s = pem.find("-----BEGIN CERTIFICATE-----")
    if s >= 0:
        e = pem.find("-----END CERTIFICATE-----")
        pem = pem[s+27:e]

    return pem

def initialize_nss_database(dbdir=None):
    """
    Initializes NSS database, if not initialized yet. Uses a proper database
    directory (.ipa/alias or HTTPD_ALIAS_DIR), depending on the value of
    api.env.in_tree.
    """

    if not nss.nss_is_initialized():
        if dbdir is None:
            if 'in_tree' in api.env:
                if api.env.in_tree:
                    dbdir = api.env.dot_ipa + os.sep + 'alias'
                else:
                    dbdir = paths.HTTPD_ALIAS_DIR
                nss.nss_init(dbdir)
            else:
                nss.nss_init_nodb()
        else:
            nss.nss_init(dbdir)

def load_certificate(data, datatype=PEM, dbdir=None):
    """
    Given a base64-encoded certificate, with or without the
    header/footer, return a request object.

    Returns a nss.Certificate type
    """
    if type(data) in (tuple, list):
        data = data[0]

    if (datatype == PEM):
        data = strip_header(data)
        data = base64.b64decode(data)

    initialize_nss_database(dbdir=dbdir)

    if six.PY2:
        return nss.Certificate(buffer(data))  # pylint: disable=buffer-builtin
    else:
        # In python 3 , `bytes` has the buffer interface
        return nss.Certificate(data)

def load_certificate_from_file(filename, dbdir=None):
    """
    Load a certificate from a PEM file.

    Returns a nss.Certificate type
    """
    fd = open(filename, 'r')
    data = fd.read()
    fd.close()

    return load_certificate(data, PEM, dbdir)

def load_certificate_list(data, dbdir=None):
    certs = PEM_REGEX.findall(data)
    certs = [load_certificate(cert, PEM, dbdir) for cert in certs]
    return certs

def load_certificate_list_from_file(filename, dbdir=None):
    """
    Load a certificate list from a PEM file.

    Returns a list of nss.Certificate objects.
    """
    fd = open(filename, 'r')
    data = fd.read()
    fd.close()

    return load_certificate_list(data, dbdir)

def get_subject(certificate, datatype=PEM, dbdir=None):
    """
    Load an X509.3 certificate and get the subject.
    """

    nsscert = load_certificate(certificate, datatype, dbdir)
    subject = nsscert.subject
    del(nsscert)
    return subject

def get_issuer(certificate, datatype=PEM, dbdir=None):
    """
    Load an X509.3 certificate and get the issuer.
    """

    nsscert = load_certificate(certificate, datatype, dbdir)
    issuer = nsscert.issuer
    del(nsscert)
    return issuer

def get_serial_number(certificate, datatype=PEM, dbdir=None):
    """
    Return the decimal value of the serial number.
    """
    nsscert = load_certificate(certificate, datatype, dbdir)
    serial_number = nsscert.serial_number
    del(nsscert)
    return serial_number

def is_self_signed(certificate, datatype=PEM, dbdir=None):
    nsscert = load_certificate(certificate, datatype, dbdir)
    self_signed = (nsscert.issuer == nsscert.subject)
    del nsscert
    return self_signed


def _get_der_field(cert, datatype, dbdir, field):
    cert = load_certificate(cert, datatype, dbdir)
    cert = cert.der_data
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

def get_ext_key_usage(certificate, datatype=PEM, dbdir=None):
    nsscert = load_certificate(certificate, datatype, dbdir)
    if not nsscert.extensions:
        return None

    for ext in nsscert.extensions:
        if ext.oid_tag == nss.SEC_OID_X509_EXT_KEY_USAGE:
            break
    else:
        return None

    eku = nss.x509_ext_key_usage(ext.value, nss.AsDottedDecimal)
    eku = set(o[4:] for o in eku)
    return eku

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

    if util.isvalid_base64(rawcert):
        try:
            dercert = base64.b64decode(rawcert)
        except Exception as e:
            raise errors.Base64DecodeError(reason=str(e))
    else:
        dercert = rawcert

    # At this point we should have a certificate, either because the data
    # was base64-encoded and now its not or it came in as DER format.
    # Let's decode it and see. Fetching the serial number will pass the
    # certificate through the NSS DER parser.
    validate_certificate(dercert, datatype=DER)

    return dercert


def validate_certificate(cert, datatype=PEM, dbdir=None):
    """
    Perform certificate validation by trying to load it into NSS database
    """
    try:
        load_certificate(cert, datatype=datatype, dbdir=dbdir)
    except NSPRError as nsprerr:
        if nsprerr.errno == -8183: # SEC_ERROR_BAD_DER
            raise errors.CertificateFormatError(
                error=_('improperly formatted DER-encoded certificate'))
        else:
            raise errors.CertificateFormatError(error=str(nsprerr))


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
    ext['extnValue'] = univ.OctetString(value)
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
    realm = (str(principal['realm']).replace('\\', '\\\\')
                                    .replace('@', '\\@'))
    name = principal['principalName']['name-string']
    name = '/'.join(str(n).replace('\\', '\\\\')
                          .replace('/', '\\/')
                          .replace('@', '\\@') for n in name)
    name = '%s@%s' % (name, realm)
    return name


GeneralNameInfo = collections.namedtuple(
        'GeneralNameInfo', ('type', 'desc', 'value', 'der_value'))


def decode_generalnames(secitem):
    """
    Decode a GeneralNames object (this the data for the Subject
    Alt Name and Issuer Alt Name extensions, among others).

    ``secitem``
      The input is the DER-encoded extension data, without the
      OCTET STRING header, as an nss SecItem object.

    Return a list of ``GeneralNameInfo`` namedtuples.  The
    ``der_value`` field is set for otherNames, otherwise it is
    ``None``.

    """
    nss_names = nss.x509_alt_name(secitem, repr_kind=nss.AsObject)
    asn1_names = decoder.decode(
            secitem.data, asn1Spec=rfc2459.SubjectAltName())[0]
    names = []
    for nss_name, asn1_name in zip(nss_names, asn1_names):
        # NOTE: we use the NSS enum to identify the name type.
        # (For otherName we also tuple it up with the type-id OID).
        # The enum does not correspond exactly to the ASN.1 tags.
        # If we ever want to switch to using the true tag numbers,
        # the expression to get the tag is:
        #
        #   asn1_name.getComponent().getTagSet()[0].asTuple()[2]
        #
        if nss_name.type_enum == nss.certOtherName:
            oid = str(asn1_name['otherName']['type-id'])
            nametype = (nss_name.type_enum, oid)
            der_value = asn1_name['otherName']['value'].asOctets()
        else:
            nametype = nss_name.type_enum
            der_value = None

        if nametype == (nss.certOtherName, SAN_KRB5PRINCIPALNAME):
            name = _decode_krb5principalname(asn1_name['otherName']['value'])
        else:
            name = nss_name.name

        gni = GeneralNameInfo(nametype, nss_name.type_string, name, der_value)
        names.append(gni)

    return names


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


if __name__ == '__main__':
    # this can be run with:
    # python ipalib/x509.py < /etc/ipa/ca.crt

    api.bootstrap()
    api.finalize()

    nss.nss_init_nodb()

    # Read PEM certs from stdin and print out its components

    certlines = sys.stdin.readlines()
    cert = ''.join(certlines)

    nsscert = load_certificate(cert)

    print(nsscert)
