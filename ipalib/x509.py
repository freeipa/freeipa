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

import os
import sys
import base64
import re
import nss.nss as nss
from nss.error import NSPRError
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import decoder, encoder
from ipapython import ipautil
from ipalib import api
from ipalib import _
from ipalib import util
from ipalib import errors
from ipaplatform.paths import paths
from ipapython.dn import DN

PEM = 0
DER = 1

PEM_REGEX = re.compile(r'(?<=-----BEGIN CERTIFICATE-----).*?(?=-----END CERTIFICATE-----)', re.DOTALL)

EKU_SERVER_AUTH = '1.3.6.1.5.5.7.3.1'
EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'
EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
EKU_EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4'
EKU_ANY = '2.5.29.37.0'
EKU_PLACEHOLDER = '1.3.6.1.4.1.3319.6.10.16'

_subject_base = None

def subject_base():
    global _subject_base

    if _subject_base is None:
        config = api.Command['config_show']()['result']
        _subject_base = DN(config['ipacertificatesubjectbase'][0])

    return _subject_base

def valid_issuer(issuer):
    if not api.Command.ca_is_enabled()['result']:
        return True
    # Handle all supported forms of issuer -- currently dogtag only.
    if api.env.ra_plugin == 'dogtag':
        return DN(issuer) == DN(('CN', 'Certificate Authority'), subject_base())
    return True

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

    return nss.Certificate(buffer(data))

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

class _TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'version',
            univ.Integer().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('serialNumber', univ.Integer()),
        namedtype.NamedType('signature', univ.Sequence()),
        namedtype.NamedType('issuer', univ.Sequence()),
        namedtype.NamedType('validity', univ.Sequence()),
        namedtype.NamedType('subject', univ.Sequence()),
        namedtype.NamedType('subjectPublicKeyInfo', univ.Sequence()),
        namedtype.OptionalNamedType(
            'issuerUniquedID',
            univ.BitString().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType(
            'subjectUniquedID',
            univ.BitString().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType(
            'extensions',
            univ.Sequence().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 3))),
        )

class _Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', _TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', univ.Sequence()),
        namedtype.NamedType('signature', univ.BitString()),
        )

def _get_der_field(cert, datatype, dbdir, field):
    cert = load_certificate(cert, datatype, dbdir)
    cert = cert.der_data
    cert = decoder.decode(cert, _Certificate())[0]
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
    pemcert = '\n'.join([data[x:x+64] for x in range(0, len(data), 64)])
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
        except Exception, e:
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
    except (IOError, OSError), e:
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
    except (IOError, OSError), e:
        raise errors.FileError(reason=str(e))

def verify_cert_subject(ldap, hostname, dercert):
    """
    Verify that the certificate issuer we're adding matches the issuer
    base of our installation.

    This assumes the certificate has already been normalized.

    This raises an exception on errors and returns nothing otherwise.
    """
    nsscert = load_certificate(dercert, datatype=DER)
    subject = str(nsscert.subject)
    issuer = str(nsscert.issuer)
    del(nsscert)

    if (not valid_issuer(issuer)):
        raise errors.CertificateOperationError(error=_('Issuer "%(issuer)s" does not match the expected issuer') % \
        {'issuer' : issuer})

class _Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.NamedType('critical', univ.Boolean()),
        namedtype.NamedType('extnValue', univ.OctetString()),
    )

def _encode_extension(oid, critical, value):
    ext = _Extension()
    ext['extnID'] = univ.ObjectIdentifier(oid)
    ext['critical'] = univ.Boolean(critical)
    ext['extnValue'] = univ.OctetString(value)
    ext = encoder.encode(ext)
    return ext

class _ExtKeyUsageSyntax(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()

def encode_ext_key_usage(ext_key_usage):
    eku = _ExtKeyUsageSyntax()
    for i, oid in enumerate(ext_key_usage):
        eku[i] = univ.ObjectIdentifier(oid)
    eku = encoder.encode(eku)
    return _encode_extension('2.5.29.37', EKU_ANY not in ext_key_usage, eku)

if __name__ == '__main__':
    # this can be run with:
    # python ipalib/x509.py < /etc/ipa/ca.crt

    from ipalib import api
    api.bootstrap()
    api.finalize()

    nss.nss_init_nodb()

    # Read PEM certs from stdin and print out its components

    certlines = sys.stdin.readlines()
    cert = ''.join(certlines)

    nsscert = load_certificate(cert)

    print nsscert
