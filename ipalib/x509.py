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
# app (dogtag, candlepin, etc) or as user input.

# Conventions
#
# Where possible the following naming conventions are used:
#
# cert: the certificate is a PEM-encoded certificate
# dercert: the certificate is DER-encoded
# rawcert: the cert is in an unknown format

from __future__ import print_function

import os
import binascii
import datetime
import ipaddress
import ssl
import base64
import re

from cryptography import x509 as crypto_x509
from cryptography import utils as crypto_utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, load_pem_private_key
)
import pyasn1
from pyasn1.type import univ, char, namedtype, tag
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2315, rfc2459
import six

from ipalib import errors
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

PEM = 0
DER = 1

PEM_CERT_REGEX = re.compile(
    b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
    re.DOTALL)
PEM_PRIV_REGEX = re.compile(
    b'-----BEGIN(?: ENCRYPTED)?(?: (?:RSA|DSA|DH|EC))? PRIVATE KEY-----.*?'
    b'-----END(?: ENCRYPTED)?(?: (?:RSA|DSA|DH|EC))? PRIVATE KEY-----',
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


@crypto_utils.register_interface(crypto_x509.Certificate)
class IPACertificate(object):
    """
    A proxy class wrapping a python-cryptography certificate representation for
    FreeIPA purposes
    """
    def __init__(self, cert, backend=None):
        """
        :param cert: A python-cryptography Certificate object
        :param backend: A python-cryptography Backend object
        """
        self._cert = cert
        self.backend = default_backend() if backend is None else backend()

        # initialize the certificate fields
        # we have to do it this way so that some systems don't explode since
        # some field types encode-decoding is not strongly defined
        self._subject = self.__get_der_field('subject')
        self._issuer = self.__get_der_field('issuer')
        self._serial_number = self.__get_der_field('serialNumber')

    def __getstate__(self):
        state = {
            '_cert': self.public_bytes(Encoding.DER),
            '_subject': self.subject_bytes,
            '_issuer': self.issuer_bytes,
            '_serial_number': self._serial_number,
        }
        return state

    def __setstate__(self, state):
        self._subject = state['_subject']
        self._issuer = state['_issuer']
        self._issuer = state['_serial_number']
        self._cert = crypto_x509.load_der_x509_certificate(
            state['_cert'], backend=default_backend())

    def __eq__(self, other):
        """
        Checks equality.

        :param other: either cryptography.Certificate or IPACertificate or
                      bytes representing a DER-formatted certificate
        """
        if (isinstance(other, (crypto_x509.Certificate, IPACertificate))):
            return (self.public_bytes(Encoding.DER) ==
                    other.public_bytes(Encoding.DER))
        elif isinstance(other, bytes):
            return self.public_bytes(Encoding.DER) == other
        else:
            return False

    def __ne__(self, other):
        """
        Checks not equal.
        """
        return not self.__eq__(other)

    def __hash__(self):
        """
        Computes a hash of the wrapped cryptography.Certificate.
        """
        return hash(self._cert)

    def __encode_extension(self, oid, critical, value):
        # TODO: have another proxy for crypto_x509.Extension which would
        # provide public_bytes on the top of what python-cryptography has
        ext = rfc2459.Extension()
        # TODO: this does not have to be so weird, pyasn1 now has codecs
        # which are capable of providing python-native types
        ext['extnID'] = univ.ObjectIdentifier(oid)
        ext['critical'] = univ.Boolean(critical)
        if pyasn1.__version__.startswith('0.3'):
            # pyasn1 <= 0.3.7 needs explicit encoding
            # see https://pagure.io/freeipa/issue/7685
            value = encoder.encode(univ.OctetString(value))
        ext['extnValue'] = univ.Any(value)
        ext = encoder.encode(ext)
        return ext

    def __get_pyasn1_field(self, field):
        """
        :returns: a field of the certificate in pyasn1 representation
        """
        cert_bytes = self.tbs_certificate_bytes
        cert = decoder.decode(cert_bytes, rfc2459.TBSCertificate())[0]
        field = cert[field]
        return field

    def __get_der_field(self, field):
        """
        :field: the name of the field of the certificate
        :returns: bytes representing the value of a certificate field
        """
        return encoder.encode(self.__get_pyasn1_field(field))

    def public_bytes(self, encoding):
        """
        Serializes the certificate to PEM or DER format.
        """
        return self._cert.public_bytes(encoding)

    def is_self_signed(self):
        """
        :returns: True if this certificate is self-signed, False otherwise
        """
        return self._cert.issuer == self._cert.subject

    def fingerprint(self, algorithm):
        """
        Counts fingerprint of the wrapped cryptography.Certificate
        """
        return self._cert.fingerprint(algorithm)

    @property
    def serial_number(self):
        return self._cert.serial_number

    @property
    def serial_number_bytes(self):
        return self._serial_number

    @property
    def version(self):
        return self._cert.version

    @property
    def subject(self):
        return self._cert.subject

    @property
    def subject_bytes(self):
        return self._subject

    @property
    def signature_hash_algorithm(self):
        """
        Returns a HashAlgorithm corresponding to the type of the digest signed
        in the certificate.
        """
        return self._cert.signature_hash_algorithm

    @property
    def signature_algorithm_oid(self):
        """
        Returns the ObjectIdentifier of the signature algorithm.
        """
        return self._cert.signature_algorithm_oid

    @property
    def signature(self):
        """
        Returns the signature bytes.
        """
        return self._cert.signature

    @property
    def issuer(self):
        return self._cert.issuer

    @property
    def issuer_bytes(self):
        return self._issuer

    @property
    def not_valid_before(self):
        return self._cert.not_valid_before

    @property
    def not_valid_after(self):
        return self._cert.not_valid_after

    @property
    def tbs_certificate_bytes(self):
        return self._cert.tbs_certificate_bytes

    @property
    def extensions(self):
        # TODO: own Extension and Extensions classes proxying
        # python-cryptography
        return self._cert.extensions

    def public_key(self):
        return self._cert.public_key()

    @property
    def public_key_info_bytes(self):
        return self._cert.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)

    @property
    def extended_key_usage(self):
        try:
            ext_key_usage = self._cert.extensions.get_extension_for_oid(
                crypto_x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
        except crypto_x509.ExtensionNotFound:
            return None

        return set(oid.dotted_string for oid in ext_key_usage)

    @property
    def extended_key_usage_bytes(self):
        eku = self.extended_key_usage
        if eku is None:
            return None

        ekurfc = rfc2459.ExtKeyUsageSyntax()
        for i, oid in enumerate(sorted(eku)):
            ekurfc[i] = univ.ObjectIdentifier(oid)
        ekurfc = encoder.encode(ekurfc)
        return self.__encode_extension('2.5.29.37', EKU_ANY not in eku, ekurfc)

    @property
    def san_general_names(self):
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
        gns = self.__pyasn1_get_san_general_names()

        GENERAL_NAME_CONSTRUCTORS = {
            'rfc822Name': lambda x: crypto_x509.RFC822Name(unicode(x)),
            'dNSName': lambda x: crypto_x509.DNSName(unicode(x)),
            'directoryName': _pyasn1_to_cryptography_directoryname,
            'registeredID': _pyasn1_to_cryptography_registeredid,
            'iPAddress': _pyasn1_to_cryptography_ipaddress,
            'uniformResourceIdentifier':
                lambda x: crypto_x509.UniformResourceIdentifier(unicode(x)),
            'otherName': _pyasn1_to_cryptography_othername,
        }

        result = []

        for gn in gns:
            gn_type = gn.getName()
            if gn_type in GENERAL_NAME_CONSTRUCTORS:
                result.append(
                    GENERAL_NAME_CONSTRUCTORS[gn_type](gn.getComponent()))

        return result

    def __pyasn1_get_san_general_names(self):
        # pyasn1 returns None when the key is not present in the certificate
        # but we need an iterable
        extensions = self.__get_pyasn1_field('extensions') or []
        OID_SAN = univ.ObjectIdentifier('2.5.29.17')
        gns = []
        for ext in extensions:
            if ext['extnID'] == OID_SAN:
                der = ext['extnValue']
                if pyasn1.__version__.startswith('0.3'):
                    # pyasn1 <= 0.3.7 needs explicit unwrap of ANY container
                    # see https://pagure.io/freeipa/issue/7685
                    der = decoder.decode(der, asn1Spec=univ.OctetString())[0]
                gns = decoder.decode(der, asn1Spec=rfc2459.SubjectAltName())[0]
                break
        return gns

    @property
    def san_a_label_dns_names(self):
        gns = self.__pyasn1_get_san_general_names()
        result = []

        for gn in gns:
            if gn.getName() == 'dNSName':
                result.append(unicode(gn.getComponent()))

        return result

    def match_hostname(self, hostname):
        match_cert = {}

        match_cert['subject'] = match_subject = []
        for rdn in self._cert.subject.rdns:
            match_rdn = []
            for ava in rdn:
                if ava.oid == crypto_x509.oid.NameOID.COMMON_NAME:
                    match_rdn.append(('commonName', ava.value))
            match_subject.append(match_rdn)

        values = self.san_a_label_dns_names
        if values:
            match_cert['subjectAltName'] = match_san = []
            for value in values:
                match_san.append(('DNS', value))

        ssl.match_hostname(match_cert, DNSName(hostname).ToASCII())


def load_pem_x509_certificate(data):
    """
    Load an X.509 certificate in PEM format.

    :returns: a ``IPACertificate`` object.
    :raises: ``ValueError`` if unable to load the certificate.
    """
    return IPACertificate(
        crypto_x509.load_pem_x509_certificate(data, backend=default_backend())
    )


def load_der_x509_certificate(data):
    """
    Load an X.509 certificate in DER format.

    :returns: a ``IPACertificate`` object.
    :raises: ``ValueError`` if unable to load the certificate.
    """
    return IPACertificate(
        crypto_x509.load_der_x509_certificate(data, backend=default_backend())
    )


def load_unknown_x509_certificate(data):
    """
    Only use this function when you can't be sure what kind of format does
    your certificate have, e.g. input certificate files in installers

    :returns: a ``IPACertificate`` object.
    :raises: ``ValueError`` if unable to load the certificate.
    """
    try:
        return load_pem_x509_certificate(data)
    except ValueError:
        return load_der_x509_certificate(data)


def load_certificate_from_file(filename):
    """
    Load a certificate from a PEM file.

    Returns a python-cryptography ``Certificate`` object.
    """
    with open(filename, mode='rb') as f:
        return load_pem_x509_certificate(f.read())


def load_certificate_list(data):
    """
    Load a certificate list from a sequence of concatenated PEMs.

    Return a list of python-cryptography ``Certificate`` objects.
    """
    certs = PEM_CERT_REGEX.findall(data)
    return [load_pem_x509_certificate(cert) for cert in certs]


def load_certificate_list_from_file(filename):
    """
    Load a certificate list from a PEM file.

    Return a list of python-cryptography ``Certificate`` objects.

    """
    with open(filename, 'rb') as f:
        return load_certificate_list(f.read())


def load_private_key_list(data, password=None):
    """
    Load a private key list from a sequence of concatenated PEMs.

    :param data: bytes containing the private keys
    :param password: bytes, the password to encrypted keys in the bundle

    :returns: List of python-cryptography ``PrivateKey`` objects
    """
    crypto_backend = default_backend()
    priv_keys = []

    for match in re.finditer(PEM_PRIV_REGEX, data):
        if re.search(b"ENCRYPTED", match.group()) is not None:
            if password is None:
                raise RuntimeError("Password is required for the encrypted "
                                   "keys in the bundle.")
            # Load private key as encrypted
            priv_keys.append(
                load_pem_private_key(match.group(), password,
                                     backend=crypto_backend))
        else:
            priv_keys.append(
                load_pem_private_key(match.group(), None,
                                     backend=crypto_backend))

    return priv_keys


def pkcs7_to_certs(data, datatype=PEM):
    """
    Extract certificates from a PKCS #7 object.

    :returns: a ``list`` of ``IPACertificate`` objects.
    """
    if datatype == PEM:
        match = re.match(
            br'-----BEGIN PKCS7-----(.*?)-----END PKCS7-----',
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
        certificate = load_der_x509_certificate(certificate)
        result.append(certificate)

    return result


def validate_pem_x509_certificate(cert):
    """
    Perform cert validation by trying to load it via python-cryptography.
    """
    try:
        load_pem_x509_certificate(cert)
    except ValueError as e:
        raise errors.CertificateFormatError(error=str(e))


def validate_der_x509_certificate(cert):
    """
    Perform cert validation by trying to load it via python-cryptography.
    """
    try:
        load_der_x509_certificate(cert)
    except ValueError as e:
        raise errors.CertificateFormatError(error=str(e))


def write_certificate(cert, filename):
    """
    Write the certificate to a file in PEM format.

    :param cert: cryptograpy ``Certificate`` object
    """

    try:
        with open(filename, 'wb') as fp:
            fp.write(cert.public_bytes(Encoding.PEM))
    except (IOError, OSError) as e:
        raise errors.FileError(reason=str(e))


def write_certificate_list(certs, filename, mode=None):
    """
    Write a list of certificates to a file in PEM format.

    :param certs: a list of IPACertificate objects to be written to a file
    :param filename: a path to the file the certificates should be written into
    """

    try:
        with open(filename, 'wb') as f:
            if mode is not None:
                os.fchmod(f.fileno(), mode)
            for cert in certs:
                f.write(cert.public_bytes(Encoding.PEM))
    except (IOError, OSError) as e:
        raise errors.FileError(reason=str(e))


def write_pem_private_key(priv_key, filename, passwd=None):
    """
    Write a private key to a file in PEM format. Will force 0x600 permissions
    on file.

    :param priv_key: cryptography ``PrivateKey`` object
    :param passwd: ``bytes`` representing the password to store the
                    private key with
    """
    if passwd is not None:
        enc_alg = serialization.BestAvailableEncryption(passwd)
    else:
        enc_alg = serialization.NoEncryption()
    try:
        with open(filename, 'wb') as fp:
            os.fchmod(fp.fileno(), 0o600)
            fp.write(priv_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc_alg))
    except (IOError, OSError) as e:
        raise errors.FileError(reason=str(e))


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


class KRB5PrincipalName(crypto_x509.general_name.OtherName):
    def __init__(self, type_id, value):
        super(KRB5PrincipalName, self).__init__(type_id, value)
        self.name = _decode_krb5principalname(value)


class UPN(crypto_x509.general_name.OtherName):
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
        if isinstance(gn, crypto_x509.general_name.OtherName):
            cls = OTHERNAME_CLASS_MAP.get(
                gn.type_id.dotted_string,
                crypto_x509.general_name.OtherName)
            yield cls(gn.type_id, gn.value)
        else:
            yield gn


def _pyasn1_to_cryptography_directoryname(dn):
    attrs = []

    # Name is CHOICE { RDNSequence } (only one possibility)
    for rdn in dn.getComponent():
        for ava in rdn:
            attr = crypto_x509.NameAttribute(
                _pyasn1_to_cryptography_oid(ava['type']),
                unicode(decoder.decode(ava['value'])[0])
            )
            attrs.append(attr)

    return crypto_x509.DirectoryName(crypto_x509.Name(attrs))


def _pyasn1_to_cryptography_registeredid(oid):
    return crypto_x509.RegisteredID(_pyasn1_to_cryptography_oid(oid))


def _pyasn1_to_cryptography_ipaddress(octet_string):
    return crypto_x509.IPAddress(
        ipaddress.ip_address(bytes(octet_string)))


def _pyasn1_to_cryptography_othername(on):
    return crypto_x509.OtherName(
        _pyasn1_to_cryptography_oid(on['type-id']),
        bytes(on['value'])
    )


def _pyasn1_to_cryptography_oid(oid):
    return crypto_x509.ObjectIdentifier(str(oid))


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
