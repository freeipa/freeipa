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
import enum
import ipaddress
import base64
import re

from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, load_pem_private_key
)
import synta
import synta.general_name as gn
import six

try:
    from urllib3.util import ssl_match_hostname
except ImportError:
    from urllib3.packages import ssl_match_hostname

from ipalib import errors
from ipapython.dnsutil import DNSName

PEM = 0
DER = 1

# The first group is the whole PEM datum and the second group is
# the base64 content (with newlines).  For findall() the result is
# a list of 2-tuples of the PEM and base64 data.
PEM_CERT_REGEX = re.compile(
    b'(-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----)',
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


class IPACertificate:
    """
    A proxy class wrapping a python-cryptography certificate representation for
    IPA purposes
    """
    def __init__(self, cert, backend=None):
        """
        :param cert: A python-cryptography Certificate object
        :param backend: A python-cryptography Backend object
        """
        self._cert = cert
        self.backend = default_backend() if backend is None else backend()
        # Cache the synta Certificate view once; from_pyca() is a DER
        # round-trip so calling it on every san_general_names access is wasteful
        self._synta_cert = synta.Certificate.from_pyca(cert)

        # initialize the certificate fields
        self._subject = self._cert.subject.public_bytes()
        self._issuer = self._cert.issuer.public_bytes()
        _enc = synta.Encoder(synta.Encoding.DER)
        _enc.encode_integer(self._cert.serial_number)
        self._serial_number = _enc.finish()

        if self.version.name != 'v3':
            raise ValueError('X.509 %s is not supported' %
                             self.version.name)

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
        self._serial_number = state['_serial_number']
        self._cert = crypto_x509.load_der_x509_certificate(
            state['_cert'], backend=default_backend())
        self._synta_cert = synta.Certificate.from_der(state['_cert'])

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
        # Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
        #                          extnValue OCTET STRING }
        inner = synta.Encoder(synta.Encoding.DER)
        inner.encode_oid(synta.ObjectIdentifier(oid))
        if critical:
            inner.encode_boolean(True)
        inner.encode_octet_string(value)
        outer = synta.Encoder(synta.Encoding.DER)
        outer.encode_sequence(inner.finish())
        return outer.finish()

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
    def cert(self):
        return self._cert

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

    if hasattr(crypto_x509.Certificate, "signature_algorithm_parameters"):
        # added in python-cryptography 41.0
        @property
        def signature_algorithm_parameters(self):
            return self._cert.signature_algorithm_parameters

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
        return self._cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

    @property
    def not_valid_after(self):
        return self._cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    if hasattr(crypto_x509.Certificate, "not_valid_before_utc"):
        # added in python-cryptography 42.0.0
        @property
        def not_valid_before_utc(self):
            return self._cert.not_valid_before_utc

        @property
        def not_valid_after_utc(self):
            return self._cert.not_valid_after_utc
    else:
        @property
        def not_valid_before_utc(self):
            return self._cert.not_valid_before.replace(
                tzinfo=datetime.timezone.utc
            )

        @property
        def not_valid_after_utc(self):
            return self._cert.not_valid_after.replace(
                tzinfo=datetime.timezone.utc
            )

    if hasattr(crypto_x509.Certificate, "public_key_algorithm_oid"):
        # added in python-cryptography 43.0.0
        @property
        def public_key_algorithm_oid(self):
            """
            Returns the ObjectIdentifier of the public key.
            """
            return self._cert.public_key_algorithm_oid

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

        # ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
        inner = synta.Encoder(synta.Encoding.DER)
        for oid in sorted(eku):
            inner.encode_oid(synta.ObjectIdentifier(oid))
        outer = synta.Encoder(synta.Encoding.DER)
        outer.encode_sequence(inner.finish())
        ekurfc = outer.finish()
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
        return self.__get_san_general_names()

    def __get_san_general_names(self):
        """
        Parse the SubjectAltName extension using synta.

        Certificate.subject_alt_names() combines the SAN extension lookup
        with GeneralName parsing, returning (tag_number, content_bytes) pairs.
        Named tag constants live in synta.general_name (imported as gn).

        [3] x400Address and [5] ediPartyName are not supported by
        python-cryptography and are silently skipped.
        """
        result = []
        for tag_num, raw in self._synta_cert.subject_alt_names():
            if tag_num == gn.OTHER_NAME:
                # OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
                on_dec = synta.Decoder(raw, synta.Encoding.DER)
                oid_obj = on_dec.decode_oid()
                val_child = on_dec.decode_explicit_tag(0)
                on_val_raw = val_child.remaining_bytes()
                oid = crypto_x509.ObjectIdentifier(str(oid_obj))
                result.append(crypto_x509.OtherName(oid, on_val_raw))
            elif tag_num == gn.RFC822_NAME:
                result.append(crypto_x509.RFC822Name(raw.decode("ascii")))
            elif tag_num == gn.DNS_NAME:
                result.append(crypto_x509.DNSName(raw.decode("ascii")))
            elif tag_num == gn.DIRECTORY_NAME:
                result.append(
                    crypto_x509.DirectoryName(_parse_directory_name(raw)))
            elif tag_num == gn.URI:
                result.append(
                    crypto_x509.UniformResourceIdentifier(raw.decode("ascii")))
            elif tag_num == gn.IP_ADDRESS:
                result.append(
                    crypto_x509.IPAddress(ipaddress.ip_address(raw)))
            elif tag_num == gn.REGISTERED_ID:
                oid = crypto_x509.ObjectIdentifier(
                    str(synta.ObjectIdentifier.from_der_value(raw)))
                result.append(crypto_x509.RegisteredID(oid))
        return result

    @property
    def san_a_label_dns_names(self):
        result = []
        for gn in self.__get_san_general_names():
            if isinstance(gn, crypto_x509.DNSName):
                result.append(gn.value)
        return result

    def match_hostname(self, hostname):
        # The caller is expected to catch any exceptions
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

        ssl_match_hostname.match_hostname(
            match_cert, DNSName(hostname).ToASCII()
        )

    # added in python-cryptography 38.0
    @property
    def tbs_precertificate_bytes(self):
        return self._cert.tbs_precertificate_bytes

    if hasattr(crypto_x509.Certificate, "verify_directly_issued_by"):
        # added in python-cryptography 40.0
        def verify_directly_issued_by(self, issuer):
            return self._cert.verify_directly_issued_by(issuer)


def load_pem_x509_certificate(data):
    """
    Load an X.509 certificate in PEM format.

    :returns: a ``IPACertificate`` object.
    :raises: ``ValueError`` if unable to load the certificate.
    """
    if isinstance(data, IPACertificate):
        return data
    return IPACertificate(
        crypto_x509.load_pem_x509_certificate(data, backend=default_backend())
    )


def load_der_x509_certificate(data):
    """
    Load an X.509 certificate in DER format.

    :returns: a ``IPACertificate`` object.
    :raises: ``ValueError`` if unable to load the certificate.
    """
    if isinstance(data, IPACertificate):
        return data
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
    return [load_pem_x509_certificate(cert[0]) for cert in certs]


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
                PrivateFormat.PKCS8,
                encryption_algorithm=enc_alg))
    except (IOError, OSError) as e:
        raise errors.FileError(reason=str(e))


def _decode_krb5principalname(data):
    """
    Decode a KRB5PrincipalName (RFC 4556) from DER bytes.

    Returns the principal string in the form ``name@REALM``, with
    backslash, slash, and at-sign characters escaped.
    """
    import synta.krb5
    p = synta.krb5.Krb5PrincipalName.from_der(data)
    realm = p.realm.replace('\\', '\\\\').replace('@', '\\@')
    parts = [s.replace('\\', '\\\\').replace('/', '\\/').replace('@', '\\@')
             for s in p.components]
    return u'%s@%s' % (u'/'.join(parts), realm)


class KRB5PrincipalName(crypto_x509.general_name.OtherName):
    def __init__(self, type_id, value):
        super(KRB5PrincipalName, self).__init__(type_id, value)
        self.name = _decode_krb5principalname(value)


class UPN(crypto_x509.general_name.OtherName):
    def __init__(self, type_id, value):
        super(UPN, self).__init__(type_id, value)
        self.name = synta.Decoder(value, synta.Encoding.DER).decode_any_str()


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


def _parse_directory_name(raw):
    """
    Parse a Name (RDNSequence) from the raw content bytes of the [4] tag
    in a directoryName GeneralName.

    In RFC 5280, Name is a CHOICE type; the [4] tag effectively wraps the
    full Name encoding, so *raw* contains the RDNSequence SEQUENCE TLV:
      ``30 <len> 31 <len> ...``

    Returns a ``cryptography.x509.Name`` object.
    """
    return crypto_x509.Name([
        crypto_x509.NameAttribute(crypto_x509.ObjectIdentifier(oid), val)
        for oid, val in synta.parse_name_attrs(raw)
    ])


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
    return str(t.strftime("%a %b %d %H:%M:%S %Y %Z"))


class ExternalCAType(enum.Enum):
    GENERIC = 'generic'
    MS_CS = 'ms-cs'


class ExternalCAProfile:
    """
    An external CA profile configuration.  Currently the only
    subclasses are for Microsoft CAs, for providing data in the
    "Certificate Template" extension.

    Constructing this class will actually return an instance of a
    subclass.

    Subclasses MUST set ``valid_for``.

    """
    def __init__(self, s=None):
        self.unparsed_input = s

    # Which external CA types is the data valid for?
    # A set of VALUES of the ExternalCAType enum.
    valid_for = set()

    def __new__(cls, s=None):
        """Construct the ExternalCAProfile value.

        Return an instance of a subclass determined by
        the format of the argument.

        """
        # we are directly constructing a subclass; instantiate
        # it and be done
        if cls is not ExternalCAProfile:
            return super(ExternalCAProfile, cls).__new__(cls)

        # construction via the base class; therefore the string
        # argument is required, and is used to determine which
        # subclass to construct
        if s is None:
            raise ValueError('string argument is required')

        parts = s.split(':')

        try:
            # Is the first part an OID?
            synta.ObjectIdentifier(parts[0])

            # It is; construct a V2 template
            return MSCSTemplateV2.__new__(MSCSTemplateV2, s)

        except ValueError:
            # It is not an OID; treat as a template name
            return MSCSTemplateV1.__new__(MSCSTemplateV1, s)

    def __getstate__(self):
        return self.unparsed_input

    def __setstate__(self, state):
        # explicitly call __init__ method to initialise object
        self.__init__(state)


class MSCSTemplate(ExternalCAProfile):
    """
    An Microsoft AD-CS Template specifier.

    Subclasses MUST set ext_oid.

    """
    valid_for = set([ExternalCAType.MS_CS.value])

    ext_oid = None  # extension OID, as a Python str

    def get_ext_data(self):
        """Return DER-encoded extension data."""
        raise NotImplementedError


class MSCSTemplateV1(MSCSTemplate):
    """
    A v1 template specifier, per
    https://msdn.microsoft.com/en-us/library/cc250011.aspx.

    ::

        CertificateTemplateName ::= SEQUENCE {
           Name            UTF8String
        }

    But note that a bare BMPString is used in practice.

    """
    ext_oid = "1.3.6.1.4.1.311.20.2"

    def __init__(self, s):
        super(MSCSTemplateV1, self).__init__(s)
        parts = s.split(':')
        if len(parts) > 1:
            raise ValueError(
                "Cannot specify certificate template version when using name.")
        self._template_name = str(parts[0])

    def get_ext_data(self):
        """Return DER-encoded BMPString of the template name."""
        enc = synta.Encoder(synta.Encoding.DER)
        enc.encode_bmp_string(self._template_name)
        return enc.finish()


class MSCSTemplateV2(MSCSTemplate):
    """
    A v2 template specifier, per
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378274(v=vs.85).aspx

    ::

        CertificateTemplate ::= SEQUENCE {
            templateID              EncodedObjectID,
            templateMajorVersion    TemplateVersion,
            templateMinorVersion    TemplateVersion OPTIONAL
        }

        TemplateVersion ::= INTEGER (0..4294967295)

    """
    ext_oid = "1.3.6.1.4.1.311.21.7"

    @staticmethod
    def check_version_in_range(desc, n):
        if n < 0 or n >= 2**32:
            raise ValueError(
                "Template {} version must be in range 0..4294967295"
                .format(desc))

    def __init__(self, s):
        super(MSCSTemplateV2, self).__init__(s)

        parts = s.split(':')

        if len(parts) < 2 or len(parts) > 3:
            raise ValueError(
                "Incorrect template specification; required format is: "
                "<oid>:<majorVersion>[:<minorVersion>]")

        try:
            synta.ObjectIdentifier(parts[0])
        except ValueError:
            raise ValueError("Could not parse certificate template specifier.")
        self._template_oid = parts[0]

        major = int(parts[1])
        self.check_version_in_range("major", major)
        self._major = major

        if len(parts) > 2:
            minor = int(parts[2])
            self.check_version_in_range("minor", minor)
            self._minor = minor
        else:
            self._minor = None

    def get_ext_data(self):
        """
        Return DER-encoded CertificateTemplate SEQUENCE:
            SEQUENCE { OID, INTEGER, INTEGER OPTIONAL }
        """
        inner = synta.Encoder(synta.Encoding.DER)
        inner.encode_oid(synta.ObjectIdentifier(self._template_oid))
        inner.encode_integer(self._major)
        if self._minor is not None:
            inner.encode_integer(self._minor)
        outer = synta.Encoder(synta.Encoding.DER)
        outer.encode_sequence(inner.finish())
        return outer.finish()
