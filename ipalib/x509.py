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
import re

import synta
import synta.general_name as gn
import synta.krb5 as _krb5
import synta.oids
import synta.oids.attr as name_oids
import six

try:
    from urllib3.util import ssl_match_hostname
except ImportError:
    from urllib3.packages import ssl_match_hostname

from ipalib import errors
from ipapython.dnsutil import DNSName as _IPADnsName

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


class Encoding(enum.Enum):
    """Encoding sentinel used by public_bytes()."""
    PEM = "PEM"
    DER = "DER"


EKU_SERVER_AUTH = str(synta.oids.KP_SERVER_AUTH)
EKU_CLIENT_AUTH = str(synta.oids.KP_CLIENT_AUTH)
EKU_CODE_SIGNING = str(synta.oids.KP_CODE_SIGNING)
EKU_EMAIL_PROTECTION = str(synta.oids.KP_EMAIL_PROTECTION)
EKU_PKINIT_CLIENT_AUTH = str(synta.oids.PKINIT_KP_CLIENT_AUTH)
EKU_PKINIT_KDC = str(synta.oids.PKINIT_KP_KDC)
EKU_ANY = str(synta.oids.ANY_EXTENDED_KEY_USAGE)
EKU_PLACEHOLDER = '1.3.6.1.4.1.3319.6.10.16'

SAN_UPN = str(synta.oids.MS_SAN_UPN)
SAN_KRB5PRINCIPALNAME = str(synta.oids.PKINIT_SAN)


# GeneralName types — re-export synta.general_name types for convenience.
# Callers that previously imported from ipalib.x509 continue to work.
# Note: ipapython.dnsutil.DNSName is imported above as _IPADnsName to avoid
# shadowing this alias.
OtherName = gn.OtherName
RFC822Name = gn.RFC822Name
DNSName = gn.DNSName
DirectoryName = gn.DirectoryName
UniformResourceIdentifier = gn.UniformResourceIdentifier
IPAddress = gn.IPAddress
RegisteredID = gn.RegisteredID


class IPACertificate:
    """
    A proxy class wrapping a synta.Certificate representation for IPA purposes.
    """
    def __init__(self, cert):
        """
        :param cert: A synta.Certificate object.
        """
        self._synta_cert = cert

        self._subject = self._synta_cert.subject_raw_der
        self._issuer = self._synta_cert.issuer_raw_der
        enc = synta.Encoder(synta.Encoding.DER)
        enc.encode_integer(self._synta_cert.serial_number)
        self._serial_number = enc.finish()

        # X.509 version field: v3 is encoded as integer 2
        if self._synta_cert.version != 2:
            raise ValueError(
                'X.509 v%d is not supported'
                % ((self._synta_cert.version or 0) + 1))

    def __getstate__(self):
        return {
            '_cert': self._synta_cert.to_der(),
            '_subject': self._subject,
            '_issuer': self._issuer,
            '_serial_number': self._serial_number,
        }

    def __setstate__(self, state):
        self._subject = state['_subject']
        self._issuer = state['_issuer']
        self._serial_number = state['_serial_number']
        self._synta_cert = synta.Certificate.from_der(state['_cert'])

    def __eq__(self, other):
        if isinstance(other, IPACertificate):
            return self._synta_cert.to_der() == other._synta_cert.to_der()
        elif isinstance(other, bytes):
            return self._synta_cert.to_der() == other
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self._synta_cert.to_der())

    def __encode_extension(self, oid, critical, value):
        # Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
        #                          extnValue OCTET STRING }
        inner = synta.Encoder(synta.Encoding.DER)
        inner.encode_oid(oid)
        if critical:
            inner.encode_boolean(True)
        inner.encode_octet_string(value)
        outer = synta.Encoder(synta.Encoding.DER)
        outer.encode_sequence(inner.finish())
        return outer.finish()

    def public_bytes(self, encoding):
        """
        Serializes the certificate to PEM or DER format.

        *encoding* may be an ``Encoding`` enum value or a plain string
        ``"PEM"`` / ``"DER"``.
        """
        enc_val = encoding.value if isinstance(encoding, Encoding) else encoding
        if enc_val == "PEM":
            return synta.Certificate.to_pem(self._synta_cert)
        return self._synta_cert.to_der()

    def is_self_signed(self):
        """
        :returns: True if this certificate is self-signed, False otherwise
        """
        return synta.name_der_equal(
            self._synta_cert.subject_raw_der,
            self._synta_cert.issuer_raw_der,
        )

    def fingerprint(self, algorithm):
        """
        Compute a fingerprint of the certificate.

        *algorithm* may be a string (``"sha256"``) or a
        any object with a ``.name`` attribute (e.g. ``hashes.SHA256()``).
        """
        if isinstance(algorithm, str):
            algo = algorithm.lower()
        else:
            algo = getattr(algorithm, 'name', str(algorithm)).lower()
        return self._synta_cert.fingerprint(algo)

    def get_extension_value_der(self, oid):
        """Return the raw DER value bytes of the named extension, or None."""
        return self._synta_cert.get_extension_value_der(oid)

    @property
    def cert(self):
        """The underlying synta.Certificate object."""
        return self._synta_cert

    def to_pyca(self):
        """Return a ``cryptography.x509.Certificate`` (PyCA) object.

        Use this when passing the certificate to a Dogtag or other third-party
        API that requires a PyCA object (e.g.
        ``pki.crypto.CryptographyCryptoProvider``).
        """
        return self._synta_cert.to_pyca()

    @property
    def serial_number(self):
        return self._synta_cert.serial_number

    @property
    def serial_number_bytes(self):
        return self._serial_number

    @property
    def version(self):
        """X.509 version as an integer (v3 = 2)."""
        return self._synta_cert.version

    @property
    def subject(self):
        """DER bytes of the subject Name SEQUENCE."""
        return self._subject

    @property
    def subject_bytes(self):
        return self._subject

    @property
    def issuer(self):
        """DER bytes of the issuer Name SEQUENCE."""
        return self._issuer

    @property
    def issuer_bytes(self):
        return self._issuer

    @property
    def signature_hash_algorithm(self):
        """
        Returns the hash algorithm name string used to sign the certificate,
        or None for algorithms without a separate hash (e.g. Ed25519).
        """
        return self._synta_cert.signature_hash_algorithm_name

    @property
    def signature_algorithm_oid(self):
        """Returns the synta.ObjectIdentifier of the signature algorithm."""
        return self._synta_cert.signature_algorithm_oid

    @property
    def signature_algorithm_parameters(self):
        """Raw DER bytes of signature algorithm parameters, or None."""
        return self._synta_cert.signature_algorithm_params

    @property
    def signature(self):
        """Returns the signature bytes."""
        return self._synta_cert.signature_value

    @property
    def not_valid_before(self):
        return self._synta_cert.not_before_utc

    @property
    def not_valid_after(self):
        return self._synta_cert.not_after_utc

    @property
    def not_valid_before_utc(self):
        return self._synta_cert.not_before_utc

    @property
    def not_valid_after_utc(self):
        return self._synta_cert.not_after_utc

    @property
    def public_key_algorithm_oid(self):
        """Returns the synta.ObjectIdentifier of the public key algorithm."""
        return self._synta_cert.public_key_algorithm_oid

    @property
    def tbs_certificate_bytes(self):
        return self._synta_cert.tbs_certificate_der

    def public_key(self):
        """Return the public key as a synta.PublicKey object."""
        return synta.PublicKey.from_der(
            self._synta_cert.subject_public_key_info_der)

    @property
    def public_key_info_bytes(self):
        return self._synta_cert.subject_public_key_info_der

    @property
    def extended_key_usage(self):
        eku_der = self._synta_cert.get_extension_value_der(
            synta.oids.EXTENDED_KEY_USAGE)
        if eku_der is None:
            return None
        seq = synta.Decoder(eku_der, synta.Encoding.DER).decode_sequence()
        oids = set()
        while not seq.is_empty():
            oids.add(str(seq.decode_oid()))
        return oids

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
        return self.__encode_extension(
            synta.oids.EXTENDED_KEY_USAGE, EKU_ANY not in eku, ekurfc)

    @property
    def san_general_names(self):
        """
        Return SAN general names as typed ``synta.general_name`` objects.
        If the SAN extension is not present, return an empty list.

        OtherName types are NOT resolved to more specific types here.
        Use ``process_othernames`` to do that.
        """
        return list(self._synta_cert.subject_alt_names())

    @property
    def san_a_label_dns_names(self):
        return [item.value for item in self.san_general_names
                if isinstance(item, gn.DNSName)]

    def match_hostname(self, hostname):
        # The caller is expected to catch any exceptions
        match_cert = {}

        match_cert['subject'] = match_subject = []
        cn_oid = str(name_oids.COMMON_NAME)
        for oid_str, val in synta.parse_name_attrs(self._subject):
            if oid_str == cn_oid:
                match_subject.append([('commonName', val)])

        values = self.san_a_label_dns_names
        if values:
            match_cert['subjectAltName'] = [('DNS', v) for v in values]

        ssl_match_hostname.match_hostname(
            match_cert, _IPADnsName(hostname).ToASCII()
        )

    def verify_directly_issued_by(self, issuer):
        if isinstance(issuer, IPACertificate):
            return self._synta_cert.verify_issued_by(issuer._synta_cert)
        return self._synta_cert.verify_issued_by(issuer)




def load_pem_x509_certificate(data):
    """
    Load an X.509 certificate in PEM format.

    :returns: a ``IPACertificate`` object.
    :raises: ``ValueError`` if unable to load the certificate.
    """
    if isinstance(data, IPACertificate):
        return data
    return IPACertificate(synta.Certificate.from_pem(data))


def load_der_x509_certificate(data):
    """
    Load an X.509 certificate in DER format.

    :returns: a ``IPACertificate`` object.
    :raises: ``ValueError`` if unable to load the certificate.
    """
    if isinstance(data, IPACertificate):
        return data
    return IPACertificate(synta.Certificate.from_der(data))


def load_unknown_x509_certificate(data):
    """
    Only use this function when you can't be sure what kind of format does
    your certificate have, e.g. input certificate files in installers

    :returns: a ``IPACertificate`` object.
    :raises: ``ValueError`` if unable to load the certificate.
    """
    if isinstance(data, IPACertificate):
        return data
    blocks = synta.read_pki_blocks(data)
    if not blocks:
        raise ValueError("no certificate found in data")
    _label, der = blocks[0]
    return IPACertificate(synta.Certificate.from_der(der))


def load_certificate_from_file(filename):
    """
    Load a certificate from a PEM file.

    Returns an ``IPACertificate`` object.
    """
    with open(filename, mode='rb') as f:
        return load_pem_x509_certificate(f.read())


def load_certificate_list(data):
    """
    Load a certificate list from a sequence of concatenated PEMs.

    Return a list of ``IPACertificate`` objects.
    """
    return [IPACertificate(synta.Certificate.from_der(der))
            for label, der in synta.read_pki_blocks(data)
            if label == "CERTIFICATE"]


def load_certificate_list_from_file(filename):
    """
    Load a certificate list from a PEM file.

    Return a list of ``IPACertificate`` objects.
    """
    with open(filename, 'rb') as f:
        return load_certificate_list(f.read())


def load_private_key_list(data, password=None):
    """
    Load a private key list from a sequence of concatenated PEMs.

    :param data: bytes containing the private keys
    :param password: bytes, the password to encrypted keys in the bundle

    :returns: List of ``synta.PrivateKey`` objects
    """
    priv_keys = []

    for match in re.finditer(PEM_PRIV_REGEX, data):
        is_encrypted = re.search(b"ENCRYPTED", match.group()) is not None
        if is_encrypted and password is None:
            raise RuntimeError("Password is required for the encrypted "
                               "keys in the bundle.")
        pw = password if is_encrypted else None
        priv_keys.append(synta.PrivateKey.from_pem(match.group(), pw))

    return priv_keys


def pkcs7_to_certs(data, datatype=PEM):
    """
    Extract certificates from a PKCS #7 object.

    *datatype* is accepted for API compatibility but is no longer used:
    ``synta.read_pki_blocks`` auto-detects PEM, PKCS#7, PKCS#12, and raw DER.

    :returns: a ``list`` of ``IPACertificate`` objects.
    """
    return [IPACertificate(synta.Certificate.from_der(der))
            for label, der in synta.read_pki_blocks(data)
            if label == "CERTIFICATE"]


def validate_pem_x509_certificate(cert):
    """
    Perform cert validation by trying to load it.
    """
    try:
        load_pem_x509_certificate(cert)
    except ValueError as e:
        raise errors.CertificateFormatError(error=str(e))


def validate_der_x509_certificate(cert):
    """
    Perform cert validation by trying to load it.
    """
    try:
        load_der_x509_certificate(cert)
    except ValueError as e:
        raise errors.CertificateFormatError(error=str(e))


def write_certificate(cert, filename):
    """
    Write the certificate to a file in PEM format.

    :param cert: ``IPACertificate`` object
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

    :param priv_key: ``synta.PrivateKey`` object
    :param passwd: ``bytes`` representing the password to store the
                    private key with
    """
    try:
        with open(filename, 'wb') as fp:
            os.fchmod(fp.fileno(), 0o600)
            fp.write(priv_key.to_pem(password=passwd))
    except (IOError, OSError) as e:
        raise errors.FileError(reason=str(e))


# KRB5PrincipalName and UPN are provided by synta.krb5.
KRB5PrincipalName = _krb5.Krb5PrincipalName
UPN = _krb5.UPN

OTHERNAME_CLASS_MAP = {
    SAN_KRB5PRINCIPALNAME: KRB5PrincipalName,
    SAN_UPN: UPN,
}


def process_othernames(gns):
    """
    Yield GeneralName objects, resolving ``OtherName`` entries whose type-id
    is known to a more specific type (``KRB5PrincipalName`` or ``UPN``).

    *gns* must be a list of typed ``synta.general_name`` objects as returned
    by ``cert.san_general_names`` or ``cert.subject_alt_names()``.
    """
    for item in gns:
        if isinstance(item, gn.OtherName):
            oid_str = str(item.type_id)
            cls = OTHERNAME_CLASS_MAP.get(oid_str)
            if cls is not None:
                yield cls.from_der(item.value)
            else:
                yield item
        else:
            yield item


# Module-level state for _parse_san_tuples: a throwaway EC key and name
# used to wrap CSR SAN tuples into a temporary cert for typed GN parsing.
_san_parse_key = None
_san_parse_name = None


def _parse_san_tuples(san_tuples):
    """Convert (tag, bytes) SAN tuples from
    ``CertificationRequest.subject_alt_names()`` into typed
    ``synta.general_name`` objects suitable for ``process_othernames()``.

    ``CertificationRequest.subject_alt_names()`` returns raw ``(int, bytes)``
    tuples; this helper re-encodes them as a SAN extension DER value and
    parses it through a throwaway certificate to obtain the same typed
    ``synta.general_name`` objects that ``Certificate.general_names()``
    produces.
    """
    global _san_parse_key, _san_parse_name
    if _san_parse_key is None:
        _san_parse_key = synta.PrivateKey.generate_ec('P-256')
        _san_parse_name = (
            synta.NameBuilder().common_name(u'_ipa').build()
        )
    san_der = synta.encode_subject_alt_names(san_tuples)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cert = synta.Certificate.from_der(synta.Certificate.to_der(
        synta.CertificateBuilder()
        .serial_number(1)
        .issuer_name(_san_parse_name)
        .subject_name(_san_parse_name)
        .public_key(_san_parse_key.public_key)
        .not_valid_before_utc(now)
        .not_valid_after_utc(now + datetime.timedelta(days=1))
        .add_extension(
            str(synta.oids.SUBJECT_ALT_NAME), False, san_der)
        .sign(_san_parse_key, 'sha256')
    ))
    return list(cert.subject_alt_names())


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
    ext_oid = str(synta.oids.MS_CERTIFICATE_TEMPLATE_NAME)

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
    ext_oid = str(synta.oids.MS_CERTIFICATE_TEMPLATE)

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
