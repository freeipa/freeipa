# Authors: Nathaniel McCallum <npmccallum@redhat.com>
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

from __future__ import absolute_import

import abc
import base64
import datetime
import logging
import os
import uuid

from lxml import etree
import dateutil.parser
import dateutil.tz
import gssapi
import six

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ipaplatform.paths import paths
from ipapython import admintool
from ipalib import api, errors
from ipaserver.plugins.ldap2 import AUTOBIND_DISABLED

if six.PY3:
    unicode = str
    long = int

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    pass


def fetchAll(element, xpath, conv=lambda x: x):
    return [conv(e) for e in element.xpath(xpath, namespaces={
        "pkcs5": "http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#",
        "pskc": "urn:ietf:params:xml:ns:keyprov:pskc",
        "xenc11": "http://www.w3.org/2009/xmlenc11#",
        "xenc": "http://www.w3.org/2001/04/xmlenc#",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    })]


def fetch(element, xpath, conv=lambda x: x, default=None):
    result = fetchAll(element, xpath, conv)
    return result[0] if result else default


def convertDate(value):
    "Converts an ISO 8601 string into a UTC datetime object."

    dt = dateutil.parser.parse(value)

    # pylint: disable=E1101
    if dt.tzinfo is None:
        dt = datetime.datetime(*dt.timetuple()[0:6],
                               tzinfo=dateutil.tz.tzlocal())

    return dt.astimezone(dateutil.tz.tzutc())


def convertTokenType(value):
    "Converts token algorithm URI to token type string."

    return {
        "urn:ietf:params:xml:ns:keyprov:pskc:hotp": u"hotp",
        "urn:ietf:params:xml:ns:keyprov:pskc#hotp": u"hotp",
        "urn:ietf:params:xml:ns:keyprov:pskc:totp": u"totp",
        "urn:ietf:params:xml:ns:keyprov:pskc#totp": u"totp",
    }.get(value.lower(), None)


def convertHashName(value):
    "Converts hash names to their canonical names."

    default_hash = u"sha1"
    known_prefixes = ("", "hmac-",)
    known_hashes = {
        "sha1":    u"sha1",
        "sha224":  u"sha224",
        "sha256":  u"sha256",
        "sha384":  u"sha384",
        "sha512":  u"sha512",
        "sha-1":   u"sha1",
        "sha-224": u"sha224",
        "sha-256": u"sha256",
        "sha-384": u"sha384",
        "sha-512": u"sha512",
    }

    if value is None:
        return default_hash

    v = value.lower()
    for prefix in known_prefixes:
        if prefix:
            w = v[len(prefix):]
        else:
            w = v
        result = known_hashes.get(w)
        if result is not None:
            break
    else:
        result = default_hash

    return result


def convertHMACType(value):
    "Converts HMAC URI to hashlib object."

    return {
        "http://www.w3.org/2000/09/xmldsig#hmac-sha1":        hashes.SHA1,
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224": hashes.SHA224,
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256": hashes.SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384": hashes.SHA384,
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512": hashes.SHA512,
    }.get(value.lower(), hashes.SHA1)


def convertAlgorithm(value):
    "Converts encryption URI to (mech, ivlen)."

    return {
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc": (
            algorithms.AES, modes.CBC, 128),
        "http://www.w3.org/2001/04/xmlenc#aes192-cbc": (
            algorithms.AES, modes.CBC, 192),
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc": (
            algorithms.AES, modes.CBC, 256),
        "http://www.w3.org/2001/04/xmlenc#tripledes-cbc": (
            algorithms.TripleDES, modes.CBC, 64),
        "http://www.w3.org/2001/04/xmldsig-more#camellia128": (
            algorithms.Camellia, modes.CBC, 128),
        "http://www.w3.org/2001/04/xmldsig-more#camellia192": (
            algorithms.Camellia, modes.CBC, 192),
        "http://www.w3.org/2001/04/xmldsig-more#camellia256": (
            algorithms.Camellia, modes.CBC, 256),

        # TODO: add support for these formats.
        # "http://www.w3.org/2001/04/xmlenc#kw-aes128": "kw-aes128",
        # "http://www.w3.org/2001/04/xmlenc#kw-aes192": "kw-aes192",
        # "http://www.w3.org/2001/04/xmlenc#kw-aes256": "kw-aes256",
        # "http://www.w3.org/2001/04/xmlenc#kw-tripledes": "kw-tripledes",
        # "http://www.w3.org/2001/04/xmldsig-more#kw-camellia128": "kw-camellia128",
        # "http://www.w3.org/2001/04/xmldsig-more#kw-camellia192": "kw-camellia192",
        # "http://www.w3.org/2001/04/xmldsig-more#kw-camellia256": "kw-camellia256",
    }.get(value.lower(), (None, None, None))


def convertEncrypted(value, decryptor=None, pconv=base64.b64decode, econv=lambda x: x):
    "Converts a value element, decrypting if necessary. See RFC 6030."

    v = fetch(value, "./pskc:PlainValue/text()", pconv)
    if v is not None:
        return v

    mac = fetch(value, "./pskc:ValueMAC/text()", base64.b64decode)
    ev = fetch(value, "./pskc:EncryptedValue")
    if ev is not None and decryptor is not None:
        return econv(decryptor(ev, mac))

    return None


class XMLKeyDerivation(six.with_metaclass(abc.ABCMeta, object)):
    "Interface for XML Encryption 1.1 key derivation."
    @abc.abstractmethod
    def __init__(self, enckey):
        "Sets up key derivation parameters from the parent XML entity."

    @abc.abstractmethod
    def derive(self, masterkey):
        "Derives a key from the master key."


class PBKDF2KeyDerivation(XMLKeyDerivation):
    def __init__(self, enckey):
        params = fetch(enckey, "./xenc11:DerivedKey/xenc11:KeyDerivationMethod/pkcs5:PBKDF2-params")
        if params is None:
            raise ValueError("XML file is missing PBKDF2 parameters!")

        salt = fetch(params, "./Salt/Specified/text()", base64.b64decode)
        itrs = fetch(params, "./IterationCount/text()", int)
        klen = fetch(params, "./KeyLength/text()", int)
        hmod = fetch(params, "./PRF/@Algorithm", convertHMACType, hashes.SHA1)

        if salt is None:
            raise ValueError("XML file is missing PBKDF2 salt!")

        if itrs is None:
            raise ValueError("XML file is missing PBKDF2 iteration count!")

        if klen is None:
            raise ValueError("XML file is missing PBKDF2 key length!")

        self.kdf = pbkdf2.PBKDF2HMAC(
            algorithm=hmod(),
            length=klen,
            salt=salt,
            iterations=itrs,
            backend=default_backend()
        )

    def derive(self, masterkey):
        return self.kdf.derive(masterkey)


def convertKeyDerivation(value):
    "Converts key derivation URI to a BaseKeyDerivation class."

    return {
        "http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2": PBKDF2KeyDerivation,
    }.get(value.lower(), None)


class XMLDecryptor:
    """This decrypts values from XML as specified in:
        * http://www.w3.org/TR/xmlenc-core/
        * RFC 6931"""

    def __init__(self, key, hmac=None):
        self.__key = key
        self.__hmac = hmac

    def __call__(self, element, mac=None):
        algo, mode, klen = fetch(
            element, "./xenc:EncryptionMethod/@Algorithm", convertAlgorithm)
        data = fetch(
            element,
            "./xenc:CipherData/xenc:CipherValue/text()",
            base64.b64decode
        )

        # Make sure the key is the right length.
        if len(self.__key) * 8 != klen:
            raise ValidationError("Invalid key length!")

        # If a MAC is present, perform validation.
        if mac:
            tmp = self.__hmac.copy()
            tmp.update(data)
            try:
                tmp.verify(mac)
            except InvalidSignature as e:
                raise ValidationError("MAC validation failed!", e)

        iv = data[:algo.block_size // 8]
        data = data[len(iv):]

        algorithm = algo(self.__key)
        cipher = Cipher(algorithm, mode(iv), default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(data)
        padded += decryptor.finalize()

        unpadder = PKCS7(algorithm.block_size).unpadder()
        out = unpadder.update(padded)
        out += unpadder.finalize()

        return out


class PSKCKeyPackage:
    _XML = {
        'pskc:DeviceInfo': {
            'pskc:IssueNo/text()':      ('issueno',      unicode),
            'pskc:ExpiryDate/text()':   ('notafter.hw',  convertDate),
            'pskc:Manufacturer/text()': ('vendor',       unicode),
            'pskc:Model/text()':        ('model',        unicode),
            'pskc:SerialNo/text()':     ('serial',       unicode),
            'pskc:StartDate/text()':    ('notbefore.hw', convertDate),
            'pskc:UserId/text()':       ('owner',        unicode),
        },

        'pskc:Key': {
            '@Algorithm':               ('type',        convertTokenType),
            '@Id':                      ('id',          unicode),
            'pskc:FriendlyName/text()': ('description', unicode),
            'pskc:Issuer/text()':       ('issuer',      unicode),
            'pskc:KeyReference/text()': ('keyref',      unicode),

            'pskc:AlgorithmParameters': {
                'pskc:Suite/text()':               ('algorithm',  convertHashName),
                'pskc:ResponseFormat/@CheckDigit': ('checkdigit', unicode),
                'pskc:ResponseFormat/@Encoding':   ('encoding',   unicode),
                'pskc:ResponseFormat/@Length':     ('digits',     int),
            },

            'pskc:Data': {
                'pskc:Counter':      ('counter',  lambda v, d: convertEncrypted(v, d, long, long)),
                'pskc:Secret':       ('key',      convertEncrypted),
                'pskc:Time':         ('time',     lambda v, d: convertEncrypted(v, d, int, int)),
                'pskc:TimeDrift':    ('offset',   lambda v, d: convertEncrypted(v, d, int, int)),
                'pskc:TimeInterval': ('interval', lambda v, d: convertEncrypted(v, d, int, int)),
            },

            'pskc:Policy': {
                'pskc:ExpiryDate/text()':    ('notafter.sw',  convertDate),
                'pskc:KeyUsage/text()':      ('keyusage',     unicode),
                'pskc:NumberOfTransactions': ('maxtransact',  lambda v: v),
                'pskc:PINPolicy':            ('pinpolicy',    lambda v: v),
                'pskc:StartDate/text()':     ('notbefore.sw', convertDate),
            },
        },
    }

    _MAP = (
        ('type',        'type',                    lambda v, o: v.strip()),
        ('description', 'description',             lambda v, o: v.strip()),
        ('vendor',      'ipatokenvendor',          lambda v, o: v.strip()),
        ('model',       'ipatokenmodel',           lambda v, o: v.strip()),
        ('serial',      'ipatokenserial',          lambda v, o: v.strip()),
        ('issueno',     'ipatokenserial',          lambda v, o: o.get('ipatokenserial', '') + '-' + v.strip()),
        (
            'key',
            'ipatokenotpkey',
            lambda v, o: base64.b32encode(v).decode('ascii')
        ),
        ('digits',      'ipatokenotpdigits',       lambda v, o: v),
        ('algorithm',   'ipatokenotpalgorithm',    lambda v, o: v),
        ('counter',     'ipatokenhotpcounter',     lambda v, o: v),
        ('interval',    'ipatokentotptimestep',    lambda v, o: v),
        ('offset',      'ipatokentotpclockoffset', lambda v, o: o.get('ipatokentotptimestep', 30) * v),
    )

    def __init__(self, element, decryptor):
        self.__element = element
        self.__decryptor = decryptor
        self.__id = None
        self.__options = None

    @property
    def id(self):
        if self.__id is None:
            self.__process()

        return self.__id

    @property
    def options(self):
        if self.__options is None:
            self.__process()

        return self.__options

    def remove(self):
        self.__element.getparent().remove(self.__element)

    def __process(self):
        # Parse and validate.
        data = self.__parse(self.__decryptor, self.__element, ".", self._XML)
        self.__validate(data)

        # Copy values into output.
        options = {}
        for (dk, ok, f) in self._MAP:
            if dk in data:
                options[ok] = f(data[dk], options)

        # Copy validity dates.
        self.__dates(options, data, 'notbefore', max)
        self.__dates(options, data, 'notafter', min)

        # Save attributes.
        self.__options = options
        self.__id = data.get('id', uuid.uuid4())

    def __parse(self, decryptor, element, prefix, table):
        "Recursively parses the xml from a table."

        data = {}
        for k, v in table.items():
            path = prefix + "/" + k

            if isinstance(v, dict):
                data.update(self.__parse(decryptor, element, path, v))
                continue

            result = fetch(element, path)
            if result is not None:
                lambda_code_attr = "__code__" if six.PY3 else "func_code"
                if getattr(
                        getattr(v[1], lambda_code_attr, None),
                        "co_argcount", 0) > 1:
                    data[v[0]] = v[1](result, decryptor)
                else:
                    data[v[0]] = v[1](result)

        return data

    def __validate(self, data):
        "Validates the parsed data."

        if 'type' not in data or data['type'] not in ('totp', 'hotp'):
            raise ValidationError("Unsupported token type!")

        if 'key' not in data:
            if 'keyref' in data:
                raise ValidationError("Referenced keys are not supported!")
            raise ValidationError("Key not found in token!")

        if data.get('checkdigit', 'FALSE').upper() != 'FALSE':
            raise ValidationError("CheckDigit not supported!")

        if data.get('maxtransact', None) is not None:
            raise ValidationError('NumberOfTransactions policy not supported!')

        if data.get('pinpolicy', None) is not None:
            raise ValidationError('PINPolicy policy not supported!')

        if data.get('time', 0) != 0:
            raise ValidationError('Specified time is not supported!')

        encoding = data.get('encoding', 'DECIMAL').upper()
        if encoding != 'DECIMAL':
            raise ValidationError('Unsupported encoding: %s!' % encoding)

        usage = data.get('keyusage', 'OTP')
        if usage != 'OTP':
            raise ValidationError('Unsupported key usage: %s' % usage)

    def __dates(self, out, data, key, reducer):
        dates = (data.get(key + '.sw', None), data.get(key + '.hw', None))
        dates = [x for x in dates if x is not None]
        if dates:
            out['ipatoken' + key] = unicode(reducer(dates).strftime("%Y%m%d%H%M%SZ"))


class PSKCDocument:
    @property
    def keyname(self):
        return self.__keyname

    def __init__(self, filename):
        self.__keyname = None
        self.__decryptor = None
        self.__doc = etree.parse(filename)
        self.__mkey = fetch(self.__doc, "./pskc:MACMethod/pskc:MACKey")
        self.__algo = fetch(self.__doc, "./pskc:MACMethod/@Algorithm", convertHMACType)

        self.__keypackages = fetchAll(self.__doc, "./pskc:KeyPackage")
        if not self.__keypackages:
            raise ValueError("PSKC file is invalid!")

        self.__enckey = fetch(self.__doc, "./pskc:EncryptionKey")
        if self.__enckey is not None:
            # Check for x509 key.
            x509key = fetch(self.__enckey, "./ds:X509Data")
            if x509key is not None:
                raise NotImplementedError("X.509 keys are not currently supported!")

            # Get the keyname.
            self.__keyname = fetch(self.__enckey, "./ds:KeyName/text()")
            if self.__keyname is None:
                self.__keyname = fetch(self.__enckey,
                                       "./xenc11:DerivedKey/xenc11:MasterKeyName/text()")

    def setKey(self, key):
        # Derive the enckey if required.
        kd = fetch(self.__enckey,
                   "./xenc11:DerivedKey/xenc11:KeyDerivationMethod/@Algorithm",
                   convertKeyDerivation)
        if kd is not None:
            key = kd(self.__enckey).derive(key)

        # Load the decryptor.
        self.__decryptor = XMLDecryptor(key)
        if self.__mkey is not None and self.__algo is not None:
            tmp = hmac.HMAC(
                self.__decryptor(self.__mkey),
                self.__algo(),
                backend=default_backend()
            )
            self.__decryptor = XMLDecryptor(key, tmp)

    def getKeyPackages(self):
        for kp in self.__keypackages:
            yield PSKCKeyPackage(kp, self.__decryptor)

    def save(self, dest):
        self.__doc.write(dest)


class OTPTokenImport(admintool.AdminTool):
    command_name = 'ipa-otptoken-import'
    description = "Import OTP tokens."
    usage = "%prog [options] <PSKC file> <output file>"

    @classmethod
    def add_options(cls, parser):
        super(OTPTokenImport, cls).add_options(parser)

        parser.add_option("-k", "--keyfile", dest="keyfile",
                          help="File containing the key used to decrypt token secrets")

    def validate_options(self):
        super(OTPTokenImport, self).validate_options()

        # Parse the file.
        if len(self.args) < 1:
            raise admintool.ScriptError("Import file required!")
        self.doc = PSKCDocument(self.args[0])

        # Get the output file.
        if len(self.args) < 2:
            raise admintool.ScriptError("Output file required!")
        self.output = self.args[1]
        if os.path.exists(self.output):
            raise admintool.ScriptError("Output file already exists!")

        # Verify a key is provided if one is needed.
        if self.doc.keyname is not None:
            if self.safe_options.keyfile is None:  # pylint: disable=no-member
                raise admintool.ScriptError("Encryption key required: %s!" % self.doc.keyname)

            # Load the keyfile.
            keyfile = self.safe_options.keyfile  # pylint: disable=no-member
            with open(keyfile) as f:
                self.doc.setKey(f.read())

    def run(self):
        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()

        try:
            api.Backend.ldap2.connect(ccache=os.environ.get('KRB5CCNAME'),
                                      autobind=AUTOBIND_DISABLED)
        except (gssapi.exceptions.GSSError, errors.ACIError):
            raise admintool.ScriptError("Unable to connect to LDAP! Did you kinit?")

        try:
            # Parse tokens
            for keypkg in self.doc.getKeyPackages():
                try:
                    api.Command.otptoken_add(keypkg.id, no_qrcode=True, **keypkg.options)
                except Exception as e:
                    logger.warning("Error adding token: %s", e)
                else:
                    logger.info("Added token: %s", keypkg.id)
                    keypkg.remove()
        finally:
            api.Backend.ldap2.disconnect()

        # Write out the XML file without the tokens that succeeded.
        self.doc.save(self.output)
