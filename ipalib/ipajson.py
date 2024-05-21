#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

import base64
from cryptography import x509 as crypto_x509
import datetime
from decimal import Decimal
import json
import six
from ipalib.constants import LDAP_GENERALIZED_TIME_FORMAT
from ipalib import capabilities
from ipalib.x509 import Encoding as x509_Encoding
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipapython.kerberos import Principal

if six.PY3:
    unicode = str


class _JSONPrimer(dict):
    """Fast JSON primer and pre-converter

    Prepare a data structure for JSON serialization. In an ideal world, priming
    could be handled by the default hook of json.dumps(). Unfortunately the
    hook treats Python 2 str as text while IPA considers str as bytes.

    The primer uses a couple of tricks to archive maximum performance:

    * O(1) type look instead of O(n) chain of costly isinstance() calls
    * __missing__ and __mro__ with caching to handle subclasses
    * inline code with minor code duplication (func lookup in enc_list/dict)
    * avoid surplus function calls (e.g. func is _identity, obj.__class__
      instead if type(obj))
    * function default arguments to turn global into local lookups
    * avoid re-creation of bound method objects (e.g. result.append)
    * on-demand lookup of client capabilities with cached values

    Depending on the client version number, the primer converts:

    * bytes -> {'__base64__': b64encode}
    * datetime -> {'__datetime__': LDAP_GENERALIZED_TIME}
    * DNSName -> {'__dns_name__': unicode}

    The _ipa_obj_hook() functions unserializes the marked JSON objects to
    bytes, datetime and DNSName.

    :see: _ipa_obj_hook
    """
    __slots__ = ('version', '_cap_datetime', '_cap_dnsname')

    _identity = object()

    def __init__(self, version, _identity=_identity):
        super(_JSONPrimer, self).__init__()
        self.version = version
        self._cap_datetime = None
        self._cap_dnsname = None
        self.update({
            unicode: _identity,
            bool: _identity,
            int: _identity,
            type(None): _identity,
            float: _identity,
            Decimal: unicode,
            DN: str,
            Principal: unicode,
            DNSName: self._enc_dnsname,
            datetime.datetime: self._enc_datetime,
            bytes: self._enc_bytes,
            list: self._enc_list,
            tuple: self._enc_list,
            dict: self._enc_dict,
            crypto_x509.Certificate: self._enc_certificate,
            crypto_x509.CertificateSigningRequest: self._enc_certificate,
        })

    def __missing__(self, typ):
        # walk MRO to find best match
        for c in typ.__mro__:
            if c in self:
                self[typ] = self[c]
                return self[c]
        # use issubclass to check for registered ABCs
        for c in self:
            if issubclass(typ, c):
                self[typ] = self[c]
                return self[c]
        raise TypeError(typ)

    def convert(self, obj, _identity=_identity):
        # obj.__class__ is twice as fast as type(obj)
        func = self[obj.__class__]
        return obj if func is _identity else func(obj)

    def _enc_datetime(self, val):
        cap = self._cap_datetime
        if cap is None:
            cap = capabilities.client_has_capability(self.version,
                                                     'datetime_values')
            self._cap_datetime = cap
        if cap:
            return {'__datetime__': val.strftime(LDAP_GENERALIZED_TIME_FORMAT)}
        else:
            return val.strftime(LDAP_GENERALIZED_TIME_FORMAT)

    def _enc_dnsname(self, val):
        cap = self._cap_dnsname
        if cap is None:
            cap = capabilities.client_has_capability(self.version,
                                                     'dns_name_values')
            self._cap_dnsname = cap
        if cap:
            return {'__dns_name__': unicode(val)}
        else:
            return unicode(val)

    def _enc_bytes(self, val):
        encoded = base64.b64encode(val)
        if not six.PY2:
            encoded = encoded.decode('ascii')
        return {'__base64__': encoded}

    def _enc_list(self, val, _identity=_identity):
        result = []
        append = result.append
        for v in val:
            func = self[v.__class__]
            append(v if func is _identity else func(v))
        return result

    def _enc_dict(self, val, _identity=_identity, _iteritems=six.iteritems):
        result = {}
        for k, v in _iteritems(val):
            func = self[v.__class__]
            result[k] = v if func is _identity else func(v)
        return result

    def _enc_certificate(self, val):
        return self._enc_bytes(val.public_bytes(x509_Encoding.DER))


def json_encode_binary(val, version, pretty_print=False):
    """Serialize a Python object structure to JSON

    :param object val: Python object structure
    :param str version: client version
    :param bool pretty_print: indent and sort JSON (warning: slow!)
    :return: text
    :note: pretty printing triggers a slow path in Python's JSON module. Only
           use pretty_print in debug mode.
    """
    result = _JSONPrimer(version).convert(val)
    if pretty_print:
        return json.dumps(result, indent=4, sort_keys=True)
    else:
        return json.dumps(result)


def _ipa_obj_hook(dct, _iteritems=six.iteritems, _list=list):
    """JSON object hook

    :see: _JSONPrimer
    """
    if '__base64__' in dct:
        return base64.b64decode(dct['__base64__'])
    elif '__datetime__' in dct:
        return datetime.datetime.strptime(dct['__datetime__'],
                                          LDAP_GENERALIZED_TIME_FORMAT)
    elif '__dns_name__' in dct:
        return DNSName(dct['__dns_name__'])
    else:
        # XXX tests assume tuples. Is this really necessary?
        for k, v in _iteritems(dct):
            if v.__class__ is _list:
                dct[k] = tuple(v)
        return dct


def json_decode_binary(val):
    """Convert serialized JSON string back to Python data structure

    :param val: JSON string
    :type val: str, bytes
    :return: Python data structure
    :see: _ipa_obj_hook, _JSONPrimer
    """
    if isinstance(val, bytes):
        val = val.decode('utf-8')

    return json.loads(val, object_hook=_ipa_obj_hook)
