# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import


import socket

from jwcrypto.common import json_decode
from jwcrypto.jwk import JWK

import requests
from requests.adapters import HTTPAdapter
from requests.compat import unquote, urlparse
# requests 2.18 no longer vendors urllib3
# pylint: disable=import-error
from requests.packages.urllib3.connection import HTTPConnection
from requests.packages.urllib3.connectionpool import HTTPConnectionPool
# pylint: enable=import-error

try:
    import requests_gssapi
except ImportError:
    requests_gssapi = None

from custodia.log import getLogger
from custodia.message.kem import (
    check_kem_claims, decode_enc_kem, make_enc_kem
)


logger = getLogger(__name__)


class HTTPUnixConnection(HTTPConnection):

    def __init__(self, host, timeout=60, **kwargs):
        # pylint: disable=bad-super-call
        super(HTTPConnection, self).__init__('localhost')
        self.unix_socket = host
        self.timeout = timeout

    def connect(self):
        s = socket.socket(family=socket.AF_UNIX)
        s.settimeout(self.timeout)
        s.connect(self.unix_socket)
        self.sock = s  # pylint: disable=attribute-defined-outside-init


class HTTPUnixConnectionPool(HTTPConnectionPool):

    scheme = 'http+unix'
    ConnectionCls = HTTPUnixConnection


class HTTPUnixAdapter(HTTPAdapter):

    def get_connection(self, url, proxies=None):
        # proxies, silently ignored
        path = unquote(urlparse(url).netloc)
        return HTTPUnixConnectionPool(path)


DEFAULT_HEADERS = {'Content-Type': 'application/json'}


class CustodiaHTTPClient(object):
    timeout = None  # seconds (float)

    def __init__(self, url):
        self.session = requests.Session()
        self.session.mount('http+unix://', HTTPUnixAdapter())
        self.headers = dict(DEFAULT_HEADERS)
        self.url = url
        self._last_response = None

    def set_simple_auth_keys(self, name, key,
                             name_header='CUSTODIA_AUTH_ID',
                             key_header='CUSTODIA_AUTH_KEY'):
        self.headers[name_header] = name
        self.headers[key_header] = key

    def set_ca_cert(self, cafile):
        self.session.verify = cafile

    def set_client_cert(self, certfile, keyfile=None):
        if keyfile is None:
            self.session.cert = certfile
        else:
            self.session.cert = (certfile, keyfile)

    def set_gssapi_auth(self, **kwargs):
        if requests_gssapi is None:
            raise ImportError('requests_gssapi')
        self.session.auth = requests_gssapi.HTTPSPNEGOAuth(**kwargs)

    def _join_url(self, path):
        return self.url.rstrip('/') + '/' + path.lstrip('/')

    def _add_headers(self, **kwargs):
        headers = kwargs.get('headers', None)
        if headers is None:
            headers = dict()
        headers.update(self.headers)
        return headers

    def _request(self, cmd, path, **kwargs):
        self._last_response = None
        url = self._join_url(path)
        kwargs.setdefault('timeout', self.timeout)
        kwargs['headers'] = self._add_headers(**kwargs)
        logger.debug("%s %s", cmd.__name__.upper(), url)
        self._last_response = cmd(url, **kwargs)
        logger.debug("Response: %s", self._last_response)
        return self._last_response

    @property
    def last_response(self):
        return self._last_response

    def delete(self, path, **kwargs):
        return self._request(self.session.delete, path, **kwargs)

    def get(self, path, **kwargs):
        return self._request(self.session.get, path, **kwargs)

    def head(self, path, **kwargs):
        return self._request(self.session.head, path, **kwargs)

    def patch(self, path, **kwargs):
        return self._request(self.session.patch, path, **kwargs)

    def post(self, path, **kwargs):
        return self._request(self.session.post, path, **kwargs)

    def put(self, path, **kwargs):
        return self._request(self.session.put, path, **kwargs)

    def container_name(self, name):
        return name if name.endswith('/') else name + '/'

    def create_container(self, name):
        raise NotImplementedError

    def list_container(self, name):
        raise NotImplementedError

    def delete_container(self, name):
        raise NotImplementedError

    def get_secret(self, name):
        raise NotImplementedError

    def set_secret(self, name, value):
        raise NotImplementedError

    def del_secret(self, name):
        raise NotImplementedError


class CustodiaSimpleClient(CustodiaHTTPClient):

    def create_container(self, name):
        r = self.post(self.container_name(name))
        r.raise_for_status()

    def delete_container(self, name):
        r = self.delete(self.container_name(name))
        r.raise_for_status()

    def list_container(self, name):
        r = self.get(self.container_name(name))
        r.raise_for_status()
        return r.json()

    def get_secret(self, name):
        r = self.get(name)
        r.raise_for_status()
        simple = r.json()
        ktype = simple.get("type", None)
        if ktype != "simple":
            raise TypeError("Invalid key type: %s" % ktype)
        return simple["value"]

    def set_secret(self, name, value):
        r = self.put(name, json={"type": "simple", "value": value})
        r.raise_for_status()

    def del_secret(self, name):
        r = self.delete(name)
        r.raise_for_status()


class CustodiaKEMClient(CustodiaHTTPClient):
    def __init__(self, url):
        super(CustodiaKEMClient, self).__init__(url)
        self._cli_signing_key = None
        self._cli_decryption_key = None
        self._srv_verifying_key = None
        self._srv_encryption_key = None
        self._sig_alg = None
        self._enc_alg = None

    def _decode_key(self, key):
        if key is None:
            return None
        elif isinstance(key, JWK):
            return key
        elif isinstance(key, dict):
            return JWK(**key)
        elif isinstance(key, str):
            return JWK(**(json_decode(key)))
        else:
            raise TypeError("Invalid key type")

    def set_server_public_keys(self, sig, enc):
        self._srv_verifying_key = self._decode_key(sig)
        self._srv_encryption_key = self._decode_key(enc)

    def set_client_keys(self, sig, enc):
        self._cli_signing_key = self._decode_key(sig)
        self._cli_decryption_key = self._decode_key(enc)

    def set_algorithms(self, sig, enc):
        self._sig_alg = sig
        self._enc_alg = enc

    def _signing_algorithm(self, key):
        if self._sig_alg is not None:
            return self._sig_alg
        elif key.key_type == 'RSA':
            return 'RS256'
        elif key.key_type == 'EC':
            return 'ES256'
        else:
            raise ValueError('Unsupported key type')

    def _encryption_algorithm(self, key):
        if self._enc_alg is not None:
            return self._enc_alg
        elif key.key_type == 'RSA':
            return ('RSA-OAEP', 'A256CBC-HS512')
        elif key.key_type == 'EC':
            return ('ECDH-ES+A256KW', 'A256CBC-HS512')
        else:
            raise ValueError('Unsupported key type')

    def _kem_wrap(self, name, value):
        if self._cli_signing_key is None:
            raise KeyError("Client Signing key is not available")
        if self._srv_encryption_key is None:
            raise KeyError("Server Encryption key is not available")
        sig_alg = self._signing_algorithm(self._cli_signing_key)
        enc_alg = self._encryption_algorithm(self._srv_encryption_key)
        return make_enc_kem(name, value,
                            self._cli_signing_key, sig_alg,
                            self._srv_encryption_key, enc_alg)

    def _kem_unwrap(self, name, message):
        if message.get("type", None) != "kem":
            raise TypeError("Invalid token type, expected 'kem', got %s" % (
                            message.get("type", None),))

        if self._cli_decryption_key is None:
            raise KeyError("Client Decryption key is not available")
        if self._srv_verifying_key is None:
            raise KeyError("Server Verifying key is not available")
        claims = decode_enc_kem(message["value"],
                                self._cli_decryption_key,
                                self._srv_verifying_key)
        check_kem_claims(claims, name)
        return claims

    def create_container(self, name):
        cname = self.container_name(name)
        message = self._kem_wrap(cname, None)
        r = self.post(cname, json={"type": "kem", "value": message})
        r.raise_for_status()
        self._kem_unwrap(cname, r.json())

    def delete_container(self, name):
        cname = self.container_name(name)
        message = self._kem_wrap(cname, None)
        r = self.delete(cname, json={"type": "kem", "value": message})
        r.raise_for_status()
        self._kem_unwrap(cname, r.json())

    def list_container(self, name):
        return self.get_secret(self.container_name(name))

    def get_secret(self, name):
        message = self._kem_wrap(name, None)
        r = self.get(name, params={"type": "kem", "value": message})
        r.raise_for_status()
        claims = self._kem_unwrap(name, r.json())
        return claims['value']

    def set_secret(self, name, value):
        message = self._kem_wrap(name, value)
        r = self.put(name, json={"type": "kem", "value": message})
        r.raise_for_status()
        self._kem_unwrap(name, r.json())

    def del_secret(self, name):
        message = self._kem_wrap(name, None)
        r = self.delete(name, json={"type": "kem", "value": message})
        r.raise_for_status()
        self._kem_unwrap(name, r.json())
