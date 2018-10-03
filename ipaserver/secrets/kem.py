# Copyright (C) 2015  IPA Project Contributors, see COPYING for license

from __future__ import print_function, absolute_import

import errno
import os

from configparser import ConfigParser

from ipaplatform.paths import paths
from ipapython.dn import DN
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
# pylint: disable=relative-import
from custodia.message.kem import KEMKeysStore
from custodia.message.kem import KEY_USAGE_SIG, KEY_USAGE_ENC, KEY_USAGE_MAP
# pylint: enable=relative-import
from jwcrypto.common import json_decode, json_encode
from jwcrypto.common import base64url_encode
from jwcrypto.jwk import JWK
from ipaserver.secrets.common import iSecLdap
from binascii import unhexlify
import ldap


IPA_REL_BASE_DN = 'cn=custodia,cn=ipa,cn=etc'
IPA_KEYS_QUERY = '(&(ipaKeyUsage={usage:s})(memberPrincipal={princ:s}))'
IPA_CHECK_QUERY = '(cn=enc/{host:s})'
RFC5280_USAGE_MAP = {KEY_USAGE_SIG: 'digitalSignature',
                     KEY_USAGE_ENC: 'dataEncipherment'}


class KEMLdap(iSecLdap):

    @property
    def keysbase(self):
        return '%s,%s' % (IPA_REL_BASE_DN, self.basedn)

    def _encode_int(self, i):
        I = hex(i).rstrip("L").lstrip("0x")
        return base64url_encode(unhexlify((len(I) % 2) * '0' + I))

    def _parse_public_key(self, ipa_public_key):
        public_key = serialization.load_der_public_key(ipa_public_key,
                                                       default_backend())
        num = public_key.public_numbers()
        if isinstance(num, rsa.RSAPublicNumbers):
            return {'kty': 'RSA',
                    'e': self._encode_int(num.e),
                    'n': self._encode_int(num.n)}
        elif isinstance(num, ec.EllipticCurvePublicNumbers):
            if num.curve.name == 'secp256r1':
                curve = 'P-256'
            elif num.curve.name == 'secp384r1':
                curve = 'P-384'
            elif num.curve.name == 'secp521r1':
                curve = 'P-521'
            else:
                raise TypeError('Unsupported Elliptic Curve')
            return {'kty': 'EC',
                    'crv': curve,
                    'x': self._encode_int(num.x),
                    'y': self._encode_int(num.y)}
        else:
            raise TypeError('Unknown Public Key type')

    def get_key(self, usage, principal):
        conn = self.connect()
        scope = ldap.SCOPE_SUBTREE

        ldap_filter = self.build_filter(IPA_KEYS_QUERY,
                                        {'usage': RFC5280_USAGE_MAP[usage],
                                         'princ': principal})
        r = conn.search_s(self.keysbase, scope, ldap_filter)
        if len(r) != 1:
            raise ValueError("Incorrect number of results (%d) searching for "
                             "public key for %s" % (len(r), principal))
        ipa_public_key = r[0][1]['ipaPublicKey'][0]
        jwk = self._parse_public_key(ipa_public_key)
        jwk['use'] = KEY_USAGE_MAP[usage]
        return json_encode(jwk)

    def check_host_keys(self, host):
        conn = self.connect()
        scope = ldap.SCOPE_SUBTREE

        ldap_filter = self.build_filter(IPA_CHECK_QUERY, {'host': host})
        r = conn.search_s(self.keysbase, scope, ldap_filter)
        if not r:
            raise ValueError("No public keys were found for %s" % host)
        return True

    def _format_public_key(self, key):
        if isinstance(key, str):
            jwkey = json_decode(key)
            if 'kty' not in jwkey:
                raise ValueError('Invalid key, missing "kty" attribute')
            if jwkey['kty'] == 'RSA':
                pubnum = rsa.RSAPublicNumbers(jwkey['e'], jwkey['n'])
                pubkey = pubnum.public_key(default_backend())
            elif jwkey['kty'] == 'EC':
                if jwkey['crv'] == 'P-256':
                    curve = ec.SECP256R1
                elif jwkey['crv'] == 'P-384':
                    curve = ec.SECP384R1
                elif jwkey['crv'] == 'P-521':
                    curve = ec.SECP521R1
                else:
                    raise TypeError('Unsupported Elliptic Curve')
                pubnum = ec.EllipticCurvePublicNumbers(
                    jwkey['x'], jwkey['y'], curve)
                pubkey = pubnum.public_key(default_backend())
            else:
                raise ValueError('Unknown key type: %s' % jwkey['kty'])
        elif isinstance(key, rsa.RSAPublicKey):
            pubkey = key
        elif isinstance(key, ec.EllipticCurvePublicKey):
            pubkey = key
        else:
            raise TypeError('Unknown key type: %s' % type(key))

        return pubkey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def _get_dn(self, usage, principal):
        servicename, host = principal.split('@')[0].split('/')
        name = '%s/%s' % (KEY_USAGE_MAP[usage], host)
        service_rdn = ('cn', servicename) if servicename != 'host' else DN()
        return DN(('cn', name), service_rdn, self.keysbase)

    def set_key(self, usage, principal, key):
        """
        Write key for the host or service.

        Service keys are nested one level beneath the 'cn=custodia'
        container, in the 'cn=<servicename>' container; this allows
        fine-grained control over key management permissions for
        specific services.

        The container is assumed to exist.

        """
        public_key = self._format_public_key(key)
        dn = self._get_dn(usage, principal)
        conn = self.connect()
        try:
            mods = [('objectClass', [b'nsContainer',
                                     b'ipaKeyPolicy',
                                     b'ipaPublicKeyObject',
                                     b'groupOfPrincipals']),
                    ('cn', dn[0].value.encode('utf-8')),
                    ('ipaKeyUsage', RFC5280_USAGE_MAP[usage].encode('utf-8')),
                    ('memberPrincipal', principal.encode('utf-8')),
                    ('ipaPublicKey', public_key)]
            conn.add_s(str(dn), mods)
        except ldap.ALREADY_EXISTS:
            mods = [(ldap.MOD_REPLACE, 'ipaPublicKey', public_key)]
            conn.modify_s(str(dn), mods)

    def del_key(self, usage, principal):
        """Delete key for host or service

        :returns: DN of removed key or None when key was not found
        """
        dn = self._get_dn(usage, principal)
        conn = self.connect()
        try:
            conn.delete_s(str(dn))
        except ldap.NO_SUCH_OBJECT:
            return None
        else:
            return dn


def newServerKeys(path, keyid):
    skey = JWK(generate='RSA', use='sig', kid=keyid)
    ekey = JWK(generate='RSA', use='enc', kid=keyid)
    with open(path, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        os.fchown(f.fileno(), 0, 0)
        f.write('[%s,%s]' % (skey.export(), ekey.export()))
    return [skey.get_op_key('verify'), ekey.get_op_key('encrypt')]


class IPAKEMKeys(KEMKeysStore):
    """A KEM Keys Store.

    This is a store that holds public keys of registered
    clients allowed to use KEM messages. It takes the form
    of an authorizer merely for the purpose of attaching
    itself to a 'request' so that later on the KEM Parser
    can fetch the appropariate key to verify/decrypt an
    incoming request and make the payload available.

    The KEM Parser will actually perform additional
    authorization checks in this case.

    SimplePathAuthz is extended here as we want to attach the
    store only to requests on paths we are configured to
    manage.
    """

    def __init__(self, config=None, ipaconf=paths.IPA_DEFAULT_CONF):
        super(IPAKEMKeys, self).__init__(config)
        conf = ConfigParser()
        self.host = None
        self.realm = None
        self.ldap_uri = config.get('ldap_uri', None)
        if conf.read(ipaconf):
            self.host = conf.get('global', 'host')
            self.realm = conf.get('global', 'realm')
            if self.ldap_uri is None:
                self.ldap_uri = conf.get('global', 'ldap_uri', raw=True)

        self._server_keys = None

    def find_key(self, kid, usage):
        if kid is None:
            raise TypeError('Key ID is None, should be a SPN')
        conn = KEMLdap(self.ldap_uri)
        return conn.get_key(usage, kid)

    def generate_server_keys(self):
        self.generate_keys('host')

    def generate_keys(self, servicename):
        principal = '%s/%s@%s' % (servicename, self.host, self.realm)
        # Neutralize the key with read if any
        self._server_keys = None
        # Generate private key and store it
        pubkeys = newServerKeys(self.config['server_keys'], principal)
        # Store public key in LDAP
        ldapconn = KEMLdap(self.ldap_uri)
        ldapconn.set_key(KEY_USAGE_SIG, principal, pubkeys[0])
        ldapconn.set_key(KEY_USAGE_ENC, principal, pubkeys[1])

    def remove_server_keys_file(self):
        """Remove keys from disk

        The method does not fail when the file is missing.
        """
        try:
            os.unlink(self.config['server_keys'])
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            return False
        else:
            return True

    def remove_server_keys(self):
        """Remove keys from LDAP and disk
        """
        self.remove_keys('host')

    def remove_keys(self, servicename):
        """Remove keys from LDAP and disk
        """
        self.remove_server_keys_file()
        principal = '%s/%s@%s' % (servicename, self.host, self.realm)
        if self.ldap_uri is not None:
            ldapconn = KEMLdap(self.ldap_uri)
            ldapconn.del_key(KEY_USAGE_SIG, principal)
            ldapconn.del_key(KEY_USAGE_ENC, principal)

    @property
    def server_keys(self):
        if self._server_keys is None:
            with open(self.config['server_keys']) as f:
                jsonkeys = f.read()
            dictkeys = json_decode(jsonkeys)
            self._server_keys = (JWK(**dictkeys[KEY_USAGE_SIG]),
                                 JWK(**dictkeys[KEY_USAGE_ENC]))
        return self._server_keys


# Manual testing
if __name__ == '__main__':
    IKK = IPAKEMKeys({'paths': '/',
                      'server_keys': '/etc/ipa/custodia/server.keys'})
    IKK.generate_server_keys()
    print(('SIG', IKK.server_keys[0].export_public()))
    print(('ENC', IKK.server_keys[1].export_public()))
    print(IKK.find_key('host/%s@%s' % (IKK.host, IKK.realm),
                       usage=KEY_USAGE_SIG))
    print(IKK.find_key('host/%s@%s' % (IKK.host, IKK.realm),
                       usage=KEY_USAGE_ENC))
