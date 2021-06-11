# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import os
import time

from jwcrypto.common import json_decode
from jwcrypto.common import json_encode
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from jwcrypto.jwt import JWT

from custodia.httpd.authorizers import SimplePathAuthz
from custodia.log import getLogger
from custodia.message.common import InvalidMessage
from custodia.message.common import MessageHandler

logger = getLogger(__name__)

KEY_USAGE_SIG = 0
KEY_USAGE_ENC = 1
KEY_USAGE_MAP = {KEY_USAGE_SIG: 'sig', KEY_USAGE_ENC: 'enc'}


class UnknownPublicKey(Exception):
    def __init__(self, message=None):
        logger.debug(message)
        super(UnknownPublicKey, self).__init__(message)


class KEMKeysStore(SimplePathAuthz):
    """A KEM Keys Store.

    This is a store that holds public keys of registered
    clients allowed to use KEM messages. It takes the form
    of an authorizer merely for the purpose of attaching
    itself to a 'request' so that later on the KEM Parser
    can fetch the appropriate key to verify/decrypt an
    incoming request and make the payload available.

    The KEM Parser will actually perform additional
    authorization checks in this case.

    SimplePathAuthz is extended here as we ant to attach the
    store only to requests on paths we are configured to
    manage.
    """

    def __init__(self, config):
        super(KEMKeysStore, self).__init__(config)
        self._server_keys = None
        self._alg = None
        self._enc = None

    def _db_key(self, kid):
        return os.path.join('kemkeys', kid)

    def handle(self, request):
        inpath = super(KEMKeysStore, self).handle(request)
        if inpath:
            request['KEMKeysStore'] = self
        return inpath

    def find_key(self, kid, usage):
        dbkey = self._db_key('%s/%s' % (KEY_USAGE_MAP[usage], kid))
        pubkey = self.store.get(dbkey)
        if pubkey is None:
            raise UnknownPublicKey(kid)
        return pubkey

    @property
    def server_keys(self):
        if self._server_keys is None:
            if 'server_keys' not in self.config:
                raise UnknownPublicKey("Server Keys not defined")
            skey = self.find_key(self.config['server_keys'], KEY_USAGE_SIG)
            ekey = self.find_key(self.config['server_keys'], KEY_USAGE_ENC)
            self._server_keys = [JWK(**(json_decode(skey))),
                                 JWK(**(json_decode(ekey)))]
        return self._server_keys

    @property
    def alg(self):
        if self._alg is None:
            alg = self.config.get('signing_algorithm', None)
            if alg is None:
                ktype = self.server_keys[KEY_USAGE_SIG].key_type
                if ktype == 'RSA':
                    alg = 'RS256'
                elif ktype == 'EC':
                    alg = 'ES256'
                else:
                    raise ValueError('Key type unsupported for signing')
            self._alg = alg
        return self._alg


def check_kem_claims(claims, name):
    if 'sub' not in claims:
        raise InvalidMessage('Missing subject in payload')
    if claims['sub'] != name:
        raise InvalidMessage('Key name %s does not match subject %s' % (
            name, claims['sub']))
    if 'exp' not in claims:
        raise InvalidMessage('Missing expiration time in payload')
    if claims['exp'] - (10 * 60) > int(time.time()):
        raise InvalidMessage('Message expiration too far in the future')
    if claims['exp'] < int(time.time()):
        raise InvalidMessage('Message Expired')


class KEMHandler(MessageHandler):
    """Handles 'kem' messages"""

    def __init__(self, request):
        super(KEMHandler, self).__init__(request)
        self.kkstore = self.req.get('KEMKeysStore', None)
        if self.kkstore is None:
            raise Exception('KEM KeyStore not configured')
        self.client_keys = None
        self.name = None

    def _get_key(self, header, usage):
        if 'kid' not in header:
            raise InvalidMessage("Missing key identifier")

        key = self.kkstore.find_key(header['kid'], usage)
        if key is None:
            raise UnknownPublicKey('Key found [kid:%s]' % header['kid'])
        return json_decode(key)

    def parse(self, msg, name):
        """Parses the message.

        We check that the message is properly formatted.

        :param msg: a json-encoded value containing a JWS or JWE+JWS token

        :raises InvalidMessage: if the message cannot be parsed or validated

        :returns: A verified payload
        """

        try:
            jtok = JWT(jwt=msg)
        except Exception as e:
            raise InvalidMessage('Failed to parse message: %s' % str(e))

        try:
            token = jtok.token
            if isinstance(token, JWE):
                token.decrypt(self.kkstore.server_keys[KEY_USAGE_ENC])
                # If an encrypted payload is received then there must be
                # a nested signed payload to verify the provenance.
                payload = token.payload.decode('utf-8')
                token = JWS()
                token.deserialize(payload)
            elif isinstance(token, JWS):
                pass
            else:
                raise TypeError("Invalid Token type: %s" % type(jtok))

            # Retrieve client keys for later use
            self.client_keys = [
                JWK(**self._get_key(token.jose_header, KEY_USAGE_SIG)),
                JWK(**self._get_key(token.jose_header, KEY_USAGE_ENC))]

            # verify token and get payload
            token.verify(self.client_keys[KEY_USAGE_SIG])
            claims = json_decode(token.payload)
        except Exception as e:
            logger.debug('Failed to validate message', exc_info=True)
            raise InvalidMessage('Failed to validate message: %s' % str(e))

        check_kem_claims(claims, name)
        self.name = name
        self.payload = claims.get('value')
        self.msg_type = 'kem'

        return {'type': self.msg_type,
                'value': {'kid': self.client_keys[KEY_USAGE_ENC].key_id,
                          'claims': claims}}

    def reply(self, output):
        if self.client_keys is None:
            raise UnknownPublicKey("Peer key not defined")

        ktype = self.client_keys[KEY_USAGE_ENC].key_type
        if ktype == 'RSA':
            enc = ('RSA-OAEP', 'A256CBC-HS512')
        else:
            raise ValueError("'%s' type not supported yet" % ktype)

        value = make_enc_kem(self.name, output,
                             self.kkstore.server_keys[KEY_USAGE_SIG],
                             self.kkstore.alg,
                             self.client_keys[1], enc)

        return {'type': 'kem', 'value': value}


class KEMClient(object):

    def __init__(self, server_keys, client_keys):
        self.server_keys = server_keys
        self.client_keys = client_keys

    def make_request(self, name, value=None, alg="RS256", encalg=None):
        if encalg is None:
            return make_sig_kem(name, value,
                                self.client_keys[KEY_USAGE_SIG], alg)
        else:
            return make_enc_kem(name, value,
                                self.client_keys[KEY_USAGE_SIG], alg,
                                self.server_keys[KEY_USAGE_ENC], encalg)

    def parse_reply(self, name, message):
        claims = decode_enc_kem(message,
                                self.client_keys[KEY_USAGE_ENC],
                                self.server_keys[KEY_USAGE_SIG])
        check_kem_claims(claims, name)
        return claims['value']


def make_sig_kem(name, value, key, alg):
    header = {'kid': key.key_id, 'alg': alg}
    claims = {'sub': name, 'exp': int(time.time() + (5 * 60))}
    if value is not None:
        claims['value'] = value
    jwt = JWT(header, claims)
    jwt.make_signed_token(key)
    return jwt.serialize(compact=True)


def make_enc_kem(name, value, sig_key, alg, enc_key, enc):
    plaintext = make_sig_kem(name, value, sig_key, alg)
    eprot = {'kid': enc_key.key_id, 'alg': enc[0], 'enc': enc[1]}
    jwe = JWE(plaintext, json_encode(eprot))
    jwe.add_recipient(enc_key)
    return jwe.serialize(compact=True)


def decode_enc_kem(message, enc_key, sig_key):
    jwe = JWT(jwt=message, key=enc_key)
    jws = JWT(jwt=jwe.claims, key=sig_key)
    return json_decode(jws.claims)
