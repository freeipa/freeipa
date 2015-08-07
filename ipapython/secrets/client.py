# Copyright (C) 2015  IPA Project Contributors, see COPYING for license

from __future__ import print_function
from custodia.message.kem import KEMClient, KEY_USAGE_SIG, KEY_USAGE_ENC
from jwcrypto.common import json_decode
from jwcrypto.jwk import JWK
from ipapython.secrets.kem import IPAKEMKeys
from ipapython.secrets.store import iSecStore
from ipaplatform.paths import paths
from base64 import b64encode
import ldapurl
import gssapi
import os
import requests


class CustodiaClient(object):

    def _client_keys(self):
        return self.ikk.server_keys

    def _server_keys(self, server, realm):
        principal = 'host/%s@%s' % (server, realm)
        sk = JWK(**json_decode(self.ikk.find_key(principal, KEY_USAGE_SIG)))
        ek = JWK(**json_decode(self.ikk.find_key(principal, KEY_USAGE_ENC)))
        return (sk, ek)

    def _ldap_uri(self, realm):
        dashrealm = '-'.join(realm.split('.'))
        socketpath = paths.SLAPD_INSTANCE_SOCKET_TEMPLATE % (dashrealm,)
        return 'ldapi://' + ldapurl.ldapUrlEscape(socketpath)

    def _keystore(self, realm, ldap_uri, auth_type):
        config = dict()
        if ldap_uri is None:
            config['ldap_uri'] = self._ldap_uri(realm)
        else:
            config['ldap_uri'] = ldap_uri
        if auth_type is not None:
            config['auth_type'] = auth_type

        return iSecStore(config)

    def __init__(self, client, server, realm, ldap_uri=None, auth_type=None):
        self.client = client
        self.creds = None

        self.service_name = gssapi.Name('HTTP@%s' % (server,),
                                        gssapi.NameType.hostbased_service)
        self.server = server

        keyfile = os.path.join(paths.IPA_CUSTODIA_CONF_DIR, 'server.keys')
        self.ikk = IPAKEMKeys({'server_keys': keyfile})

        self.kemcli = KEMClient(self._server_keys(server, realm),
                                self._client_keys())

        self.keystore = self._keystore(realm, ldap_uri, auth_type)

        # FIXME: Remove warnings about missig subjAltName
        requests.packages.urllib3.disable_warnings()

    def init_creds(self):
        name = gssapi.Name('host@%s' % (self.client,),
                           gssapi.NameType.hostbased_service)
        store = {'client_keytab': paths.KRB5_KEYTAB,
                 'ccache': 'MEMORY:Custodia_%s' % b64encode(os.urandom(8))}
        return gssapi.Credentials(name=name, store=store, usage='initiate')

    def _auth_header(self):
        if not self.creds or self.creds.lifetime < 300:
            self.creds = self.init_creds()
        ctx = gssapi.SecurityContext(name=self.service_name, creds=self.creds)
        authtok = ctx.step()
        return {'Authorization': 'Negotiate %s' % b64encode(authtok)}

    def fetch_key(self, keyname, store=True):

        # Prepare URL
        url = 'https://%s/ipa/keys/%s' % (self.server, keyname)

        # Prepare signed/encrypted request
        encalg = ('RSA1_5', 'A256CBC-HS512')
        request = self.kemcli.make_request(keyname, encalg=encalg)

        # Prepare Authentication header
        headers = self._auth_header()

        # Perform request
        r = requests.get(url, headers=headers,
                         params={'type': 'kem', 'value': request})
        r.raise_for_status()
        reply = r.json()

        if 'type' not in reply or reply['type'] != 'kem':
            raise RuntimeError('Invlid JSON response type')

        value = self.kemcli.parse_reply(keyname, reply['value'])

        if store:
            self.keystore.set('keys/%s' % keyname, value)
        else:
            return value
