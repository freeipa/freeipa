# Copyright (C) 2015  IPA Project Contributors, see COPYING for license

from __future__ import print_function, absolute_import
# pylint: disable=relative-import
from custodia.message.kem import KEMClient, KEY_USAGE_SIG, KEY_USAGE_ENC
# pylint: enable=relative-import
from jwcrypto.common import json_decode
from jwcrypto.jwk import JWK
from ipaserver.secrets.kem import IPAKEMKeys
from ipaserver.secrets.store import iSecStore
from ipaplatform.paths import paths
from base64 import b64encode
import ldapurl
import gssapi
import os
import urllib3
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

    def __init__(
            self, client_service, keyfile, keytab, server, realm,
            ldap_uri=None, auth_type=None):
        self.client_service = client_service
        self.keytab = keytab

        # Init creds immediately to make sure they are valid.  Creds
        # can also be re-inited by _auth_header to avoid expiry.
        #
        self.creds = self.init_creds()

        self.service_name = gssapi.Name('HTTP@%s' % (server,),
                                        gssapi.NameType.hostbased_service)
        self.server = server

        self.ikk = IPAKEMKeys({'server_keys': keyfile, 'ldap_uri': ldap_uri})

        self.kemcli = KEMClient(self._server_keys(server, realm),
                                self._client_keys())

        self.keystore = self._keystore(realm, ldap_uri, auth_type)

        # FIXME: Remove warnings about missing subjAltName for the
        #        requests module
        urllib3.disable_warnings()

    def init_creds(self):
        name = gssapi.Name(self.client_service,
                           gssapi.NameType.hostbased_service)
        store = {'client_keytab': self.keytab,
                 'ccache': 'MEMORY:Custodia_%s' % b64encode(
                     os.urandom(8)).decode('ascii')}
        return gssapi.Credentials(name=name, store=store, usage='initiate')

    def _auth_header(self):
        if not self.creds or self.creds.lifetime < 300:
            self.creds = self.init_creds()
        ctx = gssapi.SecurityContext(name=self.service_name, creds=self.creds)
        authtok = ctx.step()
        return {'Authorization': 'Negotiate %s' % b64encode(
            authtok).decode('ascii')}

    def fetch_key(self, keyname, store=True):

        # Prepare URL
        url = 'https://%s/ipa/keys/%s' % (self.server, keyname)

        # Prepare signed/encrypted request
        encalg = ('RSA-OAEP', 'A256CBC-HS512')
        request = self.kemcli.make_request(keyname, encalg=encalg)

        # Prepare Authentication header
        headers = self._auth_header()

        # Perform request
        r = requests.get(url, headers=headers,
                         verify=paths.IPA_CA_CRT,
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

        return None
