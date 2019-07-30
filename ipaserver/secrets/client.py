# Copyright (C) 2015  IPA Project Contributors, see COPYING for license

from __future__ import print_function, absolute_import

import contextlib
import os
from base64 import b64encode


# pylint: disable=relative-import
from custodia.message.kem import KEMClient, KEY_USAGE_SIG, KEY_USAGE_ENC
# pylint: enable=relative-import
from jwcrypto.common import json_decode
from jwcrypto.jwk import JWK
from ipalib.krb_utils import krb5_format_service_principal_name
from ipaserver.install.installutils import realm_to_ldapi_uri
from ipaserver.secrets.kem import IPAKEMKeys
from ipaserver.secrets.store import IPASecStore
from ipaplatform.paths import paths
import gssapi
import requests


@contextlib.contextmanager
def ccache_env(ccache):
    """Temporarily set KRB5CCNAME environment variable
    """
    orig_ccache = os.environ.get('KRB5CCNAME')
    os.environ['KRB5CCNAME'] = ccache
    try:
        yield
    finally:
        os.environ.pop('KRB5CCNAME', None)
        if orig_ccache is not None:
            os.environ['KRB5CCNAME'] = orig_ccache


class CustodiaClient(object):
    def __init__(self, client_service, keyfile, keytab, server, realm,
                 ldap_uri=None, auth_type=None):
        if client_service.endswith(realm) or "@" not in client_service:
            raise ValueError(
                "Client service name must be a GSS name (service@host), "
                "not '{}'.".format(client_service)
            )
        self.client_service = client_service
        self.keytab = keytab
        self.server = server
        self.realm = realm
        self.ldap_uri = ldap_uri or realm_to_ldapi_uri(realm)
        self.auth_type = auth_type
        self.service_name = gssapi.Name(
            'HTTP@{}'.format(server), gssapi.NameType.hostbased_service
        )

        config = {'ldap_uri': self.ldap_uri}
        if auth_type is not None:
            config['auth_type'] = auth_type
        self.keystore = IPASecStore(config)

        # use in-process MEMORY ccache. Handler process don't need a TGT.
        token = b64encode(os.urandom(8)).decode('ascii')
        self.ccache = 'MEMORY:Custodia_{}'.format(token)

        with ccache_env(self.ccache):
            # Init creds immediately to make sure they are valid.  Creds
            # can also be re-inited by _auth_header to avoid expiry.
            self.creds = self._init_creds()

            self.ikk = IPAKEMKeys(
                {'server_keys': keyfile, 'ldap_uri': ldap_uri}
            )
            self.kemcli = KEMClient(
                self._server_keys(), self._client_keys()
            )

    def _client_keys(self):
        return self.ikk.server_keys

    def _server_keys(self):
        principal = krb5_format_service_principal_name(
            'host', self.server, self.realm
        )
        sk = JWK(**json_decode(self.ikk.find_key(principal, KEY_USAGE_SIG)))
        ek = JWK(**json_decode(self.ikk.find_key(principal, KEY_USAGE_ENC)))
        return sk, ek

    def _init_creds(self):
        name = gssapi.Name(
            self.client_service, gssapi.NameType.hostbased_service
        )
        store = {
            'client_keytab': self.keytab,
            'ccache': self.ccache
        }
        return gssapi.Credentials(name=name, store=store, usage='initiate')

    def _auth_header(self):
        if self.creds.lifetime < 300:
            self.creds = self._init_creds()
        ctx = gssapi.SecurityContext(
            name=self.service_name,
            creds=self.creds
        )
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
        r = requests.get(
            url, headers=headers,
            verify=paths.IPA_CA_CRT,
            params={'type': 'kem', 'value': request}
        )
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
