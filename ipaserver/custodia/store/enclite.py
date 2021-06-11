# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

from jwcrypto.common import json_decode, json_encode
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK

from custodia.plugin import CSStoreError, PluginOption, REQUIRED
from custodia.store.sqlite import SqliteStore


class EncryptedStore(SqliteStore):
    master_key = PluginOption(str, REQUIRED, None)
    master_enctype = PluginOption(str, 'A256CBC-HS512', None)

    def __init__(self, config, section):
        super(EncryptedStore, self).__init__(config, section)
        with open(self.master_key) as f:
            data = f.read()
            key = json_decode(data)
            self.mkey = JWK(**key)

    def get(self, key):
        value = super(EncryptedStore, self).get(key)
        if value is None:
            return None
        try:
            jwe = JWE()
            jwe.deserialize(value, self.mkey)
            return jwe.payload.decode('utf-8')
        except Exception:
            self.logger.exception("Error parsing key %s", key)
            raise CSStoreError('Error occurred while trying to parse key')

    def set(self, key, value, replace=False):
        protected = json_encode({'alg': 'dir', 'enc': self.master_enctype})
        jwe = JWE(value, protected)
        jwe.add_recipient(self.mkey)
        cvalue = jwe.serialize(compact=True)
        return super(EncryptedStore, self).set(key, cvalue, replace)
