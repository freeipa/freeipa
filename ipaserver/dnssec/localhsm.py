#!/usr/bin/python3
#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import os
from pprint import pprint

import six

from ipalib.constants import SOFTHSM_DNSSEC_TOKEN_LABEL
from ipaplatform.paths import paths
from ipaserver import p11helper as _ipap11helper
from ipaserver.dnssec.abshsm import (attrs_name2id, attrs_id2name, AbstractHSM,
                                     keytype_id2name, keytype_name2id,
                                     ldap2p11helper_api_params)
from ipaserver.dnssec.ldapkeydb import str_hexlify

# pylint: disable=no-name-in-module, import-error
if six.PY3:
    from collections.abc import MutableMapping
else:
    from collections import MutableMapping
# pylint: enable=no-name-in-module, import-error


private_key_api_params = set(["label", "id", "data", "unwrapping_key",
    "wrapping_mech", "key_type", "cka_always_authenticate", "cka_copyable",
    "cka_decrypt", "cka_derive", "cka_extractable", "cka_modifiable",
    "cka_private", "cka_sensitive", "cka_sign", "cka_sign_recover",
    "cka_unwrap", "cka_wrap_with_trusted"])

public_key_api_params = set(["label", "id", "data", "cka_copyable",
    "cka_derive", "cka_encrypt", "cka_modifiable", "cka_private",
    "cka_trusted", "cka_verify", "cka_verify_recover", "cka_wrap"])


class Key(MutableMapping):
    def __init__(self, p11, handle):
        self.p11 = p11
        self.handle = handle
        # sanity check CKA_ID and CKA_LABEL
        try:
            cka_id = self.p11.get_attribute(handle, _ipap11helper.CKA_ID)
            assert len(cka_id) != 0, 'ipk11id length should not be 0'
        except _ipap11helper.NotFound:
            raise _ipap11helper.NotFound('key without ipk11id: handle %s' % handle)

        try:
            cka_label = self.p11.get_attribute(handle, _ipap11helper.CKA_LABEL)
            assert len(cka_label) != 0, 'ipk11label length should not be 0'

        except _ipap11helper.NotFound:
            raise _ipap11helper.NotFound(
                'key without ipk11label: id 0x%s' % str_hexlify(cka_id))

    def __getitem__(self, key):
        key = key.lower()
        try:
            value = self.p11.get_attribute(self.handle, attrs_name2id[key])
            if key == 'ipk11keytype':
                value = keytype_id2name[value]
            return value
        except _ipap11helper.NotFound:
            raise KeyError()

    def __setitem__(self, key, value):
        key = key.lower()
        if key == 'ipk11keytype':
            value = keytype_name2id[value]

        return self.p11.set_attribute(self.handle, attrs_name2id[key], value)

    def __delitem__(self, key):
        raise _ipap11helper.P11HelperException('__delitem__ is not supported')

    def __iter__(self):
        """generates list of ipa names of all attributes present in the object"""
        for pkcs11_id, ipa_name in attrs_id2name.items():
            try:
                self.p11.get_attribute(self.handle, pkcs11_id)
            except _ipap11helper.NotFound:
                continue

            yield ipa_name

    def __len__(self):
        cnt = 0
        for _attr in self:
            cnt += 1
        return cnt

    def __str__(self):
        return str(dict(self))

    def __repr__(self):
        return self.__str__()


class LocalHSM(AbstractHSM):
    def __init__(self, library, label, pin):
        self.cache_replica_pubkeys = None
        self.p11 = _ipap11helper.P11_Helper(label, pin, library)

    def __del__(self):
        self.p11.finalize()

    def find_keys(self, **kwargs):
        """Return dict with Key objects matching given criteria.

        CKA_ID is used as key so all matching objects have to have unique ID."""

        # this is a hack for old p11-kit URI parser
        # see https://bugs.freedesktop.org/show_bug.cgi?id=85057
        if 'uri' in kwargs:
            kwargs['uri'] = kwargs['uri'].replace('type=', 'object-type=')

        handles = self.p11.find_keys(**kwargs)
        keys = {}
        for h in handles:
            key = Key(self.p11, h)
            o_id = key['ipk11id']
            assert o_id not in keys, 'duplicate ipk11Id = 0x%s; keys = %s' % (
                    str_hexlify(o_id), keys)
            keys[o_id] = key

        return keys

    @property
    def replica_pubkeys(self):
        return self._filter_replica_keys(
                self.find_keys(objclass=_ipap11helper.KEY_CLASS_PUBLIC_KEY))

    @property
    def replica_pubkeys_wrap(self):
        return self._filter_replica_keys(
                self.find_keys(objclass=_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                cka_wrap=True))

    @property
    def master_keys(self):
        """Get all usable DNSSEC master keys"""
        keys = self.find_keys(objclass=_ipap11helper.KEY_CLASS_SECRET_KEY, label=u'dnssec-master', cka_unwrap=True)

        for key in keys.values():
            prefix = 'dnssec-master'
            assert key['ipk11label'] == prefix, \
                'secret key ipk11id=0x%s ipk11label="%s" with ipk11UnWrap ' \
                '= TRUE does not have "%s" key label' % (
                    str_hexlify(key['ipk11id']),
                    str(key['ipk11label']), prefix
                )

        return keys

    @property
    def active_master_key(self):
        """Get one active DNSSEC master key suitable for key wrapping"""
        keys = self.find_keys(objclass=_ipap11helper.KEY_CLASS_SECRET_KEY,
                label=u'dnssec-master', cka_wrap=True, cka_unwrap=True)
        assert len(keys) > 0, "DNSSEC master key with UN/WRAP = TRUE not found"
        return keys.popitem()[1]

    @property
    def zone_pubkeys(self):
        return self._filter_zone_keys(
                self.find_keys(objclass=_ipap11helper.KEY_CLASS_PUBLIC_KEY))

    @property
    def zone_privkeys(self):
        return self._filter_zone_keys(
                self.find_keys(objclass=_ipap11helper.KEY_CLASS_PRIVATE_KEY))


    def import_public_key(self, source, data):
        params = ldap2p11helper_api_params(source)
        # filter out params inappropriate for public keys
        for par in set(params).difference(public_key_api_params):
            del params[par]
        params['data'] = data

        h = self.p11.import_public_key(**params)
        return Key(self.p11, h)

    def import_private_key(self, source, data, unwrapping_key):
        params = ldap2p11helper_api_params(source)
        # filter out params inappropriate for private keys
        for par in set(params).difference(private_key_api_params):
            del params[par]
        params['data'] = data
        params['unwrapping_key'] = unwrapping_key.handle

        h = self.p11.import_wrapped_private_key(**params)
        return Key(self.p11, h)


if __name__ == '__main__':
    if 'SOFTHSM2_CONF' not in os.environ:
        os.environ['SOFTHSM2_CONF'] = paths.DNSSEC_SOFTHSM2_CONF
    localhsm = LocalHSM(paths.LIBSOFTHSM2_SO, SOFTHSM_DNSSEC_TOKEN_LABEL,
            open(paths.DNSSEC_SOFTHSM_PIN).read())

    print('replica public keys: CKA_WRAP = TRUE')
    print('====================================')
    for pubkey_id, pubkey in localhsm.replica_pubkeys_wrap.items():
        print(str_hexlify(pubkey_id))
        pprint(pubkey)

    print('')
    print('replica public keys: all')
    print('========================')
    for pubkey_id, pubkey in localhsm.replica_pubkeys.items():
        print(str_hexlify(pubkey_id))
        pprint(pubkey)

    print('')
    print('master keys')
    print('===========')
    for mkey_id, mkey in localhsm.master_keys.items():
        print(str_hexlify(mkey_id))
        pprint(mkey)

    print('')
    print('zone public keys')
    print('================')
    for key_id, zkey in localhsm.zone_pubkeys.items():
        print(str_hexlify(key_id))
        pprint(zkey)

    print('')
    print('zone private keys')
    print('=================')
    for key_id, zkey in localhsm.zone_privkeys.items():
        print(str_hexlify(key_id))
        pprint(zkey)
