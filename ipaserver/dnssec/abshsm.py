#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

import logging

from ipaserver import p11helper as _ipap11helper

logger = logging.getLogger(__name__)

attrs_id2name = {
    #_ipap11helper.CKA_ALLOWED_MECHANISMS: 'ipk11allowedmechanisms',
    _ipap11helper.CKA_ALWAYS_AUTHENTICATE: 'ipk11alwaysauthenticate',
    _ipap11helper.CKA_ALWAYS_SENSITIVE: 'ipk11alwayssensitive',
    #_ipap11helper.CKA_CHECK_VALUE: 'ipk11checkvalue',
    _ipap11helper.CKA_COPYABLE: 'ipk11copyable',
    _ipap11helper.CKA_DECRYPT: 'ipk11decrypt',
    _ipap11helper.CKA_DERIVE: 'ipk11derive',
    #_ipap11helper.CKA_DESTROYABLE: 'ipk11destroyable',
    _ipap11helper.CKA_ENCRYPT: 'ipk11encrypt',
    #_ipap11helper.CKA_END_DATE: 'ipk11enddate',
    _ipap11helper.CKA_EXTRACTABLE: 'ipk11extractable',
    _ipap11helper.CKA_ID: 'ipk11id',
    #_ipap11helper.CKA_KEY_GEN_MECHANISM: 'ipk11keygenmechanism',
    _ipap11helper.CKA_KEY_TYPE: 'ipk11keytype',
    _ipap11helper.CKA_LABEL: 'ipk11label',
    _ipap11helper.CKA_LOCAL: 'ipk11local',
    _ipap11helper.CKA_MODIFIABLE: 'ipk11modifiable',
    _ipap11helper.CKA_NEVER_EXTRACTABLE: 'ipk11neverextractable',
    _ipap11helper.CKA_PRIVATE: 'ipk11private',
    #_ipap11helper.CKA_PUBLIC_KEY_INFO: 'ipapublickey',
    #_ipap11helper.CKA_PUBLIC_KEY_INFO: 'ipk11publickeyinfo',
    _ipap11helper.CKA_SENSITIVE: 'ipk11sensitive',
    _ipap11helper.CKA_SIGN: 'ipk11sign',
    _ipap11helper.CKA_SIGN_RECOVER: 'ipk11signrecover',
    #_ipap11helper.CKA_START_DATE: 'ipk11startdate',
    #_ipap11helper.CKA_SUBJECT: 'ipk11subject',
    _ipap11helper.CKA_TRUSTED: 'ipk11trusted',
    _ipap11helper.CKA_UNWRAP: 'ipk11unwrap',
    #_ipap11helper.CKA_UNWRAP_TEMPLATE: 'ipk11unwraptemplate',
    _ipap11helper.CKA_VERIFY: 'ipk11verify',
    _ipap11helper.CKA_VERIFY_RECOVER: 'ipk11verifyrecover',
    _ipap11helper.CKA_WRAP: 'ipk11wrap',
    #_ipap11helper.CKA_WRAP_TEMPLATE: 'ipk11wraptemplate',
    _ipap11helper.CKA_WRAP_WITH_TRUSTED: 'ipk11wrapwithtrusted',
}

attrs_name2id = {v: k for k, v in attrs_id2name.items()}

# attribute:
# http://www.freeipa.org/page/V4/PKCS11_in_LDAP/Schema#ipk11KeyType
#
# mapping table:
# http://www.freeipa.org/page/V4/PKCS11_in_LDAP/Schema#CK_MECHANISM_TYPE
keytype_name2id = {
        "rsa": _ipap11helper.KEY_TYPE_RSA,
        "aes": _ipap11helper.KEY_TYPE_AES,
        }

keytype_id2name = {v: k for k, v in keytype_name2id.items()}

wrappingmech_name2id = {
        "rsaPkcs": _ipap11helper.MECH_RSA_PKCS,
        "rsaPkcsOaep": _ipap11helper.MECH_RSA_PKCS_OAEP,
        "aesKeyWrap": _ipap11helper.MECH_AES_KEY_WRAP,
        "aesKeyWrapPad": _ipap11helper.MECH_AES_KEY_WRAP_PAD
        }

wrappingmech_id2name = {v: k for k, v in wrappingmech_name2id.items()}


bool_attr_names = set([
    'ipk11alwaysauthenticate',
    'ipk11alwayssensitive',
    'ipk11copyable',
    'ipk11decrypt',
    'ipk11derive',
    'ipk11encrypt',
    'ipk11extractable',
    'ipk11local',
    'ipk11modifiable',
    'ipk11neverextractable',
    'ipk11private',
    'ipk11sensitive',
    'ipk11sign',
    'ipk11signrecover',
    'ipk11trusted',
    'ipk11unwrap',
    'ipk11verify',
    'ipk11verifyrecover',
    'ipk11wrap',
    'ipk11wrapwithtrusted',
])

modifiable_attrs_id2name = {
    _ipap11helper.CKA_DECRYPT: 'ipk11decrypt',
    _ipap11helper.CKA_DERIVE: 'ipk11derive',
    _ipap11helper.CKA_ENCRYPT: 'ipk11encrypt',
    _ipap11helper.CKA_EXTRACTABLE: 'ipk11extractable',
    _ipap11helper.CKA_ID: 'ipk11id',
    _ipap11helper.CKA_LABEL: 'ipk11label',
    _ipap11helper.CKA_SENSITIVE: 'ipk11sensitive',
    _ipap11helper.CKA_SIGN: 'ipk11sign',
    _ipap11helper.CKA_SIGN_RECOVER: 'ipk11signrecover',
    _ipap11helper.CKA_UNWRAP: 'ipk11unwrap',
    _ipap11helper.CKA_VERIFY: 'ipk11verify',
    _ipap11helper.CKA_VERIFY_RECOVER: 'ipk11verifyrecover',
    _ipap11helper.CKA_WRAP: 'ipk11wrap',
}

modifiable_attrs_name2id = {v: k for k, v in modifiable_attrs_id2name.items()}


def sync_pkcs11_metadata(name, source, target):
    """sync ipk11 metadata from source object to target object"""

    # iterate over list of modifiable PKCS#11 attributes - this prevents us
    # from attempting to set read-only attributes like CKA_LOCAL
    for attr in modifiable_attrs_name2id:
        if attr in source:
            if source[attr] != target[attr]:
                logger.debug('%s: Updating attribute %s from "%s" to "%s"',
                             name,
                             attr,
                             repr(source[attr]),
                             repr(target[attr]))
                target[attr] = source[attr]

def populate_pkcs11_metadata(source, target):
    """populate all ipk11 metadata attributes in target object from source object"""
    for attr in attrs_name2id:
        if attr in source:
            target[attr] = source[attr]

def ldap2p11helper_api_params(ldap_key):
    """prepare dict with metadata parameters suitable for key unwrapping"""
    unwrap_params = {}

    # some attributes are just renamed
    direct_param_map = {
            "ipk11label": "label",
            "ipk11id": "id",
            "ipk11copyable": "cka_copyable",
            "ipk11decrypt": "cka_decrypt",
            "ipk11derive": "cka_derive",
            "ipk11encrypt": "cka_encrypt",
            "ipk11extractable": "cka_extractable",
            "ipk11modifiable": "cka_modifiable",
            "ipk11private": "cka_private",
            "ipk11sensitive": "cka_sensitive",
            "ipk11sign": "cka_sign",
            "ipk11unwrap": "cka_unwrap",
            "ipk11verify": "cka_verify",
            "ipk11wrap": "cka_wrap",
            "ipk11wrapwithtrusted": "cka_wrap_with_trusted"
            }

    for ldap_name, p11h_name in direct_param_map.items():
        if ldap_name in ldap_key:
            unwrap_params[p11h_name] = ldap_key[ldap_name]

    # and some others needs conversion

    indirect_param_map = {
            "ipk11keytype": ("key_type", keytype_name2id),
            "ipawrappingmech": ("wrapping_mech", wrappingmech_name2id),
            }

    for ldap_name, rules in indirect_param_map.items():
        p11h_name, mapping = rules
        if ldap_name in ldap_key:
            unwrap_params[p11h_name] = mapping[ldap_key[ldap_name]]

    return unwrap_params


class AbstractHSM:
    def _filter_replica_keys(self, all_keys):
        replica_keys = {}
        for key_id, key in all_keys.items():
            if not key['ipk11label'].startswith('dnssec-replica:'):
                continue
            replica_keys[key_id] = key
        return replica_keys

    def _filter_zone_keys(self, all_keys):
        zone_keys = {}
        for key_id, key in all_keys.items():
            if key['ipk11label'] == u'dnssec-master' \
                or key['ipk11label'].startswith('dnssec-replica:'):
                continue
            zone_keys[key_id] = key
        return zone_keys
