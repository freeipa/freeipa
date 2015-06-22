#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from binascii import hexlify
import collections
import sys
import time

import ipalib
from ipapython.dn import DN
from ipapython import ipaldap
from ipapython import ipautil
from ipaplatform.paths import paths

from abshsm import attrs_name2id, attrs_id2name, bool_attr_names, populate_pkcs11_metadata, AbstractHSM
import _ipap11helper
import uuid

def uri_escape(val):
    """convert val to %-notation suitable for ID component in URI"""
    assert len(val) > 0, "zero-length URI component detected"
    hexval = hexlify(val)
    out = '%'
    # pylint: disable=E1127
    out += '%'.join(hexval[i:i+2] for i in range(0, len(hexval), 2))
    return out

def ldap_bool(val):
    if val == 'TRUE' or val is True:
        return True
    elif val == 'FALSE' or val is False:
        return False
    else:
        raise AssertionError('invalid LDAP boolean "%s"' % val)

def get_default_attrs(object_classes):
    # object class -> default attribute values mapping
    defaults = {
        u'ipk11publickey': {
            'ipk11copyable': True,
            'ipk11derive': False,
            'ipk11encrypt': False,
            'ipk11local': True,
            'ipk11modifiable': True,
            'ipk11private': True,
            'ipk11trusted': False,
            'ipk11verify': True,
            'ipk11verifyrecover': True,
            'ipk11wrap': False
        },
        u'ipk11privatekey': {
            'ipk11alwaysauthenticate': False,
            'ipk11alwayssensitive': True,
            'ipk11copyable': True,
            'ipk11decrypt': False,
            'ipk11derive': False,
            'ipk11extractable': True,
            'ipk11local': True,
            'ipk11modifiable': True,
            'ipk11neverextractable': False,
            'ipk11private': True,
            'ipk11sensitive': True,
            'ipk11sign': True,
            'ipk11signrecover': True,
            'ipk11unwrap': False,
            'ipk11wrapwithtrusted': False
        },
        u'ipk11secretkey': {
            'ipk11alwaysauthenticate': False,
            'ipk11alwayssensitive': True,
            'ipk11copyable': True,
            'ipk11decrypt': False,
            'ipk11derive': False,
            'ipk11encrypt': False,
            'ipk11extractable': True,
            'ipk11local': True,
            'ipk11modifiable': True,
            'ipk11neverextractable': False,
            'ipk11private': True,
            'ipk11sensitive': True,
            'ipk11sign': False,
            'ipk11trusted': False,
            'ipk11unwrap': True,
            'ipk11verify': False,
            'ipk11wrap': True,
            'ipk11wrapwithtrusted': False
        }
    }

    # get set of supported object classes
    present_clss = set()
    for cls in object_classes:
        present_clss.add(cls.lower())
    present_clss.intersection_update(set(defaults.keys()))
    if len(present_clss) <= 0:
        raise AssertionError('none of "%s" object classes are supported' %
                object_classes)

    result = {}
    for cls in present_clss:
        result.update(defaults[cls])
    return result

class Key(collections.MutableMapping):
    """abstraction to hide LDAP entry weirdnesses:
        - non-normalized attribute names
        - boolean attributes returned as strings
    """
    def __init__(self, entry, ldap, ldapkeydb):
        self.entry = entry
        self.ldap = ldap
        self.ldapkeydb = ldapkeydb
        self.log = ldap.log.getChild(__name__)

    def __getitem__(self, key):
        val = self.entry.single_value[key]
        if key.lower() in bool_attr_names:
            val = ldap_bool(val)
        return val

    def __setitem__(self, key, value):
        self.entry[key] = value

    def __delitem__(self, key):
        del self.entry[key]

    def __iter__(self):
        """generates list of ipa names of all PKCS#11 attributes present in the object"""
        for ipa_name in self.entry.keys():
            lowercase = ipa_name.lower()
            if lowercase in attrs_name2id:
                yield lowercase

    def __len__(self):
        return len(self.entry)

    def __str__(self):
        return str(self.entry)

    def _cleanup_key(self):
        """remove default values from LDAP entry"""
        default_attrs = get_default_attrs(self.entry['objectclass'])
        empty = object()
        for attr in default_attrs:
            if self.get(attr, empty) == default_attrs[attr]:
                del self[attr]

class ReplicaKey(Key):
    # TODO: object class assert
    def __init__(self, entry, ldap, ldapkeydb):
        super(ReplicaKey, self).__init__(entry, ldap, ldapkeydb)

class MasterKey(Key):
    # TODO: object class assert
    def __init__(self, entry, ldap, ldapkeydb):
        super(MasterKey, self).__init__(entry, ldap, ldapkeydb)

    @property
    def wrapped_entries(self):
        """LDAP entires with wrapped data

        One entry = one blob + ipaWrappingKey pointer to unwrapping key"""

        keys = []
        if 'ipaSecretKeyRef' not in self.entry:
            return keys

        for dn in self.entry['ipaSecretKeyRef']:
            try:
                obj = self.ldap.get_entry(dn)
                keys.append(obj)
            except ipalib.errors.NotFound:
                continue

        return keys

    def add_wrapped_data(self, data, wrapping_mech, replica_key_id):
        wrapping_key_uri = 'pkcs11:id=%s;type=public' \
                % uri_escape(replica_key_id)
        # TODO: replace this with 'autogenerate' to prevent collisions
        uuid_rdn = DN('ipk11UniqueId=%s' % uuid.uuid1())
        entry_dn = DN(uuid_rdn, self.ldapkeydb.base_dn)
        # TODO: add ipaWrappingMech attribute
        entry = self.ldap.make_entry(entry_dn,
                   objectClass=['ipaSecretKeyObject', 'ipk11Object'],
                   ipaSecretKey=data,
                   ipaWrappingKey=wrapping_key_uri,
                   ipaWrappingMech=wrapping_mech)

        self.log.info('adding master key 0x%s wrapped with replica key 0x%s to %s',
                hexlify(self['ipk11id']),
                hexlify(replica_key_id),
                entry_dn)
        self.ldap.add_entry(entry)
        if 'ipaSecretKeyRef' not in self.entry:
            self.entry['objectClass'] += ['ipaSecretKeyRefObject']
        self.entry.setdefault('ipaSecretKeyRef', []).append(entry_dn)


class LdapKeyDB(AbstractHSM):
    def __init__(self, log, ldap, base_dn):
        self.ldap = ldap
        self.base_dn = base_dn
        self.log = log
        self.cache_replica_pubkeys_wrap = None
        self.cache_masterkeys = None
        self.cache_zone_keypairs = None

    def _get_key_dict(self, key_type, ldap_filter):
        try:
            objs = self.ldap.get_entries(base_dn=self.base_dn,
                    filter=ldap_filter)
        except ipalib.errors.NotFound:
            return {}

        keys = {}
        for o in objs:
            # add default values not present in LDAP
            key = key_type(o, self.ldap, self)
            default_attrs = get_default_attrs(key.entry['objectclass'])
            for attr in default_attrs:
                key.setdefault(attr, default_attrs[attr])

            assert 'ipk11id' in o, 'key is missing ipk11Id in %s' % key.entry.dn
            key_id = key['ipk11id']
            assert key_id not in keys, 'duplicate ipk11Id=0x%s in "%s" and "%s"' % (hexlify(key_id), key.entry.dn, keys[key_id].entry.dn)
            assert 'ipk11label' in key, 'key "%s" is missing ipk11Label' % key.entry.dn
            assert 'objectclass' in key.entry, 'key "%s" is missing objectClass attribute' % key.entry.dn

            keys[key_id] = key

        self._update_keys()
        return keys

    def _update_key(self, key):
        """remove default values from LDAP entry and write back changes"""
        key._cleanup_key()

        try:
            self.ldap.update_entry(key.entry)
        except ipalib.errors.EmptyModlist:
            pass

    def _update_keys(self):
        for cache in [self.cache_masterkeys, self.cache_replica_pubkeys_wrap,
                self.cache_zone_keypairs]:
            if cache:
                for key in cache.itervalues():
                    self._update_key(key)

    def flush(self):
        """write back content of caches to LDAP"""
        self._update_keys()
        self.cache_masterkeys = None
        self.cache_replica_pubkeys_wrap = None
        self.cache_zone_keypairs = None

    def _import_keys_metadata(self, source_keys):
        """import key metadata from Key-compatible objects

        metadata from multiple source keys can be imported into single LDAP
        object

        :param: source_keys is iterable of (Key object, PKCS#11 object class)"""

        entry_dn = DN('ipk11UniqueId=autogenerate', self.base_dn)
        entry = self.ldap.make_entry(entry_dn, objectClass=['ipk11Object'])
        new_key = Key(entry, self.ldap, self)

        for source_key, pkcs11_class in source_keys:
            if pkcs11_class == _ipap11helper.KEY_CLASS_SECRET_KEY:
                entry['objectClass'].append('ipk11SecretKey')
            elif pkcs11_class == _ipap11helper.KEY_CLASS_PUBLIC_KEY:
                entry['objectClass'].append('ipk11PublicKey')
            elif pkcs11_class == _ipap11helper.KEY_CLASS_PRIVATE_KEY:
                entry['objectClass'].append('ipk11PrivateKey')
            else:
                raise AssertionError('unsupported object class %s' % pkcs11_class)

            populate_pkcs11_metadata(source_key, new_key)
        new_key._cleanup_key()
        return new_key

    def import_master_key(self, mkey):
        new_key = self._import_keys_metadata(
                [(mkey, _ipap11helper.KEY_CLASS_SECRET_KEY)])
        self.ldap.add_entry(new_key.entry)
        self.log.debug('imported master key metadata: %s', new_key.entry)

    def import_zone_key(self, pubkey, pubkey_data, privkey,
            privkey_wrapped_data, wrapping_mech, master_key_id):
        new_key = self._import_keys_metadata(
                    [(pubkey, _ipap11helper.KEY_CLASS_PUBLIC_KEY),
                    (privkey, _ipap11helper.KEY_CLASS_PRIVATE_KEY)])

        new_key.entry['objectClass'].append('ipaPrivateKeyObject')
        new_key.entry['ipaPrivateKey'] = privkey_wrapped_data
        new_key.entry['ipaWrappingKey'] = 'pkcs11:id=%s;type=secret-key' \
                % uri_escape(master_key_id)
        new_key.entry['ipaWrappingMech'] = wrapping_mech

        new_key.entry['objectClass'].append('ipaPublicKeyObject')
        new_key.entry['ipaPublicKey'] = pubkey_data

        self.ldap.add_entry(new_key.entry)
        self.log.debug('imported zone key id: 0x%s', hexlify(new_key['ipk11id']))

    @property
    def replica_pubkeys_wrap(self):
        if self.cache_replica_pubkeys_wrap:
            return self.cache_replica_pubkeys_wrap

        keys = self._filter_replica_keys(
                self._get_key_dict(ReplicaKey,
                '(&(objectClass=ipk11PublicKey)(ipk11Wrap=TRUE)(objectClass=ipaPublicKeyObject))'))

        self.cache_replica_pubkeys_wrap = keys
        return keys

    @property
    def master_keys(self):
        if self.cache_masterkeys:
            return self.cache_masterkeys

        keys = self._get_key_dict(MasterKey,
                '(&(objectClass=ipk11SecretKey)(|(ipk11UnWrap=TRUE)(!(ipk11UnWrap=*)))(ipk11Label=dnssec-master))')
        for key in keys.itervalues():
            prefix = 'dnssec-master'
            assert key['ipk11label'] == prefix, \
                'secret key dn="%s" ipk11id=0x%s ipk11label="%s" with ipk11UnWrap = TRUE does not have '\
                '"%s" key label' % (
                    key.entry.dn,
                    hexlify(key['ipk11id']),
                    str(key['ipk11label']),
                    prefix)

        self.cache_masterkeys = keys
        return keys

    @property
    def zone_keypairs(self):
        if self.cache_zone_keypairs:
            return self.cache_zone_keypairs

        self.cache_zone_keypairs = self._filter_zone_keys(
                self._get_key_dict(Key,
                '(&(objectClass=ipk11PrivateKey)(objectClass=ipaPrivateKeyObject)(objectClass=ipk11PublicKey)(objectClass=ipaPublicKeyObject))'))

        return self.cache_zone_keypairs
