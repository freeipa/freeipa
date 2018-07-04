#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

from binascii import hexlify
import logging
from pprint import pprint

import six

import ipalib
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython import ipaldap
from ipapython import ipa_log_manager

from ipaserver.dnssec.abshsm import (
    attrs_name2id,
    AbstractHSM,
    bool_attr_names,
    populate_pkcs11_metadata)
from ipaserver import p11helper as _ipap11helper
import uuid

# pylint: disable=no-name-in-module, import-error
if six.PY3:
    from collections.abc import MutableMapping
else:
    from collections import MutableMapping
# pylint: enable=no-name-in-module, import-error

logger = logging.getLogger(__name__)


def uri_escape(val):
    """convert val to %-notation suitable for ID component in URI"""
    if len(val) == 0:
        raise ValueError("zero-length URI component detected")
    hexval = str_hexlify(val)
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
        raise ValueError('invalid LDAP boolean "%s"' % val)


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
        raise ValueError(
            "none of '%s' object classes are supported" % object_classes
        )

    result = {}
    for cls in present_clss:
        result.update(defaults[cls])
    return result


def str_hexlify(data):
    out = hexlify(data)
    if isinstance(out, bytes):
        out = out.decode('utf-8')
    return out


class Key(MutableMapping):
    """abstraction to hide LDAP entry weirdnesses:
        - non-normalized attribute names
        - boolean attributes returned as strings
        - planned entry deletion prevents subsequent use of the instance
    """
    def __init__(self, entry, ldap, ldapkeydb):
        self.entry = entry
        self._delentry = None  # indicates that object was deleted
        self.ldap = ldap
        self.ldapkeydb = ldapkeydb

    def __assert_not_deleted(self):
        assert self.entry and not self._delentry, (
            "attempt to use to-be-deleted entry %s detected"
            % self._delentry.dn)

    def __getitem__(self, key):
        self.__assert_not_deleted()
        val = self.entry.single_value[key]
        if key.lower() in bool_attr_names:
            val = ldap_bool(val)
        return val

    def __setitem__(self, key, value):
        self.__assert_not_deleted()
        self.entry[key] = value

    def __delitem__(self, key):
        self.__assert_not_deleted()
        del self.entry[key]

    def __iter__(self):
        """generates list of ipa names of all PKCS#11 attributes present in the object"""
        self.__assert_not_deleted()
        for ipa_name in list(self.entry.keys()):
            lowercase = ipa_name.lower()
            if lowercase in attrs_name2id:
                yield lowercase

    def __len__(self):
        self.__assert_not_deleted()
        return len(self.entry)

    def __repr__(self):
        if self._delentry:
            return 'deleted entry: %s' % repr(self._delentry)

        sanitized = dict(self.entry)
        for attr in ['ipaPrivateKey', 'ipaPublicKey', 'ipk11publickeyinfo']:
            if attr in sanitized:
                del sanitized[attr]
        return repr(sanitized)

    def _cleanup_key(self):
        """remove default values from LDAP entry"""
        default_attrs = get_default_attrs(self.entry['objectclass'])
        empty = object()
        for attr in default_attrs:
            if self.get(attr, empty) == default_attrs[attr]:
                del self[attr]

    def _update_key(self):
        """remove default values from LDAP entry and write back changes"""
        if self._delentry:
            self._delete_key()
            return

        self._cleanup_key()

        try:
            self.ldap.update_entry(self.entry)
        except ipalib.errors.EmptyModlist:
            pass

    def _delete_key(self):
        """remove key metadata entry from LDAP

        After calling this, the python object is no longer valid and all
        subsequent method calls on it will fail.
        """
        assert not self.entry, (
            "Key._delete_key() called before Key.schedule_deletion()")
        assert self._delentry, "Key._delete_key() called more than once"
        logger.debug('deleting key id 0x%s DN %s from LDAP',
                     str_hexlify(self._delentry.single_value['ipk11id']),
                     self._delentry.dn)
        self.ldap.delete_entry(self._delentry)
        self._delentry = None
        self.ldap = None
        self.ldapkeydb = None

    def schedule_deletion(self):
        """schedule key deletion from LDAP

        Calling schedule_deletion() will make this object incompatible with
        normal Key. After that the object must not be read or modified.
        Key metadata will be actually deleted when LdapKeyDB.flush() is called.
        """
        assert not self._delentry, (
            "Key.schedule_deletion() called more than once")
        self._delentry = self.entry
        self.entry = None


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
        entry = self.ldap.make_entry(entry_dn,
                   objectClass=['ipaSecretKeyObject', 'ipk11Object'],
                   ipaSecretKey=data,
                   ipaWrappingKey=wrapping_key_uri,
                   ipaWrappingMech=wrapping_mech)

        logger.info('adding master key 0x%s wrapped with replica key 0x%s to '
                    '%s',
                    str_hexlify(self['ipk11id']),
                    str_hexlify(replica_key_id),
                    entry_dn)
        self.ldap.add_entry(entry)
        if 'ipaSecretKeyRef' not in self.entry:
            self.entry['objectClass'] += ['ipaSecretKeyRefObject']
        self.entry.setdefault('ipaSecretKeyRef', []).append(entry_dn)


class LdapKeyDB(AbstractHSM):
    def __init__(self, ldap, base_dn):
        self.ldap = ldap
        self.base_dn = base_dn
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

            if 'ipk11id' not in key:
                raise ValueError(
                    'key is missing ipk11Id in %s' % key.entry.dn
                )
            key_id = key['ipk11id']
            if key_id in keys:
                raise ValueError(
                    "duplicate ipk11Id=0x%s in '%s' and '%s'"
                    % (str_hexlify(key_id), key.entry.dn,
                       keys[key_id].entry.dn)
                )
            if 'ipk11label' not in key:
                raise ValueError(
                    "key '%s' is missing ipk11Label" % key.entry.dn
                )
            if 'objectclass' not in key.entry:
                raise ValueError(
                    "key '%s' is missing objectClass attribute"
                    % key.entry.dn
                )

            keys[key_id] = key

        self._update_keys()
        return keys

    def _update_keys(self):
        for cache in [self.cache_masterkeys, self.cache_replica_pubkeys_wrap,
                      self.cache_zone_keypairs]:
            if cache:
                for key in cache.values():
                    key._update_key()

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
                raise ValueError(
                    "unsupported object class '%s'" % pkcs11_class
                )

            populate_pkcs11_metadata(source_key, new_key)
        new_key._cleanup_key()
        return new_key

    def import_master_key(self, mkey):
        new_key = self._import_keys_metadata(
                [(mkey, _ipap11helper.KEY_CLASS_SECRET_KEY)])
        self.ldap.add_entry(new_key.entry)
        logger.debug('imported master key metadata: %s', new_key.entry)

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
        logger.debug('imported zone key id: 0x%s',
                     str_hexlify(new_key['ipk11id']))

    @property
    def replica_pubkeys_wrap(self):
        if self.cache_replica_pubkeys_wrap:
            return self.cache_replica_pubkeys_wrap

        keys = self._filter_replica_keys(
            self._get_key_dict(
                ReplicaKey,
                '(&(objectClass=ipk11PublicKey)(ipk11Wrap=TRUE)'
                '(objectClass=ipaPublicKeyObject))'
            )
        )

        self.cache_replica_pubkeys_wrap = keys
        return keys

    @property
    def master_keys(self):
        if self.cache_masterkeys:
            return self.cache_masterkeys

        keys = self._get_key_dict(
            MasterKey,
            '(&(objectClass=ipk11SecretKey)'
            '(|(ipk11UnWrap=TRUE)(!(ipk11UnWrap=*)))'
            '(ipk11Label=dnssec-master))'
        )
        for key in keys.values():
            prefix = 'dnssec-master'
            if key['ipk11label'] != prefix:
                raise ValueError(
                    "secret key dn='%s' ipk11id=0x%s ipk11label='%s' with "
                    "ipk11UnWrap = TRUE does not have '%s' key label'"
                    % (key.entry.dn, str_hexlify(key['ipk11id']),
                       str(key['ipk11label']), prefix)
                )

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

if __name__ == '__main__':
    # this is debugging mode
    # print information we think are useful to stdout
    # other garbage goes via logger to stderr
    ipa_log_manager.standard_logging_setup(debug=True)

    # IPA framework initialization
    # no logging to file
    ipalib.api.bootstrap(in_server=True, log=None, confdir=paths.ETC_IPA)
    ipalib.api.finalize()

    # LDAP initialization
    dns_dn = DN(ipalib.api.env.container_dns, ipalib.api.env.basedn)
    ldap = ipaldap.LDAPClient(ipalib.api.env.ldap_uri)
    logger.debug('Connecting to LDAP')
    # GSSAPI will be used, used has to be kinited already
    ldap.gssapi_bind()
    logger.debug('Connected')

    ldapkeydb = LdapKeyDB(ldap, DN(('cn', 'keys'),
                                   ('cn', 'sec'),
                                   ipalib.api.env.container_dns,
                                   ipalib.api.env.basedn))

    print('replica public keys: CKA_WRAP = TRUE')
    print('====================================')
    for pubkey_id, pubkey in ldapkeydb.replica_pubkeys_wrap.items():
        print(str_hexlify(pubkey_id))
        pprint(pubkey)

    print('')
    print('master keys')
    print('===========')
    for mkey_id, mkey in ldapkeydb.master_keys.items():
        print(str_hexlify(mkey_id))
        pprint(mkey)

    print('')
    print('zone key pairs')
    print('==============')
    for key_id, key in ldapkeydb.zone_keypairs.items():
        print(str_hexlify(key_id))
        pprint(key)
