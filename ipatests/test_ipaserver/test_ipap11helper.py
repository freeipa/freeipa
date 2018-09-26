# -*- coding: utf-8 -*-
#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#
"""
Test the `ipapython/ipap11helper/p11helper.c` module.
"""


from __future__ import absolute_import

from binascii import hexlify
import os
import os.path
import logging
import subprocess
import tempfile

import pytest
from ipaplatform.paths import paths

from ipaserver import p11helper as _ipap11helper

pytestmark = pytest.mark.tier0

CONFIG_DATA = """
# SoftHSM v2 configuration file
directories.tokendir = %s/tokens
objectstore.backend = file
"""

LIBSOFTHSM = paths.LIBSOFTHSM2_SO
SOFTHSM2_UTIL = paths.SOFTHSM2_UTIL

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('t')


master_key_label = u"master-ž"  # random non-ascii character to test unicode
master_key_id = "m"
replica1_key_label = u"replica1"
replica1_key_id = "id1"
replica1_import_label = u"replica1-import"
replica1_import_id = "id1-import"
replica1_new_label = u"replica1-new-label-ž"
replica2_key_label = u"replica2"
replica2_key_id = "id2"
replica_non_existent_label = u"replica-nonexistent"


@pytest.fixture(scope="module")
def token_path():
    token_path = tempfile.mkdtemp(prefix='pytest_', suffix='_pkcs11')
    os.mkdir(os.path.join(token_path, 'tokens'))
    return token_path


@pytest.fixture(scope="module")
def p11(request, token_path):
    with open(os.path.join(token_path, 'softhsm2.conf'), 'w') as cfg:
        cfg.write(CONFIG_DATA % token_path)

    args = [
        SOFTHSM2_UTIL, '--init-token', '--free',
        '--label', 'test',
        '--pin', '1234',
        '--so-pin', '1234'
    ]
    os.environ['SOFTHSM2_CONF'] = os.path.join(token_path, 'softhsm2.conf')
    subprocess.check_call(args, cwd=token_path)

    try:
        p11 = _ipap11helper.P11_Helper('test', "1234", LIBSOFTHSM)
    except _ipap11helper.Error:
        pytest.fail('Failed to initialize the helper object.', pytrace=False)

    def fin():
        try:
            p11.finalize()
        except _ipap11helper.Error:
            pytest.fail('Failed to finalize the helper object.', pytrace=False)
        finally:
            subprocess.call(
                [SOFTHSM2_UTIL, '--delete-token', '--label', 'test'],
                cwd=token_path
            )
            del os.environ['SOFTHSM2_CONF']

    request.addfinalizer(fin)

    return p11


class test_p11helper:
    def test_generate_master_key(self, p11):
        assert p11.generate_master_key(master_key_label, master_key_id,
                                       key_length=16, cka_wrap=True,
                                       cka_unwrap=True)

    def test_search_for_master_key(self, p11):
        master_key = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                                   label=master_key_label, id=master_key_id)
        assert len(master_key) == 1, "The master key should exist."

    def test_generate_replica_key_pair(self, p11):
        assert p11.generate_replica_key_pair(replica1_key_label,
                                             replica1_key_id,
                                             pub_cka_wrap=True,
                                             priv_cka_unwrap=True)

    def test_find_key(self, p11):
        rep1_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                 label=replica1_key_label, cka_wrap=True)
        assert len(rep1_pub) == 1, ("replica key pair has to contain "
                                    "1 pub key instead of %s" % len(rep1_pub))

        rep1_priv = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY,
                                  label=replica1_key_label, cka_unwrap=True)
        assert len(rep1_priv) == 1, ("replica key pair has to contain 1 "
                                     "private key instead of %s" %
                                     len(rep1_priv))

    def test_find_key_by_uri(self, p11):
        rep1_pub = p11.find_keys(uri="pkcs11:object=replica1;objecttype=public")
        assert len(rep1_pub) == 1, ("replica key pair has to contain 1 pub "
                                    "key instead of %s" % len(rep1_pub))

    def test_get_attribute_from_object(self, p11):
        rep1_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                 label=replica1_key_label, cka_wrap=True)[0]

        iswrap = p11.get_attribute(rep1_pub, _ipap11helper.CKA_WRAP)
        assert iswrap is True, "replica public key has to have CKA_WRAP = TRUE"

    def test_generate_replica_keypair_with_extractable_private_key(self, p11):
        assert p11.generate_replica_key_pair(replica2_key_label,
                                             replica2_key_id,
                                             pub_cka_wrap=True,
                                             priv_cka_unwrap=True,
                                             priv_cka_extractable=True)

    def test_find_key_on_nonexistent_key_pair(self, p11):
        test_list = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                  label=replica_non_existent_label)
        assert len(test_list) == 0, ("list should be empty because label "
                                     "'%s' should not exist" %
                                     replica_non_existent_label)

    def test_export_import_of_public_key(self, p11, token_path):
        rep1_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                 label=replica1_key_label, cka_wrap=True)[0]
        pub = p11.export_public_key(rep1_pub)

        log.debug("Exported public key %s", hexlify(pub))
        pubfile = os.path.join(token_path, "public_key.asn1.der")
        with open(pubfile, "wb") as f:
            f.write(pub)

        rep1_pub_import = p11.import_public_key(replica1_import_label,
                                                replica1_import_id,
                                                pub,
                                                cka_wrap=True)
        log.debug('imported replica 1 public key: %s', rep1_pub_import)

        # test public key import
        rep1_modulus_orig = p11.get_attribute(rep1_pub,
                                              _ipap11helper.CKA_MODULUS)
        rep1_modulus_import = p11.get_attribute(rep1_pub_import,
                                                _ipap11helper.CKA_MODULUS)
        log.debug('rep1_modulus_orig   = 0x%s', hexlify(rep1_modulus_orig))
        log.debug('rep1_modulus_import = 0x%s', hexlify(rep1_modulus_import))
        assert rep1_modulus_import == rep1_modulus_orig

        rep1_pub_exp_orig = p11.get_attribute(
            rep1_pub, _ipap11helper.CKA_PUBLIC_EXPONENT)
        rep1_pub_exp_import = p11.get_attribute(
            rep1_pub_import, _ipap11helper.CKA_PUBLIC_EXPONENT)
        log.debug('rep1_pub_exp_orig   = 0x%s', hexlify(rep1_pub_exp_orig))
        log.debug('rep1_pub_exp_import = 0x%s', hexlify(rep1_pub_exp_import))
        assert rep1_pub_exp_import == rep1_pub_exp_orig

    def test_wrap_unwrap_key_by_master_key_with_AES(self, p11, token_path):
        master_key = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                                   label=master_key_label, id=master_key_id)[0]
        rep2_priv = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY,
                                  label=replica2_key_label, cka_unwrap=True)[0]

        log.debug("wrapping dnssec priv key by master key")
        wrapped_priv = p11.export_wrapped_key(
            rep2_priv, master_key, _ipap11helper.MECH_AES_KEY_WRAP_PAD
        )
        assert wrapped_priv

        log.debug("wrapped_dnssec priv key: %s", hexlify(wrapped_priv))
        privfile = os.path.join(token_path, "wrapped_priv.der")
        with open(privfile, "wb") as f:
            f.write(wrapped_priv)

        assert p11.import_wrapped_private_key(
            u'test_import_wrapped_priv',
            '1',
            wrapped_priv,
            master_key,
            _ipap11helper.MECH_AES_KEY_WRAP_PAD,
            _ipap11helper.KEY_TYPE_RSA
        )

    def test_wrap_unwrap_key_by_master_key_with_RSA_PKCS(self, p11):
        master_key = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                                   label=master_key_label, id=master_key_id)[0]
        rep2_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                 label=replica2_key_label, cka_wrap=True)[0]
        rep2_priv = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY,
                                  label=replica2_key_label, cka_unwrap=True)[0]

        wrapped = p11.export_wrapped_key(master_key,
                                         rep2_pub,
                                         _ipap11helper.MECH_RSA_PKCS)
        assert wrapped

        log.debug("wrapped key MECH_RSA_PKCS (secret master wrapped by pub "
                  "key): %s", hexlify(wrapped))
        assert p11.import_wrapped_secret_key(u'test_import_wrapped',
                                             '2',
                                             wrapped,
                                             rep2_priv,
                                             _ipap11helper.MECH_RSA_PKCS,
                                             _ipap11helper.KEY_TYPE_AES)

    def test_wrap_unwrap_by_master_key_with_RSA_PKCS_OAEP(self, p11):
        master_key = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                                   label=master_key_label, id=master_key_id)[0]
        rep2_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                 label=replica2_key_label, cka_wrap=True)[0]
        rep2_priv = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY,
                                  label=replica2_key_label, cka_unwrap=True)[0]

        wrapped = p11.export_wrapped_key(master_key,
                                         rep2_pub,
                                         _ipap11helper.MECH_RSA_PKCS_OAEP)
        assert wrapped

        log.debug("wrapped key MECH_RSA_PKCS_OAEP (secret master wrapped by "
                  "pub key): %s", hexlify(wrapped))

        assert p11.import_wrapped_secret_key(u'test_import_wrapped',
                                             '3',
                                             wrapped,
                                             rep2_priv,
                                             _ipap11helper.MECH_RSA_PKCS_OAEP,
                                             _ipap11helper.KEY_TYPE_AES)

    def test_set_attribute_on_object(self, p11):
        rep1_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                 label=replica1_key_label, cka_wrap=True)[0]
        test_label = replica1_new_label

        p11.set_attribute(rep1_pub, _ipap11helper.CKA_LABEL, test_label)
        assert p11.get_attribute(rep1_pub, _ipap11helper.CKA_LABEL) \
            == test_label, "The labels do not match."

    def test_do_not_generate_identical_master_keys(self, p11):
        with pytest.raises(_ipap11helper.DuplicationError):
            p11.generate_master_key(master_key_label, master_key_id,
                                    key_length=16)

        master_key = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                                   label=master_key_label)
        assert len(master_key) == 1, ("There shouldn't be multiple keys "
                                      "with the same label.")

    def test_delete_key(self, p11):
        master_key = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                                   label=master_key_label, id=master_key_id)[0]
        rep1_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                 label=replica1_new_label, cka_wrap=True)[0]
        rep2_priv = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY,
                                  label=replica2_key_label, cka_unwrap=True)[0]

        for key in (rep1_pub, rep2_priv, master_key):
            p11.delete_key(key)

        master_key = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                                   label=master_key_label, id=master_key_id)
        assert len(master_key) == 0, "The master key should be deleted."
        rep1_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                 label=replica1_new_label, cka_wrap=True)
        assert len(rep1_pub) == 0, ("The public key of replica1 pair should "
                                    "be deleted.")
        rep2_priv = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY,
                                  label=replica2_key_label, cka_unwrap=True)
        assert len(rep2_priv) == 0, ("The private key of replica2 pair should"
                                     " be deleted.")
