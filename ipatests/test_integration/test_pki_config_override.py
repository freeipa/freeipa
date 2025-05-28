#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""Test cases for PKI config overrides
"""
from __future__ import absolute_import

from cryptography.hazmat.primitives import hashes

from ipalib.x509 import load_pem_x509_certificate
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


KEY_OVERRIDE = """
[DEFAULT]
ipa_ca_key_size=4096
ipa_ca_key_algorithm=SHA512withRSA
ipa_ca_signing_algorithm=SHA512withRSA
"""

HSM_OVERRIDE = """
[CA]
pki_hsm_enable = True
pki_hsm_libfile = /usr/lib64/pkcs11/libsofthsm2.so
pki_hsm_modulename = libsofthsm2
pki_token_name = ipa_token
pki_token_password = Secret123
"""


def server_install_teardown(func):
    def wrapped(*args):
        master = args[0].master
        try:
            func(*args)
        finally:
            tasks.uninstall_master(master)
    return wrapped


class TestPKIConfigOverride(IntegrationTest):
    @classmethod
    def install(cls, mh):
        pki_ini = tasks.upload_temp_contents(cls.master, KEY_OVERRIDE)
        extra_args = [
            '--pki-config-override', pki_ini,
        ]
        tasks.install_master(
            cls.master, setup_dns=False, extra_args=extra_args
        )
        cls.master.run_command(['rm', '-f', pki_ini])

    def test_cert_rsa4096(self):
        ca_pem = self.master.get_file_contents(
            paths.IPA_CA_CRT, encoding=None
        )
        cert = load_pem_x509_certificate(ca_pem)
        assert cert.public_key().key_size == 4096
        assert cert.signature_hash_algorithm.name == hashes.SHA512.name


class TestPKIHSMConfigOverride(IntegrationTest):
    num_replicas = 0

    @classmethod
    def install(cls, mh):
        pass

    @server_install_teardown
    def test_immutable_options(self):
        """Providing the immunible HSM options should fail"""
        pki_ini = tasks.upload_temp_contents(self.master, HSM_OVERRIDE)
        extra_args = [
            '--pki-config-override', pki_ini,
        ]
        result = tasks.install_master(
            self.master, setup_dns=False, extra_args=extra_args,
            raiseonerr=False
        )
        self.master.run_command(['rm', '-f', pki_ini])
        tasks.assert_error(
            result,
            'immutable options: pki_hsm_enable, pki_hsm_libfile, '
            'pki_hsm_modulename, pki_token_name, pki_token_password'
        )
