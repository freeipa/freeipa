#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Integration tests for ML-KEM (post-quantum) support in IPA vaults.

These tests cover the changes proposed in

    https://github.com/freeipa/freeipa/pull/8560/

which teach ``ipaclient/plugins/vault.py`` about ML-KEM (FIPS 203) keys in
two independent places:

1. **Asymmetric vault keys.**  ``encrypt()``/``decrypt()`` learn to
   encapsulate against an ML-KEM public key and to wrap the vault
   encryption key with AES-KW instead of RSA-OAEP.  The KEM ciphertext
   travels next to the wrapped key in the vault payload as
   ``kem_ciphertext``.  This is purely client side: the server stores the
   public key and the opaque payload, so it works against an unmodified
   IPA/KRA deployment.  Most of the tests below live here.

2. **The KRA transport certificate.**  ``_mlkem_archive()`` /
   ``_mlkem_retrieve()`` replace the RSA-wrapped session key with an
   ML-KEM encapsulation whose shared secret is truncated to 16 bytes for
   Dogtag compatibility.  FreeIPA's installer does not provision a KRA
   with an ML-KEM transport certificate, so the tests for this path
   detect the deployed transport key type and skip themselves when it is
   not ML-KEM.  Point the test suite at a KRA that was set up with an
   ML-KEM transport certificate to exercise them.

The whole class skips when the host's ``cryptography`` has no ML-KEM
support (it landed in cryptography 50.0.0) or when the installed
``ipaclient`` does not carry the ML-KEM patch.
"""

from __future__ import absolute_import

import json
import os
import time

import pytest

from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

# give some time to replication before reading a vault from another server
WAIT_AFTER_ARCHIVE = 45

WORK_DIR = '/root/mlkem-vault-tests'

# FIPS 203 ciphertext sizes, used to prove that a real encapsulation
# happened and that the right parameter set was picked up from the PEM.
MLKEM_CIPHERTEXT_SIZE = {
    'ML-KEM-768': 1088,
    'ML-KEM-1024': 1568,
}

# Probe run on the host before anything is installed.  It checks the three
# things the patched vault plugin needs: the ML-KEM key classes, AES key
# wrapping, and PEM (de)serialization of ML-KEM keys.
MLKEM_PROBE_SCRIPT = """
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey, MLKEM768PublicKey,
    MLKEM1024PrivateKey, MLKEM1024PublicKey,
)
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap_with_padding, aes_key_unwrap_with_padding,
)

for private_cls, public_cls in (
    (MLKEM768PrivateKey, MLKEM768PublicKey),
    (MLKEM1024PrivateKey, MLKEM1024PublicKey),
):
    private_key = private_cls.generate()
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert isinstance(serialization.load_pem_public_key(pem), public_cls)

# a 32 byte shared secret must be able to wrap a vault encryption key
wrapped = aes_key_wrap_with_padding(b'0' * 32, b'secret')
assert aes_key_unwrap_with_padding(b'0' * 32, wrapped) == b'secret'
"""

# Probe for the client side patch itself.  MLKEM_PUBLIC_KEY_TYPES is set to
# an empty tuple by the patch when cryptography is too old, and does not
# exist at all on an unpatched client.
#
# ipaclient.plugins.vault reads api.env.cache_dir while being imported, so
# the API has to be bootstrapped first.
IPACLIENT_PROBE_SCRIPT = """
from ipalib import api

api.bootstrap(context='cli')

from ipaclient.plugins import vault

assert getattr(vault, 'MLKEM_PUBLIC_KEY_TYPES', ()), \\
    'ipaclient vault plugin has no ML-KEM support'
assert getattr(vault, 'MLKEM_PRIVATE_KEY_TYPES', ()), \\
    'ipaclient vault plugin has no ML-KEM support'
"""

GENERATE_KEY_SCRIPT = """
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem

CLASSES = {
    'ML-KEM-768': mlkem.MLKEM768PrivateKey,
    'ML-KEM-1024': mlkem.MLKEM1024PrivateKey,
}

algorithm, private_path, public_path = sys.argv[1:4]

private_key = CLASSES[algorithm].generate()

with open(private_path, 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

with open(public_path, 'wb') as f:
    f.write(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
"""

PUBLIC_KEY_TYPE_SCRIPT = """
import sys

from cryptography.hazmat.primitives.serialization import load_pem_public_key

with open(sys.argv[1], 'rb') as f:
    print(type(load_pem_public_key(f.read())).__name__)
"""

CERT_KEY_TYPE_SCRIPT = """
import sys

from ipalib import x509

with open(sys.argv[1], 'rb') as f:
    cert = x509.load_der_x509_certificate(f.read())

print(type(cert.public_key()).__name__)
"""

# Mirrors ipaclient.plugins.vault._KraConfigCache._get_filename()
CACHE_FILE_SCRIPT = """
import os

from ipalib import api
from ipapython.dnsutil import DNSName

api.bootstrap(context='cli')
print(os.path.join(api.env.cache_dir, 'kra-config',
                   DNSName(api.env.domain).ToASCII() + '.json'))
"""

# Drives ipaclient.plugins.vault.encrypt()/decrypt() directly so that the
# KEM ciphertext, which the CLI never exposes, can be inspected.
ENCRYPT_DECRYPT_SCRIPT = """
import base64
import os
import sys

from ipalib import api

api.bootstrap(context='cli')

from ipaclient.plugins.vault import encrypt, decrypt

public_path, private_path, expected_ct_size = sys.argv[1:4]
expected_ct_size = int(expected_ct_size)

with open(public_path, 'rb') as f:
    public_key = f.read()
with open(private_path, 'rb') as f:
    private_key = f.read()

# vault_archive wraps a base64 encoded 32 byte Fernet key
encryption_key = base64.b64encode(os.urandom(32))

result = encrypt(encryption_key, public_key=public_key)
assert isinstance(result, tuple), \\
    'ML-KEM encrypt() must return (kem_ciphertext, wrapped_key), got %r' \\
    % type(result)

kem_ciphertext, wrapped_key = result
assert len(kem_ciphertext) == expected_ct_size, \\
    'unexpected KEM ciphertext size %d' % len(kem_ciphertext)
# AES-KW with padding: 8 byte AIV plus the key padded to a multiple of 8
expected_wrapped = 8 + -(-len(encryption_key) // 8) * 8
assert len(wrapped_key) == expected_wrapped, \\
    'unexpected wrapped key size %d' % len(wrapped_key)
assert encryption_key not in wrapped_key

assert decrypt(wrapped_key, private_key=private_key,
               kem_ciphertext=kem_ciphertext) == encryption_key

print('OK')
"""

# Without the KEM ciphertext the vault encryption key is unrecoverable and
# the caller has to be told why.
MISSING_KEM_CIPHERTEXT_SCRIPT = """
import base64
import os
import sys

from ipalib import api

api.bootstrap(context='cli')

from ipaclient.plugins.vault import encrypt, decrypt

public_path, private_path = sys.argv[1:3]

with open(public_path, 'rb') as f:
    public_key = f.read()
with open(private_path, 'rb') as f:
    private_key = f.read()

encryption_key = base64.b64encode(os.urandom(32))
_kem_ciphertext, wrapped_key = encrypt(encryption_key, public_key=public_key)

try:
    decrypt(wrapped_key, private_key=private_key)
except Exception as e:
    assert 'kem_ciphertext' in str(e), \\
        'misleading error for a missing KEM ciphertext: %s: %s' \\
        % (type(e).__name__, e)
else:
    raise AssertionError('a missing KEM ciphertext was not rejected')

print('OK')
"""


def _probe(host, script, args=()):
    """Run a Python snippet on host, return (succeeded, output)."""
    path = os.path.join('/tmp', 'ipa-mlkem-probe.py')
    host.put_file_contents(path, script)
    try:
        result = host.run_command(
            ['python3', path] + list(args), raiseonerr=False
        )
    finally:
        host.run_command(['rm', '-f', path], raiseonerr=False)
    return result.returncode == 0, result.stdout_text + result.stderr_text


def cryptography_skip_reason(host):
    """Why host's python3-cryptography cannot do ML-KEM, or None."""
    ok, output = _probe(host, MLKEM_PROBE_SCRIPT)
    if ok:
        return None
    return (
        'host has no usable ML-KEM support in python3-cryptography '
        '(needs cryptography >= 50.0.0): %s' % output.strip()
    )


def ipaclient_skip_reason(host):
    """Why the installed ipaclient cannot do ML-KEM vaults, or None.

    Only meaningful once the IPA packages are installed and configured.
    """
    ok, output = _probe(host, IPACLIENT_PROBE_SCRIPT)
    if ok:
        return None
    return (
        'installed ipaclient vault plugin has no ML-KEM support: %s'
        % output.strip()
    )


class TestVaultMLKEM(IntegrationTest):
    """ML-KEM vault keys and ML-KEM KRA transport."""

    num_replicas = 1
    topology = 'star'

    mlkem_skip = 'not initialized'
    transport_key_type = None
    cache_file = None

    vault_user = 'mlkem_vault_user'
    vault_user_password = 'Secret123'

    @classmethod
    def install(cls, mh):
        cls.mlkem_skip = cryptography_skip_reason(cls.master)
        if cls.mlkem_skip:
            # Every test is going to skip, do not spend an hour of CI time
            # installing a topology nobody will use.
            return

        tasks.install_master(cls.master, setup_kra=True,
                             random_serial=cls.random_serial)
        tasks.install_replica(cls.master, cls.replicas[0], setup_kra=True)

        # needs a configured client, hence after the installation
        cls.mlkem_skip = ipaclient_skip_reason(cls.master)
        if cls.mlkem_skip:
            return

        for host in (cls.master, cls.replicas[0]):
            host.run_command(['mkdir', '-p', WORK_DIR])
        cls.master.put_file_contents(cls.script('generate_key.py'),
                                     GENERATE_KEY_SCRIPT)

        # keys used by the tests; "other768" is a second ML-KEM-768 key
        # used to prove that the wrong private key does not decrypt
        for name, algorithm in (('mlkem768', 'ML-KEM-768'),
                                ('mlkem1024', 'ML-KEM-1024'),
                                ('other768', 'ML-KEM-768')):
            cls.master.run_command([
                'python3', cls.script('generate_key.py'), algorithm,
                cls.key(name, 'priv'), cls.key(name, 'pub'),
            ])

        # RSA keys for the regression and re-keying tests
        cls.master.run_command([
            'openssl', 'genrsa', '-out', cls.key('rsa', 'priv'), '2048'])
        cls.master.run_command([
            'openssl', 'rsa', '-in', cls.key('rsa', 'priv'),
            '-pubout', '-out', cls.key('rsa', 'pub')])

        # a PEM that is valid but is not a public key at all
        cls.master.put_file_contents(cls.key('bogus', 'pub'),
                                     '-----BEGIN PUBLIC KEY-----\n'
                                     'bm90IGEgcHVibGljIGtleQ==\n'
                                     '-----END PUBLIC KEY-----\n')

        cls.cache_file = cls.run_script(cls.master, 'cache_file.py',
                                        CACHE_FILE_SCRIPT).strip()
        cls.transport_key_type = cls.read_transport_key_type()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def script(name):
        return os.path.join(WORK_DIR, name)

    @staticmethod
    def key(name, kind):
        return os.path.join(WORK_DIR, '%s.%s.pem' % (name, kind))

    @classmethod
    def run_script(cls, host, name, script, args=()):
        path = cls.script(name)
        host.put_file_contents(path, script)
        result = host.run_command(['python3', path] + list(args))
        return result.stdout_text

    @classmethod
    def read_transport_key_type(cls):
        """Class name of the KRA transport certificate's public key."""
        tasks.kinit_admin(cls.master)
        der = cls.script('transport.der')
        cls.master.run_command([
            'ipa', 'vaultconfig-show', '--transport-out=%s' % der])
        return cls.run_script(cls.master, 'cert_key_type.py',
                              CERT_KEY_TYPE_SCRIPT, [der]).strip()

    def add_asymmetric_vault(self, name, public_key, host=None,
                             extra_args=()):
        host = host or self.master
        host.run_command([
            'ipa', 'vault-add', name,
            '--type', 'asymmetric',
            '--public-key-file', public_key,
        ] + list(extra_args))

    def archive(self, name, path, host=None, extra_args=()):
        host = host or self.master
        host.run_command(
            ['ipa', 'vault-archive', name, '--in', path] + list(extra_args))

    def retrieve(self, name, path, host=None, extra_args=(),
                 raiseonerr=True):
        host = host or self.master
        return host.run_command(
            ['ipa', 'vault-retrieve', name, '--out', path]
            + list(extra_args),
            raiseonerr=raiseonerr)

    def make_secret(self, name, size=4096, host=None):
        """Create a file of random bytes on the host and return its path."""
        host = host or self.master
        path = os.path.join(WORK_DIR, '%s.secret' % name)
        host.run_command([
            'dd', 'if=/dev/urandom', 'of=%s' % path,
            'bs=%d' % size, 'count=1', 'status=none',
        ])
        return path

    def roundtrip(self, vault_name, public_key, private_key, size=4096):
        """add + archive + retrieve, asserting the data survives intact."""
        secret = self.make_secret(vault_name, size=size)
        out = os.path.join(WORK_DIR, '%s.out' % vault_name)

        self.add_asymmetric_vault(vault_name, public_key)
        self.archive(vault_name, secret)
        self.retrieve(vault_name, out,
                      extra_args=['--private-key-file', private_key])

        self.master.run_command(['cmp', secret, out])
        return secret, out

    @pytest.fixture(autouse=True)
    def require_mlkem(self):
        if self.mlkem_skip:
            pytest.skip(self.mlkem_skip)

    def require_mlkem_transport(self):
        if 'MLKEM' not in self.transport_key_type.upper():
            pytest.skip(
                'KRA transport certificate uses %s, not ML-KEM'
                % self.transport_key_type
            )

    # ------------------------------------------------------------------
    # ML-KEM asymmetric vault keys
    # ------------------------------------------------------------------

    def test_generated_keys_are_mlkem(self):
        """The generated PEMs load back as the expected ML-KEM key types.

        Everything else in this class depends on ``load_pem_public_key()``
        returning something ``isinstance()`` of the plugin's
        ``MLKEM_PUBLIC_KEY_TYPES``, so check that up front.
        """
        for name, expected in (('mlkem768', 'MLKEM768PublicKey'),
                               ('mlkem1024', 'MLKEM1024PublicKey')):
            key_type = self.run_script(
                self.master, 'public_key_type.py', PUBLIC_KEY_TYPE_SCRIPT,
                [self.key(name, 'pub')],
            ).strip()
            assert key_type == expected, (
                '%s loaded as %s' % (name, key_type))

    @pytest.mark.parametrize('algorithm,name',
                             [('ML-KEM-768', 'mlkem768'),
                              ('ML-KEM-1024', 'mlkem1024')])
    def test_encrypt_decrypt_encapsulates(self, algorithm, name):
        """encrypt()/decrypt() perform a real KEM encapsulation.

        The CLI never shows the KEM ciphertext, so call the plugin helpers
        directly and check the sizes defined by FIPS 203 and RFC 5649.
        """
        output = self.run_script(
            self.master, 'encrypt_decrypt.py', ENCRYPT_DECRYPT_SCRIPT,
            [self.key(name, 'pub'), self.key(name, 'priv'),
             str(MLKEM_CIPHERTEXT_SIZE[algorithm])],
        )
        assert 'OK' in output

    def test_decrypt_without_kem_ciphertext_is_explicit(self):
        """A missing KEM ciphertext must not look like a bad key.

        ``decrypt()`` raises ``ValueError('kem_ciphertext is required ...')``
        from inside the ``try`` block whose ``except ValueError`` turns
        every failure into ``AuthenticationError('Invalid credentials')``,
        so the specific message never reaches the caller.
        """
        output = self.run_script(
            self.master, 'missing_kem_ct.py', MISSING_KEM_CIPHERTEXT_SCRIPT,
            [self.key('mlkem768', 'pub'), self.key('mlkem768', 'priv')],
        )
        assert 'OK' in output

    def test_asymmetric_vault_mlkem768(self):
        self.roundtrip('mlkem768_vault',
                       self.key('mlkem768', 'pub'),
                       self.key('mlkem768', 'priv'))

    def test_asymmetric_vault_mlkem1024(self):
        self.roundtrip('mlkem1024_vault',
                       self.key('mlkem1024', 'pub'),
                       self.key('mlkem1024', 'priv'))

    def test_asymmetric_vault_mlkem_binary_data(self):
        """Binary data with NUL bytes survives the AES-KW round trip."""
        secret = os.path.join(WORK_DIR, 'binary.secret')
        out = os.path.join(WORK_DIR, 'binary.out')
        self.master.run_command([
            'python3', '-c',
            'open("%s", "wb").write(bytes(range(256)) * 64)' % secret,
        ])

        self.add_asymmetric_vault('mlkem_binary_vault',
                                  self.key('mlkem768', 'pub'))
        self.archive('mlkem_binary_vault', secret)
        self.retrieve('mlkem_binary_vault', out, extra_args=[
            '--private-key-file', self.key('mlkem768', 'priv')])

        self.master.run_command(['cmp', secret, out])

    def test_asymmetric_vault_mlkem_overwrite(self):
        """Re-archiving replaces the secret and a fresh encapsulation."""
        first = self.make_secret('overwrite_first')
        second = self.make_secret('overwrite_second')
        out = os.path.join(WORK_DIR, 'overwrite.out')

        self.add_asymmetric_vault('mlkem_overwrite_vault',
                                  self.key('mlkem768', 'pub'))
        self.archive('mlkem_overwrite_vault', first)
        self.archive('mlkem_overwrite_vault', second)
        self.retrieve('mlkem_overwrite_vault', out, extra_args=[
            '--private-key-file', self.key('mlkem768', 'priv')])

        self.master.run_command(['cmp', second, out])

    def test_retrieve_mlkem_vault_without_private_key(self):
        out = os.path.join(WORK_DIR, 'no-key.out')
        result = self.retrieve('mlkem768_vault', out, raiseonerr=False)

        assert result.returncode != 0
        assert 'Missing vault private key' in result.stderr_text

    def test_retrieve_mlkem_vault_with_wrong_private_key(self):
        """A wrong ML-KEM key must fail the same way a wrong RSA key does.

        ML-KEM decapsulation uses implicit rejection: it never fails, it
        just returns a different shared secret.  The failure therefore
        surfaces from ``aes_key_unwrap_with_padding()``, which raises
        ``cryptography...keywrap.InvalidUnwrap``.  That is not a
        ``ValueError``, so the ``except ValueError`` in ``decrypt()`` does
        not catch it and the user gets an unhandled exception instead of
        the usual authentication error.
        """
        out = os.path.join(WORK_DIR, 'wrong-key.out')
        result = self.retrieve('mlkem768_vault', out, raiseonerr=False,
                               extra_args=['--private-key-file',
                                           self.key('other768', 'priv')])

        assert result.returncode != 0
        combined = result.stdout_text + result.stderr_text
        assert 'Traceback' not in combined, combined
        assert 'an internal error has occurred' not in combined, combined
        assert 'Invalid credentials' in combined, combined

    def test_retrieve_mlkem_vault_with_rsa_private_key(self):
        """An RSA key against an ML-KEM vault fails cleanly."""
        out = os.path.join(WORK_DIR, 'rsa-key.out')
        result = self.retrieve('mlkem768_vault', out, raiseonerr=False,
                               extra_args=['--private-key-file',
                                           self.key('rsa', 'priv')])

        assert result.returncode != 0
        combined = result.stdout_text + result.stderr_text
        assert 'Traceback' not in combined, combined

    def test_mlkem_vault_retrieve_on_replica(self):
        """A vault archived on the master is readable on a KRA replica."""
        secret = self.make_secret('replica')
        out = os.path.join(WORK_DIR, 'replica.out')

        self.add_asymmetric_vault('mlkem_replica_vault',
                                  self.key('mlkem768', 'pub'))
        self.archive('mlkem_replica_vault', secret)
        time.sleep(WAIT_AFTER_ARCHIVE)

        # the private key never leaves the client, so copy it over
        replica = self.replicas[0]
        replica.put_file_contents(
            self.key('mlkem768', 'priv'),
            self.master.get_file_contents(self.key('mlkem768', 'priv')))
        replica.put_file_contents(
            self.script('replica.secret'),
            self.master.get_file_contents(secret))

        tasks.kinit_admin(replica)
        self.retrieve('mlkem_replica_vault', out, host=replica,
                      extra_args=['--private-key-file',
                                  self.key('mlkem768', 'priv')])
        replica.run_command(['cmp', self.script('replica.secret'), out])

    def test_shared_mlkem_vault_for_non_admin_user(self):
        """A vault member can read a shared ML-KEM vault."""
        secret = self.make_secret('shared')
        out = os.path.join(WORK_DIR, 'shared.out')

        tasks.kinit_admin(self.master)
        self.add_asymmetric_vault('mlkem_shared_vault',
                                  self.key('mlkem768', 'pub'),
                                  extra_args=['--shared'])
        self.archive('mlkem_shared_vault', secret, extra_args=['--shared'])

        password = self.vault_user_password
        self.master.run_command([
            'ipa', 'user-add', self.vault_user,
            '--first', self.vault_user, '--last', self.vault_user,
            '--password'], stdin_text='%s\n%s\n' % (password, password))
        self.master.run_command([
            'ipa', 'vault-add-member', 'mlkem_shared_vault',
            '--shared', '--users', self.vault_user])

        try:
            self.master.run_command(['kdestroy', '-A'])
            # first kinit forces a password change
            self.master.run_command(
                ['kinit', self.vault_user],
                stdin_text='%s\n%s\n%s\n' % (password, password, password))

            self.retrieve('mlkem_shared_vault', out,
                          extra_args=['--shared', '--private-key-file',
                                      self.key('mlkem768', 'priv')])
            self.master.run_command(['cmp', secret, out])
        finally:
            self.master.run_command(['kdestroy', '-A'], raiseonerr=False)
            tasks.kinit_admin(self.master)

    def test_service_mlkem_vault(self):
        """Service vaults work with an ML-KEM key."""
        principal = 'HTTP/%s' % self.master.hostname
        secret = self.make_secret('service')
        out = os.path.join(WORK_DIR, 'service.out')

        self.add_asymmetric_vault('mlkem_service_vault',
                                  self.key('mlkem768', 'pub'),
                                  extra_args=['--service', principal])
        self.archive('mlkem_service_vault', secret,
                     extra_args=['--service', principal])
        self.retrieve('mlkem_service_vault', out,
                      extra_args=['--service', principal,
                                  '--private-key-file',
                                  self.key('mlkem768', 'priv')])

        self.master.run_command(['cmp', secret, out])

    # ------------------------------------------------------------------
    # re-keying
    # ------------------------------------------------------------------

    def test_rekey_rsa_vault_to_mlkem(self):
        """The RSA to post-quantum migration path preserves the secret."""
        secret = self.make_secret('rekey_rsa')
        out = os.path.join(WORK_DIR, 'rekey_rsa.out')

        self.add_asymmetric_vault('rekey_rsa_vault', self.key('rsa', 'pub'))
        self.archive('rekey_rsa_vault', secret)

        self.master.run_command([
            'ipa', 'vault-mod', 'rekey_rsa_vault',
            '--private-key-file', self.key('rsa', 'priv'),
            '--public-key-file', self.key('mlkem768', 'pub'),
        ])

        # the old RSA key must no longer work
        result = self.retrieve(
            'rekey_rsa_vault', out, raiseonerr=False,
            extra_args=['--private-key-file', self.key('rsa', 'priv')])
        assert result.returncode != 0

        self.retrieve('rekey_rsa_vault', out, extra_args=[
            '--private-key-file', self.key('mlkem768', 'priv')])
        self.master.run_command(['cmp', secret, out])

    def test_rekey_mlkem768_vault_to_mlkem1024(self):
        secret = self.make_secret('rekey_mlkem')
        out = os.path.join(WORK_DIR, 'rekey_mlkem.out')

        self.add_asymmetric_vault('rekey_mlkem_vault',
                                  self.key('mlkem768', 'pub'))
        self.archive('rekey_mlkem_vault', secret)

        self.master.run_command([
            'ipa', 'vault-mod', 'rekey_mlkem_vault',
            '--private-key-file', self.key('mlkem768', 'priv'),
            '--public-key-file', self.key('mlkem1024', 'pub'),
        ])

        self.retrieve('rekey_mlkem_vault', out, extra_args=[
            '--private-key-file', self.key('mlkem1024', 'priv')])
        self.master.run_command(['cmp', secret, out])

    def test_rekey_mlkem_vault_to_symmetric(self):
        """An ML-KEM vault can be converted back to a symmetric one."""
        secret = self.make_secret('rekey_symmetric')
        out = os.path.join(WORK_DIR, 'rekey_symmetric.out')
        password = 'Symmetric123'

        self.add_asymmetric_vault('rekey_symmetric_vault',
                                  self.key('mlkem768', 'pub'))
        self.archive('rekey_symmetric_vault', secret)

        self.master.run_command([
            'ipa', 'vault-mod', 'rekey_symmetric_vault',
            '--private-key-file', self.key('mlkem768', 'priv'),
            '--type', 'symmetric', '--new-password', password,
        ])

        self.retrieve('rekey_symmetric_vault', out,
                      extra_args=['--password', password])
        self.master.run_command(['cmp', secret, out])

    # ------------------------------------------------------------------
    # public key validation
    # ------------------------------------------------------------------

    def test_vault_add_rejects_private_key(self):
        """vault-add refuses a private key passed as the public key."""
        result = self.master.run_command([
            'ipa', 'vault-add', 'rejected_add_vault',
            '--type', 'asymmetric',
            '--public-key-file', self.key('mlkem768', 'priv'),
        ], raiseonerr=False)

        assert result.returncode != 0
        assert 'Invalid or unsupported vault public key' \
            in result.stderr_text

    def test_vault_mod_rejects_private_key(self):
        """vault-mod refuses a private key as the new public key.

        Without the validation added by the patch the private key is sent
        to the server and silently stored as the vault public key.
        """
        self.add_asymmetric_vault('rejected_mod_vault',
                                  self.key('mlkem768', 'pub'))

        result = self.master.run_command([
            'ipa', 'vault-mod', 'rejected_mod_vault',
            '--private-key-file', self.key('mlkem768', 'priv'),
            '--public-key-file', self.key('mlkem1024', 'priv'),
        ], raiseonerr=False)

        assert result.returncode != 0
        assert 'Invalid or unsupported vault public key' \
            in result.stderr_text

        # the vault must still be readable with the original key
        out = os.path.join(WORK_DIR, 'rejected_mod.out')
        self.retrieve('rejected_mod_vault', out, extra_args=[
            '--private-key-file', self.key('mlkem768', 'priv')])

    def test_vault_mod_rejects_malformed_public_key(self):
        self.add_asymmetric_vault('rejected_pem_vault',
                                  self.key('mlkem768', 'pub'))

        result = self.master.run_command([
            'ipa', 'vault-mod', 'rejected_pem_vault',
            '--private-key-file', self.key('mlkem768', 'priv'),
            '--public-key-file', self.key('bogus', 'pub'),
        ], raiseonerr=False)

        assert result.returncode != 0
        assert 'Invalid or unsupported vault public key' \
            in result.stderr_text

    # ------------------------------------------------------------------
    # regressions for the RSA paths refactored by the patch
    # ------------------------------------------------------------------

    def test_rsa_asymmetric_vault_still_works(self):
        secret = self.make_secret('rsa')
        out = os.path.join(WORK_DIR, 'rsa.out')

        self.add_asymmetric_vault('rsa_vault', self.key('rsa', 'pub'))
        self.archive('rsa_vault', secret)
        self.retrieve('rsa_vault', out, extra_args=[
            '--private-key-file', self.key('rsa', 'priv')])

        self.master.run_command(['cmp', secret, out])

    def test_standard_and_symmetric_vaults_still_work(self):
        """_wrap_data()/_unwrap_response() moved to the shared base class."""
        secret = self.make_secret('plain')

        self.master.run_command([
            'ipa', 'vault-add', 'standard_vault', '--type', 'standard'])
        self.archive('standard_vault', secret)
        out = os.path.join(WORK_DIR, 'standard.out')
        self.retrieve('standard_vault', out)
        self.master.run_command(['cmp', secret, out])

        self.master.run_command([
            'ipa', 'vault-add', 'symmetric_vault', '--type', 'symmetric',
            '--password', 'Symmetric123'])
        self.archive('symmetric_vault', secret,
                     extra_args=['--password', 'Symmetric123'])
        out = os.path.join(WORK_DIR, 'symmetric.out')
        self.retrieve('symmetric_vault', out,
                      extra_args=['--password', 'Symmetric123'])
        self.master.run_command(['cmp', secret, out])

    def test_stale_transport_cert_cache_is_refreshed(self):
        """A wrong cached transport cert is detected and replaced.

        ``internal()`` and the new ``_mlkem_archive()``/``_mlkem_retrieve()``
        share this recovery: on a server error the cached KRA config is
        dropped and the operation retried with a freshly fetched transport
        certificate.
        """
        secret = self.make_secret('stale_cache')
        out = os.path.join(WORK_DIR, 'stale_cache.out')

        self.add_asymmetric_vault('stale_cache_vault',
                                  self.key('mlkem768', 'pub'))

        # populate the cache, then poison it with a valid certificate that
        # the KRA cannot decrypt with
        self.master.run_command(['ipa', 'vaultconfig-show'])
        cached = self.master.get_file_contents(self.cache_file,
                                               encoding='utf-8')
        ca_cert = self.master.get_file_contents(paths.IPA_CA_CRT,
                                                encoding='utf-8')
        poisoned = json.loads(cached)
        assert poisoned['transport_cert'] != ca_cert
        poisoned['transport_cert'] = ca_cert
        self.master.put_file_contents(self.cache_file, json.dumps(poisoned))

        self.archive('stale_cache_vault', secret)
        self.retrieve('stale_cache_vault', out, extra_args=[
            '--private-key-file', self.key('mlkem768', 'priv')])
        self.master.run_command(['cmp', secret, out])

        refreshed = json.loads(
            self.master.get_file_contents(self.cache_file, encoding='utf-8'))
        assert refreshed['transport_cert'] != ca_cert

    # ------------------------------------------------------------------
    # ML-KEM KRA transport
    #
    # These need a KRA whose transport certificate carries an ML-KEM public
    # key, which ipa-kra-install does not create, so they skip on a stock
    # deployment.
    # ------------------------------------------------------------------

    def test_mlkem_transport_standard_vault(self):
        self.require_mlkem_transport()

        secret = self.make_secret('transport_standard')
        out = os.path.join(WORK_DIR, 'transport_standard.out')

        self.master.run_command([
            'ipa', 'vault-add', 'transport_standard_vault',
            '--type', 'standard'])
        self.archive('transport_standard_vault', secret)
        self.retrieve('transport_standard_vault', out)

        self.master.run_command(['cmp', secret, out])

    def test_mlkem_transport_symmetric_vault(self):
        self.require_mlkem_transport()

        secret = self.make_secret('transport_symmetric')
        out = os.path.join(WORK_DIR, 'transport_symmetric.out')
        password = 'Transport123'

        self.master.run_command([
            'ipa', 'vault-add', 'transport_symmetric_vault',
            '--type', 'symmetric', '--password', password])
        self.archive('transport_symmetric_vault', secret,
                     extra_args=['--password', password])
        self.retrieve('transport_symmetric_vault', out,
                      extra_args=['--password', password])

        self.master.run_command(['cmp', secret, out])

    def test_mlkem_transport_and_mlkem_vault_key(self):
        """ML-KEM on both layers at once."""
        self.require_mlkem_transport()

        self.roundtrip('transport_mlkem_vault',
                       self.key('mlkem768', 'pub'),
                       self.key('mlkem768', 'priv'))

    def test_mlkem_transport_without_cached_config(self):
        """The ML-KEM transport path works on a cold KRA config cache."""
        self.require_mlkem_transport()

        secret = self.make_secret('transport_cold')
        out = os.path.join(WORK_DIR, 'transport_cold.out')

        self.master.run_command([
            'ipa', 'vault-add', 'transport_cold_vault', '--type', 'standard'])

        self.master.run_command(
            ['rm', '-f', self.cache_file], raiseonerr=False)
        self.archive('transport_cold_vault', secret)

        self.master.run_command(
            ['rm', '-f', self.cache_file], raiseonerr=False)
        self.retrieve('transport_cold_vault', out)

        self.master.run_command(['cmp', secret, out])
