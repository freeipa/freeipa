# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Tests for private key encryption (AES-256-GCM)

Tests KeyEncryption class with temporary master keys.
"""

import os
import pytest
import tempfile

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from ipathinca.key_encryption import KeyEncryption, KeyEncryptionError


@pytest.fixture
def master_key_file(tmp_path):
    """Create a temporary master key file."""
    key_path = tmp_path / "master.key"
    key_data = os.urandom(32)
    key_path.write_bytes(key_data)
    key_path.chmod(0o400)
    return str(key_path)


@pytest.fixture
def enc(master_key_file):
    """Create a KeyEncryption instance with temp master key."""
    return KeyEncryption(master_key_path=master_key_file)


@pytest.fixture
def sample_pem():
    """Generate a sample RSA private key in PEM format."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


class TestKeyEncryption:
    """Test encrypt/decrypt round-trip and edge cases."""

    def test_encrypt_decrypt_round_trip(self, enc, sample_pem):
        """Encrypting then decrypting must return original data."""
        encrypted = enc.encrypt_key(sample_pem)
        decrypted = enc.decrypt_key(encrypted)
        assert decrypted == sample_pem

    def test_different_ciphertexts(self, enc, sample_pem):
        """Two encryptions of same data must produce different ciphertexts."""
        enc1 = enc.encrypt_key(sample_pem)
        enc2 = enc.encrypt_key(sample_pem)
        assert enc1 != enc2

    def test_tampered_ciphertext_fails(self, enc, sample_pem):
        """Tampered ciphertext must raise KeyEncryptionError."""
        encrypted = enc.encrypt_key(sample_pem)
        # Flip a byte in the ciphertext portion (after salt+IV)
        tampered = bytearray(encrypted)
        tampered[-10] ^= 0xFF
        with pytest.raises(KeyEncryptionError):
            enc.decrypt_key(bytes(tampered))

    def test_wrong_master_key_fails(self, sample_pem, tmp_path):
        """Decrypting with different master key must fail."""
        # Encrypt with key 1
        key1 = tmp_path / "key1"
        key1.write_bytes(os.urandom(32))
        enc1 = KeyEncryption(master_key_path=str(key1))
        encrypted = enc1.encrypt_key(sample_pem)

        # Decrypt with key 2
        key2 = tmp_path / "key2"
        key2.write_bytes(os.urandom(32))
        enc2 = KeyEncryption(master_key_path=str(key2))
        with pytest.raises(KeyEncryptionError):
            enc2.decrypt_key(encrypted)

    def test_short_data_fails(self, enc):
        """Data shorter than salt+IV+tag must raise error."""
        with pytest.raises(KeyEncryptionError):
            enc.decrypt_key(b"too short")

    def test_encrypted_format(self, enc, sample_pem):
        """Encrypted data must be salt(32) + IV(12) + ciphertext+tag."""
        encrypted = enc.encrypt_key(sample_pem)
        # Must be at least 32 + 12 + 16 (tag) = 60 bytes
        assert len(encrypted) >= 60
        # Ciphertext+tag should be at least as long as plaintext + 16 (tag)
        assert len(encrypted) >= 32 + 12 + len(sample_pem) + 16

    def test_auto_generate_master_key(self, tmp_path):
        """Master key is auto-generated if file doesn't exist."""
        key_path = tmp_path / "subdir" / "auto.key"
        enc = KeyEncryption(master_key_path=str(key_path))
        data = b"test data for encryption"
        encrypted = enc.encrypt_key(data)
        decrypted = enc.decrypt_key(encrypted)
        assert decrypted == data
        assert key_path.exists()
        assert key_path.stat().st_size == 32


class TestKeyEncryptionConstants:
    """Test encryption parameters."""

    def test_key_size(self):
        assert KeyEncryption.KEY_SIZE == 32

    def test_iv_size(self):
        assert KeyEncryption.IV_SIZE == 12

    def test_pbkdf2_iterations(self):
        assert KeyEncryption.PBKDF2_ITERATIONS == 600000
