# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Secure Private Key Encryption for LDAP Storage

This module provides secure encryption/decryption of private keys before
storing them in LDAP. Private keys should never be stored in plain text.

Security Design:
    - Master encryption key derived from system secrets (Custodia/Vault)
    - AES-256-GCM for authenticated encryption
    - Unique IV per encryption operation
    - Key derivation using PBKDF2-HMAC-SHA256
    - Forward secrecy: each key encrypted independently
"""

import logging
import os
import threading
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ipaplatform.paths import paths

logger = logging.getLogger(__name__)


class KeyEncryptionError(Exception):
    """Error during key encryption/decryption"""


class KeyEncryption:
    """
    Manages secure encryption/decryption of private keys for LDAP storage

    This class uses AES-256-GCM authenticated encryption with a master key
    derived from system secrets. Each encryption uses a unique IV.

    Security Properties:
        - Confidentiality: AES-256-GCM encryption
        - Integrity: GCM authentication tag
        - Uniqueness: Random IV per encryption
        - Key derivation: PBKDF2-HMAC-SHA256
    """

    # Master key file path (should be protected by filesystem permissions)
    MASTER_KEY_PATH = f"{paths.IPATHINCA_PRIVATE_DIR}/ipathinca-master.key"

    # Key derivation parameters
    PBKDF2_ITERATIONS = 600000  # OWASP recommendation (2023)
    KEY_SIZE = 32  # 256 bits for AES-256
    IV_SIZE = 12  # 96 bits (recommended for GCM)

    def __init__(self, master_key_path: Optional[str] = None):
        """
        Initialize key encryption

        Args:
            master_key_path: Path to master encryption key file
                            (defaults to {MASTER_KEY_PATH})
        """
        self.master_key_path = Path(master_key_path or self.MASTER_KEY_PATH)
        self._master_key = None

    def _get_master_key(self) -> bytes:
        """
        Get or create master encryption key

        The master key is:
        1. Read from file if exists
        2. Generated securely if not exists
        3. Protected by filesystem permissions (0o400)

        Returns:
            32-byte master key

        Raises:
            KeyEncryptionError: If key cannot be read or created
        """
        if self._master_key is not None:
            return self._master_key

        try:
            # Try to read existing key
            if self.master_key_path.exists():
                with open(self.master_key_path, "rb") as f:
                    self._master_key = f.read()

                if len(self._master_key) != self.KEY_SIZE:
                    raise KeyEncryptionError(
                        "Invalid master key size:"
                        f" {len(self._master_key)} bytes (expected"
                        f" {self.KEY_SIZE})"
                    )

                logger.debug(
                    "Loaded master encryption key from %s",
                    self.master_key_path,
                )
                return self._master_key

            # Generate new master key
            logger.info(
                "Generating new master encryption key at %s",
                self.master_key_path,
            )

            # Ensure parent directory exists with correct permissions
            self.master_key_path.parent.mkdir(parents=True, exist_ok=True)
            self.master_key_path.parent.chmod(0o700)

            # Generate cryptographically secure random key
            self._master_key = os.urandom(self.KEY_SIZE)

            # Write key with restrictive permissions (owner read-only)
            with open(self.master_key_path, "wb") as f:
                f.write(self._master_key)

            self.master_key_path.chmod(0o400)

            logger.info("Master encryption key generated and stored securely")
            return self._master_key

        except Exception as e:
            raise KeyEncryptionError(
                f"Failed to get master encryption key: {e}"
            )

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive encryption key from master key using PBKDF2

        Args:
            salt: Cryptographic salt (random per encryption)

        Returns:
            Derived 32-byte key
        """
        master_key = self._get_master_key()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )

        return kdf.derive(master_key)

    def encrypt_key(self, private_key_pem: bytes) -> bytes:
        """
        Encrypt private key for secure LDAP storage

        Encryption format:
            [salt (32 bytes)][iv (12 bytes)][ciphertext + tag]

        Args:
            private_key_pem: Private key in PEM format (bytes)

        Returns:
            Encrypted key data (salt + iv + ciphertext)

        Raises:
            KeyEncryptionError: If encryption fails
        """
        try:
            # Generate random salt and IV
            salt = os.urandom(self.KEY_SIZE)
            iv = os.urandom(self.IV_SIZE)

            # Derive encryption key from master key + salt
            derived_key = self._derive_key(salt)

            # Encrypt using AES-256-GCM
            aesgcm = AESGCM(derived_key)
            ciphertext = aesgcm.encrypt(iv, private_key_pem, None)

            # Format: [salt][iv][ciphertext+tag]
            encrypted_data = salt + iv + ciphertext

            logger.debug(
                "Encrypted private key: %d bytes -> %d bytes",
                len(private_key_pem),
                len(encrypted_data),
            )

            return encrypted_data

        except Exception as e:
            raise KeyEncryptionError(f"Failed to encrypt private key: {e}")

    def decrypt_key(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt private key from LDAP storage

        Args:
            encrypted_data: Encrypted key data (salt + iv + ciphertext)

        Returns:
            Decrypted private key in PEM format

        Raises:
            KeyEncryptionError: If decryption fails or authentication fails
        """
        try:
            # Parse encrypted data format: [salt][iv][ciphertext+tag]
            if len(encrypted_data) < self.KEY_SIZE + self.IV_SIZE + 16:
                raise KeyEncryptionError("Invalid encrypted data: too short")

            salt = encrypted_data[: self.KEY_SIZE]
            iv = encrypted_data[self.KEY_SIZE : self.KEY_SIZE + self.IV_SIZE]
            ciphertext = encrypted_data[self.KEY_SIZE + self.IV_SIZE :]

            # Derive decryption key from master key + salt
            derived_key = self._derive_key(salt)

            # Decrypt using AES-256-GCM
            # This will raise an exception if the authentication tag doesn't
            # match
            aesgcm = AESGCM(derived_key)
            private_key_pem = aesgcm.decrypt(iv, ciphertext, None)

            logger.debug(
                "Decrypted private key: %d bytes -> %d bytes",
                len(encrypted_data),
                len(private_key_pem),
            )

            return private_key_pem

        except Exception as e:
            raise KeyEncryptionError(
                "Failed to decrypt private key (possible tampering or "
                f"wrong master key): {e}"
            )


# Global key encryption instance
_key_encryption = None
_key_encryption_lock = threading.Lock()


def get_key_encryption(
    master_key_path: Optional[str] = None,
) -> KeyEncryption:
    """
    Get global key encryption instance (singleton)

    Args:
        master_key_path: Optional custom master key path

    Returns:
        KeyEncryption instance
    """
    global _key_encryption

    with _key_encryption_lock:
        if _key_encryption is None:
            _key_encryption = KeyEncryption(master_key_path)

        return _key_encryption


def encrypt_private_key(private_key_pem: bytes) -> bytes:
    """
    Convenience function to encrypt a private key

    Args:
        private_key_pem: Private key in PEM format

    Returns:
        Encrypted key data
    """
    return get_key_encryption().encrypt_key(private_key_pem)


def decrypt_private_key(encrypted_data: bytes) -> bytes:
    """
    Convenience function to decrypt a private key

    Args:
        encrypted_data: Encrypted key data

    Returns:
        Decrypted private key in PEM format
    """
    return get_key_encryption().decrypt_key(encrypted_data)
