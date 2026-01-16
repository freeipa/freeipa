# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
KRA (Key Recovery Authority) Implementation

This module provides key archival and recovery functionality compatible with
Dogtag KRA. It handles:
- Transport key management (for wrapping/unwrapping secrets)
- Key archival (storing encrypted secrets)
- Key retrieval (recovering secrets)
- Key lifecycle management

HSM Support:
    Both TransportKey and StorageKey support HSM storage following Dogtag's
    pattern:
    - Configuration stored in LDAP (ipaCaHSMConfiguration attribute)
    - Runtime detection of HSM vs file-based keys
    - Transparent PKCS#11 access via HSMPrivateKeyProxy (transport key)
    - HSM-backed symmetric key storage (storage key)
"""

import os
import logging
import secrets
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
import pwd
import grp

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ipalib import errors
from ipaplatform.paths import paths

from ipathinca.hsm import HSMConfig, HSMKeyBackend, HSMPrivateKeyProxy
from ipathinca.ldap_utils import is_internal_token
from ipathinca.nss_utils import NSSDatabase

logger = logging.getLogger(__name__)


class TransportKey:
    """
    KRA Transport Key Management

    The transport key is used to wrap/unwrap secrets during archival and
    recovery. It's similar to Dogtag's transport certificate but implemented
    in pure Python with HSM support.

    HSM Support:
        Follows Dogtag's pattern for conditional key loading:
        - Check HSM configuration from LDAP
        - If HSM enabled: use HSMPrivateKeyProxy for transparent PKCS#11 access
        - If HSM disabled: load from PEM file (traditional file-based)
    """

    def __init__(
        self, key_size: int = 4096, storage_backend=None, kra_id: str = "kra"
    ):
        """
        Initialize transport key manager

        Args:
            key_size: RSA key size (default: 4096 bits)
            storage_backend: Optional storage backend for HSM config lookup
            kra_id: KRA identifier for HSM key label (default: "kra")
        """
        self.key_size = key_size
        self.private_key = None
        self.certificate = None
        self.storage_backend = storage_backend
        self.kra_id = kra_id

        # Paths for storing transport key and certificate
        self.kra_dir = os.path.join(paths.IPATHINCA_DIR, "kra")
        self.transport_key_path = os.path.join(self.kra_dir, "transport.key")
        self.transport_cert_path = os.path.join(self.kra_dir, "transport.crt")

    def _ensure_kra_dir(self):
        """Ensure KRA directory exists with correct ownership"""
        os.makedirs(self.kra_dir, mode=0o700, exist_ok=True)

        # Set ownership to ipaca:ipaca
        try:
            ipaca_uid = pwd.getpwnam("ipaca").pw_uid
            ipaca_gid = grp.getgrnam("ipaca").gr_gid
            os.chown(self.kra_dir, ipaca_uid, ipaca_gid)
        except KeyError:
            logger.warning(
                "ipaca user/group not found, directory will be owned by "
                "current user"
            )

    def generate_transport_key(self, ca_key, ca_cert, force: bool = False):
        """
        Generate new transport key and certificate in NSSDB (Dogtag-compatible)

        Args:
            ca_key: CA private key (for signing transport cert)
            ca_cert: CA certificate (issuer)
            force: Force regeneration even if key exists

        Returns:
            Tuple of (private_key, certificate)
        """

        # Certificate nickname in NSSDB
        transport_nickname = "transportCert cert-pki-kra"

        # Initialize NSSDB access
        nssdb = NSSDatabase()

        # Check if transport key already exists in NSSDB
        if not force and nssdb.cert_exists(transport_nickname):
            logger.debug("Transport key already exists in NSSDB, loading")
            return self.load_transport_key()

        logger.debug(
            "Generating new KRA transport key (%s bits) in NSSDB",
            self.key_size,
        )

        # Generate RSA key pair in memory (will be imported to NSSDB with cert)
        private_key = nssdb.generate_key_pair(
            transport_nickname, key_size=self.key_size
        )

        # Create transport certificate
        subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME,
                    ca_cert.subject.get_attributes_for_oid(
                        NameOID.ORGANIZATION_NAME
                    )[0].value,
                ),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, "KRA Transport Certificate"
                ),
            ]
        )

        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650)  # 10 years
        )

        # Add extensions for transport certificate
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=True,  # For wrapping keys
                data_encipherment=True,  # For encrypting data
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH,  # For authentication
                ]
            ),
            critical=False,
        )

        # Sign certificate with CA key
        certificate = builder.sign(ca_key, hashes.SHA256())

        # Import key and certificate to NSSDB
        logger.debug(
            "Importing transport key and certificate to NSSDB: %s",
            transport_nickname,
        )
        nssdb.import_key_and_cert(
            transport_nickname,
            private_key,
            certificate,
            trust_flags="u,u,u",
        )

        # Save certificate to file (for compatibility/reference)
        # Note: Private key is NOT saved to disk - it stays in NSSDB only
        self._ensure_kra_dir()
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        with open(self.transport_cert_path, "wb") as f:
            f.write(cert_pem)
        os.chmod(self.transport_cert_path, 0o640)
        try:
            ipaca_uid = pwd.getpwnam("ipaca").pw_uid
            ipaca_gid = grp.getgrnam("ipaca").gr_gid
            os.chown(self.transport_cert_path, ipaca_uid, ipaca_gid)
        except KeyError:
            logger.warning(
                "ipaca user/group not found, transport cert ownership "
                "not set"
            )

        self.private_key = private_key
        self.certificate = certificate

        logger.debug(
            "KRA transport key generated in NSSDB and certificate imported"
        )
        return private_key, certificate

    def load_transport_key(self):
        """
        Load transport key and certificate from NSSDB or HSM
        (Dogtag-compatible)

        This method implements Dogtag's pattern for conditional key loading:
        - Check HSM configuration from LDAP
        - If HSM enabled: use HSMPrivateKeyProxy (transparent PKCS#11 access)
        - If HSM disabled: extract from NSSDB (Dogtag approach)

        Returns:
            Tuple of (private_key, certificate)
        """

        # Certificate nickname in NSSDB
        transport_nickname = "transportCert cert-pki-kra"

        # Check if certificate exists in NSSDB before trying to load
        nssdb = NSSDatabase()
        if not nssdb.cert_exists(transport_nickname):
            raise RuntimeError(
                "Transport certificate not found in NSSDB: "
                f"{transport_nickname}"
            )

        # Load certificate from NSSDB
        certificate = nssdb.extract_certificate(transport_nickname)

        # Load private key - conditional based on HSM configuration
        # This matches Dogtag's pattern: check config, then load from
        # appropriate source
        hsm_config = None
        if self.storage_backend and hasattr(
            self.storage_backend, "get_hsm_config"
        ):
            try:
                hsm_config = self.storage_backend.get_hsm_config(self.kra_id)
            except Exception as e:
                logger.debug(
                    "Could not retrieve HSM config for KRA %s: %s",
                    self.kra_id,
                    e,
                )
                hsm_config = None

        # Check if HSM is enabled for this KRA
        if hsm_config and hsm_config.get("enabled"):
            # HSM path - use HSMPrivateKeyProxy for transparent PKCS#11 access
            logger.debug(
                "Loading KRA transport key from HSM for %s", self.kra_id
            )

            token_name = hsm_config.get("token_name")

            # Verify this is not an internal token (Dogtag validation)
            if is_internal_token(token_name):
                logger.error(
                    "HSM enabled but token_name is internal: %s", token_name
                )
                raise errors.CertificateOperationError(
                    error=(
                        "HSM configuration invalid: token_name cannot be "
                        "'internal' when HSM is enabled"
                    )
                )

            # Initialize HSM backend
            hsm = HSMKeyBackend(HSMConfig(hsm_config))

            # Key label follows Dogtag pattern: {kra_id}_transport
            key_label = f"{self.kra_id}_transport"

            # Create proxy that implements private key interface
            private_key = HSMPrivateKeyProxy(hsm, key_label)

            logger.debug(
                "Successfully loaded KRA transport certificate and HSM "
                "private key (token=%s, label=%s)",
                token_name,
                key_label,
            )
        else:
            # NSSDB path - extract from NSSDB (Dogtag-compatible)
            # Keys are stored in NSSDB, not as PEM files
            logger.debug(
                "Extracting KRA transport key from NSSDB for %s", self.kra_id
            )

            private_key = nssdb.extract_private_key(transport_nickname)

            logger.debug(
                "Successfully loaded KRA transport certificate and extracted "
                "private key from NSSDB"
            )

        self.private_key = private_key
        self.certificate = certificate

        return private_key, certificate

    def get_transport_cert_pem(self) -> str:
        """Get transport certificate as PEM string"""
        if self.certificate is None:
            self.load_transport_key()

        return self.certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode("utf-8")

    def wrap_secret(self, secret_data: bytes) -> bytes:
        """
        Wrap (encrypt) secret data with transport public key

        This is used by clients to encrypt secrets before sending to KRA.

        Args:
            secret_data: Secret to encrypt (bytes)

        Returns:
            Encrypted secret (bytes)
        """
        if self.certificate is None:
            self.load_transport_key()

        public_key = self.certificate.public_key()

        # Use RSA-OAEP padding (same as Dogtag)
        encrypted = public_key.encrypt(
            secret_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return encrypted

    def unwrap_secret(self, encrypted_data: bytes) -> bytes:
        """
        Unwrap (decrypt) secret data with transport private key

        This is used by KRA to decrypt secrets received from clients.

        Args:
            encrypted_data: Encrypted secret (bytes)

        Returns:
            Decrypted secret (bytes)
        """
        if self.private_key is None:
            self.load_transport_key()

        # Use RSA-OAEP padding (same as Dogtag)
        decrypted = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return decrypted


class StorageKey:
    """
    KRA Storage Key Management

    The storage key is used to encrypt secrets before storing them in LDAP.
    This provides an additional layer of security - even if LDAP is
    compromised, secrets remain encrypted.

    Dogtag Compatibility:
        Uses RSA asymmetric encryption like Dogtag KRA storage certificate.
        Secrets are encrypted with storage public key and can only be
        decrypted with storage private key.

    HSM Support:
        The storage key can be stored in HSM following Dogtag's pattern,
        using HSMPrivateKeyProxy for transparent PKCS#11 access.
    """

    def __init__(
        self, key_size: int = 4096, storage_backend=None, kra_id: str = "kra"
    ):
        """
        Initialize storage key manager

        Args:
            key_size: RSA key size (default: 4096 bits)
            storage_backend: Optional storage backend for HSM config lookup
            kra_id: KRA identifier for HSM key label (default: "kra")
        """
        self.key_size = key_size
        self.private_key = None
        self.certificate = None
        self.storage_backend = storage_backend
        self.kra_id = kra_id

        # Paths for storing storage key and certificate
        self.kra_dir = os.path.join(paths.IPATHINCA_DIR, "kra")
        self.storage_key_path = os.path.join(self.kra_dir, "storage.key")
        self.storage_cert_path = os.path.join(self.kra_dir, "storage.crt")

    def _ensure_kra_dir(self):
        """Ensure KRA directory exists with correct ownership"""
        os.makedirs(self.kra_dir, mode=0o700, exist_ok=True)

        # Set ownership to ipaca:ipaca
        try:
            ipaca_uid = pwd.getpwnam("ipaca").pw_uid
            ipaca_gid = grp.getgrnam("ipaca").gr_gid
            os.chown(self.kra_dir, ipaca_uid, ipaca_gid)
        except KeyError:
            logger.warning(
                "ipaca user/group not found, directory will be owned by "
                "current user"
            )

    def generate_storage_key(self, ca_key, ca_cert, force: bool = False):
        """
        Generate new storage key and certificate in NSSDB (Dogtag-compatible)

        Args:
            ca_key: CA private key (for signing storage cert)
            ca_cert: CA certificate (issuer)
            force: Force regeneration even if key exists

        Returns:
            Tuple of (private_key, certificate)
        """

        # Certificate nickname in NSSDB
        storage_nickname = "storageCert cert-pki-kra"

        # Initialize NSSDB access
        nssdb = NSSDatabase()

        # Check if storage key already exists in NSSDB
        if not force and nssdb.cert_exists(storage_nickname):
            logger.debug("Storage key already exists in NSSDB, loading")
            return self.load_storage_key()

        logger.debug(
            "Generating new KRA storage key (%s bits) in NSSDB", self.key_size
        )

        # Generate RSA key pair in memory (will be imported to NSSDB with cert)
        private_key = nssdb.generate_key_pair(
            storage_nickname, key_size=self.key_size
        )

        # Create storage certificate
        subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME,
                    ca_cert.subject.get_attributes_for_oid(
                        NameOID.ORGANIZATION_NAME
                    )[0].value,
                ),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, "KRA Storage Certificate"
                ),
            ]
        )

        # Build certificate (valid for 10 years like Dogtag)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
                critical=True,
            )
        )

        # Sign with CA key
        certificate = builder.sign(ca_key, hashes.SHA256())

        # Import key and certificate to NSSDB
        logger.debug(
            "Importing storage key and certificate to NSSDB: %s",
            storage_nickname,
        )
        nssdb.import_key_and_cert(
            storage_nickname,
            private_key,
            certificate,
            trust_flags="u,u,u",
        )

        # Save certificate to file (for compatibility/reference)
        # Note: Private key is NOT saved to disk - it stays in NSSDB only
        self._ensure_kra_dir()
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        with open(self.storage_cert_path, "wb") as f:
            f.write(cert_pem)
        os.chmod(self.storage_cert_path, 0o640)
        try:
            ipaca_uid = pwd.getpwnam("ipaca").pw_uid
            ipaca_gid = grp.getgrnam("ipaca").gr_gid
            os.chown(self.storage_cert_path, ipaca_uid, ipaca_gid)
        except KeyError:
            logger.warning(
                "ipaca user/group not found, storage cert ownership not set"
            )

        self.private_key = private_key
        self.certificate = certificate

        logger.debug(
            "KRA storage key generated in NSSDB and certificate imported"
        )
        return private_key, certificate

    def load_storage_key(self):
        """
        Load storage key and certificate from NSSDB or HSM (Dogtag-compatible)

        This method implements Dogtag's pattern for conditional key loading:
        - Check HSM configuration from LDAP
        - If HSM enabled: use HSMPrivateKeyProxy (transparent PKCS#11 access)
        - If HSM disabled: extract from NSSDB (Dogtag approach)

        Returns:
            Tuple of (private_key, certificate)
        """

        # Certificate nickname in NSSDB
        storage_nickname = "storageCert cert-pki-kra"

        # Check if certificate exists in NSSDB before trying to load
        nssdb = NSSDatabase()
        if not nssdb.cert_exists(storage_nickname):
            raise RuntimeError(
                f"Storage certificate not found in NSSDB: {storage_nickname}"
            )

        # Load certificate from NSSDB
        certificate = nssdb.extract_certificate(storage_nickname)

        # Load private key (from HSM or NSSDB)
        # Check if HSM is enabled
        hsm_config = None
        if self.storage_backend:
            try:
                hsm_config = self.storage_backend.get_hsm_config(self.kra_id)
            except Exception as e:
                logger.debug("Could not check HSM config: %s", e)

        if hsm_config and hsm_config.get("enabled"):
            # HSM path - use HSMPrivateKeyProxy for transparent PKCS#11 access
            logger.debug(
                "Loading KRA storage key from HSM for %s", self.kra_id
            )

            token_name = hsm_config.get("token_name")

            # Verify this is not an internal token (Dogtag validation)
            if is_internal_token(token_name):
                logger.error(
                    "HSM enabled but token_name is internal: %s", token_name
                )
                raise errors.CertificateOperationError(
                    error=(
                        "HSM configuration invalid: token_name cannot be "
                        "'internal' when HSM is enabled"
                    )
                )

            hsm_backend = HSMKeyBackend(HSMConfig(hsm_config))
            private_key = HSMPrivateKeyProxy(
                hsm_backend, f"{self.kra_id}_storage"
            )
        else:
            # NSSDB path - extract from NSSDB (Dogtag-compatible)
            # Keys are stored in NSSDB, not as PEM files
            logger.debug(
                "Extracting KRA storage key from NSSDB for %s", self.kra_id
            )

            private_key = nssdb.extract_private_key(storage_nickname)

            logger.debug(
                "Successfully loaded KRA storage certificate and extracted "
                "private key from NSSDB"
            )

        self.private_key = private_key
        self.certificate = certificate

        return private_key, certificate

    def get_storage_cert_pem(self) -> str:
        """Get storage certificate as PEM string"""
        if self.certificate is None:
            self.load_storage_key()

        return self.certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode("utf-8")

    def encrypt_for_storage(self, plaintext: bytes) -> bytes:
        """
        Encrypt data for LDAP storage using RSA (Dogtag-compatible)

        For large data, this uses a hybrid approach:
        1. Generate random AES-256 session key
        2. Encrypt data with session key (AES-GCM)
        3. Encrypt session key with storage RSA public key
        4. Store both encrypted session key and encrypted data

        Args:
            plaintext: Data to encrypt

        Returns:
            Encrypted data (format: enc_session_key_len + enc_session_key
                                    + nonce + ciphertext)
        """
        if self.certificate is None:
            self.load_storage_key()

        # Generate random session key (AES-256)
        session_key = secrets.token_bytes(32)

        # Encrypt data with session key using AES-GCM
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Encrypt session key with storage RSA public key
        public_key = self.certificate.public_key()
        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Pack: length of encrypted session key (2 bytes) + encrypted session
        # key + nonce + ciphertext
        enc_session_key_len = len(encrypted_session_key).to_bytes(2, "big")
        return enc_session_key_len + encrypted_session_key + nonce + ciphertext

    def decrypt_from_storage(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data from LDAP storage using RSA (Dogtag-compatible)

        Args:
            encrypted_data: Encrypted data (enc_session_key_len
                                            + enc_session_key + nonce
                                            + ciphertext)

        Returns:
            Decrypted plaintext
        """
        if self.private_key is None:
            self.load_storage_key()

        # Validate minimum size: 2 (length) + 1 (key) + 12 (nonce) + 1 (ct)
        if len(encrypted_data) < 16:
            raise ValueError(
                f"Encrypted data too short ({len(encrypted_data)} bytes)"
            )

        # Unpack: length of encrypted session key
        enc_session_key_len = int.from_bytes(encrypted_data[:2], "big")

        # Validate enc_session_key_len is reasonable (max ~512 bytes for RSA)
        if enc_session_key_len > 1024 or enc_session_key_len == 0:
            raise ValueError(
                f"Invalid encrypted session key length: {enc_session_key_len}"
            )

        # Validate total length
        min_required = 2 + enc_session_key_len + 12 + 1  # +nonce +min ct
        if len(encrypted_data) < min_required:
            raise ValueError(
                f"Encrypted data truncated (need {min_required}, "
                f"got {len(encrypted_data)})"
            )

        # Extract encrypted session key
        encrypted_session_key = encrypted_data[2 : 2 + enc_session_key_len]

        # Extract nonce and ciphertext
        remaining = encrypted_data[2 + enc_session_key_len :]
        nonce = remaining[:12]
        ciphertext = remaining[12:]

        # Decrypt session key with storage RSA private key
        session_key = self.private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt data with session key
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext


class KRA:
    """
    Main KRA (Key Recovery Authority) class

    Coordinates transport key, storage key, and key archival/recovery
    operations with HSM support.
    """

    def __init__(
        self,
        ca_key=None,
        ca_cert=None,
        storage_backend=None,
        kra_id: str = "kra",
    ):
        """
        Initialize KRA

        Args:
            ca_key: CA private key (for signing transport cert)
            ca_cert: CA certificate (for transport cert issuer)
            storage_backend: Optional storage backend for HSM config lookup
            kra_id: KRA identifier for HSM key labels (default: "kra")
        """
        self.kra_id = kra_id

        # Initialize key managers with HSM support
        self.transport_key_manager = TransportKey(
            storage_backend=storage_backend, kra_id=kra_id
        )
        self.storage_key_manager = StorageKey(
            storage_backend=storage_backend, kra_id=kra_id
        )

        # Will be set during initialization
        self.ca_key = ca_key
        self.ca_cert = ca_cert
        self.storage_backend = storage_backend

    def initialize(
        self, ca_key, ca_cert, storage_backend, force: bool = False
    ):
        """
        Initialize KRA with CA keys and storage backend

        Args:
            ca_key: CA private key
            ca_cert: CA certificate
            storage_backend: KRA storage backend instance
            force: Force regeneration of keys
        """
        self.ca_key = ca_key
        self.ca_cert = ca_cert
        self.storage_backend = storage_backend

        # Update storage backend on key managers (for HSM config lookup)
        self.transport_key_manager.storage_backend = storage_backend
        self.storage_key_manager.storage_backend = storage_backend

        logger.debug("Initializing KRA...")

        # Generate or load transport key (with HSM support)
        # Note: RuntimeError is raised when key doesn't exist in NSSDB
        try:
            self.transport_key_manager.load_transport_key()
            logger.debug("Loaded existing KRA transport key")
        except (FileNotFoundError, RuntimeError):
            logger.debug("No transport key found, generating new one")
            self.transport_key_manager.generate_transport_key(
                ca_key, ca_cert, force=force
            )

        # Generate or load storage key (with HSM support)
        # Note: RuntimeError is raised when key doesn't exist in NSSDB
        try:
            self.storage_key_manager.load_storage_key()
            logger.debug("Loaded existing KRA storage key")
        except (FileNotFoundError, RuntimeError):
            logger.debug("No storage key found, generating new one")
            self.storage_key_manager.generate_storage_key(
                ca_key, ca_cert, force=force
            )

        logger.debug("KRA initialized successfully")

    def get_transport_cert(self) -> str:
        """Get transport certificate (PEM format) for clients"""
        return self.transport_key_manager.get_transport_cert_pem()

    def archive_secret(
        self,
        encrypted_secret: bytes,
        owner: str,
        algorithm: str = "AES",
        key_size: int = 256,
    ) -> str:
        """
        Archive an encrypted secret in KRA

        Args:
            encrypted_secret: Secret encrypted with transport public key
            owner: Owner of the secret (e.g., vault DN or username)
            algorithm: Key algorithm (AES, 3DES, etc.)
            key_size: Key size in bits

        Returns:
            Key ID for retrieving the secret later
        """
        if self.storage_backend is None:
            raise RuntimeError("KRA not initialized - no storage backend")

        # Unwrap secret using transport private key
        secret = self.transport_key_manager.unwrap_secret(encrypted_secret)

        # Re-encrypt with storage key for LDAP
        encrypted_for_storage = self.storage_key_manager.encrypt_for_storage(
            secret
        )

        # Store in LDAP
        key_id = self.storage_backend.store_key(
            encrypted_data=encrypted_for_storage,
            owner=owner,
            algorithm=algorithm,
            key_size=key_size,
            status="active",
        )

        logger.debug("Archived secret for %s, key_id=%s", owner, key_id)
        return key_id

    def retrieve_secret(self, key_id: str, requester: str) -> bytes:
        """
        Retrieve and decrypt a secret from KRA

        Args:
            key_id: Key identifier
            requester: Principal requesting the secret

        Returns:
            Secret encrypted with transport public key (for secure
            transmission)
        """
        if self.storage_backend is None:
            raise RuntimeError("KRA not initialized - no storage backend")

        # Retrieve from LDAP
        key_record = self.storage_backend.get_key(key_id)

        if key_record is None:
            raise ValueError(f"Key {key_id} not found")

        # Authorization check: requester must be key owner
        # Fail-closed: reject if requester is missing or doesn't match owner
        key_owner = key_record.get("owner", "")
        if not requester:
            logger.warning(
                "Key retrieval rejected: no requester specified, key=%s",
                key_id,
            )
            raise PermissionError(
                f"Requester identity required to retrieve key {key_id}"
            )
        if key_owner and requester != key_owner:
            logger.warning(
                "Unauthorized key retrieval attempt: "
                "requester=%s, owner=%s, key=%s",
                requester,
                key_owner,
                key_id,
            )
            raise PermissionError(
                f"Requester {requester} is not authorized to "
                f"retrieve key {key_id}"
            )

        # Decrypt from storage
        secret = self.storage_key_manager.decrypt_from_storage(
            key_record["encrypted_data"]
        )

        # Re-wrap with transport key for transmission
        wrapped_secret = self.transport_key_manager.wrap_secret(secret)

        logger.debug(
            "Retrieved secret %s for %s, owner=%s",
            key_id,
            requester,
            key_record.get("owner"),
        )
        return wrapped_secret

    def list_keys(
        self, owner: Optional[str] = None, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List archived keys

        Args:
            owner: Filter by owner (optional)
            status: Filter by status (optional)

        Returns:
            List of key metadata dictionaries
        """
        if self.storage_backend is None:
            raise RuntimeError("KRA not initialized - no storage backend")

        return self.storage_backend.list_keys(owner=owner, status=status)

    def modify_key_status(self, key_id: str, status: str) -> bool:
        """
        Modify key status (active, inactive, archived)

        Args:
            key_id: Key identifier
            status: New status

        Returns:
            True if successful
        """
        if self.storage_backend is None:
            raise RuntimeError("KRA not initialized - no storage backend")

        return self.storage_backend.update_key_status(key_id, status)


# Singleton KRA instance
_kra_instance = None
_kra_lock = threading.Lock()


def get_kra() -> KRA:
    """Get singleton KRA instance"""
    global _kra_instance
    with _kra_lock:
        if _kra_instance is None:
            _kra_instance = KRA()
        return _kra_instance
