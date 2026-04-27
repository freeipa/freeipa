# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Python CA Key Escrow Backend

This module implements key escrow functionality using Python cryptography
library as a replacement for Dogtag PKI KRA (Key Recovery Authority).

Key escrow allows for secure storage and retrieval of encrypted data
using transport encryption and key wrapping mechanisms.
"""

import logging
import json
import os
import secrets
from datetime import datetime, timezone
from typing import List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from ipalib import errors
from ipathinca import get_config_value
from ipathinca import x509_utils

logger = logging.getLogger(__name__)


# Constants for key wrapping algorithms (compatible with vault.py)
DES_EDE3_CBC_OID = "1.2.840.113549.3.7"
AES_128_CBC_OID = "2.16.840.1.101.3.4.1.2"

# Key status constants (compatible with PKI)
KEY_STATUS_ACTIVE = "active"
KEY_STATUS_INACTIVE = "inactive"

# Key types
PASS_PHRASE_TYPE = "passphrase"


class KeyInfo:
    """
    Key information object compatible with PKI KeyInfo
    """

    def __init__(self, key_id: str, client_key_id: str, status: str):
        self.key_id = key_id
        self.client_key_id = client_key_id
        self.status = status
        self.key_type = PASS_PHRASE_TYPE

    def get_key_id(self):
        return self.key_id


class KeyData:
    """
    Key data object compatible with PKI KeyData
    """

    def __init__(self, encrypted_data: bytes, nonce_data: bytes):
        self.encrypted_data = encrypted_data
        self.nonce_data = nonce_data


class KeyResponse:
    """
    Key response object compatible with PKI
    """

    def __init__(self, key_infos: List[KeyInfo]):
        self.key_infos = key_infos


class PythonKeyEscrowBackend:
    """
    Python implementation of key escrow functionality

    This replaces Dogtag PKI KRA for key archival and recovery operations.
    """

    def __init__(self, storage_path: str = None):
        if storage_path is None:
            # Try to read from config, default to /var/lib/ipa/key_escrow
            storage_path = get_config_value(
                "key_escrow", "storage_path", "/var/lib/ipa/key_escrow"
            )

        self.storage_path = storage_path
        self.transport_cert_path = os.path.join(
            storage_path, "transport_cert.pem"
        )
        self.transport_key_path = os.path.join(
            storage_path, "transport_key.pem"
        )

        # Initialize storage directory
        os.makedirs(storage_path, mode=0o750, exist_ok=True)

        # Initialize transport certificate if needed
        self._ensure_transport_cert()

    def _ensure_transport_cert(self):
        """
        Ensure transport certificate exists for key wrapping
        """
        if not os.path.exists(self.transport_cert_path):
            logger.info("Generating transport certificate for key escrow")
            self._generate_transport_cert()

    def _generate_transport_cert(self):
        """
        Generate self-signed transport certificate for key wrapping
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )

        # Create self-signed certificate
        subject = issuer = x509_utils.build_x509_name(
            [
                ("CN", "Transport Certificate"),
                ("O", "IPA Key Escrow"),
                ("L", "Unknown"),
                ("ST", "Unknown"),
                ("C", "US"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(
                datetime.now(timezone.utc).replace(
                    year=datetime.now().year + 10
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Save certificate and key
        with open(self.transport_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(self.transport_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Set restrictive permissions
        os.chmod(self.transport_key_path, 0o600)
        os.chmod(self.transport_cert_path, 0o644)

    def get_transport_cert(self):
        """
        Get transport certificate for key wrapping

        Returns:
            Transport certificate object with binary property
        """
        with open(self.transport_cert_path, "rb") as f:
            cert_data = f.read()

        class TransportCert:
            def __init__(self, data):
                self.binary = data

        return TransportCert(cert_data)

    def _get_storage_file(self, client_key_id: str) -> str:
        """
        Get storage file path for client key ID
        """
        # Sanitize client_key_id for filename
        safe_id = client_key_id.replace("/", "_").replace(":", "_")
        return os.path.join(self.storage_path, f"{safe_id}.json")

    def archive_encrypted_data(
        self,
        client_key_id: str,
        key_type: str,
        wrapped_vault_data: bytes,
        wrapped_session_key: bytes,
        algorithm_oid: str = None,
        nonce_iv: bytes = None,
    ):
        """
        Archive encrypted data (replacement for KRA archive_encrypted_data)

        Args:
            client_key_id: Client identifier for the key
            key_type: Type of key (e.g., PASS_PHRASE_TYPE)
            wrapped_vault_data: Encrypted vault data
            wrapped_session_key: Session key wrapped with transport cert
            algorithm_oid: Algorithm OID for wrapping
            nonce_iv: Nonce/IV for encryption
        """
        logger.debug(f"Archiving data for client key ID: {client_key_id}")

        # Generate unique key ID
        key_id = f"key-{secrets.token_hex(16)}"

        # Create key record
        key_record = {
            "key_id": key_id,
            "client_key_id": client_key_id,
            "key_type": key_type,
            "status": KEY_STATUS_ACTIVE,
            "wrapped_vault_data": (
                wrapped_vault_data.hex() if wrapped_vault_data else None
            ),
            "wrapped_session_key": (
                wrapped_session_key.hex() if wrapped_session_key else None
            ),
            "algorithm_oid": algorithm_oid,
            "nonce_iv": nonce_iv.hex() if nonce_iv else None,
            "created_time": datetime.now(timezone.utc).isoformat(),
            "modified_time": datetime.now(timezone.utc).isoformat(),
        }

        # Store key record
        storage_file = self._get_storage_file(client_key_id)

        # Load existing records or create new list
        if os.path.exists(storage_file):
            with open(storage_file, "r") as f:
                records = json.load(f)
        else:
            records = []

        # Deactivate existing active keys for this client
        for record in records:
            if record["status"] == KEY_STATUS_ACTIVE:
                record["status"] = KEY_STATUS_INACTIVE
                record["modified_time"] = datetime.now(
                    timezone.utc
                ).isoformat()

        # Add new record
        records.append(key_record)

        # Save updated records
        with open(storage_file, "w") as f:
            json.dump(records, f, indent=2)

        # Set restrictive permissions
        os.chmod(storage_file, 0o600)

        logger.info(f"Successfully archived data with key ID: {key_id}")
        return key_id

    def list_keys(self, client_key_id: str, status: str = None) -> KeyResponse:
        """
        List keys for a client (replacement for KRA list_keys)

        Args:
            client_key_id: Client identifier
            status: Filter by status (e.g., KEY_STATUS_ACTIVE)

        Returns:
            KeyResponse object with list of KeyInfo objects
        """
        logger.debug(
            f"Listing keys for client: {client_key_id}, status: {status}"
        )

        storage_file = self._get_storage_file(client_key_id)

        if not os.path.exists(storage_file):
            return KeyResponse([])

        with open(storage_file, "r") as f:
            records = json.load(f)

        key_infos = []
        for record in records:
            if status is None or record["status"] == status:
                key_info = KeyInfo(
                    key_id=record["key_id"],
                    client_key_id=record["client_key_id"],
                    status=record["status"],
                )
                key_infos.append(key_info)

        return KeyResponse(key_infos)

    def modify_key_status(self, key_id: str, new_status: str):
        """
        Modify key status (replacement for KRA modify_key_status)

        Args:
            key_id: Key identifier
            new_status: New status (e.g., KEY_STATUS_INACTIVE)
        """
        logger.debug(f"Modifying key status: {key_id} -> {new_status}")

        # Find the key across all storage files
        for filename in os.listdir(self.storage_path):
            if not filename.endswith(".json"):
                continue

            filepath = os.path.join(self.storage_path, filename)

            with open(filepath, "r") as f:
                records = json.load(f)

            modified = False
            for record in records:
                if record["key_id"] == key_id:
                    record["status"] = new_status
                    record["modified_time"] = datetime.now(
                        timezone.utc
                    ).isoformat()
                    modified = True
                    break

            if modified:
                with open(filepath, "w") as f:
                    json.dump(records, f, indent=2)
                logger.info(f"Updated key {key_id} status to {new_status}")
                return

        raise errors.NotFound(reason=f"Key {key_id} not found")

    def retrieve_key(self, key_id: str, wrapped_session_key: bytes) -> KeyData:
        """
        Retrieve key data (replacement for KRA retrieve_key)

        Args:
            key_id: Key identifier
            wrapped_session_key: Session key wrapped with transport cert

        Returns:
            KeyData object with encrypted data and nonce
        """
        logger.debug(f"Retrieving key: {key_id}")

        # Find the key across all storage files
        for filename in os.listdir(self.storage_path):
            if not filename.endswith(".json"):
                continue

            filepath = os.path.join(self.storage_path, filename)

            with open(filepath, "r") as f:
                records = json.load(f)

            for record in records:
                if record["key_id"] == key_id:
                    if record["status"] != KEY_STATUS_ACTIVE:
                        raise errors.InvalidRequest(
                            reason=f"Key {key_id} is not active"
                        )

                    # Return the stored encrypted data
                    encrypted_data = (
                        bytes.fromhex(record["wrapped_vault_data"])
                        if record["wrapped_vault_data"]
                        else b""
                    )
                    nonce_data = (
                        bytes.fromhex(record["nonce_iv"])
                        if record["nonce_iv"]
                        else b""
                    )

                    logger.info(f"Successfully retrieved key: {key_id}")
                    return KeyData(encrypted_data, nonce_data)

        raise errors.NotFound(reason=f"Key {key_id} not found")


class PythonKeyEscrowClient:
    """
    Client interface for key escrow operations

    This replaces the KRA client interface used in vault.py
    """

    def __init__(self, backend: PythonKeyEscrowBackend = None):
        self.backend = backend or PythonKeyEscrowBackend()
        self.keys = self  # For compatibility with kra_client.keys interface
        self.system_certs = (
            self  # For compatibility with kra_client.system_certs
        )
        self.connection = None  # For compatibility with PKI connection

        # Constants for compatibility
        self.KEY_STATUS_ACTIVE = KEY_STATUS_ACTIVE
        self.KEY_STATUS_INACTIVE = KEY_STATUS_INACTIVE
        self.PASS_PHRASE_TYPE = PASS_PHRASE_TYPE

        # Encryption algorithm OID (compatibility)
        self.encrypt_alg_oid = None

    def get_transport_cert(self):
        """Get transport certificate"""
        return self.backend.get_transport_cert()

    def archive_encrypted_data(
        self,
        client_key_id: str,
        key_type: str,
        wrapped_vault_data: bytes,
        wrapped_session_key: bytes,
        algorithm_oid: str = None,
        nonce_iv: bytes = None,
    ):
        """Archive encrypted data"""
        return self.backend.archive_encrypted_data(
            client_key_id,
            key_type,
            wrapped_vault_data,
            wrapped_session_key,
            algorithm_oid,
            nonce_iv,
        )

    def list_keys(self, client_key_id: str, status: str = None):
        """List keys"""
        return self.backend.list_keys(client_key_id, status)

    def modify_key_status(self, key_id: str, new_status: str):
        """Modify key status"""
        return self.backend.modify_key_status(key_id, new_status)

    def retrieve_key(self, key_id: str, wrapped_session_key: bytes):
        """Retrieve key"""
        return self.backend.retrieve_key(key_id, wrapped_session_key)


def get_python_key_escrow_client() -> PythonKeyEscrowClient:
    """
    Factory function to get Python key escrow client

    Returns:
        PythonKeyEscrowClient instance
    """
    return PythonKeyEscrowClient()


# Compatibility constants for vault.py
class PKICompatibility:
    """PKI compatibility constants and types"""

    # Exception for compatibility
    class PKIException(Exception):
        pass

    # Account client for compatibility
    class AccountClient:
        def __init__(self, connection=None, subsystem=None):
            self.connection = connection
            self.subsystem = subsystem

        def login(self):
            pass  # No-op for Python implementation

        def logout(self):
            pass  # No-op for Python implementation


# Export compatibility objects
PKIException = PKICompatibility.PKIException
AccountClient = PKICompatibility.AccountClient
