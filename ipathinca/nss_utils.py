# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
"""
NSS Database Utilities for IPAthinCA

This module provides utilities for working with NSS databases (NSSDB),
following Dogtag's approach of storing all private keys in the NSSDB
rather than as PEM files on the filesystem.

Key Features:
- Generate RSA key pairs directly in NSSDB using certutil
- Extract private keys from NSSDB for cryptographic operations
- Extract certificates from NSSDB
- Dogtag-compatible key storage without PEM files
"""

import logging
import os
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ipapython import ipautil
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)


class NSSDatabase:
    """
    NSS Database manager for IPAthinCA

    Provides Dogtag-compatible key and certificate management using NSSDB
    as the primary storage location (no PEM key files on disk).
    """

    def __init__(
        self,
        nssdb_dir: Path = None,
        nssdb_password: str = None,
        password_file: Path = None,
    ):
        """
        Initialize NSS Database manager

        Args:
            nssdb_dir: Path to NSSDB directory
                      (default: /etc/pki/pki-tomcat/alias)
            nssdb_password: NSSDB password (if not provided, read from file)
            password_file: Path to password file
                          (default: /etc/pki/pki-tomcat/password.conf)
        """
        self.nssdb_dir = nssdb_dir or Path(paths.PKI_TOMCAT_ALIAS_DIR)
        self.password_file = password_file or Path(
            paths.PKI_TOMCAT_PASSWORD_CONF
        )

        if nssdb_password:
            self.nssdb_password = nssdb_password
        else:
            self.nssdb_password = self._load_password()

    def _load_password(self) -> str:
        """Load NSSDB password from password.conf file"""
        if not self.password_file.exists():
            raise RuntimeError(
                f"NSSDB password file not found: {self.password_file}"
            )

        with open(self.password_file, "r") as f:
            for line in f:
                if line.startswith("internal="):
                    password = line.split("=", 1)[1].strip()
                    logger.debug("Loaded NSSDB password from file")
                    return password

        raise RuntimeError(f"NSSDB password not found in {self.password_file}")

    def generate_key_pair(
        self, nickname: str, key_size: int = 4096
    ) -> rsa.RSAPrivateKey:
        """
        Generate RSA key pair for NSSDB

        Hybrid approach (Option B):
        - Generate key in memory using cryptography library
        - Key will be imported to NSSDB later via import_key_and_cert()
        - No PEM files created on disk
        - Key ends up ONLY in NSSDB

        This avoids certutil hanging issues while maintaining NSSDB-only
        storage.

        Args:
            nickname: Certificate/key nickname in NSSDB (for logging)
            key_size: RSA key size in bits (default: 4096)

        Returns:
            RSA private key object (in memory, will be imported to NSSDB)

        Raises:
            RuntimeError: If key generation fails
        """
        logger.debug(
            f"Generating {key_size}-bit RSA key pair for NSSDB: {nickname}"
        )

        from cryptography.hazmat.primitives.asymmetric import rsa

        # Generate RSA key pair in memory
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        logger.debug(
            f"Generated {key_size}-bit RSA key pair (will be imported to "
            "NSSDB)"
        )

        return private_key

    def extract_private_key(self, nickname: str) -> rsa.RSAPrivateKey:
        """
        Extract private key from NSSDB for cryptographic operations

        This extracts the key temporarily for use with the cryptography
        library, but the key remains stored in NSSDB. The extracted key only
        exists in memory and is not written to disk.

        Args:
            nickname: Certificate/key nickname in NSSDB

        Returns:
            RSA private key object from cryptography library

        Raises:
            RuntimeError: If key extraction fails
        """
        logger.debug(f"Extracting private key from NSSDB: {nickname}")

        # Create temporary password file (restrictive permissions)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as pwdfile:
            os.fchmod(pwdfile.fileno(), 0o600)
            pwdfile.write(self.nssdb_password)
            pwdfile.flush()
            temp_password_file = pwdfile.name

        # Create temporary PKCS#12 file
        with tempfile.NamedTemporaryFile(
            suffix=".p12", delete=False
        ) as p12_file:
            p12_path = p12_file.name

        try:
            # Export key+cert to PKCS#12 using pk12util
            logger.debug(f"Exporting {nickname} to temporary PKCS#12")
            result = ipautil.run(
                [
                    "pk12util",
                    "-o",
                    p12_path,
                    "-d",
                    str(self.nssdb_dir),
                    "-n",
                    nickname,
                    "-k",
                    temp_password_file,
                    "-w",
                    temp_password_file,
                ],
                capture_output=True,
                raiseonerr=False,
            )

            if result.returncode != 0:
                logger.error(f"pk12util export failed: {result.error_output}")
                raise RuntimeError(
                    f"Failed to extract key for {nickname} from NSSDB"
                )

            # Convert PKCS#12 to PEM in memory using openssl
            logger.debug("Converting PKCS#12 to PEM in memory")
            result = ipautil.run(
                [
                    "openssl",
                    "pkcs12",
                    "-in",
                    p12_path,
                    "-nocerts",
                    "-nodes",
                    "-passin",
                    f"pass:{self.nssdb_password}",
                ],
                capture_output=True,
                raiseonerr=True,
            )

            # Load private key from PEM (in memory only)
            key_pem = (
                result.output.encode()
                if isinstance(result.output, str)
                else result.output
            )
            private_key = serialization.load_pem_private_key(
                key_pem, password=None
            )

            logger.debug(
                f"Successfully extracted private key from NSSDB: {nickname}"
            )
            return private_key

        finally:
            # Clean up temporary files
            Path(temp_password_file).unlink(missing_ok=True)
            Path(p12_path).unlink(missing_ok=True)

    def extract_certificate(self, nickname: str) -> x509.Certificate:
        """
        Extract certificate from NSSDB

        Args:
            nickname: Certificate nickname in NSSDB

        Returns:
            X.509 certificate object

        Raises:
            RuntimeError: If certificate extraction fails
        """
        logger.debug(f"Extracting certificate from NSSDB: {nickname}")

        # Export certificate using certutil -L
        result = ipautil.run(
            [
                "certutil",
                "-L",
                "-d",
                str(self.nssdb_dir),
                "-n",
                nickname,
                "-a",  # ASCII/PEM output
            ],
            capture_output=True,
            raiseonerr=False,
        )

        if result.returncode != 0:
            logger.error(f"certutil -L failed: {result.error_output}")
            raise RuntimeError(
                f"Failed to extract certificate for {nickname} from NSSDB"
            )

        # Parse certificate
        cert_pem = (
            result.output.encode()
            if isinstance(result.output, str)
            else result.output
        )
        certificate = x509.load_pem_x509_certificate(cert_pem)

        logger.debug(f"Successfully extracted certificate: {nickname}")
        return certificate

    def import_key_and_cert(
        self,
        nickname: str,
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate,
        trust_flags: str = "u,u,u",
    ) -> None:
        """
        Import private key and certificate into NSSDB

        This is the hybrid approach: key generated in memory, imported to NSSDB
        via PKCS#12, then PKCS#12 file deleted. Key ends up ONLY in NSSDB.

        Args:
            nickname: Certificate nickname in NSSDB
            private_key: RSA private key to import
            certificate: X.509 certificate to import
            trust_flags: NSS trust flags (default: u,u,u)

        Raises:
            RuntimeError: If import fails
        """
        logger.debug(f"Importing key and certificate to NSSDB: {nickname}")

        # Create temporary password file (restrictive permissions)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as pwdfile:
            os.fchmod(pwdfile.fileno(), 0o600)
            pwdfile.write(self.nssdb_password)
            pwdfile.flush()
            temp_password_file = pwdfile.name

        # Create temporary PKCS#12 file
        with tempfile.NamedTemporaryFile(
            suffix=".p12", delete=False
        ) as p12_file:
            p12_path = p12_file.name

        temp_key_file = None
        temp_cert_file = None
        try:
            # Create PKCS#12 from key and cert using openssl
            # First create temp PEM files
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".key", delete=False
            ) as keyfile:
                os.fchmod(keyfile.fileno(), 0o600)
                keyfile.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
                temp_key_file = keyfile.name

            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".crt", delete=False
            ) as certfile:
                certfile.write(
                    certificate.public_bytes(serialization.Encoding.PEM)
                )
                temp_cert_file = certfile.name

            # Create PKCS#12
            ipautil.run(
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-in",
                    temp_cert_file,
                    "-inkey",
                    temp_key_file,
                    "-out",
                    p12_path,
                    "-name",
                    nickname,
                    "-passout",
                    f"pass:{self.nssdb_password}",
                ],
                raiseonerr=True,
            )

            # Import PKCS#12 to NSSDB
            ipautil.run(
                [
                    "pk12util",
                    "-i",
                    p12_path,
                    "-d",
                    str(self.nssdb_dir),
                    "-k",
                    temp_password_file,
                    "-w",
                    temp_password_file,
                ],
                raiseonerr=True,
            )

            # Set trust flags
            ipautil.run(
                [
                    "certutil",
                    "-M",
                    "-d",
                    str(self.nssdb_dir),
                    "-n",
                    nickname,
                    "-t",
                    trust_flags,
                    "-f",
                    temp_password_file,
                ],
                raiseonerr=True,
            )

            logger.debug(
                "Successfully imported key and certificate to NSSDB: "
                f"{nickname}"
            )

        finally:
            # Clean up all temporary files
            Path(temp_password_file).unlink(missing_ok=True)
            Path(p12_path).unlink(missing_ok=True)
            if temp_key_file:
                Path(temp_key_file).unlink(missing_ok=True)
            if temp_cert_file:
                Path(temp_cert_file).unlink(missing_ok=True)

    def import_certificate(
        self,
        nickname: str,
        certificate: x509.Certificate,
        trust_flags: str = "u,u,u",
    ) -> None:
        """
        Import certificate into NSSDB (key must already exist in NSSDB)

        This is used when the key was already generated/imported to NSSDB
        and we just need to import the signed certificate.

        Args:
            nickname: Certificate nickname in NSSDB
            certificate: X.509 certificate to import
            trust_flags: NSS trust flags (default: u,u,u)

        Raises:
            RuntimeError: If certificate import fails
        """
        logger.debug(f"Importing certificate to NSSDB: {nickname}")

        # Create temporary password file (restrictive permissions)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as pwdfile:
            os.fchmod(pwdfile.fileno(), 0o600)
            pwdfile.write(self.nssdb_password)
            pwdfile.flush()
            temp_password_file = pwdfile.name

        # Create temporary certificate file
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".crt", delete=False
        ) as cert_file:
            cert_file.write(
                certificate.public_bytes(serialization.Encoding.PEM)
            )
            cert_file.flush()
            temp_cert_file = cert_file.name

        try:
            # Import certificate using certutil -A
            result = ipautil.run(
                [
                    "certutil",
                    "-A",
                    "-d",
                    str(self.nssdb_dir),
                    "-n",
                    nickname,
                    "-t",
                    trust_flags,
                    "-i",
                    temp_cert_file,
                    "-f",
                    temp_password_file,
                ],
                capture_output=True,
                raiseonerr=False,
            )

            if result.returncode != 0:
                logger.error(f"certutil -A failed: {result.error_output}")
                raise RuntimeError(
                    f"Failed to import certificate for {nickname} to NSSDB"
                )

            logger.debug(
                f"Successfully imported certificate to NSSDB: {nickname}"
            )

        finally:
            # Clean up temporary files
            Path(temp_password_file).unlink(missing_ok=True)
            Path(temp_cert_file).unlink(missing_ok=True)

    def cert_exists(self, nickname: str) -> bool:
        """
        Check if a certificate with the given nickname exists in NSSDB

        Args:
            nickname: Certificate nickname to check

        Returns:
            True if certificate exists, False otherwise
        """
        # Use certutil -L with nickname to check existence
        # Don't log errors since this is an existence check
        result = ipautil.run(
            [
                "certutil",
                "-L",
                "-d",
                str(self.nssdb_dir),
                "-n",
                nickname,
            ],
            capture_output=True,
            raiseonerr=False,
        )
        return result.returncode == 0
