# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""NSS database helper for IPAThinCAInstance.

Handles creation and management of the NSSDB at
/etc/pki/pki-tomcat/alias/ for Dogtag/certmonger compatibility.
"""

from __future__ import absolute_import

import logging
import os
import shutil
import tempfile
from pathlib import Path

from ipaplatform.paths import paths
from ipapython import ipautil

logger = logging.getLogger(__name__)


class NSSDB:
    """Helper providing NSS database operations."""

    def __init__(self):
        self.nssdb_dir = None
        self.nssdb_password_file = None
        self.nssdb_password = None

    def create_nssdb(self):
        """Create NSS database for Dogtag/certmonger compatibility.

        Creates NSSDB at /etc/pki/pki-tomcat/alias/ to ensure ipathinca is a
        100% drop-in replacement for Dogtag. This allows:
        - Certmonger to track certificates by nickname
        - NSS tools (certutil, pk12util) to work
        - Smooth migration from Dogtag to ipathinca
        """
        logger.debug("Creating NSS database for certificate storage")

        # NSS database directory (same as Dogtag)
        self.nssdb_dir = Path(paths.PKI_TOMCAT_ALIAS_DIR)
        self.nssdb_password_file = Path(paths.PKI_TOMCAT_PASSWORD_CONF)

        # Create directories
        self.nssdb_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.nssdb_password_file.parent.mkdir(
            parents=True, exist_ok=True, mode=0o750
        )

        # Set ownership (same as Dogtag: ipaca:ipaca)
        shutil.chown(self.nssdb_dir, user="ipaca", group="ipaca")
        shutil.chown(
            self.nssdb_password_file.parent, user="ipaca", group="ipaca"
        )

        # Check if NSS database already exists (e.g., from previous Dogtag
        # installation)
        # Both old (cert8.db) and new (cert9.db) format files
        nssdb_files = [
            "cert9.db",
            "key4.db",
            "pkcs11.txt",
            "cert8.db",
            "key3.db",
            "secmod.db",
        ]
        existing_files = [
            f for f in nssdb_files if (self.nssdb_dir / f).exists()
        ]

        if existing_files:
            logger.info(
                "Removing existing NSSDB files from previous installation: "
                f"{existing_files}"
            )
            for filename in existing_files:
                filepath = self.nssdb_dir / filename
                try:
                    filepath.unlink()
                    logger.debug(f"Removed {filepath}")
                except Exception as e:
                    logger.warning(f"Failed to remove {filepath}: {e}")

        # Check for existing password file (idempotency: reuse if NSSDB
        # already exists from interrupted installation)
        if (
            self.nssdb_password_file.exists()
            and (self.nssdb_dir / "cert9.db").exists()
        ):
            logger.debug(
                "NSSDB password file and database exist, reusing password"
            )
            self.load_nssdb_password()
            return

        # Generate strong random password for NSSDB
        self.nssdb_password = ipautil.ipa_generate_password()

        # Create password file atomically with restrictive permissions
        # (Dogtag format: internal=password)
        fd = os.open(
            str(self.nssdb_password_file),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(fd, "w") as f:
            f.write(f"internal={self.nssdb_password}\n")
        shutil.chown(self.nssdb_password_file, user="ipaca", group="ipaca")

        # Create NSS database using certutil
        logger.debug(f"Initializing NSSDB at {self.nssdb_dir}")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as pwdfile:
            os.fchmod(pwdfile.fileno(), 0o600)
            pwdfile.write(self.nssdb_password)
            pwdfile.flush()
            temp_password_file = pwdfile.name

        try:
            # Create NSSDB with certutil -N (same as Dogtag)
            ipautil.run(
                [
                    "certutil",
                    "-N",
                    "-d",
                    str(self.nssdb_dir),
                    "-f",
                    temp_password_file,
                ]
            )
            logger.debug(f"NSSDB created successfully at {self.nssdb_dir}")
        finally:
            # Clean up temporary password file
            os.unlink(temp_password_file)

        # Verify NSSDB was created
        if not (self.nssdb_dir / "cert9.db").exists():
            raise RuntimeError(f"Failed to create NSSDB at {self.nssdb_dir}")

        # Fix ownership of NSSDB files (certutil creates as root, need ipaca)
        logger.debug("Setting NSSDB file ownership to ipaca:ipaca")
        for nssdb_file in ["cert9.db", "key4.db", "pkcs11.txt"]:
            file_path = self.nssdb_dir / nssdb_file
            if file_path.exists():
                shutil.chown(file_path, user="ipaca", group="ipaca")
        logger.debug("NSSDB file ownership set to ipaca:ipaca")

        logger.debug("NSS database created and verified")

    def load_nssdb_password(self):
        """Load NSSDB password from file if not already in memory.

        This is needed when enable_kra() or other methods are called
        separately from create_instance() in a different execution context.
        """
        if self.nssdb_password:
            return

        # Set NSSDB paths if not already set
        if self.nssdb_dir is None:
            self.nssdb_dir = Path(paths.PKI_TOMCAT_ALIAS_DIR)
        if self.nssdb_password_file is None:
            self.nssdb_password_file = Path(paths.PKI_TOMCAT_PASSWORD_CONF)

        # Read password from file
        if self.nssdb_password_file.exists():
            with open(self.nssdb_password_file, "r") as f:
                for line in f:
                    if line.startswith("internal="):
                        self.nssdb_password = line.split("=", 1)[1].strip()
                        if not self.nssdb_password:
                            raise RuntimeError(
                                "NSSDB password is empty in "
                                f"{self.nssdb_password_file}"
                            )
                        logger.debug("Loaded NSSDB password from file")
                        return

        raise RuntimeError(
            f"NSSDB password not found in {self.nssdb_password_file}"
        )

    def import_cert_to_nssdb(
        self, cert_pem_path, key_pem_path, nickname, trust_flags="u,u,u"
    ):
        """Import certificate and private key to NSSDB.

        This ensures certificates are accessible to:
        - Certmonger for certificate tracking and renewal
        - NSS tools (certutil, pk12util, modutil)

        Args:
            cert_pem_path: Path to PEM certificate file
            key_pem_path: Path to PEM private key file
            nickname: Certificate nickname in NSSDB (e.g., "caSigningCert
                      cert-pki-ca")
            trust_flags: NSS trust flags (default: u,u,u for user certs)
        """
        logger.debug(f"Importing certificate '{nickname}' to NSSDB")

        # Ensure NSSDB password is loaded
        self.load_nssdb_password()

        # Create temporary PKCS#12 file from PEM cert+key
        with tempfile.NamedTemporaryFile(
            suffix=".p12", delete=False
        ) as p12_file:
            p12_path = p12_file.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as pwdfile:
            os.fchmod(pwdfile.fileno(), 0o600)
            pwdfile.write(self.nssdb_password)
            pwdfile.flush()
            temp_password_file = pwdfile.name

        try:
            # Create PKCS#12 from PEM cert+key using openssl
            logger.debug(
                f"Creating PKCS#12 from {cert_pem_path} and {key_pem_path}"
            )
            ipautil.run(
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-in",
                    str(cert_pem_path),
                    "-inkey",
                    str(key_pem_path),
                    "-out",
                    p12_path,
                    "-name",
                    nickname,
                    "-passout",
                    f"file:{temp_password_file}",
                ]
            )

            # Import PKCS#12 to NSSDB using pk12util
            logger.debug(
                f"Importing PKCS#12 to NSSDB with nickname '{nickname}'"
            )
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
                ]
            )

            # Set trust flags if not default
            if trust_flags != "u,u,u":
                logger.debug(
                    f"Setting trust flags to '{trust_flags}' for '{nickname}'"
                )
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
                    ]
                )

            # Verify certificate was imported
            result = ipautil.run(
                [
                    "certutil",
                    "-L",
                    "-d",
                    str(self.nssdb_dir),
                    "-n",
                    nickname,
                    "-f",
                    temp_password_file,
                ],
                raiseonerr=False,
            )

            if result.returncode == 0:
                logger.debug(
                    f"Certificate '{nickname}' successfully imported to NSSDB"
                )
            else:
                raise RuntimeError(
                    f"Failed to verify certificate import: {nickname}"
                )

        finally:
            # Clean up temporary files
            if os.path.exists(p12_path):
                os.unlink(p12_path)
            if os.path.exists(temp_password_file):
                os.unlink(temp_password_file)
