# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Certificate generation helper for IPAThinCAInstance.

Handles CA certificate generation (self-signed, external CA, HSM), subsystem
certificate generation, server certificate, RA agent certificate, and CA
certificate storage in LDAP and NSS databases.
"""

from __future__ import absolute_import

import datetime
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ipalib import errors
from ipalib.constants import IPA_CA_CN, IPAAPI_GROUP
from ipaplatform.paths import paths
from ipapython import ipautil, dogtag
from ipapython.dn import DN
from ipapython.certdb import get_ca_nickname
from ipathinca.ca import CertificateRequest, CertificateRecord, PythonCA
from ipathinca.hsm import HSMConfig, HSMKeyBackend
from ipathinca.nss_utils import NSSDatabase
from ipathinca.storage_factory import get_storage_backend
from ipathinca.x509_utils import (
    ipa_dn_to_x509_name,
    get_subject_dn_str,
    build_x509_name,
)

logger = logging.getLogger(__name__)


def get_cert_params_from_config(pki_config, cert_type):
    """Get certificate key parameters from pki_config.

    Args:
        pki_config: ConfigParser with PKI configuration, or None
        cert_type: Certificate type (e.g., 'ca_signing', 'subsystem',
                   'audit_signing', 'ocsp_signing', 'sslserver')

    Returns:
        tuple: (key_size, signing_algorithm) with defaults if not in config
    """
    if pki_config is None:
        return (2048, "SHA256withRSA")

    config_prefix = {
        "ca_signing": "pki_ca_signing",
        "subsystem": "pki_subsystem",
        "audit_signing": "pki_audit_signing",
        "ocsp_signing": "pki_ocsp_signing",
        "sslserver": "pki_sslserver",
    }.get(cert_type, "pki_sslserver")

    key_size = pki_config.getint(
        "CA",
        f"{config_prefix}_key_size",
        fallback=pki_config.getint("DEFAULT", "ipa_key_size", fallback=2048),
    )

    signing_alg = pki_config.get(
        "CA",
        f"{config_prefix}_signing_algorithm",
        fallback=pki_config.get(
            "DEFAULT", "ipa_signing_algorithm", fallback="SHA256withRSA"
        ),
    )

    return (key_size, signing_alg)


def convert_signing_algorithm(signing_alg):
    """Convert PKI signing algorithm string to cryptography hash algorithm.

    Args:
        signing_alg: PKI algorithm string (e.g., 'SHA256withRSA',
                     'SHA512withRSA')

    Returns:
        cryptography hash algorithm instance
    """
    if "SHA512" in signing_alg:
        return hashes.SHA512()
    elif "SHA384" in signing_alg:
        return hashes.SHA384()
    elif "SHA256" in signing_alg:
        return hashes.SHA256()
    elif "SHA1" in signing_alg:
        return hashes.SHA1()
    else:
        logger.warning(
            f"Unknown signing algorithm '{signing_alg}', "
            "defaulting to SHA256"
        )
        return hashes.SHA256()


class Certs:
    """Helper providing certificate generation and storage methods."""

    def __init__(
        self,
        ldap,
        config,
        pki_config,
        nssdb,
        subject_base,
        ca_subject,
        realm,
        fqdn,
        basedn,
        random_serial_numbers,
        ca_signing_algorithm=None,
        external_ca_step=0,
        external_ca_type=None,
        external_ca_profile=None,
        csr_file=None,
        cert_file=None,
        cert_chain_file=None,
        tokenname=None,
        token_library_path=None,
        token_password=None,
        load_external_cert_fn=None,
    ):
        self.ldap = ldap
        self.config = config
        self.pki_config = pki_config
        self._nssdb = nssdb
        self.subject_base = subject_base
        self.ca_subject = ca_subject
        self.realm = realm
        self.fqdn = fqdn
        self.basedn = basedn
        self.random_serial_numbers = random_serial_numbers
        self.ca_signing_algorithm = ca_signing_algorithm
        self.external_ca_step = external_ca_step
        self.external_ca_type = external_ca_type
        self.external_ca_profile = external_ca_profile
        self.csr_file = csr_file
        self.cert_file = cert_file
        self.cert_chain_file = cert_chain_file
        self.tokenname = tokenname
        self.token_library_path = token_library_path
        self.token_password = token_password
        self._load_external_cert = load_external_cert_fn

        # Paths (from platform constants)
        self.ca_cert_path = Path(paths.IPA_CA_CRT)
        self.ca_key_path = Path(paths.IPATHINCA_SIGNING_KEY)
        self.ipaca_certs_dir = Path(paths.IPATHINCA_CERTS_DIR)
        self.ca_cert_working = self.ipaca_certs_dir / "ca.crt"

        # These are set during create_instance()
        self.ca_signing_cert = None
        self.ca_signing_key = None

    @property
    def nssdb_dir(self):
        return self._nssdb.nssdb_dir

    @property
    def nssdb_password(self):
        return self._nssdb.nssdb_password

    def _configure_ca_certs(self):
        """Configure CA certificates and keys matching the manual setup."""
        logger.debug("Configuring CA certificates and keys")

        if self.ca_signing_cert and self.ca_signing_key:
            # Use existing CA certificate and key (e.g., during replica
            # install)
            logger.debug("Using existing CA certificate and key")

            # Copy CA certificate to working directory
            shutil.copy2(self.ca_signing_cert, self.ca_cert_working)
            self.ca_cert_working.chmod(0o644)
            shutil.chown(self.ca_cert_working, user="ipaca", group="ipaca")

            # Copy CA key to private directory
            shutil.copy2(self.ca_signing_key, self.ca_key_path)
            self.ca_key_path.chmod(0o640)
            shutil.chown(self.ca_key_path, user="ipaca", group="ipaca")

            # Copy CA certificate to standard IPA location
            shutil.copy2(self.ca_cert_working, self.ca_cert_path)
            self.ca_cert_path.chmod(0o644)

            logger.debug("CA certificates and keys configured successfully")

        elif self.ca_cert_working.exists() and self.ca_key_path.exists():
            # CA certificate and key already exist from manual setup
            logger.debug(
                "CA certificate and key already exist in ipathinca directories"
            )

            # Make sure they are also in standard IPA location
            if not self.ca_cert_path.exists():
                shutil.copy2(self.ca_cert_working, self.ca_cert_path)
                self.ca_cert_path.chmod(0o644)
                logger.debug("Copied CA certificate to /etc/ipa/ca.crt")

        else:
            # During fresh installation, we need to generate the CA certificate
            # Check for external CA mode
            if self.external_ca_step == 1:
                # External CA Step 1: Generate CSR and exit
                logger.debug("External CA Step 1: Generating CSR")
                self._generate_external_ca_csr()
                # Never returns - exits after CSR generation
            elif self.external_ca_step == 2:
                # External CA Step 2: Install signed certificate
                logger.debug(
                    "External CA Step 2: Installing signed certificate"
                )
                self._install_external_ca_cert()
                # Continue with normal installation after this
            else:
                # Normal self-signed CA installation
                logger.debug(
                    "Generating new self-signed CA certificate and key"
                )
                self._generate_ca_certificate()

        logger.debug("CA certificate configuration step completed")

    def _get_signing_hash_algorithm(self):
        """Map CA signing algorithm to cryptography hash function.

        Uses ipaserver.install.ca.CASigningAlgorithm enum values.
        Default from ipaca_customize.ini: SHA256withRSA

        Returns:
            cryptography.hazmat.primitives.hashes hash algorithm instance

        Raises:
            ValueError: If algorithm is unsupported
        """
        # Map CASigningAlgorithm enum to hash function
        # Default: SHA256withRSA (from ipaca_customize.ini)
        if self.ca_signing_algorithm is None:
            # Default from ipaca_customize.ini
            return hashes.SHA256()

        # Get the algorithm string value from enum
        if hasattr(self.ca_signing_algorithm, "value"):
            alg_str = self.ca_signing_algorithm.value
        else:
            alg_str = str(self.ca_signing_algorithm)

        algorithm_map = {
            "SHA1withRSA": hashes.SHA1(),
            "SHA256withRSA": hashes.SHA256(),
            "SHA384withRSA": hashes.SHA384(),
            "SHA512withRSA": hashes.SHA512(),
        }

        hash_alg = algorithm_map.get(alg_str)
        if hash_alg is None:
            raise ValueError(
                f"Unsupported CA signing algorithm: {alg_str}. "
                f"Supported algorithms: {', '.join(algorithm_map.keys())}"
            )

        logger.info(f"Using CA signing algorithm: {alg_str}")
        return hash_alg

    def _generate_external_ca_csr(self):
        """Generate CA signing CSR for external CA
        (Step 1 - Dogtag-compatible).

        The NSSDB at /etc/pki/pki-tomcat/alias/ persists for Step 2.
        """
        logger.info("=== External CA Step 1: Generating CA signing CSR ===")

        from ipalib import x509 as ipalib_x509

        logger.info(f"CA subject DN: {self.ca_subject}")

        # Initialize NSSDB
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        ca_nickname = "caSigningCert cert-pki-ca"

        # Get CA signing key size from config
        ca_key_size, _ = get_cert_params_from_config(
            self.pki_config, "ca_signing"
        )

        # Generate key pair in NSSDB
        logger.info(
            f"Generating {ca_key_size}-bit RSA key in NSSDB: {ca_nickname}"
        )
        private_key = nssdb.generate_key_pair(
            ca_nickname, key_size=ca_key_size
        )

        # Build CSR
        subject_dn_x509 = ipa_dn_to_x509_name(str(self.ca_subject))
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject_dn_x509)

        # Add MS Certificate Template extension if needed
        if self.external_ca_type == ipalib_x509.ExternalCAType.MS_CS.value:
            logger.info("Adding Microsoft Certificate Template extension")
            template = self.external_ca_profile or ipalib_x509.MSCSTemplateV1(
                "SubCA"
            )
            ext_data = template.get_ext_data()
            csr_builder = csr_builder.add_extension(
                x509.UnrecognizedExtension(
                    oid=x509.ObjectIdentifier(template.ext_oid), value=ext_data
                ),
                critical=False,
            )

        # Get signing algorithm for CSR (use CA signing algorithm)
        _, signing_alg = get_cert_params_from_config(
            self.pki_config, "ca_signing"
        )
        hash_alg = convert_signing_algorithm(signing_alg)

        # Sign CSR with configured algorithm
        logger.info(f"Signing CSR with {signing_alg}")
        csr = csr_builder.sign(private_key, hash_alg)

        # Save CSR to file
        logger.info(f"Saving CSR to {self.csr_file}")
        fd = os.open(
            self.csr_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        with os.fdopen(fd, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        # Save state for Step 2
        state_file = "/var/lib/ipa/ipathinca_external_ca.state"
        state = {
            "step": 1,
            "csr_path": self.csr_file,
            "ca_subject": str(self.ca_subject),
            "subject_base": str(self.subject_base),
            "ca_nickname": ca_nickname,
        }
        os.makedirs("/var/lib/ipa", exist_ok=True)
        fd = os.open(state_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2)

        # Print instructions (Dogtag-style)
        print(
            "The next step is to get %s signed by your CA and re-run %s as:"
            % (self.csr_file, sys.argv[0])
        )
        print(
            "%s --external-cert-file=/path/to/signed_certificate "
            "--external-cert-file=/path/to/external_ca_certificate"
            % sys.argv[0]
        )

        logger.info("External CA Step 1 complete - exiting")
        sys.exit(0)

    def _install_external_ca_cert(self):
        """Install externally-signed CA certificate (Step 2).

        Imports signed cert to NSSDB where the key exists from Step 1.
        """
        logger.info(
            "=== External CA Step 2: Installing signed certificate ==="
        )

        # Load state from Step 1
        state_file = "/var/lib/ipa/ipathinca_external_ca.state"
        if not os.path.exists(state_file):
            raise RuntimeError(
                "External CA state file not found. "
                "Run Step 1 first (without --external-cert-file)"
            )

        try:
            with open(state_file) as f:
                state = json.load(f)
        except (json.JSONDecodeError, KeyError) as e:
            raise RuntimeError(
                f"External CA state file is corrupted: {state_file}: {e}. "
                "Remove it and re-run Step 1."
            )

        logger.info(f"CA Subject DN: {state['ca_subject']}")
        ca_nickname = state["ca_nickname"]

        # Verify NSSDB key exists (check if cert exists - key must exist if
        # cert does)
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        if not nssdb.cert_exists(ca_nickname):
            raise RuntimeError(
                f"Certificate/key not found in NSSDB: {ca_nickname}\n"
                f"NSSDB may have been recreated. Start over with Step 1."
            )

        # Load and validate external certificate
        logger.info("Loading and validating external certificate")
        external_cert_file, external_ca_file = self._load_external_cert(
            [self.cert_file, self.cert_chain_file], state["ca_subject"]
        )

        # Read signed CA certificate
        try:
            with open(external_cert_file.name, "rb") as f:
                ca_cert_data = f.read()
                ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
        except FileNotFoundError:
            raise RuntimeError(
                f"Signed certificate file not found: "
                f"{external_cert_file.name}"
            )
        except ValueError as e:
            raise RuntimeError(
                f"Invalid certificate format in {external_cert_file.name}: {e}"
            )

        # Read CA chain
        try:
            with open(external_ca_file.name, "rb") as f:
                ca_chain_pem = f.read()
        except FileNotFoundError:
            raise RuntimeError(
                f"CA chain file not found: {external_ca_file.name}"
            )

        # Verify subject matches
        cert_subject_str = get_subject_dn_str(ca_cert)
        if cert_subject_str != state["ca_subject"]:
            raise ValueError(
                f"Certificate subject '{cert_subject_str}' != "
                f"CSR subject '{state['ca_subject']}'"
            )

        # Import certificate to NSSDB (key already exists from Step 1)
        logger.info(f"Importing signed certificate to NSSDB: {ca_nickname}")
        nssdb.import_certificate(
            nickname=ca_nickname, certificate=ca_cert, trust_flags="CTu,Cu,Cu"
        )

        # Export cert and key to PEM for IPAThinCA runtime
        logger.info(f"Exporting CA certificate to {self.ca_cert_path}")
        with open(self.ca_cert_path, "wb") as f:
            f.write(ca_cert_data)
        self.ca_cert_path.chmod(0o644)

        logger.info(f"Exporting CA private key to {self.ca_key_path}")
        private_key = nssdb.extract_private_key(ca_nickname)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.ca_key_path, "wb") as f:
            f.write(key_pem)
        self.ca_key_path.chmod(0o600)
        shutil.chown(self.ca_key_path, user="ipaca", group="ipaca")

        # Store full chain
        ca_chain_path = Path(paths.IPA_CA_CRT)
        with open(ca_chain_path, "wb") as f:
            f.write(ca_cert_data)
            f.write(b"\n")
            f.write(ca_chain_pem)
        ca_chain_path.chmod(0o644)
        shutil.chown(ca_chain_path, user="root", group="root")

        # Clean up state file
        try:
            os.unlink(state_file)
        except Exception as e:
            logger.error(f"Failed to remove state file: {e}")

        logger.info(
            "External CA certificate installed - continuing installation"
        )

    def _generate_ca_certificate(self):
        """Generate CA certificate and private key for fresh installation.

        Dogtag-compatible approach: Generate key in NSSDB, extract for signing,
        import certificate back to NSSDB. No PEM key files on disk.
        """
        logger.debug(
            "Generating CA certificate and private key in NSSDB "
            "(Dogtag-compatible)"
        )

        # Use configured CA subject
        subject_dn = self.ca_subject
        logger.debug(f"CA subject DN: {subject_dn}")

        # Certificate nickname in NSSDB/HSM
        ca_nickname = "caSigningCert cert-pki-ca"

        # Get CA signing key size from config
        ca_key_size, ca_signing_alg = get_cert_params_from_config(
            self.pki_config, "ca_signing"
        )
        logger.info(
            f"CA signing certificate parameters: key_size={ca_key_size}, "
            f"signing_alg={ca_signing_alg}"
        )

        # Check if HSM is enabled
        use_hsm = self.tokenname and self.tokenname != "internal"

        if use_hsm:
            # HSM path - generate key in HSM
            logger.info(
                f"Generating CA key pair in HSM token: {self.tokenname}"
            )

            hsm_config = HSMConfig(
                {
                    "pkcs11_library": self.token_library_path,
                    "slot_label": self.tokenname,
                    "token_pin": self.token_password,
                }
            )

            hsm = HSMKeyBackend(hsm_config)

            # Generate RSA key pair in HSM with configured key size
            key_label = "ipa-ca-signing"
            logger.debug(
                f"Generating {ca_key_size}-bit RSA key in HSM with label: "
                f"{key_label}"
            )
            public_key_obj, private_key_obj = hsm.generate_key_pair(
                key_label, key_size=ca_key_size, key_type="RSA"
            )

            # Get public key for certificate building
            private_key = hsm.get_private_key_proxy(key_label)
            logger.debug("HSM key pair generated successfully")
        else:
            # NSSDB path - generate key in NSSDB (default)
            logger.debug("Generating CA key pair in NSSDB (default)")
            nssdb = NSSDatabase(
                nssdb_dir=self.nssdb_dir,
                nssdb_password=self.nssdb_password,
            )

            # Generate private key (in memory, will be imported to NSSDB)
            logger.debug(
                f"Generating {ca_key_size}-bit RSA key pair for NSSDB: "
                f"{ca_nickname}"
            )
            private_key = nssdb.generate_key_pair(
                ca_nickname, key_size=ca_key_size
            )

        # Build certificate subject using shared utility
        # Convert IPA DN to x509.Name with proper RDN wrapping and ordering
        cert_subject = ipa_dn_to_x509_name(str(subject_dn))

        # Set validity period (10 years, matching OpenSSL version)
        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_before = now
        not_valid_after = now + datetime.timedelta(days=3650)

        # Generate serial number for CA certificate
        # Use serial 1 when random serial numbers are disabled (matching
        # Dogtag)
        # Use random serial when enabled
        if self.random_serial_numbers:
            # Read serial_number_bits from config (default: 128, matching
            # Dogtag RSNv3)
            # Config is not yet loaded at this point, use default
            serial_number_bits = 128

            # Generate random number with MSB set to ensure consistent length
            # E.g., 128 bits = 32 hex digits, 160 bits = 40 hex digits
            serial_number = secrets.randbits(serial_number_bits) | (
                1 << (serial_number_bits - 1)
            )
            logger.debug(
                f"Using random serial number ({serial_number_bits} bits): "
                f"{serial_number}"
            )
        else:
            serial_number = 1
            logger.debug("Using serial number 1 for CA certificate")

        # Build certificate
        logger.debug("Building self-signed CA certificate")
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(cert_subject)
        cert_builder = cert_builder.issuer_name(cert_subject)  # Self-signed
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(serial_number)
        cert_builder = cert_builder.not_valid_before(not_valid_before)
        cert_builder = cert_builder.not_valid_after(not_valid_after)

        # Add CA extensions
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Add Subject Key Identifier
        ski = x509.SubjectKeyIdentifier.from_public_key(
            private_key.public_key()
        )
        cert_builder = cert_builder.add_extension(ski, critical=False)

        # Add Authority Key Identifier (same as SKI for self-signed)
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            private_key.public_key()
        )
        cert_builder = cert_builder.add_extension(aki, critical=False)

        # Sign the certificate with configured algorithm
        # (default: SHA256withRSA from ipaca_customize.ini)
        hash_alg = self._get_signing_hash_algorithm()
        logger.debug(f"Signing CA certificate with {hash_alg.name}")
        certificate = cert_builder.sign(private_key, hash_alg)

        if use_hsm:
            # HSM path - store HSM configuration and import cert to NSSDB
            # Key stays in HSM, only certificate imported to NSSDB for tracking
            logger.debug(
                f"Importing CA certificate to NSSDB (key in HSM): "
                f"{ca_nickname}"
            )
            # Initialize NSSDB for certificate import
            nssdb = NSSDatabase(
                nssdb_dir=self.nssdb_dir,
                nssdb_password=self.nssdb_password,
            )
            nssdb.import_certificate(
                nickname=ca_nickname,
                certificate=certificate,
                trust_flags="CTu,Cu,Cu",  # CA trust flags
            )
            logger.debug(
                "CA certificate imported to NSSDB, private key in HSM"
            )

            # Store HSM configuration in LDAP for replica discovery
            self._store_hsm_configuration()
        else:
            # NSSDB path - import key and certificate to NSSDB
            logger.debug(
                f"Importing CA key and certificate to NSSDB: {ca_nickname}"
            )
            nssdb.import_key_and_cert(
                ca_nickname,
                private_key,
                certificate,
                trust_flags="CTu,Cu,Cu",  # CA trust flags
            )
            logger.debug(
                "CA private key generated in NSSDB (no PEM file created)"
            )

        # Save certificate to file (for compatibility with IPA tools)
        logger.debug(f"Writing CA certificate to {self.ca_cert_working}")
        with open(self.ca_cert_working, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        # Set ownership and permissions on certificate
        self.ca_cert_working.chmod(0o644)
        shutil.chown(self.ca_cert_working, user="ipaca", group="ipaca")
        logger.debug(f"Set permissions on {self.ca_cert_working}")

        # Copy CA certificate to standard IPA location
        shutil.copy2(self.ca_cert_working, self.ca_cert_path)
        self.ca_cert_path.chmod(0o644)
        logger.debug(f"Installed CA certificate to {self.ca_cert_path}")

        # Export CA certificate to NSSDB alias directory (Dogtag compatibility)
        # Dogtag exports ca.crt to /etc/pki/pki-tomcat/alias/ca.crt for
        # convenience
        ca_crt_alias = self.nssdb_dir / "ca.crt"
        logger.debug(
            f"Exporting CA certificate to {ca_crt_alias}"
            " (Dogtag compatibility)"
        )
        shutil.copy2(self.ca_cert_working, ca_crt_alias)
        ca_crt_alias.chmod(0o600)  # Dogtag uses -rw------- for ca.crt
        shutil.chown(ca_crt_alias, user="ipaca", group="ipaca")

        logger.debug(
            "CA certificate and private key generated successfully with "
            f"serial {serial_number}"
        )

    def _install_ca_trust(self):
        """Install CA certificate to system trust store."""
        logger.debug("Installing CA certificate to system trust store")

        try:
            # Use 'trust anchor --store' to properly add CA as a trust anchor
            # This is more reliable than copying to anchors directory
            logger.debug("Adding CA certificate as trust anchor")
            ipautil.run(["trust", "anchor", "--store", str(self.ca_cert_path)])

            logger.debug(
                "CA certificate installed to system trust successfully"
            )
        except Exception as e:
            logger.warning(f"Failed to install CA to system trust: {e}")
            # Don't fail the installation if this step fails

    def _store_ca_cert_ldap(self):
        """Store CA certificate in LDAP with proper nickname."""
        logger.debug("Storing CA certificate in LDAP")

        if not self.ldap.isconnected():
            self.ldap.connect()

        ldap = self.ldap

        # Read the CA certificate
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_pem = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

        # Get the proper nickname for the CA certificate
        ca_nickname = get_ca_nickname(self.realm)

        # DN for the CA certificate in LDAP
        ca_dn = DN(("cn", "CAcert"), ("cn", "ipa"), ("cn", "etc"), self.basedn)

        # Ensure parent container exists
        ipa_etc_dn = DN(("cn", "ipa"), ("cn", "etc"), self.basedn)
        try:
            ldap.get_entry(ipa_etc_dn)
        except errors.NotFound:
            logger.debug(f"Creating parent container {ipa_etc_dn}")
            parent_entry = ldap.make_entry(
                ipa_etc_dn, objectClass=["nsContainer", "top"], cn=["ipa"]
            )
            ldap.add_entry(parent_entry)

        try:
            # Check if entry already exists
            entry = ldap.get_entry(ca_dn)
            logger.debug(f"CA certificate entry already exists at {ca_dn}")

            # Update it with our certificate (but not cn, which is the RDN)
            cert_der = ca_cert.public_bytes(serialization.Encoding.DER)

            entry["cACertificate"] = [cert_der]
            # Don't modify cn - it's the RDN and cannot be changed
            ldap.update_entry(entry)
            logger.debug("Updated CA certificate in LDAP")

        except errors.NotFound:
            # Create new entry
            logger.debug(
                "Creating CA certificate entry in LDAP with "
                f"nickname '{ca_nickname}'"
            )

            cert_der = ca_cert.public_bytes(serialization.Encoding.DER)

            entry = ldap.make_entry(
                ca_dn,
                objectClass=["nsContainer", "pkiCA", "top"],
                cn=[ca_nickname],
                cACertificate=[cert_der],
            )
            ldap.add_entry(entry)
            logger.debug("CA certificate stored in LDAP successfully")

    def _store_hsm_configuration(self):
        """Store HSM configuration in LDAP.

        Stores token name and library path (not password) for replica
        discovery.  Format matches Dogtag: "token_name;library_path"
        """
        if not self.tokenname or self.tokenname == "internal":
            logger.debug("No HSM configuration to store (using NSSDB)")
            return

        logger.debug(f"Storing HSM configuration in LDAP: {self.tokenname}")

        if not self.ldap.isconnected():
            self.ldap.connect()

        ldap = self.ldap

        # IPA CA entry DN
        ipa_ca_dn = DN(
            ("cn", IPA_CA_CN), ("cn", "cas"), ("cn", "ca"), self.basedn
        )

        try:
            # Get existing entry
            entry = ldap.get_entry(ipa_ca_dn)

            # Format: "token_name;library_path" (matches Dogtag)
            hsm_config_value = f"{self.tokenname};{self.token_library_path}"
            entry["ipaCaHSMConfiguration"] = [hsm_config_value]

            ldap.update_entry(entry)
            logger.info(f"Stored HSM configuration in LDAP: {self.tokenname}")

        except errors.NotFound:
            logger.warning(
                "IPA CA entry not found yet - HSM configuration will be "
                "added when CA entry is created"
            )

    def _create_ipa_ca_entry(self):
        """Create IPA CA entry in cn=cas,cn=ca,{basedn} with certificate and
        key.
        """
        logger.debug("Creating IPA CA entry in LDAP")

        if not self.ldap.isconnected():
            self.ldap.connect()

        ldap = self.ldap

        # DN for the IPA CA entry
        ipa_ca_dn = DN(("cn", "ipa"), ("cn", "cas"), ("cn", "ca"), self.basedn)

        try:
            # Check if entry already exists
            ldap.get_entry(ipa_ca_dn)
            logger.debug("IPA CA entry already exists")
            return
        except errors.NotFound:
            pass

        # Read the CA certificate
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_pem = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

        # Convert subject to proper DN string format (like Dogtag does)
        # Extract CA subject DN using shared utility
        ca_subject_str = get_subject_dn_str(ca_cert)

        logger.debug(f"CA Subject DN: {ca_subject_str}")

        # Generate a UUID for the CA Authority ID (like Dogtag does)
        ca_authority_id = str(uuid.uuid4())

        # Create the IPA CA entry with certificate and private key
        # This allows replicas to fetch the CA cert/key from LDAP instead of
        # Custodia
        logger.debug(
            f"Creating IPA CA entry at {ipa_ca_dn} with authority "
            f"ID {ca_authority_id}"
        )

        # Determine random serial number version (RSNv3 = 3, disabled = 0)
        rsn_version = "3" if self.random_serial_numbers else "0"

        # Build entry attributes
        entry_attrs = {
            "objectClass": ["top", "ipaca"],
            "cn": [IPA_CA_CN],
            "ipaCaId": [ca_authority_id],
            "ipaCaSubjectDN": [ca_subject_str],
            "ipaCaIssuerDN": [ca_subject_str],  # Self-signed
            # Note: ipaCertificateSubjectBase is stored globally in
            # cn=ipaConfig,cn=etc,{basedn}, not per-CA
            "ipaCaRandomSerialNumberVersion": [rsn_version],
            "description": ["IPA CA"],
        }

        # Add HSM configuration if enabled
        if self.tokenname and self.tokenname != "internal":
            # Format: "token_name;library_path" (matches Dogtag)
            hsm_config_value = f"{self.tokenname};{self.token_library_path}"
            entry_attrs["ipaCaHSMConfiguration"] = [hsm_config_value]
            logger.debug(
                f"Adding HSM configuration to CA entry: {hsm_config_value}"
            )

        entry = ldap.make_entry(ipa_ca_dn, **entry_attrs)

        ldap.add_entry(entry)
        logger.debug(
            "IPA CA entry created successfully with certificate and private "
            "key"
        )

    def _init_cert_storage_schema(self):
        """Initialize certificate storage LDAP schema."""
        logger.debug("Initializing certificate storage LDAP schema")

        try:
            # Get storage backend (Dogtag backend only)
            backend = get_storage_backend()

            # Initialize LDAP schema (creates Dogtag LDAP containers)
            backend.initialize_schema()

            logger.debug("Certificate storage schema initialized successfully")
        except Exception as e:
            logger.warning(
                f"Failed to initialize certificate storage schema: {e}"
            )
            # Don't fail installation if schema already exists
            logger.debug("Schema may already exist, continuing...")

    def _store_ca_cert_in_certdb(self):
        """Store CA certificate in certificate database using Dogtag storage
        backend.
        """
        logger.debug("Storing CA certificate in certificate database")

        # Read the CA certificate
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_pem = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

        # Use the CA's actual serial number from the certificate
        serial_number = ca_cert.serial_number
        logger.debug(f"CA certificate serial number: {serial_number}")

        # Use storage backend to store CA certificate in Dogtag schema
        backend = get_storage_backend()

        # Check if certificate already exists
        try:
            existing_cert = backend.get_certificate(serial_number)
            if existing_cert:
                logger.debug(
                    f"CA certificate (serial {serial_number}) already in "
                    "database"
                )
                return
        except errors.NotFound:
            pass  # Certificate doesn't exist, continue to store it

        # Create a dummy request for the CA certificate
        dummy_request = CertificateRequest(csr=None, profile="caCACert")
        dummy_request.request_id = "ca-self-signed"

        # Create CertificateRecord for the CA certificate
        cert_record = CertificateRecord(
            ca_cert, dummy_request, principal="ca_installation"
        )
        cert_record.serial_number = serial_number

        # Store certificate using Dogtag backend
        backend.store_certificate(cert_record, allow_update=False)

        # Update serial number counter to prevent reuse when not using random
        # serials
        # This ensures the next certificate doesn't try to reuse serial 1
        if not self.random_serial_numbers:
            config_dn = DN(("cn", "CAConfig"), ("ou", "ca"), ("o", "ipaca"))
            try:
                if not self.ldap.isconnected():
                    self.ldap.connect()
                config_entry = self.ldap.get_entry(config_dn)
                config_entry["serialno"] = [str(serial_number)]
                config_entry["lastSerialNo"] = [str(serial_number)]
                self.ldap.update_entry(config_entry)
                logger.info(
                    f"Updated serial number counter to {serial_number} after "
                    "storing CA certificate"
                )
            except errors.NotFound:
                logger.error(
                    f"CA config entry {config_dn} not found, serial counter "
                    "not updated - subsystem cert generation will fail!"
                )
                raise RuntimeError(
                    f"CA config entry not found at {config_dn}. Schema "
                    "initialization may have failed."
                )
            except Exception as e:
                logger.error(
                    f"Failed to update serial counter: {e}", exc_info=True
                )
                raise

        logger.debug(
            "CA certificate stored in certificate database with serial "
            f"{serial_number}"
        )

    def _generate_subsystem_certs(self):
        """Generate PKI subsystem certificates through ipathinca CA.

        Dogtag-compatible approach: Generate keys in NSSDB, extract for CSR,
        import certificates back to NSSDB. No PEM key files on disk.
        """
        logger.debug(
            "Generating PKI subsystem certificates through ipathinca CA "
            "(Dogtag-compatible NSSDB storage)"
        )

        # Import NSS utilities

        # Load CA certificate to get organization
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Extract organization from CA subject for subsystem certificates
        org = None
        for attr in ca_cert.subject:
            if attr.oid == NameOID.ORGANIZATION_NAME:
                org = attr.value
                break

        if not org:
            org = self.realm

        # Initialize ipathinca CA instance for certificate issuance
        ca = PythonCA(
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path),
            ca_id="ipa",
            random_serial_numbers=self.random_serial_numbers,
            config=self.config,
        )

        # Initialize NSSDB access
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        # Define subsystem certificates to generate
        # Format: (common_name, profile, file_prefix)
        subsystem_certs = [
            ("CA Subsystem", dogtag.SUBSYSTEM_PROFILE, "ca_subsystem"),
            ("CA Audit", dogtag.AUDIT_PROFILE, "ca_audit"),
            ("OCSP Subsystem", dogtag.OCSP_PROFILE, "ocsp_subsystem"),
            ("ipa-ca-agent", dogtag.CASERVER_PROFILE, "ipa_ca_agent"),
        ]

        # Map profile to NSSDB nickname (Dogtag-compatible naming)
        nickname_map = {
            dogtag.SUBSYSTEM_PROFILE: "subsystemCert cert-pki-ca",
            dogtag.AUDIT_PROFILE: "auditSigningCert cert-pki-ca",
            dogtag.OCSP_PROFILE: "ocspSigningCert cert-pki-ca",
            dogtag.CASERVER_PROFILE: "ipa-ca-agent cert-pki-ca",
        }

        # Map profile to cert_type for config lookup
        cert_type_map = {
            dogtag.SUBSYSTEM_PROFILE: "subsystem",
            dogtag.AUDIT_PROFILE: "audit_signing",
            dogtag.OCSP_PROFILE: "ocsp_signing",
            # Use subsystem settings for CA agent
            dogtag.CASERVER_PROFILE: "subsystem",
        }

        for cn, profile, file_prefix in subsystem_certs:
            cert_path = self.ipaca_certs_dir / f"{file_prefix}.crt"
            nssdb_nickname = nickname_map.get(profile, f"{cn} cert-pki-ca")

            # Skip if certificate already exists in NSSDB
            if nssdb.cert_exists(nssdb_nickname):
                logger.debug(f"{cn} certificate already exists in NSSDB")
                continue

            # Get certificate parameters from config
            cert_type = cert_type_map.get(profile, "subsystem")
            key_size, signing_alg = get_cert_params_from_config(
                self.pki_config, cert_type
            )
            hash_alg = convert_signing_algorithm(signing_alg)

            logger.debug(
                f"Generating {cn} certificate with profile {profile} "
                f"(key_size={key_size}, signing_alg={signing_alg})"
            )

            # Generate private key in memory (will be imported to NSSDB with
            # cert)
            logger.debug(f"Generating key pair for NSSDB: {nssdb_nickname}")
            private_key = nssdb.generate_key_pair(
                nssdb_nickname, key_size=key_size
            )

            # Build subject using shared utility
            # Attributes in natural/display order (most-specific-first)
            subject = build_x509_name([("CN", cn), ("O", org)], reverse=True)

            # Create CSR
            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(subject)

            # Sign CSR with private key using configured hash algorithm
            csr = csr_builder.sign(private_key, hash_alg)

            # Convert CSR to PEM
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            )

            # Submit certificate request through ipathinca CA
            request_id = ca.submit_certificate_request(csr_pem, profile)
            logger.debug(
                f"Submitted certificate request {request_id} for " f"{cn}"
            )

            # Sign the request to issue certificate
            serial_number = ca.sign_certificate_request(request_id)
            logger.debug(
                f"Issued certificate with serial {serial_number} for {cn}"
            )

            # Retrieve the issued certificate
            cert_record = ca.get_certificate(serial_number)
            if not cert_record:
                raise RuntimeError(
                    f"Failed to retrieve issued certificate for {cn}"
                )

            # Import key and certificate to NSSDB
            trust_flags_map = {
                dogtag.SUBSYSTEM_PROFILE: "u,u,u",
                dogtag.AUDIT_PROFILE: "u,u,Pu",
                dogtag.OCSP_PROFILE: "u,u,u",
                dogtag.CASERVER_PROFILE: "u,u,u",
            }
            trust_flags = trust_flags_map.get(profile, "u,u,u")

            logger.debug(
                f"Importing {cn} key and certificate to NSSDB: "
                f"{nssdb_nickname}"
            )
            nssdb.import_key_and_cert(
                nssdb_nickname,
                private_key,
                cert_record.certificate,
                trust_flags=trust_flags,
            )

            # Save certificate to file (for compatibility/reference)
            # Note: Private key is NOT saved to disk - it stays in NSSDB only
            with open(cert_path, "wb") as f:
                f.write(
                    cert_record.certificate.public_bytes(
                        serialization.Encoding.PEM
                    )
                )
            cert_path.chmod(0o644)
            shutil.chown(cert_path, user="ipaca", group="ipaca")

            logger.debug(
                f"{cn} certificate issued and saved (serial: {serial_number})"
            )

            # For subsystem cert, create pkidbuser LDAP entry (healthcheck
            # compatibility)
            if profile == dogtag.SUBSYSTEM_PROFILE:
                self._create_pkidbuser_entry(cert_record.certificate)

        logger.debug(
            "All PKI subsystem certificates generated through ipathinca CA"
        )

    def _create_pkidbuser_entry(self, subsystem_cert):
        """Create uid=pkidbuser,ou=people,o=ipaca entry.

        This entry is required for healthcheck compatibility. Dogtag creates
        this user to hold the subsystem certificate used for LDAP
        authentication.

        Args:
            subsystem_cert: The CA subsystem certificate
                            (cryptography.x509.Certificate)
        """
        logger.debug(
            "Creating pkidbuser LDAP entry for healthcheck compatibility"
        )

        if not self.ldap.isconnected():
            self.ldap.connect()

        # DN for pkidbuser entry
        pkidbuser_dn = DN("uid=pkidbuser", "ou=people", "o=ipaca")

        # Check if entry already exists
        try:
            self.ldap.get_entry(pkidbuser_dn)
            logger.debug("pkidbuser entry already exists")
            return
        except errors.NotFound:
            pass

        # Encode certificate to DER format for LDAP storage
        cert_der = subsystem_cert.public_bytes(serialization.Encoding.DER)

        # Create pkidbuser entry
        # Following Dogtag's schema for this user
        entry = self.ldap.make_entry(
            pkidbuser_dn,
            objectclass=[
                "top",
                "person",
                "organizationalPerson",
                "inetOrgPerson",
            ],
            uid=["pkidbuser"],
            sn=["pkidbuser"],
            cn=["pkidbuser"],
            userCertificate=[cert_der],
            description=[
                "CA database user - created by IPAThinCA for compatibility"
            ],
        )

        try:
            self.ldap.add_entry(entry)
            logger.info(
                "Created pkidbuser LDAP entry with subsystem certificate for "
                "healthcheck"
            )
        except Exception as e:
            logger.warning(f"Failed to create pkidbuser entry: {e}")
            # Non-fatal - healthcheck will fail but CA continues to work

    def _generate_server_cert(self):
        """Generate server SSL certificate through ipathinca CA.

        Note: Server certificate requires both NSSDB storage AND PEM files
        because gunicorn needs the private key to serve HTTPS. This is similar
        to the RA agent exception.
        """
        logger.debug(
            "Generating server SSL certificate through ipathinca CA "
            "(NSSDB + PEM file for gunicorn)"
        )

        server_cert_path = self.ipaca_certs_dir / "server.crt"
        server_key_path = Path(paths.IPATHINCA_DIR) / "private" / "server.key"
        server_nickname = "Server-Cert cert-pki-ca"

        # Initialize NSSDB access
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        # Skip if server certificate already exists in NSSDB
        if nssdb.cert_exists(server_nickname):
            logger.debug("Server SSL certificate already exists in NSSDB")
            return

        # Initialize ipathinca CA instance for certificate issuance
        ca = PythonCA(
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path),
            ca_id="ipa",
            random_serial_numbers=self.random_serial_numbers,
            config=self.config,
        )

        # Get certificate parameters from config
        key_size, signing_alg = get_cert_params_from_config(
            self.pki_config, "sslserver"
        )
        hash_alg = convert_signing_algorithm(signing_alg)

        logger.debug(
            f"Generating server certificate (key_size={key_size}, "
            f"signing_alg={signing_alg})"
        )

        # Generate private key in memory (will be imported to NSSDB with cert)
        logger.debug(
            f"Generating server key pair for NSSDB: {server_nickname}"
        )
        private_key = nssdb.generate_key_pair(
            server_nickname, key_size=key_size
        )

        # Build subject for server certificate (CN=<fqdn>)
        subject = build_x509_name([("CN", self.fqdn)], reverse=True)

        # Create CSR with Subject Alternative Name
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject)

        # Add SAN extension to CSR (required for modern browsers)
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.fqdn)]),
            critical=False,
        )

        # Sign CSR with private key using configured hash algorithm
        csr = csr_builder.sign(private_key, hash_alg)

        # Convert CSR to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # Submit certificate request through ipathinca CA
        # Use caIPAserviceCert profile (supports both server and client auth)
        profile = "caIPAserviceCert"
        request_id = ca.submit_certificate_request(csr_pem, profile)
        logger.debug(f"Submitted server certificate request {request_id}")

        # Sign the request to issue certificate
        serial_number = ca.sign_certificate_request(request_id)
        logger.debug(f"Issued server certificate with serial {serial_number}")

        # Retrieve the issued certificate
        cert_record = ca.get_certificate(serial_number)
        if not cert_record:
            raise RuntimeError("Failed to retrieve issued server certificate")

        # Import key and certificate to NSSDB
        logger.debug(
            f"Importing server key and certificate to NSSDB: {server_nickname}"
        )
        nssdb.import_key_and_cert(
            server_nickname,
            private_key,
            cert_record.certificate,
            trust_flags="u,u,u",
        )

        # Load CA certificate for creating chain file
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Save server certificate with CA chain
        logger.debug(f"Writing server certificate to {server_cert_path}")
        with open(server_cert_path, "wb") as f:
            # Write server certificate
            f.write(
                cert_record.certificate.public_bytes(
                    serialization.Encoding.PEM
                )
            )
            # Append CA certificate for complete chain
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        server_cert_path.chmod(0o644)
        shutil.chown(server_cert_path, user="ipaca", group="ipaca")

        # Save server private key (required for gunicorn HTTPS)
        # This is an exception to the NSSDB-only policy, similar to RA agent
        logger.debug(f"Writing server private key to {server_key_path}")
        server_key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(server_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        server_key_path.chmod(0o600)
        shutil.chown(server_key_path, user="ipaca", group="ipaca")

        logger.debug(
            f"Server SSL certificate generated successfully (serial: "
            f"{serial_number})"
        )

    def _generate_ra_cert(self):
        """Generate RA agent certificate through ipathinca CA.

        Uses the same issuance flow as subsystem certificates for consistency
        and automatic LDAP storage.
        """
        logger.debug("Generating RA agent certificate through ipathinca CA")

        ra_cert_path = Path(paths.RA_AGENT_PEM)
        ra_key_path = Path(paths.RA_AGENT_KEY)

        # Skip if RA certificate already exists
        if ra_cert_path.exists() and ra_key_path.exists():
            logger.debug("RA agent certificate already exists")
            return

        # Initialize ipathinca CA instance for certificate issuance
        ca = PythonCA(
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path),
            ca_id="ipa",
            random_serial_numbers=self.random_serial_numbers,
            config=self.config,
        )

        # Get certificate parameters from config (use sslserver settings for
        # RA cert)
        key_size, signing_alg = get_cert_params_from_config(
            self.pki_config, "sslserver"
        )
        hash_alg = convert_signing_algorithm(signing_alg)

        logger.debug(
            f"Generating RA agent certificate (key_size={key_size}, "
            f"signing_alg={signing_alg})"
        )

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size
        )

        # Build subject for RA certificate
        # Simple DN: CN=IPA RA (matches what validator expects)
        ra_dn = DN(("CN", "IPA RA"))
        logger.debug(f"RA agent certificate subject: {ra_dn}")
        subject = ipa_dn_to_x509_name(str(ra_dn))

        # Create CSR
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject)

        # Sign CSR with private key using configured hash algorithm
        csr = csr_builder.sign(private_key, hash_alg)

        # Convert CSR to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # Submit certificate request through ipathinca CA
        # Use caIPAserviceCert profile (same as ipa-ca-agent subsystem cert)
        profile = "caIPAserviceCert"
        request_id = ca.submit_certificate_request(csr_pem, profile)
        logger.debug(f"Submitted RA agent certificate request {request_id}")

        # Sign the request to issue certificate
        serial_number = ca.sign_certificate_request(request_id)
        logger.debug(
            f"Issued RA agent certificate with serial {serial_number}"
        )

        # Retrieve the issued certificate
        cert_record = ca.get_certificate(serial_number)
        if not cert_record:
            raise RuntimeError(
                "Failed to retrieve issued RA agent certificate"
            )

        # Ensure parent directories exist
        ra_cert_path.parent.mkdir(parents=True, exist_ok=True)
        ra_key_path.parent.mkdir(parents=True, exist_ok=True)

        # Save certificate to file
        logger.debug(f"Writing RA agent certificate to {ra_cert_path}")
        with open(ra_cert_path, "wb") as f:
            f.write(
                cert_record.certificate.public_bytes(
                    serialization.Encoding.PEM
                )
            )
        ra_cert_path.chmod(0o440)

        # Save private key to file
        logger.debug(f"Writing RA agent private key to {ra_key_path}")
        with open(ra_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        ra_key_path.chmod(0o440)

        # Set ownership to allow IPA API access
        group = IPAAPI_GROUP
        group.chgrp(ra_cert_path)
        group.chgrp(ra_key_path)

        # Import RA agent certificate to NSSDB for certmonger tracking
        # Note: RA agent cert is not typically in NSSDB in Dogtag, but we
        # import it for consistency and to enable certmonger tracking if
        # needed
        logger.debug("Importing RA agent certificate to NSSDB")
        self._nssdb.import_cert_to_nssdb(
            cert_pem_path=ra_cert_path,
            key_pem_path=ra_key_path,
            nickname="ipaCert",
            trust_flags="u,u,u",
        )

        logger.debug(
            f"RA agent certificate generated successfully (serial: "
            f"{serial_number})"
        )

    def _verify_ra_key_custodia(self):
        """Verify that RA agent key is accessible via Custodia for replica
        installation.

        This ensures that when replicas try to import the RA key via Custodia,
        the key files are properly readable and the Custodia handler can
        export them.
        """
        logger.debug("Verifying RA key accessibility for Custodia")

        ra_cert_path = paths.RA_AGENT_PEM
        ra_key_path = paths.RA_AGENT_KEY

        # Verify files exist and have correct permissions
        if not os.path.exists(ra_cert_path):
            raise RuntimeError(
                f"RA agent certificate not found: {ra_cert_path}"
            )
        if not os.path.exists(ra_key_path):
            raise RuntimeError(f"RA agent key not found: {ra_key_path}")

        # Check file permissions
        cert_stat = os.stat(ra_cert_path)
        key_stat = os.stat(ra_key_path)

        if (cert_stat.st_mode & 0o777) != 0o440:
            logger.warning(
                f"RA cert has unexpected permissions: "
                f"{oct(cert_stat.st_mode & 0o777)}, expected 0o440"
            )

        if (key_stat.st_mode & 0o777) != 0o440:
            logger.warning(
                f"RA key has unexpected permissions: "
                f"{oct(key_stat.st_mode & 0o777)}, expected 0o440"
            )

        # Check if Custodia handler script exists
        handler_script = (
            paths.LIBEXEC_IPA_DIR + "/custodia/ipa-custodia-ra-agent"
        )
        if not os.path.exists(handler_script):
            logger.warning(
                f"Custodia RA agent handler not found at {handler_script}. "
                "Skipping export verification. "
                "This is normal during development, but in production the "
                "handler should be installed. RA key files exist and have "
                "correct permissions."
            )
            logger.info(
                "To enable full Custodia verification, ensure FreeIPA is "
                "fully installed (make install) or the handler script is "
                "available."
            )
            return

        # Test that the Custodia RA agent handler can export the key
        # This simulates what happens when a replica requests the key
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                export_file = os.path.join(tmpdir, "export.json")

                # Run the Custodia RA agent export handler
                # This is the same command Custodia uses when serving the key
                result = subprocess.run(
                    [handler_script, "--export", export_file],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode != 0:
                    logger.error(f"RA key export test failed: {result.stderr}")
                    raise RuntimeError(
                        f"Failed to export RA key via Custodia handler. "
                        f"Replicas will not be able to import the RA key. "
                        f"Error: {result.stderr}"
                    )

                # Verify export file was created and contains data
                if not os.path.exists(export_file):
                    raise RuntimeError(
                        "RA key export completed but no export file was "
                        "created"
                    )

                with open(export_file, "r") as f:
                    export_data = json.load(f)

                    if "export password" not in export_data:
                        raise RuntimeError(
                            "RA key export data missing 'export password' "
                            "field"
                        )
                    if "pkcs12 data" not in export_data:
                        raise RuntimeError(
                            "RA key export data missing 'pkcs12 data' field"
                        )

                logger.debug(
                    "RA key export test successful - replicas will be able to "
                    "import the RA key via Custodia"
                )

                # Log important information for replica setup
                logger.debug(
                    "IMPORTANT: When installing replicas, ensure they are "
                    "configured to fetch the RA key from THIS master server "
                    f"({self.fqdn}). If replica installation fails with "
                    "'404 Not Found' when fetching ra/ipaCert, the replica "
                    "may be trying to fetch from the wrong server. As a "
                    "workaround, "
                    f"manually copy {ra_cert_path} and {ra_key_path} to the "
                    "replica before running ipa-replica-install."
                )

        except subprocess.TimeoutExpired:
            logger.error("RA key export test timed out")
            raise RuntimeError(
                "RA key export test timed out. Check if OpenSSL is available."
            )
        except Exception as e:
            logger.error(f"RA key export verification failed: {e}")
            raise RuntimeError(
                f"RA key is not accessible via Custodia. Replicas will not be "
                f"able to import the RA key. Error: {e}"
            )
