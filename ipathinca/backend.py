# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Python-cryptography CA backend implementation that replaces Dogtag

SECURITY ARCHITECTURE:
======================

This module is part of the ipathinca service and HAS ACCESS TO CA PRIVATE
KEYS.
It should NEVER be imported directly by httpd or any process running as apache
user.

Process Isolation:
------------------
1. httpd (apache user) -> ipaserver/plugins/dogtag.py -> HTTPS REST API
2. ipathinca.service (ipaca) -> rest_api.py -> backend.py (THIS FILE) -> CA
   private keys

The backend is accessed ONLY through the REST API (rest_api.py) which runs in
the ipathinca service (systemd service running as ipaca with access to
private keys).

See SERVICE_ARCHITECTURE.md for complete documentation.
"""

import logging
from datetime import datetime, timedelta, timezone
import uuid
import os
import socket
import base64

from ipalib import errors
from ipapython.dn import DN
from ipaplatform.paths import paths
from ipathinca import x509_utils, set_global_config, load_config
from ipathinca.ca import RevocationReason
from ipathinca.ca_internal import InternalCA
from ipathinca.exceptions import ProfileNotFound
from ipathinca.profiles import ProfileManager, CertificateProfile
from ipathinca.pruning import PruningManager
from ipathinca.x509_utils import (
    get_ca_key_usage_extension,
    get_subject_dn_str,
    get_issuer_dn_str,
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


class PythonCABackend:
    """
    Python-cryptography backend that implements the same interface as Dogtag

    This class provides drop-in replacement functionality for FreeIPA's
    Dogtag integration, using pure Python cryptography libraries.
    """

    def __init__(self, config=None):
        """
        Initialize the Python CA backend

        Args:
            config: RawConfigParser object from ipathinca.conf (optional,
                    will be loaded if not provided)

        Raises:
            FileNotFoundError: If config file doesn't exist and no config
                               provided
            Exception: If config cannot be loaded
        """
        # Load config if not provided
        if config is None:
            config = load_config()

        # Store config for use by all methods
        self.config = config

        # Set global config for all ipathinca components
        set_global_config(config)

        # Validate hostname configuration matches system hostname
        self._validate_hostname_config()

        # Read CA configuration
        # Use "ipa" as the CA ID - the REST API handlers will also check
        # against the actual UUID from LDAP when needed
        ca_id = "ipa"

        # Read random_serial_numbers from config file
        random_serial_numbers = False
        if self.config.has_option("ca", "random_serial_numbers"):
            random_serial_numbers = self.config.getboolean(
                "ca", "random_serial_numbers"
            )
            logger.info(
                f"Random serial numbers from config: {random_serial_numbers}"
            )

        # Initialize CA with configuration
        self.ca = InternalCA(
            ca_cert_path=paths.IPA_CA_CRT,
            ca_key_path=paths.IPATHINCA_SIGNING_KEY,
            ca_id=ca_id,
            random_serial_numbers=random_serial_numbers,
            config=self.config,
        )
        self.profile_manager = ProfileManager()

        # Initialize pruning manager (for certificate/request cleanup)
        self.pruning_manager = PruningManager(self.config, self.ca.storage)

    def _validate_hostname_config(self):
        """
        Validate that configured hostname matches system hostname

        This prevents misconfiguration where the hostname in ipathinca.conf
        doesn't match the actual system hostname, which would cause certificate
        validation failures, Kerberos issues, and replica problems.

        Raises:
            Exception: If hostname is not configured or doesn't match system
                       FQDN
        """
        if not self.config.has_option("global", "host"):
            raise Exception(
                "Hostname not configured in ipathinca.conf [global] section. "
                "Add 'host = <fqdn>' to the configuration file."
            )

        configured_host = self.config.get("global", "host")
        system_fqdn = socket.getfqdn()

        # Compare hostnames (case-insensitive)
        if configured_host.lower() != system_fqdn.lower():
            logger.warning(
                f"Configured hostname '{configured_host}' does not match "
                f"system FQDN '{system_fqdn}'. This may cause certificate "
                "validation issues, Kerberos authentication failures, and "
                "replica communication problems."
            )
            # Log warning but don't fail - admin may have valid reasons
            # (e.g., testing, migration, DNS not yet configured)
            # In production, this should match exactly
        else:
            logger.info(
                f"Hostname validation passed: configured='{configured_host}', "
                f"system='{system_fqdn}'"
            )

    def _get_ca_host(self):
        """Get CA hostname from configuration"""
        # Read from config (required)
        if self.config.has_option("global", "host"):
            try:
                return self.config.get("global", "host")
            except Exception as e:
                logger.debug(f"Failed to read host from config: {e}")

        # Fallback to system hostname if not in config
        hostname = socket.getfqdn()
        logger.warning(
            f"CA host not found in config, using system hostname: {hostname}"
        )
        return hostname

    # Certificate Request Operations (replaces dogtag.py functions)

    def request_certificate(
        self, csr, profile_id="caIPAserviceCert", ca_id="ipa"
    ):
        """
        Submit certificate request - replaces dogtag.request_certificate()

        Args:
            csr: PEM-encoded certificate signing request
            profile_id: Certificate profile to use
            ca_id: CA identifier (for sub-CA support)

        Returns:
            Dict with request_id and status information
        """
        try:
            # Parse CSR from PEM format
            if isinstance(csr, str):
                csr_obj = x509.load_pem_x509_csr(
                    csr.encode("utf-8"), default_backend()
                )
            else:
                csr_obj = csr

            # Validate profile and CSR
            self.profile_manager.validate_profile_for_csr(profile_id, csr_obj)

            # Convert CSR object back to PEM string if needed
            # (IPA framework passes parsed CSR objects, but CA expects PEM
            # string)
            if not isinstance(csr, str):
                csr_pem = csr_obj.public_bytes(
                    serialization.Encoding.PEM
                ).decode("utf-8")
            else:
                csr_pem = csr

            # Submit request with CA ID
            request_id = self.ca.submit_certificate_request(
                csr_pem, profile_id, ca_id=ca_id
            )

            # Automatically sign for now (can add approval workflow later)
            serial_number = self.ca.sign_certificate_request(request_id)

            # Get the issued certificate
            cert_record = self.ca.get_certificate(serial_number)

            return {
                "request_id": request_id,
                # Return serial number in hex format with 0x prefix to match
                # Dogtag
                "serial_number": f"0x{serial_number:x}",
                "status": "complete",
                "certificate": base64.b64encode(
                    cert_record.certificate.public_bytes(
                        encoding=serialization.Encoding.DER
                    )
                ).decode("ascii"),
                "subject": x509_utils.get_subject_dn_str(
                    cert_record.certificate
                ),
                "issuer": x509_utils.get_issuer_dn_str(
                    cert_record.certificate
                ),
            }

        except errors.NotFound:
            # Re-raise NotFound errors (e.g., invalid profile)
            raise
        except ProfileNotFound:
            # Re-raise ProfileNotFound to be handled by REST API decorator
            # The REST API decorator will format it for Dogtag compatibility
            raise
        except errors.CertificateOperationError as e:
            # If CA is not configured yet, raise NotFound error (errno 4001)
            # This matches what IPA framework expects during installation
            if "CA certificate and/or private key not available" in str(e):
                logger.error(
                    "Certificate request failed: CA not configured yet during "
                    "installation"
                )
                raise errors.NotFound(reason="CA is not configured")
            else:
                logger.error(f"Certificate request failed: {e}")
                raise e
        except Exception as e:
            logger.error(f"Certificate request failed: {e}", exc_info=True)
            error_msg = str(e) if str(e) else f"{type(e).__name__}: {repr(e)}"
            raise errors.CertificateOperationError(error=error_msg)

    def check_request_status(self, request_id):
        """
        Check certificate request status

        Replaces dogtag.check_request_status()
        """
        request = self.ca.get_request_status(request_id)
        if not request:
            raise errors.NotFound(reason=f"Request {request_id} not found")

        return {
            "request_id": request.request_id,
            "status": request.status,
            # Return serial number in hex format with 0x prefix to match Dogtag
            "serial_number": (
                f"0x{request.serial_number:x}"
                if request.serial_number
                else None
            ),
        }

    def get_certificate(self, serial_number):
        """
        Retrieve certificate by serial number

        Replaces dogtag.get_certificate()
        """
        cert_record = self.ca.get_certificate(int(serial_number))
        logger.debug(f"CA returned cert_record: {cert_record}")
        logger.debug(f"cert_record type: {type(cert_record)}")

        if not cert_record:
            # Format serial number as hex to match Dogtag behavior
            serial_hex = f"0x{int(serial_number):x}"
            logger.error(
                "Certificate not found, raising NotFound error for "
                f"{serial_hex}"
            )
            raise errors.NotFound(
                reason=f"Certificate ID {serial_hex} not found"
            )

        # Convert subject and issuer DNs to proper format with short names
        # and correct order
        # Extract subject and issuer DN using shared utility
        subject_dn = get_subject_dn_str(cert_record.certificate)
        issuer_dn = get_issuer_dn_str(cert_record.certificate)

        # Convert certificate to PEM format to match Dogtag behavior
        # The REST API should return PEM format (with headers and newlines)
        # The Dogtag RA plugin (ipaserver/plugins/dogtag.py) strips the headers
        # when needed by the IPA framework, and pki_issue_certificate()
        # expects PEM
        #
        # IMPORTANT: Dogtag returns PEM with CRLF (\r\n) line endings, not
        # LF (\n)
        # Python cryptography library uses LF, so we need to convert to CRLF
        cert_pem = (
            cert_record.certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            )
            .decode("ascii")
            .replace("\n", "\r\n")
        )

        result = {
            # Return serial number in hex format with 0x prefix to match Dogtag
            # (Dogtag's CertId.toHexString() returns "0x" + hex_value)
            "serial_number": f"0x{cert_record.serial_number:x}",
            "certificate": cert_pem,
            "subject": subject_dn,
            "issuer": issuer_dn,
            "status": cert_record.status.value,
        }

        # Add revocation details if certificate is revoked
        if cert_record.revoked_at:
            result["revoked_at"] = cert_record.revoked_at.isoformat()
        if cert_record.revocation_reason:
            result["revocation_reason"] = cert_record.revocation_reason.value

        return result

    # Certificate Revocation Operations

    def revoke_certificate(self, serial_number, revocation_reason=0):
        """
        Revoke certificate - replaces dogtag.revoke_certificate()
        """
        try:
            reason_map = {
                0: RevocationReason.UNSPECIFIED,
                1: RevocationReason.KEY_COMPROMISE,
                2: RevocationReason.CA_COMPROMISE,
                3: RevocationReason.AFFILIATION_CHANGED,
                4: RevocationReason.SUPERSEDED,
                5: RevocationReason.CESSATION_OF_OPERATION,
                6: RevocationReason.CERTIFICATE_HOLD,
                8: RevocationReason.REMOVE_FROM_CRL,
                9: RevocationReason.PRIVILEGE_WITHDRAWN,
                10: RevocationReason.AA_COMPROMISE,
            }

            reason = reason_map.get(
                revocation_reason, RevocationReason.UNSPECIFIED
            )
            self.ca.revoke_certificate(int(serial_number), reason)

            return {"status": "SUCCESS"}

        except errors.NotFound:
            # Re-raise NotFound errors
            raise
        except Exception as e:
            logger.error(f"Certificate revocation failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    def take_certificate_off_hold(self, serial_number):
        """
        Remove certificate from hold

        Replaces dogtag.take_certificate_off_hold()
        """
        try:
            self.ca.take_certificate_off_hold(int(serial_number))
            return {"status": "SUCCESS"}

        except errors.NotFound:
            # Re-raise NotFound errors
            raise
        except Exception as e:
            logger.error(f"Take certificate off hold failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    # Certificate Search Operations

    def find_certificates(self, criteria=None):
        """
        Search certificates - replaces dogtag.find_certificates()
        """
        try:
            cert_records = self.ca.find_certificates(criteria or {})

            # Use shared utility for DN formatting

            results = []
            for cert_record in cert_records:
                # Convert subject and issuer DN using shared utility
                subject_dn = get_subject_dn_str(cert_record.certificate)
                issuer_dn = get_issuer_dn_str(cert_record.certificate)

                # Convert datetime to Unix timestamp in milliseconds (as
                # expected by IPA)
                not_before_ts = int(
                    cert_record.certificate.not_valid_before_utc.timestamp()
                    * 1000
                )
                not_after_ts = int(
                    cert_record.certificate.not_valid_after_utc.timestamp()
                    * 1000
                )
                not_before = (
                    cert_record.certificate.not_valid_before.isoformat()
                )
                not_after = cert_record.certificate.not_valid_after.isoformat()

                results.append(
                    {
                        # Use 'id' field with hex format (0x prefix) for
                        # Dogtag compatibility
                        "id": f"0x{cert_record.serial_number:x}",
                        "serial_number": f"0x{cert_record.serial_number:x}",
                        "SubjectDN": subject_dn,  # Dogtag format
                        "IssuerDN": issuer_dn,  # Dogtag format
                        "subject": subject_dn,
                        "issuer": issuer_dn,
                        "status": cert_record.status.value,
                        "Status": cert_record.status.value,  # Dogtag format
                        "not_before": not_before,
                        "not_after": not_after,
                        "NotValidBefore": str(not_before_ts),  # Dogtag format
                        "NotValidAfter": str(not_after_ts),  # Dogtag format
                        "valid_not_before": str(not_before_ts),
                        "valid_not_after": str(not_after_ts),
                    }
                )

            return {"entries": results, "total_entries": len(results)}

        except Exception as e:
            logger.error(f"Certificate search failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    # Profile Management Operations

    def create_profile(self, profile_data):
        """
        Create certificate profile - replaces ra_certprofile.create_profile()
        """
        try:
            profile = CertificateProfile.from_dict(profile_data)
            self.profile_manager.create_profile(profile)
            return {"status": "SUCCESS"}

        except Exception as e:
            logger.error(f"Profile creation failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    def read_profile(self, profile_id):
        """
        Read certificate profile - replaces ra_certprofile.read_profile()
        """
        profile = self.profile_manager.get_profile(profile_id)
        if not profile:
            # Match Dogtag's new profile not found error message
            error_msg = (
                f"Unable to get enrollment template for {profile_id}: "
                "Profile not found"
            )
            raise errors.CertificateOperationError(error=error_msg)

        return profile.to_dict()

    def update_profile(self, profile_data):
        """
        Update certificate profile - replaces ra_certprofile.update_profile()
        """
        try:
            profile = CertificateProfile.from_dict(profile_data)
            self.profile_manager.update_profile(profile)
            return {"status": "SUCCESS"}

        except Exception as e:
            logger.error(f"Profile update failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    def delete_profile(self, profile_id):
        """
        Delete certificate profile - replaces ra_certprofile.delete_profile()
        """
        try:
            self.profile_manager.delete_profile(profile_id)
            return {"status": "SUCCESS"}

        except Exception as e:
            logger.error(f"Profile deletion failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    def enable_profile(self, profile_id):
        """
        Enable certificate profile - replaces ra_certprofile.enable_profile()
        """
        try:
            self.profile_manager.enable_profile(profile_id)
            return {"status": "SUCCESS"}

        except Exception as e:
            logger.error(f"Profile enable failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    def disable_profile(self, profile_id):
        """
        Disable certificate profile - replaces ra_certprofile.disable_profile()
        """
        try:
            self.profile_manager.disable_profile(profile_id)
            return {"status": "SUCCESS"}

        except Exception as e:
            logger.error(f"Profile disable failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    # CRL Operations

    def update_crl(self):
        """
        Update Certificate Revocation List - replaces updateCRL operation

        Publishes CRL to two locations:
        1. ipathinca directory (for REST API access)
        2. IPA PKI publish directory (for Apache/HTTP access via /ipa/crl)

        Matches Dogtag behavior:
        - Writes timestamped CRL file (MasterCRL-YYYYMMDD-HHMMSS.der)
        - Creates/updates symlink (MasterCRL.bin -> timestamped file)
        """
        try:
            crl = self.ca.generate_crl()

            # Serialize CRL to DER format
            crl_der = crl.public_bytes(serialization.Encoding.DER)

            # Store CRL in ipathinca directory (for REST API)
            crl_path = os.path.join(paths.IPATHINCA_CERTS_DIR, "ca_crl.der")
            with open(crl_path, "wb") as f:
                f.write(crl_der)

            # Publish CRL to IPA PKI directory (for Apache/HTTP access)
            # This makes the CRL available at
            # http://<hostname>/ipa/crl/MasterCRL.bin
            publish_dir = paths.IPA_PKI_PUBLISH_DIR
            os.makedirs(publish_dir, mode=0o755, exist_ok=True)

            # Generate timestamped filename
            # (Dogtag format: MasterCRL-YYYYMMDD-HHMMSS.der)

            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            timestamped_filename = f"MasterCRL-{timestamp}.der"
            timestamped_path = os.path.join(publish_dir, timestamped_filename)

            # Write timestamped CRL file
            with open(timestamped_path, "wb") as f:
                f.write(crl_der)
            # Set world-readable permissions for Apache to serve
            os.chmod(timestamped_path, 0o644)

            # Create/update symlink MasterCRL.bin -> timestamped file
            symlink_path = os.path.join(publish_dir, "MasterCRL.bin")
            # Remove old symlink if exists
            if os.path.islink(symlink_path) or os.path.exists(symlink_path):
                os.unlink(symlink_path)
            # Create new symlink (use absolute path for symlink target)
            os.symlink(timestamped_path, symlink_path)

            logger.debug(
                f"CRL updated successfully: {crl_path} and {symlink_path} "
                f"-> {timestamped_filename}"
            )
            return {"status": "SUCCESS"}

        except Exception as e:
            logger.error(f"CRL update failed: {e}")
            raise errors.CertificateOperationError(error=str(e))

    # CA Management Operations

    def create_ca_certificate(self, subject, algorithm=None):
        """
        Create CA certificate and private key - used during CA installation

        Args:
            subject: The certificate subject DN as a string
            algorithm: Signing algorithm (e.g., "SHA256withRSA")

        Returns:
            Dict with 'certificate' and 'private_key' in PEM format
        """
        try:
            logger.debug(f"Creating CA certificate with subject: {subject}")

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )

            # Parse subject DN
            subject_dn = DN(subject)

            # Build certificate subject
            # Convert IPA DN to x509.Name using utility function
            # This handles proper RDN wrapping and ordering automatically
            cert_subject = x509_utils.ipa_dn_to_x509_name(str(subject_dn))

            # Set validity period (10 years)
            now = datetime.now(timezone.utc)
            not_valid_before = now
            not_valid_after = now + timedelta(days=3650)

            # Generate serial number
            serial_number = int(uuid.uuid4().hex[:16], 16)

            # Create certificate
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(cert_subject)
            cert_builder = cert_builder.issuer_name(
                cert_subject
            )  # Self-signed
            cert_builder = cert_builder.public_key(private_key.public_key())
            cert_builder = cert_builder.serial_number(serial_number)
            cert_builder = cert_builder.not_valid_before(not_valid_before)
            cert_builder = cert_builder.not_valid_after(not_valid_after)

            # Add CA extensions
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )

            # Use shared CA KeyUsage extension utility
            cert_builder = cert_builder.add_extension(
                get_ca_key_usage_extension(), critical=True
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

            # Choose hash algorithm based on the algorithm parameter
            if algorithm and "SHA1" in algorithm.upper():
                hash_alg = hashes.SHA1()
            elif algorithm and "SHA384" in algorithm.upper():
                hash_alg = hashes.SHA384()
            elif algorithm and "SHA512" in algorithm.upper():
                hash_alg = hashes.SHA512()
            else:
                hash_alg = hashes.SHA256()  # Default

            # Sign the certificate
            certificate = cert_builder.sign(private_key, hash_alg)

            # Convert to PEM format
            cert_pem = certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode("utf-8")
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            logger.debug(
                "CA certificate created successfully with serial number: "
                f"{serial_number}"
            )

            return {
                "certificate": cert_pem,
                "private_key": key_pem,
                "serial_number": serial_number,
            }

        except Exception as e:
            logger.error(f"CA certificate creation failed: {e}")
            raise errors.CertificateOperationError(
                error=f"Failed to create CA certificate: {e}"
            )

    # System Operations

    def get_ca_info(self):
        """
        Get CA information - replaces various Dogtag info endpoints
        """
        try:
            # Try to ensure CA is loaded
            self.ca._ensure_ca_loaded()

            # Use x509_utils helper to convert certificate subject to IPA DN
            # string

            ca_subject_str = get_subject_dn_str(self.ca.ca_cert)
            ca_not_before = self.ca.ca_cert.not_valid_before_utc.isoformat()
            ca_not_after = self.ca.ca_cert.not_valid_after_utc.isoformat()

            return {
                "ca_id": self.ca.ca_id,
                "ca_subject": ca_subject_str,
                "ca_serial_number": str(self.ca.ca_cert.serial_number),
                "ca_not_before": ca_not_before,
                "ca_not_after": ca_not_after,
                "status": "RUNNING",
            }
        except errors.CertificateOperationError:
            # CA not available yet (probably during installation)
            return {
                "ca_id": self.ca.ca_id,
                "ca_subject": "Not available - CA not configured",
                "ca_serial_number": "Not available",
                "ca_not_before": "Not available",
                "ca_not_after": "Not available",
                "status": "NOT_CONFIGURED",
            }

    def get_certificate_chain(self):
        """
        Get CA certificate chain - replaces getCertChain operation
        """
        try:
            # Try to ensure CA is loaded
            self.ca._ensure_ca_loaded()

            # Convert to PEM with CRLF line endings to match Dogtag
            ca_cert_pem = (
                self.ca.ca_cert.public_bytes(
                    encoding=serialization.Encoding.PEM
                )
                .decode()
                .replace("\n", "\r\n")
            )

            return {"certificate_chain": ca_cert_pem}
        except errors.CertificateOperationError:
            # CA not available yet (probably during installation)
            return {
                "certificate_chain": (
                    "CA certificate not available - CA not configured yet"
                )
            }


# Global backend instance
_python_ca_backend = None


def get_python_ca_backend():
    """Get singleton Python CA backend instance"""
    global _python_ca_backend
    if _python_ca_backend is None:
        _python_ca_backend = PythonCABackend()
    return _python_ca_backend
