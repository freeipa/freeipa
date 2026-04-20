# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Core Certificate Authority Engine

This module provides the foundational CA functionality for certificate
signing, revocation, and CRL generation using LDAP storage. It provides
core CA operations without audit logging, authentication, or sub-CA management.

Use this for:
- **Testing**: Test CA operations without audit infrastructure
- **Migration tools**: Certificate import/export utilities
- **ACME protocol**: Certificate issuance without audit requirements
- **Building blocks**: Composition in SubCA and other components

For production FreeIPA deployments, use InternalCA from ca_internal.py which
adds:
- Comprehensive audit logging for all operations
- Principal tracking for authentication/authorization
- LDAP schema initialization

Architecture:
    PythonCA (this file)
    ├── Core CA engine with LDAP storage
    │
    └── InternalCA (ca_internal.py)
        ├── Adds: audit logging, principal tracking, sub-CA, schema init

Key Features:
    - Certificate signing and issuance
    - Certificate revocation (revoke, hold, unhold)
    - CRL generation
    - LDAP storage backend (always enabled)
    - Profile management integration
    - Serial number generation (sequential or random)

LDAP Storage:
    PythonCA always uses LDAP storage via CAStorageBackend. This is core
    to ipathinca, not an optional feature. The storage layer handles:
    - Certificate persistence
    - Serial number management
    - Certificate retrieval and search
"""

import datetime
import logging
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from ipalib import errors
from ipathinca.profiles import ProfileManager
from ipathinca.certificate_types import (  # noqa: F401 — re-exported
    CertificateStatus,
    RevocationReason,
    CertificateRequest,
    CertificateRecord,
    REVOCATION_REASON_TO_FLAG,
)
from ipathinca.storage_factory import get_storage_backend
from ipathinca.hsm import HSMConfig, HSMKeyBackend, HSMPrivateKeyProxy
from ipathinca.ldap_utils import is_internal_token
from ipathinca.nss_utils import NSSDatabase
from ipathinca import x509_utils
import ipathinca

# Try to import cachetools for bounded request cache
try:
    from cachetools import TTLCache

    CACHETOOLS_AVAILABLE = True
except ImportError:
    CACHETOOLS_AVAILABLE = False

logger = logging.getLogger(__name__)


class PythonCA:
    """
    Python-cryptography based Certificate Authority implementation

    This class provides the core CA functionality to replace Dogtag PKI:
    - Certificate signing
    - Certificate revocation
    - CRL generation
    - Certificate storage and retrieval
    """

    def __init__(
        self,
        ca_cert_path: str,
        ca_key_path: str,
        ca_id: str = "ipa",
        random_serial_numbers: bool = False,
        config=None,
    ):
        """
        Initialize the CA

        Args:
            ca_cert_path: Path to CA certificate file
            ca_key_path: Path to CA private key file
            ca_id: CA identifier (for sub-CA support)
            random_serial_numbers: Use RSNv3 random serial numbers
                                       (default: False)
            config: RawConfigParser object from ipathinca.conf (optional)
        """
        self.ca_id = ca_id
        self.ca_cert_path = Path(ca_cert_path)
        self.ca_key_path = Path(ca_key_path)
        self.config = config

        # Initialize CA cert and key as None - will be loaded on demand
        self.ca_cert = None
        self.ca_private_key = None
        self._ca_load_lock = threading.Lock()

        # Cached CRL timing (populated on first call to _get_crl_timing)
        self._crl_timing = None
        self._crl_timing_lock = threading.Lock()

        # Initialize storage backend (LDAP required for ipathinca)
        # Uses factory to select backend based on configuration
        self.storage = get_storage_backend(
            ca_id=ca_id,
            random_serial_numbers=random_serial_numbers,
            config=config,
        )
        logger.debug(
            "Successfully initialized storage backend for certificates"
        )

        # Initialize ProfileManager for certificate profiles
        self.profile_manager = ProfileManager(
            config=config, storage_backend=self.storage
        )
        logger.debug(
            "Successfully initialized ProfileManager for certificate profiles"
        )

        # In-memory cache for requests with LDAP persistence
        # Use TTLCache to prevent memory leaks in long-running deployments
        # Cache up to 1000 recent requests for 1 hour (3600 seconds)
        # After TTL expiry, requests are still available from LDAP
        self._requests_lock = threading.Lock()
        if CACHETOOLS_AVAILABLE:
            self.requests = TTLCache(maxsize=1000, ttl=3600)
            logger.debug(
                "Using TTLCache for certificate requests (maxsize=1000,"
                " ttl=3600s)"
            )
        else:
            self.requests: Dict[str, CertificateRequest] = {}
            logger.warning(
                "cachetools not available, using unbounded dict for requests. "
                "This may cause memory leaks in long-running deployments. "
                "Install cachetools: pip install cachetools"
            )

    def _load_ca_cert_and_key(self):
        """Load CA certificate and private key from files

        Returns:
            bool: True if successful, False if cert/key files don't exist
        """
        try:
            # Check if certificate file exists before trying to load it
            if not self.ca_cert_path.exists():
                logger.debug(
                    "CA certificate file does not exist: %s", self.ca_cert_path
                )
                return False

            # Load CA certificate (always from file for ipathinca)
            with open(self.ca_cert_path, "rb") as f:
                ca_cert_data = f.read()
                self.ca_cert = x509.load_pem_x509_certificate(ca_cert_data)

            # Load CA private key - conditional based on HSM configuration
            hsm_config = None
            if hasattr(self.storage, "get_hsm_config"):
                try:
                    hsm_config = self.storage.get_hsm_config(self.ca_id)
                except Exception as e:
                    logger.debug(
                        "Could not retrieve HSM config for CA %s: %s",
                        self.ca_id,
                        e,
                    )

            if hsm_config and hsm_config.get("enabled"):
                # HSM path - use HSMPrivateKeyProxy
                token_name = hsm_config.get("token_name")
                if is_internal_token(token_name):
                    raise errors.CertificateOperationError(
                        error=(
                            f"HSM is enabled for CA {self.ca_id} but token "
                            f"'{token_name}' is internal NSS token. "
                            "HSM requires external hardware token."
                        )
                    )

                logger.debug(
                    "Loading CA private key from HSM token '%s' for CA %s",
                    token_name,
                    self.ca_id,
                )

                hsm = HSMKeyBackend(HSMConfig(hsm_config))
                key_label = f"{self.ca_id}_signing"
                self.ca_private_key = HSMPrivateKeyProxy(hsm, key_label)

                logger.debug(
                    "Successfully loaded CA certificate and HSM private key "
                )
            else:
                # NSSDB path - extract from NSSDB (Dogtag-compatible)
                # Keys are stored in NSSDB, not as PEM files
                logger.debug(
                    "Extracting CA private key from NSSDB for CA %s",
                    self.ca_id,
                )

                # Determine nickname based on CA ID
                if self.ca_id == "ipa":
                    ca_nickname = "caSigningCert cert-pki-ca"
                else:
                    # Sub-CA nickname format
                    ca_nickname = f"caSigningCert cert-pki-ca {self.ca_id}"

                try:
                    nssdb = NSSDatabase()
                    self.ca_private_key = nssdb.extract_private_key(
                        ca_nickname
                    )

                    logger.debug(
                        "Successfully loaded CA certificate and extracted "
                        "private key from NSSDB for CA %s",
                        self.ca_id,
                    )
                except RuntimeError as e:
                    logger.debug(
                        "CA private key not found in NSSDB: %s: %s",
                        ca_nickname,
                        e,
                    )
                    return False

            return True

        except Exception as e:
            logger.error("Failed to load CA cert/key: %s", e, exc_info=True)
            raise errors.CertificateOperationError(
                error=f"Failed to load CA certificate or key: {e}"
            )

    def _ensure_ca_loaded(self):
        """Ensure CA certificate and key are loaded"""
        if self.ca_cert is None or self.ca_private_key is None:
            with self._ca_load_lock:
                # Double-check under lock
                if (
                    self.ca_cert is not None
                    and self.ca_private_key is not None
                ):
                    return
                if not self._load_ca_cert_and_key():
                    raise errors.CertificateOperationError(
                        error=(
                            "CA certificate and/or private key not available. "
                            "CA may not be configured yet."
                        )
                    )

    def ensure_ca_loaded(self):
        """Public wrapper: ensure CA certificate and key are loaded."""
        self._ensure_ca_loaded()

    def _get_crl_timing(self):
        """Get CRL update interval and grace period from config.

        Returns:
            tuple: (update_interval_minutes, next_update_minutes)
        """
        if self._crl_timing is not None:
            return self._crl_timing

        with self._crl_timing_lock:
            if self._crl_timing is not None:
                return self._crl_timing

            update_interval = int(
                ipathinca.get_config_value(
                    "ca", "crl_update_interval", default="240"
                )
            )
            grace_period = int(
                ipathinca.get_config_value(
                    "ca", "crl_next_update_grace_period", default="0"
                )
            )
            if update_interval < 1:
                logger.warning(
                    "crl_update_interval=%d is invalid, using 240 minutes",
                    update_interval,
                )
                update_interval = 240
            if grace_period < 0:
                logger.warning(
                    "crl_next_update_grace_period=%d is invalid, using 0",
                    grace_period,
                )
                grace_period = 0
            self._crl_timing = (
                update_interval,
                update_interval + grace_period,
            )
            return self._crl_timing

    def _get_next_serial_number(self) -> int:
        """Generate next serial number for certificate via LDAP storage
        backend"""
        return self.storage.get_next_serial_number()

    def submit_certificate_request(
        self, csr_pem: str, profile: str = "caIPAserviceCert"
    ) -> str:
        """
        Submit a certificate signing request

        Args:
            csr_pem: PEM-encoded certificate signing request
            profile: Certificate profile to use

        Returns:
            Request ID for tracking
        """
        try:
            # Parse and validate CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            if not csr.is_signature_valid:
                raise errors.CertificateOperationError(
                    error="CSR signature verification failed"
                )

            # Create request record
            request = CertificateRequest(csr, profile)

            # Store in memory cache (thread-safe)
            with self._requests_lock:
                self.requests[request.request_id] = request

            # Persist to LDAP storage
            self.storage.store_request(request)

            logger.debug(
                "Certificate request %s submitted with profile %s and "
                "persisted to LDAP",
                request.request_id,
                profile,
            )
            return request.request_id

        except Exception as e:
            logger.error("Failed to submit certificate request: %s", e)
            raise errors.CertificateOperationError(
                error=f"Failed to submit certificate request: {e}"
            )

    def sign_certificate_request(self, request_id: str) -> int:
        """
        Sign a certificate request and issue certificate

        Args:
            request_id: ID of the request to sign

        Returns:
            Serial number of issued certificate
        """
        # Ensure CA cert and key are loaded
        self._ensure_ca_loaded()

        # Get request from cache or LDAP
        request = self.get_request_status(request_id)
        if not request:
            raise errors.NotFound(
                reason=f"Certificate request {request_id} not found"
            )
        csr = request.csr

        try:
            # Validate CSR against profile before signing
            # This ensures the profile exists and CSR meets requirements
            self.profile_manager.validate_profile_for_csr(request.profile, csr)

            # Get profile to determine validity period
            profile_obj = self.profile_manager.get_profile(request.profile)
            validity_days = profile_obj.validity_days if profile_obj else 365

            # Sign certificate with algorithm matching CA certificate
            # Note: This is the legacy/simple CA class. For full Dogtag profile
            # support with per-profile algorithm selection, use CAInternal.
            signing_alg = x509_utils.get_certificate_signature_algorithm(
                self.ca_cert
            )
            hash_alg = x509_utils.parse_signature_algorithm(signing_alg)

            # Retry loop for LDAP collisions (multi-worker).
            # MidairCollision can occur at serial allocation or cert
            # storage when multiple workers race on the same LDAP entry.
            max_retries = 10
            for attempt in range(max_retries):
                try:
                    serial_number = self._get_next_serial_number()
                except errors.MidairCollision:
                    if attempt < max_retries - 1:
                        logger.debug(
                            "Serial allocation collision (attempt %d/%d)",
                            attempt + 1,
                            max_retries,
                        )
                        continue
                    raise

                # Build certificate
                builder = x509.CertificateBuilder()
                builder = builder.subject_name(csr.subject)
                builder = builder.issuer_name(self.ca_cert.subject)
                builder = builder.public_key(csr.public_key())
                builder = builder.serial_number(serial_number)

                now = datetime.datetime.now(datetime.timezone.utc)
                not_after = now + datetime.timedelta(days=validity_days)

                # Enforce parent CA validity constraint (RFC 5280):
                # issued certificate must not extend beyond CA's notAfter
                ca_not_after = self.ca_cert.not_valid_after_utc
                if not_after > ca_not_after:
                    logger.warning(
                        "Certificate validity (%s) would exceed CA validity "
                        "(%s), clamping to CA notAfter",
                        not_after.isoformat(),
                        ca_not_after.isoformat(),
                    )
                    not_after = ca_not_after

                builder = builder.not_valid_before(now)
                builder = builder.not_valid_after(not_after)

                # Add extensions based on profile
                builder = self._add_extensions_for_profile(
                    builder, request.profile, csr
                )

                certificate = builder.sign(self.ca_private_key, hash_alg)

                # Store certificate record in LDAP
                # Use allow_update=False to detect serial number collisions
                cert_record = CertificateRecord(certificate, request)
                try:
                    self.storage.store_certificate(
                        cert_record, allow_update=False
                    )
                    break
                except errors.DuplicateEntry:
                    if attempt < max_retries - 1:
                        logger.warning(
                            "Serial number %d collision, retrying (%d/%d)",
                            serial_number,
                            attempt + 1,
                            max_retries,
                        )
                        continue
                    raise
                except errors.MidairCollision:
                    if attempt < max_retries - 1:
                        logger.debug(
                            "LDAP collision storing cert (attempt %d/%d)",
                            attempt + 1,
                            max_retries,
                        )
                        continue
                    raise

            # Update request status (lowercase to match PKI CertRequestStatus
            # constants)
            request.status = "complete"
            request.serial_number = serial_number

            # Update request in LDAP storage
            self.storage.store_request(request)

            logger.debug(
                "Certificate %s issued for request %s,",
                serial_number,
                request_id,
            )
            return serial_number

        except Exception as e:
            logger.error("Failed to sign certificate: %s", e)
            # Use lowercase to match PKI CertRequestStatus constants
            request.status = "rejected"

            # Update rejected status in LDAP storage
            try:
                self.storage.store_request(request)
            except Exception as storage_error:
                logger.warning(
                    "Failed to update rejected request in LDAP: %s",
                    storage_error,
                )

            raise errors.CertificateOperationError(
                error=f"Failed to sign certificate: {e}"
            )

    def _add_extensions_for_profile(
        self,
        builder: x509.CertificateBuilder,
        profile: str,
        csr: x509.CertificateSigningRequest,
        issuer_cert: Optional[x509.Certificate] = None,
    ) -> x509.CertificateBuilder:
        """Add extensions based on certificate profile using ProfileManager

        Args:
            builder: Certificate builder
            profile: Certificate profile name (supports aliases)
            csr: Certificate signing request
            issuer_cert: Issuer certificate (defaults to self.ca_cert if not
                         provided)

        Returns:
            Certificate builder with extensions added

        Raises:
            NotFound: If profile not found in ProfileManager
        """
        if issuer_cert is None:
            issuer_cert = self.ca_cert

        # Get extensions from ProfileManager
        # This replaces all the hardcoded if/elif blocks
        try:
            profile_extensions = (
                self.profile_manager.get_extensions_for_profile(profile)
            )
        except errors.NotFound:
            # Re-raise with clear error message
            raise errors.CertificateOperationError(
                error=(
                    f"Certificate profile '{profile}' not found. Please "
                    "check profile configuration."
                )
            )

        # Add all profile-defined extensions (BasicConstraints, KeyUsage,
        # ExtendedKeyUsage)
        for ext in profile_extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)

        # Copy subject alternative names from CSR if present
        # This is not profile-specific, so handle separately
        try:
            for ext in csr.extensions:
                if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    builder = builder.add_extension(
                        ext.value, critical=ext.critical
                    )
                    break  # Only copy SAN once
        except x509.ExtensionNotFound:
            pass

        # Add authority key identifier (always required for cert chain
        # validation)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_cert.public_key()
            ),
            critical=False,
        )

        # Add subject key identifier (always required for cert identification)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )

        return builder

    def get_certificate(
        self, serial_number: int
    ) -> Optional[CertificateRecord]:
        """Retrieve certificate by serial number from LDAP storage"""
        logger.debug(
            "Getting certificate with serial_number=%s", serial_number
        )
        return self.storage.get_certificate(serial_number)

    def revoke_certificate(
        self,
        serial_number: int,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
    ):
        """Revoke a certificate"""
        cert_record = self.storage.get_certificate(serial_number)
        if not cert_record:
            raise errors.NotFound(
                reason=f"Certificate {serial_number} not found"
            )

        cert_record.revoke(reason)
        self.storage.store_certificate(cert_record)

        logger.debug(
            "Certificate %s revoked with reason %s", serial_number, reason.name
        )

    def put_certificate_on_hold(self, serial_number: int):
        """Put certificate on hold"""
        cert_record = self.storage.get_certificate(serial_number)
        if not cert_record:
            raise errors.NotFound(
                reason=f"Certificate {serial_number} not found"
            )

        cert_record.put_on_hold()
        self.storage.store_certificate(cert_record)

        logger.debug("Certificate %s put on hold", serial_number)

    def take_certificate_off_hold(self, serial_number: int):
        """Remove certificate from hold"""
        cert_record = self.storage.get_certificate(serial_number)
        if not cert_record:
            raise errors.NotFound(
                reason=f"Certificate {serial_number} not found"
            )

        cert_record.take_off_hold()
        self.storage.store_certificate(cert_record)

        logger.debug("Certificate %s taken off hold", serial_number)

    def generate_crl(self) -> x509.CertificateRevocationList:
        """Generate Certificate Revocation List

        Uses configuration settings matching Dogtag CS.cfg:
        - ca.crl.MasterCRL.autoUpdateInterval (crl_update_interval)
        - ca.crl.MasterCRL.nextUpdateGracePeriod (crl_next_update_grace_period)
        """
        # Ensure CA cert and key are loaded
        self._ensure_ca_loaded()

        # Read CRL timing from config
        next_update_minutes = self._get_crl_timing()[1]

        # Get next CRL number from storage (RFC 5280 §5.2.3 requirement)
        crl_number = self.storage.get_next_crl_number()

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)

        now = datetime.datetime.now(datetime.timezone.utc)
        builder = builder.last_update(now)
        builder = builder.next_update(
            now + datetime.timedelta(minutes=next_update_minutes)
        )

        # Add CRL Number extension (RFC 5280 §5.2.3 requirement)
        builder = builder.add_extension(
            x509.CRLNumber(crl_number), critical=False
        )

        # Add Authority Key Identifier extension (RFC 5280 §5.2.1)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.ca_cert.public_key()
            ),
            critical=False,
        )

        # Get all revoked certificates from LDAP storage
        # Optionally filter out expired certificates
        include_expired = (
            ipathinca.get_config_value(
                "ca", "crl_include_expired_certs", default="false"
            ).lower()
            == "true"
        )
        revoked_certs = self.storage.find_certificates({"status": "REVOKED"})
        if not include_expired:
            revoked_certs = [
                c
                for c in revoked_certs
                if c.certificate is not None
                and c.certificate.not_valid_after_utc > now
            ]

        # Add revoked certificates to CRL
        for cert_record in revoked_certs:
            if cert_record.status == CertificateStatus.REVOKED:
                if cert_record.revoked_at is None:
                    logger.warning(
                        "Revoked certificate %s has no revocation date, "
                        "skipping in CRL",
                        cert_record.serial_number,
                    )
                    continue
                revoked_cert = x509.RevokedCertificateBuilder()
                revoked_cert = revoked_cert.serial_number(
                    cert_record.serial_number
                )
                revoked_cert = revoked_cert.revocation_date(
                    cert_record.revoked_at
                )

                if cert_record.revocation_reason:
                    reason_flag = REVOCATION_REASON_TO_FLAG.get(
                        cert_record.revocation_reason,
                        x509.ReasonFlags.unspecified,
                    )
                    revoked_cert = revoked_cert.add_extension(
                        x509.CRLReason(reason_flag),
                        critical=False,
                    )

                builder = builder.add_revoked_certificate(revoked_cert.build())

        # Sign CRL with algorithm matching CA certificate
        # Extract algorithm from the CA cert that will sign this CRL
        signing_alg = x509_utils.get_certificate_signature_algorithm(
            self.ca_cert
        )
        hash_alg = x509_utils.parse_signature_algorithm(signing_alg)
        crl = builder.sign(self.ca_private_key, hash_alg)
        return crl

    def find_certificates(
        self, criteria: Dict[str, Any] = None
    ) -> List[CertificateRecord]:
        """Search certificates by criteria in LDAP storage"""
        return self.storage.find_certificates(criteria or {})

    def get_request_status(
        self, request_id: str
    ) -> Optional[CertificateRequest]:
        """
        Get status of certificate request

        Checks cache first, then falls back to LDAP if not in cache
        (cache miss due to TTL expiry or restart)

        Args:
            request_id: Request ID to check

        Returns:
            CertificateRequest object or None if not found
        """
        # Check cache first (fast path, thread-safe)
        with self._requests_lock:
            request = self.requests.get(request_id)

        if request is not None:
            logger.debug("Request %s found in cache", request_id)
            return request

        # Cache miss - check LDAP storage (slow path)
        logger.debug(
            "Request %s not in cache, checking LDAP storage", request_id
        )
        request = self.storage.get_request(request_id)

        if request is not None:
            # Restore to cache for future lookups (thread-safe)
            with self._requests_lock:
                self.requests[request_id] = request
            logger.debug(
                "Request %s restored to cache from LDAP storage", request_id
            )

        return request

    def shutdown(self):
        """
        Shutdown CA and cleanup resources

        Matches Dogtag's shutdown() method for ProfileSubsystem
        """
        logger.info("Shutting down CA")

        # Stop profile change monitor
        if hasattr(self, "profile_manager") and self.profile_manager:
            self.profile_manager.stop_monitoring()

        logger.info("CA shutdown complete")
