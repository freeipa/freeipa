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
import enum
import logging
import os
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from ipalib import errors
from ipathinca.profiles import ProfileManager
from ipathinca.certificate_lifecycle import (
    CertificateLifecycle,
    CertificateState,
    CertificateEvent,
    InvalidStateTransition,
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


class CertificateStatus(enum.Enum):
    """Certificate status enumeration"""

    VALID = "VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    ON_HOLD = "ON_HOLD"


class RevocationReason(enum.Enum):
    """Certificate revocation reasons per RFC 5280"""

    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10
    REMOVE_FROM_CRL = 8  # Special case for unrevoke


# Canonical mappings for RevocationReason — used by CertificateRecord,
# CRL generation, and REST API.  Defined once to avoid drift.

REVOCATION_REASON_TO_STRING = {
    RevocationReason.UNSPECIFIED: "unspecified",
    RevocationReason.KEY_COMPROMISE: "keyCompromise",
    RevocationReason.CA_COMPROMISE: "CACompromise",
    RevocationReason.AFFILIATION_CHANGED: "affiliationChanged",
    RevocationReason.SUPERSEDED: "superseded",
    RevocationReason.CESSATION_OF_OPERATION: "cessationOfOperation",
    RevocationReason.CERTIFICATE_HOLD: "certificateHold",
    RevocationReason.PRIVILEGE_WITHDRAWN: "privilegeWithdrawn",
    RevocationReason.AA_COMPROMISE: "AACompromise",
}

REVOCATION_STRING_TO_REASON = {
    v: k for k, v in REVOCATION_REASON_TO_STRING.items()
}

REVOCATION_REASON_TO_FLAG = {
    RevocationReason.UNSPECIFIED: x509.ReasonFlags.unspecified,
    RevocationReason.KEY_COMPROMISE: x509.ReasonFlags.key_compromise,
    RevocationReason.CA_COMPROMISE: x509.ReasonFlags.ca_compromise,
    RevocationReason.AFFILIATION_CHANGED: x509.ReasonFlags.affiliation_changed,
    RevocationReason.SUPERSEDED: x509.ReasonFlags.superseded,
    RevocationReason.CESSATION_OF_OPERATION: (
        x509.ReasonFlags.cessation_of_operation
    ),
    RevocationReason.CERTIFICATE_HOLD: x509.ReasonFlags.certificate_hold,
    RevocationReason.PRIVILEGE_WITHDRAWN: (
        x509.ReasonFlags.privilege_withdrawn
    ),
    RevocationReason.AA_COMPROMISE: x509.ReasonFlags.aa_compromise,
    RevocationReason.REMOVE_FROM_CRL: x509.ReasonFlags.remove_from_crl,
}


class CertificateRequest:
    """Container for certificate request data"""

    # Monotonic counter for generating Dogtag-compatible integer request IDs.
    # Seeded from current time in microseconds plus PID-based offset to
    # avoid collisions across restarts AND across gunicorn worker processes
    # (which are forked from the master and would otherwise share the same
    # seed).  Thread-safe via threading.Lock.
    _request_counter_lock = threading.Lock()
    _request_counter = 0
    _request_counter_pid = 0

    @classmethod
    def _next_request_id(cls) -> str:
        with cls._request_counter_lock:
            pid = os.getpid()
            if cls._request_counter_pid != pid:
                # (Re-)seed after fork: time-in-microseconds * 65536 + PID
                # gives each worker a unique starting range.
                cls._request_counter = int(
                    datetime.datetime.now(
                        datetime.timezone.utc
                    ).timestamp() * 1_000_000
                ) * 65536 + pid
                cls._request_counter_pid = pid
            cls._request_counter += 1
            return str(cls._request_counter)

    def __init__(
        self, csr: x509.CertificateSigningRequest, profile: str = None
    ):
        self.csr = csr
        self.profile = profile or "caIPAserviceCert"
        # Use integer-based request IDs for PKI client compatibility.
        # IPA's dogtag.py calls int(request_id, 0), which crashes on UUIDs.
        self.request_id = self._next_request_id()
        # Use lowercase status to match PKI CertRequestStatus constants
        self.status = "pending"
        self.serial_number = None
        self.submitted_at = datetime.datetime.now(datetime.timezone.utc)

    @classmethod
    def for_subca(cls, ca_id: str, profile: str = "caSubCACert"):
        """Create a CertificateRequest for sub-CA certificate storage."""
        obj = cls.__new__(cls)
        obj.csr = None
        obj.profile = profile
        obj.request_id = f"subca-{ca_id}"
        obj.status = "complete"
        obj.serial_number = None
        obj.submitted_at = datetime.datetime.now(datetime.timezone.utc)
        return obj

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/API"""
        return {
            "request_id": self.request_id,
            "profile": self.profile,
            "status": self.status,
            "serial_number": self.serial_number,
            "submitted_at": self.submitted_at.isoformat(),
            "csr_pem": (
                self.csr.public_bytes(serialization.Encoding.PEM).decode()
                if self.csr
                else None
            ),
        }


class CertificateRecord:
    """
    Container for issued certificate data with lifecycle state management

    This class now uses the CertificateLifecycle state machine for robust
    state management and audit trailing. All state transitions are validated
    and recorded.

    Attributes:
        certificate: The X.509 certificate
        serial_number: Certificate serial number
        lifecycle: State machine managing certificate lifecycle
        issued_at: Timestamp when certificate was issued
        request_id: Associated certificate request ID
        profile: Certificate profile used
    """

    def __init__(
        self,
        certificate: x509.Certificate,
        request: CertificateRequest,
        principal: Optional[str] = None,
    ):
        """
        Initialize certificate record

        Args:
            certificate: The X.509 certificate
            request: The certificate request
            principal: Who issued the certificate (for audit)
        """
        self.certificate = certificate
        self.serial_number = certificate.serial_number
        self.issued_at = datetime.datetime.now(datetime.timezone.utc)
        self.request_id = request.request_id
        self.profile = request.profile

        # Initialize lifecycle state machine
        self.lifecycle = CertificateLifecycle(
            initial_state=CertificateState.PENDING,
            serial_number=self.serial_number,
        )

        # Issue the certificate (transition PENDING -> VALID)
        try:
            self.lifecycle.transition(
                CertificateEvent.ISSUE,
                principal=principal,
                reason=f"Certificate issued with profile {self.profile}",
            )
        except InvalidStateTransition as e:
            logger.error(
                f"Failed to issue certificate {self.serial_number}: {e}"
            )
            raise errors.CertificateOperationError(error=str(e))

    @property
    def status(self) -> CertificateStatus:
        """
        Get certificate status (for backward compatibility)

        Maps new CertificateState to old CertificateStatus enum
        """
        state_mapping = {
            # Shouldn't happen:
            CertificateState.PENDING: CertificateStatus.VALID,
            CertificateState.VALID: CertificateStatus.VALID,
            CertificateState.EXPIRED: CertificateStatus.EXPIRED,
            CertificateState.REVOKED: CertificateStatus.REVOKED,
            CertificateState.ON_HOLD: CertificateStatus.ON_HOLD,
            # Map to REVOKED:
            CertificateState.SUPERSEDED: CertificateStatus.REVOKED,
        }
        return state_mapping.get(
            self.lifecycle.current_state, CertificateStatus.VALID
        )

    @property
    def revoked_at(self) -> Optional[datetime.datetime]:
        """Get revocation timestamp (for backward compatibility)"""
        revocation_info = self.lifecycle.get_revocation_info()
        if revocation_info:
            return revocation_info["revoked_at"]
        return None

    @property
    def revocation_reason(self) -> Optional[RevocationReason]:
        """Get revocation reason (for backward compatibility)"""
        revocation_info = self.lifecycle.get_revocation_info()
        if revocation_info and revocation_info.get("reason"):
            reason_str = revocation_info["reason"]
            return REVOCATION_STRING_TO_REASON.get(
                reason_str, RevocationReason.UNSPECIFIED
            )
        return None

    def revoke(
        self,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
        principal: Optional[str] = None,
    ):
        """
        Revoke the certificate

        Args:
            reason: Revocation reason (RFC 5280)
            principal: Who is revoking the certificate (for audit)

        Raises:
            CertificateOperationError: If revocation is not allowed from
                                       current state

        Example:
            >>> cert_record.revoke(
            ...     reason=RevocationReason.KEY_COMPROMISE,
            ...     principal='admin'
            ... )
        """
        # Handle CERTIFICATE_HOLD specially (maps to HOLD event, not REVOKE)
        if reason == RevocationReason.CERTIFICATE_HOLD:
            return self.put_on_hold(principal=principal)

        reason_str = REVOCATION_REASON_TO_STRING.get(reason, "unspecified")

        try:
            self.lifecycle.transition(
                CertificateEvent.REVOKE,
                principal=principal,
                reason=reason_str,
            )
            logger.info(
                f"Certificate {self.serial_number} revoked: {reason_str} "
                f"by {principal}"
            )
        except InvalidStateTransition as e:
            logger.error(
                f"Cannot revoke certificate {self.serial_number}: {e}"
            )
            raise errors.CertificateOperationError(error=str(e))

    def put_on_hold(self, principal: Optional[str] = None):
        """
        Put certificate on hold (temporary suspension)

        Args:
            principal: Who is putting the certificate on hold

        Raises:
            CertificateOperationError: If hold is not allowed from current
                                       state

        Example:
            >>> cert_record.put_on_hold(principal='admin')
        """
        try:
            self.lifecycle.transition(
                CertificateEvent.HOLD,
                principal=principal,
                reason="certificateHold",
            )
            logger.info(
                f"Certificate {self.serial_number} put on hold by {principal}"
            )
        except InvalidStateTransition as e:
            logger.error(
                f"Cannot put certificate {self.serial_number} on hold: {e}"
            )
            raise errors.CertificateOperationError(error=str(e))

    def take_off_hold(self, principal: Optional[str] = None):
        """
        Remove certificate from hold (resume validity)

        Args:
            principal: Who is releasing the certificate from hold

        Raises:
            CertificateOperationError: If release is not allowed from current
                                       state

        Example:
            >>> cert_record.take_off_hold(principal='admin')
        """
        try:
            self.lifecycle.transition(
                CertificateEvent.RELEASE,
                principal=principal,
                reason="Released from hold",
            )
            logger.info(
                f"Certificate {self.serial_number} released from hold by "
                f"{principal or 'system'}"
            )
        except InvalidStateTransition as e:
            logger.error(
                f"Cannot release certificate {self.serial_number} from hold: "
                f"{e}"
            )
            raise errors.CertificateOperationError(error=str(e))

    def mark_as_expired(self, principal: Optional[str] = None):
        """
        Mark certificate as expired

        This is typically called automatically when not_after is reached.

        Args:
            principal: Who is marking the certificate as expired (usually
                       'system')

        Raises:
            CertificateOperationError: If expiration is not allowed from
                                       current state
        """
        try:
            self.lifecycle.transition(
                CertificateEvent.EXPIRE,
                principal=principal or "system",
                reason="Certificate validity period expired",
            )
            logger.info(f"Certificate {self.serial_number} marked as expired")
        except InvalidStateTransition as e:
            # Expired certificates might already be revoked, that's OK
            logger.debug(
                f"Cannot mark certificate {self.serial_number} as expired: {e}"
            )

    def supersede(
        self,
        principal: Optional[str] = None,
        replacement_serial: Optional[int] = None,
    ):
        """
        Mark certificate as superseded by a newer certificate

        Args:
            principal: Who is superseding the certificate
            replacement_serial: Serial number of the replacement certificate

        Raises:
            CertificateOperationError: If superseding is not allowed from
                                       current state
        """
        reason = (
            f"Superseded by certificate {replacement_serial}"
            if replacement_serial
            else "Superseded"
        )
        try:
            self.lifecycle.transition(
                CertificateEvent.SUPERSEDE, principal=principal, reason=reason
            )
            logger.info(
                f"Certificate {self.serial_number} superseded by "
                f"{replacement_serial}"
            )
        except InvalidStateTransition as e:
            logger.error(
                f"Cannot supersede certificate {self.serial_number}: {e}"
            )
            raise errors.CertificateOperationError(error=str(e))

    def get_state_history(self) -> List[Dict[str, Any]]:
        """
        Get complete state transition history

        Returns:
            List of state transitions with timestamps, principals, and reasons

        Example:
            >>> history = cert_record.get_state_history()
            >>> for transition in history:
            ...     print(f"{transition['event']}: {transition['timestamp']}")
        """
        return [t.to_dict() for t in self.lifecycle.get_history()]

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for storage/API

        Returns:
            Dictionary with certificate data and lifecycle information
        """
        data = {
            "serial_number": str(self.serial_number),
            "status": self.status.value,
            "issued_at": self.issued_at.isoformat(),
            "revoked_at": (
                self.revoked_at.isoformat() if self.revoked_at else None
            ),
            "revocation_reason": (
                self.revocation_reason.value
                if self.revocation_reason
                else None
            ),
            "request_id": self.request_id,
            "profile": self.profile,
            "certificate_pem": self.certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode(),
        }

        # Add lifecycle information
        data["lifecycle"] = self.lifecycle.to_dict()

        return data


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
                    f"CA certificate file does not exist: {self.ca_cert_path}"
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
                        "Could not retrieve HSM config for "
                        f"CA {self.ca_id}: {e}"
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
                    f"Loading CA private key from HSM token '{token_name}' "
                    f"for CA {self.ca_id}"
                )

                hsm = HSMKeyBackend(HSMConfig(hsm_config))
                key_label = f"{self.ca_id}_signing"
                self.ca_private_key = HSMPrivateKeyProxy(hsm, key_label)

                logger.debug(
                    f"Successfully loaded CA certificate and HSM private key "
                    f"proxy for CA {self.ca_id}"
                )
            else:
                # NSSDB path - extract from NSSDB (Dogtag-compatible)
                # Keys are stored in NSSDB, not as PEM files
                logger.debug(
                    f"Extracting CA private key from NSSDB for CA {self.ca_id}"
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
                        f"private key from NSSDB for CA {self.ca_id}"
                    )
                except RuntimeError as e:
                    logger.debug(
                        f"CA private key not found in NSSDB: {ca_nickname}: "
                        f"{e}"
                    )
                    return False

            return True

        except Exception as e:
            logger.error(f"Failed to load CA cert/key: {e}", exc_info=True)
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
        self._crl_timing = (update_interval, update_interval + grace_period)
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

            # Store in memory cache
            self.requests[request.request_id] = request

            # Persist to LDAP storage
            self.storage.store_request(request)

            logger.debug(
                f"Certificate request {request.request_id} submitted with "
                f"profile {profile} and persisted to LDAP"
            )
            return request.request_id

        except Exception as e:
            logger.error(f"Failed to submit certificate request: {e}")
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
                f"Certificate {serial_number} issued for request {request_id},"
                " request updated in LDAP"
            )
            return serial_number

        except Exception as e:
            logger.error(f"Failed to sign certificate: {e}")
            # Use lowercase to match PKI CertRequestStatus constants
            request.status = "rejected"

            # Update rejected status in LDAP storage
            try:
                self.storage.store_request(request)
            except Exception as storage_error:
                logger.warning(
                    "Failed to update rejected request in LDAP:"
                    f" {storage_error}"
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
        logger.debug(f"Getting certificate with serial_number={serial_number}")
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
        self.storage.update_certificate(cert_record)

        logger.debug(
            f"Certificate {serial_number} revoked with reason {reason.name}"
        )

    def put_certificate_on_hold(self, serial_number: int):
        """Put certificate on hold"""
        cert_record = self.storage.get_certificate(serial_number)
        if not cert_record:
            raise errors.NotFound(
                reason=f"Certificate {serial_number} not found"
            )

        cert_record.put_on_hold()
        self.storage.update_certificate(cert_record)

        logger.debug(f"Certificate {serial_number} put on hold")

    def take_certificate_off_hold(self, serial_number: int):
        """Remove certificate from hold"""
        cert_record = self.storage.get_certificate(serial_number)
        if not cert_record:
            raise errors.NotFound(
                reason=f"Certificate {serial_number} not found"
            )

        cert_record.take_off_hold()
        self.storage.update_certificate(cert_record)

        logger.debug(f"Certificate {serial_number} taken off hold")

    def generate_crl(self) -> x509.CertificateRevocationList:
        """Generate Certificate Revocation List

        Uses configuration settings matching Dogtag CS.cfg:
        - ca.crl.MasterCRL.autoUpdateInterval (crl_update_interval)
        - ca.crl.MasterCRL.nextUpdateGracePeriod (crl_next_update_grace_period)
        """
        # Ensure CA cert and key are loaded
        self._ensure_ca_loaded()

        # Read CRL timing from config
        _, next_update_minutes = self._get_crl_timing()

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
        # Check cache first (fast path)
        request = self.requests.get(request_id)

        if request is not None:
            logger.debug(f"Request {request_id} found in cache")
            return request

        # Cache miss - check LDAP storage (slow path)
        logger.debug(
            f"Request {request_id} not in cache, checking LDAP storage"
        )
        request = self.storage.get_request(request_id)

        if request is not None:
            # Restore to cache for future lookups
            self.requests[request_id] = request
            logger.debug(
                f"Request {request_id} restored to cache from LDAP storage"
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
