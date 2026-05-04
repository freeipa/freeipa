# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Certificate data types and enumerations

Extracted from ca.py to break circular imports between ca and storage
modules.  Both ca.py (re-exports) and storage_certificates.py import
from here.
"""

import datetime
import enum
import logging
import os
import threading
from typing import Optional, List, Dict, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ipalib import errors
from ipathinca.certificate_lifecycle import (
    CertificateLifecycle,
    CertificateState,
    CertificateEvent,
    InvalidStateTransition,
)


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
                cls._request_counter = (
                    int(
                        datetime.datetime.now(
                            datetime.timezone.utc
                        ).timestamp()
                        * 1_000_000
                    )
                    * 65536
                    + pid
                )
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
                "Failed to issue certificate %s: %s", self.serial_number, e
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
        """
        # Handle CERTIFICATE_HOLD specially (maps to HOLD event, not REVOKE)
        if reason == RevocationReason.CERTIFICATE_HOLD:
            self.put_on_hold(principal=principal)
            return

        reason_str = REVOCATION_REASON_TO_STRING.get(reason, "unspecified")

        try:
            self.lifecycle.transition(
                CertificateEvent.REVOKE,
                principal=principal,
                reason=reason_str,
            )
            logger.info(
                "Certificate %s revoked: %s by %s",
                self.serial_number,
                reason_str,
                principal,
            )
        except InvalidStateTransition as e:
            logger.error(
                "Cannot revoke certificate %s: %s", self.serial_number, e
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
        """
        try:
            self.lifecycle.transition(
                CertificateEvent.HOLD,
                principal=principal,
                reason="certificateHold",
            )
            logger.info(
                "Certificate %s put on hold by %s",
                self.serial_number,
                principal,
            )
        except InvalidStateTransition as e:
            logger.error(
                "Cannot put certificate %s on hold: %s", self.serial_number, e
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
        """
        try:
            self.lifecycle.transition(
                CertificateEvent.RELEASE,
                principal=principal,
                reason="Released from hold",
            )
            logger.info(
                "Certificate %s released from hold by %s",
                self.serial_number,
                principal or "system",
            )
        except InvalidStateTransition as e:
            logger.error(
                "Cannot release certificate %s from hold: %s",
                self.serial_number,
                e,
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
            logger.info("Certificate %s marked as expired", self.serial_number)
        except InvalidStateTransition as e:
            # Expired certificates might already be revoked, that's OK
            logger.debug(
                "Cannot mark certificate %s as expired: %s",
                self.serial_number,
                e,
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
                "Certificate %s superseded by %s",
                self.serial_number,
                replacement_serial,
            )
        except InvalidStateTransition as e:
            logger.error(
                "Cannot supersede certificate %s: %s", self.serial_number, e
            )
            raise errors.CertificateOperationError(error=str(e))

    def get_state_history(self) -> List[Dict[str, Any]]:
        """
        Get complete state transition history

        Returns:
            List of state transitions with timestamps, principals, and reasons
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
