# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Audit Logging for Python CA

This module provides comprehensive audit logging for all CA operations,
compatible with Dogtag PKI's audit log format and Common Criteria requirements.

Dogtag-compatible implementation:
- Uses audit signing certificate from NSSDB
- RSA-SHA256 digital signatures (not HMAC)
- Private key accessed via NSSDB (never exported)
"""

import hashlib
import logging
import base64
import secrets
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pathlib import Path
from logging.handlers import RotatingFileHandler

from cryptography.hazmat.primitives.asymmetric import padding

from ipaplatform.paths import paths
import ipathinca
from ipathinca import x509_utils
from ipathinca.nss_utils import NSSDatabase

logger = logging.getLogger(__name__)


# ============================================================================
# Audit Event Types (compatible with Dogtag PKI)
# ============================================================================


class AuditEvent:
    """Audit event type definitions"""

    # Authentication events
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAIL = "AUTH_FAIL"
    AUTHZ_SUCCESS = "AUTHZ_SUCCESS"
    AUTHZ_FAIL = "AUTHZ_FAIL"

    # Certificate lifecycle events
    CERT_REQUEST = "CERT_REQUEST"
    CERT_REQUEST_PROCESSED = "CERT_REQUEST_PROCESSED"
    CERT_STATUS_CHANGE_REQUEST = "CERT_STATUS_CHANGE_REQUEST"
    CERT_STATUS_CHANGE_REQUEST_PROCESSED = (
        "CERT_STATUS_CHANGE_REQUEST_PROCESSED"
    )

    # Profile events
    PROFILE_CERT_REQUEST = "PROFILE_CERT_REQUEST"
    CONFIG_CERT_PROFILE = "CONFIG_CERT_PROFILE"

    # CRL events
    CRL_GENERATION = "CRL_GENERATION"
    CRL_RETRIEVAL = "CRL_RETRIEVAL"

    # Key events
    KEY_GEN_ASYMMETRIC = "KEY_GEN_ASYMMETRIC"
    KEY_RECOVERY_REQUEST = "KEY_RECOVERY_REQUEST"
    KEY_RECOVERY_REQUEST_PROCESSED = "KEY_RECOVERY_REQUEST_PROCESSED"

    # CA management events
    CA_SIGNING = "CA_SIGNING"
    OCSP_GENERATION = "OCSP_GENERATION"
    SECURITY_DOMAIN_UPDATE = "SECURITY_DOMAIN_UPDATE"

    # Sub-CA events
    SUBCA_CREATION = "SUBCA_CREATION"
    SUBCA_DELETION = "SUBCA_DELETION"

    # Configuration events
    CONFIG_SERIAL_NUMBER = "CONFIG_SERIAL_NUMBER"
    CONFIG_TRUSTED_PUBLIC_KEY = "CONFIG_TRUSTED_PUBLIC_KEY"

    # Audit log events
    LOG_SIGNING = "LOG_SIGNING"
    AUDIT_LOG_STARTUP = "AUDIT_LOG_STARTUP"
    AUDIT_LOG_SHUTDOWN = "AUDIT_LOG_SHUTDOWN"

    # Role management
    ROLE_ASSUME = "ROLE_ASSUME"

    # Selftests
    SELFTESTS_EXECUTION = "SELFTESTS_EXECUTION"


class AuditOutcome:
    """Audit outcome values"""

    SUCCESS = "Success"
    FAILURE = "Failure"


# ============================================================================
# Audit Logger
# ============================================================================


class AuditLogger:
    """
    Audit logger for CA operations

    Implements signed audit logging compatible with Common Criteria and
    Dogtag PKI audit log format.
    """

    def __init__(
        self,
        log_file: str = None,
        max_size: int = 52428800,  # 50MB
        backup_count: int = 50,
        enable_signing: bool = True,
        audit_cert_nickname: str = "auditSigningCert cert-pki-ca",
    ):
        """
        Initialize audit logger

        Args:
            log_file: Path to audit log file (defaults to
                      /var/log/ipathinca/audit.log)
            max_size: Maximum log file size before rotation
            backup_count: Number of backup files to keep
            enable_signing: Enable log signing for tamper detection
            audit_cert_nickname: NSSDB nickname for audit signing cert
        """
        if log_file is None:
            log_file = f"{paths.IPATHINCA_LOG_DIR}/audit.log"
        self.log_file = Path(log_file)
        self.enable_signing = enable_signing
        self.audit_cert_nickname = audit_cert_nickname

        # Create log directory
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Create dedicated audit logger
        self.logger = logging.getLogger("ipa_ca_audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        # Create rotating file handler
        try:
            handler = RotatingFileHandler(
                str(self.log_file),
                maxBytes=max_size,
                backupCount=backup_count,
            )

            # Set format (compatible with Dogtag PKI)
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)

            self.logger.addHandler(handler)
        except (PermissionError, OSError) as e:
            # If we can't create the audit log file, just log to stderr
            logger.warning(
                f"Cannot create audit log file {self.log_file}: {e}"
            )
            logger.warning("Audit logging will be sent to stderr instead")
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        # Hash chain: each record includes the hash of the previous record
        self._previous_hash = ""

        # Load audit signing private key from NSSDB (Dogtag-compatible)
        if enable_signing:
            try:
                self.signing_key = self._load_signing_key_from_nssdb()
            except Exception as e:
                logger.warning(
                    f"Cannot load audit signing key from NSSDB: {e}"
                )
                logger.warning("Audit log signing will be disabled")
                self.signing_key = None
        else:
            self.signing_key = None

        # Log startup
        self.log_event(
            AuditEvent.AUDIT_LOG_STARTUP,
            outcome=AuditOutcome.SUCCESS,
            details={
                "log_file": str(self.log_file),
                "signing_enabled": self.enable_signing,
                "signing_cert": (
                    self.audit_cert_nickname if self.enable_signing else "N/A"
                ),
            },
        )

    def _load_signing_key_from_nssdb(self):
        """
        Load audit signing private key from NSSDB (Dogtag-compatible)

        Returns:
            RSA private key from NSSDB

        Raises:
            RuntimeError: If key cannot be loaded
        """

        try:
            nssdb = NSSDatabase()

            # Check if audit signing cert exists
            if not nssdb.cert_exists(self.audit_cert_nickname):
                raise RuntimeError(
                    "Audit signing certificate not found: "
                    f"{self.audit_cert_nickname}"
                )

            # Extract private key from NSSDB
            private_key = nssdb.extract_private_key(self.audit_cert_nickname)
            logger.debug(
                f"Loaded audit signing key from NSSDB: "
                f"{self.audit_cert_nickname}"
            )
            return private_key

        except Exception as e:
            logger.error(f"Failed to load audit signing key from NSSDB: {e}")
            raise

    def _sign_message(self, message: str) -> str:
        """
        Sign audit log message (RSA-SHA256 or configured algorithm)

        Args:
            message: Message to sign

        Returns:
            Base64-encoded signature
        """
        if not self.signing_key:
            return ""

        try:
            message_bytes = message.encode("utf-8")

            # Traditional RSA signature (read algorithm from config)
            # Matches Dogtag's ca.audit_signing.defaultSigningAlgorithm
            audit_alg = ipathinca.get_config_value(
                "ca", "audit_signing_algorithm", default="SHA256withRSA"
            )
            hash_alg = x509_utils.parse_signature_algorithm(audit_alg)
            signature_bytes = self.signing_key.sign(
                message_bytes, padding.PKCS1v15(), hash_alg
            )

            # Base64 encode for text log format
            signature = base64.b64encode(signature_bytes).decode("ascii")
            return signature

        except Exception as e:
            logger.error(f"Failed to sign audit message: {e}")
            return ""

    def log_event(
        self,
        event_type: str,
        outcome: str = AuditOutcome.SUCCESS,
        principal: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None,
    ):
        """
        Log audit event

        Args:
            event_type: Event type from AuditEvent
            outcome: Event outcome (Success/Failure)
            principal: User/principal performing the action
            details: Additional event details
            source_ip: Source IP address
        """
        details = details or {}

        # Build audit record (Dogtag PKI format)
        timestamp = datetime.now(timezone.utc).isoformat()

        audit_record = {
            "type": event_type,
            "outcome": outcome,
            "timestamp": timestamp,
            "principal": principal or "System",
            "source_ip": source_ip or "localhost",
        }

        # Add details
        audit_record.update(details)

        # Format as key=value pairs (Dogtag format)
        record_parts = []
        for key, value in audit_record.items():
            if value is not None:
                # Escape special characters
                value_str = str(value).replace(";", "\\;").replace("=", "\\=")
                record_parts.append(f"{key}={value_str}")

        record_parts.append(f"prev_hash={self._previous_hash}")
        record_line = "[" + "; ".join(record_parts) + "]"

        # Add signature if enabled
        if self.enable_signing:
            signature = self._sign_message(record_line)
            record_line += f" [signature={signature}]"

        # Update hash chain for next record
        self._previous_hash = hashlib.sha256(
            record_line.encode("utf-8")
        ).hexdigest()

        # Write to audit log
        self.logger.info(record_line)

    def log_action(
        self,
        principal: str,
        action: str,
        details: Dict[str, Any],
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """
        Log a user action

        Args:
            principal: User performing the action
            action: Action being performed
            details: Action details
            source_ip: Source IP address
            outcome: Action outcome
        """
        # Map action to event type
        event_mapping = {
            "request_certificate": AuditEvent.CERT_REQUEST,
            "sign_certificate": AuditEvent.CA_SIGNING,
            "revoke_certificate": AuditEvent.CERT_STATUS_CHANGE_REQUEST,
            "update_crl": AuditEvent.CRL_GENERATION,
            "create_profile": AuditEvent.CONFIG_CERT_PROFILE,
            "update_profile": AuditEvent.CONFIG_CERT_PROFILE,
            "delete_profile": AuditEvent.CONFIG_CERT_PROFILE,
            "create_subca": AuditEvent.SUBCA_CREATION,
            "delete_subca": AuditEvent.SUBCA_DELETION,
        }

        event_type = event_mapping.get(action, action)

        self.log_event(
            event_type=event_type,
            outcome=outcome,
            principal=principal,
            details=details,
            source_ip=source_ip,
        )

    def log_certificate_request(
        self,
        principal: str,
        request_id: str,
        profile: str,
        subject: str,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """Log certificate request"""
        self.log_event(
            event_type=AuditEvent.CERT_REQUEST,
            outcome=outcome,
            principal=principal,
            details={
                "request_id": request_id,
                "profile": profile,
                "subject": subject,
            },
            source_ip=source_ip,
        )

    def log_certificate_issued(
        self,
        principal: str,
        request_id: str,
        serial_number: str,
        subject: str,
        profile: str,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
        signing_algorithm: Optional[str] = None,
    ):
        """Log certificate issuance

        Args:
            principal: User or system issuing the certificate
            request_id: Certificate request ID
            serial_number: Certificate serial number
            subject: Certificate subject DN
            profile: Profile used for issuance
            source_ip: Source IP address
            outcome: Success or failure
            signing_algorithm: Signature algorithm used (e.g., "SHA256withRSA")
        """
        details = {
            "request_id": request_id,
            "serial_number": serial_number,
            "subject": subject,
            "profile": profile,
        }

        # Add signing algorithm if provided
        if signing_algorithm:
            details["signing_algorithm"] = signing_algorithm

        self.log_event(
            event_type=AuditEvent.CERT_REQUEST_PROCESSED,
            outcome=outcome,
            principal=principal,
            details=details,
            source_ip=source_ip,
        )

    def log_certificate_revoked(
        self,
        principal: str,
        serial_number: str,
        reason: str,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """Log certificate revocation"""
        self.log_event(
            event_type=AuditEvent.CERT_STATUS_CHANGE_REQUEST_PROCESSED,
            outcome=outcome,
            principal=principal,
            details={
                "serial_number": serial_number,
                "reason": reason,
                "new_status": "REVOKED",
            },
            source_ip=source_ip,
        )

    def log_certificate_unrevoked(
        self,
        principal: str,
        serial_number: str,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """Log certificate unrevocation (removal from hold)"""
        self.log_event(
            event_type=AuditEvent.CERT_STATUS_CHANGE_REQUEST_PROCESSED,
            outcome=outcome,
            principal=principal,
            details={
                "serial_number": serial_number,
                "action": "REMOVE_FROM_HOLD",
                "new_status": "VALID",
            },
            source_ip=source_ip,
        )

    def log_authentication(
        self,
        principal: str,
        auth_method: str,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """Log authentication attempt"""
        event_type = (
            AuditEvent.AUTH_SUCCESS
            if outcome == AuditOutcome.SUCCESS
            else AuditEvent.AUTH_FAIL
        )

        self.log_event(
            event_type=event_type,
            outcome=outcome,
            principal=principal,
            details={
                "auth_method": auth_method,
            },
            source_ip=source_ip,
        )

    def log_authorization(
        self,
        principal: str,
        permission: str,
        resource: str,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """Log authorization check"""
        event_type = (
            AuditEvent.AUTHZ_SUCCESS
            if outcome == AuditOutcome.SUCCESS
            else AuditEvent.AUTHZ_FAIL
        )

        self.log_event(
            event_type=event_type,
            outcome=outcome,
            principal=principal,
            details={
                "permission": permission,
                "resource": resource,
            },
            source_ip=source_ip,
        )

    def log_profile_operation(
        self,
        principal: str,
        operation: str,
        profile_id: str,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """Log profile management operation"""
        self.log_event(
            event_type=AuditEvent.CONFIG_CERT_PROFILE,
            outcome=outcome,
            principal=principal,
            details={
                "operation": operation,
                "profile_id": profile_id,
            },
            source_ip=source_ip,
        )

    def log_crl_generation(
        self,
        principal: str,
        crl_number: int,
        num_revoked: int,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """Log CRL generation"""
        self.log_event(
            event_type=AuditEvent.CRL_GENERATION,
            outcome=outcome,
            principal=principal,
            details={
                "crl_number": crl_number,
                "num_revoked_certs": num_revoked,
            },
            source_ip=source_ip,
        )

    def log_subca_operation(
        self,
        principal: str,
        operation: str,
        ca_id: str,
        subject: Optional[str] = None,
        source_ip: Optional[str] = None,
        outcome: str = AuditOutcome.SUCCESS,
    ):
        """Log sub-CA operation"""
        event_type = (
            AuditEvent.SUBCA_CREATION
            if operation == "create"
            else AuditEvent.SUBCA_DELETION
        )

        details = {
            "operation": operation,
            "ca_id": ca_id,
        }

        if subject:
            details["subject"] = subject

        self.log_event(
            event_type=event_type,
            outcome=outcome,
            principal=principal,
            details=details,
            source_ip=source_ip,
        )

    def verify_log_integrity(self, log_file: Optional[str] = None) -> bool:
        """
        Verify audit log integrity using signatures

        Args:
            log_file: Log file to verify (default: current log file)

        Returns:
            True if log is intact, False if tampered
        """
        if not self.enable_signing:
            logger.warning("Log signing not enabled, cannot verify integrity")
            return True

        log_path = Path(log_file) if log_file else self.log_file

        if not log_path.exists():
            logger.error(f"Log file not found: {log_path}")
            return False

        try:
            with open(log_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    if not line:
                        continue

                    # Extract message and signature
                    if "[signature=" not in line:
                        logger.warning(f"Line {line_num}: No signature found")
                        continue

                    parts = line.rsplit(" [signature=", 1)
                    message = parts[0]
                    signature = parts[1].rstrip("]")

                    # Verify signature
                    expected_signature = self._sign_message(message)

                    if not secrets.compare_digest(
                        signature, expected_signature
                    ):
                        logger.error(
                            f"Line {line_num}: Signature mismatch! Log may be "
                            "tampered."
                        )
                        return False

            logger.info(f"Log integrity verified: {log_path}")
            return True

        except Exception as e:
            logger.error(f"Error verifying log integrity: {e}")
            return False

    def close(self):
        """Close audit logger"""
        self.log_event(
            AuditEvent.AUDIT_LOG_SHUTDOWN,
            outcome=AuditOutcome.SUCCESS,
            details={"log_file": str(self.log_file)},
        )

        # Close handlers
        for handler in self.logger.handlers:
            handler.close()
            self.logger.removeHandler(handler)


# ============================================================================
# Global audit logger instance (lazy-initialized)
# ============================================================================

_audit_logger = None
_audit_logger_lock = threading.Lock()


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger, creating it on first use."""
    global _audit_logger
    if _audit_logger is None:
        with _audit_logger_lock:
            if _audit_logger is None:
                _audit_logger = AuditLogger()
    return _audit_logger


class _LazyAuditLogger:
    """Proxy that delays AuditLogger creation until first use.

    This allows ``from ipathinca.audit import audit_logger`` to work
    at import time (before NSSDB exists) without triggering key loading.
    """

    def __getattr__(self, name):
        return getattr(get_audit_logger(), name)


audit_logger = _LazyAuditLogger()


# ============================================================================
# Convenience functions
# ============================================================================


def log_audit_event(event_type: str, **kwargs):
    """Log audit event (convenience function)"""
    get_audit_logger().log_event(event_type, **kwargs)


def verify_audit_log(log_file: Optional[str] = None) -> bool:
    """Verify audit log integrity (convenience function)"""
    return get_audit_logger().verify_log_integrity(log_file)
