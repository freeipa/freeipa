# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
OCSP Responder Implementation

This module implements an OCSP (Online Certificate Status Protocol) responder
according to RFC 6960. It provides real-time certificate revocation checking
as an alternative to CRLs.

Features:
- RFC 6960 compliant OCSP responses
- Nonce support (replay attack prevention)
- Response caching for performance
- OCSP signing certificate management
- Support for delegated OCSP signing
"""

import hashlib
import logging
import os
import threading
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID

from ipaplatform.paths import paths

import ipathinca
from ipathinca import x509_utils

logger = logging.getLogger(__name__)


class OCSPResponse:
    """OCSP Response container"""

    def __init__(self, response_bytes: bytes, cache_until: datetime = None):
        self.response_bytes = response_bytes
        self.cache_until = cache_until or (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        )

    def is_expired(self) -> bool:
        """Check if cached response is expired"""
        return datetime.now(timezone.utc) > self.cache_until


class OCSPResponder:
    """
    OCSP Responder implementing RFC 6960

    Provides real-time certificate revocation status checking.
    """

    def __init__(
        self,
        ca,
        ocsp_cert_path: str = None,
        ocsp_key_path: str = None,
        cache_timeout: int = 300,
    ):
        """
        Initialize OCSP Responder

        Args:
            ca: Certificate Authority instance (PythonCA or InternalCA)
            ocsp_cert_path: Path to OCSP signing certificate (optional, will
                            use CA cert if not provided)
            ocsp_key_path: Path to OCSP signing private key (optional)
            cache_timeout: Response cache timeout in seconds (default:
                           300 = 5 minutes)
        """
        self.ca = ca
        self.cache_timeout = cache_timeout
        self.response_cache: OrderedDict = OrderedDict()
        self.cache_maxsize = 1000
        self._cache_lock = threading.Lock()

        # OCSP signing certificate paths
        self.ocsp_cert_path = Path(ocsp_cert_path) if ocsp_cert_path else None
        self.ocsp_key_path = Path(ocsp_key_path) if ocsp_key_path else None

        # Load or generate OCSP signing certificate
        self.ocsp_cert = None
        self.ocsp_key = None
        self._init_ocsp_signing_cert()

    def _init_ocsp_signing_cert(self):
        """Initialize OCSP signing certificate and key from filesystem

        IMPORTANT: OCSP signing keys are NEVER stored in LDAP, only on
        filesystem.
        This matches Dogtag behavior where CA/Sub-CA/OCSP signing keys are
        filesystem-only for security. Only KRA archived keys (for key recovery)
        are stored in LDAP.
        """
        # Load from filesystem if paths are provided
        if self.ocsp_cert_path and self.ocsp_cert_path.exists():
            logger.info(
                f"Loading OCSP signing certificate from {self.ocsp_cert_path}"
            )
            with open(self.ocsp_cert_path, "rb") as f:
                self.ocsp_cert = x509.load_pem_x509_certificate(f.read())

            if self.ocsp_key_path and self.ocsp_key_path.exists():
                with open(self.ocsp_key_path, "rb") as f:
                    self.ocsp_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
        else:
            # Generate OCSP signing certificate
            logger.info("Generating OCSP signing certificate")
            self._generate_ocsp_signing_cert()

    def _generate_ocsp_signing_cert(self):
        """Generate OCSP signing certificate"""
        try:
            # Ensure CA cert and key are loaded
            self.ca._ensure_ca_loaded()

            # Generate OCSP signing key (read size from config)
            ocsp_key_size = int(
                ipathinca.get_config_value(
                    "ca", "ocsp_signing_key_size", default="3072"
                )
            )
            self.ocsp_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=ocsp_key_size,
            )
            logger.info(f"Generated OCSP signing key ({ocsp_key_size} bits)")

            # Build OCSP signing certificate
            ca_cn = self.ca.ca_cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
            subject = x509_utils.build_x509_name(
                [("CN", f"OCSP Responder - {ca_cn}")]
            )

            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(self.ca.ca_cert.subject)
            builder = builder.public_key(self.ocsp_key.public_key())
            builder = builder.serial_number(self.ca._get_next_serial_number())

            # Set validity (1 year)
            now = datetime.now(timezone.utc)
            builder = builder.not_valid_before(now)
            builder = builder.not_valid_after(now + timedelta(days=365))

            # Add OCSP signing extension (critical)
            builder = builder.add_extension(
                x509_utils.get_ocsp_extended_key_usage(), critical=True
            )

            # Add key identifiers
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    self.ocsp_key.public_key()
                ),
                critical=False,
            )

            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca.ca_cert.public_key()
                ),
                critical=False,
            )

            # Sign the certificate with algorithm matching CA
            # OCSP signing certs use the CA's algorithm
            signing_alg = x509_utils.get_certificate_signature_algorithm(
                self.ca.ca_cert
            )
            hash_alg = x509_utils.parse_signature_algorithm(signing_alg)
            self.ocsp_cert = builder.sign(self.ca.ca_private_key, hash_alg)

            # Save to filesystem (OCSP keys are NEVER stored in LDAP)
            # This follows Dogtag behavior where CA/Sub-CA/OCSP signing keys
            # are filesystem-only
            if self.ocsp_cert_path:
                self.ocsp_cert_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.ocsp_cert_path, "wb") as f:
                    f.write(
                        self.ocsp_cert.public_bytes(serialization.Encoding.PEM)
                    )
                os.chmod(self.ocsp_cert_path, 0o644)

            if self.ocsp_key_path:
                self.ocsp_key_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.ocsp_key_path, "wb") as f:
                    f.write(
                        self.ocsp_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption(),
                        )
                    )
                os.chmod(self.ocsp_key_path, 0o600)

            logger.info(
                "OCSP signing certificate generated with serial "
                f"{self.ocsp_cert.serial_number}"
            )

        except Exception as e:
            logger.error(f"Failed to generate OCSP signing certificate: {e}")
            # Fall back to using CA cert for OCSP signing
            logger.warning(
                "Falling back to using CA certificate for OCSP signing"
            )
            self.ocsp_cert = self.ca.ca_cert
            self.ocsp_key = self.ca.ca_private_key

    def _get_cache_key(self, serial_number: int, nonce: bytes = None) -> str:
        """Generate cache key for OCSP response"""
        key_data = f"{serial_number}"
        if nonce:
            key_data += f":{nonce.hex()}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _get_cert_status(self, serial_number: int) -> Tuple[
        ocsp.OCSPCertStatus,
        Optional[datetime],
        Optional[x509.ReasonFlags],
        Optional[x509.Certificate],
    ]:
        """
        Get certificate status from CA

        Returns:
            Tuple of (status, revocation_time, revocation_reason, certificate)
        """
        try:
            cert_record = self.ca.get_certificate(serial_number)

            if not cert_record:
                return ocsp.OCSPCertStatus.UNKNOWN, None, None, None

            # Check if revoked
            if cert_record.status.value in ("REVOKED", "ON_HOLD"):
                # Map our RevocationReason to x509.ReasonFlags
                reason_map = {
                    0: x509.ReasonFlags.unspecified,
                    1: x509.ReasonFlags.key_compromise,
                    2: x509.ReasonFlags.ca_compromise,
                    3: x509.ReasonFlags.affiliation_changed,
                    4: x509.ReasonFlags.superseded,
                    5: x509.ReasonFlags.cessation_of_operation,
                    6: x509.ReasonFlags.certificate_hold,
                    9: x509.ReasonFlags.privilege_withdrawn,
                    10: x509.ReasonFlags.aa_compromise,
                }

                reason = None
                if cert_record.revocation_reason:
                    reason_value = (
                        cert_record.revocation_reason.value
                        if hasattr(cert_record.revocation_reason, "value")
                        else cert_record.revocation_reason
                    )
                    reason = reason_map.get(
                        reason_value, x509.ReasonFlags.unspecified
                    )

                return (
                    ocsp.OCSPCertStatus.REVOKED,
                    cert_record.revoked_at,
                    reason,
                    cert_record.certificate,
                )

            # Certificate is valid
            return (
                ocsp.OCSPCertStatus.GOOD,
                None,
                None,
                cert_record.certificate,
            )

        except Exception as e:
            logger.error(
                "Error checking certificate status for serial "
                f"{serial_number}: {e}"
            )
            return ocsp.OCSPCertStatus.UNKNOWN, None, None, None

    def create_response(self, request_der: bytes) -> bytes:
        """
        Create OCSP response from request

        Args:
            request_der: DER-encoded OCSP request

        Returns:
            DER-encoded OCSP response
        """
        try:
            # Parse OCSP request
            ocsp_req = ocsp.load_der_ocsp_request(request_der)

            # Extract nonce if present (for replay protection)
            nonce = None
            try:
                for ext in ocsp_req.extensions:
                    if ext.oid == ExtensionOID.OCSP_NONCE:
                        nonce = ext.value.nonce
                        break
            except x509.ExtensionNotFound:
                pass

            # Get certificate serial number from request
            serial_number = ocsp_req.serial_number

            # Check cache (thread-safe)
            cache_key = self._get_cache_key(serial_number, nonce)
            with self._cache_lock:
                cached_response = self.response_cache.get(cache_key)
            if cached_response is not None:
                if not cached_response.is_expired():
                    logger.debug(
                        "Returning cached OCSP response for serial "
                        f"{serial_number}"
                    )
                    return cached_response.response_bytes
                else:
                    # Remove expired entry
                    with self._cache_lock:
                        self.response_cache.pop(cache_key, None)

            # Ensure CA cert is loaded
            self.ca._ensure_ca_loaded()

            # Get certificate status and certificate object
            cert_status, revocation_time, revocation_reason, certificate = (
                self._get_cert_status(serial_number)
            )

            # Build response
            now = datetime.now(timezone.utc)

            # Create cert status based on revocation info
            if cert_status == ocsp.OCSPCertStatus.REVOKED:
                cert_status_obj = ocsp.OCSPCertStatus.REVOKED
                this_update = revocation_time or now
            elif cert_status == ocsp.OCSPCertStatus.GOOD:
                cert_status_obj = ocsp.OCSPCertStatus.GOOD
                this_update = now
            else:
                cert_status_obj = ocsp.OCSPCertStatus.UNKNOWN
                this_update = now

            next_update = now + timedelta(seconds=self.cache_timeout)

            # Build OCSP response
            builder = ocsp.OCSPResponseBuilder()

            # Use the actual certificate if available, fall back to CA cert
            # for unknown certificates
            resp_cert = certificate if certificate else self.ca.ca_cert

            # Add certificate status
            builder = builder.add_response(
                cert=resp_cert,
                issuer=self.ca.ca_cert,
                algorithm=ocsp_req.hash_algorithm,
                cert_status=cert_status_obj,
                this_update=this_update,
                next_update=next_update,
                revocation_time=revocation_time,
                revocation_reason=revocation_reason,
            )

            # Add nonce if present in request (echo it back)
            if nonce:
                builder = builder.add_extension(
                    x509.OCSPNonce(nonce), critical=False
                )

            # Sign the response with algorithm matching OCSP certificate
            # OCSP responses use the OCSP cert's algorithm
            signing_alg = x509_utils.get_certificate_signature_algorithm(
                self.ocsp_cert
            )
            hash_alg = x509_utils.parse_signature_algorithm(signing_alg)
            ocsp_response = builder.sign(self.ocsp_key, hash_alg)

            # Serialize response
            response_bytes = ocsp_response.public_bytes(
                serialization.Encoding.DER
            )

            # Cache the response (bounded: evict expired, then oldest)
            with self._cache_lock:
                expired_keys = [
                    k
                    for k, v in self.response_cache.items()
                    if v.is_expired()
                ]
                for k in expired_keys:
                    del self.response_cache[k]
                while len(self.response_cache) >= self.cache_maxsize:
                    self.response_cache.popitem(last=False)
                self.response_cache[cache_key] = OCSPResponse(
                    response_bytes, cache_until=next_update
                )

            logger.info(
                f"Created OCSP response for serial {serial_number}, status: "
                f"{cert_status.name}"
            )
            return response_bytes

        except Exception as e:
            logger.error(f"Error creating OCSP response: {e}")
            # Return internal error response
            return self._create_error_response()

    def _create_error_response(self) -> bytes:
        """Create OCSP error response"""
        builder = ocsp.OCSPResponseBuilder()
        error_response = builder.build_unsuccessful(
            ocsp.OCSPResponseStatus.INTERNAL_ERROR
        )
        return error_response.public_bytes(serialization.Encoding.DER)

    def clear_cache(self):
        """Clear response cache"""
        with self._cache_lock:
            self.response_cache.clear()
        logger.info("OCSP response cache cleared")

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        with self._cache_lock:
            total = len(self.response_cache)
            expired = sum(
                1
                for resp in self.response_cache.values()
                if resp.is_expired()
            )

        return {
            "total_entries": total,
            "expired_entries": expired,
            "valid_entries": total - expired,
            "cache_timeout": self.cache_timeout,
        }


class OCSPResponderManager:
    """
    Manager for OCSP Responder instances

    Handles multiple OCSP responders for different CAs (main CA + sub-CAs)
    """

    def __init__(self, base_storage_path: str = None):
        """
        Initialize OCSP Responder Manager

        Args:
            base_storage_path: Base path for OCSP cert/key storage
        """
        self.responders: Dict[str, OCSPResponder] = {}
        self._responders_lock = threading.Lock()
        self.base_storage_path = Path(
            base_storage_path or f"{paths.IPATHINCA_DIR}ocsp"
        )
        self.base_storage_path.mkdir(parents=True, exist_ok=True, mode=0o750)

    def get_responder(self, ca, ca_id: str = "ipa") -> OCSPResponder:
        """
        Get or create OCSP responder for a CA

        Args:
            ca: CA instance
            ca_id: CA identifier

        Returns:
            OCSPResponder instance
        """
        if ca_id not in self.responders:
            with self._responders_lock:
                if ca_id not in self.responders:
                    # Create paths for this CA
                    ocsp_cert_path = (
                        self.base_storage_path / f"{ca_id}_ocsp.crt"
                    )
                    ocsp_key_path = (
                        self.base_storage_path / f"{ca_id}_ocsp.key"
                    )

                    # Create responder
                    self.responders[ca_id] = OCSPResponder(
                        ca=ca,
                        ocsp_cert_path=str(ocsp_cert_path),
                        ocsp_key_path=str(ocsp_key_path),
                    )

                    logger.info(f"Created OCSP responder for CA: {ca_id}")

        return self.responders[ca_id]

    def clear_all_caches(self):
        """Clear all OCSP response caches"""
        with self._responders_lock:
            responders = dict(self.responders)
        for responder in responders.values():
            responder.clear_cache()
        logger.info("Cleared all OCSP response caches")

    def get_all_stats(self) -> Dict[str, Dict]:
        """Get statistics for all responders"""
        with self._responders_lock:
            responders = dict(self.responders)
        return {
            ca_id: responder.get_cache_stats()
            for ca_id, responder in responders.items()
        }


# Global OCSP responder manager instance
_ocsp_manager = None
_ocsp_manager_lock = threading.Lock()


def get_ocsp_manager(base_storage_path: str = None) -> OCSPResponderManager:
    """Get singleton OCSP responder manager"""
    global _ocsp_manager
    with _ocsp_manager_lock:
        if _ocsp_manager is None:
            _ocsp_manager = OCSPResponderManager(base_storage_path)
        return _ocsp_manager
