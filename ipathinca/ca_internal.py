# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
IPA's Internal Production CA Implementation

This module provides FreeIPA's internal production-ready CA implementation
that replaces external Dogtag/PKI dependencies. It extends the core PythonCA
(which provides LDAP storage and basic CA operations) with enterprise features
required for IPA production deployment:

Production Features Added (beyond PythonCA):
- **Comprehensive audit logging**: Full audit trail for compliance and security
- **Principal tracking**: Authentication and authorization integration
                          (principal parameter on all operations)
- **LDAP schema initialization**: Automated schema setup and validation
                                  (initialize_schema())

Inherited from PythonCA:
- LDAP storage backend (certificate and request persistence)
- Certificate signing and issuance
- Certificate revocation (revoke, hold, unhold)
- CRL generation
- Profile management integration

This is the CA implementation used by the FreeIPA ipathinca service through
PythonCABackend for production deployments.

Architecture:
    PythonCA (ca.py)
    ├── Core CA with LDAP storage
    │
    └── InternalCA (this file)
        ├── Adds: audit logging, principal tracking, sub-CA management,
        │         schema init

When to use InternalCA:
    - Production IPA deployments (ipathinca service) ← PRIMARY USE
    - REST API backend (backend.py)
    - Audit/compliance requirements

When to use PythonCA instead:
    - Testing without audit infrastructure
    - Tools without audit requirements (ACME, migration scripts)
    - Building blocks for composition (SubCA uses PythonCA to avoid circular
      deps)
    - Scenarios where audit logging is not needed

    key loading (matching Dogtag's pattern):
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ipalib import errors

import ipathinca
from ipathinca.ca import (
    PythonCA,
    CertificateRequest,
    CertificateRecord,
    RevocationReason,
)
from ipathinca.subca import SubCAManager
from ipathinca import x509_utils
from ipathinca.audit import audit_logger, AuditOutcome
from ipathinca.ldap_utils import is_main_ca_id

logger = logging.getLogger(__name__)


class InternalCA(PythonCA):
    """
    IPA's Internal Production CA with LDAP storage, authentication, and audit
    logging

    This class extends PythonCA with production-ready features for FreeIPA's
    internal CA deployment. It provides comprehensive audit logging, LDAP
    persistence, principal tracking, and sub-CA management.

    Replaces external Dogtag/PKI as IPA's internal CA implementation.
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
        Initialize IPA's internal production CA

        Args:
            ca_cert_path: Path to CA certificate file
            ca_key_path: Path to CA private key file
            ca_id: CA identifier
            random_serial_numbers: Use RSNv3 random serial numbers
                                       (default: False)
            config: RawConfigParser object from ipathinca.conf (optional)
        """
        # Initialize parent class with random serial number configuration
        super().__init__(
            ca_cert_path, ca_key_path, ca_id, random_serial_numbers, config
        )

        # Parent class creates self.storage (CAStorageBackend)
        # Create alias ldap_storage for backward compatibility with existing
        # code
        self.ldap_storage = self.storage

        # Initialize LDAP schema (always required for production CA)
        try:
            self.ldap_storage.initialize_schema()
            logger.debug("LDAP storage backend initialized successfully")
        except Exception as e:
            logger.error(
                f"Failed to initialize LDAP schema: {e}", exc_info=True
            )
            raise Exception(
                f"LDAP storage is required but failed to initialize: {e}"
            )

        # Initialize sub-CA manager with reference to main CA
        self.subca_manager = SubCAManager(main_ca=self)

    def _get_next_serial_number(self) -> int:
        """Generate next serial number for certificate via LDAP"""
        return self.ldap_storage.get_next_serial_number()

    def submit_certificate_request(
        self,
        csr_pem: str,
        profile: str = "caIPAserviceCert",
        principal: Optional[str] = None,
        ca_id: Optional[str] = None,
    ) -> str:
        """
        Submit a certificate signing request with audit logging

        Args:
            csr_pem: PEM-encoded certificate signing request
            profile: Certificate profile to use
            principal: User principal submitting the request
            ca_id: CA identifier (None for main CA, or sub-CA ID for

        Returns:
            Request ID for tracking
        """
        try:
            # Parse CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
            subject = str(x509_utils.cert_name_to_ipa_dn(csr.subject))

            # Create request record
            request = CertificateRequest(csr, profile)
            # Store CA ID with the request
            request.ca_id = ca_id
            logger.debug(
                f"Storing request {request.request_id} with ca_id={ca_id}"
            )

            # Store request in LDAP
            self.ldap_storage.store_request(request)

            # Audit log
            audit_logger.log_certificate_request(
                principal=principal or "System",
                request_id=request.request_id,
                profile=profile,
                subject=subject,
                outcome=AuditOutcome.SUCCESS,
            )

            logger.debug(
                f"Certificate request {request.request_id} submitted with "
                f"profile {profile}"
            )
            return request.request_id

        except Exception as e:
            # Audit log failure
            audit_logger.log_certificate_request(
                principal=principal or "System",
                request_id="FAILED",
                profile=profile,
                subject="UNKNOWN",
                outcome=AuditOutcome.FAILURE,
            )

            logger.error(f"Failed to submit certificate request: {e}")
            raise errors.CertificateOperationError(
                error=f"Failed to submit certificate request: {e}"
            )

    def sign_certificate_request(
        self, request_id: str, principal: Optional[str] = None
    ) -> int:
        """
        Sign a certificate request and issue certificate with audit logging

        Args:
            request_id: ID of the request to sign
            principal: User principal signing the request

        Returns:
            Serial number of issued certificate
        """
        # Ensure CA cert and key are loaded
        self._ensure_ca_loaded()

        # Get request from LDAP
        request = self.ldap_storage.get_request(request_id)

        if not request:
            audit_logger.log_certificate_issued(
                principal=principal or "System",
                request_id=request_id,
                serial_number="FAILED",
                subject="NOT_FOUND",
                profile="UNKNOWN",
                outcome=AuditOutcome.FAILURE,
            )
            raise errors.NotFound(
                reason=f"Certificate request {request_id} not found"
            )

        csr = request.csr

        try:
            # Determine which CA to use for signing
            signing_cert = self.ca_cert
            signing_key = self.ca_private_key
            ca_id = getattr(request, "ca_id", None)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "Signing request %s: ca_id from request = %s",
                    request_id,
                    ca_id,
                )

            # Check if ca_id is the main CA (by name or by UUID)
            is_main_ca = is_main_ca_id(ca_id, self.ca_id, self.config)

            if not is_main_ca:
                # Try to use sub-CA for signing, but fall back to main CA if
                # not found
                try:
                    subca = self.subca_manager.get_subca(ca_id)
                    if subca and subca.ca_cert and subca.ca_key:
                        signing_cert = subca.ca_cert
                        signing_key = subca.ca_key
                        logger.debug(
                            f"Using sub-CA {ca_id} to sign certificate"
                        )
                except Exception as e:
                    logger.debug(
                        f"Sub-CA lookup failed, falling back to main CA: {e}"
                    )

            # Generate serial number
            serial_number = self._get_next_serial_number()

            # Build certificate
            builder = x509.CertificateBuilder()
            builder = builder.serial_number(serial_number)
            builder = builder.issuer_name(signing_cert.subject)

            # Try to load Dogtag profile for full compatibility
            from ipathinca.profile import Profile
            from ipathinca import x509_utils

            try:
                profile = self.profile_manager.get_profile_for_signing(
                    request.profile
                )
                is_dogtag = isinstance(profile, Profile)
            except Exception as e:
                logger.warning(
                    f"Failed to load profile {request.profile}: {e}"
                )
                profile = None
                is_dogtag = False

            if is_dogtag:
                # Use Dogtag profile policy chain
                context = {
                    "request": {
                        "csr": csr,
                    },
                    "principal": principal,
                    "signing_algorithm": None,  # Will be set by
                    # SigningAlgDefault
                    "ca_certificate": signing_cert,
                }

                # Execute policy chain (sets subject, validity, extensions,
                # etc.)
                builder = self._execute_policy_chain(
                    profile, builder, csr, context
                )

                # Get signing algorithm from context (with config fallback)
                default_alg = ipathinca.get_config_value(
                    "ca", "default_signing_algorithm", default="SHA256withRSA"
                )
                signing_alg = context.get("signing_algorithm", default_alg)
            else:
                # Legacy profile path
                builder = builder.subject_name(csr.subject)
                builder = builder.public_key(csr.public_key())

                # Set validity period (1 year by default)
                now = datetime.now(timezone.utc)
                builder = builder.not_valid_before(now)
                builder = builder.not_valid_after(now + timedelta(days=365))

                # Add extensions based on profile
                builder = self._add_extensions_for_profile(
                    builder, request.profile, csr, signing_cert
                )

                # Default for legacy profiles (read from config)
                signing_alg = ipathinca.get_config_value(
                    "ca", "default_signing_algorithm", default="SHA256withRSA"
                )

            # Sign certificate with algorithm from profile
            hash_alg = x509_utils.parse_signature_algorithm(signing_alg)
            certificate = builder.sign(
                signing_key, hash_alg, default_backend()
            )

            # Store certificate record in LDAP
            # Use allow_update=False to detect serial number collisions
            cert_record = CertificateRecord(certificate, request)
            self.ldap_storage.store_certificate(
                cert_record, allow_update=False
            )
            logger.debug(
                f"Certificate {cert_record.serial_number} stored in LDAP "
                "successfully"
            )

            # Update request status (lowercase to match PKI CertRequestStatus
            # constants)
            request.status = "complete"
            request.serial_number = serial_number

            # Update request in LDAP
            self.ldap_storage.store_request(request)

            # Audit log
            audit_logger.log_certificate_issued(
                principal=principal or "System",
                request_id=request_id,
                serial_number=str(serial_number),
                subject=x509_utils.get_subject_dn_str(certificate),
                profile=request.profile,
                outcome=AuditOutcome.SUCCESS,
                signing_algorithm=signing_alg,
            )

            logger.debug(
                f"Certificate {serial_number} issued for request {request_id}"
            )
            return serial_number

        except Exception as e:
            # Audit log failure
            audit_logger.log_certificate_issued(
                principal=principal or "System",
                request_id=request_id,
                serial_number="FAILED",
                subject=str(x509_utils.cert_name_to_ipa_dn(csr.subject)),
                profile=request.profile,
                outcome=AuditOutcome.FAILURE,
            )

            logger.error(f"Failed to sign certificate: {e}")
            # Use lowercase to match PKI CertRequestStatus constants
            request.status = "rejected"
            self.ldap_storage.store_request(request)

            raise errors.CertificateOperationError(
                error=f"Failed to sign certificate: {e}"
            )

    def _execute_policy_chain(self, profile, builder, csr, context: dict):
        """Execute Dogtag profile policy chain

        This method executes the constraint validation and default application
        for each policy in the profile's policy chain.

        Args:
            profile: Profile object with policy chain
            builder: x509.CertificateBuilder
            csr: Certificate signing request
            context: Request context dictionary

        Returns:
            Modified certificate builder

        Raises:
            ValueError: If constraint validation fails
        """
        from ipathinca.profile import Profile

        # Check if this is a Dogtag profile with policy chain
        if not isinstance(profile, Profile):
            # Legacy profile - use old extension method
            logger.debug("Using legacy profile extension method")
            return builder

        logger.debug(
            "Executing Dogtag profile policy chain for "
            f"'{profile.profile_id}': {len(profile.policies)} policies"
        )

        # Execute each policy in order
        # NOTE: In Dogtag, defaults provide values and constraints validate
        # those values
        # So we apply the default FIRST, then validate the result
        for policy in profile.policies:
            # Apply default first (provides values)
            logger.debug(
                f"Policy {policy.number}: Applying "
                f"{policy.default.__class__.__name__}"
            )
            builder = policy.default.apply(builder, csr, context)

            # Run constraint validation on the result
            logger.debug(
                f"Policy {policy.number}: Validating with "
                f"{policy.constraint.__class__.__name__}"
            )
            errors = policy.constraint.validate(csr, context)
            if errors:
                logger.error(
                    f"Policy {policy.number} constraint validation FAILED: "
                    f"{errors}"
                )
                raise ValueError(
                    "Constraint validation failed for policy "
                    f"{policy.number}: {', '.join(errors)}"
                )

        logger.debug(
            "Policy chain completed. "
            "Signing algorithm: %s",
            context.get("signing_algorithm", "not set"),
        )

        return builder

    def get_certificate(
        self, serial_number: int
    ) -> Optional[CertificateRecord]:
        """Retrieve certificate by serial number from LDAP"""
        return self.ldap_storage.get_certificate(serial_number)

    def revoke_certificate(
        self,
        serial_number: int,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
        principal: Optional[str] = None,
    ):
        """Revoke a certificate with audit logging"""
        cert_record = self.ldap_storage.get_certificate(serial_number)

        if not cert_record:
            audit_logger.log_certificate_revoked(
                principal=principal or "System",
                serial_number=str(serial_number),
                reason="NOT_FOUND",
                outcome=AuditOutcome.FAILURE,
            )
            # Format serial number as hex to match Dogtag behavior
            serial_hex = f"0x{serial_number:x}"
            raise errors.NotFound(
                reason=f"Certificate ID {serial_hex} not found"
            )

        try:
            # Handle certificate hold separately from permanent revocation
            if reason == RevocationReason.CERTIFICATE_HOLD:
                cert_record.put_on_hold(principal=principal)
            else:
                cert_record.revoke(reason, principal=principal)

            self.ldap_storage.store_certificate(cert_record)

            # Audit log
            audit_logger.log_certificate_revoked(
                principal=principal or "System",
                serial_number=str(serial_number),
                reason=reason.name,
                outcome=AuditOutcome.SUCCESS,
            )

            logger.debug(
                f"Certificate {serial_number} revoked with reason "
                f"{reason.name}"
            )

        except Exception as e:
            audit_logger.log_certificate_revoked(
                principal=principal or "System",
                serial_number=str(serial_number),
                reason=reason.name,
                outcome=AuditOutcome.FAILURE,
            )
            logger.error(f"Failed to revoke certificate {serial_number}: {e}")
            raise

    def take_certificate_off_hold(
        self, serial_number: int, principal: Optional[str] = None
    ):
        """Remove certificate from hold with LDAP storage and audit logging"""
        cert_record = self.ldap_storage.get_certificate(serial_number)

        if not cert_record:
            audit_logger.log_certificate_unrevoked(
                principal=principal or "System",
                serial_number=str(serial_number),
                outcome=AuditOutcome.FAILURE,
            )
            # Format serial number as hex to match Dogtag behavior
            serial_hex = f"0x{serial_number:x}"
            raise errors.NotFound(
                reason=f"Certificate ID {serial_hex} not found"
            )

        try:
            cert_record.take_off_hold()
            self.ldap_storage.store_certificate(cert_record)

            # Audit log
            audit_logger.log_certificate_unrevoked(
                principal=principal or "System",
                serial_number=str(serial_number),
                outcome=AuditOutcome.SUCCESS,
            )

            logger.debug(f"Certificate {serial_number} taken off hold")

        except Exception as e:
            audit_logger.log_certificate_unrevoked(
                principal=principal or "System",
                serial_number=str(serial_number),
                outcome=AuditOutcome.FAILURE,
            )
            logger.error(
                f"Failed to take certificate {serial_number} off hold: {e}"
            )
            raise

    def find_certificates(
        self, criteria: Dict[str, Any] = None
    ) -> List[CertificateRecord]:
        """Search certificates by criteria in LDAP"""
        return self.ldap_storage.find_certificates(criteria)

    def generate_crl(
        self, principal: Optional[str] = None
    ) -> x509.CertificateRevocationList:
        """Generate Certificate Revocation List with audit logging"""
        self._ensure_ca_loaded()

        try:
            # Get next CRL number from LDAP storage
            crl_number = self.ldap_storage.get_next_crl_number()

            builder = x509.CertificateRevocationListBuilder()
            builder = builder.issuer_name(self.ca_cert.subject)

            now = datetime.now(timezone.utc)
            builder = builder.last_update(now)
            builder = builder.next_update(now + timedelta(days=1))

            # Add CRL Number extension (RFC 5280 requirement)
            builder = builder.add_extension(
                x509.CRLNumber(crl_number), critical=False
            )

            # Get revoked certificates from LDAP
            revoked_certs = self.ldap_storage.get_revoked_certificates()

            # Add revoked certificates
            num_revoked = 0
            for cert_record in revoked_certs:
                if cert_record.status == cert_record.status.REVOKED:
                    revoked_cert = x509.RevokedCertificateBuilder()
                    revoked_cert = revoked_cert.serial_number(
                        cert_record.serial_number
                    )
                    revoked_cert = revoked_cert.revocation_date(
                        cert_record.revoked_at
                    )

                    if cert_record.revocation_reason:
                        # Convert RevocationReason enum to cryptography
                        # ReasonFlags
                        reason_map = {
                            RevocationReason.UNSPECIFIED: (
                                x509.ReasonFlags.unspecified
                            ),
                            RevocationReason.KEY_COMPROMISE: (
                                x509.ReasonFlags.key_compromise
                            ),
                            RevocationReason.CA_COMPROMISE: (
                                x509.ReasonFlags.ca_compromise
                            ),
                            RevocationReason.AFFILIATION_CHANGED: (
                                x509.ReasonFlags.affiliation_changed
                            ),
                            RevocationReason.SUPERSEDED: (
                                x509.ReasonFlags.superseded
                            ),
                            RevocationReason.CESSATION_OF_OPERATION: (
                                x509.ReasonFlags.cessation_of_operation
                            ),
                            RevocationReason.CERTIFICATE_HOLD: (
                                x509.ReasonFlags.certificate_hold
                            ),
                            RevocationReason.PRIVILEGE_WITHDRAWN: (
                                x509.ReasonFlags.privilege_withdrawn
                            ),
                            RevocationReason.AA_COMPROMISE: (
                                x509.ReasonFlags.aa_compromise
                            ),
                            RevocationReason.REMOVE_FROM_CRL: (
                                x509.ReasonFlags.remove_from_crl
                            ),
                        }
                        reason_flag = reason_map.get(
                            cert_record.revocation_reason,
                            x509.ReasonFlags.unspecified,
                        )
                        revoked_cert = revoked_cert.add_extension(
                            x509.CRLReason(reason_flag),
                            critical=False,
                        )

                    builder = builder.add_revoked_certificate(
                        revoked_cert.build()
                    )
                    num_revoked += 1

            # Sign CRL with algorithm matching CA certificate
            # Extract algorithm from the CA cert that will sign this CRL
            from ipathinca import x509_utils

            signing_alg = x509_utils.get_certificate_signature_algorithm(
                self.ca_cert
            )
            hash_alg = x509_utils.parse_signature_algorithm(signing_alg)
            crl = builder.sign(
                self.ca_private_key, hash_alg, default_backend()
            )

            # Audit log
            audit_logger.log_crl_generation(
                principal=principal or "System",
                crl_number=crl_number,
                num_revoked=num_revoked,
                outcome=AuditOutcome.SUCCESS,
            )

            logger.debug(
                f"Generated CRL #{crl_number} with {num_revoked} revoked "
                "certificates"
            )
            return crl

        except Exception as e:
            audit_logger.log_crl_generation(
                principal=principal or "System",
                crl_number=0,
                num_revoked=0,
                outcome=AuditOutcome.FAILURE,
            )
            logger.error(
                "Failed to generate certificate revocation list "
                f"{principal}: {e}"
            )
            raise

    def get_request_status(
        self, request_id: str
    ) -> Optional[CertificateRequest]:
        """Get status of certificate request from LDAP"""
        return self.ldap_storage.get_request(request_id)
