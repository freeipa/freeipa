# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Storage module extracted from storage_ca.py for modularity
"""

from __future__ import absolute_import

import logging
from typing import Dict, Any, List
import secrets
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ipathinca.storage_base import BaseStorageBackend
from ipalib import errors
from ipapython.dn import DN
from ipathinca import x509_utils
from ipathinca.ca import (
    CertificateRecord,
    RevocationReason,
    CertificateRequest,
)
from ipathinca.storage_base import biginteger_to_db

# Import LDAP filter escaping from shared location
from ipathinca.storage_base import escape_filter_chars


logger = logging.getLogger(__name__)


class CertificateStorage(BaseStorageBackend):
    """Storage operations"""

    def store_certificate(self, cert_record, allow_update=True):
        """
        Store certificate in Dogtag-compatible LDAP schema

        Args:
            cert_record: CertificateRecord object to store
            allow_update: If False, raise an error if certificate already
                          exists (default: True for backward compatibility)
        """
        with self._get_ldap_connection() as ldap:

            serial = str(cert_record.serial_number)
            cert_dn = DN(("cn", serial), self.certs_base_dn)

            # Encode certificate as DER
            cert_der = cert_record.certificate.public_bytes(
                serialization.Encoding.DER
            )

            # Extract certificate details
            subject = x509_utils.get_subject_dn_str(cert_record.certificate)
            issuer = x509_utils.get_issuer_dn_str(cert_record.certificate)
            not_before = (
                cert_record.certificate.not_valid_before_utc.isoformat()
            )
            not_after = cert_record.certificate.not_valid_after_utc.isoformat()

            try:
                # Check if certificate already exists
                existing_entry = ldap.get_entry(cert_dn)

                if not allow_update:
                    raise errors.DuplicateEntry(
                        message=f"Certificate {serial} already exists "
                        "and allow_update=False"
                    )

                # Update existing entry
                logger.debug(
                    f"Updating certificate {serial} in LDAP (Dogtag schema)"
                )
                # Map ipathinca status to Dogtag status
                dogtag_status = self._map_status_to_dogtag(
                    cert_record.status.value
                )
                existing_entry["certStatus"] = [dogtag_status]
                existing_entry["dateOfCreate"] = [
                    cert_record.issued_at.isoformat()
                ]

                # Handle revocation attributes
                if cert_record.revoked_at:
                    existing_entry["revokedOn"] = [
                        cert_record.revoked_at.isoformat()
                    ]
                else:
                    if "revokedOn" in existing_entry:
                        del existing_entry["revokedOn"]

                if cert_record.revocation_reason:
                    existing_entry["revInfo"] = [
                        str(cert_record.revocation_reason.value)
                    ]
                else:
                    if "revInfo" in existing_entry:
                        del existing_entry["revInfo"]

                ldap.update_entry(existing_entry)

            except errors.NotFound:
                # Create new entry using Dogtag objectClass
                logger.debug(
                    f"Storing new certificate {serial} in LDAP (Dogtag schema)"
                    f" at {cert_dn}"
                )

                # Map ipathinca status to Dogtag status
                dogtag_status = self._map_status_to_dogtag(
                    cert_record.status.value
                )

                # Encode serial number using Dogtag's length-prefixed format
                # for sortable LDAP storage
                encoded_serial = biginteger_to_db(cert_record.serial_number)

                entry_attrs = {
                    "objectClass": ["top", "certificateRecord"],
                    "cn": [serial],  # Plain decimal for DN lookups
                    "serialno": [encoded_serial],  # Encoded for LDAP sorting
                    "subjectName": [subject],
                    "issuerName": [issuer],
                    "notBefore": [not_before],
                    "notAfter": [not_after],
                    "certStatus": [dogtag_status],
                    "userCertificate;binary": [cert_der],
                    "dateOfCreate": [cert_record.issued_at.isoformat()],
                }

                # Note: requestId is not stored in certificate entries in
                # Dogtag schema
                # The relationship is tracked via the request entry, not the
                # certificate entry

                if cert_record.revoked_at:
                    entry_attrs["revokedOn"] = [
                        cert_record.revoked_at.isoformat()
                    ]

                if cert_record.revocation_reason:
                    entry_attrs["revInfo"] = [
                        str(cert_record.revocation_reason.value)
                    ]

                entry = ldap.make_entry(cert_dn, **entry_attrs)
                ldap.add_entry(entry)
                logger.debug(
                    f"Successfully stored certificate {serial} in LDAP (Dogtag"
                    " schema)"
                )

    def _map_status_to_dogtag(self, status: str) -> str:
        """Map ipathinca status values to Dogtag status values"""
        # Dogtag uses: VALID, INVALID, REVOKED, EXPIRED, REVOKED_EXPIRED
        status_map = {
            "VALID": "VALID",
            "REVOKED": "REVOKED",
            "EXPIRED": "EXPIRED",
            # Dogtag doesn't have ON_HOLD, map to REVOKED
            "ON_HOLD": "REVOKED",
            "PENDING": "VALID",  # Dogtag doesn't have PENDING at cert level
        }
        return status_map.get(status, "VALID")

    def _map_status_from_dogtag(self, status: str) -> str:
        """Map Dogtag status values to ipathinca status values"""
        status_map = {
            "VALID": "VALID",
            "REVOKED": "REVOKED",
            "EXPIRED": "EXPIRED",
            "REVOKED_EXPIRED": "REVOKED",
            "INVALID": "REVOKED",
        }
        return status_map.get(status, "VALID")

    def get_certificate(self, serial_number: int):
        """
        Retrieve certificate from Dogtag-compatible LDAP schema

        Args:
            serial_number: Certificate serial number

        Returns:
            CertificateRecord object or None
        """

        logger.debug(
            "CAStorageBackend.get_certificate: serial_number=%s " "(type: %s)",
            serial_number,
            type(serial_number).__name__,
        )

        with self._get_ldap_connection() as ldap:
            logger.debug("LDAP connection established successfully")

            serial = str(serial_number)
            cert_dn = DN(("cn", serial), self.certs_base_dn)

            logger.debug(
                "Retrieving certificate from LDAP: serial=%s, dn=%s",
                serial_number,
                cert_dn,
            )

            try:
                entry = ldap.get_entry(cert_dn)
                logger.debug(
                    "Found LDAP entry for serial %s: %s",
                    serial_number,
                    entry.dn,
                )

                # Decode certificate - Dogtag uses userCertificate;binary
                logger.debug(
                    "Attempting to decode certificate from"
                    " userCertificate;binary attribute..."
                )

                # Try different attribute names (Dogtag can use different
                # formats)
                cert_data = None
                for attr_name in [
                    "usercertificate;binary",
                    "usercertificate",
                    "userCertificate;binary",
                    "userCertificate",
                ]:
                    if attr_name in entry:
                        cert_data = entry[attr_name][0]
                        logger.debug(
                            f"Found certificate in attribute: {attr_name}"
                        )
                        break

                if cert_data is None:
                    logger.error("Certificate data not found in entry")
                    return None

                logger.debug(
                    "Retrieved cert_data, type: %s, length: %s",
                    type(cert_data).__name__,
                    len(cert_data) if hasattr(cert_data, "__len__") else "N/A",
                )

                # Use shared utility to handle multiple certificate formats
                certificate = x509_utils.load_certificate_from_ldap_data(
                    cert_data
                )
                logger.debug(
                    "Certificate decoded successfully using shared utility"
                )

                # Extract profile - Dogtag may not have this, default to
                # 'unknown'
                profile = "unknown"

                # Extract request ID if available
                request_id = None
                if "requestid" in entry or "requestId" in entry:
                    request_id = entry.get(
                        "requestid", entry.get("requestId", [None])
                    )[0]
                    if request_id and isinstance(request_id, bytes):
                        request_id = request_id.decode("utf-8")
                logger.debug(f"Request ID: {request_id}")

                # Create dummy request for CertificateRecord
                logger.debug("Creating dummy CertificateRequest...")
                dummy_request = CertificateRequest(csr=None, profile=profile)
                if request_id:
                    dummy_request.request_id = request_id
                logger.debug("Dummy request created successfully")

                # Create CertificateRecord (this creates it in VALID state)
                logger.debug("Creating CertificateRecord...")
                cert_record = CertificateRecord(
                    certificate, dummy_request, principal="ldap_restore"
                )
                logger.debug("CertificateRecord created successfully")
                cert_record.serial_number = int(serial)
                logger.debug(f"Serial number set to {int(serial)}")

                # Extract status from LDAP
                logger.debug("Parsing certificate status...")
                status_str = entry.get(
                    "certstatus", entry.get("certStatus", ["VALID"])
                )[0]
                if isinstance(status_str, bytes):
                    status_str = status_str.decode("utf-8")

                # Map Dogtag status to ipathinca status
                status_str = self._map_status_from_dogtag(status_str)
                logger.debug(
                    f"Status string (decoded and mapped): {status_str}"
                )

                # Extract issued_at timestamp
                created = entry.get(
                    "dateofcreate",
                    entry.get(
                        "dateOfCreate",
                        [datetime.now(timezone.utc).isoformat()],
                    ),
                )[0]
                if isinstance(created, bytes):
                    created = created.decode("utf-8")
                issued_at = datetime.fromisoformat(created)
                cert_record.issued_at = issued_at

                # Extract revocation_reason if present
                revocation_reason = None
                if "revinfo" in entry or "revInfo" in entry:
                    reason = entry.get(
                        "revinfo", entry.get("revInfo", [None])
                    )[0]
                    if reason:
                        if isinstance(reason, bytes):
                            reason = reason.decode("utf-8")
                        revocation_reason = RevocationReason(int(reason))

                # Reconstruct lifecycle state to match LDAP data
                logger.debug(
                    f"Reconstructing lifecycle state: status_str={status_str},"
                    f" revocation_reason={revocation_reason}"
                )

                if status_str == "REVOKED":
                    # Dogtag stores ON_HOLD as REVOKED with revInfo=6
                    # Check if this is actually a certificate on hold
                    if revocation_reason == RevocationReason.CERTIFICATE_HOLD:
                        cert_record.put_on_hold(principal="ldap_restore")
                        logger.debug(
                            "Transitioned to ON_HOLD state (from"
                            " REVOKED+reason=6)"
                        )
                    else:
                        cert_record.revoke(
                            reason=revocation_reason
                            or RevocationReason.UNSPECIFIED,
                            principal="ldap_restore",
                        )
                        logger.debug("Transitioned to REVOKED state")
                elif status_str == "ON_HOLD":
                    cert_record.put_on_hold(principal="ldap_restore")
                    logger.debug("Transitioned to ON_HOLD state")
                elif status_str == "EXPIRED":
                    cert_record.mark_as_expired(principal="ldap_restore")
                    logger.debug("Transitioned to EXPIRED state")

                return cert_record

            except errors.NotFound:
                logger.debug(
                    f"Certificate with serial {serial_number} not found in"
                    " LDAP (Dogtag schema)"
                )
                return None
            except Exception as e:
                logger.error(
                    "Unexpected error retrieving certificate"
                    f" {serial_number}: {e}",
                    exc_info=True,
                )
                return None

    def find_certificates(self, criteria: Dict[str, Any] = None) -> List:
        """
        Search certificates in Dogtag-compatible LDAP schema

        Args:
            criteria: Search criteria dictionary
                - subject: Subject DN substring search
                - status: Certificate status (VALID, REVOKED, EXPIRED)
                - serial_number: Exact serial number match
                - min_serial_number: Minimum serial number (inclusive)
                - max_serial_number: Maximum serial number (inclusive)

        Returns:
            List of CertificateRecord objects
        """

        with self._get_ldap_connection() as ldap:
            criteria = criteria or {}

            # Build LDAP filter with proper escaping
            filters = ["(objectClass=certificateRecord)"]

            if "subject" in criteria:
                escaped_subject = escape_filter_chars(str(criteria["subject"]))
                filters.append(f"(subjectName=*{escaped_subject}*)")

            if "status" in criteria:
                dogtag_status = self._map_status_to_dogtag(criteria["status"])
                escaped_status = escape_filter_chars(str(dogtag_status))
                filters.append(f"(certStatus={escaped_status})")

            if "serial_number" in criteria:
                # Encode serial number for Dogtag format
                encoded_serial = biginteger_to_db(criteria["serial_number"])
                escaped_serial = escape_filter_chars(encoded_serial)
                filters.append(f"(serialno={escaped_serial})")

            # Range queries using encoded serialno for proper LDAP ordering
            if "min_serial_number" in criteria:
                # Encode minimum serial number for Dogtag format
                encoded_min = biginteger_to_db(criteria["min_serial_number"])
                escaped_min = escape_filter_chars(encoded_min)
                filters.append(f"(serialno>={escaped_min})")

            if "max_serial_number" in criteria:
                # Encode maximum serial number for Dogtag format
                encoded_max = biginteger_to_db(criteria["max_serial_number"])
                escaped_max = escape_filter_chars(encoded_max)
                filters.append(f"(serialno<={escaped_max})")

            # Combine filters
            if len(filters) > 1:
                ldap_filter = f"(&{''.join(filters)})"
            else:
                ldap_filter = filters[0]

            logger.debug(
                "Searching certificates with filter (Dogtag schema): "
                f"{ldap_filter}"
            )

            try:
                # OPTIMIZED: Fetch only required attributes for
                # CertificateRecord reconstruction (avoid fetching unused
                # attributes like subjectName, issuerName, notBefore, notAfter
                # which are also in the certificate)
                entries = ldap.get_entries(
                    self.certs_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter=ldap_filter,
                    attrs_list=[
                        "userCertificate;binary",  # Primary cert storage
                        "usercertificate;binary",  # Alternate format
                        "serialno",
                        "cn",
                        "certStatus",
                        "dateOfCreate",
                        "revInfo",
                        "requestId",
                    ],
                )

                results = []
                for entry in entries:
                    # Decode certificate
                    cert_data = None
                    for attr_name in [
                        "usercertificate;binary",
                        "usercertificate",
                        "userCertificate;binary",
                        "userCertificate",
                    ]:
                        if attr_name in entry:
                            cert_data = entry[attr_name][0]
                            break

                    if cert_data is None:
                        logger.warning(
                            f"Skipping entry {entry.dn} - no certificate data "
                            "found"
                        )
                        continue

                    certificate = x509_utils.load_certificate_from_ldap_data(
                        cert_data
                    )

                    # Create dummy request
                    dummy_request = CertificateRequest(
                        csr=None, profile="unknown"
                    )

                    if "requestid" in entry or "requestId" in entry:
                        request_id = entry.get(
                            "requestid", entry.get("requestId", [None])
                        )[0]
                        if request_id and isinstance(request_id, bytes):
                            request_id = request_id.decode("utf-8")
                        dummy_request.request_id = request_id

                    # Create CertificateRecord
                    cert_record = CertificateRecord(
                        certificate, dummy_request, principal="ldap_restore"
                    )

                    # Use cn for serial number (plain decimal)
                    # Note: serialno is encoded with Dogtag format, cn is not
                    serial = entry.get("cn", [None])[0]
                    if isinstance(serial, bytes):
                        serial = serial.decode("utf-8")
                    cert_record.serial_number = int(serial)

                    # Extract status
                    status_str = entry.get(
                        "certstatus", entry.get("certStatus", ["VALID"])
                    )[0]
                    if isinstance(status_str, bytes):
                        status_str = status_str.decode("utf-8")
                    status_str = self._map_status_from_dogtag(status_str)

                    # Extract issued_at
                    created = entry.get(
                        "dateofcreate",
                        entry.get(
                            "dateOfCreate",
                            [datetime.now(timezone.utc).isoformat()],
                        ),
                    )[0]
                    if isinstance(created, bytes):
                        created = created.decode("utf-8")
                    cert_record.issued_at = datetime.fromisoformat(created)

                    # Extract revocation_reason
                    revocation_reason = None
                    if "revinfo" in entry or "revInfo" in entry:
                        reason = entry.get(
                            "revinfo", entry.get("revInfo", [None])
                        )[0]
                        if reason:
                            if isinstance(reason, bytes):
                                reason = reason.decode("utf-8")
                            revocation_reason = RevocationReason(int(reason))

                    # Reconstruct lifecycle state
                    if status_str == "REVOKED":
                        # Dogtag stores ON_HOLD as REVOKED with revInfo=6
                        # Check if this is actually a certificate on hold
                        if (
                            revocation_reason
                            == RevocationReason.CERTIFICATE_HOLD
                        ):
                            cert_record.put_on_hold(principal="ldap_restore")
                        else:
                            cert_record.revoke(
                                reason=revocation_reason
                                or RevocationReason.UNSPECIFIED,
                                principal="ldap_restore",
                            )
                    elif status_str == "ON_HOLD":
                        cert_record.put_on_hold(principal="ldap_restore")
                    elif status_str == "EXPIRED":
                        cert_record.mark_as_expired(principal="ldap_restore")

                    results.append(cert_record)

                return results

            except errors.NotFound:
                return []

    def get_revoked_certificates(self) -> List:
        """Get all revoked certificates for CRL generation"""
        return self.find_certificates({"status": "REVOKED"})

    # ========================================================================
    # Batch Operations (Performance Optimization)
    # ========================================================================

    def bulk_store_certificates(self, cert_records: List) -> Dict[str, Any]:
        """
        Store multiple certificates in batch (Dogtag schema)

        Args:
            cert_records: List of CertificateRecord objects to store

        Returns:
            Dictionary with operation statistics
        """

        stats = {
            "total": len(cert_records),
            "stored": 0,
            "updated": 0,
            "failed": 0,
            "errors": [],
        }

        for cert_record in cert_records:
            try:
                self.store_certificate(cert_record)
                stats["stored"] += 1
            except Exception as e:
                stats["failed"] += 1
                stats["errors"].append(
                    f"Serial {cert_record.serial_number}: {str(e)}"
                )
                logger.warning(
                    "Failed to store certificate %s in bulk operation: %s",
                    cert_record.serial_number,
                    e,
                )

        logger.info(
            "Bulk store completed (Dogtag schema): %s stored, %s updated, "
            "%s failed out of %s total",
            stats["stored"],
            stats["updated"],
            stats["failed"],
            stats["total"],
        )
        return stats

    def bulk_revoke_certificates(
        self, serial_numbers: List[int], reason: int = 0
    ) -> Dict[str, Any]:
        """
        Revoke multiple certificates in batch (Dogtag schema)

        Args:
            serial_numbers: List of serial numbers to revoke
            reason: Revocation reason code

        Returns:
            Dictionary with operation statistics
        """
        with self._get_ldap_connection() as ldap:

            stats = {
                "total": len(serial_numbers),
                "revoked": 0,
                "not_found": 0,
                "failed": 0,
                "errors": [],
            }

            revocation_time = datetime.now(timezone.utc).isoformat()

            for serial_number in serial_numbers:
                try:
                    serial = str(serial_number)
                    cert_dn = DN(("cn", serial), self.certs_base_dn)

                    try:
                        entry = ldap.get_entry(cert_dn)

                        # Update entry with revocation info
                        entry["certStatus"] = ["REVOKED"]
                        entry["revokedOn"] = [revocation_time]
                        entry["revInfo"] = [str(reason)]

                        ldap.update_entry(entry)
                        stats["revoked"] += 1

                    except errors.NotFound:
                        stats["not_found"] += 1
                        stats["errors"].append(
                            f"Serial {serial_number}: not found"
                        )
                        logger.warning(
                            "Certificate %s not found for bulk revocation",
                            serial_number,
                        )

                except Exception as e:
                    stats["failed"] += 1
                    stats["errors"].append(f"Serial {serial_number}: {str(e)}")
                    logger.warning(
                        "Failed to revoke certificate %s in bulk"
                        " operation: %s",
                        serial_number,
                        e,
                    )

            logger.info(
                "Bulk revoke completed (Dogtag schema): %s revoked, %s not "
                "found, %s failed out of %s total",
                stats["revoked"],
                stats["not_found"],
                stats["failed"],
                stats["total"],
            )
            return stats

    # ========================================================================
    # Certificate Request Storage Operations
    # ========================================================================

    def store_request(self, cert_request):
        """
        Store certificate request in Dogtag-compatible LDAP schema

        Args:
            cert_request: CertificateRequest object to store
        """
        with self._get_ldap_connection() as ldap:

            request_id = cert_request.request_id
            request_dn = DN(("cn", request_id), self.requests_base_dn)

            # Encode CSR as PEM
            csr_pem = cert_request.csr.public_bytes(
                serialization.Encoding.PEM
            ).decode("ascii")

            try:
                # Check if request already exists
                existing_entry = ldap.get_entry(request_dn)

                # Update existing entry
                logger.debug(
                    f"Updating request {request_id} in LDAP (Dogtag schema)"
                )

                # Ensure extensibleObject is in objectClass (for older entries
                # that might not have it)
                existing_classes = existing_entry.get("objectClass", [])
                if "extensibleObject" not in existing_classes:
                    logger.debug(
                        "Adding extensibleObject to request"
                        f" {request_id} objectClass"
                    )
                    existing_entry["objectClass"] = existing_classes + [
                        "extensibleObject"
                    ]

                existing_entry["requestState"] = [cert_request.status]

                # Update profile if present
                if hasattr(cert_request, "profile") and cert_request.profile:
                    existing_entry["extdata-profile-id"] = [
                        cert_request.profile
                    ]

                if cert_request.serial_number:
                    existing_entry["extdata-cert-serial-number"] = [
                        str(cert_request.serial_number)
                    ]

                ldap.update_entry(existing_entry)

            except errors.NotFound:
                # Create new entry using Dogtag objectClass
                logger.debug(
                    f"Storing new request {request_id} in LDAP (Dogtag schema)"
                )

                entry_attrs = {
                    "objectClass": ["top", "request", "extensibleObject"],
                    "cn": [request_id],
                    "requestState": [cert_request.status],
                    "extdata-cert-request": [csr_pem],
                    "dateOfCreate": [cert_request.submitted_at.isoformat()],
                }

                # Store profile (using extdata-* attribute which
                # extensibleObject allows)
                if hasattr(cert_request, "profile") and cert_request.profile:
                    entry_attrs["extdata-profile-id"] = [cert_request.profile]

                if cert_request.serial_number:
                    entry_attrs["extdata-cert-serial-number"] = [
                        str(cert_request.serial_number)
                    ]

                try:
                    entry = ldap.make_entry(request_dn, **entry_attrs)
                    ldap.add_entry(entry)
                except errors.NotFound:
                    # Parent container doesn't exist - initialize schema and
                    # retry
                    logger.debug(
                        "Requests container not found, initializing schema"
                    )
                    self.initialize_schema()
                    # Retry the add
                    entry = ldap.make_entry(request_dn, **entry_attrs)
                    ldap.add_entry(entry)

    def get_request(self, request_id: str):
        """
        Retrieve certificate request from Dogtag-compatible LDAP schema

        Args:
            request_id: Request identifier

        Returns:
            CertificateRequest object or None
        """

        with self._get_ldap_connection() as ldap:
            request_dn = DN(("cn", request_id), self.requests_base_dn)

            try:
                entry = ldap.get_entry(request_dn)

                # Decode CSR
                csr_pem_attr = entry.get(
                    "extdata-cert-request", entry.get("requestData", [None])
                )[0]
                if csr_pem_attr is None:
                    logger.warning(f"Request {request_id} has no CSR data")
                    return None

                if isinstance(csr_pem_attr, bytes):
                    csr_pem = csr_pem_attr.decode("utf-8")
                else:
                    csr_pem = csr_pem_attr

                csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))

                # Extract profile from LDAP (use default if not present)
                profile = "unknown"  # Default if profile not stored
                if "extdata-profile-id" in entry:
                    profile_val = entry["extdata-profile-id"][0]
                    if isinstance(profile_val, bytes):
                        profile = profile_val.decode("utf-8")
                    else:
                        profile = profile_val

                # Create CertificateRequest
                cert_request = CertificateRequest(csr=csr, profile=profile)
                cert_request.request_id = request_id
                cert_request.status = entry.get(
                    "requeststate", entry.get("requestState", ["pending"])
                )[0]

                create_date = entry.get(
                    "dateofcreate",
                    entry.get(
                        "dateOfCreate",
                        [datetime.now(timezone.utc).isoformat()],
                    ),
                )[0]
                if isinstance(create_date, bytes):
                    create_date = create_date.decode("utf-8")
                cert_request.submitted_at = datetime.fromisoformat(create_date)

                # Extract serial number if present
                if "extdata-cert-serial-number" in entry:
                    serial_str = entry["extdata-cert-serial-number"][0]
                    if isinstance(serial_str, bytes):
                        serial_str = serial_str.decode("utf-8")
                    cert_request.serial_number = int(serial_str)

                return cert_request

            except errors.NotFound:
                return None

    def delete_request(self, request_id: str):
        """
        Delete a certificate request (Dogtag compatible)

        This is typically used for cleanup of old completed/rejected requests.
        In Dogtag, this is done by the PruningJob.

        Args:
            request_id: Request identifier to delete
        """
        with self._get_ldap_connection() as ldap:
            request_dn = DN(("cn", request_id), self.requests_base_dn)

            try:
                ldap.delete_entry(request_dn)
                logger.info(f"Deleted request {request_id}")
            except errors.NotFound:
                logger.warning(f"Request {request_id} not found for deletion")

    # ========================================================================
    # Serial Number Management
    # ========================================================================

    def get_next_serial_number(self) -> int:
        """
        Get next serial number (Dogtag-compatible)

        Returns:
            Next available serial number
        """
        if self.random_serial_numbers:
            # RSNv3: Generate cryptographically secure random serial number
            max_attempts = self.collision_recovery_attempts

            for attempt in range(max_attempts):
                # Generate random number with MSB set to ensure consistent
                # length
                # E.g., 128 bits = 32 hex digits, 160 bits = 40 hex digits
                random_serial = secrets.randbits(self.serial_number_bits) | (
                    1 << (self.serial_number_bits - 1)
                )

                # Check for collision - OPTIMIZED: Only check if entry exists,
                # don't fetch attributes
                cert_dn = DN(("cn", str(random_serial)), self.certs_base_dn)
                try:
                    with self._get_ldap_connection() as ldap:
                        # Only fetch DN to check existence (minimal overhead)
                        ldap.get_entry(cert_dn, attrs_list=["dn"])
                        logger.warning(
                            "Random serial number collision detected (attempt"
                            f" {attempt + 1}): {random_serial}."
                            " Regenerating..."
                        )
                        continue
                except errors.NotFound:
                    logger.debug(
                        f"Allocated random serial number: {random_serial}"
                    )
                    return random_serial

            # If we get here, all attempts failed
            raise RuntimeError(
                "Failed to generate unique random serial number after "
                f"{max_attempts} attempts"
            )
        else:
            # Sequential counter mode.
            # threading.Lock protects against concurrent threads within
            # one gunicorn worker.  With multiple workers (separate
            # processes), LDAP optimistic locking detects conflicts
            # (MidairCollision).  We retry on collision.
            max_retries = 10
            for attempt in range(max_retries):
                with self._serial_lock:
                    with self._get_ldap_connection() as ldap:
                        try:
                            entry = ldap.get_entry(self.config_dn)

                            # Get current serial number
                            current_serial = int(
                                entry.get(
                                    "serialno",
                                    entry.get("lastSerialNo", ["0"]),
                                )[0]
                            )

                            # Increment and allocate next serial
                            next_serial = current_serial + 1

                            # Update LDAP with new serial number
                            entry["serialno"] = [str(next_serial)]
                            entry["lastSerialNo"] = [str(next_serial)]
                            ldap.update_entry(entry)

                            logger.debug(
                                "Allocated serial number: %d", next_serial
                            )
                            return next_serial

                        except errors.MidairCollision:
                            if attempt < max_retries - 1:
                                logger.debug(
                                    "Serial number allocation collision "
                                    "(attempt %d/%d), retrying",
                                    attempt + 1,
                                    max_retries,
                                )
                                continue
                            raise

                        except errors.NotFound:
                            logger.debug(
                                "CA config entry not found, "
                                "initializing schema"
                            )
                            self.initialize_schema()
                            return self.get_next_serial_number()

    def get_next_crl_number(self) -> int:
        """
        Get next CRL number (Dogtag-compatible)

        Returns:
            Next available CRL number
        """
        max_retries = 10
        for attempt in range(max_retries):
            with self._get_ldap_connection() as ldap:
                try:
                    entry = ldap.get_entry(self.config_dn)

                    # Dogtag uses 'crlNumber'
                    current_crl_num = int(
                        entry.get(
                            "crlnumber", entry.get("crlNumber", ["0"])
                        )[0]
                    )
                    next_crl_num = current_crl_num + 1

                    # Update attribute
                    entry["crlNumber"] = [str(next_crl_num)]

                    ldap.update_entry(entry)

                    logger.debug(
                        "Allocated CRL number: %d", next_crl_num
                    )
                    return next_crl_num

                except errors.MidairCollision:
                    if attempt < max_retries - 1:
                        logger.debug(
                            "CRL number allocation collision "
                            "(attempt %d/%d), retrying",
                            attempt + 1,
                            max_retries,
                        )
                        continue
                    raise

                except errors.NotFound:
                    logger.debug(
                        "CA config entry not found, initializing schema"
                    )
                    self.initialize_schema()
                    return self.get_next_crl_number()
