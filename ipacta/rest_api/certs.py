# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import base64
import logging

from flask import Blueprint, Response, request, jsonify

import ipacta
import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import require_ca_backend
from ipacta.rest_api._utils import _search_certificates
from ipacta.exceptions import ProfileNotFound
from ipacta.rest_api._helpers import (
    handle_ca_errors,
    validate_input,
    require_agent_auth,
    validate_serial_number,
    validate_profile_id,
    validate_ca_id,
    error_response,
    success_response,
    CertificateHandler,
    RequestHandler,
)

logger = logging.getLogger(__name__)

bp = Blueprint("certs", __name__)


# ============================================================================
# Certificate Request Endpoints
# ============================================================================


@bp.route("/ca/rest/certrequests", methods=["POST"])
@bp.route("/ca/rest/agent/certrequests", methods=["POST"])
@bp.route("/ca/v2/certrequests", methods=["POST"])
@bp.route("/ca/v2/agent/certrequests", methods=["POST"])
@require_ca_backend
@handle_ca_errors
def submit_certificate_request():
    """
    Submit certificate request - compatible with PKI cert request API
    POST /ca/rest/certrequests
    """
    # Parse request data
    data = request.get_json()
    if not data:
        return error_response("BadRequest", "No request data provided", 400)

    # Extract and validate parameters
    profile_id = data.get("ProfileID") or "caIPAserviceCert"
    ca_id = data.get("AuthorityID")

    if not validate_profile_id(profile_id):
        return error_response(
            "BadRequest", f"Invalid profile ID format: {profile_id}", 400
        )
    if ca_id and not validate_ca_id(ca_id):
        return error_response(
            "BadRequest", f"Invalid CA ID format: {ca_id}", 400
        )

    # Extract CSR data
    csr_data = None
    if "Input" in data:
        # Dogtag REST API format: Input is an array of input objects
        # Each input object has Attribute array with name/value pairs
        for input_item in data.get("Input", []):
            # Look for cert_request in the Attribute array
            for attr in input_item.get("Attribute", []):
                if attr.get("name") == "cert_request":
                    csr_data = attr.get("Value")
                    break
            if csr_data:
                break
            # Legacy format: look for i_cert_request id with direct Value
            if input_item.get("id") == "i_cert_request":
                csr_data = input_item.get("Value")
                break
    elif "pkcs10" in data:
        csr_data = data.get("pkcs10")

    if not csr_data:
        logger.error(
            "No CSR data found in request. Data keys: %s", list(data.keys())
        )
        return error_response("BadRequest", "No CSR data provided", 400)

    # Decode CSR if base64 encoded
    if not csr_data.startswith("-----BEGIN"):
        if len(csr_data) > 65536:
            return error_response("BadRequest", "CSR data too large", 400)
        try:
            csr_data = base64.b64decode(csr_data).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as e:
            logger.warning("Failed to base64-decode CSR data: %s", e)

    # Fix PEM formatting - ensure proper line breaks
    # The CSR from Dogtag REST API often has headers/footers/data all on one
    # line
    # Handle both "CERTIFICATE REQUEST" (with space) and "CERTIFICATEREQUEST"
    # (no space)
    begin_marker = None
    end_marker = None

    if "-----BEGIN CERTIFICATE REQUEST-----" in csr_data:
        begin_marker = "-----BEGIN CERTIFICATE REQUEST-----"
        end_marker = "-----END CERTIFICATE REQUEST-----"
    elif "-----BEGIN CERTIFICATEREQUEST-----" in csr_data:
        # Some implementations use no space
        begin_marker = "-----BEGIN CERTIFICATEREQUEST-----"
        end_marker = "-----END CERTIFICATEREQUEST-----"

    if begin_marker and end_marker:
        # Split into parts
        parts = csr_data.split(begin_marker)
        if len(parts) == 2:
            data_and_footer = parts[1].split(end_marker)
            if len(data_and_footer) >= 1:
                # Get just the base64 data (remove any whitespace)
                b64_data = (
                    data_and_footer[0]
                    .replace("\n", "")
                    .replace(" ", "")
                    .replace("\r", "")
                    .strip()
                )
                if not b64_data:
                    raise ValueError("Empty CSR data between PEM markers")
                # Reformat with proper line breaks (64 chars per line)
                lines = [
                    b64_data[i : i + 64] for i in range(0, len(b64_data), 64)
                ]
                csr_data = "-----BEGIN CERTIFICATE REQUEST-----\n"
                csr_data += "\n".join(lines)
                csr_data += "\n-----END CERTIFICATE REQUEST-----\n"

    return RequestHandler.submit(csr_data, profile_id, _g.ca_backend, ca_id)


@bp.route("/ca/rest/certrequests/<request_id>", methods=["GET"])
@bp.route("/ca/rest/agent/certrequests/<request_id>", methods=["GET"])
@bp.route("/ca/v2/certrequests/<request_id>", methods=["GET"])
@bp.route("/ca/v2/agent/certrequests/<request_id>", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def get_certificate_request(request_id):
    """Get certificate request status"""
    get_certificate_request.__resource_type__ = "Request"
    return RequestHandler.get_status(request_id, _g.ca_backend)


@bp.route("/ca/rest/certrequests/<request_id>", methods=["DELETE"])
@bp.route("/ca/rest/agent/certrequests/<request_id>", methods=["DELETE"])
@bp.route("/ca/v2/certrequests/<request_id>", methods=["DELETE"])
@bp.route("/ca/v2/agent/certrequests/<request_id>", methods=["DELETE"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def delete_certificate_request(request_id):
    """
    Delete a certificate request

    This is used for cleanup of old completed/rejected requests.
    Dogtag uses this in its PruningJob for maintenance.
    Requires agent authentication.
    """
    try:
        storage = _g.ca_backend.ca.storage

        if hasattr(storage, "delete_request"):
            storage.delete_request(request_id)
            return (
                success_response(
                    {"message": f"Request {request_id} deleted successfully"}
                ),
                200,
            )
        else:
            return error_response(
                "NotImplemented", "Request deletion not available", 501
            )

    except Exception as e:
        logger.error(
            "Error deleting request %s: %s", request_id, e, exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to delete request: {str(e)}", 500
        )


@bp.route("/ca/rest/certrequests/profiles/<profile_id>", methods=["GET"])
@bp.route("/ca/v2/certrequests/profiles/<profile_id>", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def get_enrollment_template(profile_id):
    """
    Get enrollment template for a profile

    Returns a CertEnrollmentRequest template with all input fields for the
    profile.
    This is used by IPA to understand what fields are needed for certificate
    requests.
    """
    get_enrollment_template.__resource_type__ = "Profile"

    # Validate profile exists
    if not validate_profile_id(profile_id):
        return error_response(
            "BadRequest", f"Invalid profile ID format: {profile_id}", 400
        )

    profile = _g.ca_backend.profile_manager.get_profile(profile_id)
    if not profile:
        # Raise ProfileNotFound to be handled by @handle_ca_errors decorator
        # This will format the error to match Dogtag's format
        raise ProfileNotFound(profile_id)

    # Build enrollment template with minimal fields
    # IPA doesn't actually use most of these fields, it just needs to know the
    # profile exists
    template = {
        "ProfileId": profile_id,
        "Renewal": False,
        "RemoteAddr": "",
        "RemoteHost": "",
        "Input": [
            {
                "id": "i_cert_request",
                "ClassID": "certReqInputImpl",
                "Name": "Certificate Request Input",
                "Attribute": [
                    {
                        "name": "cert_request_type",
                        "Value": "",
                        "Descriptor": {
                            "Syntax": "cert_request_type",
                            "Description": "Certificate Request Type",
                        },
                    },
                    {
                        "name": "cert_request",
                        "Value": "",
                        "Descriptor": {
                            "Syntax": "cert_request",
                            "Description": "Certificate Request",
                        },
                    },
                ],
                "ConfigAttribute": [
                    {
                        "name": "cert_request_type",
                        "Value": "pkcs10",
                        "Descriptor": {
                            "Syntax": "string",
                            "Description": "Certificate Request Type",
                        },
                    },
                    {
                        "name": "cert_request",
                        "Value": "",
                        "Descriptor": {
                            "Syntax": "string",
                            "Description": "Certificate Request",
                        },
                    },
                ],
            }
        ],
    }

    return success_response(template)


# ============================================================================
# Certificate Management Endpoints
# ============================================================================


@bp.route("/ca/rest/certs/<serial_number>", methods=["GET"])
@bp.route("/ca/v2/certs/<serial_number>", methods=["GET"])
@require_ca_backend
@validate_input(serial_number=validate_serial_number)
@handle_ca_errors
def get_certificate_public(serial_number):
    """Get certificate by serial number (public endpoint)"""
    get_certificate_public.__resource_type__ = "Certificate"
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "REST API: get_certificate (public) called with serial_number=%s",
            serial_number,
        )

    return CertificateHandler.get(serial_number, _g.ca_backend)


@bp.route("/ca/rest/agent/certs/<serial_number>", methods=["GET"])
@bp.route("/ca/v2/agent/certs/<serial_number>", methods=["GET"])
@require_agent_auth  # SECURITY: Agent endpoint requires authentication
@require_ca_backend
@validate_input(serial_number=validate_serial_number)
@handle_ca_errors
def get_certificate_agent(serial_number):
    """Get certificate by serial number (agent endpoint - requires auth)"""
    get_certificate_agent.__resource_type__ = "Certificate"
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "REST API: get_certificate (agent) called with serial_number=%s",
            serial_number,
        )

    return CertificateHandler.get(serial_number, _g.ca_backend)


@bp.route("/ca/rest/certs", methods=["GET", "POST"])  # Dogtag compatibility
@bp.route("/ca/rest/certs/search", methods=["GET", "POST"])
@bp.route("/ca/v2/certs", methods=["GET", "POST"])
@bp.route("/ca/v2/certs/search", methods=["GET", "POST"])
@require_ca_backend
@handle_ca_errors
def search_certificates_public():
    """Search certificates (public endpoint)"""
    return _search_certificates(_g.ca_backend)


@bp.route("/ca/rest/agent/certs/search", methods=["GET", "POST"])
@bp.route("/ca/v2/agent/certs/search", methods=["GET", "POST"])
@require_agent_auth  # SECURITY: Agent endpoint requires authentication
@require_ca_backend
@handle_ca_errors
def search_certificates_agent():
    """Search certificates (agent endpoint - requires auth)"""
    return _search_certificates(_g.ca_backend)


@bp.route("/ca/rest/agent/certs/<serial_number>/revoke", methods=["POST"])
@bp.route("/ca/rest/certs/<serial_number>/revoke", methods=["POST"])
@bp.route("/ca/v2/agent/certs/<serial_number>/revoke", methods=["POST"])
@bp.route("/ca/v2/certs/<serial_number>/revoke", methods=["POST"])
@require_agent_auth
@require_ca_backend
@validate_input(serial_number=validate_serial_number)
@handle_ca_errors
def revoke_certificate(serial_number):
    """Revoke certificate"""
    revoke_certificate.__resource_type__ = "Certificate"
    data = request.get_json() or {}

    # Parse revocation reason - can be string name or integer code
    reason_value = data.get("Reason", 0)

    # Map Dogtag reason strings to integer codes
    reason_map = {
        "Unspecified": 0,
        "Key_Compromise": 1,
        "CA_Compromise": 2,
        "Affiliation_Changed": 3,
        "Superseded": 4,
        "Cessation_of_Operation": 5,
        "Certificate_Hold": 6,
        "Remove_from_CRL": 8,
        "Privilege_Withdrawn": 9,
        "AA_Compromise": 10,
    }

    if isinstance(reason_value, str):
        revocation_reason = reason_map.get(reason_value, 0)
    else:
        revocation_reason = reason_value

    return CertificateHandler.revoke(
        serial_number, revocation_reason, _g.ca_backend
    )


@bp.route(
    "/ca/rest/agent/certs/<serial_number>/revoke-ca", methods=["POST"]
)
@bp.route(
    "/ca/rest/agent/certs/<serial_number>/unrevoke", methods=["POST"]
)
@bp.route(
    "/ca/v2/agent/certs/<serial_number>/revoke-ca", methods=["POST"]
)
@bp.route(
    "/ca/v2/agent/certs/<serial_number>/unrevoke", methods=["POST"]
)
@require_agent_auth
@require_ca_backend
@validate_input(serial_number=validate_serial_number)
@handle_ca_errors
def unrevoke_certificate(serial_number):
    """Take certificate off hold"""
    unrevoke_certificate.__resource_type__ = "Certificate"
    return CertificateHandler.unrevoke(serial_number, _g.ca_backend)


# Bulk Certificate Operations
# ----------------------------------------------------------------------------


@bp.route("/ca/rest/certs/bulk-revoke", methods=["POST"])
@bp.route("/ca/v2/certs/bulk-revoke", methods=["POST"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def bulk_revoke_certificates():
    """
    Bulk revoke multiple certificates

    Request body:
    {
        "serial_numbers": [1, 2, 3, ...],
        "revocation_reason": 0  (optional, default: 0 = unspecified)
    }

    Returns:
    {
        "successful": [1, 2, 3],
        "failed": [{"serial": 4, "error": "..."}],
        "total": 4,
        "success_count": 3,
        "failure_count": 1
    }
    """
    try:
        data = request.get_json() or {}
        serial_numbers = data.get("serial_numbers", [])
        revocation_reason = data.get("revocation_reason", 0)

        if not serial_numbers:
            return error_response(
                "BadRequest", "serial_numbers is required", 400
            )

        if not isinstance(serial_numbers, list):
            return error_response(
                "BadRequest", "serial_numbers must be a list", 400
            )

        storage = _g.ca_backend.ca.storage

        if hasattr(storage, "bulk_revoke_certificates"):
            # Use storage's bulk method
            result = storage.bulk_revoke_certificates(
                serial_numbers, revocation_reason
            )
            return jsonify(result), 200
        else:
            # Fallback to individual revocations
            successful = []
            failed = []

            for serial in serial_numbers:
                try:
                    _g.ca_backend.revoke_certificate(
                        serial, revocation_reason=revocation_reason
                    )
                    successful.append(serial)
                except Exception as e:
                    failed.append({"serial": serial, "error": str(e)})

            return (
                jsonify(
                    {
                        "successful": successful,
                        "failed": failed,
                        "total": len(serial_numbers),
                        "success_count": len(successful),
                        "failure_count": len(failed),
                    }
                ),
                200,
            )

    except Exception as e:
        logger.error("Error in bulk revoke: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to bulk revoke: {str(e)}", 500
        )


@bp.route("/ca/rest/certs/revoked", methods=["GET"])
@bp.route("/ca/v2/certs/revoked", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def get_revoked_certificates():
    """
    Get list of revoked certificates

    This is useful for CRL generation and audit purposes.

    Query parameters:
        - limit: Maximum number of results (default: 1000)
        - offset: Skip first N results (default: 0)

    Returns list of revoked certificate serial numbers and revocation info
    """
    try:
        # Read max search returns from config
        # (matching Dogtag ca.maxSearchReturns)
        default_limit = int(
            ipacta.get_config_value(
                "ca", "max_search_returns", default="1000"
            )
        )
        try:
            limit = int(request.args.get("limit", default_limit))
            offset = int(request.args.get("offset", 0))
        except (ValueError, TypeError):
            return error_response(
                "BadRequest", "Invalid limit or offset parameter", 400
            )
        if limit < 1 or offset < 0:
            return error_response(
                "BadRequest",
                "limit must be >= 1 and offset must be >= 0",
                400,
            )

        storage = _g.ca_backend.ca.storage

        if hasattr(storage, "get_revoked_certificates"):
            revoked = storage.get_revoked_certificates()

            # Apply pagination
            total = len(revoked)
            paginated = revoked[offset : offset + limit]
            entries = [
                r.to_dict() if hasattr(r, "to_dict") else r
                for r in paginated
            ]

            return (
                jsonify(
                    {
                        "entries": entries,
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                    }
                ),
                200,
            )
        else:
            return error_response(
                "NotImplemented",
                "Revoked certificate listing not available",
                501,
            )

    except Exception as e:
        logger.error(
            "Error getting revoked certificates: %s", e, exc_info=True
        )
        return error_response(
            "InternalError",
            f"Failed to get revoked certificates: {str(e)}",
            500,
        )


# ============================================================================
# Legacy Certificate Display Endpoint
# ============================================================================


@bp.route("/ca/ee/ca/displayBySerial", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def display_by_serial():
    """
    Legacy Dogtag endpoint for certificate retrieval by serial number.
    Used by IPA's cert_show command.

    Query parameters:
    - serialNumber: Serial number in hex format (e.g., 0x0F4242)
    """
    display_by_serial.__resource_type__ = "Certificate"

    # Get and validate serial number
    serial_hex = request.args.get("serialNumber")
    if not serial_hex:
        return error_response(
            "BadRequest", "serialNumber parameter required", 400
        )

    # Convert hex to decimal
    validated_serial = validate_serial_number(serial_hex)
    if validated_serial is None:
        return error_response(
            "BadRequest", f"Invalid serial number: {serial_hex}", 400
        )

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Display certificate by serial: %s -> %s",
            serial_hex,
            validated_serial,
        )

    # Get and return certificate
    result = _g.ca_backend.get_certificate(validated_serial)
    return Response(result["certificate"], mimetype="application/x-pem-file")
