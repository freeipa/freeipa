# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
REST API Helper Functions and Classes

This module contains all the helper code for the REST API, including:
- Decorators for common patterns
- Handler classes for grouped operations
- Response builders
- Input validation
- Legacy Dogtag compatibility helpers

Separating these from rest_api.py makes the main module cleaner and
easier to maintain.
"""

import base64
import logging
import re
from functools import wraps
from typing import Dict, Any, Optional

from flask import jsonify, request

from ipalib import errors

logger = logging.getLogger(__name__)


# ============================================================================
# Decorators for Common Patterns
# ============================================================================


def require_ca_backend(f):
    """Decorator to auto-initialize backend before endpoint execution"""

    @wraps(f)
    def wrapper(*args, **kwargs):
        # Import here to avoid circular dependency
        from ipathinca.rest_api import init_ca

        init_ca()
        return f(*args, **kwargs)

    return wrapper


def handle_ca_errors(f):
    """Decorator to handle common CA errors consistently"""
    from ipathinca.exceptions import ProfileNotFound

    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ProfileNotFound as e:
            # Match Dogtag's new profile not found error message
            profile_id = e.profile_id
            error_msg = (
                f"Unable to get enrollment template for {profile_id}: "
                "Profile not found"
            )
            logger.error(f"Profile not found in {f.__name__}: {e}")
            return error_response(
                "BadRequestException",
                error_msg,
                400,
                class_name="com.netscape.certsrv.base.BadRequestException",
            )
        except errors.NotFound as e:
            resource_type = getattr(f, "__resource_type__", "Resource")
            # Extract error message - IPA errors store message in 'reason'
            # attribute
            error_msg = (
                getattr(e, "reason", None)
                or getattr(e, "message", None)
                or str(e)
            )
            if not error_msg:
                error_msg = f"{resource_type} not found"
            return error_response(f"{resource_type}NotFound", error_msg, 404)
        except errors.CertificateOperationError as e:
            logger.error(f"Certificate operation failed in {f.__name__}: {e}")
            error_msg = (
                getattr(e, "reason", None)
                or getattr(e, "message", None)
                or str(e)
            )
            return error_response("CertificateOperationError", error_msg, 400)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {e}", exc_info=True)
            return error_response("ServerError", str(e), 500)

    return wrapper


def validate_input(**validators):
    """Decorator to validate input parameters"""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Validate path parameters
            for param_name, validator in validators.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    validated = validator(value)
                    if validated is None or validated is False:
                        return error_response(
                            "BadRequest",
                            f"Invalid {param_name}: {value}",
                            400,
                        )
                    # Update with validated value if it's not just a boolean
                    if validated is not True:
                        kwargs[param_name] = validated
            return f(*args, **kwargs)

        return wrapper

    return decorator


def require_agent_auth(f):
    """
    Decorator to require authentication for agent endpoints

    SECURITY MODEL:
    ===============
    This decorator enforces client certificate authentication for privileged
    CA operations (certificate revocation, issuance, etc.).

    Authentication Method:
    - Client Certificate (Mutual TLS) - RA Agent Certificate (REQUIRED)
      - Required from ALL connections to agent endpoints
      - Validates certificate subject DN matches: CN=IPA RA
      - Supported natively by gunicorn (--cert-reqs 1 requests certs)
      - gunicorn exposes certificate via
        request.environ["gunicorn.socket"].getpeercert()
      - Used by IPA framework (hybrid_ra.py) and multi-server deployments

    Behavior matches Dogtag PKI:
    - No localhost trust exception (unlike earlier versions)
    - All agent endpoints require RA agent certificate
    - Public endpoints do NOT require authentication
    - Authentication enforced at application layer (not TLS layer)

    Connection Requirements (for AGENT endpoints only):
    - Same-server IPA framework (hybrid_ra.py): MUST provide client certificate
    - Same-server scripts/curl: MUST provide client certificate
    - Multi-server (other IPA servers): MUST provide client certificate
    - No exceptions - certificate required for all agent endpoint connections

    Returns 401 Unauthorized if authentication fails.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        authenticated = False
        auth_method = None
        principal = None
        remote_addr = request.remote_addr

        # SECURITY MODEL:
        # 1. Client Certificate (highest priority): Accepted from ANY IP
        # 2. Localhost Trust: Only 127.0.0.1/::1 in IPA context
        #
        # This allows:
        # - Client cert auth from any IP (including server's own IP)
        # - Localhost trust for IPA framework (hybrid_ra.py)
        # - Blocks unauthenticated access from server's public IP

        # Check for client certificate authentication FIRST (works from any IP)
        # This takes priority over localhost trust
        cert_subject_dn = None

        # Try Apache-style environment variables first (for reverse proxy
        # deployments)
        # Check both direct WSGI env vars and HTTP headers (RequestHeader)
        ssl_client_verify = request.environ.get(
            "SSL_CLIENT_VERIFY"
        ) or request.environ.get("HTTP_SSL_CLIENT_VERIFY")
        if ssl_client_verify == "SUCCESS":
            cert_subject_dn = request.environ.get(
                "SSL_CLIENT_S_DN"
            ) or request.environ.get("HTTP_SSL_CLIENT_S_DN")

        # If not found, try gunicorn's direct socket access
        if not cert_subject_dn:
            try:
                # gunicorn exposes the peer certificate via the socket
                sock = request.environ.get("gunicorn.socket")
                if sock:
                    peercert = sock.getpeercert()

                    if peercert:
                        # Extract subject DN from certificate
                        # peercert is a dict with 'subject' containing tuples
                        # of tuples
                        # Example: {'subject': ((('commonName', 'IPA RA'),),)}
                        subject = peercert.get("subject", ())
                        if subject:
                            # Convert to DN string format using standard
                            # attribute names
                            # Map long names to short names: commonName → CN,
                            # organizationName → O, etc.
                            attr_map = {
                                "commonName": "CN",
                                "organizationName": "O",
                                "organizationalUnitName": "OU",
                                "countryName": "C",
                                "stateOrProvinceName": "ST",
                                "localityName": "L",
                            }
                            dn_parts = []
                            for rdn in subject:
                                for attr, value in rdn:
                                    # Use short form if available, otherwise
                                    # use as-is
                                    short_attr = attr_map.get(attr, attr)
                                    dn_parts.append(f"{short_attr}={value}")
                            cert_subject_dn = ",".join(dn_parts)
                            logger.debug(
                                "Extracted client cert DN from gunicorn "
                                f"socket: {cert_subject_dn}"
                            )
            except Exception as e:
                logger.debug(
                    f"Failed to get client cert from gunicorn socket: {e}"
                )

        if cert_subject_dn:
            # Client certificate provided - verify it's RA agent cert
            authenticated = _validate_ra_agent_cert(cert_subject_dn)
            if authenticated:
                auth_method = "client_cert"
                principal = cert_subject_dn
                logger.info(
                    "Authenticated via client certificate from "
                    f"{remote_addr}: {cert_subject_dn}"
                )
            else:
                logger.warning(
                    "Client certificate provided but not RA agent cert: "
                    f"{cert_subject_dn}"
                )

        # Final authentication check
        # SECURITY: No localhost trust - same behavior as Dogtag PKI
        # All agent endpoints require valid RA agent certificate
        if not authenticated:
            logger.warning(
                f"Unauthorized access attempt to {request.path} from "
                f"{remote_addr}"
            )
            error_msg = (
                "Agent endpoints require client certificate authentication. "
                "Provide RA agent certificate (CN=IPA RA)."
            )
            return error_response("Unauthorized", error_msg, 401)

        # Store authentication info in request context for audit logging
        request.auth_method = auth_method
        request.auth_principal = principal

        logger.info(
            f"Agent endpoint access: {request.path} by {principal} via "
            f"{auth_method}"
        )

        return f(*args, **kwargs)

    return wrapper


def _validate_ra_agent_cert(cert_subject_dn: str) -> bool:
    """
    Validate that client certificate is the IPA RA agent certificate

    Args:
        cert_subject_dn: Certificate subject DN from SSL_CLIENT_S_DN

    Returns:
        True if certificate is valid RA agent cert, False otherwise

    Expected RA agent certificate DN pattern:
        CN=IPA RA,O=<REALM>
    """
    try:
        from ipapython.dn import DN
        from ipathinca import get_config_value

        # Parse certificate subject DN
        try:
            cert_dn = DN(cert_subject_dn)
        except Exception as e:
            logger.warning(f"Failed to parse client certificate DN: {e}")
            return False

        # Try to get realm from config
        try:
            get_config_value("global", "realm")
        except Exception:
            logger.warning(
                "Realm not available in config - cannot validate RA agent "
                "certificate"
            )
            # In this case, accept any cert with "IPA RA" CN as a fallback
            # This is less secure but allows operation during startup
            cert_cn = cert_dn[0].attr
            cert_cn_value = str(cert_dn[0].value)
            if cert_cn.lower() == "cn" and "ipa ra" in cert_cn_value.lower():
                logger.info(
                    "Accepting client cert with 'IPA RA' CN (config "
                    f"unavailable): {cert_subject_dn}"
                )
                return True
            return False

        # Expected RA agent DN: CN=IPA RA (the actual RA agent cert only has
        # CN)
        # We just check that CN=IPA RA is present in the certificate
        # The certificate issuer will be the IPA CA, so the trust chain
        # validates it

        # Check if the first (and possibly only) component is CN=IPA RA
        if len(cert_dn) > 0:
            first_rdn = cert_dn[0]
            if first_rdn.attr.upper() == "CN" and first_rdn.value == "IPA RA":
                logger.info(
                    "Client certificate matches RA agent cert: CN=IPA RA"
                )
                return True

        logger.warning(
            "Client certificate DN does not match RA agent pattern. Expected "
            f"CN=IPA RA, Got: {cert_dn}"
        )
        return False

    except Exception as e:
        logger.error(
            f"Error validating RA agent certificate: {e}", exc_info=True
        )
        return False


# ============================================================================
# Input Validation Helpers
# ============================================================================


def validate_serial_number(serial_str: str) -> Optional[int]:
    """
    Validate and parse serial number from string

    Args:
        serial_str: Serial number as string (decimal or hex with 0x prefix)

    Returns:
        Integer serial number or None if invalid
    """
    if not serial_str:
        return None

    try:
        # Handle hex format (0x prefix)
        if serial_str.startswith(("0x", "0X")):
            return int(serial_str, 16)
        # Handle decimal format
        return int(serial_str)
    except (ValueError, OverflowError):
        return None


def validate_profile_id(profile_id: str) -> bool:
    """
    Validate profile ID format

    Profile IDs should be alphanumeric with optional hyphens and underscores.

    Args:
        profile_id: Profile identifier string

    Returns:
        True if valid, False otherwise
    """
    if not profile_id or len(profile_id) > 255:
        return False

    # Allow alphanumeric, hyphens, underscores
    # Typical profile IDs: caIPAserviceCert, caServerCert, etc.
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", profile_id))


def validate_ca_id(ca_id: str) -> bool:
    """
    Validate CA ID format

    CA IDs should be alphanumeric with optional hyphens.

    Args:
        ca_id: CA identifier string

    Returns:
        True if valid, False otherwise
    """
    if not ca_id or len(ca_id) > 255:
        return False

    # Allow alphanumeric and hyphens
    # Special case: 'host-authority' is the main CA
    if ca_id == "host-authority":
        return True

    return bool(re.match(r"^[a-zA-Z0-9-]+$", ca_id))


# ============================================================================
# Response Helpers
# ============================================================================


def error_response(
    error_type: str,
    message: str,
    status_code: int = 400,
    class_name: str = None,
) -> tuple:
    """Create error response in PKI format

    Args:
        error_type: Error type for Attributes
        message: Error message
        status_code: HTTP status code
        class_name: Java exception class name (defaults to PKIException)
    """
    if class_name is None:
        class_name = "com.netscape.certsrv.base.PKIException"

    return (
        jsonify(
            {
                "ClassName": class_name,
                "Code": status_code,
                "Message": message,
                "Attributes": {
                    "Attribute": [{"name": "error", "value": error_type}]
                },
            }
        ),
        status_code,
    )


def success_response(data: Dict[str, Any], status_code: int = 200) -> tuple:
    """Create success response"""
    return jsonify(data), status_code


# ============================================================================
# Response Builders (Centralized formatting)
# ============================================================================


def build_certificate_response(
    cert_data, include_pem: bool = True
) -> Dict[str, Any]:
    """
    Build standardized certificate response

    Args:
        cert_data: Certificate data (dict from backend.get_certificate())
        include_pem: Include PEM-encoded certificate in response

    Returns:
        Standardized certificate response dict
    """
    # Handle both dict (from backend) and object (from CertificateRecord)
    if isinstance(cert_data, dict):
        response = {
            "id": cert_data["serial_number"],
            "SerialNumber": cert_data["serial_number"],
            "Status": cert_data["status"],
        }

        if include_pem and "certificate" in cert_data:
            # Backend returns PEM format (base64 with headers and line breaks)
            # matching Dogtag behavior - pass through as-is for Encoded field
            response["Encoded"] = cert_data["certificate"]
            # PrettyPrint is not used by IPA, but we can keep it for
            # compatibility
            response["PrettyPrint"] = cert_data["certificate"]

        if "revoked_at" in cert_data and cert_data["revoked_at"]:
            response["RevokedAt"] = cert_data["revoked_at"]
        if "revocation_reason" in cert_data and cert_data["revocation_reason"]:
            response["RevocationReason"] = cert_data["revocation_reason"]
    else:
        # Object with attributes (CertificateRecord)
        response = {
            "id": cert_data.serial_number,
            "SerialNumber": cert_data.serial_number,
            "Status": cert_data.status,
        }

        if include_pem:
            cert_b64 = base64.b64encode(
                cert_data.certificate.encode()
            ).decode()
            response["Encoded"] = cert_b64
            response["PrettyPrint"] = cert_data.certificate

        if hasattr(cert_data, "revoked_at") and cert_data.revoked_at:
            response["RevokedAt"] = cert_data.revoked_at
        if (
            hasattr(cert_data, "revocation_reason")
            and cert_data.revocation_reason
        ):
            response["RevocationReason"] = cert_data.revocation_reason

    return response


def build_request_response(
    result, include_cert: bool = False
) -> Dict[str, Any]:
    """
    Build standardized certificate request response

    Args:
        result: Request data (dict from backend)
        include_cert: Include certificate data in response

    Returns:
        Standardized request response dict
    """
    response = {
        "requestId": result["request_id"],
        "requestURL": f"/ca/rest/certrequests/{result['request_id']}",
        "requestType": "enrollment",
        "requestStatus": result["status"],
        "certId": (
            str(result["serial_number"])
            if result.get("serial_number")
            else None
        ),
        # CRITICAL FIX: Always include operationResult for PKI client
        # compatibility
        # The PKI client library expects this field to be present in the
        # response (see pki.cert.CertRequestInfo.operation_result)
        "operationResult": "success",
    }

    if include_cert and "certificate" in result:
        response.update(
            {
                "certificate": result["certificate"],
                "subject": result.get("subject"),
                "issuer": result.get("issuer"),
            }
        )

    return response


def build_profile_response(profile_data) -> Dict[str, Any]:
    """
    Build standardized profile response

    Args:
        profile_data: Profile data (dict or object)

    Returns:
        Standardized profile response dict
    """
    # Handle both dict (from backend) and object (Profile)
    if isinstance(profile_data, dict):
        return {
            "id": profile_data.get("profile_id") or profile_data.get("id"),
            "ProfileId": profile_data.get("profile_id")
            or profile_data.get("id"),
            "Name": profile_data.get("name"),
            "Description": profile_data.get("description"),
            "Enabled": profile_data.get("enabled", True),
        }
    else:
        # Object with attributes (Profile)
        return {
            "id": profile_data.profile_id,
            "ProfileId": profile_data.profile_id,
            "Name": profile_data.name,
            "Description": profile_data.description,
            "Enabled": profile_data.enabled,
        }


def build_authority_response(authority_info) -> Dict[str, Any]:
    """Build standardized authority response"""
    return authority_info  # Already properly formatted


# ============================================================================
# Handler Classes (Grouped operations)
# ============================================================================


class CertificateHandler:
    """Handler for certificate operations"""

    @staticmethod
    def get(serial_number: int, ca_backend):
        """Get certificate by serial number"""
        result = ca_backend.get_certificate(serial_number)
        response_data = build_certificate_response(result)
        return success_response(response_data)

    @staticmethod
    def search(criteria: Dict[str, Any], ca_backend):
        """Search certificates"""
        result = ca_backend.find_certificates(criteria)
        return success_response(
            {"entries": result["entries"], "total": result["total_entries"]}
        )

    @staticmethod
    def revoke(serial_number: str, revocation_reason: int, ca_backend):
        """Revoke certificate"""
        ca_backend.revoke_certificate(serial_number, revocation_reason)
        # Return Dogtag-compatible response format
        return success_response(
            {
                "operationResult": "success",
                "requestType": "revocation",
                "requestStatus": "complete",
                "certId": hex(int(serial_number)),
            }
        )

    @staticmethod
    def unrevoke(serial_number: str, ca_backend):
        """Take certificate off hold"""
        ca_backend.take_certificate_off_hold(serial_number)
        # Return Dogtag-compatible response format
        return success_response(
            {
                "operationResult": "success",
                "requestType": "unrevocation",
                "requestStatus": "complete",
            }
        )


class RequestHandler:
    """Handler for certificate request operations"""

    @staticmethod
    def submit(
        csr_data: str,
        profile_id: str,
        ca_backend,
        ca_id: Optional[str] = None,
    ):
        """Submit certificate request"""
        result = ca_backend.request_certificate(
            csr_data, profile_id, ca_id=ca_id
        )
        response = build_request_response(result, include_cert=True)
        return success_response({"entries": [response]}, 201)

    @staticmethod
    def get_status(request_id: str, ca_backend):
        """Get certificate request status"""
        result = ca_backend.check_request_status(request_id)
        response = build_request_response(result)
        return success_response(response)


class ProfileHandler:
    """Handler for profile operations"""

    @staticmethod
    def list_all(ca_backend):
        """List all profiles"""
        profiles = ca_backend.profile_manager.list_profiles()
        entries = [build_profile_response(p) for p in profiles]
        return success_response({"entries": entries, "total": len(entries)})

    @staticmethod
    def get(profile_id: str, ca_backend):
        """Get profile by ID"""
        profile_data = ca_backend.read_profile(profile_id)
        return success_response(build_profile_response(profile_data))

    @staticmethod
    def create_or_update(
        profile_id: str,
        data: Dict[str, Any],
        ca_backend,
        is_update: bool = False,
    ):
        """Create or update profile"""
        if is_update:
            result = ca_backend.update_profile(data)
        else:
            result = ca_backend.create_profile(data)

        return success_response(
            {"Status": result["status"], "ProfileId": profile_id}
        )

    @staticmethod
    def delete(profile_id: str, ca_backend):
        """Delete profile"""
        result = ca_backend.delete_profile(profile_id)
        return success_response(
            {"Status": result["status"], "ProfileId": profile_id}
        )


# ============================================================================
# Legacy Dogtag Helper Functions
# ============================================================================


def clean_csr_data(csr_data: str) -> str:
    """
    Clean CSR data from certmonger format to proper PEM

    Certmonger sends CSRs with leading spaces on each line.
    This function reconstructs proper PEM format.
    """
    csr_data = csr_data.strip()

    # Remove leading spaces from each line
    csr_lines = [line.strip() for line in csr_data.split("\n")]
    csr_data = "\n".join(csr_lines)

    # Ensure proper PEM headers
    if not csr_data.startswith("-----BEGIN"):
        csr_data = (
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            f"{csr_data}\n"
            "-----END CERTIFICATE REQUEST-----"
        )

    return csr_data


def build_dogtag_xml_response(
    request_id: str,
    serial_number: str = None,
    cert_pem: str = None,
    status: int = 0,
) -> str:
    """
    Build Dogtag-compatible XML response

    Args:
        request_id: Certificate request ID
        serial_number: Certificate serial number (if issued)
        cert_pem: Certificate in PEM format (if issued)
        status: Status code (0=success, 1=error, 2=pending)

    Returns:
        XML response string
    """
    if cert_pem and status == 0:
        # Success - extract base64 data from PEM
        # IMPORTANT: dogtag-submit expects ONLY base64 data, NOT PEM format
        # It will add the -----BEGIN CERTIFICATE----- headers itself
        cert_lines = cert_pem.strip().split("\n")
        cert_b64 = "".join(
            [line for line in cert_lines if not line.startswith("-----")]
        )

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<XMLResponse>
<Status>0</Status>
<Requests>
<Request>
<RequestId>{request_id}</RequestId>
<SerialNo>{serial_number}</SerialNo>
<b64>{cert_b64}</b64>
</Request>
</Requests>
</XMLResponse>"""

    elif status == 2:
        # Pending
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<XMLResponse>
<Status>2</Status>
<RequestId>{request_id}</RequestId>
<Info>Request pending</Info>
</XMLResponse>"""

    else:
        # Error
        return """<?xml version="1.0" encoding="UTF-8"?>
<XMLResponse>
<Status>1</Status>
<Error>Certificate request failed</Error>
</XMLResponse>"""
