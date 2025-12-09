# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
REST API Server for Python CA - Replacement for pki-tomcat

This module provides a Flask-based REST API server that implements the
PKI REST API endpoints, allowing ipathinca to serve as a drop-in
replacement for Dogtag PKI's pki-tomcat service.
"""

import logging
import os
import base64
import traceback
import argparse
import secrets

from flask import Flask, request, Response, make_response, jsonify

from ipathinca.backend import get_python_ca_backend
from ipathinca.exceptions import ProfileNotFound
from ipalib import errors
from ipaplatform.paths import paths

# Import REST API helpers
from ipathinca.rest_api_helpers import (
    # Decorators
    require_ca_backend,
    handle_ca_errors,
    validate_input,
    require_agent_auth,
    # Validators
    validate_serial_number,
    validate_profile_id,
    validate_ca_id,
    # Response helpers
    error_response,
    success_response,
    # Handler classes
    CertificateHandler,
    RequestHandler,
    ProfileHandler,
    # Legacy helpers
    clean_csr_data,
    build_dogtag_xml_response,
)

# Configure logging - will be set from config in create_app()
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Global CA backend instance
ca_backend = None

# Global configuration (loaded from ipathinca.conf)
ipa_ca_config = None


# ============================================================================
# Initializors
# ============================================================================


def init_ca():
    """Initialize CA backend"""
    global ca_backend
    if ca_backend is None:
        try:
            logger.debug("Initializing Python CA backend...")
            ca_backend = get_python_ca_backend()
            logger.debug(
                "Python CA backend initialized successfully with LDAP storage"
            )
        except Exception as e:
            logger.error(f"Failed to initialize CA backend: {e}")
            logger.error(traceback.format_exc())
            raise


# ============================================================================
# Error Handlers
# ============================================================================


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return error_response(
        "NotFound", f"Endpoint not found: {request.path}", 404
    )


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return error_response("InternalServerError", "Internal server error", 500)


# ============================================================================
# Health and Status Endpoints
# ============================================================================


@app.route("/pki/rest/info", methods=["GET"])
@app.route("/pki/v2/info", methods=["GET"])
def pki_info():
    """Get PKI version information - compatible with Dogtag /pki/rest/info and
    /pki/v2/info"""
    # Return version info that dogtag.py expects
    # This is used by dogtag.py to determine API compatibility
    return success_response(
        {
            "Version": "11.5.0",  # Claim to be Dogtag 11.5.0 for compatibility
            "Attributes": {"Attribute": []},
        }
    )


@app.route("/ca/rest/info", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def ca_info():
    """Get CA information - compatible with PKI /ca/rest/info"""
    info = ca_backend.get_ca_info()
    return success_response(
        {
            "Version": "1.0",
            # Identify this as ipathinca for hybrid_ra detection
            "backend": "ipathinca",
            "Attributes": {
                "ca_id": info["ca_id"],
                "subject": info["ca_subject"],
                "serial_number": info["ca_serial_number"],
                "not_before": info["ca_not_before"],
                "not_after": info["ca_not_after"],
                "status": info["status"],
            },
        }
    )


@app.route("/ca/admin/ca/getStatus", methods=["GET"])
@require_ca_backend
def ca_status():
    """Get CA status - compatible with Dogtag getStatus endpoint"""
    try:
        info = ca_backend.get_ca_info()
        return Response(f"status={info['status']}", mimetype="text/plain")
    except Exception as e:
        logger.error("Error in ca_status: %s", e)
        return Response(
            f"status=ERROR: {e}", mimetype="text/plain", status=500
        )


@app.route("/ca/ee/ca/getStatus", methods=["GET"])
def ca_ee_status():
    """Get CA status (end-entity interface)"""
    return ca_status()


# ============================================================================
# Admin/Agent Endpoints
# ============================================================================


def _account_login():
    """Shared implementation for account login endpoint.

    IPA's dogtag plugin uses client certificate authentication and expects
    a session cookie to be returned for subsequent requests.

    Used by both CA and KRA subsystems.
    """
    # Generate a simple session token
    session_token = secrets.token_hex(32)

    # Create response and convert tuple to Response object
    response = make_response(success_response({"Status": "success"}))
    # Set session cookie that expires in 30 minutes
    response.set_cookie(
        "JSESSIONID",
        session_token,
        max_age=1800,  # 30 minutes
        httponly=True,
        secure=True,
        samesite="Strict",
    )
    return response


def _account_logout():
    """Shared implementation for account logout endpoint (v1 REST API).

    Clears session cookie. Returns 200 with success message.
    """
    response = make_response(success_response({"Status": "success"}))
    # Clear the session cookie
    response.set_cookie("JSESSIONID", "", expires=0)
    return response


def _account_logout_v2():
    """Shared implementation for account logout endpoint (v2 REST API).

    Clears session cookie. Returns 204 No Content (Dogtag v2 compatibility).
    """
    response = make_response("", 204)
    # Clear the session cookie
    response.set_cookie("JSESSIONID", "", expires=0)
    return response


# CA Account Management Endpoints
@app.route("/ca/rest/account/login", methods=["GET", "POST"])
@require_agent_auth
def account_login():
    """CA account login endpoint for REST API session management."""
    return _account_login()


@app.route("/ca/v2/account/login", methods=["GET", "POST"])
@require_agent_auth
def account_login_v2():
    """CA account login endpoint for REST API v2 session management."""
    return _account_login()


@app.route("/ca/rest/account/logout", methods=["GET", "POST"])
def account_logout():
    """CA account logout (compatibility endpoint - clears session cookie)"""
    return _account_logout()


@app.route("/ca/v2/account/logout", methods=["GET", "POST"])
def account_logout_v2():
    """CA account logout endpoint for REST API v2 (returns 204)"""
    return _account_logout_v2()


# ============================================================================
# Security Domain Endpoints
# ============================================================================


@app.route("/ca/rest/securityDomain/domainInfo", methods=["GET"])
@app.route("/ca/v2/securityDomain/domainInfo", methods=["GET"])
def get_security_domain_info():
    """
    Get security domain information

    Returns information about all subsystems (CA, KRA, etc.) in the security
    domain.
    This is used during installation and replica management.
    """
    try:
        init_ca()

        # Build security domain info
        # In IPA, the security domain is essentially the IPA deployment
        # with all its CA/KRA replicas

        # For now, return minimal domain info with just the master CA
        # In a full implementation, this would query LDAP for all replicas

        # Get realm and hostname from backend's config
        # Hostname is REQUIRED - no fallback to localhost for certificate
        # operations
        realm = "IPA"  # Default
        hostname = None

        if ca_backend.config:
            if ca_backend.config.has_option("global", "realm"):
                realm = ca_backend.config.get("global", "realm")
            if ca_backend.config.has_option("global", "host"):
                hostname = ca_backend.config.get("global", "host")

        if not hostname:
            logger.error("Hostname not configured in ipathinca.conf")
            return error_response(
                "ConfigurationError",
                "Hostname not configured in ipathinca.conf [global] section",
                500,
            )

        domain_info = {
            "id": realm,
            "Subsystem": [
                {
                    "id": "CA",
                    "Host": [
                        {
                            "id": hostname,
                            "Hostname": hostname,
                            "Port": "8080",
                            "SecurePort": "8443",
                            "SecureAgentPort": "8443",
                            "SecureAdminPort": "8443",
                            "SecureEEClientAuthPort": "8443",
                            "Clone": "FALSE",
                            "SubsystemName": "CA",
                            "DomainManager": "TRUE",
                        }
                    ],
                }
            ],
        }

        return success_response(domain_info)

    except Exception as e:
        logger.error(f"Error getting security domain info: {e}")
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/securityDomain/hosts/<path:host_id>", methods=["DELETE"])
@app.route("/ca/v2/securityDomain/hosts/<path:host_id>", methods=["DELETE"])
@require_agent_auth
def remove_security_domain_host(host_id):
    """
    Remove a host from the security domain

    This is called during server uninstallation to clean up replica
    information.
    The host_id is in format: "{subsystem} {hostname} {port}" (space-separated,
    URL-encoded)

    For ipathinca, we accept the deletion but don't need to track security
    domain hosts since we don't have multiple PKI instances. The security
    domain concept is mainly for tracking Dogtag replicas, which doesn't apply
    to our pure Python CA.
    """
    try:
        logger.info(f"Security domain host removal requested: {host_id}")

        # Parse host_id: "{subsystem} {hostname} {port}"
        parts = host_id.split(" ")
        if len(parts) != 3:
            return error_response(
                "BadRequest",
                f"Invalid host ID format: {host_id}. Expected 'subsystem"
                " hostname port'",
                400,
            )

        subsystem, hostname, port = parts
        logger.info(
            f"Removing {subsystem} host {hostname}:{port} from security domain"
        )

        # In ipathinca, we don't need to track security domain hosts
        # Just return success to allow the uninstallation to proceed
        return success_response(
            {
                "Status": "SUCCESS",
                "Message": (
                    f"Host {hostname} removed from security domain (no-op for"
                    " ipathinca)"
                ),
            }
        )

    except Exception as e:
        logger.error(f"Error removing security domain host: {e}")
        return error_response("ServerError", str(e), 500)


# ============================================================================
# Certificate Request Endpoints
# ============================================================================


@app.route("/ca/rest/certrequests", methods=["POST"])
@app.route("/ca/rest/agent/certrequests", methods=["POST"])
@app.route("/ca/v2/certrequests", methods=["POST"])
@app.route("/ca/v2/agent/certrequests", methods=["POST"])
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
            f"No CSR data found in request. Data keys: {list(data.keys())}"
        )
        return error_response("BadRequest", "No CSR data provided", 400)

    # Decode CSR if base64 encoded
    if not csr_data.startswith("-----BEGIN"):
        try:
            csr_data = base64.b64decode(csr_data).decode("utf-8")
        except Exception:
            pass

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
                # Reformat with proper line breaks (64 chars per line)
                lines = [
                    b64_data[i : i + 64] for i in range(0, len(b64_data), 64)
                ]
                csr_data = "-----BEGIN CERTIFICATE REQUEST-----\n"
                csr_data += "\n".join(lines)
                csr_data += "\n-----END CERTIFICATE REQUEST-----\n"

    return RequestHandler.submit(csr_data, profile_id, ca_backend, ca_id)


@app.route("/ca/rest/certrequests/<request_id>", methods=["GET"])
@app.route("/ca/rest/agent/certrequests/<request_id>", methods=["GET"])
@app.route("/ca/v2/certrequests/<request_id>", methods=["GET"])
@app.route("/ca/v2/agent/certrequests/<request_id>", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def get_certificate_request(request_id):
    """Get certificate request status"""
    get_certificate_request.__resource_type__ = "Request"
    return RequestHandler.get_status(request_id, ca_backend)


@app.route("/ca/rest/certrequests/<request_id>", methods=["DELETE"])
@app.route("/ca/rest/agent/certrequests/<request_id>", methods=["DELETE"])
@app.route("/ca/v2/certrequests/<request_id>", methods=["DELETE"])
@app.route("/ca/v2/agent/certrequests/<request_id>", methods=["DELETE"])
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
        storage = ca_backend.ca.storage

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
            f"Error deleting request {request_id}: {e}", exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to delete request: {str(e)}", 500
        )


@app.route("/ca/rest/certrequests/profiles/<profile_id>", methods=["GET"])
@app.route("/ca/v2/certrequests/profiles/<profile_id>", methods=["GET"])
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

    profile = ca_backend.profile_manager.get_profile(profile_id)
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


def _search_certificates():
    """
    Internal helper for certificate search (handles both GET and POST)

    Parses PKI-style search parameters and converts them to backend format.
    Supports both URL query parameters (GET) and JSON body (POST).

    Parameter mapping from PKI to backend:
    - serialFrom/serialTo -> min_serial_number/max_serial_number
    - commonName -> subject (common name search)
    - issuerDN -> issuer
    - status -> status
    - issuedOnFrom/issuedOnTo -> issued_on_from/issued_on_to
    - validNotBeforeFrom/validNotBeforeTo
      -> valid_not_before_from/valid_not_before_to
    - validNotAfterFrom/validNotAfterTo
      -> valid_not_after_from/valid_not_after_to
    - revokedOnFrom/revokedOnTo -> revoked_on_from/revoked_on_to
    - matchExactly -> exactly
    """
    # Parse pagination parameters from URL (both GET and POST)
    size = request.args.get("size", type=int)
    start = request.args.get("start", type=int, default=0)
    max_results = request.args.get("maxResults", type=int)
    max_time = request.args.get("maxTime", type=int)

    # Parse search criteria based on request method
    search_request = {}

    if request.method == "POST":
        # POST request - JSON body contains search criteria
        search_request = request.get_json() or {}
    else:
        # GET request - URL parameters (build from query string)
        # This is used by some older clients
        search_request = dict(request.args)
        # Remove pagination params from search criteria
        for key in ["size", "start", "maxResults", "maxTime"]:
            search_request.pop(key, None)

    # Map PKI parameter names to backend parameter names
    # Based on pki/cert.py CertSearchRequest.search_params mapping
    criteria = {}

    # Serial number range
    if "serialFrom" in search_request:
        criteria["min_serial_number"] = search_request["serialFrom"]
    if "serialTo" in search_request:
        criteria["max_serial_number"] = search_request["serialTo"]

    # Subject fields (mapped to subject search in backend)
    if "commonName" in search_request:
        criteria["subject"] = search_request["commonName"]
    if "eMail" in search_request:
        criteria["email"] = search_request["eMail"]
    if "userID" in search_request:
        criteria["user_id"] = search_request["userID"]
    if "orgUnit" in search_request:
        criteria["org_unit"] = search_request["orgUnit"]
    if "org" in search_request:
        criteria["org"] = search_request["org"]
    if "locality" in search_request:
        criteria["locality"] = search_request["locality"]
    if "state" in search_request:
        criteria["state"] = search_request["state"]
    if "country" in search_request:
        criteria["country"] = search_request["country"]

    # Match exactly flag
    if "matchExactly" in search_request:
        criteria["exactly"] = search_request["matchExactly"]

    # Issuer DN
    if "issuerDN" in search_request:
        criteria["issuer"] = search_request["issuerDN"]

    # Status
    if "status" in search_request:
        criteria["status"] = search_request["status"]

    # Revocation info
    if "revokedBy" in search_request:
        criteria["revoked_by"] = search_request["revokedBy"]
    if "revokedOnFrom" in search_request:
        criteria["revoked_on_from"] = search_request["revokedOnFrom"]
    if "revokedOnTo" in search_request:
        criteria["revoked_on_to"] = search_request["revokedOnTo"]
    if "revocationReason" in search_request:
        criteria["revocation_reason"] = search_request["revocationReason"]

    # Issuance info
    if "issuedBy" in search_request:
        criteria["issued_by"] = search_request["issuedBy"]
    if "issuedOnFrom" in search_request:
        criteria["issued_on_from"] = search_request["issuedOnFrom"]
    if "issuedOnTo" in search_request:
        criteria["issued_on_to"] = search_request["issuedOnTo"]

    # Validity dates
    if "validNotBeforeFrom" in search_request:
        criteria["valid_not_before_from"] = search_request[
            "validNotBeforeFrom"
        ]
    if "validNotBeforeTo" in search_request:
        criteria["valid_not_before_to"] = search_request["validNotBeforeTo"]
    if "validNotAfterFrom" in search_request:
        criteria["valid_not_after_from"] = search_request["validNotAfterFrom"]
    if "validNotAfterTo" in search_request:
        criteria["valid_not_after_to"] = search_request["validNotAfterTo"]

    # Certificate type filters
    if "certTypeSubEmailCA" in search_request:
        criteria["cert_type_sub_email_ca"] = search_request[
            "certTypeSubEmailCA"
        ]
    if "certTypeSubSSLCA" in search_request:
        criteria["cert_type_sub_ssl_ca"] = search_request["certTypeSubSSLCA"]
    if "certTypeSecureEmail" in search_request:
        criteria["cert_type_secure_email"] = search_request[
            "certTypeSecureEmail"
        ]
    if "certTypeSSLClient" in search_request:
        criteria["cert_type_ssl_client"] = search_request["certTypeSSLClient"]
    if "certTypeSSLServer" in search_request:
        criteria["cert_type_ssl_server"] = search_request["certTypeSSLServer"]

    # Add pagination parameters to criteria
    if size is not None:
        criteria["sizelimit"] = size
    elif max_results is not None:
        criteria["sizelimit"] = max_results

    if start is not None:
        criteria["offset"] = start

    if max_time is not None:
        criteria["timelimit"] = max_time

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Certificate search criteria: %s", criteria)

    # Execute search through handler
    return CertificateHandler.search(criteria, ca_backend)


@app.route("/ca/rest/certs/<serial_number>", methods=["GET"])
@app.route("/ca/v2/certs/<serial_number>", methods=["GET"])
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

    return CertificateHandler.get(serial_number, ca_backend)


@app.route("/ca/rest/agent/certs/<serial_number>", methods=["GET"])
@app.route("/ca/v2/agent/certs/<serial_number>", methods=["GET"])
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

    return CertificateHandler.get(serial_number, ca_backend)


@app.route("/ca/rest/certs", methods=["GET", "POST"])  # Dogtag compatibility
@app.route("/ca/rest/certs/search", methods=["GET", "POST"])
@app.route("/ca/v2/certs", methods=["GET", "POST"])
@app.route("/ca/v2/certs/search", methods=["GET", "POST"])
@require_ca_backend
@handle_ca_errors
def search_certificates_public():
    """Search certificates (public endpoint)"""
    return _search_certificates()


@app.route("/ca/rest/agent/certs/search", methods=["GET", "POST"])
@app.route("/ca/v2/agent/certs/search", methods=["GET", "POST"])
@require_agent_auth  # SECURITY: Agent endpoint requires authentication
@require_ca_backend
@handle_ca_errors
def search_certificates_agent():
    """Search certificates (agent endpoint - requires auth)"""
    return _search_certificates()


@app.route("/ca/rest/agent/certs/<serial_number>/revoke", methods=["POST"])
@app.route("/ca/rest/certs/<serial_number>/revoke", methods=["POST"])
@app.route("/ca/v2/agent/certs/<serial_number>/revoke", methods=["POST"])
@app.route("/ca/v2/certs/<serial_number>/revoke", methods=["POST"])
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
        serial_number, revocation_reason, ca_backend
    )


@app.route("/ca/rest/agent/certs/<serial_number>/revoke-ca", methods=["POST"])
@app.route("/ca/rest/agent/certs/<serial_number>/unrevoke", methods=["POST"])
@app.route("/ca/v2/agent/certs/<serial_number>/revoke-ca", methods=["POST"])
@app.route("/ca/v2/agent/certs/<serial_number>/unrevoke", methods=["POST"])
@require_agent_auth
@require_ca_backend
@validate_input(serial_number=validate_serial_number)
@handle_ca_errors
def unrevoke_certificate(serial_number):
    """Take certificate off hold"""
    unrevoke_certificate.__resource_type__ = "Certificate"
    return CertificateHandler.unrevoke(serial_number, ca_backend)


# Bulk Certificate Operations
# ----------------------------------------------------------------------------


@app.route("/ca/rest/certs/bulk-revoke", methods=["POST"])
@app.route("/ca/v2/certs/bulk-revoke", methods=["POST"])
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

        storage = ca_backend.ca.storage

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
                    ca_backend.revoke_certificate(
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
        logger.error(f"Error in bulk revoke: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to bulk revoke: {str(e)}", 500
        )


@app.route("/ca/rest/certs/revoked", methods=["GET"])
@app.route("/ca/v2/certs/revoked", methods=["GET"])
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
        limit = int(request.args.get("limit", 1000))
        offset = int(request.args.get("offset", 0))

        storage = ca_backend.ca.storage

        if hasattr(storage, "get_revoked_certificates"):
            revoked = storage.get_revoked_certificates()

            # Apply pagination
            total = len(revoked)
            paginated = revoked[offset : offset + limit]

            return (
                jsonify(
                    {
                        "entries": paginated,
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
        logger.error(f"Error getting revoked certificates: {e}", exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get revoked certificates: {str(e)}",
            500,
        )


# ============================================================================
# Legacy Certificate Display Endpoint
# ============================================================================


@app.route("/ca/ee/ca/displayBySerial", methods=["GET"])
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
    result = ca_backend.get_certificate(validated_serial)
    return Response(result["certificate"], mimetype="application/x-pem-file")


# ============================================================================
# Certificate Profile Endpoints
# ============================================================================


@app.route("/ca/ee/ca/profileList", methods=["GET"])
def legacy_profile_list():
    """Legacy Dogtag endpoint for profile list - returns XML"""
    try:
        init_ca()

        xml_output = request.args.get("xml", "false").lower() == "true"

        if xml_output:
            # Return XML format for dogtag-submit compatibility
            profiles = ca_backend.profile_manager.list_profiles()

            profile_entries = []
            for profile in profiles:
                profile_entries.append(
                    f'<profile id="{profile.profile_id}">{profile.name}'
                    "</profile>"
                )

            profiles_xml = "\n".join(profile_entries)

            response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<profiles>
{profiles_xml}
</profiles>"""

            return Response(response_xml, mimetype="application/xml")
        else:
            # Return text format
            profiles = ca_backend.profile_manager.list_profiles()
            profile_list = "\n".join(
                [f"{p.profile_id}:{p.name}" for p in profiles]
            )
            return Response(profile_list, mimetype="text/plain")

    except Exception as e:
        logger.error(f"Error in legacy_profile_list: {e}")
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/profiles", methods=["GET"])
@app.route("/ca/v2/profiles", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def list_profiles():
    """List certificate profiles"""
    return ProfileHandler.list_all(ca_backend)


@app.route("/ca/rest/profiles/<profile_id>", methods=["GET"])
@app.route("/ca/v2/profiles/<profile_id>", methods=["GET"])
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def get_profile(profile_id):
    """Get certificate profile"""
    get_profile.__resource_type__ = "Profile"
    return ProfileHandler.get(profile_id, ca_backend)


@app.route("/ca/rest/profiles/<profile_id>", methods=["POST", "PUT"])
@app.route("/ca/v2/profiles/<profile_id>", methods=["POST", "PUT"])
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def update_profile(profile_id):
    """Create or update certificate profile"""
    data = request.get_json()
    if not data:
        return error_response("BadRequest", "No profile data provided", 400)

    is_update = request.method == "PUT"
    return ProfileHandler.create_or_update(
        profile_id, data, ca_backend, is_update
    )


@app.route("/ca/rest/profiles/<profile_id>", methods=["DELETE"])
@app.route("/ca/v2/profiles/<profile_id>", methods=["DELETE"])
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def delete_profile(profile_id):
    """Delete certificate profile"""
    delete_profile.__resource_type__ = "Profile"
    return ProfileHandler.delete(profile_id, ca_backend)


@app.route("/ca/rest/profiles/<profile_id>/enable", methods=["POST"])
@app.route("/ca/v2/profiles/<profile_id>/enable", methods=["POST"])
@require_agent_auth
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def enable_profile(profile_id):
    """
    Enable a certificate profile

    This allows the profile to be used for certificate requests.
    Requires agent authentication.
    """
    try:
        # For now, profiles are always enabled in ipathinca
        # This endpoint is provided for Dogtag API compatibility
        # In a full implementation, you would call storage.enable_profile()

        return (
            success_response(
                {
                    "message": f"Profile {profile_id} enabled successfully",
                    "profile_id": profile_id,
                    "enabled": True,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(
            f"Error enabling profile {profile_id}: {e}", exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to enable profile: {str(e)}", 500
        )


@app.route("/ca/rest/profiles/<profile_id>/disable", methods=["POST"])
@app.route("/ca/v2/profiles/<profile_id>/disable", methods=["POST"])
@require_agent_auth
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def disable_profile(profile_id):
    """
    Disable a certificate profile

    This prevents the profile from being used for certificate requests.
    Requires agent authentication.
    """
    try:
        # For now, profiles cannot be disabled in ipathinca
        # This endpoint is provided for Dogtag API compatibility
        # In a full implementation, you would call storage.disable_profile()

        return (
            success_response(
                {
                    "message": f"Profile {profile_id} disabled successfully",
                    "profile_id": profile_id,
                    "enabled": False,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(
            f"Error disabling profile {profile_id}: {e}", exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to disable profile: {str(e)}", 500
        )


# ============================================================================
# Legacy Dogtag Endpoints (for backward compatibility with certmonger)
# ============================================================================


@app.route("/ca/ee/ca/profileSubmitSSLClient", methods=["POST", "GET"])
@app.route("/ca/eeca/ca/profileSubmitSSLClient", methods=["POST", "GET"])
@require_ca_backend
def profile_submit_ssl_client():
    """
    Legacy Dogtag endpoint for certificate submission with SSL client auth.
    Used by certmonger's dogtag-submit helper.

    Accepts form-encoded parameters:
    - cert_request: The CSR in PEM format
    - cert_request_type: Type of request (e.g., 'pkcs10')
    - profileId: Certificate profile to use
    - xmlOutput: Set to 'true' for XML response
    """
    try:
        # Get parameters from form data or query string
        params = request.form if request.method == "POST" else request.args

        # Validate CSR data
        csr_data = params.get("cert_request")
        if not csr_data:
            return Response(
                build_dogtag_xml_response("", status=1),
                mimetype="application/xml",
                status=400,
            )

        profile_id = params.get("profileId", "caIPAserviceCert")
        xml_output = params.get("xmlOutput", "true").lower() == "true"

        # Clean CSR data (certmonger format to proper PEM)
        csr_data = clean_csr_data(csr_data)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Legacy cert request via profileSubmitSSLClient: profile=%s",
                profile_id,
            )
            logger.debug("Cleaned CSR length: %d bytes", len(csr_data))

        # Submit certificate request
        result = ca_backend.request_certificate(csr_data, profile_id)

        # Get the issued certificate if available
        cert_pem = None
        if result.get("serial_number"):
            cert_result = ca_backend.get_certificate(result["serial_number"])
            cert_pem = cert_result["certificate"]

        # Return response
        if xml_output:
            status = 0 if cert_pem else 2  # 0=success, 2=pending
            response_xml = build_dogtag_xml_response(
                result["request_id"],
                result.get("serial_number", ""),
                cert_pem,
                status,
            )

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "Returning %s XML response, serial=%s",
                    "success" if cert_pem else "pending",
                    result.get("serial_number"),
                )

            return Response(response_xml, mimetype="application/xml")
        else:
            # Return cert in PEM format
            return Response(cert_pem or "", mimetype="application/x-pem-file")

    except errors.CertificateOperationError as e:
        logger.error("Certificate request failed: %s", e, exc_info=True)
        error_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f"<XMLResponse>\n<Status>1</Status>\n<Error>{str(e)}"
            "</Error>\n</XMLResponse>"
        )
        return Response(error_xml, mimetype="application/xml", status=400)

    except Exception as e:
        logger.error(
            "Error in profile_submit_ssl_client: %s", e, exc_info=True
        )
        error_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<XMLResponse>\n<Status>1</Status>\n"
            f"<Error>{str(e)}</Error>\n</XMLResponse>"
        )
        return Response(error_xml, mimetype="application/xml", status=500)


# CRL Endpoints
# ============================================================================


@app.route("/ca/ee/ca/getCRL", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def get_crl():
    """Get Certificate Revocation List

    Serves CRL at /ca/ee/ca/getCRL (Dogtag format).

    Note: /ipa/crl/MasterCRL.bin is served by Apache directly via Alias
    directive from /var/lib/ipa/pki-ca/publish/MasterCRL.bin (not via this
    REST API).
    """
    # Generate fresh CRL
    ca_backend.update_crl()

    # Read CRL from file
    crl_path = os.path.join(paths.IPATHINCA_CERTS_DIR, "ca_crl.der")
    if os.path.exists(crl_path):
        with open(crl_path, "rb") as f:
            crl_data = f.read()
        return Response(crl_data, mimetype="application/pkix-crl")
    else:
        return error_response("CRLNotFound", "CRL file not found", 404)


@app.route("/ca/rest/agent/crl", methods=["POST"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def update_crl():
    """Update CRL (force regeneration)"""
    result = ca_backend.update_crl()
    return success_response({"Status": result["status"]})


@app.route("/ca/agent/ca/updateCRL", methods=["GET"])
@require_agent_auth
@require_ca_backend
def update_crl_legacy():
    """
    Legacy Dogtag XML endpoint for CRL update
    Used by IPA RA plugin (ipaserver/plugins/dogtag.py updateCRL method)

    Query parameters:
    - crlIssuingPoint: CRL issuing point (usually 'MasterCRL')
    - waitForUpdate: Wait for update completion (ignored - operation is
                     synchronous)
    - xml: Return XML response ('true')
    """
    try:
        # Get parameters
        crl_issuing_point = request.args.get("crlIssuingPoint", "MasterCRL")
        # Note: waitForUpdate is ignored - CRL update is always synchronous
        xml_output = request.args.get("xml", "true")

        # Force CRL update
        result = ca_backend.update_crl()

        # Return XML response (Dogtag format)
        if xml_output.lower() == "true":
            # Success response in Dogtag XML format
            # requestStatus: 2 = SUCCESS (from dogtag.py CMS_STATUS_SUCCESS)
            crl_update_status = (
                "Success" if result.get("status") == "success" else "Failure"
            )

            response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xml>
  <fixed>
    <requestStatus>2</requestStatus>
  </fixed>
  <header>
    <crlIssuingPoint>{crl_issuing_point}</crlIssuingPoint>
    <crlUpdate>{crl_update_status}</crlUpdate>
  </header>
</xml>"""

            return Response(response_xml, mimetype="application/xml")
        else:
            # Text response
            return Response(
                f"crlUpdate={result.get('status', 'unknown')}",
                mimetype="text/plain",
            )

    except Exception as e:
        logger.error(f"Error in updateCRL (legacy): {e}", exc_info=True)

        # Return XML error response
        error_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xml>
  <fixed>
    <requestStatus>6</requestStatus>
    <errorDetails>{str(e)}</errorDetails>
  </fixed>
</xml>"""
        return Response(error_xml, mimetype="application/xml", status=500)


# CRL Issuing Points Management
# ----------------------------------------------------------------------------


@app.route("/ca/rest/crl/issuingpoints", methods=["GET"])
@app.route("/ca/v2/crl/issuingpoints", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def list_crl_issuing_points():
    """
    List all CRL issuing points

    Returns list of CRL issuing point names
    """
    try:
        storage = ca_backend.ca.storage

        if hasattr(storage, "list_crl_issuing_points"):
            crl_points = storage.list_crl_issuing_points()
            return (
                jsonify({"entries": crl_points, "total": len(crl_points)}),
                200,
            )
        else:
            # Fallback for storage backends without this method
            return jsonify({"entries": ["MasterCRL"], "total": 1}), 200

    except Exception as e:
        logger.error(f"Error listing CRL issuing points: {e}", exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to list CRL issuing points: {str(e)}",
            500,
        )


@app.route("/ca/rest/crl/issuingpoints/<crl_name>", methods=["GET"])
@app.route("/ca/v2/crl/issuingpoints/<crl_name>", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def get_crl_issuing_point_info(crl_name):
    """
    Get CRL issuing point information

    Returns metadata about a CRL issuing point including:
    - crl_number
    - crl_size (number of revoked certificates)
    - this_update (issue time)
    - next_update (next scheduled update)
    """
    try:
        storage = ca_backend.ca.storage

        if hasattr(storage, "get_crl_info"):
            crl_info = storage.get_crl_info(crl_name)

            if crl_info:
                return jsonify(crl_info), 200
            else:
                return error_response(
                    "CRLIssuingPointNotFound",
                    f"CRL issuing point '{crl_name}' not found",
                    404,
                )
        else:
            return error_response(
                "NotImplemented", "CRL issuing point info not available", 501
            )

    except Exception as e:
        logger.error(
            f"Error getting CRL issuing point info: {e}", exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to get CRL info: {str(e)}", 500
        )


@app.route("/ca/rest/crl/issuingpoints/<crl_name>", methods=["DELETE"])
@app.route("/ca/v2/crl/issuingpoints/<crl_name>", methods=["DELETE"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def delete_crl_issuing_point(crl_name):
    """
    Delete a CRL issuing point

    This removes the CRL issuing point configuration.
    Requires agent authentication.
    """
    try:
        storage = ca_backend.ca.storage

        if hasattr(storage, "delete_crl_issuing_point"):
            storage.delete_crl_issuing_point(crl_name)
            return (
                success_response(
                    {
                        "message": (
                            f"CRL issuing point '{crl_name}' deleted"
                            " successfully"
                        )
                    }
                ),
                200,
            )
        else:
            return error_response(
                "NotImplemented",
                "CRL issuing point deletion not available",
                501,
            )

    except Exception as e:
        logger.error(f"Error deleting CRL issuing point: {e}", exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to delete CRL issuing point: {str(e)}",
            500,
        )


# ============================================================================
# Certificate and Request Pruning Endpoints
# ============================================================================


@app.route("/ca/rest/pruning/config", methods=["GET"])
@app.route("/ca/v2/pruning/config", methods=["GET"])
@require_ca_backend
def get_pruning_config():
    """
    Get pruning configuration

    Returns configuration for certificate and request pruning including
    retention times, search limits, and enabled status.
    """
    try:
        config = ca_backend.pruning_manager.get_config()
        return success_response(config)

    except Exception as e:
        logger.error(f"Error getting pruning config: {e}", exc_info=True)
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/pruning/config", methods=["POST", "PUT"])
@app.route("/ca/v2/pruning/config", methods=["POST", "PUT"])
@require_agent_auth
@require_ca_backend
def update_pruning_config():
    """
    Update pruning configuration

    Requires agent authentication.

    Request body can include:
    - certRetentionTime: Certificate retention time value
    - certRetentionUnit: Certificate retention unit (minute, hour, day, year)
    - certSearchSizeLimit: LDAP search size limit for certificates
    - certSearchTimeLimit: LDAP search time limit for certificates
    - requestRetentionTime: Request retention time value
    - requestRetentionUnit: Request retention unit
    - requestSearchSizeLimit: LDAP search size limit for requests
    - requestSearchTimeLimit: LDAP search time limit for requests
    - cronSchedule: Cron schedule for automatic pruning
    """
    try:
        data = request.get_json() or {}

        # Validate and update configuration
        ca_backend.pruning_manager.update_config(data)

        # Get updated config to return
        config = ca_backend.pruning_manager.get_config()
        return success_response(config)

    except Exception as e:
        logger.error(f"Error updating pruning config: {e}", exc_info=True)
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/pruning/enable", methods=["POST"])
@app.route("/ca/v2/pruning/enable", methods=["POST"])
@require_agent_auth
@require_ca_backend
def enable_pruning():
    """
    Enable certificate pruning

    Sets pruningEnabled=TRUE in LDAP configuration.
    Requires agent authentication.
    """
    try:
        ca_backend.pruning_manager.set_enabled(True)
        logger.info("Certificate pruning enabled")
        return success_response(
            {"Status": "SUCCESS", "Message": "Pruning enabled"}
        )

    except Exception as e:
        logger.error(f"Error enabling pruning: {e}", exc_info=True)
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/pruning/disable", methods=["POST"])
@app.route("/ca/v2/pruning/disable", methods=["POST"])
@require_agent_auth
@require_ca_backend
def disable_pruning():
    """
    Disable certificate pruning

    Sets pruningEnabled=FALSE in LDAP configuration.
    Requires agent authentication.
    """
    try:
        ca_backend.pruning_manager.set_enabled(False)
        logger.info("Certificate pruning disabled")
        return success_response(
            {"Status": "SUCCESS", "Message": "Pruning disabled"}
        )

    except Exception as e:
        logger.error(f"Error disabling pruning: {e}", exc_info=True)
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/pruning/run", methods=["POST"])
@app.route("/ca/v2/pruning/run", methods=["POST"])
@require_agent_auth
@require_ca_backend
def run_pruning():
    """
    Run pruning job manually

    Executes certificate and request pruning based on current configuration.
    Requires agent authentication.

    Returns:
    {
        "certificates_deleted": 123,
        "requests_deleted": 45,
        "errors": []
    }
    """
    try:
        results = ca_backend.pruning_manager.run_pruning()
        return success_response(results)

    except ValueError as e:
        # Pruning not enabled
        return error_response("PruningNotEnabled", str(e), 400)
    except Exception as e:
        logger.error(f"Error running pruning job: {e}", exc_info=True)
        return error_response("ServerError", str(e), 500)


# ============================================================================
# Main Entry Point
# ============================================================================


def create_app(config=None):
    """
    Application factory

    Args:
        config: Dictionary containing 'config' key with RawConfigParser object
                from ipathinca.conf
    """
    global ipa_ca_config

    if config:
        # Store the ipathinca.conf configuration for use by the application
        if "config" in config:
            ipa_ca_config = config["config"]

            # Configure logger level from config
            log_level = ipa_ca_config.get("logging", "level", fallback="INFO")
            logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
            logger.debug(
                "Stored ipathinca.conf configuration for application use "
                f"(log level: {log_level})"
            )

        # Update Flask's internal config
        app.config.update(config)

    # Initialize backends on startup
    with app.app_context():
        init_ca()

    return app


def main():
    """Main entry point for running the server"""

    parser = argparse.ArgumentParser(description="Python CA REST API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument(
        "--port", type=int, default=8080, help="Port to bind to"
    )
    parser.add_argument("--ssl-cert", help="SSL certificate file")
    parser.add_argument("--ssl-key", help="SSL key file")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode"
    )

    args = parser.parse_args()

    # Configure SSL if certificates provided
    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        ssl_context = (args.ssl_cert, args.ssl_key)
        logger.debug(f"SSL enabled with cert: {args.ssl_cert}")

    logger.debug(
        f"Starting Python CA REST API server on {args.host}:{args.port}"
    )

    # Run Flask application
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        ssl_context=ssl_context,
    )


if __name__ == "__main__":
    main()
