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
import json
import secrets

from flask import Flask, request, Response, make_response, jsonify

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

from ipathinca.backend import get_python_ca_backend
from ipathinca import x509_utils
from ipathinca.exceptions import ProfileNotFound
from ipathinca.kra import get_kra
from ipathinca.ldap_utils import is_main_ca_id
from ipathinca.ocsp import get_ocsp_manager
from ipathinca.storage_kra import KRAStorageBackend
from ipathinca.x509_utils import get_subject_dn, get_issuer_dn
from ipalib import errors
from ipaplatform.paths import paths
from ipapython.dn import DN

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
    validate_dn,
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

# Global KRA instance
kra_backend = None

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


def init_kra():
    """Initialize KRA backend"""
    global kra_backend
    if kra_backend is None:
        try:
            logger.info("Initializing KRA backend...")

            # Get KRA instance
            logger.debug("Getting KRA instance...")
            kra = get_kra()

            # Initialize KRA storage
            logger.debug("Initializing KRA storage backend...")
            kra_storage = KRAStorageBackend()

            # Load CA certificate and key from disk (same as enable_kra does)
            # This is needed for signing the KRA transport certificate
            try:
                logger.debug(f"Loading CA cert from {paths.IPA_CA_CRT}")
                with open(paths.IPA_CA_CRT, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(
                        f.read(), default_backend()
                    )

                logger.debug(
                    f"Loading CA key from {paths.IPATHINCA_SIGNING_KEY}"
                )
                with open(paths.IPATHINCA_SIGNING_KEY, "rb") as f:
                    ca_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )

                # Initialize KRA with CA keys and storage
                logger.debug("Calling kra.initialize()...")
                kra.initialize(
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                    storage_backend=kra_storage,
                )
                kra_backend = kra
                logger.info("KRA backend initialized successfully")

            except FileNotFoundError as e:
                logger.error(
                    f"CA keys not found, KRA initialization failed: {e}"
                )
                logger.error(traceback.format_exc())
            except Exception as e:
                logger.error(f"Failed to load CA keys for KRA: {e}")
                logger.error(traceback.format_exc())

        except Exception as e:
            logger.error(f"Failed to initialize KRA backend: {e}")
            logger.error(traceback.format_exc())
            # Don't raise - KRA is optional


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

        # Build subsystems list (CA is always present, KRA is optional)
        subsystems = [
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
        ]

        # Add KRA subsystem if available
        # Try to initialize KRA (non-fatal if it fails)
        if kra_backend is None:
            init_kra()

        if kra_backend is not None:
            subsystems.append(
                {
                    "id": "KRA",
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
                            "SubsystemName": "KRA",
                            "DomainManager": "FALSE",
                        }
                    ],
                }
            )

        domain_info = {
            "id": realm,
            "Subsystem": subsystems,
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
# OCSP Endpoints
# ============================================================================


@app.route("/ca/ocsp", methods=["POST", "GET"])
@app.route("/ca/ocsp/<path:ocsp_data>", methods=["GET"])
@app.route("/ca/ee/ca/ocsp", methods=["POST", "GET"])
@app.route("/ca/ee/ca/ocsp/<path:ocsp_data>", methods=["GET"])
def ocsp_request(ocsp_data=None):
    """
    OCSP responder endpoint (RFC 6960)

    Supports both POST and GET methods:
    - POST: OCSP request in request body (DER-encoded)
    - GET: OCSP request in URL (base64-encoded)
    """
    try:
        init_ca()

        # Get OCSP manager
        ocsp_manager = get_ocsp_manager()

        # Get OCSP responder for main CA
        ocsp_responder = ocsp_manager.get_responder(ca_backend.ca, ca_id="ipa")

        # Parse OCSP request
        if request.method == "POST":
            # POST request - DER-encoded in body
            ocsp_request_der = request.get_data()

        else:  # GET
            # GET request - base64-encoded in URL path
            # Extract base64-encoded request from URL (RFC 6960 section 2.1)
            request_b64 = ocsp_data if ocsp_data else request.path.split("/")[-1]
            if len(request_b64) > 8192:
                return Response(
                    ocsp_responder._create_error_response(),
                    mimetype="application/ocsp-response",
                    status=400,
                )
            try:
                ocsp_request_der = base64.b64decode(request_b64)
            except Exception as e:
                logger.error(f"Failed to decode OCSP request from URL: {e}")
                return Response(
                    ocsp_responder._create_error_response(),
                    mimetype="application/ocsp-response",
                    status=400,
                )

        if not ocsp_request_der:
            logger.warning("Empty OCSP request received")
            return Response(
                ocsp_responder._create_error_response(),
                mimetype="application/ocsp-response",
                status=400,
            )

        # Create OCSP response
        ocsp_response_der = ocsp_responder.create_response(ocsp_request_der)

        # Return OCSP response
        return Response(
            ocsp_response_der,
            mimetype="application/ocsp-response",
            status=200,
        )

    except Exception as e:
        logger.error(f"Error in OCSP request handler: {e}", exc_info=True)
        # Return error response
        try:
            ocsp_manager = get_ocsp_manager()
            ocsp_responder = ocsp_manager.get_responder(
                ca_backend.ca, ca_id="ipa"
            )
            error_response_der = ocsp_responder._create_error_response()
            return Response(
                error_response_der,
                mimetype="application/ocsp-response",
                status=500,
            )
        except Exception:
            return Response(
                b"", mimetype="application/ocsp-response", status=500
            )


@app.route("/ca/rest/ocsp/stats", methods=["GET"])
def ocsp_stats():
    """Get OCSP responder statistics"""
    try:
        init_ca()

        ocsp_manager = get_ocsp_manager()

        stats = ocsp_manager.get_all_stats()

        return success_response(stats)

    except Exception as e:
        logger.error(f"Error getting OCSP stats: {e}")
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/ocsp/cache/clear", methods=["POST"])
def ocsp_clear_cache():
    """Clear OCSP response cache"""
    try:
        init_ca()

        ocsp_manager = get_ocsp_manager()
        ocsp_manager.clear_all_caches()

        return success_response(
            {"Status": "SUCCESS", "Message": "OCSP cache cleared"}
        )

    except Exception as e:
        logger.error(f"Error clearing OCSP cache: {e}")
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/ocsp/cert", methods=["GET"])
def get_ocsp_cert():
    """Get OCSP signing certificate for main CA"""
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        # Get OCSP cert from LDAP
        if (
            hasattr(ca_backend.ca, "ldap_storage")
            and ca_backend.ca.ldap_storage
        ):
            ocsp_data = ca_backend.ca.ldap_storage.get_ocsp_cert(ca_id)

            if ocsp_data:
                return success_response(
                    {
                        "ca_id": ocsp_data["ca_id"],
                        "serial_number": ocsp_data["serial_number"],
                        "not_before": ocsp_data["not_before"],
                        "not_after": ocsp_data["not_after"],
                        "enabled": ocsp_data["enabled"],
                        "certificate": ocsp_data["ocsp_cert"],
                        "cache_timeout": ocsp_data["cache_timeout"],
                    }
                )
            else:
                return error_response(
                    "NotFound",
                    f"OCSP signing certificate for CA {ca_id} not found",
                    404,
                )
        else:
            return error_response(
                "NotSupported", "LDAP storage not enabled", 400
            )

    except Exception as e:
        logger.error(f"Error getting OCSP certificate: {e}")
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/ocsp/cert/renew", methods=["POST"])
def renew_ocsp_cert():
    """Regenerate OCSP signing certificate"""
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        ocsp_manager = get_ocsp_manager()

        # TODO: responder needed?
        # Get responder for this CA
        # responder = ocsp_manager.get_responder(ca_backend.ca, ca_id=ca_id)

        # Delete old cert from LDAP if present
        if (
            hasattr(ca_backend.ca, "ldap_storage")
            and ca_backend.ca.ldap_storage
        ):
            try:
                ca_backend.ca.ldap_storage.delete_ocsp_cert(ca_id)
            except Exception:
                pass

        # Force regeneration by creating a new responder
        del ocsp_manager.responders[ca_id]
        # TODO: new_responder needed?
        # new_responder = ocsp_manager.get_responder(ca_backend.ca,
        #                                            ca_id=ca_id)

        # Get the new certificate info
        if (
            hasattr(ca_backend.ca, "ldap_storage")
            and ca_backend.ca.ldap_storage
        ):
            ocsp_data = ca_backend.ca.ldap_storage.get_ocsp_cert(ca_id)
            if ocsp_data:
                return success_response(
                    {
                        "Status": "SUCCESS",
                        "Message": "OCSP signing certificate renewed",
                        "serial_number": ocsp_data["serial_number"],
                        "not_before": ocsp_data["not_before"],
                        "not_after": ocsp_data["not_after"],
                    }
                )

        return success_response(
            {
                "Status": "SUCCESS",
                "Message": "OCSP signing certificate renewed",
            }
        )

    except Exception as e:
        logger.error(f"Error renewing OCSP certificate: {e}")
        return error_response("ServerError", str(e), 500)


@app.route("/ca/rest/ocsp/responders", methods=["GET"])
def list_ocsp_responders():
    """List all OCSP responders (multi-CA support)"""
    try:
        init_ca()

        # Get all OCSP certs from LDAP
        if (
            hasattr(ca_backend.ca, "ldap_storage")
            and ca_backend.ca.ldap_storage
        ):
            ocsp_certs = ca_backend.ca.ldap_storage.list_ocsp_certs()

            return success_response(
                {"total": len(ocsp_certs), "entries": ocsp_certs}
            )

        # Fallback: get active responders (should not reach here with
        # InternalCA)
        ocsp_manager = get_ocsp_manager()

        responders = []
        for ca_id, responder in ocsp_manager.responders.items():
            responders.append({"ca_id": ca_id, "enabled": True})

            return success_response(
                {"total": len(responders), "entries": responders}
            )

    except Exception as e:
        logger.error(f"Error listing OCSP responders: {e}")
        return error_response("ServerError", str(e), 500)


# ============================================================================
# Certificate Chain Endpoints
# ============================================================================


@app.route("/ca/rest/certs/chain", methods=["GET"])
@app.route("/ca/ee/ca/getCertChain", methods=["GET"])
def get_cert_chain():
    """Get CA certificate chain"""
    try:
        init_ca()

        result = ca_backend.get_certificate_chain()
        cert_chain = result["certificate_chain"]

        # Return as PKCS7 chain or PEM
        output_format = request.args.get("format", "pem")

        if output_format == "pkcs7":
            # DEFERRED: PKCS7 format implementation
            # PEM format is sufficient for current IPA requirements and is
            # more widely supported. PKCS7 can be added later if needed. For
            # now, return PEM even if PKCS7 is requested (Dogtag compatibility
            # - it also falls back to PEM).
            logger.debug(
                "PKCS7 format requested but not yet implemented, returning PEM"
            )
            return Response(cert_chain, mimetype="application/x-pem-file")
        else:
            return Response(cert_chain, mimetype="application/x-pem-file")

    except Exception as e:
        logger.error(f"Error in get_cert_chain: {e}")
        return error_response("ServerError", str(e), 500)


# ============================================================================
# Lightweight CA (Authorities) Endpoints
# ============================================================================


@app.route("/ca/rest/authorities", methods=["GET"])
@app.route("/ca/rest/ca/authorities", methods=["GET"])
@app.route("/ca/v2/authorities", methods=["GET"])
@app.route("/ca/v2/ca/authorities", methods=["GET"])
def list_authorities():
    """
    List all certificate authorities (lightweight CAs)

    Dogtag API compatibility endpoint for listing authorities
    """
    try:
        ca_backend = get_python_ca_backend()

        # Ensure CA certificate is loaded
        ca_backend.ca._ensure_ca_loaded()

        # Get all sub-CAs
        subcas = ca_backend.ca.subca_manager.list_subcas()

        # Build authorities list
        authorities = []

        # Add the main IPA CA as host-authority
        # Convert subject and issuer to IPA DN format using shared utility
        main_subject_dn = get_subject_dn(ca_backend.ca.ca_cert)
        main_issuer_dn = get_issuer_dn(ca_backend.ca.ca_cert)

        main_ca_info = {
            "id": "host-authority",
            "dn": str(main_subject_dn),
            "issuerDN": str(main_issuer_dn),
            "description": "IPA CA",
            "enabled": True,
            "isHostAuthority": "TRUE",  # PKI client expects string "TRUE"
            "serial": str(ca_backend.ca.ca_cert.serial_number),
        }
        authorities.append(main_ca_info)

        # Add sub-CAs
        for subca in subcas:
            ca_info = {
                "id": subca.ca_id,
                "dn": subca.subject_dn,
                "issuerDN": (
                    x509_utils.get_subject_dn_str(subca.parent_ca.ca_cert)
                    if subca.parent_ca
                    else subca.subject_dn
                ),
                "description": f"Sub-CA {subca.ca_id}",
                "enabled": True,
                "isHostAuthority": "FALSE",  # Sub-CAs are not host authority
            }
            if subca.ca_cert:
                ca_info["serial"] = str(subca.ca_cert.serial_number)
            authorities.append(ca_info)

        # PKI client expects just the list of authorities, not wrapped in a
        # response object
        # Return the authorities list directly
        return jsonify(authorities), 200

    except Exception as e:
        logger.error(f"Error listing authorities: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to list authorities: {str(e)}", 500
        )


@app.route("/ca/rest/authorities/<authority_id>", methods=["GET"])
@app.route("/ca/rest/ca/authorities/<authority_id>", methods=["GET"])
@app.route("/ca/v2/authorities/<authority_id>", methods=["GET"])
def get_authority(authority_id):
    """
    Get details of a specific authority

    Args:
        authority_id: Authority identifier
    """
    try:
        ca_backend = get_python_ca_backend()

        # Ensure CA certificate is loaded
        ca_backend.ca._ensure_ca_loaded()

        # Check if authority_id refers to the main IPA CA (by name or UUID)
        is_main_ca = is_main_ca_id(
            authority_id, ca_backend.ca.ca_id, ca_backend.config
        )

        if is_main_ca:
            ca_cert = ca_backend.ca.ca_cert

            # Convert subject and issuer to IPA DN format using shared utility
            # This avoids RFC4514 escaping issues when stored in LDAP
            subject_dn = get_subject_dn(ca_cert)
            issuer_dn = get_issuer_dn(ca_cert)

            authority_info = {
                "id": ca_backend.ca.ca_id or "host-authority",
                "dn": str(subject_dn),
                "issuerDN": str(issuer_dn),
                "description": "IPA CA",
                "enabled": True,
                "serial": str(ca_cert.serial_number),
                "notBefore": ca_cert.not_valid_before_utc.isoformat(),
                "notAfter": ca_cert.not_valid_after_utc.isoformat(),
            }
            return success_response(authority_info)

        # Get sub-CA (force reload to get latest enabled status from LDAP)
        subca = ca_backend.ca.subca_manager.get_subca(
            authority_id, force_reload=True
        )
        if not subca:
            return error_response(
                "CANotFound", f"Authority {authority_id} not found", 404
            )

        # Convert issuer DN to string (if parent exists, use RFC4514 format)
        if subca.parent_ca and subca.parent_ca.ca_cert:
            issuer_dn = subca.parent_ca.ca_cert.subject.rfc4514_string()
        else:
            issuer_dn = str(subca.subject_dn)

        authority_info = {
            "id": subca.ca_id,
            "dn": str(subca.subject_dn),
            "issuerDN": issuer_dn,
            "description": f"Sub-CA {subca.ca_id}",
            "enabled": subca.enabled,
        }

        if subca.ca_cert:
            not_before = subca.ca_cert.not_valid_before_utc.isoformat()
            authority_info.update(
                {
                    "serial": str(subca.ca_cert.serial_number),
                    "notBefore": not_before,
                    "notAfter": subca.ca_cert.not_valid_after_utc.isoformat(),
                }
            )

        return success_response(authority_info)

    except Exception as e:
        logger.error(
            f"Error getting authority {authority_id}: {e}", exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to get authority: {str(e)}", 500
        )


@app.route("/ca/rest/authorities", methods=["POST"])
@app.route("/ca/rest/ca/authorities", methods=["POST"])
@app.route("/ca/v2/authorities", methods=["POST"])
@app.route("/ca/v2/ca/authorities", methods=["POST"])
@require_agent_auth
def create_authority():
    """
    Create a new lightweight CA

    Request body should contain:
        - id: CA identifier (optional, will be extracted from CN if not
              provided)
        - dn: Subject DN for the new CA
        - description: Description (optional)
        - parentID: Parent authority ID (optional, defaults to host-authority)
    """
    try:
        data = request.get_json() or {}

        # Validate required fields
        subject_dn = data.get("dn")
        if not subject_dn:
            return error_response(
                "BadRequest", "Missing required field: dn", 400
            )

        # Validate DN format
        if not validate_dn(subject_dn):
            return error_response(
                "BadRequest", f"Invalid DN format: {subject_dn}", 400
            )

        # Get CA ID from request, or fall back to extracting from subject CN
        ca_id = data.get("id")

        if not ca_id:
            # Fall back to extracting from subject CN (backward compatibility)
            dn_obj = DN(subject_dn)
            for rdn in dn_obj:
                if rdn.attr.lower() == "cn":
                    ca_id = rdn.value
                    break

        if not ca_id:
            return error_response(
                "BadRequest",
                "Missing required field: id (or subject DN must contain CN)",
                400,
            )

        # Get parent CA ID
        parent_id = data.get("parentID", "host-authority")
        if parent_id == "host-authority":
            parent_id = None  # None means issued by main CA

        ca_backend = get_python_ca_backend()

        # Create sub-CA
        subca = ca_backend.ca.subca_manager.create_subca(
            ca_id=ca_id,
            subject_dn=subject_dn,
            parent_ca_id=parent_id,
            key_size=2048,
            validity_days=3650,
        )

        # Convert issuer DN from cryptography Name to string
        if subca.parent_ca and subca.parent_ca.ca_cert:
            issuer_cert = subca.parent_ca.ca_cert
        else:
            issuer_cert = ca_backend.ca.ca_cert

        # Convert cryptography Name to RFC4514 DN string
        issuer_dn = issuer_cert.subject.rfc4514_string()

        # Return created authority info
        authority_info = {
            "id": subca.ca_id,
            "dn": subca.subject_dn,
            "issuerDN": issuer_dn,
            "description": data.get("description", f"Sub-CA {subca.ca_id}"),
            "enabled": True,
            "serial": (
                str(subca.ca_cert.serial_number) if subca.ca_cert else None
            ),
        }

        return success_response(authority_info, status_code=201)

    except Exception as e:
        logger.error(f"Error creating authority: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to create authority: {str(e)}", 500
        )


@app.route("/ca/rest/authorities/<authority_id>/cert", methods=["GET"])
@app.route("/ca/rest/ca/authorities/<authority_id>/cert", methods=["GET"])
@app.route("/ca/v2/authorities/<authority_id>/cert", methods=["GET"])
def get_authority_cert(authority_id):
    """
    Get the certificate of a specific authority

    Args:
        authority_id: Authority identifier
    """
    logger.debug(f"get_authority_cert called for authority_id={authority_id}")

    try:
        # Initialize backend
        try:
            init_ca()
        except Exception as e:
            logger.error(f"Failed to initialize backend: {e}", exc_info=True)
            return error_response(
                "BackendError", f"CA backend not initialized: {str(e)}", 503
            )

        # Handle main IPA CA - special identifiers
        if authority_id in ("host-authority", "ipa"):
            try:
                logger.debug(
                    "Returning main IPA CA certificate (special ID: "
                    f"{authority_id})"
                )
                # CRITICAL FIX: Ensure CA cert is loaded before accessing it
                ca_backend.ca._ensure_ca_loaded()

                ca_cert = ca_backend.ca.ca_cert
                cert_pem = ca_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode("utf-8")
                return Response(cert_pem, mimetype="application/pkix-cert")
            except Exception as e:
                logger.error(f"Failed to get main CA cert: {e}", exc_info=True)
                return error_response(
                    "InternalError",
                    f"Failed to get main CA certificate: {str(e)}",
                    500,
                )

        # Try to look up as a sub-CA first
        # If lookup fails or returns None, fall back to main CA (Dogtag
        # compatibility)
        try:
            logger.debug(f"Looking up sub-CA with ID: {authority_id}")
            subca = ca_backend.ca.subca_manager.get_subca(authority_id)
            logger.debug(f"Sub-CA lookup result: {subca}")
        except Exception as lookup_error:
            # Exception during lookup - could be LDAP error or missing entry
            # In Dogtag, if a UUID doesn't match a sub-CA, it might be the
            # main CA's UUID
            # So log the error but fall through to try main CA
            logger.warning(
                f"Sub-CA lookup failed for {authority_id}, trying main CA: "
                f"{lookup_error}"
            )
            logger.warning("Traceback:", exc_info=True)
            subca = None

        # If sub-CA found, return it
        if subca:
            if not subca.ca_cert:
                logger.warning(
                    f"Sub-CA {authority_id} exists but has no certificate"
                )
                return error_response(
                    "CANotFound",
                    f"Authority {authority_id} has no certificate",
                    404,
                )

            try:
                logger.debug(
                    f"Returning sub-CA certificate for {authority_id}"
                )
                cert_pem = subca.ca_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode("utf-8")
                return Response(cert_pem, mimetype="application/pkix-cert")
            except Exception as e:
                logger.error(
                    f"Failed to serialize sub-CA cert: {e}", exc_info=True
                )
                return error_response(
                    "InternalError",
                    f"Failed to serialize certificate: {str(e)}",
                    500,
                )

        # No sub-CA found - assume this is the main CA's UUID (Dogtag
        # compatibility)
        # In Dogtag, the main CA also has a UUID that can be queried
        logger.debug(
            f"No sub-CA found for {authority_id}, returning main CA "
            "certificate"
        )
        try:
            # CRITICAL FIX: Ensure CA cert is loaded before accessing it
            ca_backend.ca._ensure_ca_loaded()

            ca_cert = ca_backend.ca.ca_cert
            cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            )
            return Response(cert_pem, mimetype="application/pkix-cert")
        except Exception as e:
            logger.error(f"Failed to get main CA cert: {e}", exc_info=True)
            return error_response(
                "InternalError",
                f"Failed to get main CA certificate: {str(e)}",
                500,
            )

    except Exception as e:
        # Catch-all for any unexpected errors
        logger.error(
            f"Unexpected error getting authority cert {authority_id}: {e}",
            exc_info=True,
        )
        logger.error(f"Traceback: {traceback.format_exc()}")
        return error_response(
            "InternalError", f"Unexpected error: {str(e)}", 500
        )


@app.route("/ca/rest/authorities/<authority_id>/chain", methods=["GET"])
@app.route("/ca/rest/ca/authorities/<authority_id>/chain", methods=["GET"])
@app.route("/ca/v2/authorities/<authority_id>/chain", methods=["GET"])
def get_authority_chain(authority_id):
    """
    Get the certificate chain of a specific authority (PKCS#7)

    Args:
        authority_id: Authority identifier
    """
    try:
        ca_backend = get_python_ca_backend()

        # Ensure CA cert is loaded
        ca_backend.ca._ensure_ca_loaded()

        # Build certificate chain
        chain_certs = []

        if authority_id in ("host-authority", "ipa"):
            # Main CA - just return its cert
            chain_certs = [ca_backend.ca.ca_cert]
        else:
            # Try to find sub-CA
            subca = ca_backend.ca.subca_manager.get_subca(authority_id)

            if subca and subca.ca_cert:
                # Sub-CA found - build chain up to root
                chain_certs.append(subca.ca_cert)

                # Add parent certs up to root
                current = subca
                while current.parent_ca:
                    chain_certs.append(current.parent_ca.ca_cert)
                    current = current.parent_ca
            else:
                # No sub-CA found - assume this is the main CA's UUID (Dogtag
                # compatibility)
                # In Dogtag, the main CA also has a UUID that can be queried
                logger.debug(
                    f"No sub-CA found for {authority_id}, returning main CA "
                    "chain"
                )
                chain_certs = [ca_backend.ca.ca_cert]

        # Serialize as PKCS#7 in PEM format (Dogtag compatibility)
        # The IPA plugin expects PEM format with ----BEGIN PKCS7---- headers
        pkcs7_pem = pkcs7.serialize_certificates(
            chain_certs, encoding=serialization.Encoding.PEM
        )

        # Return as text/plain (PEM format)
        return Response(pkcs7_pem, mimetype="text/plain")

    except Exception as e:
        logger.error(
            f"Error getting authority chain {authority_id}: {e}",
            exc_info=True,
        )
        return error_response(
            "InternalError", f"Failed to get authority chain: {str(e)}", 500
        )


@app.route("/ca/rest/authorities/<authority_id>/disable", methods=["POST"])
@app.route("/ca/rest/ca/authorities/<authority_id>/disable", methods=["POST"])
@app.route("/ca/v2/authorities/<authority_id>/disable", methods=["POST"])
@app.route("/ca/v2/ca/authorities/<authority_id>/disable", methods=["POST"])
@require_agent_auth
def disable_authority(authority_id):
    """
    Disable a lightweight CA

    Args:
        authority_id: Authority identifier
    """
    try:
        ca_backend = get_python_ca_backend()

        # Prevent disabling the main IPA CA
        if authority_id in ("host-authority", "ipa"):
            return error_response(
                "BadRequest", "Cannot disable the main IPA CA", 400
            )

        # Get sub-CA
        subca = ca_backend.ca.subca_manager.get_subca(authority_id)
        if not subca:
            return error_response(
                "CANotFound", f"Authority {authority_id} not found", 404
            )

        # Check if already disabled
        if not subca.enabled:
            return error_response(
                "BadRequest",
                f"Authority {authority_id} is already disabled",
                400,
            )

        # Disable the CA (mark as disabled in LDAP)
        subca.enabled = False
        ca_backend.ca.subca_manager.update_subca_status(
            authority_id, enabled=False
        )

        return success_response(
            {
                "Status": "SUCCESS",
                "Message": f"Authority {authority_id} disabled successfully",
            }
        )

    except Exception as e:
        logger.error(
            f"Error disabling authority {authority_id}: {e}", exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to disable authority: {str(e)}", 500
        )


@app.route("/ca/rest/authorities/<authority_id>/enable", methods=["POST"])
@app.route("/ca/rest/ca/authorities/<authority_id>/enable", methods=["POST"])
@app.route("/ca/v2/authorities/<authority_id>/enable", methods=["POST"])
@app.route("/ca/v2/ca/authorities/<authority_id>/enable", methods=["POST"])
@require_agent_auth
def enable_authority(authority_id):
    """
    Enable a lightweight CA

    Args:
        authority_id: Authority identifier
    """
    try:
        ca_backend = get_python_ca_backend()

        # Get sub-CA
        subca = ca_backend.ca.subca_manager.get_subca(authority_id)
        if not subca:
            return error_response(
                "CANotFound", f"Authority {authority_id} not found", 404
            )

        # Check if already enabled
        if subca.enabled:
            return error_response(
                "BadRequest",
                f"Authority {authority_id} is already enabled",
                400,
            )

        # Enable the CA (mark as enabled in LDAP)
        subca.enabled = True
        ca_backend.ca.subca_manager.update_subca_status(
            authority_id, enabled=True
        )

        return success_response(
            {
                "Status": "SUCCESS",
                "Message": f"Authority {authority_id} enabled successfully",
            }
        )

    except Exception as e:
        logger.error(
            f"Error enabling authority {authority_id}: {e}", exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to enable authority: {str(e)}", 500
        )


@app.route("/ca/rest/authorities/<authority_id>", methods=["DELETE"])
@app.route("/ca/rest/ca/authorities/<authority_id>", methods=["DELETE"])
@app.route("/ca/v2/authorities/<authority_id>", methods=["DELETE"])
@app.route("/ca/v2/ca/authorities/<authority_id>", methods=["DELETE"])
@require_agent_auth
def delete_authority(authority_id):
    """
    Delete a lightweight CA (includes LDAP deletion)

    Args:
        authority_id: Authority identifier
    """
    try:
        ca_backend = get_python_ca_backend()

        # Prevent deleting the main IPA CA
        if authority_id in ("host-authority", "ipa"):
            return error_response(
                "BadRequest", "Cannot delete the main IPA CA", 400
            )

        # Get sub-CA
        subca = ca_backend.ca.subca_manager.get_subca(authority_id)
        if not subca:
            return error_response(
                "CANotFound", f"Authority {authority_id} not found", 404
            )

        # Delete the CA (includes LDAP deletion)
        ca_backend.ca.subca_manager.delete_subca(authority_id)

        return success_response(
            {
                "Status": "SUCCESS",
                "Message": f"Authority {authority_id} deleted successfully",
            }
        )

    except Exception as e:
        logger.error(
            f"Error deleting authority {authority_id}: {e}", exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to delete authority: {str(e)}", 500
        )


# ============================================================================
# Range Management Endpoints (Multi-Master Replication)
# ============================================================================


@app.route("/ca/rest/ranges", methods=["GET"])
@app.route("/ca/v2/ranges", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def list_all_ranges():
    """
    List all serial number ranges across all replicas

    Returns comprehensive range information for multi-master deployments
    """
    try:
        storage = ca_backend.ca.storage

        if hasattr(storage, "list_all_ranges"):
            ranges = storage.list_all_ranges()
            return jsonify({"entries": ranges, "total": len(ranges)}), 200
        else:
            return error_response(
                "NotImplemented", "Range management not available", 501
            )

    except Exception as e:
        logger.error(f"Error listing ranges: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to list ranges: {str(e)}", 500
        )


@app.route("/ca/rest/ranges/replica/<replica_id>", methods=["GET"])
@app.route("/ca/v2/ranges/replica/<replica_id>", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def get_replica_ranges(replica_id):
    """
    Get all serial ranges allocated to a specific replica

    Args:
        replica_id: Replica identifier

    Returns list of (begin_range, end_range) tuples
    """
    try:
        storage = ca_backend.ca.storage

        if hasattr(storage, "get_replica_ranges"):
            ranges = storage.get_replica_ranges(replica_id)
            return (
                jsonify(
                    {
                        "replica_id": replica_id,
                        "ranges": ranges,
                        "total": len(ranges),
                    }
                ),
                200,
            )
        else:
            return error_response(
                "NotImplemented", "Range management not available", 501
            )

    except Exception as e:
        logger.error(f"Error getting replica ranges: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to get replica ranges: {str(e)}", 500
        )


@app.route("/ca/rest/ranges/allocate", methods=["POST"])
@app.route("/ca/v2/ranges/allocate", methods=["POST"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def allocate_serial_range():
    """
    Allocate a new serial number range for a replica

    Request body:
    {
        "replica_id": "replica1",
        "range_size": 10000  (optional, default: 10000)
    }

    Returns:
    {
        "replica_id": "replica1",
        "begin_range": 1,
        "end_range": 10000,
        "range_size": 10000
    }
    """
    try:
        data = request.get_json() or {}
        replica_id = data.get("replica_id")
        range_size = data.get("range_size", 10000)

        if not replica_id:
            return error_response("BadRequest", "replica_id is required", 400)

        storage = ca_backend.ca.storage

        if hasattr(storage, "allocate_serial_range"):
            begin, end = storage.allocate_serial_range(replica_id, range_size)
            return (
                jsonify(
                    {
                        "replica_id": replica_id,
                        "begin_range": begin,
                        "end_range": end,
                        "range_size": end - begin + 1,
                    }
                ),
                201,
            )
        else:
            return error_response(
                "NotImplemented", "Range allocation not available", 501
            )

    except Exception as e:
        logger.error(f"Error allocating range: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to allocate range: {str(e)}", 500
        )


@app.route(
    "/ca/rest/ranges/replica/<replica_id>/<int:begin_range>", methods=["PUT"]
)
@app.route(
    "/ca/v2/ranges/replica/<replica_id>/<int:begin_range>", methods=["PUT"]
)
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def update_serial_range(replica_id, begin_range):
    """
    Update (extend) a serial number range

    Request body:
    {
        "new_end_range": 20000
    }

    This extends the range endpoint, useful when a range is running low.
    """
    try:
        data = request.get_json() or {}
        new_end_range = data.get("new_end_range")

        if not new_end_range:
            return error_response(
                "BadRequest", "new_end_range is required", 400
            )

        storage = ca_backend.ca.storage

        if hasattr(storage, "update_range"):
            storage.update_range(replica_id, begin_range, new_end_range)
            return (
                success_response(
                    {
                        "message": "Range updated successfully",
                        "replica_id": replica_id,
                        "begin_range": begin_range,
                        "new_end_range": new_end_range,
                    }
                ),
                200,
            )
        else:
            return error_response(
                "NotImplemented", "Range update not available", 501
            )

    except ValueError as e:
        return error_response("BadRequest", str(e), 400)
    except Exception as e:
        logger.error(f"Error updating range: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to update range: {str(e)}", 500
        )


@app.route(
    "/ca/rest/ranges/replica/<replica_id>/<int:begin_range>",
    methods=["DELETE"],
)
@app.route(
    "/ca/v2/ranges/replica/<replica_id>/<int:begin_range>", methods=["DELETE"]
)
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def delete_serial_range(replica_id, begin_range):
    """
    Delete a specific serial range allocation

    Args:
        replica_id: Replica identifier
        begin_range: Beginning of the range to delete
    """
    try:
        storage = ca_backend.ca.storage

        if hasattr(storage, "delete_range"):
            storage.delete_range(replica_id, begin_range)
            return (
                success_response(
                    {
                        "message": (
                            f"Range {replica_id}-{begin_range} deleted"
                            " successfully"
                        )
                    }
                ),
                200,
            )
        else:
            return error_response(
                "NotImplemented", "Range deletion not available", 501
            )

    except Exception as e:
        logger.error(f"Error deleting range: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to delete range: {str(e)}", 500
        )


@app.route("/ca/rest/ranges/replica/<replica_id>", methods=["DELETE"])
@app.route("/ca/v2/ranges/replica/<replica_id>", methods=["DELETE"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def delete_all_replica_ranges(replica_id):
    """
    Delete all serial ranges allocated to a specific replica

    Args:
        replica_id: Replica identifier

    This is useful when decommissioning a replica.
    """
    try:
        storage = ca_backend.ca.storage

        if hasattr(storage, "delete_replica_ranges"):
            storage.delete_replica_ranges(replica_id)
            return (
                success_response(
                    {
                        "message": (
                            f"All ranges for replica {replica_id} deleted"
                            " successfully"
                        )
                    }
                ),
                200,
            )
        else:
            return error_response(
                "NotImplemented", "Range deletion not available", 501
            )

    except Exception as e:
        logger.error(f"Error deleting replica ranges: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to delete replica ranges: {str(e)}", 500
        )


# ----------------------------------------------------------------------------
# KRA (Key Recovery Authority)
# ----------------------------------------------------------------------------


@app.route("/kra/rest/info", methods=["GET"])
@app.route("/kra/v2/info", methods=["GET"])
def kra_info():
    """Get KRA information - compatible with Dogtag /kra/rest/info"""
    try:
        # Initialize KRA if needed
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        return success_response(
            {
                "Version": "1.0",
                "backend": "ipathinca-kra",
                "Attributes": {"subsystem": "kra", "status": "running"},
            }
        )

    except Exception as e:
        logger.error(f"Error in kra_info: {e}", exc_info=True)
        return error_response("ServerError", str(e), 500)


@app.route("/kra/admin/kra/getStatus", methods=["GET"])
def kra_status():
    """Get KRA status - compatible with Dogtag getStatus endpoint"""
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return Response(
                "status=unavailable", mimetype="text/plain", status=503
            )

        return Response("status=running", mimetype="text/plain")

    except Exception as e:
        logger.error("Error in kra_status: %s", e)
        return Response(
            f"status=ERROR: {e}", mimetype="text/plain", status=500
        )


@app.route("/kra/rest/account/login", methods=["GET", "POST"])
@require_agent_auth
def kra_account_login():
    """KRA account login endpoint for REST API session management."""
    return _account_login()


@app.route("/kra/v2/account/login", methods=["GET", "POST"])
@require_agent_auth
def kra_account_login_v2():
    """KRA account login endpoint for REST API v2 session management."""
    return _account_login()


@app.route("/kra/rest/account/logout", methods=["GET", "POST"])
def kra_account_logout():
    """KRA account logout (compatibility endpoint - clears session cookie)"""
    return _account_logout()


@app.route("/kra/v2/account/logout", methods=["GET", "POST"])
def kra_account_logout_v2():
    """KRA account logout endpoint for REST API v2 (returns 204)"""
    return _account_logout_v2()


# Key Management Endpoints
# ----------------------------------------------------------------------------


@app.route("/kra/rest/agent/keyrequests", methods=["POST"])
@app.route("/kra/v2/agent/keyrequests", methods=["POST"])
@require_agent_auth
def submit_key_request():
    """
    Submit a key request (archive, recovery, or generation)

    This is the main endpoint used by python-pki library for all key
    operations.
    The request type is determined by the requestType field in the JSON body.

    Request types:
    - keyArchivalRequest: Archive a key
    - keyRecoveryRequest: Retrieve a key
    - symKeyGenerationRequest: Generate symmetric key
    - asymKeyGenerationRequest: Generate asymmetric key pair

    Returns:
    {
        "requestType": "...",
        "requestStatus": "complete",
        "requestID": "...",
        "keyId": "..."
    }
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        data = request.get_json() or {}

        # Log the request for debugging
        logger.debug(f"KRA key request received: {json.dumps(data, indent=2)}")

        # The request comes as a ResourceMessage with ClassName and Attributes
        # ClassName is like "com.netscape.certsrv.key.KeyArchivalRequest"
        class_name = data.get("ClassName", "")

        # Determine request type from ClassName
        if "KeyArchivalRequest" in class_name:
            request_type = "keyArchivalRequest"
        elif "KeyRecoveryRequest" in class_name:
            request_type = "keyRecoveryRequest"
        else:
            # Fallback to old format for backward compatibility
            request_type = data.get("requestType")

        if not request_type:
            return error_response(
                "BadRequest", "Missing requestType or ClassName field", 400
            )

        # Extract attributes from ResourceMessage format
        attributes = data.get("Attributes", {})
        attr_dict = {}
        if "Attribute" in attributes:
            # Convert Attribute list to dict for easy access
            for attr in attributes["Attribute"]:
                attr_dict[attr.get("name")] = attr.get("value")

        # Handle keyArchivalRequest
        if request_type == "keyArchivalRequest":
            # Extract archival parameters from attributes
            client_key_id = attr_dict.get("clientKeyID")
            wrapped_data_b64 = attr_dict.get("wrappedPrivateData")
            trans_wrapped_key_b64 = attr_dict.get("transWrappedSessionKey")
            # data_type = attr_dict.get("dataType", "passPhrase")
            # algorithm_oid = attr_dict.get("algorithmOID")
            sym_alg_params_b64 = attr_dict.get("symmetricAlgorithmParams")

            if not wrapped_data_b64:
                return error_response(
                    "BadRequest", "Missing wrappedPrivateData", 400
                )

            # Decode base64 data
            try:
                wrapped_data = base64.b64decode(wrapped_data_b64)

                # IPA sends two-layer encryption:
                # 1. wrappedPrivateData: secret encrypted with session key
                # 2. transWrappedSessionKey: session key encrypted with
                #    transport key

                if trans_wrapped_key_b64:
                    # Two-layer encryption (IPA vault format)
                    trans_wrapped_key = base64.b64decode(trans_wrapped_key_b64)

                    # Unwrap session key using transport private key
                    session_key = (
                        kra_backend.transport_key_manager.unwrap_secret(
                            trans_wrapped_key
                        )
                    )

                    # Decrypt wrapped data with session key
                    # The algorithm OID tells us what cipher to use
                    # {2 16 840 1 101 3 4 1 2} = AES-128-CBC
                    if sym_alg_params_b64:
                        iv = base64.b64decode(sym_alg_params_b64)
                    else:
                        iv = b"\x00" * 16  # Default IV if not provided

                    # Decrypt using AES-CBC
                    cipher = Cipher(
                        algorithms.AES(session_key),
                        modes.CBC(iv),
                        backend=default_backend(),
                    )
                    decryptor = cipher.decryptor()
                    plaintext_padded = (
                        decryptor.update(wrapped_data) + decryptor.finalize()
                    )

                    # Remove PKCS7 padding
                    padding_length = plaintext_padded[-1]
                    plaintext = plaintext_padded[:-padding_length]

                    # Now plaintext is the actual secret - store it directly
                    # by encrypting with storage key (not transport key)
                    encrypted_for_storage = (
                        kra_backend.storage_key_manager.encrypt_for_storage(
                            plaintext
                        )
                    )

                    # Store in LDAP directly (bypass archive_secret to avoid
                    # double transport encryption)
                    key_id = kra_backend.storage_backend.store_key(
                        encrypted_data=encrypted_for_storage,
                        owner=client_key_id or "unknown",
                        algorithm="AES",
                        key_size=len(session_key) * 8,  # Key size in bits
                        status="active",
                    )
                else:
                    # Single-layer encryption (legacy format)
                    # wrapped_data is encrypted with transport key
                    encrypted_secret = wrapped_data
                    key_id = kra_backend.archive_secret(
                        encrypted_secret=encrypted_secret,
                        owner=client_key_id or "unknown",
                        algorithm="AES",
                        key_size=256,
                    )

            except Exception as e:
                logger.error(
                    f"Error processing archival request: {e}", exc_info=True
                )
                return error_response(
                    "BadRequest", f"Failed to process archival: {e}", 400
                )

            # Return response in KeyRequestResponse format
            return success_response(
                {
                    "RequestInfo": {
                        "requestType": "keyArchivalRequest",
                        "requestStatus": "complete",
                        "requestURL": f"/kra/rest/agent/keyrequests/{key_id}",
                        "keyURL": f"/kra/rest/agent/keys/{key_id}",
                    }
                }
            )

        # Handle keyRecoveryRequest
        elif request_type == "keyRecoveryRequest":
            # Extract recovery parameters from attributes
            key_id = attr_dict.get("keyId")
            request_id = attr_dict.get("requestId")
            trans_wrapped_key_b64 = attr_dict.get("transWrappedSessionKey")

            if not key_id and not request_id:
                return error_response(
                    "BadRequest", "Missing keyId or requestId", 400
                )

            # Use key_id or request_id for retrieval
            retrieval_id = request_id if request_id else key_id

            # Get requester from authentication (placeholder)
            requester = "admin"

            # Retrieve the secret (wrapped for transmission)
            wrapped_secret = kra_backend.retrieve_secret(
                retrieval_id, requester
            )

            # Encode to base64 for JSON
            wrapped_secret_b64 = base64.b64encode(wrapped_secret).decode(
                "utf-8"
            )

            # Get key metadata
            key_record = kra_backend.storage_backend.get_key(retrieval_id)
            if not key_record:
                return error_response(
                    "KeyNotFound", f"Key {retrieval_id} not found", 404
                )

            # Return response in KeyRequestResponse format
            return success_response(
                {
                    "RequestInfo": {
                        "requestType": "keyRecoveryRequest",
                        "requestStatus": "complete",
                        "requestURL": (
                            f"/kra/rest/agent/keyrequests/{retrieval_id}"
                        ),
                        "keyURL": f"/kra/rest/agent/keys/{retrieval_id}",
                    },
                    "KeyData": {
                        "wrappedPrivateData": wrapped_secret_b64,
                        "algorithm": key_record.get("algorithm", "AES"),
                        "size": key_record.get("key_size", 256),
                    },
                }
            )

        else:
            return error_response(
                "BadRequest", f"Unsupported request type: {request_type}", 400
            )

    except ValueError as e:
        return error_response("KeyNotFound", str(e), 404)
    except Exception as e:
        logger.error(f"Error processing key request: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to process key request: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keyrequests", methods=["GET"])
@app.route("/kra/v2/agent/keyrequests", methods=["GET"])
@require_agent_auth
def list_key_requests():
    """
    List key requests with optional filtering

    Query parameters:
    - requestState: Filter by request state (pending, complete, rejected, etc.)
    - requestType: Filter by request type (archival, recovery, etc.)
    - clientKeyID: Filter by client key ID
    - start: Start index for pagination (default: 0)
    - size: Maximum number of results (default: 20)

    Returns list of key request info
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Parse query parameters
        request_state = request.args.get("requestState")
        request_type = request.args.get("requestType")
        client_key_id = request.args.get("clientKeyID")
        # start = int(request.args.get("start", 0))
        # size = int(request.args.get("size", 20))

        # For now, return empty list as we auto-complete requests
        # In a full implementation, this would query LDAP for request records
        logger.debug(
            f"List key requests: state={request_state}, type={request_type}, "
            f"client={client_key_id}"
        )

        return jsonify({"entries": [], "total": 0}), 200

    except Exception as e:
        logger.error(f"Error listing key requests: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to list key requests: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keyrequests/<request_id>", methods=["GET"])
@app.route("/kra/v2/agent/keyrequests/<request_id>", methods=["GET"])
@require_agent_auth
def get_key_request_info(request_id):
    """
    Get key request info by request ID

    Returns request status, type, and associated key ID if available
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Get request from storage
        if hasattr(kra_backend.storage_backend, "get_key_request"):
            request_info = kra_backend.storage_backend.get_key_request(
                request_id
            )

            if not request_info:
                return error_response(
                    "RequestNotFound",
                    f"Key request {request_id} not found",
                    404,
                )

            return success_response(
                {
                    "requestType": request_info.get("request_type"),
                    "requestStatus": request_info.get("status"),
                    "requestURL": f"/kra/rest/agent/keyrequests/{request_id}",
                    "keyURL": f"/kra/rest/agent/keys/{request_id}",
                }
            )
        else:
            # For ipathinca, requests are auto-completed
            # Try to get the key directly (request_id == key_id)
            key_record = kra_backend.storage_backend.get_key(request_id)

            if not key_record:
                return error_response(
                    "RequestNotFound",
                    f"Key request {request_id} not found",
                    404,
                )

            return success_response(
                {
                    "requestType": "keyArchivalRequest",
                    "requestStatus": "complete",
                    "requestURL": f"/kra/rest/agent/keyrequests/{request_id}",
                    "keyURL": f"/kra/rest/agent/keys/{request_id}",
                }
            )

    except Exception as e:
        logger.error(f"Error getting key request info: {e}", exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get key request info: {str(e)}",
            500,
        )


@app.route(
    "/kra/rest/agent/keyrequests/<request_id>/approve", methods=["POST"]
)
@app.route("/kra/v2/agent/keyrequests/<request_id>/approve", methods=["POST"])
@require_agent_auth
def approve_key_request(request_id):
    """
    Approve a pending key request

    In ipathinca, all requests are auto-approved during submission,
    so this endpoint is a no-op for compatibility.
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Check if request/key exists
        key_record = kra_backend.storage_backend.get_key(request_id)

        if not key_record:
            return error_response(
                "RequestNotFound", f"Key request {request_id} not found", 404
            )

        # Request is already complete (auto-approved)
        return success_response(
            {
                "requestType": "keyArchivalRequest",
                "requestStatus": "complete",
                "requestURL": f"/kra/rest/agent/keyrequests/{request_id}",
                "keyURL": f"/kra/rest/agent/keys/{request_id}",
            }
        )

    except Exception as e:
        logger.error(f"Error approving key request: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to approve key request: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keyrequests/<request_id>/reject", methods=["POST"])
@app.route("/kra/v2/agent/keyrequests/<request_id>/reject", methods=["POST"])
@require_agent_auth
def reject_key_request(request_id):
    """
    Reject a key request

    This marks the key as inactive in ipathinca.
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Mark key as inactive
        success = kra_backend.modify_key_status(request_id, "inactive")

        if not success:
            return error_response(
                "RequestNotFound", f"Key request {request_id} not found", 404
            )

        return success_response(
            {
                "requestType": "keyArchivalRequest",
                "requestStatus": "rejected",
                "requestURL": f"/kra/rest/agent/keyrequests/{request_id}",
            }
        )

    except Exception as e:
        logger.error(f"Error rejecting key request: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to reject key request: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keyrequests/<request_id>/cancel", methods=["POST"])
@app.route("/kra/v2/agent/keyrequests/<request_id>/cancel", methods=["POST"])
@require_agent_auth
def cancel_key_request(request_id):
    """
    Cancel a key request

    This deletes the key in ipathinca.
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Delete the key
        if hasattr(kra_backend.storage_backend, "delete_key"):
            success = kra_backend.storage_backend.delete_key(request_id)

            if not success:
                return error_response(
                    "RequestNotFound",
                    f"Key request {request_id} not found",
                    404,
                )

            return success_response(
                {
                    "requestType": "keyArchivalRequest",
                    "requestStatus": "cancelled",
                    "requestURL": f"/kra/rest/agent/keyrequests/{request_id}",
                }
            )
        else:
            return error_response(
                "NotImplemented", "Key deletion not available", 501
            )

    except Exception as e:
        logger.error(f"Error cancelling key request: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to cancel key request: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keys/archive", methods=["POST"])
@app.route("/kra/v2/agent/keys/archive", methods=["POST"])
@app.route("/kra/agent/keys/archive", methods=["POST"])
@require_agent_auth
def archive_key():
    """
    Archive encrypted secret in KRA

    Request body:
    {
        "wrappedPrivateData": "base64-encoded-encrypted-secret",
        "clientKeyId": "vault-name-or-id",
        "dataType": "symmetricKey" | "passPhrase" | "asymmetricKey",
        "keyAlgorithm": "AES",
        "keySize": 256
    }

    Returns:
    {
        "KeyId": "0x1a",
        "Status": "complete"
    }
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        data = request.get_json() or {}

        # Extract encrypted secret (base64-encoded)
        wrapped_data_b64 = data.get("wrappedPrivateData")
        if not wrapped_data_b64:
            return error_response(
                "BadRequest", "Missing wrappedPrivateData", 400
            )

        # Decode from base64
        try:
            encrypted_secret = base64.b64decode(wrapped_data_b64)
        except Exception as e:
            return error_response(
                "BadRequest", f"Invalid base64 encoding: {e}", 400
            )

        # Get owner/client key ID
        owner = data.get("clientKeyId", "unknown")

        # Get key parameters
        algorithm = data.get("keyAlgorithm", "AES")
        key_size = int(data.get("keySize", 256))

        # Archive the secret
        key_id = kra_backend.archive_secret(
            encrypted_secret=encrypted_secret,
            owner=owner,
            algorithm=algorithm,
            key_size=key_size,
        )

        return (
            success_response(
                {
                    "KeyId": key_id,
                    "Status": "complete",
                    # Use key_id as request_id for simplicity:
                    "RequestId": key_id,
                }
            ),
            201,
        )

    except Exception as e:
        logger.error(f"Error archiving key: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to archive key: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keys/retrieve", methods=["POST"])
@app.route("/kra/v2/agent/keys/retrieve", methods=["POST"])
@app.route("/kra/agent/keys/retrieve", methods=["POST"])
@require_agent_auth
def retrieve_key():
    """
    Retrieve encrypted secret from KRA

    Request body:
    {
        "keyId": "0x1a"
    }

    Returns:
    {
        "KeyId": "0x1a",
        "WrappedPrivateData": "base64-encoded-encrypted-secret",
        "Algorithm": "AES",
        "Size": 256,
        "Status": "complete"
    }
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        data = request.get_json() or {}

        # Debug logging to see actual request structure
        logger.debug(f"KRA retrieve_key request: {json.dumps(data, indent=2)}")

        # python-pki sends KeyRecoveryRequest as ResourceMessage format
        # Extract keyId from Attributes if present (ResourceMessage format)
        class_name = data.get("ClassName", "")

        if "KeyRecoveryRequest" in class_name or "Attributes" in data:
            # ResourceMessage format - extract from Attributes
            attributes = data.get("Attributes", {})
            attr_dict = {}
            if "Attribute" in attributes:
                for attr in attributes["Attribute"]:
                    attr_dict[attr.get("name")] = attr.get("value")

            key_id = attr_dict.get("keyId") or attr_dict.get("requestId")
            trans_wrapped_key_b64 = attr_dict.get("transWrappedSessionKey")
        else:
            # Legacy format - direct fields
            key_id = data.get("keyId")
            trans_wrapped_key_b64 = None

        if not key_id:
            logger.error(f"Missing keyId in request. Request data: {data}")
            return error_response("BadRequest", "Missing keyId", 400)

        # Get requester from authentication (TODO: implement proper auth)
        # requester = "admin"  # Placeholder

        # Get key metadata
        key_record = kra_backend.storage_backend.get_key(key_id)
        if not key_record:
            return error_response(
                "KeyNotFound", f"Key {key_id} not found", 404
            )

        # Decrypt the secret from storage
        secret = kra_backend.storage_key_manager.decrypt_from_storage(
            key_record["encrypted_data"]
        )

        # Check if client provided a session key for wrapping
        if trans_wrapped_key_b64:
            # Client wants response wrapped with their session key
            # 1. Unwrap the session key using transport private key
            trans_wrapped_key = base64.b64decode(trans_wrapped_key_b64)
            session_key = kra_backend.transport_key_manager.unwrap_secret(
                trans_wrapped_key
            )

            # 2. Wrap the secret with the session key
            # Use AES-CBC with a random IV (same as archival)

            # Generate random IV
            iv = secrets.token_bytes(16)

            # Add PKCS7 padding to the secret
            padder = sym_padding.PKCS7(128).padder()
            padded_secret = padder.update(secret) + padder.finalize()

            # Encrypt with AES-CBC
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.CBC(iv),
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()
            wrapped_secret = (
                encryptor.update(padded_secret) + encryptor.finalize()
            )

            # Encode both IV and wrapped secret
            wrapped_secret_b64 = base64.b64encode(wrapped_secret).decode(
                "utf-8"
            )
            iv_b64 = base64.b64encode(iv).decode("utf-8")

            # Return with IV as nonce_data
            return success_response(
                {
                    "wrappedPrivateData": wrapped_secret_b64,
                    "nonceData": iv_b64,
                    "algorithm": key_record.get("algorithm", "AES"),
                    "size": key_record.get("key_size", 256),
                }
            )
        else:
            # Legacy mode: wrap with transport key
            wrapped_secret = kra_backend.transport_key_manager.wrap_secret(
                secret
            )
            wrapped_secret_b64 = base64.b64encode(wrapped_secret).decode(
                "utf-8"
            )

            return success_response(
                {
                    "wrappedPrivateData": wrapped_secret_b64,
                    "algorithm": key_record.get("algorithm", "AES"),
                    "size": key_record.get("key_size", 256),
                }
            )

    except ValueError as e:
        return error_response("KeyNotFound", str(e), 404)
    except Exception as e:
        logger.error(f"Error retrieving key: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to retrieve key: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keys", methods=["GET"])
@app.route("/kra/v2/agent/keys", methods=["GET"])
@app.route("/kra/agent/keys", methods=["GET"])
@require_agent_auth
def list_keys():
    """
    List archived keys

    Query parameters:
    - owner: Filter by owner (optional)
    - status: Filter by status (optional)
    - size: Maximum number of results (default: 100)

    Returns list of key metadata
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Parse query parameters
        owner = request.args.get("owner")
        status = request.args.get("status")
        size = int(request.args.get("size", 100))

        # List keys
        keys = kra_backend.list_keys(owner=owner, status=status)

        # Limit results
        keys = keys[:size]

        # Format for Dogtag compatibility
        # Note: python-pki expects specific field names (case-sensitive)
        entries = []
        for key_info in keys:
            entries.append(
                {
                    "keyURL": f"/kra/rest/agent/keys/{key_info['key_id']}",
                    "clientKeyID": key_info.get("owner"),
                    "status": key_info.get("status", "active"),
                    "algorithm": key_info.get("algorithm", "AES"),
                    "size": key_info.get("key_size", 256),
                }
            )

        return jsonify({"entries": entries, "total": len(entries)}), 200

    except Exception as e:
        logger.error(f"Error listing keys: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to list keys: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keys/<key_id>", methods=["GET"])
@app.route("/kra/v2/agent/keys/<key_id>", methods=["GET"])
@app.route("/kra/agent/keys/<key_id>", methods=["GET"])
@require_agent_auth
def get_key_info(key_id):
    """
    Get key metadata (without retrieving the actual secret)

    Returns key information including owner, algorithm, status
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Get key metadata from storage
        key_record = kra_backend.storage_backend.get_key(key_id)

        if not key_record:
            return error_response(
                "KeyNotFound", f"Key {key_id} not found", 404
            )

        return success_response(
            {
                "KeyId": key_id,
                "ClientKeyID": key_record.get("owner"),
                "Status": key_record.get("status", "active"),
                "Algorithm": key_record.get("algorithm", "AES"),
                "Size": key_record.get("key_size", 256),
                "Created": key_record.get("created"),
            }
        )

    except Exception as e:
        logger.error(f"Error getting key info: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to get key info: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keys/<key_id>", methods=["POST"])
@app.route("/kra/v2/agent/keys/<key_id>", methods=["POST"])
@app.route("/kra/agent/keys/<key_id>", methods=["POST"])
@require_agent_auth
def modify_key_status(key_id):
    """
    Modify key status (active, inactive, archived)

    python-pki sends status as URL parameter, not in body:
    POST /kra/rest/agent/keys/{key_id}?status=inactive
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # python-pki sends status as URL parameter
        new_status = request.args.get("status")

        if not new_status:
            return error_response("BadRequest", "Missing Status field", 400)

        # Validate status
        valid_statuses = ["active", "inactive", "archived"]
        if new_status.lower() not in valid_statuses:
            return error_response(
                "BadRequest",
                f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
                400,
            )

        # Update status
        success = kra_backend.modify_key_status(key_id, new_status.lower())

        if not success:
            return error_response(
                "KeyNotFound", f"Key {key_id} not found", 404
            )

        return success_response(
            {
                "KeyId": key_id,
                "Status": new_status.lower(),
                "Message": f"Key status updated to {new_status}",
            }
        )

    except Exception as e:
        logger.error(f"Error modifying key status: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to modify key status: {str(e)}", 500
        )


@app.route("/kra/rest/agent/keys/active/<client_key_id>", methods=["GET"])
@app.route("/kra/v2/agent/keys/active/<client_key_id>", methods=["GET"])
@app.route("/kra/agent/keys/active/<client_key_id>", methods=["GET"])
@require_agent_auth
def get_active_key_info(client_key_id):
    """
    Get active key info for a specific client

    Returns the most recent active key for the specified client ID.
    This is used when a client has multiple keys and you want the current one.
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # List keys for this client, filtered by active status
        keys = kra_backend.list_keys(owner=client_key_id, status="active")

        if not keys:
            return error_response(
                "KeyNotFound",
                f"No active key found for client {client_key_id}",
                404,
            )

        # Return the most recent one (keys are sorted by creation date)
        active_key = keys[0]

        return success_response(
            {
                "keyURL": f"/kra/rest/agent/keys/{active_key['key_id']}",
                "clientKeyID": active_key.get("owner"),
                "status": active_key.get("status", "active"),
                "algorithm": active_key.get("algorithm", "AES"),
                "size": active_key.get("key_size", 256),
            }
        )

    except Exception as e:
        logger.error(f"Error getting active key info: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to get active key info: {str(e)}", 500
        )


# KRA Transport Certificate Endpoint
# ----------------------------------------------------------------------------


@app.route("/kra/rest/agent/keys/transportCert", methods=["GET"])
@app.route("/kra/v2/agent/keys/transportCert", methods=["GET"])
@app.route("/kra/agent/keys/transportCert", methods=["GET"])
def get_transport_cert():
    """
    Get KRA transport certificate (public key for wrapping secrets)

    Clients use this certificate to encrypt secrets before sending to KRA.

    Returns PEM-encoded transport certificate
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Get transport certificate
        transport_cert_pem = kra_backend.get_transport_cert()

        # Return as PEM (Dogtag compatibility)
        return Response(transport_cert_pem, mimetype="application/x-pem-file")

    except Exception as e:
        logger.error(f"Error getting transport cert: {e}", exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get transport certificate: {str(e)}",
            500,
        )


@app.route("/kra/rest/config/cert/transport", methods=["GET"])
@app.route("/kra/v2/config/cert/transport", methods=["GET"])
def get_transport_cert_config():
    """
    Get KRA transport certificate via config endpoint (python-pki
    compatibility)

    This endpoint returns JSON format (CertData) unlike
    /kra/rest/agent/keys/transportCert
    which returns raw PEM. python-pki's get_transport_cert() expects JSON
    format.
    """
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Get transport certificate PEM
        transport_cert_pem = kra_backend.get_transport_cert()

        # Return as JSON in CertData format (python-pki compatibility)
        # The Encoded field should contain the PEM certificate
        cert_data = {"Encoded": transport_cert_pem}

        return success_response(cert_data)

    except Exception as e:
        logger.error(f"Error getting transport cert: {e}", exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get transport certificate: {str(e)}",
            500,
        )


# KRA Statistics Endpoint
# ----------------------------------------------------------------------------


@app.route("/kra/rest/stats", methods=["GET"])
@app.route("/kra/v2/stats", methods=["GET"])
def kra_stats():
    """Get KRA statistics (key counts, etc.)"""
    try:
        if kra_backend is None:
            init_kra()

        if kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        stats = kra_backend.storage_backend.get_statistics()

        return success_response(stats)

    except Exception as e:
        logger.error(f"Error getting KRA stats: {e}", exc_info=True)
        return error_response(
            "InternalError", f"Failed to get KRA statistics: {str(e)}", 500
        )


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
