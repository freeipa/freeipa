# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import logging
import re

from flask import Blueprint, Response

import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import require_ca_backend, init_ca, init_kra
from ipacta.rest_api._utils import (
    _account_login,
    _account_logout,
    _account_logout_v2,
)
from ipacta.rest_api._helpers import (
    handle_ca_errors,
    require_agent_auth,
    error_response,
    success_response,
)

logger = logging.getLogger(__name__)

bp = Blueprint("ca_core", __name__)


# ============================================================================
# Health and Status Endpoints
# ============================================================================


@bp.route("/pki/rest/info", methods=["GET"])
@bp.route("/pki/v2/info", methods=["GET"])
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


@bp.route("/ca/rest/info", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def ca_info():
    """Get CA information - compatible with PKI /ca/rest/info"""
    info = _g.ca_backend.get_ca_info()
    return success_response(
        {
            "Version": "1.0",
            # Identify this as ipacta for hybrid_ra detection
            "backend": "ipacta",
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


@bp.route("/ca/admin/ca/getStatus", methods=["GET"])
@require_ca_backend
def ca_status():
    """Get CA status - compatible with Dogtag getStatus endpoint"""
    try:
        info = _g.ca_backend.get_ca_info()
        return Response(f"status={info['status']}", mimetype="text/plain")
    except Exception as e:
        logger.error("Error in ca_status: %s", e)
        return Response(
            f"status=ERROR: {e}", mimetype="text/plain", status=500
        )


@bp.route("/ca/ee/ca/getStatus", methods=["GET"])
def ca_ee_status():
    """Get CA status (end-entity interface)"""
    return ca_status()


# ============================================================================
# Admin/Agent Endpoints
# ============================================================================


# CA Account Management Endpoints
@bp.route("/ca/rest/account/login", methods=["GET", "POST"])
@require_agent_auth
def account_login():
    """CA account login endpoint for REST API session management."""
    return _account_login()


@bp.route("/ca/v2/account/login", methods=["GET", "POST"])
@require_agent_auth
def account_login_v2():
    """CA account login endpoint for REST API v2 session management."""
    return _account_login()


@bp.route("/ca/rest/account/logout", methods=["GET", "POST"])
def account_logout():
    """CA account logout (compatibility endpoint - clears session cookie)"""
    return _account_logout()


@bp.route("/ca/v2/account/logout", methods=["GET", "POST"])
def account_logout_v2():
    """CA account logout endpoint for REST API v2 (returns 204)"""
    return _account_logout_v2()


# ============================================================================
# Security Domain Endpoints
# ============================================================================


@bp.route("/ca/rest/securityDomain/domainInfo", methods=["GET"])
@bp.route("/ca/v2/securityDomain/domainInfo", methods=["GET"])
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

        if _g.ca_backend.config:
            if _g.ca_backend.config.has_option("global", "realm"):
                realm = _g.ca_backend.config.get("global", "realm")
            if _g.ca_backend.config.has_option("global", "host"):
                hostname = _g.ca_backend.config.get("global", "host")

        if not hostname:
            logger.error("Hostname not configured in ipacta.conf")
            return error_response(
                "ConfigurationError",
                "Hostname not configured in ipacta.conf [global] section",
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
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is not None:
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
        logger.error("Error getting security domain info: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route(
    "/ca/rest/securityDomain/hosts/<path:host_id>", methods=["DELETE"]
)
@bp.route(
    "/ca/v2/securityDomain/hosts/<path:host_id>", methods=["DELETE"]
)
@require_agent_auth
def remove_security_domain_host(host_id):
    """
    Remove a host from the security domain

    This is called during server uninstallation to clean up replica
    information.
    The host_id is in format: "{subsystem} {hostname} {port}" (space-separated,
    URL-encoded)

    For ipacta, we accept the deletion but don't need to track security
    domain hosts since we don't have multiple PKI instances. The security
    domain concept is mainly for tracking Dogtag replicas, which doesn't apply
    to our pure Python CA.
    """
    try:
        logger.info("Security domain host removal requested")

        # Validate host_id contains only safe characters
        if not re.match(r"^[a-zA-Z0-9.\-\s]+$", host_id):
            return error_response(
                "BadRequest",
                "Invalid host ID format (invalid characters)",
                400,
            )

        # Parse host_id: "{subsystem} {hostname} {port}"
        parts = host_id.split(" ")
        if len(parts) != 3:
            return error_response(
                "BadRequest",
                "Invalid host ID format. Expected 'subsystem"
                " hostname port'",
                400,
            )

        subsystem, hostname, port = parts
        subsystem = subsystem.upper()

        if subsystem not in ("CA", "KRA", "OCSP", "TKS", "TPS"):
            return error_response("BadRequest", "Invalid subsystem type", 400)
        if not port.isdigit() or not (0 < int(port) < 65536):
            return error_response("BadRequest", "Invalid port number", 400)
        logger.info(
            "Removing %s host %s:%s from security domain",
            subsystem,
            hostname,
            port,
        )

        # In ipacta, we don't need to track security domain hosts
        # Just return success to allow the uninstallation to proceed
        return success_response(
            {
                "Status": "SUCCESS",
                "Message": (
                    f"Host {hostname} removed from security domain (no-op for"
                    " ipacta)"
                ),
            }
        )

    except Exception as e:
        logger.error("Error removing security domain host: %s", e)
        return error_response("ServerError", str(e), 500)
