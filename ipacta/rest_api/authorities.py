# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import logging
import traceback

from flask import Blueprint, Response, request, jsonify

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import init_ca
from ipacta.backend import get_python_ca_backend
from ipacta import x509_utils
from ipacta.x509_utils import get_subject_dn, get_issuer_dn
from ipacta.ldap_utils import is_main_ca_id
from ipacta.rest_api._helpers import (
    require_agent_auth,
    validate_dn,
    error_response,
    success_response,
)
from ipalib import errors
from ipapython.dn import DN

logger = logging.getLogger(__name__)

bp = Blueprint("authorities", __name__)


# ============================================================================
# Lightweight CA (Authorities) Endpoints
# ============================================================================


@bp.route("/ca/rest/authorities", methods=["GET"])
@bp.route("/ca/rest/ca/authorities", methods=["GET"])
@bp.route("/ca/v2/authorities", methods=["GET"])
@bp.route("/ca/v2/ca/authorities", methods=["GET"])
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
        logger.error("Error listing authorities: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to list authorities: {str(e)}", 500
        )


@bp.route("/ca/rest/authorities/<authority_id>", methods=["GET"])
@bp.route("/ca/rest/ca/authorities/<authority_id>", methods=["GET"])
@bp.route("/ca/v2/authorities/<authority_id>", methods=["GET"])
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
            "Error getting authority %s: %s", authority_id, e, exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to get authority: {str(e)}", 500
        )


@bp.route("/ca/rest/authorities", methods=["POST"])
@bp.route("/ca/rest/ca/authorities", methods=["POST"])
@bp.route("/ca/v2/authorities", methods=["POST"])
@bp.route("/ca/v2/ca/authorities", methods=["POST"])
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
        logger.error("Error creating authority: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to create authority: {str(e)}", 500
        )


@bp.route("/ca/rest/authorities/<authority_id>/cert", methods=["GET"])
@bp.route("/ca/rest/ca/authorities/<authority_id>/cert", methods=["GET"])
@bp.route("/ca/v2/authorities/<authority_id>/cert", methods=["GET"])
def get_authority_cert(authority_id):
    """
    Get the certificate of a specific authority

    Args:
        authority_id: Authority identifier
    """
    logger.debug("get_authority_cert called for authority_id=%s", authority_id)

    try:
        # Initialize backend
        try:
            init_ca()
        except Exception as e:
            logger.error("Failed to initialize backend: %s", e, exc_info=True)
            return error_response(
                "BackendError", f"CA backend not initialized: {str(e)}", 503
            )

        # Handle main IPA CA - special identifiers
        if authority_id in ("host-authority", "ipa"):
            try:
                logger.debug(
                    "Returning main IPA CA certificate (special ID: %s)",
                    authority_id,
                )
                # CRITICAL FIX: Ensure CA cert is loaded before accessing it
                _g.ca_backend.ca._ensure_ca_loaded()

                ca_cert = _g.ca_backend.ca.ca_cert
                cert_pem = ca_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode("utf-8")
                return Response(cert_pem, mimetype="application/pkix-cert")
            except Exception as e:
                logger.error(
                    "Failed to get main CA cert: %s", e, exc_info=True
                )
                return error_response(
                    "InternalError",
                    f"Failed to get main CA certificate: {str(e)}",
                    500,
                )

        # Try to look up as a sub-CA first
        # If lookup fails or returns None, fall back to main CA (Dogtag
        # compatibility)
        try:
            logger.debug("Looking up sub-CA with ID: %s", authority_id)
            subca = _g.ca_backend.ca.subca_manager.get_subca(authority_id)
            logger.debug("Sub-CA lookup result: %s", subca)
        except errors.NotFound:
            # Sub-CA not found by ID — fall through to try main CA
            logger.debug("Sub-CA %s not found, trying main CA", authority_id)
            subca = None
        except Exception as lookup_error:
            # LDAP or other infrastructure error — don't silently fall back
            logger.error(
                "Sub-CA lookup failed for %s: %s",
                authority_id,
                lookup_error,
                exc_info=True,
            )
            return error_response(
                "ServiceUnavailable",
                "Unable to verify CA identity at this time",
                503,
            )

        # If sub-CA found, return it
        if subca:
            if not subca.ca_cert:
                logger.warning(
                    "Sub-CA %s exists but has no certificate", authority_id
                )
                return error_response(
                    "CANotFound",
                    f"Authority {authority_id} has no certificate",
                    404,
                )

            try:
                logger.debug(
                    "Returning sub-CA certificate for %s", authority_id
                )
                cert_pem = subca.ca_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode("utf-8")
                return Response(cert_pem, mimetype="application/pkix-cert")
            except Exception as e:
                logger.error(
                    "Failed to serialize sub-CA cert: %s", e, exc_info=True
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
            "No sub-CA found for %s, returning main CA certificate",
            authority_id,
        )
        try:
            # CRITICAL FIX: Ensure CA cert is loaded before accessing it
            _g.ca_backend.ca._ensure_ca_loaded()

            ca_cert = _g.ca_backend.ca.ca_cert
            cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            )
            return Response(cert_pem, mimetype="application/pkix-cert")
        except Exception as e:
            logger.error("Failed to get main CA cert: %s", e, exc_info=True)
            return error_response(
                "InternalError",
                f"Failed to get main CA certificate: {str(e)}",
                500,
            )

    except Exception as e:
        # Catch-all for any unexpected errors
        logger.error(
            "Unexpected error getting authority cert %s: %s",
            authority_id,
            e,
            exc_info=True,
        )
        logger.error("Traceback: %s", traceback.format_exc())
        return error_response(
            "InternalError", f"Unexpected error: {str(e)}", 500
        )


@bp.route("/ca/rest/authorities/<authority_id>/chain", methods=["GET"])
@bp.route(
    "/ca/rest/ca/authorities/<authority_id>/chain", methods=["GET"]
)
@bp.route("/ca/v2/authorities/<authority_id>/chain", methods=["GET"])
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
                    "No sub-CA found for %s, returning main CA certificate",
                    authority_id,
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
            "Error getting authority chain %s: %s",
            authority_id,
            e,
            exc_info=True,
        )
        return error_response(
            "InternalError",
            f"Failed to get authority chain: {str(e)}",
            500,
        )


@bp.route(
    "/ca/rest/authorities/<authority_id>/disable", methods=["POST"]
)
@bp.route(
    "/ca/rest/ca/authorities/<authority_id>/disable", methods=["POST"]
)
@bp.route(
    "/ca/v2/authorities/<authority_id>/disable", methods=["POST"]
)
@bp.route(
    "/ca/v2/ca/authorities/<authority_id>/disable", methods=["POST"]
)
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
                "Message": (
                    f"Authority {authority_id} disabled successfully"
                ),
            }
        )

    except Exception as e:
        logger.error(
            "Error disabling authority %s: %s",
            authority_id,
            e,
            exc_info=True,
        )
        return error_response(
            "InternalError", f"Failed to disable authority: {str(e)}", 500
        )


@bp.route(
    "/ca/rest/authorities/<authority_id>/enable", methods=["POST"]
)
@bp.route(
    "/ca/rest/ca/authorities/<authority_id>/enable", methods=["POST"]
)
@bp.route(
    "/ca/v2/authorities/<authority_id>/enable", methods=["POST"]
)
@bp.route(
    "/ca/v2/ca/authorities/<authority_id>/enable", methods=["POST"]
)
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
                "Message": (
                    f"Authority {authority_id} enabled successfully"
                ),
            }
        )

    except Exception as e:
        logger.error(
            "Error enabling authority %s: %s",
            authority_id,
            e,
            exc_info=True,
        )
        return error_response(
            "InternalError", f"Failed to enable authority: {str(e)}", 500
        )


@bp.route("/ca/rest/authorities/<authority_id>", methods=["DELETE"])
@bp.route("/ca/rest/ca/authorities/<authority_id>", methods=["DELETE"])
@bp.route("/ca/v2/authorities/<authority_id>", methods=["DELETE"])
@bp.route("/ca/v2/ca/authorities/<authority_id>", methods=["DELETE"])
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
                "Message": (
                    f"Authority {authority_id} deleted successfully"
                ),
            }
        )

    except Exception as e:
        logger.error(
            "Error deleting authority %s: %s",
            authority_id,
            e,
            exc_info=True,
        )
        return error_response(
            "InternalError", f"Failed to delete authority: {str(e)}", 500
        )
