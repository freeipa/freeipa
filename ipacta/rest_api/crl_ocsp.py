# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import base64
import logging
import os
from xml.sax.saxutils import escape as xml_escape

from flask import Blueprint, Response, request, jsonify

from cryptography.hazmat.primitives import serialization

import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import require_ca_backend, init_ca
from ipacta.ocsp import get_ocsp_manager
from ipacta.rest_api._helpers import (
    handle_ca_errors,
    require_agent_auth,
    error_response,
    success_response,
)
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

bp = Blueprint("crl_ocsp", __name__)


# ============================================================================
# CRL Endpoints
# ============================================================================


@bp.route("/ca/ee/ca/getCRL", methods=["GET"])
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
    _g.ca_backend.update_crl()

    # Read CRL from file (avoid TOCTOU race with direct open)
    crl_path = os.path.join(paths.IPACTA_CERTS_DIR, "ca_crl.der")
    try:
        with open(crl_path, "rb") as f:
            crl_data = f.read()
        return Response(crl_data, mimetype="application/pkix-crl")
    except FileNotFoundError:
        return error_response("CRLNotFound", "CRL file not found", 404)


@bp.route("/ca/rest/agent/crl", methods=["POST"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def update_crl():
    """Update CRL (force regeneration)"""
    result = _g.ca_backend.update_crl()
    return success_response({"Status": result["status"]})


@bp.route("/ca/agent/ca/updateCRL", methods=["GET"])
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
        result = _g.ca_backend.update_crl()

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
    <crlIssuingPoint>{xml_escape(crl_issuing_point)}</crlIssuingPoint>
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
        logger.error("Error in updateCRL (legacy): %s", e, exc_info=True)

        # Return XML error response
        error_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xml>
  <fixed>
    <requestStatus>6</requestStatus>
    <errorDetails>{xml_escape(str(e))}</errorDetails>
  </fixed>
</xml>"""
        return Response(error_xml, mimetype="application/xml", status=500)


# CRL Issuing Points Management
# ----------------------------------------------------------------------------


@bp.route("/ca/rest/crl/issuingpoints", methods=["GET"])
@bp.route("/ca/v2/crl/issuingpoints", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def list_crl_issuing_points():
    """
    List all CRL issuing points

    Returns list of CRL issuing point names
    """
    try:
        storage = _g.ca_backend.ca.storage

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
        logger.error("Error listing CRL issuing points: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to list CRL issuing points: {str(e)}",
            500,
        )


@bp.route("/ca/rest/crl/issuingpoints/<crl_name>", methods=["GET"])
@bp.route("/ca/v2/crl/issuingpoints/<crl_name>", methods=["GET"])
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
        storage = _g.ca_backend.ca.storage

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
                "NotImplemented",
                "CRL issuing point info not available",
                501,
            )

    except Exception as e:
        logger.error(
            "Error getting CRL issuing point info: %s", e, exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to get CRL info: {str(e)}", 500
        )


@bp.route("/ca/rest/crl/issuingpoints/<crl_name>", methods=["DELETE"])
@bp.route("/ca/v2/crl/issuingpoints/<crl_name>", methods=["DELETE"])
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
        storage = _g.ca_backend.ca.storage

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
        logger.error("Error deleting CRL issuing point: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to delete CRL issuing point: {str(e)}",
            500,
        )


# ============================================================================
# Certificate and Request Pruning Endpoints
# ============================================================================


@bp.route("/ca/rest/pruning/config", methods=["GET"])
@bp.route("/ca/v2/pruning/config", methods=["GET"])
@require_ca_backend
def get_pruning_config():
    """
    Get pruning configuration

    Returns configuration for certificate and request pruning including
    retention times, search limits, and enabled status.
    """
    try:
        config = _g.ca_backend.pruning_manager.get_config()
        return success_response(config)

    except Exception as e:
        logger.error("Error getting pruning config: %s", e, exc_info=True)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/pruning/config", methods=["POST", "PUT"])
@bp.route("/ca/v2/pruning/config", methods=["POST", "PUT"])
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
        _g.ca_backend.pruning_manager.update_config(data)

        # Get updated config to return
        config = _g.ca_backend.pruning_manager.get_config()
        return success_response(config)

    except Exception as e:
        logger.error("Error updating pruning config: %s", e, exc_info=True)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/pruning/enable", methods=["POST"])
@bp.route("/ca/v2/pruning/enable", methods=["POST"])
@require_agent_auth
@require_ca_backend
def enable_pruning():
    """
    Enable certificate pruning

    Sets pruningEnabled=TRUE in LDAP configuration.
    Requires agent authentication.
    """
    try:
        _g.ca_backend.pruning_manager.set_enabled(True)
        logger.info("Certificate pruning enabled")
        return success_response(
            {"Status": "SUCCESS", "Message": "Pruning enabled"}
        )

    except Exception as e:
        logger.error("Error enabling pruning: %s", e, exc_info=True)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/pruning/disable", methods=["POST"])
@bp.route("/ca/v2/pruning/disable", methods=["POST"])
@require_agent_auth
@require_ca_backend
def disable_pruning():
    """
    Disable certificate pruning

    Sets pruningEnabled=FALSE in LDAP configuration.
    Requires agent authentication.
    """
    try:
        _g.ca_backend.pruning_manager.set_enabled(False)
        logger.info("Certificate pruning disabled")
        return success_response(
            {"Status": "SUCCESS", "Message": "Pruning disabled"}
        )

    except Exception as e:
        logger.error("Error disabling pruning: %s", e, exc_info=True)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/pruning/run", methods=["POST"])
@bp.route("/ca/v2/pruning/run", methods=["POST"])
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
        results = _g.ca_backend.pruning_manager.run_pruning()
        return success_response(results)

    except ValueError as e:
        # Pruning not enabled
        return error_response("PruningNotEnabled", str(e), 400)
    except Exception as e:
        logger.error("Error running pruning job: %s", e, exc_info=True)
        return error_response("ServerError", str(e), 500)


# ============================================================================
# OCSP Endpoints
# ============================================================================


@bp.route("/ca/ocsp", methods=["POST", "GET"])
@bp.route("/ca/ocsp/<path:ocsp_data>", methods=["GET"])
@bp.route("/ca/ee/ca/ocsp", methods=["POST", "GET"])
@bp.route("/ca/ee/ca/ocsp/<path:ocsp_data>", methods=["GET"])
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
        ocsp_responder = ocsp_manager.get_responder(
            _g.ca_backend.ca, ca_id="ipa"
        )

        # Parse OCSP request
        if request.method == "POST":
            # POST request - DER-encoded in body
            ocsp_request_der = request.get_data()

        else:  # GET
            # GET request - base64-encoded in URL path
            # Extract base64-encoded request from URL (RFC 6960 section 2.1)
            request_b64 = (
                ocsp_data if ocsp_data else request.path.split("/")[-1]
            )
            if len(request_b64) > 8192:
                return Response(
                    ocsp_responder._create_error_response(),
                    mimetype="application/ocsp-response",
                    status=400,
                )
            try:
                ocsp_request_der = base64.b64decode(request_b64)
            except Exception as e:
                logger.error("Failed to decode OCSP request from URL: %s", e)
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
        logger.error("Error in OCSP request handler: %s", e, exc_info=True)
        # Return error response
        try:
            ocsp_manager = get_ocsp_manager()
            ocsp_responder = ocsp_manager.get_responder(
                _g.ca_backend.ca, ca_id="ipa"
            )
            error_response_der = ocsp_responder._create_error_response()
            return Response(
                error_response_der,
                mimetype="application/ocsp-response",
                status=500,
            )
        except Exception as inner_e:
            logger.error(
                "Failed to build OCSP error response: %s",
                inner_e,
                exc_info=True,
            )
            # RFC 6960 OCSPResponse with responseStatus = internalError (2)
            return Response(
                b"\x30\x03\x0a\x01\x02",
                mimetype="application/ocsp-response",
                status=500,
            )


@bp.route("/ca/rest/ocsp/stats", methods=["GET"])
def ocsp_stats():
    """Get OCSP responder statistics"""
    try:
        init_ca()

        ocsp_manager = get_ocsp_manager()

        stats = ocsp_manager.get_all_stats()

        return success_response(stats)

    except Exception as e:
        logger.error("Error getting OCSP stats: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/ocsp/cache/clear", methods=["POST"])
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
        logger.error("Error clearing OCSP cache: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/ocsp/cert", methods=["GET"])
def get_ocsp_cert():
    """Get OCSP signing certificate for main CA"""
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        ocsp_manager = get_ocsp_manager()
        if ca_id not in ocsp_manager.responders:
            return error_response(
                "NotFound",
                f"OCSP signing certificate for CA {ca_id} not found",
                404,
            )

        responder = ocsp_manager.responders[ca_id]
        if responder.ocsp_cert is None:
            return error_response(
                "NotFound",
                f"OCSP signing certificate for CA {ca_id} not found",
                404,
            )

        cert = responder.ocsp_cert
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode(
            "ascii"
        )

        return success_response(
            {
                "ca_id": ca_id,
                "serial_number": cert.serial_number,
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "enabled": True,
                "certificate": cert_pem,
                "cache_timeout": responder.cache_timeout,
            }
        )

    except Exception as e:
        logger.error("Error getting OCSP certificate: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/ocsp/cert/renew", methods=["POST"])
def renew_ocsp_cert():
    """Regenerate OCSP signing certificate"""
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        ocsp_manager = get_ocsp_manager()

        # Force regeneration by deleting cached responder
        # (new responder will be created on next OCSP request)
        if ca_id in ocsp_manager.responders:
            del ocsp_manager.responders[ca_id]
        else:
            logger.debug("No cached OCSP responder for %s to remove", ca_id)

        # Create a fresh responder which generates a new OCSP cert
        responder = ocsp_manager.get_responder(_g.ca_backend.ca, ca_id)
        cert = responder.ocsp_cert

        result = {
            "Status": "SUCCESS",
            "Message": "OCSP signing certificate renewed",
        }
        if cert is not None:
            result["serial_number"] = cert.serial_number
            result["not_before"] = cert.not_valid_before_utc.isoformat()
            result["not_after"] = cert.not_valid_after_utc.isoformat()

        return success_response(result)

    except Exception as e:
        logger.error("Error renewing OCSP certificate: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/ocsp/responders", methods=["GET"])
def list_ocsp_responders():
    """List all OCSP responders (multi-CA support)"""
    try:
        init_ca()

        ocsp_manager = get_ocsp_manager()

        responders = []
        for ca_id, responder in ocsp_manager.responders.items():
            entry = {"ca_id": ca_id, "enabled": True}
            if responder.ocsp_cert is not None:
                cert = responder.ocsp_cert
                entry["serial_number"] = cert.serial_number
                entry["not_after"] = cert.not_valid_after_utc.isoformat()
            responders.append(entry)

        return success_response(
            {"total": len(responders), "entries": responders}
        )

    except Exception as e:
        logger.error("Error listing OCSP responders: %s", e)
        return error_response("ServerError", str(e), 500)


# ============================================================================
# Certificate Chain Endpoints
# ============================================================================


@bp.route("/ca/rest/certs/chain", methods=["GET"])
@bp.route("/ca/ee/ca/getCertChain", methods=["GET"])
def get_cert_chain():
    """Get CA certificate chain"""
    try:
        init_ca()

        result = _g.ca_backend.get_certificate_chain()
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
        logger.error("Error in get_cert_chain: %s", e)
        return error_response("ServerError", str(e), 500)
