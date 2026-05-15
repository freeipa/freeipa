# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import json
import logging

from flask import Blueprint, Response, request, jsonify

import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import init_ca
from ipacta.rest_api._helpers import (
    error_response,
    require_agent_auth,
    success_response,
)
import ipacta.rate_limit as _rl

logger = logging.getLogger(__name__)

bp = Blueprint("acme", __name__)


# ============================================================================
# ACME Endpoints
# ============================================================================


@bp.route("/acme/directory", methods=["GET"])
def acme_directory():
    """ACME directory endpoint"""
    try:
        init_ca()

        # Check if ACME is enabled (return 503 if disabled, like Dogtag)
        if not _g.ca_backend.acme_state.is_enabled():
            return Response(
                "ACME service is disabled", status=503, mimetype="text/plain"
            )

        directory = _g.ca_backend.get_acme_directory()
        return success_response(directory)

    except Exception as e:
        logger.error("Error in acme_directory: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/acme/new-nonce", methods=["HEAD", "GET"])
def acme_new_nonce():
    """ACME new nonce endpoint"""
    try:
        init_ca()

        nonce = _g.ca_backend.acme_server.generate_nonce()

        response = Response("", status=200)
        response.headers["Replay-Nonce"] = nonce
        response.headers["Cache-Control"] = "no-store"
        return response

    except Exception as e:
        logger.error("Error in acme_new_nonce: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/acme/<path:endpoint>", methods=["POST"])
def acme_endpoint(endpoint):
    """Generic ACME endpoint handler with JWS parsing"""
    try:
        init_ca()

        # Per-endpoint rate limiting keyed by client IP
        ip = request.remote_addr or "unknown"
        if endpoint == "new-account":
            limiter = _rl.acme_new_account
        elif endpoint == "new-order":
            limiter = _rl.acme_new_order
        elif endpoint == "revoke-cert":
            limiter = _rl.acme_revoke
        else:
            limiter = _rl.acme_general
        if not limiter.is_allowed(ip):
            return error_response(
                "rateLimited", "Too many requests, please try again later", 429
            )

        # Get raw request body (JWS-signed request)
        jws_data = request.get_json()
        if not jws_data:
            return error_response("malformed", "Missing request body", 400)

        # Reconstruct JWS token from request
        # ACME sends JWS in flattened JSON format: {protected, payload,
        # signature}
        if (
            "protected" in jws_data
            and "payload" in jws_data
            and "signature" in jws_data
        ):
            # Convert flattened JWS to compact format for processing
            jws_token = (
                f"{jws_data['protected']}.{jws_data['payload']}."
                f"{jws_data['signature']}"
            )
        else:
            return error_response("malformed", "Invalid JWS format", 400)

        # Construct expected URL for this endpoint
        # ACME requires URL validation to prevent replay attacks
        # Use the ACME server's configured base URL to handle proxy situations
        # (Apache proxy on :443 forwards to backend on :8443)
        base_url = _g.ca_backend.acme_server.base_url
        expected_url = f"{base_url}/acme/{endpoint}"

        # Process and verify JWS request
        protected_header, payload_bytes, account_id = (
            _g.ca_backend.acme_server.process_jws_request(
                jws_token, expected_url
            )
        )

        # Decode payload (can be empty for some requests like revokeCert)
        if payload_bytes:
            payload = json.loads(payload_bytes.decode("utf-8"))
        else:
            payload = {}

        # Get account key from header (for new-account, it's in jwk; for
        # others, use kid)
        account_key = protected_header.get("jwk")

        # Call backend to process the request.
        # Pass account_id directly (already validated by process_jws_request)
        # so handlers do not need to re-derive it from account_key.
        logger.debug("Processing ACME endpoint: %s", endpoint)
        result = _g.ca_backend.process_acme_request(
            endpoint, payload, account_key, account_id=account_id
        )
        result_value = (
            result
            if not isinstance(result, tuple)
            else f"tuple of {len(result)} elements"
        )
        logger.debug(
            "Result type: %s, value: %s", type(result), result_value
        )

        # Handle special case for new-account (returns tuple)
        # RFC 8555: HTTP 201 for new account, HTTP 200 for existing
        if endpoint == "new-account":
            logger.debug(
                "Handling new-account endpoint, result type=%s",
                type(result),
            )
            account_dict, is_new = result
            status_code = 201 if is_new else 200
            logger.info(
                "ACME new-account: is_new=%s, status_code=%s",
                is_new,
                status_code,
            )
            result = account_dict
        else:
            status_code = 200

        # Add nonce to response headers
        nonce = _g.ca_backend.acme_server.generate_nonce()
        response = jsonify(result)
        response.status_code = status_code
        response.headers["Replay-Nonce"] = nonce

        # Add Location header for new-account and new-order responses
        if endpoint == "new-account" and account_id:
            location = f"{base_url}/acme/acct/{account_id}"
            response.headers["Location"] = location
        elif endpoint == "new-order" and "order_id" in result:
            location = f"{base_url}/acme/order/{result['order_id']}"
            response.headers["Location"] = location

        return response

    except Exception as e:
        logger.error(
            "Error in acme_endpoint (%s): %s", endpoint, e, exc_info=True
        )
        # Return ACME-formatted error
        return error_response("serverInternal", str(e), 500)


# ACME Management Endpoints (Dogtag compatibility)
# ----------------------------------------------------------------------------


@bp.route("/acme/enable", methods=["POST"])
@require_agent_auth
def acme_enable():
    """
    Enable ACME service (Dogtag compatibility endpoint)

    Sets acmeEnabled=TRUE in LDAP (ou=config,ou=acme,o=ipaca)
    """
    try:
        init_ca()
        _g.ca_backend.acme_state.set_enabled(True)
        logger.info("ACME enabled")
        return Response("", status=200)

    except Exception as e:
        logger.error("Error enabling ACME: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/acme/disable", methods=["POST"])
@require_agent_auth
def acme_disable():
    """
    Disable ACME service (Dogtag compatibility endpoint)

    Sets acmeEnabled=FALSE in LDAP (ou=config,ou=acme,o=ipaca)
    """
    try:
        init_ca()
        _g.ca_backend.acme_state.set_enabled(False)
        logger.info("ACME disabled")
        return Response("", status=200)

    except Exception as e:
        logger.error("Error disabling ACME: %s", e)
        return error_response("ServerError", str(e), 500)
