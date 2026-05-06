# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import base64
import json
import logging
import secrets

from flask import Blueprint, Response, request, jsonify

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import init_kra
from ipacta.rest_api._utils import (
    _account_login,
    _account_logout,
    _account_logout_v2,
)
from ipacta.rest_api._helpers import (
    require_agent_auth,
    error_response,
    success_response,
)

logger = logging.getLogger(__name__)

bp = Blueprint("kra", __name__)


# ----------------------------------------------------------------------------
# KRA (Key Recovery Authority) - Info and Status
# ----------------------------------------------------------------------------


@bp.route("/kra/rest/info", methods=["GET"])
@bp.route("/kra/v2/info", methods=["GET"])
def kra_info():
    """Get KRA information - compatible with Dogtag /kra/rest/info"""
    try:
        # Initialize KRA if needed
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        return success_response(
            {
                "Version": "1.0",
                "backend": "ipacta-kra",
                "Attributes": {"subsystem": "kra", "status": "running"},
            }
        )

    except Exception as e:
        logger.error("Error in kra_info: %s", e, exc_info=True)
        return error_response("ServerError", str(e), 500)


@bp.route("/kra/admin/kra/getStatus", methods=["GET"])
def kra_status():
    """Get KRA status - compatible with Dogtag getStatus endpoint"""
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return Response(
                "status=unavailable", mimetype="text/plain", status=503
            )

        return Response("status=running", mimetype="text/plain")

    except Exception as e:
        logger.error("Error in kra_status: %s", e)
        return Response(
            f"status=ERROR: {e}", mimetype="text/plain", status=500
        )


# KRA Account Management
# ----------------------------------------------------------------------------


@bp.route("/kra/rest/account/login", methods=["GET", "POST"])
@require_agent_auth
def kra_account_login():
    """KRA account login endpoint for REST API session management."""
    return _account_login()


@bp.route("/kra/v2/account/login", methods=["GET", "POST"])
@require_agent_auth
def kra_account_login_v2():
    """KRA account login endpoint for REST API v2 session management."""
    return _account_login()


@bp.route("/kra/rest/account/logout", methods=["GET", "POST"])
def kra_account_logout():
    """KRA account logout (compatibility endpoint - clears session cookie)"""
    return _account_logout()


@bp.route("/kra/v2/account/logout", methods=["GET", "POST"])
def kra_account_logout_v2():
    """KRA account logout endpoint for REST API v2 (returns 204)"""
    return _account_logout_v2()


# Key Management Endpoints
# ----------------------------------------------------------------------------


@bp.route("/kra/rest/agent/keyrequests", methods=["POST"])
@bp.route("/kra/v2/agent/keyrequests", methods=["POST"])
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
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        data = request.get_json() or {}

        # Log the request for debugging
        logger.debug(
            "KRA key request received: %s", json.dumps(data, indent=2)
        )

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
                        _g.kra_backend.transport_key_manager.unwrap_secret(
                            trans_wrapped_key
                        )
                    )

                    # Decrypt wrapped data with session key
                    # The algorithm OID tells us what cipher to use
                    # {2 16 840 1 101 3 4 1 2} = AES-128-CBC
                    if sym_alg_params_b64:
                        iv = base64.b64decode(sym_alg_params_b64)
                    else:
                        return error_response(
                            "BadRequest",
                            "Missing algorithmOID parameters (IV) for "
                            "symmetric decryption",
                            400,
                        )

                    # Decrypt using AES-CBC
                    cipher = Cipher(
                        algorithms.AES(session_key),
                        modes.CBC(iv),
                    )
                    decryptor = cipher.decryptor()
                    plaintext_padded = (
                        decryptor.update(wrapped_data)
                        + decryptor.finalize()
                    )

                    # Remove and validate PKCS7 padding
                    if not plaintext_padded:
                        raise ValueError("Decrypted data is empty")
                    padding_length = plaintext_padded[-1]
                    if padding_length < 1 or padding_length > 16:
                        raise ValueError(
                            f"Invalid PKCS7 padding length: {padding_length}"
                        )
                    if len(plaintext_padded) < padding_length:
                        raise ValueError(
                            "Padding length exceeds data length"
                        )
                    if not all(
                        b == padding_length
                        for b in plaintext_padded[-padding_length:]
                    ):
                        raise ValueError("Invalid PKCS7 padding bytes")
                    plaintext = plaintext_padded[:-padding_length]

                    # Now plaintext is the actual secret - store it directly
                    # by encrypting with storage key (not transport key)
                    encrypted_for_storage = (
                        _g.kra_backend.storage_key_manager
                        .encrypt_for_storage(plaintext)
                    )

                    # Store in LDAP directly (bypass archive_secret to avoid
                    # double transport encryption)
                    key_id = _g.kra_backend.storage_backend.store_key(
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
                    key_id = _g.kra_backend.archive_secret(
                        encrypted_secret=encrypted_secret,
                        owner=client_key_id or "unknown",
                        algorithm="AES",
                        key_size=256,
                    )

            except Exception as e:
                logger.error(
                    "Error processing archival request: %s", e, exc_info=True
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
                        "requestURL": (
                            f"/kra/rest/agent/keyrequests/{key_id}"
                        ),
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

            # Get requester from authenticated client certificate
            requester = getattr(request, "auth_principal", "unknown")

            # Retrieve the secret (wrapped for transmission)
            wrapped_secret = _g.kra_backend.retrieve_secret(
                retrieval_id, requester
            )

            # Encode to base64 for JSON
            wrapped_secret_b64 = base64.b64encode(wrapped_secret).decode(
                "utf-8"
            )

            # Get key metadata
            key_record = _g.kra_backend.storage_backend.get_key(retrieval_id)
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
                        "keyURL": (
                            f"/kra/rest/agent/keys/{retrieval_id}"
                        ),
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
                "BadRequest",
                f"Unsupported request type: {request_type}",
                400,
            )

    except ValueError as e:
        return error_response("KeyNotFound", str(e), 404)
    except Exception as e:
        logger.error("Error processing key request: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to process key request: {str(e)}",
            500,
        )


@bp.route("/kra/rest/agent/keyrequests", methods=["GET"])
@bp.route("/kra/v2/agent/keyrequests", methods=["GET"])
@require_agent_auth
def list_key_requests():
    """
    List key requests with optional filtering

    Query parameters:
    - requestState: Filter by request state
    - requestType: Filter by request type
    - clientKeyID: Filter by client key ID
    - start: Start index for pagination (default: 0)
    - size: Maximum number of results (default: 20)

    Returns list of key request info
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
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
            "List key requests: state=%s, type=%s, client=%s",
            request_state,
            request_type,
            client_key_id,
        )

        return jsonify({"entries": [], "total": 0}), 200

    except Exception as e:
        logger.error("Error listing key requests: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to list key requests: {str(e)}",
            500,
        )


@bp.route("/kra/rest/agent/keyrequests/<request_id>", methods=["GET"])
@bp.route("/kra/v2/agent/keyrequests/<request_id>", methods=["GET"])
@require_agent_auth
def get_key_request_info(request_id):
    """
    Get key request info by request ID

    Returns request status, type, and associated key ID if available
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Get request from storage
        if hasattr(_g.kra_backend.storage_backend, "get_key_request"):
            request_info = _g.kra_backend.storage_backend.get_key_request(
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
                    "requestURL": (
                        f"/kra/rest/agent/keyrequests/{request_id}"
                    ),
                    "keyURL": f"/kra/rest/agent/keys/{request_id}",
                }
            )
        else:
            # For ipacta, requests are auto-completed
            # Try to get the key directly (request_id == key_id)
            key_record = _g.kra_backend.storage_backend.get_key(request_id)

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
                    "requestURL": (
                        f"/kra/rest/agent/keyrequests/{request_id}"
                    ),
                    "keyURL": f"/kra/rest/agent/keys/{request_id}",
                }
            )

    except Exception as e:
        logger.error("Error getting key request info: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get key request info: {str(e)}",
            500,
        )


@bp.route(
    "/kra/rest/agent/keyrequests/<request_id>/approve", methods=["POST"]
)
@bp.route(
    "/kra/v2/agent/keyrequests/<request_id>/approve", methods=["POST"]
)
@require_agent_auth
def approve_key_request(request_id):
    """
    Approve a pending key request

    In ipacta, all requests are auto-approved during submission,
    so this endpoint is a no-op for compatibility.
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Check if request/key exists
        key_record = _g.kra_backend.storage_backend.get_key(request_id)

        if not key_record:
            return error_response(
                "RequestNotFound",
                f"Key request {request_id} not found",
                404,
            )

        # Request is already complete (auto-approved)
        return success_response(
            {
                "requestType": "keyArchivalRequest",
                "requestStatus": "complete",
                "requestURL": (
                    f"/kra/rest/agent/keyrequests/{request_id}"
                ),
                "keyURL": f"/kra/rest/agent/keys/{request_id}",
            }
        )

    except Exception as e:
        logger.error("Error approving key request: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to approve key request: {str(e)}",
            500,
        )


@bp.route(
    "/kra/rest/agent/keyrequests/<request_id>/reject", methods=["POST"]
)
@bp.route(
    "/kra/v2/agent/keyrequests/<request_id>/reject", methods=["POST"]
)
@require_agent_auth
def reject_key_request(request_id):
    """
    Reject a key request

    This marks the key as inactive in ipacta.
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Mark key as inactive
        success = _g.kra_backend.modify_key_status(request_id, "inactive")

        if not success:
            return error_response(
                "RequestNotFound",
                f"Key request {request_id} not found",
                404,
            )

        return success_response(
            {
                "requestType": "keyArchivalRequest",
                "requestStatus": "rejected",
                "requestURL": (
                    f"/kra/rest/agent/keyrequests/{request_id}"
                ),
            }
        )

    except Exception as e:
        logger.error("Error rejecting key request: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to reject key request: {str(e)}",
            500,
        )


@bp.route(
    "/kra/rest/agent/keyrequests/<request_id>/cancel", methods=["POST"]
)
@bp.route(
    "/kra/v2/agent/keyrequests/<request_id>/cancel", methods=["POST"]
)
@require_agent_auth
def cancel_key_request(request_id):
    """
    Cancel a key request

    This deletes the key in ipacta.
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Delete the key
        if hasattr(_g.kra_backend.storage_backend, "delete_key"):
            success = _g.kra_backend.storage_backend.delete_key(request_id)

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
                    "requestURL": (
                        f"/kra/rest/agent/keyrequests/{request_id}"
                    ),
                }
            )
        else:
            return error_response(
                "NotImplemented", "Key deletion not available", 501
            )

    except Exception as e:
        logger.error("Error cancelling key request: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to cancel key request: {str(e)}",
            500,
        )


@bp.route("/kra/rest/agent/keys/archive", methods=["POST"])
@bp.route("/kra/v2/agent/keys/archive", methods=["POST"])
@bp.route("/kra/agent/keys/archive", methods=["POST"])
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
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
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
        try:
            key_size = int(data.get("keySize", 256))
        except (ValueError, TypeError):
            return error_response(
                "BadRequest", "Invalid keySize parameter", 400
            )

        # Archive the secret
        key_id = _g.kra_backend.archive_secret(
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
        logger.error("Error archiving key: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to archive key: {str(e)}", 500
        )


@bp.route("/kra/rest/agent/keys/retrieve", methods=["POST"])
@bp.route("/kra/v2/agent/keys/retrieve", methods=["POST"])
@bp.route("/kra/agent/keys/retrieve", methods=["POST"])
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
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        data = request.get_json() or {}

        # Debug logging to see actual request structure
        logger.debug(
            "KRA retrieve_key request: %s", json.dumps(data, indent=2)
        )

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
            logger.error("Missing keyId in request. Request data: %s", data)
            return error_response("BadRequest", "Missing keyId", 400)

        # Get key metadata
        key_record = _g.kra_backend.storage_backend.get_key(key_id)
        if not key_record:
            return error_response(
                "KeyNotFound", f"Key {key_id} not found", 404
            )

        # Decrypt the secret from storage
        secret = _g.kra_backend.storage_key_manager.decrypt_from_storage(
            key_record["encrypted_data"]
        )

        # Check if client provided a session key for wrapping
        if trans_wrapped_key_b64:
            # Client wants response wrapped with their session key
            # 1. Unwrap the session key using transport private key
            trans_wrapped_key = base64.b64decode(trans_wrapped_key_b64)
            session_key = _g.kra_backend.transport_key_manager.unwrap_secret(
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
            wrapped_secret = _g.kra_backend.transport_key_manager.wrap_secret(
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
        logger.error("Error retrieving key: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to retrieve key: {str(e)}", 500
        )


@bp.route("/kra/rest/agent/keys", methods=["GET"])
@bp.route("/kra/v2/agent/keys", methods=["GET"])
@bp.route("/kra/agent/keys", methods=["GET"])
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
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Parse query parameters
        owner = request.args.get("owner")
        status = request.args.get("status")
        try:
            size = int(request.args.get("size", 100))
        except (ValueError, TypeError):
            return error_response("BadRequest", "Invalid size parameter", 400)

        # List keys
        keys = _g.kra_backend.list_keys(owner=owner, status=status)

        # Limit results
        keys = keys[:size]

        # Format for Dogtag compatibility
        # Note: python-pki expects specific field names (case-sensitive)
        entries = []
        for key_info in keys:
            entries.append(
                {
                    "keyURL": (
                        f"/kra/rest/agent/keys/{key_info['key_id']}"
                    ),
                    "clientKeyID": key_info.get("owner"),
                    "status": key_info.get("status", "active"),
                    "algorithm": key_info.get("algorithm", "AES"),
                    "size": key_info.get("key_size", 256),
                }
            )

        return jsonify({"entries": entries, "total": len(entries)}), 200

    except Exception as e:
        logger.error("Error listing keys: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to list keys: {str(e)}", 500
        )


@bp.route("/kra/rest/agent/keys/<key_id>", methods=["GET"])
@bp.route("/kra/v2/agent/keys/<key_id>", methods=["GET"])
@bp.route("/kra/agent/keys/<key_id>", methods=["GET"])
@require_agent_auth
def get_key_info(key_id):
    """
    Get key metadata (without retrieving the actual secret)

    Returns key information including owner, algorithm, status
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Get key metadata from storage
        key_record = _g.kra_backend.storage_backend.get_key(key_id)

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
        logger.error("Error getting key info: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to get key info: {str(e)}", 500
        )


@bp.route("/kra/rest/agent/keys/<key_id>", methods=["POST"])
@bp.route("/kra/v2/agent/keys/<key_id>", methods=["POST"])
@bp.route("/kra/agent/keys/<key_id>", methods=["POST"])
@require_agent_auth
def modify_key_status(key_id):
    """
    Modify key status (active, inactive, archived)

    python-pki sends status as URL parameter, not in body:
    POST /kra/rest/agent/keys/{key_id}?status=inactive
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
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
                "Invalid status. Must be one of: "
                f"{', '.join(valid_statuses)}",
                400,
            )

        # Update status
        success = _g.kra_backend.modify_key_status(
            key_id, new_status.lower()
        )

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
        logger.error("Error modifying key status: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to modify key status: {str(e)}",
            500,
        )


@bp.route(
    "/kra/rest/agent/keys/active/<client_key_id>", methods=["GET"]
)
@bp.route("/kra/v2/agent/keys/active/<client_key_id>", methods=["GET"])
@bp.route("/kra/agent/keys/active/<client_key_id>", methods=["GET"])
@require_agent_auth
def get_active_key_info(client_key_id):
    """
    Get active key info for a specific client

    Returns the most recent active key for the specified client ID.
    This is used when a client has multiple keys and you want the current one.
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # List keys for this client, filtered by active status
        keys = _g.kra_backend.list_keys(
            owner=client_key_id, status="active"
        )

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
                "keyURL": (
                    f"/kra/rest/agent/keys/{active_key['key_id']}"
                ),
                "clientKeyID": active_key.get("owner"),
                "status": active_key.get("status", "active"),
                "algorithm": active_key.get("algorithm", "AES"),
                "size": active_key.get("key_size", 256),
            }
        )

    except Exception as e:
        logger.error("Error getting active key info: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get active key info: {str(e)}",
            500,
        )


# KRA Transport Certificate Endpoint
# ----------------------------------------------------------------------------


@bp.route("/kra/rest/agent/keys/transportCert", methods=["GET"])
@bp.route("/kra/v2/agent/keys/transportCert", methods=["GET"])
@bp.route("/kra/agent/keys/transportCert", methods=["GET"])
def get_transport_cert():
    """
    Get KRA transport certificate (public key for wrapping secrets)

    Clients use this certificate to encrypt secrets before sending to KRA.

    Returns PEM-encoded transport certificate
    """
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Get transport certificate
        transport_cert_pem = _g.kra_backend.get_transport_cert()

        # Return as PEM (Dogtag compatibility)
        return Response(transport_cert_pem, mimetype="application/x-pem-file")

    except Exception as e:
        logger.error("Error getting transport cert: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get transport certificate: {str(e)}",
            500,
        )


@bp.route("/kra/rest/config/cert/transport", methods=["GET"])
@bp.route("/kra/v2/config/cert/transport", methods=["GET"])
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
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        # Get transport certificate PEM
        transport_cert_pem = _g.kra_backend.get_transport_cert()

        # Return as JSON in CertData format (python-pki compatibility)
        # The Encoded field should contain the PEM certificate
        cert_data = {"Encoded": transport_cert_pem}

        return success_response(cert_data)

    except Exception as e:
        logger.error("Error getting transport cert: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get transport certificate: {str(e)}",
            500,
        )


# KRA Statistics Endpoint
# ----------------------------------------------------------------------------


@bp.route("/kra/rest/stats", methods=["GET"])
@bp.route("/kra/v2/stats", methods=["GET"])
def kra_stats():
    """Get KRA statistics (key counts, etc.)"""
    try:
        if _g.kra_backend is None:
            init_kra()

        if _g.kra_backend is None:
            return error_response(
                "KRANotAvailable", "KRA subsystem not initialized", 503
            )

        stats = _g.kra_backend.storage_backend.get_statistics()

        return success_response(stats)

    except Exception as e:
        logger.error("Error getting KRA stats: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to get KRA statistics: {str(e)}",
            500,
        )
