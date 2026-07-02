# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import logging
import os

from flask import Blueprint, request

import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import init_ca
from ipacta.hsm import HSMConfig, HSMKeyBackend, list_pkcs11_slots
from ipacta.hsm import get_hsm_info as get_hsm_device_info
from ipacta.rest_api._helpers import (
    error_response,
    require_agent_auth,
    success_response,
)

logger = logging.getLogger(__name__)

bp = Blueprint("hsm", __name__)


# ============================================================================
# HSM Management Endpoints
# ============================================================================


@bp.route("/ca/rest/hsm/config", methods=["GET"])
@require_agent_auth
def get_hsm_config():
    """Get HSM configuration for a CA"""
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        # Get HSM config from LDAP
        if (
            hasattr(_g.ca_backend.ca, "ldap_storage")
            and _g.ca_backend.ca.ldap_storage
        ):
            hsm_config = _g.ca_backend.ca.ldap_storage.get_hsm_config(ca_id)

            if hsm_config:
                # Don't return token_pin in the response for security
                response_config = {
                    k: v for k, v in hsm_config.items() if k != "token_pin"
                }
                response_config["has_token_pin"] = bool(
                    hsm_config.get("token_pin")
                )

                return success_response(response_config)
            else:
                return error_response(
                    "NotFound",
                    f"HSM configuration for CA {ca_id} not found",
                    404,
                )

        return error_response(
            "NotSupported", "LDAP storage not available", 500
        )

    except Exception as e:
        logger.error("Error getting HSM configuration: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/hsm/config", methods=["PUT", "POST"])
@require_agent_auth
def update_hsm_config():
    """Update HSM configuration"""
    try:
        init_ca()

        data = request.get_json()
        if not data:
            return error_response(
                "BadRequest", "No configuration data provided", 400
            )

        ca_id = data.get("ca_id", "ipa")

        # Validate required fields
        if "enabled" not in data:
            return error_response(
                "BadRequest", "Missing required field: enabled", 400
            )

        # Store HSM config in LDAP
        if (
            hasattr(_g.ca_backend.ca, "ldap_storage")
            and _g.ca_backend.ca.ldap_storage
        ):
            _g.ca_backend.ca.ldap_storage.store_hsm_config(ca_id, data)

            return success_response(
                {
                    "Status": "SUCCESS",
                    "Message": (
                        f"HSM configuration for CA {ca_id} updated "
                        "successfully"
                    ),
                    "ca_id": ca_id,
                    "enabled": data.get("enabled"),
                }
            )

        return error_response(
            "NotSupported", "LDAP storage not available", 500
        )

    except Exception as e:
        logger.error("Error updating HSM configuration: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/hsm/config", methods=["DELETE"])
@require_agent_auth
def delete_hsm_config():
    """Delete/disable HSM configuration"""
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        # Check if LDAP storage is available
        if (
            not hasattr(_g.ca_backend.ca, "ldap_storage")
            or not _g.ca_backend.ca.ldap_storage
        ):
            return error_response(
                "NotSupported", "LDAP storage not available", 500
            )

        # Get current config to verify it exists
        hsm_config_dict = _g.ca_backend.ca.ldap_storage.get_hsm_config(ca_id)

        if not hsm_config_dict:
            return error_response(
                "NotFound",
                f"HSM configuration for CA {ca_id} not found",
                404,
            )

        # Delete HSM config from LDAP
        if hasattr(_g.ca_backend.ca.ldap_storage, "delete_hsm_config"):
            _g.ca_backend.ca.ldap_storage.delete_hsm_config(ca_id)
            return success_response(
                {
                    "Status": "SUCCESS",
                    "Message": (
                        f"HSM configuration for CA {ca_id} deleted"
                    ),
                    "ca_id": ca_id,
                }
            )
        else:
            # Fallback: disable by setting enabled=False
            hsm_config_dict["enabled"] = False
            _g.ca_backend.ca.ldap_storage.store_hsm_config(
                ca_id, hsm_config_dict
            )
            return success_response(
                {
                    "Status": "SUCCESS",
                    "Message": (
                        f"HSM configuration for CA {ca_id} disabled"
                    ),
                    "ca_id": ca_id,
                }
            )

    except Exception as e:
        logger.error("Error deleting HSM configuration: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/hsm/test", methods=["POST"])
@require_agent_auth
def test_hsm_connection():
    """Test HSM connection"""
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        # Check if LDAP storage is available
        if (
            not hasattr(_g.ca_backend.ca, "ldap_storage")
            or not _g.ca_backend.ca.ldap_storage
        ):
            return error_response(
                "NotSupported", "LDAP storage not available", 500
            )

        hsm_config_dict = _g.ca_backend.ca.ldap_storage.get_hsm_config(ca_id)

        if not hsm_config_dict or not hsm_config_dict.get("enabled"):
            return error_response(
                "NotFound", f"HSM not configured for CA {ca_id}", 404
            )

        # Try to initialize HSM backend
        try:
            hsm_config = HSMConfig(hsm_config_dict)
            hsm_backend = HSMKeyBackend(hsm_config)

            # Try to list keys (minimal operation to test connection)
            keys = hsm_backend.list_keys()

            hsm_backend.close()

            return success_response(
                {
                    "Status": "SUCCESS",
                    "Message": "HSM connection successful",
                    "ca_id": ca_id,
                    "keys_found": len(keys),
                    "library": hsm_config_dict.get("pkcs11_library"),
                    "slot_label": hsm_config_dict.get("slot_label"),
                }
            )

        except Exception as hsm_error:
            return success_response(
                {
                    "Status": "FAILED",
                    "Message": f"HSM connection failed: {str(hsm_error)}",
                    "ca_id": ca_id,
                },
                status_code=503,
            )

    except Exception as e:
        logger.error("Error testing HSM connection: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/hsm/slots", methods=["GET"])
@require_agent_auth
def list_hsm_slots():
    """
    List available HSM slots

    Query parameters:
    - library: PKCS#11 library path (required)

    Returns list of available slots with their labels and info
    """
    try:
        library_path = request.args.get("library")

        if not library_path:
            return error_response(
                "BadRequest", "Missing required parameter: library", 400
            )

        # Validate library path exists
        if not os.path.exists(library_path):
            return error_response(
                "NotFound",
                f"PKCS#11 library not found: {library_path}",
                404,
            )

        # List slots using HSM backend
        try:
            slots = list_pkcs11_slots(library_path)

            return success_response(
                {
                    "library": library_path,
                    "total": len(slots),
                    "entries": slots,
                }
            )

        except Exception as hsm_error:
            logger.error("Error listing HSM slots: %s", hsm_error)
            return error_response(
                "HSMError",
                f"Failed to list HSM slots: {str(hsm_error)}",
                503,
            )

    except Exception as e:
        logger.error("Error in list_hsm_slots: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/hsm/info", methods=["GET"])
@require_agent_auth
def get_hsm_info():
    """
    Get HSM device information

    Query parameters:
    - ca_id: CA identifier (optional, default: "ipa")

    Returns detailed HSM device and token information
    """
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        # Check if LDAP storage is available
        if (
            not hasattr(_g.ca_backend.ca, "ldap_storage")
            or not _g.ca_backend.ca.ldap_storage
        ):
            return error_response(
                "NotSupported", "LDAP storage not available", 500
            )

        hsm_config_dict = _g.ca_backend.ca.ldap_storage.get_hsm_config(ca_id)

        if not hsm_config_dict or not hsm_config_dict.get("enabled"):
            return error_response(
                "NotFound", f"HSM not configured for CA {ca_id}", 404
            )

        # Get HSM info
        try:
            hsm_info = get_hsm_device_info(
                hsm_config_dict.get("pkcs11_library"),
                hsm_config_dict.get("slot_id"),
                hsm_config_dict.get("slot_label"),
            )

            return success_response(hsm_info)

        except Exception as hsm_error:
            logger.error("Error getting HSM info: %s", hsm_error)
            return error_response(
                "HSMError",
                f"Failed to get HSM info: {str(hsm_error)}",
                503,
            )

    except Exception as e:
        logger.error("Error in get_hsm_info: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/hsm/keys", methods=["GET"])
@require_agent_auth
def list_hsm_keys():
    """List keys in HSM"""
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")

        # Check if LDAP storage is available
        if (
            not hasattr(_g.ca_backend.ca, "ldap_storage")
            or not _g.ca_backend.ca.ldap_storage
        ):
            return error_response(
                "NotSupported", "LDAP storage not available", 500
            )

        hsm_config_dict = _g.ca_backend.ca.ldap_storage.get_hsm_config(ca_id)

        if not hsm_config_dict or not hsm_config_dict.get("enabled"):
            return error_response(
                "NotFound", f"HSM not configured for CA {ca_id}", 404
            )

        # List keys in HSM
        try:
            hsm_config = HSMConfig(hsm_config_dict)
            hsm_backend = HSMKeyBackend(hsm_config)

            keys = hsm_backend.list_keys()

            hsm_backend.close()

            return success_response(
                {
                    "total": len(keys),
                    "entries": [{"label": key} for key in keys],
                }
            )

        except Exception as hsm_error:
            logger.error("Error listing HSM keys: %s", hsm_error)
            return error_response(
                "HSMError",
                f"Failed to list HSM keys: {str(hsm_error)}",
                503,
            )

    except Exception as e:
        logger.error("Error in list_hsm_keys: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/hsm/keys/generate", methods=["POST"])
@require_agent_auth
def generate_hsm_key():
    """
    Generate a new key pair in HSM

    Request body:
    {
        "ca_id": "ipa",
        "key_label": "ipa-ca-signing-2025",
        "key_size": 2048,
        "key_type": "RSA"
    }

    Returns key generation status and public key info
    """
    try:
        init_ca()

        data = request.get_json() or {}

        ca_id = data.get("ca_id", "ipa")
        key_label = data.get("key_label")
        key_size = data.get("key_size", 2048)
        key_type = data.get("key_type", "RSA")

        if not key_label:
            return error_response(
                "BadRequest", "Missing required field: key_label", 400
            )

        # Validate key size
        if key_type == "RSA" and key_size not in [2048, 3072, 4096]:
            return error_response(
                "BadRequest",
                "Invalid key size for RSA (must be 2048, 3072, or 4096)",
                400,
            )

        # Check if LDAP storage is available
        if (
            not hasattr(_g.ca_backend.ca, "ldap_storage")
            or not _g.ca_backend.ca.ldap_storage
        ):
            return error_response(
                "NotSupported", "LDAP storage not available", 500
            )

        hsm_config_dict = _g.ca_backend.ca.ldap_storage.get_hsm_config(ca_id)

        if not hsm_config_dict or not hsm_config_dict.get("enabled"):
            return error_response(
                "NotFound", f"HSM not configured for CA {ca_id}", 404
            )

        # Generate key in HSM
        try:
            hsm_config = HSMConfig(hsm_config_dict)
            hsm_backend = HSMKeyBackend(hsm_config)

            # Generate key pair
            pub_handle, priv_handle = hsm_backend.generate_key_pair(
                key_label, key_size, key_type
            )

            # Get public key
            public_key = hsm_backend.get_public_key(key_label)

            hsm_backend.close()

            return success_response(
                {
                    "Status": "SUCCESS",
                    "Message": (
                        f"Key pair generated in HSM: {key_label}"
                    ),
                    "key_label": key_label,
                    "key_type": key_type,
                    "key_size": key_size,
                    "public_key_handle": str(pub_handle),
                    "private_key_handle": str(priv_handle),
                    "has_public_key": public_key is not None,
                },
                status_code=201,
            )

        except Exception as hsm_error:
            logger.error("Error generating HSM key: %s", hsm_error)
            return error_response(
                "HSMError",
                f"Failed to generate HSM key: {str(hsm_error)}",
                503,
            )

    except Exception as e:
        logger.error("Error in generate_hsm_key: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/hsm/keys/<key_label>", methods=["DELETE"])
@require_agent_auth
def delete_hsm_key(key_label):
    """
    Delete a key from HSM

    Query parameters:
    - ca_id: CA identifier (optional, default: "ipa")
    - confirm: Must be "true" to confirm deletion (required)

    This is a destructive operation and requires confirmation.
    """
    try:
        init_ca()

        ca_id = request.args.get("ca_id", "ipa")
        confirm = request.args.get("confirm", "false").lower()

        if confirm != "true":
            return error_response(
                "BadRequest",
                "Key deletion requires confirmation (set confirm=true)",
                400,
            )

        # Check if LDAP storage is available
        if (
            not hasattr(_g.ca_backend.ca, "ldap_storage")
            or not _g.ca_backend.ca.ldap_storage
        ):
            return error_response(
                "NotSupported", "LDAP storage not available", 500
            )

        hsm_config_dict = _g.ca_backend.ca.ldap_storage.get_hsm_config(ca_id)

        if not hsm_config_dict or not hsm_config_dict.get("enabled"):
            return error_response(
                "NotFound", f"HSM not configured for CA {ca_id}", 404
            )

        # Delete key from HSM
        try:
            hsm_config = HSMConfig(hsm_config_dict)
            hsm_backend = HSMKeyBackend(hsm_config)

            # Verify key exists before deletion
            priv_key = hsm_backend.find_key(key_label)
            if not priv_key:
                hsm_backend.close()
                return error_response(
                    "KeyNotFound",
                    f"Key not found in HSM: {key_label}",
                    404,
                )

            # Delete the key
            hsm_backend.delete_key(key_label)

            hsm_backend.close()

            return success_response(
                {
                    "Status": "SUCCESS",
                    "Message": f"Key deleted from HSM: {key_label}",
                    "key_label": key_label,
                }
            )

        except Exception as hsm_error:
            logger.error("Error deleting HSM key: %s", hsm_error)
            return error_response(
                "HSMError",
                f"Failed to delete HSM key: {str(hsm_error)}",
                503,
            )

    except Exception as e:
        logger.error("Error in delete_hsm_key: %s", e)
        return error_response("ServerError", str(e), 500)
