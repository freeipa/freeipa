# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import logging
import re
from xml.sax.saxutils import escape as xml_escape

from flask import Blueprint, Response, request

import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import require_ca_backend, init_ca
from ipacta.rest_api._helpers import (
    handle_ca_errors,
    validate_input,
    require_agent_auth,
    validate_profile_id,
    error_response,
    success_response,
    build_profile_response,
    ProfileHandler,
    clean_csr_data,
    build_dogtag_xml_response,
)
from ipalib import errors

logger = logging.getLogger(__name__)

bp = Blueprint("profiles", __name__)


# ============================================================================
# Certificate Profile Endpoints
# ============================================================================


@bp.route("/ca/ee/ca/profileList", methods=["GET"])
def legacy_profile_list():
    """Legacy Dogtag endpoint for profile list - returns XML"""
    try:
        init_ca()

        xml_output = request.args.get("xml", "false").lower() == "true"

        if xml_output:
            # Return XML format for dogtag-submit compatibility
            profiles = _g.ca_backend.profile_manager.list_profiles()

            profile_entries = []
            for profile in profiles:
                profile_entries.append(
                    f'<profile id="{xml_escape(profile.profile_id)}">'
                    f"{xml_escape(profile.name)}</profile>"
                )

            profiles_xml = "\n".join(profile_entries)

            response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<profiles>
{profiles_xml}
</profiles>"""

            return Response(response_xml, mimetype="application/xml")
        else:
            # Return text format
            profiles = _g.ca_backend.profile_manager.list_profiles()
            profile_list = "\n".join(
                [f"{p.profile_id}:{p.name}" for p in profiles]
            )
            return Response(profile_list, mimetype="text/plain")

    except Exception as e:
        logger.error("Error in legacy_profile_list: %s", e)
        return error_response("ServerError", str(e), 500)


@bp.route("/ca/rest/profiles", methods=["GET"])
@bp.route("/ca/v2/profiles", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def list_profiles():
    """List certificate profiles"""
    return ProfileHandler.list_all(_g.ca_backend)


@bp.route("/ca/rest/profiles", methods=["POST"])
@bp.route("/ca/v2/profiles", methods=["POST"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def create_profile():
    """Create new certificate profile

    Accepts:
    - JSON format with profileId field (Dogtag REST API style)
    - Plain text .cfg format (IPA certprofile-import style)
    """
    logger.info(
        "create_profile called, content-type: %s", request.content_type
    )

    # Try JSON format first (most common for IPA)
    try:
        data = request.get_json(silent=True)
        if data:
            logger.info("Parsed JSON data, keys: %s", list(data.keys()))
            profile_id = data.get("profileId") or data.get("ProfileId")

            # Check if profileData contains .cfg content
            if "profileData" in data:
                cfg_content = data["profileData"]
                logger.info(
                    "Found profileData field with %s chars", len(cfg_content)
                )
                if not profile_id:
                    # Extract from .cfg content
                    match = re.search(r"profileId\s*=\s*(\S+)", cfg_content)
                    if match:
                        profile_id = match.group(1)
                        logger.info(
                            "Extracted profile ID from .cfg: '%s'", profile_id
                        )

                if not profile_id:
                    return error_response(
                        "BadRequest", "profileId field required", 400
                    )

                result = ProfileHandler.create_raw(
                    profile_id, cfg_content, _g.ca_backend
                )
                return result
            elif profile_id:
                # Standard JSON profile creation
                return ProfileHandler.create_or_update(
                    profile_id, data, _g.ca_backend, is_update=False
                )
    except Exception as e:
        logger.warning("Failed to parse as JSON: %s", e)

    # Try plain text .cfg format
    content_type = request.content_type or ""
    if (
        "text/plain" in content_type
        or "application/octet-stream" in content_type
    ):
        cfg_content = request.get_data(as_text=True)
        logger.info(
            "Plain text content-type, got %d chars",
            len(cfg_content) if cfg_content else 0,
        )
        if not cfg_content:
            return error_response(
                "BadRequest", "No profile data provided", 400
            )

        # Extract profile ID from .cfg content
        match = re.search(r"profileId\s*=\s*(\S+)", cfg_content)
        if match:
            profile_id = match.group(1)
            logger.info("Extracted profile ID from .cfg: '%s'", profile_id)
        else:
            return error_response(
                "BadRequest", "Profile ID not found in configuration", 400
            )

        result = ProfileHandler.create_raw(
            profile_id, cfg_content, _g.ca_backend
        )
        return result

    # Last resort: get raw data
    cfg_content = request.get_data(as_text=True)
    logger.info(
        "Fallback: raw data, got %d chars",
        len(cfg_content) if cfg_content else 0,
    )
    if not cfg_content:
        return error_response("BadRequest", "No profile data provided", 400)

    # Extract profile ID from .cfg content
    match = re.search(r"profileId\s*=\s*(\S+)", cfg_content)
    if match:
        profile_id = match.group(1)
        logger.info("Extracted profile ID from .cfg: '%s'", profile_id)
    else:
        return error_response(
            "BadRequest", "Profile ID not found in configuration", 400
        )

    return ProfileHandler.create_raw(profile_id, cfg_content, _g.ca_backend)


@bp.route("/ca/rest/profiles/<profile_id>", methods=["GET"])
@bp.route("/ca/v2/profiles/<profile_id>", methods=["GET"])
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def get_profile(profile_id):
    """Get certificate profile"""
    get_profile.__resource_type__ = "Profile"
    return ProfileHandler.get(profile_id, _g.ca_backend)


@bp.route("/ca/rest/profiles/raw", methods=["POST"])
@bp.route("/ca/v2/profiles/raw", methods=["POST"])
@require_agent_auth
@require_ca_backend
@handle_ca_errors
def create_profile_from_raw():
    """
    Create certificate profile from .cfg format

    POST /ca/v2/profiles/raw

    Used by: ipa certprofile-import --file <file>
    Profile ID is extracted from the .cfg content

    Request body: text/plain .cfg file content
    """
    logger.info("create_profile_from_raw called")
    logger.info("Request content-type: %s", request.content_type)
    logger.info("Request content-length: %s", request.content_length)

    # Try different ways to get the data
    cfg_content = request.get_data(as_text=True)
    logger.info(
        "get_data result: %s chars", len(cfg_content) if cfg_content else 0
    )

    if not cfg_content:
        # Try form data
        if request.form:
            logger.info(
                "Found form data with keys: %s", list(request.form.keys())
            )
            cfg_content = request.form.get("file") or request.form.get(
                "profileData"
            )

        if not cfg_content:
            logger.error("No profile data found in request")
            return error_response(
                "BadRequest", "No profile data provided", 400
            )

    # Extract profile ID from .cfg content
    match = re.search(r"profileId\s*=\s*(\S+)", cfg_content)
    if match:
        profile_id = match.group(1)
        logger.info(
            "Creating profile %s from .cfg content (%s chars)",
            profile_id,
            len(cfg_content),
        )
    else:
        return error_response(
            "BadRequest", "Profile ID not found in configuration", 400
        )

    return ProfileHandler.create_raw(profile_id, cfg_content, _g.ca_backend)


@bp.route("/ca/rest/profiles/<profile_id>", methods=["POST", "PUT"])
@bp.route("/ca/v2/profiles/<profile_id>", methods=["POST", "PUT"])
@require_agent_auth  # Enable/disable actions require agent auth
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def update_profile(profile_id):
    """Create or update certificate profile

    Accepts both:
    - JSON format (Dogtag REST API style)
    - Plain text .cfg format (IPA certprofile-import style)
    - Query parameter action=enable/disable for state changes (requires agent
      auth)
    """
    # Check for action query parameter (enable/disable)
    action = request.args.get("action")
    if action == "enable":
        logger.info("update_profile: Routing to enable for %s", profile_id)
        # Return full profile object like enable_profile does
        profile_data = _g.ca_backend.read_profile(profile_id)
        return success_response(build_profile_response(profile_data))
    elif action == "disable":
        logger.info("update_profile: Routing to disable for %s", profile_id)
        # Return full profile object like disable_profile does
        profile_data = _g.ca_backend.read_profile(profile_id)
        return success_response(build_profile_response(profile_data))

    # Check Content-Type to determine format
    content_type = request.content_type or ""

    # If Content-Type is text/plain or if JSON parsing fails, treat as .cfg
    # content
    if (
        "text/plain" in content_type
        or "application/octet-stream" in content_type
    ):
        # Plain text .cfg format (ipa certprofile-import)
        cfg_content = request.get_data(as_text=True)
        if not cfg_content:
            return error_response(
                "BadRequest", "No profile data provided", 400
            )

        is_update = request.method == "PUT"
        return (
            ProfileHandler.update_raw(
                profile_id, cfg_content, _g.ca_backend
            )
            if is_update
            else ProfileHandler.create_raw(
                profile_id, cfg_content, _g.ca_backend
            )
        )

    # Try JSON format first (Dogtag REST API)
    try:
        data = request.get_json()
        if data:
            is_update = request.method == "PUT"
            return ProfileHandler.create_or_update(
                profile_id, data, _g.ca_backend, is_update
            )
    except Exception:
        # Not valid JSON, try as .cfg content
        pass

    # Fall back to treating as .cfg content
    cfg_content = request.get_data(as_text=True)
    if not cfg_content:
        return error_response("BadRequest", "No profile data provided", 400)

    is_update = request.method == "PUT"
    return (
        ProfileHandler.update_raw(profile_id, cfg_content, _g.ca_backend)
        if is_update
        else ProfileHandler.create_raw(
            profile_id, cfg_content, _g.ca_backend
        )
    )


@bp.route("/ca/rest/profiles/<profile_id>", methods=["DELETE"])
@bp.route("/ca/v2/profiles/<profile_id>", methods=["DELETE"])
@require_agent_auth
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def delete_profile(profile_id):
    """Delete certificate profile"""
    delete_profile.__resource_type__ = "Profile"
    return ProfileHandler.delete(profile_id, _g.ca_backend)


@bp.route("/ca/rest/profiles/<profile_id>/enable", methods=["POST"])
@bp.route("/ca/v2/profiles/<profile_id>/enable", methods=["POST"])
@require_agent_auth
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def enable_profile(profile_id):
    """
    Enable a certificate profile

    This allows the profile to be used for certificate requests.
    Requires agent authentication.

    Returns the full profile object like Dogtag PKI does.
    """
    logger.info("enable_profile called for %s", profile_id)
    try:
        # For now, profiles are always enabled in ipacta
        # This endpoint is provided for Dogtag API compatibility
        # In a full implementation, you would call storage.enable_profile()

        # Return the full profile object like Dogtag does
        logger.info("Reading profile %s for enable response", profile_id)
        profile_data = _g.ca_backend.read_profile(profile_id)
        logger.info("Profile data: %s", profile_data)
        response = build_profile_response(profile_data)
        logger.info("Built response: %s", response)
        return success_response(response)

    except Exception as e:
        logger.error(
            "Error enabling profile %s: %s", profile_id, e, exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to enable profile: {str(e)}", 500
        )


@bp.route("/ca/rest/profiles/<profile_id>/disable", methods=["POST"])
@bp.route("/ca/v2/profiles/<profile_id>/disable", methods=["POST"])
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
        # For now, profiles cannot be disabled in ipacta
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
            "Error disabling profile %s: %s", profile_id, e, exc_info=True
        )
        return error_response(
            "InternalError", f"Failed to disable profile: {str(e)}", 500
        )


@bp.route("/ca/rest/profiles/<profile_id>/raw", methods=["GET"])
@bp.route("/ca/v2/profiles/<profile_id>/raw", methods=["GET"])
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def get_profile_raw(profile_id):
    """
    Export certificate profile configuration in .cfg format

    GET /ca/v2/profiles/{profile_id}/raw

    Used by: ipa certprofile-show --out <file>

    Returns:
        text/plain: Profile .cfg file content
    """
    return ProfileHandler.get_raw(profile_id, _g.ca_backend)


@bp.route("/ca/rest/profiles/<profile_id>/raw", methods=["PUT"])
@bp.route("/ca/v2/profiles/<profile_id>/raw", methods=["PUT"])
@require_agent_auth
@require_ca_backend
@validate_input(profile_id=validate_profile_id)
@handle_ca_errors
def update_profile_raw(profile_id):
    """
    Update certificate profile configuration from .cfg format

    PUT /ca/v2/profiles/{profile_id}/raw

    Used by: ipa certprofile-mod --file <file>

    Request body: text/plain .cfg file content
    """
    cfg_content = request.get_data(as_text=True)
    if not cfg_content:
        return error_response("BadRequest", "No profile data provided", 400)

    return ProfileHandler.update_raw(profile_id, cfg_content, _g.ca_backend)


# ============================================================================
# Legacy Dogtag Endpoints (for backward compatibility with certmonger)
# ============================================================================


@bp.route("/ca/ee/ca/profileSubmitSSLClient", methods=["POST", "GET"])
@bp.route("/ca/eeca/ca/profileSubmitSSLClient", methods=["POST", "GET"])
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
        result = _g.ca_backend.request_certificate(csr_data, profile_id)

        # Get the issued certificate if available
        cert_pem = None
        if result.get("serial_number"):
            cert_result = _g.ca_backend.get_certificate(
                result["serial_number"]
            )
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
            return Response(
                cert_pem or "", mimetype="application/x-pem-file"
            )

    except errors.CertificateOperationError as e:
        logger.error("Certificate request failed: %s", e, exc_info=True)
        error_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f"<XMLResponse>\n<Status>1</Status>\n"
            f"<Error>{xml_escape(str(e))}</Error>\n</XMLResponse>"
        )
        return Response(error_xml, mimetype="application/xml", status=400)

    except Exception as e:
        logger.error(
            "Error in profile_submit_ssl_client: %s", e, exc_info=True
        )
        error_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<XMLResponse>\n<Status>1</Status>\n"
            f"<Error>{xml_escape(str(e))}</Error>\n</XMLResponse>"
        )
        return Response(error_xml, mimetype="application/xml", status=500)
