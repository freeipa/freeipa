# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import logging

from flask import Blueprint, request, jsonify

import ipacta.rest_api._globals as _g
from ipacta.rest_api._globals import require_ca_backend
from ipacta.rest_api._helpers import (
    handle_ca_errors,
    require_agent_auth,
    error_response,
    success_response,
)

logger = logging.getLogger(__name__)

bp = Blueprint("ranges", __name__)


# ============================================================================
# Range Management Endpoints (Multi-Master Replication)
# ============================================================================


@bp.route("/ca/rest/ranges", methods=["GET"])
@bp.route("/ca/v2/ranges", methods=["GET"])
@require_ca_backend
@handle_ca_errors
def list_all_ranges():
    """
    List all serial number ranges across all replicas

    Returns comprehensive range information for multi-master deployments
    """
    try:
        storage = _g.ca_backend.ca.storage

        if hasattr(storage, "list_all_ranges"):
            ranges = storage.list_all_ranges()
            return jsonify({"entries": ranges, "total": len(ranges)}), 200
        else:
            return error_response(
                "NotImplemented", "Range management not available", 501
            )

    except Exception as e:
        logger.error("Error listing ranges: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to list ranges: {str(e)}", 500
        )


@bp.route("/ca/rest/ranges/replica/<replica_id>", methods=["GET"])
@bp.route("/ca/v2/ranges/replica/<replica_id>", methods=["GET"])
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
        storage = _g.ca_backend.ca.storage

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
        logger.error("Error getting replica ranges: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to get replica ranges: {str(e)}", 500
        )


@bp.route("/ca/rest/ranges/allocate", methods=["POST"])
@bp.route("/ca/v2/ranges/allocate", methods=["POST"])
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

        storage = _g.ca_backend.ca.storage

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
        logger.error("Error allocating range: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to allocate range: {str(e)}", 500
        )


@bp.route(
    "/ca/rest/ranges/replica/<replica_id>/<int:begin_range>",
    methods=["PUT"],
)
@bp.route(
    "/ca/v2/ranges/replica/<replica_id>/<int:begin_range>",
    methods=["PUT"],
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

        storage = _g.ca_backend.ca.storage

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
        logger.error("Error updating range: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to update range: {str(e)}", 500
        )


@bp.route(
    "/ca/rest/ranges/replica/<replica_id>/<int:begin_range>",
    methods=["DELETE"],
)
@bp.route(
    "/ca/v2/ranges/replica/<replica_id>/<int:begin_range>",
    methods=["DELETE"],
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
        storage = _g.ca_backend.ca.storage

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
        logger.error("Error deleting range: %s", e, exc_info=True)
        return error_response(
            "InternalError", f"Failed to delete range: {str(e)}", 500
        )


@bp.route("/ca/rest/ranges/replica/<replica_id>", methods=["DELETE"])
@bp.route("/ca/v2/ranges/replica/<replica_id>", methods=["DELETE"])
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
        storage = _g.ca_backend.ca.storage

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
        logger.error("Error deleting replica ranges: %s", e, exc_info=True)
        return error_response(
            "InternalError",
            f"Failed to delete replica ranges: {str(e)}",
            500,
        )
