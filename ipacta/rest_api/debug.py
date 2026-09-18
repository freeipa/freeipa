# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Debug / diagnostics endpoints for ipacta.

Provides on-demand resource snapshots to assist with memory-leak analysis.
All endpoints require agent authentication (RA agent certificate).
"""

import logging

from flask import Blueprint, jsonify

from ipacta.rest_api._helpers import require_agent_auth

logger = logging.getLogger(__name__)

bp = Blueprint("debug", __name__)


@bp.route("/ca/rest/debug/resources", methods=["GET"])
@require_agent_auth
def resources():
    """Return a current resource-usage snapshot.

    The snapshot includes:
    - Process RSS and VMS (MB)
    - Open file-descriptor count
    - Active thread count
    - GC generation object counts
    - LDAP connection pool statistics
    - Top memory-allocation sites (only when tracemalloc is enabled)

    To enable tracemalloc, set ``tracemalloc = true`` under the ``[debug]``
    section of ``ipacta.conf`` before starting the service, or set the
    environment variable ``IPACTA_TRACEMALLOC=1``.
    """
    from ipacta.resource_tracker import get_snapshot
    snap = get_snapshot()
    return jsonify(snap.to_dict())


@bp.route("/ca/rest/debug/gc", methods=["POST"])
@require_agent_auth
def force_gc():
    """Force a full garbage-collection cycle and return object counts.

    Useful for determining whether objects are actually being freed or
    are accumulating due to reference cycles.
    """
    import gc
    before = gc.get_count()
    collected = gc.collect(2)  # full collection
    after = gc.get_count()
    return jsonify({
        "collected_unreachable": collected,
        "gc_counts_before": {
            "gen0": before[0], "gen1": before[1],
            "gen2": before[2],
        },
        "gc_counts_after": {
            "gen0": after[0], "gen1": after[1],
            "gen2": after[2],
        },
    })
