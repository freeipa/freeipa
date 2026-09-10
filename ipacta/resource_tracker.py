# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Resource usage tracking for ipacta.

Captures snapshots of process-level and application-level resource usage
so that memory leaks and connection leaks can be detected by comparing
snapshots over time.

Metrics collected per snapshot:
- RSS / VMS (from /proc/self/status)
- Open file descriptor count (from /proc/self/fd)
- Active thread count
- GC generation object counts
- LDAP connection pool stats (created, idle, max)
- tracemalloc top-N allocation sites (opt-in)

Usage
-----
Periodic logging (e.g. every 5 minutes at DEBUG level)::

    from ipacta.resource_tracker import start_periodic_logging
    start_periodic_logging(interval_seconds=300)

On-demand snapshot::

    from ipacta.resource_tracker import get_snapshot
    snap = get_snapshot()
    snap.log()   # or snap.to_dict() for JSON

Enable tracemalloc for allocation tracing::

    from ipacta.resource_tracker import enable_tracemalloc
    enable_tracemalloc()   # call before start_periodic_logging
"""

from __future__ import annotations

import gc
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LDAPPoolStats:
    created: int
    idle: int
    max_connections: int
    min_connections: int


@dataclass
class ResourceSnapshot:
    timestamp: float
    rss_bytes: int
    vms_bytes: int
    open_fds: int
    thread_count: int
    gc_counts: Tuple[int, int, int]
    ldap_pool: Optional[LDAPPoolStats] = None
    tracemalloc_top: List[str] = field(default_factory=list)

    def log(self) -> None:
        ldap_info = ""
        if self.ldap_pool:
            ldap_info = (
                f" ldap={self.ldap_pool.created}created"
                f"/{self.ldap_pool.idle}idle"
                f"/{self.ldap_pool.max_connections}max"
            )
        logger.debug(
            "resources: rss=%.1fMB vms=%.1fMB fds=%d threads=%d"
            " gc(gen0=%d,gen1=%d,gen2=%d)%s",
            self.rss_bytes / 1024 ** 2,
            self.vms_bytes / 1024 ** 2,
            self.open_fds,
            self.thread_count,
            self.gc_counts[0],
            self.gc_counts[1],
            self.gc_counts[2],
            ldap_info,
        )
        for line in self.tracemalloc_top:
            logger.debug("tracemalloc: %s", line)

    def to_dict(self) -> dict:
        d: dict = {
            "timestamp": self.timestamp,
            "memory": {
                "rss_mb": round(self.rss_bytes / 1024 ** 2, 2),
                "vms_mb": round(self.vms_bytes / 1024 ** 2, 2),
            },
            "open_fds": self.open_fds,
            "threads": self.thread_count,
            "gc": {
                "gen0": self.gc_counts[0],
                "gen1": self.gc_counts[1],
                "gen2": self.gc_counts[2],
            },
        }
        if self.ldap_pool:
            d["ldap_pool"] = {
                "created": self.ldap_pool.created,
                "idle": self.ldap_pool.idle,
                "max": self.ldap_pool.max_connections,
                "min": self.ldap_pool.min_connections,
            }
        if self.tracemalloc_top:
            d["tracemalloc_top"] = self.tracemalloc_top
        return d


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _count_open_fds() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


def _get_memory_usage() -> Tuple[int, int]:
    """Return (rss_bytes, vms_bytes) from /proc/self/status."""
    rss = vms = 0
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) * 1024
                elif line.startswith("VmSize:"):
                    vms = int(line.split()[1]) * 1024
                if rss and vms:
                    break
    except OSError:
        try:
            import resource as _resource
            usage = _resource.getrusage(_resource.RUSAGE_SELF)
            rss = usage.ru_maxrss * 1024  # Linux: KB → bytes
        except Exception:
            pass
    return rss, vms


def _get_ldap_pool_stats() -> Optional[LDAPPoolStats]:
    try:
        from ipacta.ldap_utils import _connection_pool
        if _connection_pool is None:
            return None
        return _connection_pool.get_stats()
    except Exception as e:
        logger.debug("Could not read LDAP pool stats: %s", e)
        return None


# ---------------------------------------------------------------------------
# tracemalloc
# ---------------------------------------------------------------------------

_tracemalloc_enabled = False


def enable_tracemalloc(nframes: int = 25) -> None:
    """Start tracemalloc allocation tracing (call once at startup)."""
    global _tracemalloc_enabled
    import tracemalloc
    if not tracemalloc.is_tracing():
        tracemalloc.start(nframes)
    _tracemalloc_enabled = True
    logger.info("tracemalloc enabled with %d frames", nframes)


def get_top_allocations(limit: int = 20) -> List[str]:
    """Return top-N allocation sites as human-readable strings."""
    try:
        import tracemalloc
        if not tracemalloc.is_tracing():
            return []
        snapshot = tracemalloc.take_snapshot()
        stats = snapshot.statistics("lineno")
        return [str(s) for s in stats[:limit]]
    except Exception as e:
        logger.debug("tracemalloc snapshot failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

def get_snapshot() -> ResourceSnapshot:
    """Capture a current resource usage snapshot."""
    rss, vms = _get_memory_usage()
    return ResourceSnapshot(
        timestamp=time.time(),
        rss_bytes=rss,
        vms_bytes=vms,
        open_fds=_count_open_fds(),
        thread_count=threading.active_count(),
        gc_counts=gc.get_count(),
        ldap_pool=_get_ldap_pool_stats(),
        tracemalloc_top=get_top_allocations() if _tracemalloc_enabled else [],
    )


# ---------------------------------------------------------------------------
# Periodic logging
# ---------------------------------------------------------------------------

_log_timer: Optional[threading.Timer] = None
_log_interval: float = 300.0
_log_lock = threading.Lock()


def _periodic_log() -> None:
    global _log_timer
    try:
        get_snapshot().log()
    except Exception as e:
        logger.warning("Resource snapshot failed: %s", e)
    finally:
        with _log_lock:
            if _log_timer is not None:
                _log_timer = threading.Timer(_log_interval, _periodic_log)
                _log_timer.daemon = True
                _log_timer.start()


def start_periodic_logging(interval_seconds: float = 300.0) -> None:
    """Log a resource snapshot every *interval_seconds* seconds (DEBUG level).

    The timer is a daemon thread so it does not prevent clean process exit.
    Calling this a second time resets the interval.
    """
    global _log_timer, _log_interval
    _log_interval = interval_seconds
    with _log_lock:
        if _log_timer is not None:
            _log_timer.cancel()
        _log_timer = threading.Timer(interval_seconds, _periodic_log)
        _log_timer.daemon = True
        _log_timer.start()
    logger.info(
        "Resource tracking started: interval=%.0fs tracemalloc=%s",
        interval_seconds,
        _tracemalloc_enabled,
    )


def stop_periodic_logging() -> None:
    """Cancel periodic resource logging."""
    global _log_timer
    with _log_lock:
        if _log_timer is not None:
            _log_timer.cancel()
            _log_timer = None
