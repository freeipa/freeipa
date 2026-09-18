# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""In-memory sliding-window rate limiter for REST API endpoints."""

import functools
import threading
import time
from collections import deque
from typing import Dict


_NUM_SHARDS = 16


class _Shard:
    __slots__ = ("lock", "windows")

    def __init__(self):
        self.lock = threading.Lock()
        self.windows: Dict[str, deque] = {}


class RateLimiter:
    """Sliding-window rate limiter keyed by arbitrary string (IP, account, …).

    Thread-safe.  Maintains a deque of request timestamps per key and evicts
    those older than ``window_seconds`` on each check.  Keys are distributed
    across shards to reduce lock contention under high concurrency.
    """

    def __init__(self, limit: int, window_seconds: int):
        self._limit = limit
        self._window = window_seconds
        self._shards = [_Shard() for _ in range(_NUM_SHARDS)]

    def _get_shard(self, key: str) -> _Shard:
        return self._shards[hash(key) % _NUM_SHARDS]

    def is_allowed(self, key: str) -> bool:
        """Record a request attempt and return True if within limit."""
        now = time.monotonic()
        cutoff = now - self._window
        shard = self._get_shard(key)
        with shard.lock:
            dq = shard.windows.setdefault(key, deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self._limit:
                return False
            dq.append(now)
            return True

    def purge_stale(self) -> None:
        """Remove buckets that have no requests in the last window period.

        Call periodically (e.g. from a background thread) to bound memory use
        in long-running deployments that receive requests from many IPs.
        """
        now = time.monotonic()
        cutoff = now - self._window
        for shard in self._shards:
            with shard.lock:
                stale = [
                    k
                    for k, dq in shard.windows.items()
                    if not dq or dq[-1] < cutoff
                ]
                for k in stale:
                    del shard.windows[k]


def rate_limit_flask(limiter: RateLimiter, error_type: str = "rateLimited"):
    """Flask decorator that enforces *limiter* keyed by ``request.remote_addr``.

    On excess returns HTTP 429 with an ACME-compatible JSON error body and a
    ``Retry-After`` header indicating the limiter's window length in seconds.
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify
            ip = request.remote_addr or "unknown"
            if not limiter.is_allowed(ip):
                body = jsonify({
                    "type": (
                        f"urn:ietf:params:acme:error:{error_type}"
                    ),
                    "detail": "Too many requests, please try again later",
                })
                body.status_code = 429
                body.headers["Retry-After"] = str(limiter._window)
                return body
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Shared limiter instances (module-level singletons)
#
# Limits are intentionally generous: IPA is an internal CA on a private
# network, not a public CA.  The goal is DoS mitigation, not subscriber
# throttling.
# ---------------------------------------------------------------------------

# ACME new-account: 20 per hour per IP
# Prevents account enumeration / mass registration from a single source.
acme_new_account = RateLimiter(limit=20, window_seconds=3600)

# ACME new-order: 60 per minute per IP
# A legitimate host requesting many certs (e.g. during mass re-keying) may
# burst, so the window is short.
acme_new_order = RateLimiter(limit=60, window_seconds=60)

# ACME revoke-cert: 10 per minute per IP
acme_revoke = RateLimiter(limit=10, window_seconds=60)

# All other ACME POST endpoints (challenges, finalizations, etc.): 120/min
acme_general = RateLimiter(limit=120, window_seconds=60)

# OCSP: 600 per minute per IP — high-traffic; limit is anti-DoS only
ocsp = RateLimiter(limit=600, window_seconds=60)
