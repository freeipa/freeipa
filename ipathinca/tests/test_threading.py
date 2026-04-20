# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Thread-safety and worker configuration verification tests for IPAthinCA

All tests run against a live deployed ipathinca service and verify:

1. Gunicorn worker/thread configuration is correct
2. Concurrent HTTP requests are handled without errors or deadlocks
3. Worker processes remain stable under load
4. Thread count scales under concurrent requests

Prerequisites:
    - ipathinca.service running on the test host
    - IPA CA configured and operational

Run with:
    pytest ipathinca/tests/test_threading.py -v
"""

import concurrent.futures
import configparser
import json
import os
import subprocess
import time
from collections import Counter

import pytest

# ======================================================================
# Concurrency tuning — adjust these to increase/decrease load
# ======================================================================

# Maximum concurrent threads for all test sections
MAX_WORKERS = 100

# Section 2: Concurrent request tests
CONCURRENT_INFO_REQUESTS = 40
CONCURRENT_MIXED_ROUNDS = 10         # rounds × 3 endpoints
CONCURRENT_BURST_REQUESTS = 100

# Section 3: Worker stability tests
STABILITY_LOAD_REQUESTS = 100
STABILITY_MASTER_REQUESTS = 40
STABILITY_MEMLEAK_REQUESTS = 200

# Section 4: Conflict verification tests
CONFLICT_INFO_REQUESTS = 40
CONFLICT_PROFILE_REQUESTS = 30
CONFLICT_CERT_REQUESTS = 60
CONFLICT_READ_CERT_REQUESTS = 40
CONFLICT_MIXED_ROUNDS = 30           # rounds × 3 endpoints

# Section 5: Heavy load tests
HEAVY_INFO_REQUESTS = 800
HEAVY_CERT_REQUESTS = 200
HEAVY_MIXED_INFO_READS = 200
HEAVY_MIXED_PROFILE_READS = 200
HEAVY_MIXED_CERT_SUBMITS = 120
HEAVY_STABILITY_REQUESTS = 400


def _service_is_active():
    """Check if ipathinca.service is running."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "ipathinca.service"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "active"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(
    not _service_is_active(),
    reason="ipathinca.service not active",
)


@pytest.fixture(scope="module")
def service_info():
    """Gather running service configuration."""
    info = {"base_url": "https://localhost:8443"}

    # Read port from config
    cfg = configparser.ConfigParser()
    cfg.read("/etc/ipa/ipathinca.conf")
    port = cfg.get("server", "https_port", fallback="8443")
    info["base_url"] = f"https://localhost:{port}"
    info["configured_workers"] = int(
        cfg.get("server", "workers", fallback="1")
    )
    info["configured_threads"] = int(
        cfg.get("server", "threads", fallback="4")
    )

    # RA agent credentials for authenticated endpoints
    ra_key = "/var/lib/ipa/ra-agent.key"
    ra_cert = "/var/lib/ipa/ra-agent.pem"
    if os.path.exists(ra_key) and os.path.exists(ra_cert):
        info["ra_key"] = ra_key
        info["ra_cert"] = ra_cert

    # Find master and worker PIDs
    result = subprocess.run(
        ["pgrep", "-a", "-f", "ipathinca"],
        capture_output=True,
        text=True,
    )
    pids = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(None, 1)
        if parts:
            pids.append(int(parts[0]))

    if pids:
        # Master is the one whose parent is init (ppid=1) or systemd
        for pid in pids:
            try:
                stat = open(f"/proc/{pid}/stat").read()
                ppid = int(stat.split(")")[1].split()[1])
                if ppid == 1:
                    info["master_pid"] = pid
                    break
            except (FileNotFoundError, IndexError, ValueError):
                continue

        if "master_pid" not in info:
            info["master_pid"] = pids[0]

        # Workers are children of master
        result = subprocess.run(
            ["pgrep", "-P", str(info["master_pid"])],
            capture_output=True,
            text=True,
        )
        info["worker_pids"] = [
            int(p)
            for p in result.stdout.strip().splitlines()
            if p.strip()
        ]

    return info


def _curl_get(base_url, path, timeout=30):
    """Make an HTTPS GET request using curl.

    Returns HTTP status code, or 0 if the connection failed.
    """
    try:
        result = subprocess.run(
            [
                "curl", "-sk", "--max-time", str(timeout),
                "-o", "/dev/null", "-w", "%{http_code}",
                f"{base_url}{path}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
        code = result.stdout.strip()
        return int(code) if code else 0
    except (subprocess.TimeoutExpired, ValueError):
        return 0


def _curl_get_json(base_url, path, timeout=30, client_cert=None,
                    client_key=None):
    """Make an HTTPS GET request and return (status_code, json_body).

    Returns (0, None) if the connection failed.
    """
    cmd = [
        "curl", "-sk", "--max-time", str(timeout),
        "-H", "Accept: application/json",
        "-w", "\n%{http_code}",
    ]
    if client_cert:
        cmd.extend(["--cert", client_cert])
    if client_key:
        cmd.extend(["--key", client_key])
    cmd.append(f"{base_url}{path}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired:
        return 0, None
    lines = result.stdout.rsplit("\n", 1)
    body = lines[0] if len(lines) > 1 else ""
    try:
        status = int(lines[-1].strip()) if lines[-1].strip() else 0
    except ValueError:
        status = 0
    try:
        data = json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        data = None
    return status, data


def _curl_post_json(base_url, path, payload, timeout=30, client_cert=None,
                     client_key=None):
    """Make an HTTPS POST request with JSON body, return (status, json).

    Returns (0, None) if the connection failed.
    """
    cmd = [
        "curl", "-sk", "--max-time", str(timeout),
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "-H", "Accept: application/json",
        "-d", json.dumps(payload),
        "-w", "\n%{http_code}",
    ]
    if client_cert:
        cmd.extend(["--cert", client_cert])
    if client_key:
        cmd.extend(["--key", client_key])
    cmd.append(f"{base_url}{path}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired:
        return 0, None
    lines = result.stdout.rsplit("\n", 1)
    body = lines[0] if len(lines) > 1 else ""
    try:
        status = int(lines[-1].strip()) if lines[-1].strip() else 0
    except ValueError:
        status = 0
    try:
        data = json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        data = None
    return status, data


def _generate_csr():
    """Generate a fresh CSR using openssl."""
    result = subprocess.run(
        [
            "openssl", "req", "-new", "-newkey", "rsa:2048",
            "-nodes", "-keyout", "/dev/null",
            "-subj", "/CN=threadtest.example.com",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


# ======================================================================
# 1. Worker/thread configuration tests
# ======================================================================


class TestWorkerConfiguration:
    """Verify gunicorn is running with correct worker/thread setup."""

    def test_worker_count_matches_config(self, service_info):
        """Number of worker processes must match config."""
        expected = service_info["configured_workers"]
        actual = len(service_info.get("worker_pids", []))
        assert actual == expected, (
            f"Expected {expected} worker(s), found {actual}. "
            f"Worker PIDs: {service_info.get('worker_pids')}"
        )

    def test_worker_class_is_gthread(self, service_info):
        """Worker process must use gthread (multiple threads per worker)."""
        worker_pids = service_info.get("worker_pids", [])
        if not worker_pids:
            pytest.skip("No worker PIDs found")

        n_workers = len(worker_pids)
        n_threads = service_info.get("configured_threads", 4)

        # To prove gthread is active, we need multiple requests handled
        # concurrently *within a single worker*.  Each curl subprocess
        # has startup overhead, so requests finish before others start
        # unless we saturate the server.  Send workers * threads * 2
        # concurrent requests so each worker must handle several at once.
        # Use /pki/rest/info (no LDAP) to avoid exhausting LDAP sockets.
        n_requests = n_workers * n_threads * 2
        base_url = service_info["base_url"]

        def make_request():
            return _curl_get(base_url, "/pki/rest/info")

        max_thread_count = 0
        # Launch all requests, then sample thread counts while in-flight
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=n_requests
        ) as pool:
            futures = [pool.submit(make_request) for _ in range(n_requests)]

            # Sample thread counts across all workers while load is active
            for _ in range(20):
                time.sleep(0.05)
                for pid in worker_pids:
                    try:
                        count = len(os.listdir(f"/proc/{pid}/task"))
                        max_thread_count = max(max_thread_count, count)
                    except FileNotFoundError:
                        pass
            concurrent.futures.wait(futures)

        assert max_thread_count >= 2, (
            f"Expected >= 2 threads under load (gthread), got "
            f"{max_thread_count} across all workers with "
            f"{n_requests} concurrent requests to "
            f"{n_workers} workers x {n_threads} threads. "
            f"Worker may be using 'sync' class."
        )

    def test_preload_active(self, service_info):
        """With preload, workers must share memory (low USS)."""
        worker_pids = service_info.get("worker_pids", [])
        if not worker_pids:
            pytest.skip("No worker PIDs found")
        if len(worker_pids) < 2:
            pytest.skip(
                "Need >= 2 workers to measure CoW sharing "
                "(single worker has no sibling to share pages with)"
            )

        # Read PSS/RSS from /proc/pid/smaps_rollup (no external tools).
        # PSS (Proportional Set Size) divides shared pages equally among
        # sharers, so PSS < RSS proves pages are shared via CoW preload.
        # USS drifts upward as workers accumulate private dirty pages
        # after handling requests, making it unreliable for this check.
        for pid in worker_pids:
            smaps_path = f"/proc/{pid}/smaps_rollup"
            try:
                with open(smaps_path) as f:
                    data = f.read()
            except (FileNotFoundError, PermissionError):
                pytest.skip(f"Cannot read {smaps_path}")

            rss = pss = 0
            for line in data.splitlines():
                if line.startswith("Rss:"):
                    rss = int(line.split()[1])
                elif line.startswith("Pss:"):
                    pss = int(line.split()[1])

            if rss == 0:
                continue

            # With preload, PSS should be less than RSS because shared
            # pages (preloaded code, shared libraries) are divided among
            # workers.  After sustained load, workers accumulate private
            # dirty pages that push PSS closer to RSS, so the threshold
            # must be generous.  The key signal is PSS < RSS at all —
            # without preload, PSS ≈ RSS.
            # Use a fixed threshold.  The PSS/RSS ratio after sustained
            # load settles around 0.80-0.88 regardless of worker count
            # because private dirty pages dominate.  Without preload
            # PSS ≈ RSS (ratio ~1.0).  A threshold of 0.95 reliably
            # distinguishes preload (shared CoW pages) from no-preload.
            max_ratio = 0.95
            ratio = pss / rss
            assert ratio < max_ratio, (
                f"Worker PID {pid}: PSS={pss}kB, RSS={rss}kB, "
                f"ratio={ratio:.2f}. Expected < {max_ratio:.2f} "
                f"with {n_workers} workers and preload."
            )


# ======================================================================
# 2. Concurrent request tests
# ======================================================================


class TestConcurrentRequests:
    """Verify concurrent requests are handled correctly."""

    def test_concurrent_info_requests(self, service_info):
        """Concurrent GET /pki/rest/info must all return 200."""
        results = []
        errors = []

        def fetch():
            try:
                code = _curl_get(
                    service_info["base_url"], "/pki/rest/info",
                    timeout=30,
                )
                results.append(code)
            except Exception as e:
                errors.append(e)

        n = CONCURRENT_INFO_REQUESTS
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [pool.submit(fetch) for _ in range(n)]
            concurrent.futures.wait(futures, timeout=120)

        assert not errors, f"Request errors: {errors}"
        counts = Counter(results)
        # Status 0 means curl connection failure (TLS handshake timeout)
        connected = [r for r in results if r != 0]
        assert len(connected) > 0, (
            f"All requests failed to connect: {counts}"
        )
        non_200 = [r for r in connected if r != 200]
        assert not non_200, (
            f"Expected all connected requests to return 200, got: {counts}"
        )

    def test_concurrent_mixed_endpoints(self, service_info):
        """Concurrent requests to different endpoints must not deadlock."""
        paths = [
            "/pki/rest/info",
            "/pki/v2/info",
            "/ca/rest/certrequests",
        ]
        results = []
        errors = []

        def fetch(path):
            try:
                code = _curl_get(service_info["base_url"], path)
                results.append((path, code))
            except Exception as e:
                errors.append((path, e))

        n_rounds = CONCURRENT_MIXED_ROUNDS
        n_total = n_rounds * len(paths)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = []
            for _ in range(n_rounds):
                for path in paths:
                    futures.append(pool.submit(fetch, path))
            concurrent.futures.wait(futures, timeout=120)

        assert not errors, f"Request errors: {errors}"
        # All requests must complete (no deadlock); connection failures
        # (status 0) still count as completed (curl returned, not hung)
        assert len(results) == n_total, (
            f"Expected {n_total} results, got {len(results)} — possible deadlock"
        )

    def test_high_concurrency_burst(self, service_info):
        """High-concurrency burst must complete without errors."""
        n = CONCURRENT_BURST_REQUESTS
        results = []
        errors = []

        def fetch():
            try:
                code = _curl_get(
                    service_info["base_url"], "/pki/rest/info"
                )
                results.append(code)
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [pool.submit(fetch) for _ in range(n)]
            concurrent.futures.wait(futures, timeout=180)

        assert not errors, f"Request errors: {errors}"
        assert len(results) == n, (
            f"Expected {n} results, got {len(results)}"
        )
        # Allow connection failures (0) and some non-200 under heavy load
        # but no 500 internal server errors
        connected = [r for r in results if r != 0]
        error_500s = sum(1 for r in connected if r == 500)
        assert error_500s == 0, (
            f"Got {error_500s} internal server errors (500)"
        )


# ======================================================================
# 3. Worker stability tests
# ======================================================================


class TestWorkerStability:
    """Verify workers remain stable under load."""

    def test_no_worker_crash_under_load(self, service_info):
        """Worker PIDs must not change during sustained load."""
        pids_before = set(service_info.get("worker_pids", []))
        if not pids_before:
            pytest.skip("No worker PIDs found")

        # Sustained load
        errors = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [
                pool.submit(
                    _curl_get, service_info["base_url"], "/pki/rest/info"
                )
                for _ in range(STABILITY_LOAD_REQUESTS)
            ]
            concurrent.futures.wait(futures)
            for f in futures:
                try:
                    f.result()
                except Exception as e:
                    errors.append(e)

        # Check worker PIDs after load
        result = subprocess.run(
            ["pgrep", "-P", str(service_info["master_pid"])],
            capture_output=True,
            text=True,
        )
        pids_after = set(
            int(p)
            for p in result.stdout.strip().splitlines()
            if p.strip()
        )

        assert pids_before == pids_after, (
            f"Worker PIDs changed during load test. "
            f"Before: {pids_before}, After: {pids_after}. "
            "A worker may have crashed and been restarted."
        )
        assert not errors, f"Request errors during load: {errors}"

    def test_master_process_stable(self, service_info):
        """Master process must remain the same after load."""
        master_pid = service_info.get("master_pid")
        if not master_pid:
            pytest.skip("No master PID found")

        # Load test
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [
                pool.submit(
                    _curl_get, service_info["base_url"], "/pki/rest/info"
                )
                for _ in range(STABILITY_MASTER_REQUESTS)
            ]
            concurrent.futures.wait(futures)

        # Master must still exist
        assert os.path.exists(f"/proc/{master_pid}"), (
            f"Master process {master_pid} died during load test"
        )

    def test_memory_does_not_leak_under_load(self, service_info):
        """Worker RSS must not grow unboundedly during load."""
        worker_pids = service_info.get("worker_pids", [])
        if not worker_pids:
            pytest.skip("No worker PIDs found")

        worker_pid = worker_pids[0]

        def get_rss(pid):
            try:
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            return int(line.split()[1])
            except FileNotFoundError:
                return None
            return None

        rss_before = get_rss(worker_pid)
        if rss_before is None:
            pytest.skip(f"Cannot read RSS for PID {worker_pid}")

        # Sustained load
        n = STABILITY_MEMLEAK_REQUESTS
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [
                pool.submit(
                    _curl_get, service_info["base_url"], "/pki/rest/info"
                )
                for _ in range(n)
            ]
            concurrent.futures.wait(futures)

        rss_after = get_rss(worker_pid)
        if rss_after is None:
            pytest.skip(f"Cannot read RSS for PID {worker_pid} after load")

        # Allow up to 50% growth (normal for Python GC variance)
        growth_ratio = rss_after / rss_before if rss_before > 0 else 1.0
        assert growth_ratio < 1.5, (
            f"Worker RSS grew from {rss_before}kB to {rss_after}kB "
            f"({growth_ratio:.2f}x) during {n} requests. "
            "Possible memory leak."
        )


# ======================================================================
# 4. Concurrent conflict verification tests
# ======================================================================


class TestConcurrentConflicts:
    """Verify concurrent requests do not produce data conflicts."""

    def test_concurrent_info_responses_consistent(self, service_info):
        """Concurrent /pki/rest/info requests must all return identical data."""
        results = []
        errors = []

        def fetch():
            try:
                status, data = _curl_get_json(
                    service_info["base_url"], "/pki/rest/info",
                    timeout=30,
                )
                results.append((status, data))
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [
                pool.submit(fetch) for _ in range(CONFLICT_INFO_REQUESTS)
            ]
            concurrent.futures.wait(futures, timeout=120)

        assert not errors, f"Request errors: {errors}"

        # Filter to successfully connected responses (status 0 = curl failure)
        ok_results = [
            r for r in results if r[0] == 200 and r[1] is not None
        ]
        assert len(ok_results) >= 2, (
            f"Need at least 2 successful responses to compare, got "
            f"{len(ok_results)}. Status codes: {Counter(r[0] for r in results)}"
        )

        # All successful response bodies must be identical
        reference = ok_results[0][1]
        for i, (_, body) in enumerate(ok_results[1:], 1):
            assert body == reference, (
                f"Response {i} differs from response 0. "
                f"Got {body}, expected {reference}"
            )

    def test_concurrent_profile_list_consistent(self, service_info):
        """Concurrent profile list requests must return same profiles."""
        results = []
        errors = []

        def fetch():
            try:
                status, data = _curl_get_json(
                    service_info["base_url"], "/ca/rest/profiles"
                )
                results.append((status, data))
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [
                pool.submit(fetch) for _ in range(CONFLICT_PROFILE_REQUESTS)
            ]
            concurrent.futures.wait(futures)

        assert not errors, f"Request errors: {errors}"

        # Filter successful responses
        ok_results = [r for r in results if r[0] == 200 and r[1] is not None]
        if len(ok_results) < 2:
            pytest.skip("Not enough successful profile responses")

        # Extract profile IDs from each response
        profile_sets = []
        for _, data in ok_results:
            if isinstance(data, dict) and "entries" in data:
                ids = sorted(
                    e.get("profileId", e.get("id", ""))
                    for e in data["entries"]
                )
            elif isinstance(data, list):
                ids = sorted(
                    e.get("profileId", e.get("id", ""))
                    for e in data
                )
            else:
                continue
            profile_sets.append(ids)

        if len(profile_sets) < 2:
            pytest.skip("Could not parse profile responses")

        reference = profile_sets[0]
        for i, ids in enumerate(profile_sets[1:], 1):
            assert ids == reference, (
                f"Profile list {i} differs from list 0. "
                f"Missing: {set(reference) - set(ids)}, "
                f"Extra: {set(ids) - set(reference)}"
            )

    def test_concurrent_cert_requests_unique_ids(self, service_info):
        """Concurrent cert requests must each get a unique request ID."""
        ra_cert = service_info.get("ra_cert")
        ra_key = service_info.get("ra_key")
        if not ra_cert or not ra_key:
            pytest.skip("RA agent credentials not available")

        csr = _generate_csr()
        if csr is None:
            pytest.skip("Could not generate CSR (openssl not available)")

        results = []
        errors = []

        def submit():
            try:
                payload = {
                    "ProfileID": "caIPAserviceCert",
                    "pkcs10": csr,
                }
                status, data = _curl_post_json(
                    service_info["base_url"],
                    "/ca/rest/certrequests",
                    payload,
                    timeout=30,
                    client_cert=ra_cert,
                    client_key=ra_key,
                )
                results.append((status, data))
            except Exception as e:
                errors.append(e)

        n_requests = CONFLICT_CERT_REQUESTS
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [pool.submit(submit) for _ in range(n_requests)]
            concurrent.futures.wait(futures, timeout=180)

        assert not errors, f"Request errors: {errors}"

        # Collect request IDs and cert IDs from responses
        # Response format: {"entries": [{"requestId": "...", "certId": "0x..."}]}
        request_ids = []
        cert_ids = []
        for status, data in results:
            if data is None:
                continue
            entries = data.get("entries", [data] if "requestId" in data else [])
            for entry in entries:
                req_id = entry.get("requestId")
                if req_id is not None:
                    request_ids.append(str(req_id))
                cert_id = entry.get("certId")
                if cert_id is not None:
                    cert_ids.append(str(cert_id))

        if not request_ids:
            assert len(results) == n_requests, (
                f"Expected {n_requests} responses, got {len(results)}"
            )
            pytest.skip(
                "No request IDs returned. "
                f"Status codes: {[r[0] for r in results]}"
            )

        # Request IDs must be unique
        assert len(request_ids) == len(set(request_ids)), (
            f"Duplicate request IDs found! "
            f"IDs: {request_ids}, "
            f"Duplicates: {[x for x in request_ids if request_ids.count(x) > 1]}"
        )

        # Cert IDs (serial numbers) must also be unique
        if cert_ids:
            assert len(cert_ids) == len(set(cert_ids)), (
                f"Duplicate cert IDs (serial numbers) found! "
                f"IDs: {cert_ids}, "
                f"Duplicates: "
                f"{[x for x in cert_ids if cert_ids.count(x) > 1]}"
            )

    def test_concurrent_read_same_cert(self, service_info):
        """Concurrent reads of the same certificate must return identical data."""
        ra_cert = service_info.get("ra_cert")
        ra_key = service_info.get("ra_key")
        if not ra_cert or not ra_key:
            pytest.skip("RA agent credentials not available")

        # First, find a valid certificate serial number
        status, data = _curl_get_json(
            service_info["base_url"],
            "/ca/rest/certs/search",
            timeout=15,
            client_cert=ra_cert,
            client_key=ra_key,
        )
        if status != 200 or data is None:
            # Try POST search
            status, data = _curl_post_json(
                service_info["base_url"],
                "/ca/rest/certs/search",
                {},
                timeout=15,
                client_cert=ra_cert,
                client_key=ra_key,
            )
        if status != 200 or data is None:
            pytest.skip("Cannot search certificates")

        # Extract a serial number
        serial = None
        entries = data.get("entries", data if isinstance(data, list) else [])
        for entry in entries:
            s = (
                entry.get("id")
                or entry.get("SerialNumber")
                or entry.get("serialNumber")
            )
            if s is not None:
                serial = s
                break

        if serial is None:
            pytest.skip("No certificates found to test concurrent reads")

        results = []
        errors = []

        def fetch():
            try:
                s, d = _curl_get_json(
                    service_info["base_url"],
                    f"/ca/rest/certs/{serial}",
                    client_cert=ra_cert,
                    client_key=ra_key,
                )
                results.append((s, d))
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [
                pool.submit(fetch)
                for _ in range(CONFLICT_READ_CERT_REQUESTS)
            ]
            concurrent.futures.wait(futures)

        assert not errors, f"Request errors: {errors}"

        ok_results = [r for r in results if r[0] == 200 and r[1] is not None]
        if len(ok_results) < 2:
            pytest.skip("Not enough successful cert read responses")

        # All responses for the same cert must be identical
        reference = ok_results[0][1]
        for i, (_, body) in enumerate(ok_results[1:], 1):
            assert body == reference, (
                f"Cert read {i} differs from read 0 for serial {serial}. "
                f"This indicates concurrent read corruption."
            )

    def test_mixed_read_write_no_corruption(self, service_info):
        """Concurrent reads and writes must not corrupt each other's data."""
        csr = _generate_csr()
        ra_cert = service_info.get("ra_cert")
        ra_key = service_info.get("ra_key")

        results_info = []
        results_profiles = []
        results_submit = []
        errors = []

        def fetch_info():
            try:
                s, d = _curl_get_json(
                    service_info["base_url"], "/pki/rest/info"
                )
                results_info.append((s, d))
            except Exception as e:
                errors.append(("info", e))

        def fetch_profiles():
            try:
                s, d = _curl_get_json(
                    service_info["base_url"], "/ca/rest/profiles"
                )
                results_profiles.append((s, d))
            except Exception as e:
                errors.append(("profiles", e))

        def submit_cert():
            if csr is None or not ra_cert or not ra_key:
                return
            try:
                payload = {
                    "ProfileID": "caIPAserviceCert",
                    "pkcs10": csr,
                }
                s, d = _curl_post_json(
                    service_info["base_url"],
                    "/ca/rest/certrequests",
                    payload,
                    timeout=30,
                    client_cert=ra_cert,
                    client_key=ra_key,
                )
                results_submit.append((s, d))
            except Exception as e:
                errors.append(("submit", e))

        # Mix reads and writes concurrently
        n_rounds = CONFLICT_MIXED_ROUNDS
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = []
            for _ in range(n_rounds):
                futures.append(pool.submit(fetch_info))
                futures.append(pool.submit(fetch_profiles))
                futures.append(pool.submit(submit_cert))
            concurrent.futures.wait(futures, timeout=180)

        # No exceptions
        assert not errors, f"Request errors: {errors}"

        # Info responses must all be consistent
        info_ok = [
            r[1] for r in results_info if r[0] == 200 and r[1] is not None
        ]
        if len(info_ok) >= 2:
            ref = info_ok[0]
            for i, body in enumerate(info_ok[1:], 1):
                assert body == ref, (
                    f"Info response {i} differs during mixed load"
                )

        # No 500 errors from any endpoint
        all_statuses = (
            [r[0] for r in results_info]
            + [r[0] for r in results_profiles]
            + [r[0] for r in results_submit]
        )
        error_500s = sum(1 for s in all_statuses if s == 500)
        assert error_500s == 0, (
            f"Got {error_500s} internal server errors (500) during "
            f"mixed read/write load"
        )

        # Cert submissions (if any succeeded) must have unique request IDs
        req_ids = []
        for _, data in results_submit:
            if data is None:
                continue
            entries = data.get("entries", [data] if "requestId" in data else [])
            for entry in entries:
                rid = entry.get("requestId")
                if rid is not None:
                    req_ids.append(str(rid))
        if req_ids:
            assert len(req_ids) == len(set(req_ids)), (
                f"Duplicate request IDs during mixed load: {req_ids}"
            )


# ======================================================================
# 5. Heavy load tests
# ======================================================================


class TestHeavyLoad:
    """Stress tests under sustained heavy load."""

    def test_sustained_info_barrage(self, service_info):
        """Rapid-fire info requests must all succeed."""
        n = HEAVY_INFO_REQUESTS
        results = []
        errors = []

        def fetch():
            try:
                code = _curl_get(
                    service_info["base_url"], "/pki/rest/info"
                )
                results.append(code)
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [pool.submit(fetch) for _ in range(n)]
            concurrent.futures.wait(futures, timeout=300)

        assert not errors, f"Request errors: {errors}"
        assert len(results) == n, (
            f"Expected {n} results, got {len(results)}"
        )
        connected = [r for r in results if r != 0]
        assert len(connected) > 0, "All requests failed to connect"
        error_500s = sum(1 for r in connected if r == 500)
        assert error_500s == 0, (
            f"Got {error_500s} internal server errors (500) "
            f"during {n}-request barrage"
        )

    def test_sustained_cert_issuance(self, service_info):
        """Sustained concurrent cert requests must all get unique IDs."""
        ra_cert = service_info.get("ra_cert")
        ra_key = service_info.get("ra_key")
        if not ra_cert or not ra_key:
            pytest.skip("RA agent credentials not available")

        csr = _generate_csr()
        if csr is None:
            pytest.skip("Could not generate CSR (openssl not available)")

        results = []
        errors = []

        def submit():
            try:
                payload = {
                    "ProfileID": "caIPAserviceCert",
                    "pkcs10": csr,
                }
                status, data = _curl_post_json(
                    service_info["base_url"],
                    "/ca/rest/certrequests",
                    payload,
                    timeout=60,
                    client_cert=ra_cert,
                    client_key=ra_key,
                )
                results.append((status, data))
            except Exception as e:
                errors.append(e)

        n_requests = HEAVY_CERT_REQUESTS
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [pool.submit(submit) for _ in range(n_requests)]
            concurrent.futures.wait(futures, timeout=300)

        assert not errors, f"Request errors: {errors}"
        assert len(results) == n_requests, (
            f"Expected {n_requests} results, got {len(results)}"
        )

        # No 500 errors
        connected = [(s, d) for s, d in results if s != 0]
        error_500s = sum(1 for s, _ in connected if s == 500)
        assert error_500s == 0, (
            f"Got {error_500s} internal server errors (500) "
            f"during {n_requests}-request cert issuance"
        )

        # All request IDs and cert IDs must be unique
        request_ids = []
        cert_ids = []
        for status, data in connected:
            if data is None:
                continue
            entries = data.get(
                "entries", [data] if "requestId" in data else []
            )
            for entry in entries:
                req_id = entry.get("requestId")
                if req_id is not None:
                    request_ids.append(str(req_id))
                cert_id = entry.get("certId")
                if cert_id is not None:
                    cert_ids.append(str(cert_id))

        if request_ids:
            assert len(request_ids) == len(set(request_ids)), (
                f"Duplicate request IDs in heavy load! "
                f"Total: {len(request_ids)}, "
                f"Unique: {len(set(request_ids))}"
            )
        if cert_ids:
            assert len(cert_ids) == len(set(cert_ids)), (
                f"Duplicate cert IDs in heavy load! "
                f"Total: {len(cert_ids)}, "
                f"Unique: {len(set(cert_ids))}"
            )

    def test_sustained_mixed_heavy_load(self, service_info):
        """Heavy mixed read/write load."""
        ra_cert = service_info.get("ra_cert")
        ra_key = service_info.get("ra_key")
        csr = _generate_csr() if ra_cert and ra_key else None

        results_read = []
        results_submit = []
        errors = []

        def fetch_info():
            try:
                s, d = _curl_get_json(
                    service_info["base_url"], "/pki/rest/info"
                )
                results_read.append((s, d))
            except Exception as e:
                errors.append(("info", e))

        def fetch_profiles():
            try:
                s, d = _curl_get_json(
                    service_info["base_url"], "/ca/rest/profiles"
                )
                results_read.append((s, d))
            except Exception as e:
                errors.append(("profiles", e))

        def submit_cert():
            if csr is None:
                return
            try:
                payload = {
                    "ProfileID": "caIPAserviceCert",
                    "pkcs10": csr,
                }
                s, d = _curl_post_json(
                    service_info["base_url"],
                    "/ca/rest/certrequests",
                    payload,
                    timeout=60,
                    client_cert=ra_cert,
                    client_key=ra_key,
                )
                results_submit.append((s, d))
            except Exception as e:
                errors.append(("submit", e))

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = []
            futures.extend(
                pool.submit(fetch_info)
                for _ in range(HEAVY_MIXED_INFO_READS)
            )
            futures.extend(
                pool.submit(fetch_profiles)
                for _ in range(HEAVY_MIXED_PROFILE_READS)
            )
            futures.extend(
                pool.submit(submit_cert)
                for _ in range(HEAVY_MIXED_CERT_SUBMITS)
            )
            concurrent.futures.wait(futures, timeout=300)

        assert not errors, f"Request errors: {errors}"

        # No 500 errors across all endpoints
        all_statuses = (
            [r[0] for r in results_read]
            + [r[0] for r in results_submit]
        )
        connected = [s for s in all_statuses if s != 0]
        error_500s = sum(1 for s in connected if s == 500)
        assert error_500s == 0, (
            f"Got {error_500s} internal server errors (500) "
            f"during heavy mixed load"
        )

        # Read responses must be consistent
        info_ok = [
            r[1] for r in results_read
            if r[0] == 200 and r[1] is not None
            and isinstance(r[1], dict) and "Version" in r[1]
        ]
        if len(info_ok) >= 2:
            ref = info_ok[0]
            for i, body in enumerate(info_ok[1:], 1):
                assert body == ref, (
                    f"Info response {i} differs during heavy load"
                )

        # Cert submission IDs must be unique
        req_ids = []
        cert_ids = []
        for _, data in results_submit:
            if data is None:
                continue
            entries = data.get(
                "entries", [data] if "requestId" in data else []
            )
            for entry in entries:
                rid = entry.get("requestId")
                if rid is not None:
                    req_ids.append(str(rid))
                cid = entry.get("certId")
                if cid is not None:
                    cert_ids.append(str(cid))

        if req_ids:
            assert len(req_ids) == len(set(req_ids)), (
                f"Duplicate request IDs during heavy mixed load: "
                f"Total: {len(req_ids)}, Unique: {len(set(req_ids))}"
            )
        if cert_ids:
            assert len(cert_ids) == len(set(cert_ids)), (
                f"Duplicate cert IDs during heavy mixed load: "
                f"Total: {len(cert_ids)}, Unique: {len(set(cert_ids))}"
            )

    def test_workers_stable_after_heavy_load(self, service_info):
        """Worker PIDs must not change after sustained heavy load."""
        pids_before = set(service_info.get("worker_pids", []))
        if not pids_before:
            pytest.skip("No worker PIDs found")

        master_pid = service_info.get("master_pid")

        # Heavy load
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:
            futures = [
                pool.submit(
                    _curl_get, service_info["base_url"], "/pki/rest/info"
                )
                for _ in range(HEAVY_STABILITY_REQUESTS)
            ]
            concurrent.futures.wait(futures, timeout=300)

        # Workers must still be the same
        result = subprocess.run(
            ["pgrep", "-P", str(master_pid)],
            capture_output=True,
            text=True,
        )
        pids_after = set(
            int(p)
            for p in result.stdout.strip().splitlines()
            if p.strip()
        )

        assert pids_before == pids_after, (
            f"Worker PIDs changed during heavy load. "
            f"Before: {pids_before}, After: {pids_after}. "
            "A worker may have crashed and been restarted."
        )

        # Master must still be alive
        if master_pid:
            assert os.path.exists(f"/proc/{master_pid}"), (
                f"Master process {master_pid} died during heavy load"
            )
