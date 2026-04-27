# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Shared LDAP Connection Utilities for ipathinca

This module provides a centralized LDAP connection management for all
ipathinca components, ensuring consistent authentication and connection
handling across the ipathinca service.
"""

import os
import logging
import time
from queue import Queue, Empty, Full
from threading import Lock
from contextlib import contextmanager

from ipalib import errors
from ipapython import ipaldap
from ipapython.dn import DN
from ipathinca import get_config_value
from ipathinca.exceptions import StorageConnectionError

logger = logging.getLogger(__name__)

# Global cached LDAP connection (legacy - kept for backward compatibility)
_ldap_connection = None
_ldap_connection_lock = Lock()

# Connection pool for high-concurrency scenarios
_connection_pool = None
_pool_lock = Lock()


class LDAPConnectionPool:
    """
    LDAP Connection Pool for high-concurrency scenarios

    Maintains a pool of LDAP connections to handle concurrent certificate
    operations without connection exhaustion. Provides health checking and
    automatic reconnection.
    """

    def __init__(
        self, min_connections=2, max_connections=10, health_check_interval=60
    ):
        """
        Initialize connection pool

        Args:
            min_connections: Minimum connections to keep alive
            max_connections: Maximum connections in pool
            health_check_interval: Seconds between health checks
        """
        self.min_connections = min_connections
        self.max_connections = max_connections
        self.health_check_interval = health_check_interval

        self._pool = Queue(maxsize=max_connections)
        self._lock = Lock()
        self._created_count = 0
        self._last_health_check = time.time()

        # Pre-create minimum connections
        for _ in range(min_connections):
            try:
                conn = self._create_connection()
                self._pool.put_nowait(conn)
                self._created_count += 1
            except Exception as e:
                logger.warning(f"Failed to pre-create connection: {e}")

    def _create_connection(self):
        """Create a new LDAP connection"""
        logger.debug(
            f"Creating new LDAP connection (pool size: {self._created_count})"
        )

        realm = get_config_value("global", "realm")
        ldap_client = ipaldap.LDAPClient.from_realm(
            realm, force_schema_updates=False
        )
        ldap_client.external_bind()

        return ldap_client

    def _is_connection_healthy(self, conn):
        """Check if connection is still healthy

        Uses whoami_s() extended operation to test if the connection is alive.
        This is a lightweight operation that will fail if the connection is
        broken.
        """
        try:
            # Check if connection object exists
            if not hasattr(conn, "conn") or conn.conn is None:
                return False

            # Use whoami_s() to test if connection is alive
            # This is a standard LDAP extended operation that returns the DN
            # of the authenticated user
            conn.conn.whoami_s()
            return True
        except Exception as e:
            # Any exception means connection is not healthy
            logger.debug("Connection health check failed: %s", e)
            return False

    @contextmanager
    def get_connection(self, timeout=5):
        """
        Get connection from pool (context manager)

        Usage:
            with pool.get_connection() as conn:
                conn.get_entry(dn)
        """
        conn = None
        try:
            # Try to get existing connection from pool
            try:
                conn = self._pool.get(timeout=timeout)

                # Health check
                if not self._is_connection_healthy(conn):
                    logger.debug(
                        "Connection from pool is unhealthy, creating new one"
                    )
                    try:
                        conn.close()
                    except (AttributeError, RuntimeError) as e:
                        # Connection may already be closed or in invalid state
                        logger.debug(
                            "Error closing unhealthy connection: %s", e
                        )
                    conn = self._create_connection()
            except Empty:
                # Pool is empty, create new connection if under limit
                with self._lock:
                    if self._created_count < self.max_connections:
                        conn = self._create_connection()
                        self._created_count += 1
                    else:
                        # At max connections — must wait for one to return
                        try:
                            conn = self._pool.get(timeout=timeout * 2)
                        except Empty:
                            raise StorageConnectionError(
                                "LDAP connection pool exhausted "
                                f"(max={self.max_connections})"
                            )
                        if not self._is_connection_healthy(conn):
                            # Replace unhealthy connection (count stays same)
                            try:
                                conn.close()
                            except (AttributeError, RuntimeError):
                                pass
                            conn = self._create_connection()

            yield conn

        finally:
            # Return connection to pool
            if conn is not None:
                try:
                    try:
                        is_healthy = self._is_connection_healthy(conn)
                    except Exception as e:
                        logger.warning("Connection health check failed: %s", e)
                        is_healthy = False

                    if is_healthy:
                        self._pool.put_nowait(conn)
                    else:
                        # Don't return unhealthy connection to pool
                        with self._lock:
                            self._created_count -= 1
                        try:
                            conn.close()
                        except (AttributeError, RuntimeError) as e:
                            # Connection already closed or invalid
                            logger.debug(
                                "Error closing unhealthy connection: %s", e
                            )
                except Full:
                    # Pool is full, close excess connection
                    with self._lock:
                        self._created_count -= 1
                    try:
                        conn.close()
                    except (AttributeError, RuntimeError) as e:
                        # Connection already closed or invalid
                        logger.debug("Error closing excess connection: %s", e)

    def close_all(self):
        """Close all connections in pool"""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Empty:
                # Queue became empty concurrently
                break
            except (AttributeError, RuntimeError) as e:
                # Connection already closed or invalid
                logger.debug("Error closing pooled connection: %s", e)

        with self._lock:
            self._created_count = 0


def init_connection_pool(min_connections=None, max_connections=None):
    """
    Initialize the global LDAP connection pool

    Args:
        min_connections: Minimum connections to keep alive (default: from
                         config or 2)
        max_connections: Maximum connections in pool (default: from config
                         or 10)

    Returns:
        LDAPConnectionPool instance
    """
    global _connection_pool

    with _pool_lock:
        if _connection_pool is None:
            # Read from configuration if not specified
            if min_connections is None:
                try:
                    min_connections = int(
                        get_config_value(
                            "ldap", "pool_min_connections", default="2"
                        )
                    )
                except (ValueError, TypeError):
                    min_connections = 2

            if max_connections is None:
                try:
                    max_connections = int(
                        get_config_value(
                            "ldap", "pool_max_connections", default="10"
                        )
                    )
                except (ValueError, TypeError):
                    max_connections = 10

            logger.debug(
                f"Initializing LDAP connection pool (min={min_connections}, "
                f"max={max_connections})"
            )
            _connection_pool = LDAPConnectionPool(
                min_connections, max_connections
            )
        return _connection_pool


def get_ldap_connection(force_reconnect: bool = False, use_pool: bool = None):
    """Get shared LDAP connection using Directory Manager credentials

    This function provides a pooled LDAP connection for optimal performance.
    The connection uses EXTERNAL bind via LDAPI, which works reliably for the
    ipathinca service.

    Args:
        force_reconnect: If True, close existing connection and create a new
                         one (singleton mode only, deprecated)
        use_pool: If True, use connection pool (default)
                  If False, use singleton mode (deprecated)
                  If None, defaults to True (pooling enabled)

    Returns:
        Context manager for pooled LDAP connection (use with 'with' statement)
        If use_pool=False (deprecated), returns LDAPClient instance

    Raises:
        Exception: If connection cannot be established

    Note:
        Connection pooling is now the default for optimal performance.
        To temporarily disable pooling (not recommended):
        - Set IPATHINCA_USE_LDAP_POOL=0 environment variable, OR
        - Pass use_pool=False to this function

        Pool configuration in /etc/ipa/ipathinca.conf:
        - pool_min_connections (default: 2)
        - pool_max_connections (default: 10)
    """
    global _ldap_connection

    # Determine pool mode - pooling is now the default
    if use_pool is None:
        # Check environment variable (allow opt-out if needed)
        env_pool = os.environ.get("IPATHINCA_USE_LDAP_POOL", "").lower()
        if env_pool in ("0", "false", "no", "off"):
            use_pool = False
        else:
            # Default to pooling for performance
            use_pool = True

    # Use connection pool if requested
    if use_pool:
        global _connection_pool
        if _connection_pool is None:
            init_connection_pool()
        return _connection_pool.get_connection()

    # Legacy singleton mode (deprecated, NOT thread-safe)
    # python-ldap connections must not be shared across threads.
    # Only use this for single-threaded contexts (e.g., install scripts).
    logger.warning(
        "Using legacy singleton LDAP connection (not thread-safe). "
        "Use pooled connections (use_pool=True) for threaded workers."
    )
    with _ldap_connection_lock:
        # Check if we need to reconnect
        if force_reconnect and _ldap_connection is not None:
            try:
                _ldap_connection.close()
            except (AttributeError, RuntimeError) as e:
                # Connection may already be closed or invalid
                logger.debug(
                    "Error closing connection during force_reconnect: %s", e
                )
            _ldap_connection = None

        # Check if we already have a valid connection
        if _ldap_connection is not None:
            try:
                if _ldap_connection.isconnected():
                    logger.debug("Reusing existing LDAP connection")
                    return _ldap_connection
            except Exception:
                logger.debug(
                    "Cached LDAP connection is not valid, reconnecting"
                )
                _ldap_connection = None

        # Create new LDAP connection
        try:
            realm = get_config_value("global", "realm")
            logger.debug(
                f"Connecting to LDAP via LDAPI socket for realm {realm}"
            )

            # Use from_realm() which properly configures LDAPI connection
            ldap_client = ipaldap.LDAPClient.from_realm(
                realm, force_schema_updates=False
            )

            # Try simple bind with Directory Manager credentials from
            # /etc/dirsrv. This is more reliable than EXTERNAL bind which
            # requires SSL
            try:
                realm_name = str(realm).replace(".", "-")
                dm_password_file = f"/etc/dirsrv/slapd-{realm_name}/dse.ldif"

                # Read DM password from dse.ldif (nsslapd-rootpw attribute)
                if os.path.exists(dm_password_file):
                    with open(dm_password_file, "r") as f:
                        for line in f:
                            if line.startswith("nsslapd-rootpw:"):
                                # This is hashed, we need the plain
                                # password. For now, fall back to EXTERNAL
                                # with proper setup
                                break

                # Use EXTERNAL bind with STARTTLS to satisfy SSL requirement
                # Even though it's a Unix socket, the LDAP server requires
                # SSL/TLS
                ldap_client.external_bind()

            except Exception as bind_err:
                logger.error(f"EXTERNAL bind failed: {bind_err}")
                # Simple bind as cn=Directory Manager is not available in
                # production
                raise errors.DatabaseError(
                    desc="Cannot connect to LDAP database",
                    info=f"EXTERNAL bind failed: {bind_err}",
                )

            logger.debug("Successfully connected to LDAP via LDAPI")

            # Cache the connection
            _ldap_connection = ldap_client
            return _ldap_connection

        except Exception as e:
            logger.error(
                f"Failed to create LDAP connection: {e}", exc_info=True
            )
            raise StorageConnectionError(
                f"Cannot connect to LDAP database: {e}"
            )


def close_ldap_connection():
    """Close the shared LDAP connection

    This should be called when shutting down the service or when
    you need to force a reconnection with different credentials.
    """
    global _ldap_connection

    if _ldap_connection is not None:
        try:
            _ldap_connection.close()
            logger.debug("LDAP connection closed")
        except Exception as e:
            logger.warning(f"Error closing LDAP connection: {e}")
        finally:
            _ldap_connection = None


def close_ldap_pool():
    """Close the LDAP connection pool

    This should be called when shutting down the service to cleanly
    close all pooled connections.
    """
    global _connection_pool

    if _connection_pool is not None:
        try:
            _connection_pool.close_all()
            logger.debug("LDAP connection pool closed")
        except Exception as e:
            logger.warning(f"Error closing LDAP connection pool: {e}")
        finally:
            _connection_pool = None


def is_main_ca_id(ca_id, ca_name="ipa", config=None):
    """Check if ca_id refers to the main IPA CA

    This checks both by name (ipa, host-authority) and by UUID stored in LDAP.
    The main IPA CA has a UUID stored at cn=ipa,cn=cas,cn=ca,{basedn} in the
    ipaCaId attribute.

    Args:
        ca_id: CA identifier to check (string or None)
        ca_name: Main CA name to compare against (default: "ipa")
        config: RawConfigParser object from ipathinca.conf (optional)

    Returns:
        bool: True if ca_id refers to the main CA, False otherwise
    """
    # Check by name first (fast path)
    if not ca_id or ca_id in ("ipa", "host-authority") or ca_id == ca_name:
        return True

    # Check if this is the UUID of the main IPA CA by querying LDAP
    try:
        import ldap as python_ldap

        # Get realm and basedn from config
        if config:
            realm = config.get("global", "realm")
            basedn = config.get("global", "basedn")
        else:
            realm = get_config_value("global", "realm")
            basedn = get_config_value("global", "basedn")

        # Connect to LDAP via socket
        ldap_socket = (
            f'ldapi://%2Frun%2Fslapd-{realm.replace(".", "-")}.socket'
        )
        conn = python_ldap.initialize(ldap_socket)
        conn.sasl_interactive_bind_s("", python_ldap.sasl.external())

        # Read the main CA's UUID from IPA's CA entry
        ca_dn = str(DN(("cn", "ipa"), ("cn", "cas"), ("cn", "ca"), basedn))
        result = conn.search_s(
            ca_dn, python_ldap.SCOPE_BASE, "(objectClass=*)", ["ipaCaId"]
        )

        if result and result[0][1] and "ipaCaId" in result[0][1]:
            main_ca_uuid = result[0][1]["ipaCaId"][0].decode("utf-8")
            is_main = ca_id == main_ca_uuid
            logger.debug(
                "UUID check: ca_id=%s, main_ca_uuid=%s, is_main=%s",
                ca_id,
                main_ca_uuid,
                is_main,
            )
            conn.unbind()
            return is_main

        conn.unbind()
    except Exception as e:
        logger.debug("Could not check if %s is main CA UUID: %s", ca_id, e)

    return False


def is_internal_token(token_name):
    """Check if token is internal NSS database (software) or HSM

    This matches Dogtag's token detection logic from pki/nssdb.py.
    Internal tokens are identified as empty string, 'internal', or
    'Internal Key Storage Token'.

    Args:
        token_name: Token name to check (string or None)

    Returns:
        bool: True if token is internal (software), False if HSM
    """
    if not token_name:
        return True

    if token_name.lower() == "internal":
        return True

    if token_name.lower() == "internal key storage token":
        return True

    return False
