# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
LDAP connection pool and utility tests

Tests LDAPConnectionPool, is_main_ca_id, and is_internal_token.
Unit tests for utility functions run without deployment.
Pool tests require a running LDAP server.
"""

import os

import pytest

from ipathinca.ldap_utils import is_internal_token


# ======================================================================
# is_internal_token (unit tests, no deployment needed)
# ======================================================================


class TestIsInternalToken:
    """Test is_internal_token utility."""

    def test_none_is_internal(self):
        """None means internal token."""
        assert is_internal_token(None) is True

    def test_empty_string_is_internal(self):
        """Empty string means internal token."""
        assert is_internal_token("") is True

    def test_internal_lowercase(self):
        """'internal' is internal token."""
        assert is_internal_token("internal") is True

    def test_internal_mixed_case(self):
        """'Internal' is internal token."""
        assert is_internal_token("Internal") is True

    def test_internal_key_storage_token(self):
        """'Internal Key Storage Token' is internal."""
        assert is_internal_token("Internal Key Storage Token") is True

    def test_internal_key_storage_token_lowercase(self):
        """Case-insensitive match for Internal Key Storage Token."""
        assert is_internal_token("internal key storage token") is True

    def test_hsm_token(self):
        """HSM token name is not internal."""
        assert is_internal_token("SoftHSM2") is False

    def test_pkcs11_token(self):
        """PKCS#11 token name is not internal."""
        assert is_internal_token("PKCS11:Token") is False


# ======================================================================
# LDAPConnectionPool (deployment tests)
# ======================================================================


@pytest.mark.skipif(
    not os.path.exists("/etc/ipa/ipathinca.conf"),
    reason="ipathinca not deployed (no /etc/ipa/ipathinca.conf)",
)
class TestLDAPConnectionPool:
    """Test LDAP connection pooling (requires running LDAP)."""

    def test_pool_creation(self, ipathinca_config):
        """Pool creates minimum connections on init."""
        from ipathinca.ldap_utils import LDAPConnectionPool

        pool = LDAPConnectionPool(min_connections=1, max_connections=3)
        try:
            assert pool._created_count >= 1
        finally:
            pool.close_all()

    def test_get_connection(self, ipathinca_config):
        """get_connection returns a working LDAP connection."""
        from ipathinca.ldap_utils import LDAPConnectionPool

        pool = LDAPConnectionPool(min_connections=1, max_connections=3)
        try:
            with pool.get_connection() as conn:
                assert conn is not None
                # Connection should be functional
                assert hasattr(conn, "conn")
        finally:
            pool.close_all()

    def test_close_all(self, ipathinca_config):
        """close_all empties the pool."""
        from ipathinca.ldap_utils import LDAPConnectionPool

        pool = LDAPConnectionPool(min_connections=2, max_connections=5)
        pool.close_all()
        assert pool._created_count == 0
