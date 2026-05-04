# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Tests for IPAthinCAConfig

Tests config creation, file I/O, pass-through methods, and defaults.
"""

import os
import pytest
import tempfile

from ipathinca.config import (
    IPAthinCAConfig,
    IPATHINCA_DEFAULTS,
    WSGI_DEFAULTS,
)
from ipathinca.exceptions import InvalidCAConfiguration


# ======================================================================
# IPATHINCA_DEFAULTS and WSGI_DEFAULTS
# ======================================================================


class TestDefaults:
    """Test default configuration values."""

    def test_ipathinca_defaults_keys(self):
        """IPATHINCA_DEFAULTS has all expected keys."""
        expected_keys = {
            "random_serial_numbers",
            "ca_signing_algorithm",
            "ca_signing_key_size",
            "ocsp_signing_algorithm",
            "ocsp_signing_key_size",
            "audit_signing_algorithm",
            "ecc_curve",
        }
        assert set(IPATHINCA_DEFAULTS.keys()) == expected_keys

    def test_default_signing_algorithm(self):
        """Default signing algorithm is SHA256withRSA."""
        assert IPATHINCA_DEFAULTS["ca_signing_algorithm"] == "SHA256withRSA"

    def test_default_key_size(self):
        """Default key size is 3072."""
        assert IPATHINCA_DEFAULTS["ca_signing_key_size"] == "3072"

    def test_default_random_serial_numbers(self):
        """Random serial numbers enabled by default."""
        assert IPATHINCA_DEFAULTS["random_serial_numbers"] is True

    def test_wsgi_defaults_sections(self):
        """WSGI_DEFAULTS has server, ssl, logging sections."""
        assert "server" in WSGI_DEFAULTS
        assert "ssl" in WSGI_DEFAULTS
        assert "logging" in WSGI_DEFAULTS

    def test_wsgi_default_workers(self):
        """Default workers is 1."""
        assert WSGI_DEFAULTS["server"]["workers"] == "1"


# ======================================================================
# IPAthinCAConfig construction
# ======================================================================


class TestConfigConstruction:
    """Test IPAthinCAConfig construction methods."""

    def test_empty_init(self):
        """Empty init sets defaults."""
        cfg = IPAthinCAConfig()
        assert cfg.realm is None
        assert cfg.host is None
        assert cfg.basedn is None
        assert cfg.domain is None

    def test_from_install_params_basic(self):
        """from_install_params sets core identity."""
        cfg = IPAthinCAConfig.from_install_params(
            realm="TEST.REALM",
            host="host.test.realm",
            basedn="dc=test,dc=realm",
        )
        assert cfg.realm == "TEST.REALM"
        assert cfg.host == "host.test.realm"
        assert str(cfg.basedn) == "dc=test,dc=realm"
        assert cfg.domain == "test.realm"

    def test_from_install_params_custom_algorithms(self):
        """from_install_params accepts custom signing algorithms."""
        cfg = IPAthinCAConfig.from_install_params(
            realm="TEST.REALM",
            host="host.test.realm",
            basedn="dc=test,dc=realm",
            ca_signing_algorithm="SHA384withRSA",
            ca_signing_key_size="4096",
        )
        assert cfg._ca_signing_algorithm == "SHA384withRSA"
        assert cfg._ca_signing_key_size == "4096"

    def test_from_install_params_none_keeps_defaults(self):
        """None params keep IPATHINCA_DEFAULTS values."""
        cfg = IPAthinCAConfig.from_install_params(
            realm="TEST.REALM",
            host="host.test.realm",
            basedn="dc=test,dc=realm",
        )
        assert (
            cfg._ca_signing_algorithm
            == IPATHINCA_DEFAULTS["ca_signing_algorithm"]
        )
        assert cfg._ecc_curve == IPATHINCA_DEFAULTS["ecc_curve"]


# ======================================================================
# File I/O
# ======================================================================


class TestConfigFileIO:
    """Test from_file and write_to_file."""

    def test_from_file_missing_strict(self):
        """from_file with strict=True raises on missing file."""
        with pytest.raises(FileNotFoundError):
            IPAthinCAConfig.from_file(
                "/nonexistent/ipathinca.conf", strict=True
            )

    def test_from_file_missing_nonstrict(self):
        """from_file with strict=False returns config with defaults."""
        cfg = IPAthinCAConfig.from_file(
            "/nonexistent/ipathinca.conf", strict=False
        )
        assert cfg.realm is None
        assert cfg.has_section("server") is False

    def test_from_file_with_defaults(self):
        """from_file applies defaults before reading file."""
        cfg = IPAthinCAConfig.from_file(
            "/nonexistent/ipathinca.conf",
            strict=False,
            defaults={"server": {"workers": "4", "port": "8080"}},
        )
        assert cfg.get("server", "workers") == "4"
        assert cfg.get("server", "port") == "8080"

    def test_from_file_reads_existing(self):
        """from_file reads an existing config file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("[global]\nrealm = MY.REALM\ndomain = my.realm\n")
            f.write("basedn = dc=my,dc=realm\nhost = h.my.realm\n")
            f.write("[ca]\n")
            tmpfile = f.name

        try:
            cfg = IPAthinCAConfig.from_file(tmpfile)
            assert cfg.realm == "MY.REALM"
            assert cfg.domain == "my.realm"
            assert cfg.get("global", "realm") == "MY.REALM"
        finally:
            os.unlink(tmpfile)


# ======================================================================
# Pass-through methods
# ======================================================================


class TestConfigPassThrough:
    """Test ConfigParser pass-through methods."""

    @pytest.fixture
    def cfg_with_data(self):
        """Create a config loaded from a temp file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("[global]\nrealm = TEST.REALM\n")
            f.write("domain = test.realm\n")
            f.write("basedn = dc=test,dc=realm\n")
            f.write("host = h.test.realm\n")
            f.write("[server]\nworkers = 2\nthreads = 8\n")
            f.write("enabled = true\n")
            tmpfile = f.name

        cfg = IPAthinCAConfig.from_file(tmpfile)
        os.unlink(tmpfile)
        return cfg

    def test_get(self, cfg_with_data):
        """get returns value from config."""
        assert cfg_with_data.get("global", "realm") == "TEST.REALM"

    def test_get_fallback(self, cfg_with_data):
        """get with fallback returns fallback for missing option."""
        assert cfg_with_data.get("global", "missing", fallback="x") == "x"

    def test_get_missing_raises(self, cfg_with_data):
        """get without fallback raises for missing option."""
        with pytest.raises(Exception):
            cfg_with_data.get("global", "missing_key")

    def test_get_without_config_raises(self):
        """get before loading raises RuntimeError."""
        cfg = IPAthinCAConfig()
        with pytest.raises(RuntimeError):
            cfg.get("global", "realm")

    def test_has_option(self, cfg_with_data):
        """has_option returns correct booleans."""
        assert cfg_with_data.has_option("global", "realm")
        assert not cfg_with_data.has_option("global", "nonexistent")

    def test_has_section(self, cfg_with_data):
        """has_section returns correct booleans."""
        assert cfg_with_data.has_section("global")
        assert not cfg_with_data.has_section("nonexistent")

    def test_getint(self, cfg_with_data):
        """getint parses integer values."""
        assert cfg_with_data.getint("server", "workers") == 2

    def test_getboolean(self, cfg_with_data):
        """getboolean parses boolean values."""
        assert cfg_with_data.getboolean("server", "enabled") is True

    def test_options(self, cfg_with_data):
        """options lists keys in a section."""
        opts = cfg_with_data.options("server")
        assert "workers" in opts
        assert "threads" in opts

    def test_has_option_no_config(self):
        """has_option returns False when no config loaded."""
        cfg = IPAthinCAConfig()
        assert not cfg.has_option("global", "realm")

    def test_has_section_no_config(self):
        """has_section returns False when no config loaded."""
        cfg = IPAthinCAConfig()
        assert not cfg.has_section("global")


# ======================================================================
# get_config_value from __init__.py
# ======================================================================


class TestGetConfigValue:
    """Test the module-level get_config_value function."""

    def test_get_existing_value(self, ipathinca_config):
        """get_config_value returns value from config."""
        from ipathinca import get_config_value

        realm = get_config_value("global", "realm")
        assert realm is not None

    def test_get_missing_with_default(self, ipathinca_config):
        """get_config_value returns default for missing option."""
        from ipathinca import get_config_value

        val = get_config_value("global", "nonexistent_key", default="fallback")
        assert val == "fallback"

    def test_get_missing_no_default_raises(self, ipathinca_config):
        """get_config_value raises when missing without default."""
        from ipathinca import get_config_value

        with pytest.raises(InvalidCAConfiguration):
            get_config_value("global", "nonexistent_key_xyz")
