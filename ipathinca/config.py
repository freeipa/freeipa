# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Unified IPAthinCA configuration class.

``IPAthinCAConfig`` is used at both install time and runtime:

- Install time: ``IPAthinCAConfig.from_install_params(...)`` stores
  resolved ipathinca-native values (signing algorithms, key sizes, …)
  and writes ``ipathinca.conf`` via ``write_to_file()``.

- Runtime: ``IPAthinCAConfig.from_file(config_file)`` reads an existing
  ``ipathinca.conf`` (replacing the old ``load_config()`` helper).

All PKI-specific knowledge (pki_* key names, PKI ini file paths,
immutability rules) lives in ``ipaserver/install/ipathincainstance.py``
and is kept out of this module deliberately.

Pass-through methods (``get``, ``has_option``, ``getboolean``, ``options``)
implement the same interface as ``RawConfigParser`` so that all existing
callers in ``backend.py``, ``ca.py``, ``subca.py``, ``rest_api.py``, etc.
work without change.
"""

from __future__ import absolute_import

import logging
import os
from configparser import RawConfigParser
from pathlib import Path

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.dn import DN

from ipathinca.exceptions import CAConfigurationError

logger = logging.getLogger(__name__)

# Sentinel used to distinguish "no fallback supplied" from fallback=None.
_UNSET = object()

# Canonical defaults for all ipathinca signing parameters.
# Used to initialise IPAthinCAConfig instances and as the fallback when
# a caller passes None for a particular parameter in from_install_params().
IPATHINCA_DEFAULTS = {
    "random_serial_numbers": True,
    "ca_signing_algorithm": "SHA256withRSA",
    "ca_signing_key_size": "3072",
    "ocsp_signing_algorithm": "SHA256withRSA",
    "ocsp_signing_key_size": "3072",
    "audit_signing_algorithm": "SHA256withRSA",
    "ecc_curve": "nistp256",
}

# Defaults for WSGI/server runtime configuration.
# These are applied before reading the config file so file values override.
WSGI_DEFAULTS = {
    "server": {
        "host": "0.0.0.0",
        "port": "8080",
        "ssl_port": "8443",
        "workers": "1",
        "threads": "4",
        "timeout": "120",
        "max_request_size": "10",
    },
    "ssl": {
        "enabled": "true",
        "cert_file": paths.IPA_CA_CRT,
        "key_file": paths.IPATHINCA_SIGNING_KEY,
        "ssl_version": "TLSv1_2",
        "ssl_ciphers": "HIGH:!aNULL:!MD5:!3DES",
    },
    "logging": {
        "level": "INFO",
        "log_file": f"{paths.IPATHINCA_LOG_DIR}/ipathinca.log",
        "max_log_size": "10485760",
        "backup_count": "10",
    },
}


class IPAthinCAConfig:
    """Unified configuration for IPAthinCA.

    Provides a single object used at both install time (via
    :meth:`from_install_params`) and runtime (via :meth:`from_file`).

    Install-time signing parameters use ipathinca names only — no
    ``pki_*`` key names appear in this class.  The
    :class:`configparser.RawConfigParser` interface (``get``,
    ``has_option``, ``getboolean``, ``options``) is forwarded to the
    underlying ``_config`` parser, so existing callers continue to work
    unchanged.
    """

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    def __init__(self):
        # Core identity (set by from_install_params or from_file)
        self._realm = None
        self._host = None
        self._basedn = None
        self._domain = None

        # Signing algorithm and key parameters — seeded from
        # IPATHINCA_DEFAULTS.
        self._random_serial_numbers = IPATHINCA_DEFAULTS[
            "random_serial_numbers"
        ]
        self._ca_signing_algorithm = IPATHINCA_DEFAULTS["ca_signing_algorithm"]
        self._ca_signing_key_size = IPATHINCA_DEFAULTS["ca_signing_key_size"]
        self._ocsp_signing_algorithm = IPATHINCA_DEFAULTS[
            "ocsp_signing_algorithm"
        ]
        self._ocsp_signing_key_size = IPATHINCA_DEFAULTS[
            "ocsp_signing_key_size"
        ]
        self._audit_signing_algorithm = IPATHINCA_DEFAULTS[
            "audit_signing_algorithm"
        ]
        self._ecc_curve = IPATHINCA_DEFAULTS["ecc_curve"]

        # Runtime RawConfigParser from ipathinca.conf
        # (set by from_file() or write_to_file())
        self._config = None

    # -----------------------------------------------------------------------
    # Classmethods
    # -----------------------------------------------------------------------

    @classmethod
    def from_install_params(
        cls,
        realm,
        host,
        basedn,
        random_serial_numbers=None,
        ca_signing_algorithm=None,
        ca_signing_key_size=None,
        ocsp_signing_algorithm=None,
        ocsp_signing_key_size=None,
        audit_signing_algorithm=None,
        ecc_curve=None,
    ):
        """Create config from resolved install-time parameters.

        All signing algorithm and key-size values are expressed in
        ipathinca terms (no ``pki_*`` names).  The caller is responsible
        for translating PKI config values before calling this method.

        Parameters left as ``None`` keep the value from
        :data:`IPATHINCA_DEFAULTS` (set during ``__init__``).

        ``write_to_file()`` must be called later to persist
        ``ipathinca.conf`` and populate the ``get()`` pass-through.

        Returns:
            IPAthinCAConfig with install-time attributes set.
        """
        cfg = cls()
        cfg._realm = realm
        cfg._host = host
        cfg._basedn = DN(basedn) if basedn is not None else None
        cfg._domain = realm.lower() if realm else None
        if random_serial_numbers is not None:
            cfg._random_serial_numbers = random_serial_numbers
        if ca_signing_algorithm is not None:
            cfg._ca_signing_algorithm = ca_signing_algorithm
        if ca_signing_key_size is not None:
            cfg._ca_signing_key_size = ca_signing_key_size
        if ocsp_signing_algorithm is not None:
            cfg._ocsp_signing_algorithm = ocsp_signing_algorithm
        if ocsp_signing_key_size is not None:
            cfg._ocsp_signing_key_size = ocsp_signing_key_size
        if audit_signing_algorithm is not None:
            cfg._audit_signing_algorithm = audit_signing_algorithm
        if ecc_curve is not None:
            cfg._ecc_curve = ecc_curve
        return cfg

    @classmethod
    def from_file(cls, config_file=None, strict=True, defaults=None):
        """Create config by reading an existing ``ipathinca.conf``.

        Args:
            config_file: Path to config file (default:
                                              ``paths.IPATHINCA_CONF``)
            strict: If True (default), raise FileNotFoundError when the
                    config file is missing.  If False, return a config
                    object populated only with *defaults*.
            defaults: Optional dict of ``{section: {key: value}}`` pairs
                      applied before reading the file, so file values
                      take precedence.

        Returns:
            IPAthinCAConfig with ``_config`` set.

        Raises:
            FileNotFoundError: If *strict* is True and the config file
                does not exist.
        """
        if config_file is None:
            config_file = paths.IPATHINCA_CONF

        cfg = cls()
        cfg._config = RawConfigParser()

        # Seed section defaults before reading so file values win.
        if defaults:
            for section, values in defaults.items():
                cfg._config[section] = values

        if not os.path.exists(config_file):
            if strict:
                raise FileNotFoundError(
                    f"Configuration file {config_file} not found. "
                    "IPA CA cannot operate without proper configuration."
                )
            logger.debug(
                "Config file %s not found, using defaults", config_file
            )
        else:
            try:
                cfg._config.read(config_file)
                logger.debug("Loaded configuration from %s", config_file)
            except Exception as e:
                if strict:
                    raise CAConfigurationError(
                        f"Failed to load configuration from "
                        f"{config_file}: {e}"
                    )
                logger.warning(
                    "Failed to load config file %s: %s", config_file, e
                )

        # Populate direct attributes from the parsed file so that properties
        # (realm, host, …) have a single code path regardless of whether the
        # object was created via from_file() or from_install_params().
        cfg._realm = cfg._config.get("global", "realm", fallback=None)
        cfg._host = cfg._config.get("global", "host", fallback=None)
        cfg._domain = cfg._config.get("global", "domain", fallback=None)
        _basedn = cfg._config.get("global", "basedn", fallback=None)
        cfg._basedn = DN(_basedn) if _basedn else None

        return cfg

    # -----------------------------------------------------------------------
    # Property accessors
    # -----------------------------------------------------------------------

    @property
    def realm(self):
        return self._realm

    @property
    def domain(self):
        return self._domain

    @property
    def host(self):
        return self._host

    @property
    def basedn(self):
        return self._basedn

    # -----------------------------------------------------------------------
    # ConfigParser pass-through
    # -----------------------------------------------------------------------

    def get(self, section, option, *, fallback=_UNSET):
        """Forward to the underlying RawConfigParser."""
        if self._config is None:
            raise RuntimeError(
                "ipathinca config not yet loaded from file. "
                "Call write_to_file() (install) or from_file() (runtime) "
                "first."
            )
        if fallback is not _UNSET:
            return self._config.get(section, option, fallback=fallback)
        return self._config.get(section, option)

    def has_option(self, section, option):
        """Forward to the underlying RawConfigParser."""
        if self._config is None:
            return False
        return self._config.has_option(section, option)

    def has_section(self, section):
        """Forward to the underlying RawConfigParser."""
        if self._config is None:
            return False
        return self._config.has_section(section)

    def getint(self, section, option, *, fallback=_UNSET):
        """Forward to the underlying RawConfigParser."""
        if self._config is None:
            if fallback is not _UNSET:
                return fallback
            raise RuntimeError("ipathinca config not yet loaded from file.")
        if fallback is not _UNSET:
            return self._config.getint(section, option, fallback=fallback)
        return self._config.getint(section, option)

    def getboolean(self, section, option, *, fallback=_UNSET):
        """Forward to the underlying RawConfigParser."""
        if self._config is None:
            if fallback is not _UNSET:
                return fallback
            raise RuntimeError("ipathinca config not yet loaded from file.")
        if fallback is not _UNSET:
            return self._config.getboolean(section, option, fallback=fallback)
        return self._config.getboolean(section, option)

    def options(self, section):
        """Forward to the underlying RawConfigParser."""
        if self._config is None:
            return []
        return self._config.options(section)

    # -----------------------------------------------------------------------
    # Write resolved config to ipathinca.conf (install-time)
    # -----------------------------------------------------------------------

    def write_to_file(self, config_file):
        """Write ``ipathinca.conf`` from the stored install-time parameters.

        Uses the signing algorithm and key-size values stored by
        ``from_install_params()``, substitutes them into the
        ``ipathinca.conf.template``, writes the result, then reads it
        back into ``_config`` so all pass-through methods become available.

        Args:
            config_file: ``pathlib.Path`` or string path for
                         ``ipathinca.conf``.

        Raises:
            RuntimeError: If called without a realm (i.e. the config was not
                created via ``from_install_params()``).
        """
        if self._realm is None:
            raise RuntimeError(
                "write_to_file() requires a config built via "
                "from_install_params() with a realm set."
            )

        config_file = Path(config_file)
        ipautil.copy_template_file(
            Path(paths.USR_SHARE_IPA_DIR) / "ipathinca.conf.template",
            config_file,
            dict(
                REALM=self._realm,
                DOMAIN=self._domain,
                FQDN=self._host,
                BASEDN=str(self._basedn),
                IPA_CA_CRT=paths.IPA_CA_CRT,
                RANDOM_SERIAL_NUMBERS=str(self._random_serial_numbers).lower(),
                IPATHINCA_PID=paths.IPATHINCA_PID,
                IPATHINCA_CERTS_DIR=paths.IPATHINCA_CERTS_DIR,
                IPATHINCA_PRIVATE_DIR=paths.IPATHINCA_PRIVATE_DIR,
                IPATHINCA_LOG_DIR=paths.IPATHINCA_LOG_DIR,
                # Signing algorithms
                CA_SIGNING_ALGORITHM=self._ca_signing_algorithm,
                DEFAULT_SIGNING_ALGORITHM=self._ca_signing_algorithm,
                CRL_SIGNING_ALGORITHM=self._ca_signing_algorithm,
                AUDIT_SIGNING_ALGORITHM=self._audit_signing_algorithm,
                OCSP_SIGNING_ALGORITHM=self._ocsp_signing_algorithm,
                # Key parameters
                DEFAULT_RSA_KEY_SIZE=self._ca_signing_key_size,
                DEFAULT_ECC_CURVE=self._ecc_curve,
                OCSP_SIGNING_KEY_SIZE=self._ocsp_signing_key_size,
            ),
        )
        config_file.chmod(0o644)

        # Read it back so pass-through methods work
        config = RawConfigParser()
        config.read(str(config_file))
        self._config = config
        logger.debug("Service configuration written to %s", config_file)
