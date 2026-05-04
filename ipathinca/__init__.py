# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Python-cryptography based Certificate Authority replacement for FreeIPA

This package provides a pure Python implementation of Certificate Authority
functionality using python-cryptography, replacing the need for Dogtag PKI.
"""

import logging
import threading

from ipathinca.exceptions import (
    CANotInitialized,
    InvalidCAConfiguration,
)

logger = logging.getLogger(__name__)

# Global configuration singleton
# Set by backend.py during initialization, used by all ipathinca components
_global_config = None
_global_config_lock = threading.Lock()


def set_global_config(config):
    """
    Set the global ipathinca configuration

    This should be called once during backend initialization.

    Args:
        config: IPAthinCAConfig or RawConfigParser-compatible object
    """
    global _global_config
    with _global_config_lock:
        _global_config = config
    logger.debug("Global ipathinca config initialized")


def get_global_config():
    """
    Get the global ipathinca configuration

    Returns:
        IPAthinCAConfig or RawConfigParser-compatible object

    Raises:
        CANotInitialized: If config not initialized (fail-fast design)
    """
    with _global_config_lock:
        config = _global_config
    if config is None:
        raise CANotInitialized(
            "ipathinca global config not initialized. "
            "Backend must call set_global_config() during initialization."
        )
    return config


def get_config_value(section, option, default=None):
    """
    Get a value from the global config

    Args:
        section: Config section (e.g., "global", "ca")
        option: Config option (e.g., "realm", "basedn")
        default: Default value if option not found (None = raise exception)

    Returns:
        Config value as string

    Raises:
        Exception: If config not initialized or option not found (when
                   default=None)
    """
    config = get_global_config()

    if not config.has_option(section, option):
        if default is None:
            raise InvalidCAConfiguration(
                f"Config option [{section}] {option} not found in "
                "ipathinca.conf"
            )
        return default

    return config.get(section, option)


def load_config(config_file=None):
    """
    Load configuration from file

    Delegates to ``IPAthinCAConfig.from_file()`` so there is a single
    config-reading code path.

    Args:
        config_file: Path to config file (default: paths.IPATHINCA_CONF)

    Returns:
        IPAthinCAConfig instance (RawConfigParser-compatible)

    Raises:
        FileNotFoundError: If config file doesn't exist
        Exception: If config cannot be loaded
    """
    from ipathinca.config import IPAthinCAConfig

    return IPAthinCAConfig.from_file(config_file)
