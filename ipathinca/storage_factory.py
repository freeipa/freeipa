# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Storage Backend Factory - Configuration Abstraction

This module provides a factory function that wraps CAStorageBackend creation
with automatic configuration file reading.

Why This Exists:
    - Centralized configuration parsing (DRY principle)
    - Backward compatibility with existing code
    - Simplified testing (can inject config objects)
    - Default handling when config file is missing

Historical Note:
    This was originally a true factory pattern that selected between multiple
    backend implementations ('ipathinca' vs 'dogtag'). The ipathinca backend
    was removed, leaving only CAStorageBackend. The factory is retained for
    configuration abstraction and backward compatibility.

Future Considerations:
    May be useful for selecting between CA and KRA backends:
        get_storage_backend(subsystem='ca')  → CAStorageBackend
        get_storage_backend(subsystem='kra') → KRAStorageBackend
"""

import logging
from configparser import RawConfigParser
from pathlib import Path
from typing import Optional

from ipaplatform.paths import paths

logger = logging.getLogger(__name__)


def get_storage_backend(
    ca_id: str = "ipa",
    random_serial_numbers: Optional[bool] = None,
    config_path: Optional[str] = None,
    config: Optional[RawConfigParser] = None,
):
    """
    Create CAStorageBackend with automatic configuration loading

    This is the main entry point for creating storage backends. It handles
    configuration file parsing and provides sensible defaults.

    Args:
        ca_id: CA identifier for sub-CA support (default: "ipa")
        random_serial_numbers: Use RSNv3 random serial numbers
            - None: Read from config file (default behavior)
            - True/False: Override config file setting
        config_path: Path to configuration file
            (default: /etc/ipa/ipathinca.conf)
            Ignored if `config` parameter is provided
        config: RawConfigParser object for testing
            If provided, reads from this instead of file

    Returns:
        CAStorageBackend instance configured per settings

    Configuration File Format (/etc/ipa/ipathinca.conf):
        [ca]
        random_serial_numbers = true   # or 'false'

    Examples:
        # Read from default config file
        backend = get_storage_backend()

        # Override random serial numbers
        backend = get_storage_backend(random_serial_numbers=True)

        # Use specific config file
        backend = get_storage_backend(config_path="/custom/path/config.ini")

        # Testing: inject config object
        mock_config = RawConfigParser()
        mock_config['ca'] = {'random_serial_numbers': 'true'}
        backend = get_storage_backend(config=mock_config)
    """
    # Determine if we need to read random_serial_numbers from config
    if random_serial_numbers is None:
        random_serial_numbers = _get_config_value(
            config=config,
            config_path=config_path,
            section="ca",
            option="random_serial_numbers",
            default=False,
            value_type="boolean",
        )

    # Read serial_number_bits from config (default: 128, matching Dogtag RSNv3)
    serial_number_bits = _get_config_value(
        config=config,
        config_path=config_path,
        section="ca",
        option="serial_number_bits",
        default=128,
        value_type="int",
    )

    # Read collision_recovery_attempts from config (default: 100)
    collision_recovery_attempts = _get_config_value(
        config=config,
        config_path=config_path,
        section="ca",
        option="collision_recovery_attempts",
        default=100,
        value_type="int",
    )

    logger.debug(
        "Creating CA storage backend: ca_id=%s, random_serial_numbers=%s, "
        "serial_number_bits=%s, collision_recovery_attempts=%s",
        ca_id,
        random_serial_numbers,
        serial_number_bits,
        collision_recovery_attempts,
    )

    # Late import to avoid circular dependency
    # (storage_ca imports from storage_factory)
    from ipathinca.storage_ca import CAStorageBackend

    return CAStorageBackend(
        ca_id=ca_id,
        random_serial_numbers=random_serial_numbers,
        serial_number_bits=serial_number_bits,
        collision_recovery_attempts=collision_recovery_attempts,
    )


def _get_config_value(
    config: Optional[RawConfigParser],
    config_path: Optional[str],
    section: str,
    option: str,
    default,
    value_type: str = "string",
):
    """
    Read a configuration value from config object or file

    Args:
        config: RawConfigParser object (takes precedence)
        config_path: Path to config file (used if config is None)
        section: Config section name
        option: Config option name
        default: Default value if not found
        value_type: Type of value ('string', 'boolean', 'int')

    Returns:
        Configuration value or default
    """
    # Use provided config object
    if config is not None:
        return _read_from_config_object(
            config, section, option, default, value_type
        )

    # Load config from file
    if config_path is None:
        config_path = paths.IPATHINCA_CONF

    if not Path(config_path).exists():
        logger.debug(
            "Config file not found: %s. Using default: %s",
            config_path,
            default,
        )
        return default

    try:
        from ipathinca.config import IPAthinCAConfig

        cfg = IPAthinCAConfig.from_file(config_path)
        return _read_from_config_object(
            cfg, section, option, default, value_type
        )
    except Exception as e:
        logger.warning(
            "Error reading config file %s: %s. Using default: %s",
            config_path,
            e,
            default,
        )
        return default


def _read_from_config_object(
    config: RawConfigParser,
    section: str,
    option: str,
    default,
    value_type: str,
):
    """Read value from RawConfigParser object"""
    if not config.has_section(section) or not config.has_option(
        section, option
    ):
        return default

    try:
        if value_type == "boolean":
            value = config.getboolean(section, option)
        elif value_type == "int":
            value = config.getint(section, option)
        else:
            value = config.get(section, option)

        logger.debug("Config: [%s] %s = %s", section, option, value)
        return value
    except Exception as e:
        logger.warning(
            "Error parsing config option [%s] %s: %s", section, option, e
        )
        return default


def _read_config(config_path: str) -> dict:
    """
    Read configuration from file (backward compatibility for tests)

    Args:
        config_path: Path to configuration file

    Returns:
        Dictionary with configuration values

    Note:
        This function is kept for backward compatibility with existing tests.
        New code should use get_storage_backend() which handles config
        internally.
    """
    default_config = {
        "random_serial_numbers": False,
    }

    if not Path(config_path).exists():
        logger.debug("Config file not found: %s. Using defaults.", config_path)
        return default_config

    try:
        from ipathinca import load_config

        config = load_config(config_path)

        result = {}
        if config.has_section("ca"):
            if config.has_option("ca", "random_serial_numbers"):
                result["random_serial_numbers"] = config.getboolean(
                    "ca", "random_serial_numbers"
                )

        return {**default_config, **result}

    except Exception as e:
        logger.warning(
            "Error reading configuration file %s: %s. Using defaults.",
            config_path,
            e,
        )
        return default_config


def create_default_config(
    config_path: Optional[str] = None,
    random_serial_numbers: bool = False,
):
    """
    Create a default ipathinca configuration file

    Args:
        config_path: Path to configuration file
            (default: /etc/ipa/ipathinca.conf)
        random_serial_numbers: Enable RSNv3 random serial numbers

    Raises:
        Exception: If file cannot be created

    Note:
        This is typically called by installation scripts (ipa-server-install)
    """
    if config_path is None:
        config_path = paths.IPATHINCA_CONF

    cfg = RawConfigParser()
    cfg["ca"] = {
        "random_serial_numbers": "true" if random_serial_numbers else "false",
    }

    try:
        # Create parent directory if needed
        config_dir = Path(config_path).parent
        config_dir.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w") as f:
            f.write("# IPA Thin CA Configuration\n")
            f.write("# Generated automatically by ipa-server-install\n\n")
            cfg.write(f)

        logger.info("Created configuration file: %s", config_path)
    except Exception as e:
        logger.error(
            "Failed to create configuration file %s: %s", config_path, e
        )
        raise


# Backward compatibility aliases (used by tests)
def get_ldap_storage_backend(
    ca_id: str = "ipa", random_serial_numbers: bool = False
):
    """
    Backward compatibility alias for get_storage_backend()

    Deprecated: Use get_storage_backend() instead
    """
    return get_storage_backend(
        ca_id=ca_id,
        random_serial_numbers=random_serial_numbers,
    )


def get_dogtag_storage_backend(
    ca_id: str = "ipa", random_serial_numbers: bool = False
):
    """
    Backward compatibility alias for get_storage_backend()

    Deprecated: Use get_storage_backend() instead
    """
    return get_storage_backend(
        ca_id=ca_id,
        random_serial_numbers=random_serial_numbers,
    )
