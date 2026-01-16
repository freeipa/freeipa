# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
ACME State Management for ipathinca

Manages ACME enabled/disabled state in LDAP, compatible with Dogtag's
structure:
- baseDN: ou=acme,o=ipaca
- Config DN: ou=config,ou=acme,o=ipaca
- Attribute: acmeEnabled (TRUE/FALSE)
"""

import logging
from ipalib import errors
from ipapython.dn import DN
from ipathinca.ldap_utils import get_ldap_connection

logger = logging.getLogger(__name__)


class ACMEStateManager:
    """
    Manages ACME enabled/disabled state in LDAP

    Compatible with Dogtag's LDAP structure:
    - ou=acme,o=ipaca (ACME base container)
    - ou=config,ou=acme,o=ipaca (ACME configuration)
    - acmeEnabled: TRUE/FALSE attribute
    """

    def __init__(self, config):
        """
        Initialize ACME state manager

        Args:
            config: RawConfigParser from ipathinca.conf
        """
        self.config = config

        # LDAP structure (matches Dogtag)
        self.acme_base_dn = DN(("ou", "acme"), ("o", "ipaca"))
        self.acme_config_dn = DN(
            ("ou", "config"), ("ou", "acme"), ("o", "ipaca")
        )

    def _ensure_acme_structure(self, conn):
        """
        Ensure ACME LDAP structure exists

        Creates:
        - ou=acme,o=ipaca
        - ou=config,ou=acme,o=ipaca (with acmeEnabled attribute)
        """
        # Create ACME base container if needed
        try:
            conn.get_entry(self.acme_base_dn)
            logger.debug("ACME base container exists: %s", self.acme_base_dn)
        except errors.NotFound:
            logger.info("Creating ACME base container: %s", self.acme_base_dn)
            entry = conn.make_entry(
                self.acme_base_dn,
                objectClass=["top", "organizationalUnit"],
                ou=["acme"],
            )
            conn.add_entry(entry)

        # Create ACME config container if needed
        try:
            conn.get_entry(self.acme_config_dn)
            logger.debug(
                "ACME config container exists: %s", self.acme_config_dn
            )
        except errors.NotFound:
            logger.info(
                "Creating ACME config container: %s", self.acme_config_dn
            )
            entry = conn.make_entry(
                self.acme_config_dn,
                objectClass=["top", "organizationalUnit", "extensibleObject"],
                ou=["config"],
                acmeEnabled=[
                    "FALSE"
                ],  # Disabled by default (secure-by-default)
            )
            conn.add_entry(entry)

    def is_enabled(self):
        """
        Check if ACME is enabled

        Returns:
            bool: True if enabled, False if disabled
        """
        try:
            with get_ldap_connection() as conn:
                # Ensure structure exists (create with enabled=FALSE if
                # missing)
                self._ensure_acme_structure(conn)

                # Get config entry
                entry = conn.get_entry(self.acme_config_dn, ["acmeEnabled"])

                # Check acmeEnabled attribute
                if "acmeEnabled" in entry:
                    enabled_str = entry.single_value.get("acmeEnabled")
                    if enabled_str:
                        # Convert to string in case it's a boolean or other
                        # type
                        return str(enabled_str).upper() == "TRUE"

                # Default to disabled if attribute missing (secure-by-default)
                return False

        except Exception as e:
            logger.error("Failed to check ACME status: %s", e)
            # Default to disabled on error (fail-closed for security)
            return False

    def set_enabled(self, enabled):
        """
        Enable or disable ACME

        Args:
            enabled: bool - True to enable, False to disable
        """
        try:
            with get_ldap_connection() as conn:
                # Ensure structure exists
                self._ensure_acme_structure(conn)

                # Get current value
                entry = conn.get_entry(self.acme_config_dn)
                current_value = entry.single_value.get("acmeEnabled", "FALSE")
                desired_value = "TRUE" if enabled else "FALSE"

                # Convert current_value to string (in case it's a boolean or
                # other type)
                current_value_str = (
                    str(current_value)
                    if current_value is not None
                    else "FALSE"
                )

                # Only update if value is changing
                if current_value_str.upper() != desired_value.upper():
                    entry["acmeEnabled"] = [desired_value]
                    conn.update_entry(entry)
                    logger.info(
                        "ACME %s", "enabled" if enabled else "disabled"
                    )
                else:
                    logger.info(
                        "ACME already %s, no change needed",
                        "enabled" if enabled else "disabled",
                    )

        except Exception as e:
            logger.error(
                "Failed to %s ACME: %s", "enable" if enabled else "disable", e
            )
            raise
