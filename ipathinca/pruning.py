# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Certificate and Request Pruning for ipathinca

Manages automatic cleanup of old certificates and certificate requests from
LDAP, compatible with Dogtag's pruning job functionality.

LDAP Structure:
- ou=pruning,o=ipaca (base container)
- ou=config,ou=pruning,o=ipaca (configuration)
"""

import logging
from datetime import datetime, timedelta, timezone
from ipapython.dn import DN
from ipathinca.ldap_utils import get_ldap_connection

logger = logging.getLogger(__name__)

# Default pruning configuration (matches Dogtag defaults)
DEFAULT_CONFIG = {
    "certRetentionTime": "30",
    "certRetentionUnit": "day",
    "certSearchSizeLimit": "1000",
    "certSearchTimeLimit": "0",
    "requestRetentionTime": "30",
    "requestRetentionUnit": "day",
    "requestSearchSizeLimit": "1000",
    "requestSearchTimeLimit": "0",
    "cronSchedule": "",
    "enabled": "FALSE",  # Disabled by default
}


class PruningManager:
    """
    Manages certificate and request pruning configuration and execution

    Compatible with Dogtag's pruning job:
    - Deletes old certificates based on retention policy
    - Deletes old certificate requests based on retention policy
    - Configurable via LDAP
    """

    def __init__(self, config, storage_backend):
        """
        Initialize pruning manager

        Args:
            config: RawConfigParser from ipathinca.conf
            storage_backend: Storage backend for accessing certificates/
                             requests
        """
        self.config = config
        self.storage = storage_backend

        # LDAP structure
        self.pruning_base_dn = DN(("ou", "pruning"), ("o", "ipaca"))
        self.pruning_config_dn = DN(
            ("ou", "config"), ("ou", "pruning"), ("o", "ipaca")
        )

    def _ensure_pruning_structure(self, conn):
        """
        Ensure pruning LDAP structure exists

        Creates:
        - ou=pruning,o=ipaca
        - ou=config,ou=pruning,o=ipaca (with default configuration)
        """
        # Create pruning base container if needed
        try:
            conn.get_entry(self.pruning_base_dn)
            logger.debug(
                f"Pruning base container exists: {self.pruning_base_dn}"
            )
        except Exception:
            logger.info(
                f"Creating pruning base container: {self.pruning_base_dn}"
            )
            entry = conn.make_entry(
                self.pruning_base_dn,
                objectClass=["top", "organizationalUnit"],
                ou=["pruning"],
            )
            conn.add_entry(entry)

        # Create pruning config container if needed
        try:
            conn.get_entry(self.pruning_config_dn)
            logger.debug(
                f"Pruning config container exists: {self.pruning_config_dn}"
            )
        except Exception:
            logger.info(
                f"Creating pruning config container: {self.pruning_config_dn}"
            )
            # Create with default configuration
            entry = conn.make_entry(
                self.pruning_config_dn,
                objectClass=["top", "organizationalUnit", "extensibleObject"],
                ou=["config"],
                **{k: [v] for k, v in DEFAULT_CONFIG.items()},
            )
            conn.add_entry(entry)

    def get_config(self):
        """
        Get pruning configuration from LDAP

        Returns:
            dict: Pruning configuration with all settings
        """
        try:
            with get_ldap_connection() as conn:
                # Ensure structure exists
                self._ensure_pruning_structure(conn)

                # Get config entry
                entry = conn.get_entry(self.pruning_config_dn)

                # Build configuration dict
                config = {}
                for key in DEFAULT_CONFIG.keys():
                    if key in entry:
                        config[key] = entry.single_value.get(key)
                    else:
                        config[key] = DEFAULT_CONFIG[key]

                return config

        except Exception as e:
            logger.error(f"Failed to get pruning configuration: {e}")
            # Return defaults on error
            return DEFAULT_CONFIG.copy()

    def update_config(self, updates):
        """
        Update pruning configuration in LDAP

        Args:
            updates: dict of configuration values to update
        """
        try:
            with get_ldap_connection() as conn:
                # Ensure structure exists
                self._ensure_pruning_structure(conn)

                # Get config entry
                entry = conn.get_entry(self.pruning_config_dn)

                # Track if any changes were made
                changes_made = False

                # Update attributes only if they differ
                for key, value in updates.items():
                    if key in DEFAULT_CONFIG:
                        new_value = str(value)
                        current_value = entry.single_value.get(key, "")

                        # Only update if value is different
                        if current_value != new_value:
                            entry[key] = [new_value]
                            changes_made = True

                # Only update LDAP if changes were made
                if changes_made:
                    conn.update_entry(entry)
                    logger.info(f"Updated pruning configuration: {updates}")
                else:
                    logger.info(
                        "Pruning configuration already up to date, no changes "
                        "needed"
                    )

        except Exception as e:
            logger.error(f"Failed to update pruning configuration: {e}")
            raise

    def is_enabled(self):
        """
        Check if pruning is enabled

        Returns:
            bool: True if enabled, False if disabled
        """
        config = self.get_config()
        return config.get("enabled", "FALSE").upper() == "TRUE"

    def set_enabled(self, enabled):
        """
        Enable or disable pruning

        Args:
            enabled: bool - True to enable, False to disable
        """
        self.update_config({"enabled": "TRUE" if enabled else "FALSE"})

    def _parse_retention_time(self, retention_time, retention_unit):
        """
        Parse retention time into timedelta

        Args:
            retention_time: str - retention time value (e.g., "30")
            retention_unit: str - retention unit (minute, hour, day, year)

        Returns:
            timedelta: Retention period
        """
        value = int(retention_time)

        if retention_unit == "minute":
            return timedelta(minutes=value)
        elif retention_unit == "hour":
            return timedelta(hours=value)
        elif retention_unit == "day":
            return timedelta(days=value)
        elif retention_unit == "year":
            return timedelta(days=value * 365)
        else:
            logger.warning(
                f"Unknown retention unit: {retention_unit}, defaulting to days"
            )
            return timedelta(days=value)

    def run_pruning(self):
        """
        Execute pruning job - delete old certificates and requests

        Returns:
            dict: Results with counts of deleted certificates and requests
        """
        if not self.is_enabled():
            raise ValueError("Pruning is not enabled")

        config = self.get_config()

        # Parse retention times
        cert_retention = self._parse_retention_time(
            config["certRetentionTime"], config["certRetentionUnit"]
        )
        request_retention = self._parse_retention_time(
            config["requestRetentionTime"], config["requestRetentionUnit"]
        )

        # Calculate cutoff dates
        now = datetime.now(timezone.utc)
        cert_cutoff = now - cert_retention
        request_cutoff = now - request_retention

        logger.info(
            f"Running pruning job: cert_cutoff={cert_cutoff}, "
            f"request_cutoff={request_cutoff}"
        )

        results = {
            "certificates_deleted": 0,
            "requests_deleted": 0,
            "errors": [],
        }

        # Prune certificates
        try:
            if hasattr(self.storage, "delete_old_certificates"):
                cert_count = self.storage.delete_old_certificates(
                    cutoff_date=cert_cutoff,
                    size_limit=int(config["certSearchSizeLimit"]),
                    time_limit=int(config["certSearchTimeLimit"]),
                )
                results["certificates_deleted"] = cert_count
                logger.info(f"Deleted {cert_count} old certificates")
            else:
                logger.warning(
                    "Storage backend does not support certificate pruning"
                )
        except Exception as e:
            logger.error(f"Error pruning certificates: {e}", exc_info=True)
            results["errors"].append(f"Certificate pruning failed: {str(e)}")

        # Prune requests
        try:
            if hasattr(self.storage, "delete_old_requests"):
                request_count = self.storage.delete_old_requests(
                    cutoff_date=request_cutoff,
                    size_limit=int(config["requestSearchSizeLimit"]),
                    time_limit=int(config["requestSearchTimeLimit"]),
                )
                results["requests_deleted"] = request_count
                logger.info(f"Deleted {request_count} old requests")
            else:
                logger.warning(
                    "Storage backend does not support request pruning"
                )
        except Exception as e:
            logger.error(f"Error pruning requests: {e}", exc_info=True)
            results["errors"].append(f"Request pruning failed: {str(e)}")

        return results
