# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Storage module extracted from storage_ca.py for modularity
"""

from __future__ import absolute_import

import logging
from typing import Dict, Any, Optional
import json

from ipathinca.storage_base import BaseStorageBackend
from ipalib import errors
from ipapython.dn import DN
from ipathinca.ldap_utils import get_ldap_connection

logger = logging.getLogger(__name__)


class HSMStorage(BaseStorageBackend):
    """Storage operations"""

    def store_hsm_config(self, ca_id: str, config: Dict[str, Any]):
        """
        Store HSM configuration in LDAP

        Stores HSM config in ipaCaHSMConfiguration attribute following
        Dogtag's pattern. Format: "token_name;library_path"

        Args:
            ca_id: CA identifier
            config: Dictionary with HSM configuration
                   Required keys: enabled, token_name, pkcs11_library
                   Optional keys: slot_label, token_pin
        """
        with get_ldap_connection() as conn:
            ca_dn = DN(
                ("cn", ca_id), ("cn", "cas"), ("cn", "ca"), self.base_dn
            )

            try:
                # Get existing entry
                entry = conn.get_entry(ca_dn)

                # Build HSM configuration string (Dogtag format)
                # Format: "token_name;library_path"
                token_name = config.get("token_name", "")
                library_path = config.get("pkcs11_library", "")
                hsm_config_str = f"{token_name};{library_path}"

                # Update entry
                entry["ipaCaHSMConfiguration"] = [hsm_config_str]

                # Store other HSM parameters as JSON in description
                # (for slot_label, token_pin, enabled flag)
                hsm_metadata = {
                    "enabled": config.get("enabled", False),
                    "slot_label": config.get("slot_label"),
                    "token_pin": config.get("token_pin"),
                }
                if "ipaCaHSMMetadata" in entry:
                    entry["ipaCaHSMMetadata"] = [
                        json.dumps(hsm_metadata).encode("utf-8")
                    ]
                else:
                    entry.setdefault("ipaCaHSMMetadata", []).append(
                        json.dumps(hsm_metadata).encode("utf-8")
                    )

                conn.update_entry(entry)

                logger.debug(
                    "Stored HSM config for CA %s: %s", ca_id, hsm_config_str
                )

            except errors.NotFound:
                logger.warning(
                    "CA entry not found for %s, cannot store HSM config", ca_id
                )
                raise

    def get_hsm_config(self, ca_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve HSM configuration from LDAP

        Reads ipaCaHSMConfiguration attribute following Dogtag's pattern.

        Args:
            ca_id: CA identifier

        Returns:
            Dictionary with HSM configuration or None if not configured
        """
        with get_ldap_connection() as conn:
            ca_dn = DN(
                ("cn", ca_id), ("cn", "cas"), ("cn", "ca"), self.base_dn
            )

            try:
                entry = conn.get_entry(
                    ca_dn, ["ipaCaHSMConfiguration", "ipaCaHSMMetadata"]
                )

                # Check if HSM config exists
                if "ipaCaHSMConfiguration" not in entry:
                    return None

                # Parse HSM configuration string
                # (Dogtag format: "token_name;library_path")
                hsm_config_str = entry.single_value.get(
                    "ipaCaHSMConfiguration"
                )
                if not hsm_config_str:
                    return None

                # Handle both bytes and str
                if isinstance(hsm_config_str, bytes):
                    hsm_config_str = hsm_config_str.decode("utf-8")

                # Parse token_name and library_path
                parts = hsm_config_str.split(";", 1)
                if len(parts) != 2:
                    logger.warning(
                        "Invalid HSM config format for CA %s: %s",
                        ca_id,
                        hsm_config_str,
                    )
                    return None

                token_name, library_path = parts

                if not token_name or not library_path:
                    logger.warning(
                        "HSM config for CA %s has empty token_name or "
                        "library_path: '%s'",
                        ca_id,
                        hsm_config_str,
                    )
                    return None

                # Build config dictionary
                config = {
                    "token_name": token_name,
                    "pkcs11_library": library_path,
                    "enabled": True,  # Default if metadata missing
                }

                # Read metadata if available
                if "ipaCaHSMMetadata" in entry:
                    metadata_bytes = entry.single_value.get("ipaCaHSMMetadata")
                    if metadata_bytes:
                        try:
                            if isinstance(metadata_bytes, bytes):
                                metadata_str = metadata_bytes.decode("utf-8")
                            else:
                                metadata_str = metadata_bytes
                            metadata = json.loads(metadata_str)
                            config.update(metadata)
                        except (json.JSONDecodeError, UnicodeDecodeError) as e:
                            logger.warning(
                                "Could not parse HSM metadata for CA: %s", e
                            )

                logger.debug("Retrieved HSM config for CA %s", ca_id)
                return config

            except errors.NotFound:
                logger.debug("CA entry not found for %s", ca_id)
                return None

    def delete_hsm_config(self, ca_id: str):
        """
        Delete HSM configuration from LDAP

        Args:
            ca_id: CA identifier
        """
        with get_ldap_connection() as conn:
            ca_dn = DN(
                ("cn", ca_id), ("cn", "cas"), ("cn", "ca"), self.base_dn
            )

            try:
                entry = conn.get_entry(ca_dn)

                # Remove HSM configuration attributes
                if "ipaCaHSMConfiguration" in entry:
                    del entry["ipaCaHSMConfiguration"]
                if "ipaCaHSMMetadata" in entry:
                    del entry["ipaCaHSMMetadata"]

                conn.update_entry(entry)

                logger.debug("Deleted HSM config for CA %s", ca_id)

            except errors.NotFound:
                logger.debug("CA entry not found for %s", ca_id)
