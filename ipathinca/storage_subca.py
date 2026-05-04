# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Storage module extracted from storage_ca.py for modularity
"""

from __future__ import absolute_import

import logging
from typing import Dict, Any, List

from ipathinca.storage_base import BaseStorageBackend
from ipalib import errors
from ipapython.dn import DN

logger = logging.getLogger(__name__)


class SubCAStorage(BaseStorageBackend):
    """Storage operations"""

    def store_authority(self, authority_data: Dict[str, Any]):
        """
        Store lightweight sub-CA authority

        Args:
            authority_data: Dictionary with authority information
                - authority_id: UUID string
                - subject_dn: Subject DN string
                - key_nickname: NSS key nickname
                - enabled: Boolean (default: True)
                - parent_id: Parent authority ID (optional)
                - parent_dn: Parent authority DN (optional)
                - serial_number: Authority cert serial (optional)
                - description: Description (optional)
                - key_hosts: List of key hosts (optional)
        """
        with self._get_ldap_connection() as ldap:

            auth_id = authority_data["authority_id"]
            auth_dn = DN(
                ("cn", auth_id), DN(("ou", "authorities"), self.ca_base_dn)
            )

            entry_attrs = {
                "objectClass": ["top", "authority"],
                "cn": [auth_id],
                "authorityID": [auth_id],
                "authorityDN": [authority_data["subject_dn"]],
                "authorityKeyNickname": [authority_data["key_nickname"]],
                "authorityEnabled": [
                    "TRUE" if authority_data.get("enabled", True) else "FALSE"
                ],
            }

            if "parent_id" in authority_data and authority_data["parent_id"]:
                entry_attrs["authorityParentID"] = [
                    authority_data["parent_id"]
                ]

            if "parent_dn" in authority_data and authority_data["parent_dn"]:
                entry_attrs["authorityParentDN"] = [
                    authority_data["parent_dn"]
                ]

            if (
                "serial_number" in authority_data
                and authority_data["serial_number"]
            ):
                entry_attrs["authoritySerial"] = [
                    str(authority_data["serial_number"])
                ]

            if (
                "description" in authority_data
                and authority_data["description"]
            ):
                entry_attrs["description"] = [authority_data["description"]]

            if "key_hosts" in authority_data and authority_data["key_hosts"]:
                entry_attrs["authorityKeyHost"] = authority_data["key_hosts"]

            try:
                # Check if authority already exists
                existing_entry = ldap.get_entry(auth_dn)

                # Update existing authority
                logger.debug("Updating authority %s", auth_id)
                for key, value in entry_attrs.items():
                    if key not in ["objectClass", "cn"]:
                        existing_entry[key] = value

                ldap.update_entry(existing_entry)
                logger.debug("Updated authority %s", auth_id)

            except errors.NotFound:
                # Create new authority
                logger.debug("Creating authority %s", auth_id)
                entry = ldap.make_entry(auth_dn, **entry_attrs)
                ldap.add_entry(entry)
                logger.debug("Created authority %s", auth_id)

    def get_authority(self, authority_id: str) -> Any:
        """
        Retrieve authority by ID

        Args:
            authority_id: Authority UUID

        Returns:
            Dictionary with authority data or None
        """
        with self._get_ldap_connection() as ldap:
            auth_dn = DN(
                ("cn", authority_id),
                DN(("ou", "authorities"), self.ca_base_dn),
            )

            try:
                entry = ldap.get_entry(auth_dn)

                auth_id = entry["authorityID"][0]
                if isinstance(auth_id, bytes):
                    auth_id = auth_id.decode("utf-8")

                subject_dn = entry["authorityDN"][0]
                if isinstance(subject_dn, bytes):
                    subject_dn = subject_dn.decode("utf-8")

                key_nickname = entry["authorityKeyNickname"][0]
                if isinstance(key_nickname, bytes):
                    key_nickname = key_nickname.decode("utf-8")

                enabled = entry["authorityEnabled"][0]
                if isinstance(enabled, bytes):
                    enabled = enabled.decode("utf-8")

                # Handle enabled field - can be boolean, string
                # "TRUE"/"FALSE", or True/False
                if isinstance(enabled, bool):
                    enabled_bool = enabled
                elif isinstance(enabled, str):
                    enabled_bool = enabled.upper() == "TRUE"
                else:
                    # Fallback: assume True if not explicitly False
                    enabled_bool = bool(enabled)

                result = {
                    "authority_id": auth_id,
                    "subject_dn": subject_dn,
                    "key_nickname": key_nickname,
                    "enabled": enabled_bool,
                }

                # Optional attributes
                if "authorityParentID" in entry:
                    parent_id = entry["authorityParentID"][0]
                    if isinstance(parent_id, bytes):
                        parent_id = parent_id.decode("utf-8")
                    result["parent_id"] = parent_id

                if "authorityParentDN" in entry:
                    parent_dn = entry["authorityParentDN"][0]
                    if isinstance(parent_dn, bytes):
                        parent_dn = parent_dn.decode("utf-8")
                    result["parent_dn"] = parent_dn

                if "authoritySerial" in entry:
                    serial = entry["authoritySerial"][0]
                    if isinstance(serial, bytes):
                        serial = serial.decode("utf-8")
                    result["serial_number"] = int(serial)

                if "description" in entry:
                    desc = entry["description"][0]
                    if isinstance(desc, bytes):
                        desc = desc.decode("utf-8")
                    result["description"] = desc

                if "authorityKeyHost" in entry:
                    result["key_hosts"] = [
                        h.decode("utf-8") if isinstance(h, bytes) else h
                        for h in entry["authorityKeyHost"]
                    ]

                return result

            except errors.NotFound:
                logger.debug("Authority %s not found", authority_id)
                return None

    def list_authorities(self) -> List[Dict[str, Any]]:
        """
        List all authorities

        Returns:
            List of authority dictionaries
        """
        with self._get_ldap_connection() as ldap:
            authorities_dn = DN(("ou", "authorities"), self.ca_base_dn)

            try:
                # OPTIMIZED: Only fetch attributes needed for authority listing
                entries = ldap.get_entries(
                    authorities_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=authority)",
                    attrs_list=[
                        "authorityID",
                        "authorityDN",
                        "authorityEnabled",
                        "description",
                    ],
                )

                results = []
                for entry in entries:
                    auth_id = entry["authorityID"][0]
                    if isinstance(auth_id, bytes):
                        auth_id = auth_id.decode("utf-8")

                    subject_dn = entry["authorityDN"][0]
                    if isinstance(subject_dn, bytes):
                        subject_dn = subject_dn.decode("utf-8")

                    enabled = entry["authorityEnabled"][0]
                    if isinstance(enabled, bytes):
                        enabled = enabled.decode("utf-8")

                    auth_data = {
                        "authority_id": auth_id,
                        "subject_dn": subject_dn,
                        "enabled": enabled.upper() == "TRUE",
                    }

                    # Add optional description if present
                    if "description" in entry:
                        desc = entry["description"][0]
                        if isinstance(desc, bytes):
                            desc = desc.decode("utf-8")
                        auth_data["description"] = desc

                    results.append(auth_data)

                return results

            except errors.NotFound:
                return []

    def update_authority_status(self, authority_id: str, enabled: bool):
        """
        Update the enabled/disabled status of a sub-CA

        Args:
            authority_id: Authority UUID
            enabled: True to enable, False to disable
        """
        if enabled:
            self.enable_authority(authority_id)
        else:
            self.disable_authority(authority_id)

    def enable_authority(self, authority_id: str):
        """
        Enable a sub-CA

        Args:
            authority_id: Authority UUID
        """
        with self._get_ldap_connection() as ldap:
            auth_dn = DN(
                ("cn", authority_id),
                DN(("ou", "authorities"), self.ca_base_dn),
            )

            entry = ldap.get_entry(auth_dn)
            entry["authorityEnabled"] = ["TRUE"]
            ldap.update_entry(entry)
            logger.info("Enabled authority %s", authority_id)

    def disable_authority(self, authority_id: str):
        """
        Disable a sub-CA

        Args:
            authority_id: Authority UUID
        """
        with self._get_ldap_connection() as ldap:
            auth_dn = DN(
                ("cn", authority_id),
                DN(("ou", "authorities"), self.ca_base_dn),
            )

            entry = ldap.get_entry(auth_dn)
            entry["authorityEnabled"] = ["FALSE"]
            ldap.update_entry(entry)
            logger.info("Disabled authority %s", authority_id)

    def delete_authority(self, authority_id: str):
        """
        Delete a sub-CA

        Args:
            authority_id: Authority UUID
        """
        with self._get_ldap_connection() as ldap:
            auth_dn = DN(
                ("cn", authority_id),
                DN(("ou", "authorities"), self.ca_base_dn),
            )

            ldap.delete_entry(auth_dn)
            logger.info("Deleted authority %s", authority_id)
