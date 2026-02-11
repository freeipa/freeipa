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


class ProfileStorage(BaseStorageBackend):
    """Storage operations"""

    def store_profile(self, profile_data: Dict[str, Any]):
        """
        Store certificate profile configuration

        Supports both legacy Python profiles and Dogtag .cfg profiles.
        The .cfg content is stored in certProfileConfig attribute as binary
        data.

        Args:
            profile_data: Dictionary with profile information
                - profile_id: Profile identifier (e.g., "caIPAserviceCert")
                - class_id: Profile class identifier (e.g., "caEnrollImpl")
                - config: Profile configuration (raw text/binary)
                          For Dogtag profiles, this is the .cfg file content
                - description: Optional description
        """
        with self._get_ldap_connection() as ldap:

            profile_id = profile_data["profile_id"]
            profiles_container_dn = DN(
                ("ou", "certificateProfiles"), self.ca_base_dn
            )
            profile_dn = DN(("cn", profile_id), profiles_container_dn)

            entry_attrs = {
                "objectClass": ["top", "certProfile"],
                "cn": [profile_id],
            }

            if "class_id" in profile_data and profile_data["class_id"]:
                entry_attrs["classId"] = [profile_data["class_id"]]

            if "config" in profile_data and profile_data["config"]:
                # Store config as binary data
                config_data = profile_data["config"]
                if isinstance(config_data, str):
                    config_data = config_data.encode("utf-8")
                entry_attrs["certProfileConfig"] = [config_data]

            # NOTE: certProfile objectClass does not support 'description'
            # attribute. Description is embedded in the .cfg file itself.

            try:
                # Check if profile already exists
                existing_entry = ldap.get_entry(profile_dn)

                # Update existing profile
                logger.debug(f"Updating profile {profile_id}")
                for key, value in entry_attrs.items():
                    if key != "objectClass" and key != "cn":
                        existing_entry[key] = value

                ldap.update_entry(existing_entry)
                logger.debug(f"Updated profile {profile_id}")

            except errors.NotFound:
                # Create new profile
                logger.debug(f"Creating profile {profile_id}")
                entry = ldap.make_entry(profile_dn, **entry_attrs)
                ldap.add_entry(entry)
                logger.debug(f"Created profile {profile_id}")

    def get_profile(self, profile_id: str) -> Any:
        """
        Retrieve certificate profile configuration

        Returns both legacy Python profile data and Dogtag .cfg content
        if available. The caller can parse the .cfg content using
        ProfileParser.

        Args:
            profile_id: Profile identifier (e.g., "caIPAserviceCert")

        Returns:
            Dictionary with profile info or None
            - profile_id: str
            - class_id: str
            - config: bytes (raw .cfg content for Dogtag profiles)
            - description: str
        """
        with self._get_ldap_connection() as ldap:
            profiles_container_dn = DN(
                ("ou", "certificateProfiles"), self.ca_base_dn
            )
            profile_dn = DN(("cn", profile_id), profiles_container_dn)

            try:
                entry = ldap.get_entry(profile_dn)

                # Profile config is stored as raw binary/text
                profile_config = entry.get("certProfileConfig", [None])[0]
                if profile_config and isinstance(profile_config, bytes):
                    profile_config = profile_config.decode("utf-8")

                class_id = entry.get("classId", [None])[0]
                if class_id and isinstance(class_id, bytes):
                    class_id = class_id.decode("utf-8")

                result = {
                    "profile_id": profile_id,
                    "class_id": class_id,
                    "config": profile_config,
                }

                # Optional description
                if "description" in entry:
                    desc = entry["description"][0]
                    if isinstance(desc, bytes):
                        desc = desc.decode("utf-8")
                    result["description"] = desc

                return result

            except errors.NotFound:
                logger.debug(f"Profile {profile_id} not found")
                return None

    def delete_profile(self, profile_id: str):
        """
        Delete a certificate profile

        Args:
            profile_id: Profile identifier
        """
        with self._get_ldap_connection() as ldap:
            profiles_container_dn = DN(
                ("ou", "certificateProfiles"), self.ca_base_dn
            )
            profile_dn = DN(("cn", profile_id), profiles_container_dn)

            ldap.delete_entry(profile_dn)
            logger.info(f"Deleted profile {profile_id}")

    def list_profiles(self) -> List[str]:
        """
        List all available certificate profiles

        Returns:
            List of profile IDs
        """
        with self._get_ldap_connection() as ldap:
            profiles_dn = DN(("ou", "certificateProfiles"), self.ca_base_dn)

            try:
                # OPTIMIZED: Only fetch cn attribute for listing profile IDs
                entries = ldap.get_entries(
                    profiles_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=certProfile)",
                    attrs_list=["cn"],  # Only need the profile ID
                )

                results = []
                for entry in entries:
                    profile_id = entry["cn"][0]
                    if isinstance(profile_id, bytes):
                        profile_id = profile_id.decode("utf-8")
                    results.append(profile_id)

                return results

            except errors.NotFound:
                return []

    def get_profile_cfg(self, profile_id: str) -> str:
        """Get raw .cfg file content from LDAP

        Args:
            profile_id: Profile identifier

        Returns:
            Profile .cfg file content as string

        Raises:
            errors.NotFound: If profile not found
        """
        with self._get_ldap_connection() as ldap:
            profiles_container_dn = DN(
                ("ou", "certificateProfiles"), self.ca_base_dn
            )
            profile_dn = DN(("cn", profile_id), profiles_container_dn)

            entry = ldap.get_entry(
                profile_dn, attrs_list=["certProfileConfig"]
            )

            # certProfileConfig is stored as binary
            cfg_bytes = entry.get("certProfileConfig", [b""])[0]
            if isinstance(cfg_bytes, bytes):
                return cfg_bytes.decode("utf-8")
            return cfg_bytes

    def update_profile_cfg(self, profile_id: str, cfg_content: str):
        """Update profile .cfg content in LDAP

        Args:
            profile_id: Profile identifier
            cfg_content: New .cfg file content

        Raises:
            errors.NotFound: If profile not found
        """
        with self._get_ldap_connection() as ldap:
            profiles_container_dn = DN(
                ("ou", "certificateProfiles"), self.ca_base_dn
            )
            profile_dn = DN(("cn", profile_id), profiles_container_dn)

            entry = ldap.get_entry(profile_dn)
            entry["certProfileConfig"] = [cfg_content.encode("utf-8")]
            ldap.update_entry(entry)
            logger.info(f"Updated profile {profile_id} .cfg content")

    def create_profile(
        self, profile_id: str, cfg_content: str, description: str = ""
    ):
        """Create new profile in LDAP

        Args:
            profile_id: New profile identifier
            cfg_content: Profile .cfg file content
            description: Profile description (optional, ignored - certProfile
                         objectClass doesn't support it)

        Raises:
            errors.DuplicateEntry: If profile already exists
        """
        with self._get_ldap_connection() as ldap:
            profiles_container_dn = DN(
                ("ou", "certificateProfiles"), self.ca_base_dn
            )
            profile_dn = DN(("cn", profile_id), profiles_container_dn)

            logger.info(f"Attempting to create profile with DN: {profile_dn}")

            # Check if entry already exists (including tombstones)
            try:
                existing = ldap.get_entry(profile_dn)
                logger.error(
                    f"Profile {profile_id} already exists: {existing.dn}"
                )
                raise errors.DuplicateEntry()
            except errors.NotFound:
                # Good - entry doesn't exist
                pass

            entry_attrs = {
                "objectclass": ["top", "certProfile"],
                "cn": [profile_id],
                "certProfileConfig": [cfg_content.encode("utf-8")],
            }

            # Note: description not added - certProfile objectClass doesn't
            # allow it
            # Only cn, classId, and certProfileConfig are allowed

            entry = ldap.make_entry(profile_dn, **entry_attrs)
            logger.info(f"Adding LDAP entry for profile {profile_id}")
            ldap.add_entry(entry)
            logger.info(f"Created new profile {profile_id}")

    def list_profile_ids(self) -> List[str]:
        """List all profile IDs in LDAP

        Returns:
            List of profile identifiers
        """
        return self.list_profiles()
