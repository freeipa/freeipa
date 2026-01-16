# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
KRA Storage Backend - Dogtag LDAP Schema Compatible

This module provides LDAP storage for archived keys using the Dogtag KRA
schema.
It stores encrypted keys in o=kra,o=ipaca with full Dogtag compatibility.
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from ipalib import errors
from ipapython.dn import DN

from ipathinca.storage_base import LDAPStorageMixin, escape_filter_chars

logger = logging.getLogger(__name__)


class KRAStorageBackend(LDAPStorageMixin):
    """
    Dogtag-Compatible KRA LDAP Storage Backend

    Stores archived keys in LDAP using Dogtag KRA schema:
        o=kra,o=ipaca
        ├── ou=kra,o=kra,o=ipaca (subsystem container)
        ├── ou=requests,o=kra,o=ipaca (key requests)
        └── (key records stored directly under o=kra,o=ipaca)

    Schema:
        - Keys: cn={keyId},o=kra,o=ipaca (objectClass: keyRecord)
        - Requests: cn={requestId},ou=requests,o=kra,o=ipaca
    """

    def __init__(self):
        """Initialize KRA storage backend"""
        # Dogtag KRA base DNs
        self.base_dn = DN(("o", "ipaca"))
        self.kra_base_dn = DN(("o", "kra"), self.base_dn)
        self.requests_base_dn = DN(("ou", "requests"), self.kra_base_dn)

        # Serial number counter for key IDs
        self._current_key_serial = None
        self._serial_lock = threading.Lock()

    def init_schema(self):
        """
        Initialize KRA LDAP schema structure

        Creates the Dogtag-compatible KRA containers in LDAP:
        - o=kra,o=ipaca (KRA base)
        - ou=kra,o=kra,o=ipaca (subsystem)
        - ou=people,o=kra,o=ipaca
        - ou=groups,o=kra,o=ipaca
        - ou=requests,o=kra,o=ipaca
        - ou=ranges,o=kra,o=ipaca (with sub-containers)
        """
        with self._get_ldap_connection() as ldap:
            logger.debug("Initializing KRA LDAP schema")

            # Create KRA base container (o=kra,o=ipaca)
            try:
                ldap.get_entry(self.kra_base_dn)
                logger.debug(
                    "KRA base container already exists: %s", self.kra_base_dn
                )
            except errors.NotFound:
                logger.debug(
                    "Creating KRA base container: %s", self.kra_base_dn
                )
                entry = ldap.make_entry(
                    self.kra_base_dn,
                    objectclass=["top", "organization"],
                    o=["kra"],
                )
                ldap.add_entry(entry)

            # Create KRA subsystem container
            kra_subsystem_dn = DN(("ou", "kra"), self.kra_base_dn)
            self._create_ou_if_not_exists(ldap, kra_subsystem_dn, "kra")

            # Create KRA people container
            kra_people_dn = DN(("ou", "people"), self.kra_base_dn)
            self._create_ou_if_not_exists(ldap, kra_people_dn, "people")

            # Create KRA groups container
            kra_groups_dn = DN(("ou", "groups"), self.kra_base_dn)
            self._create_ou_if_not_exists(ldap, kra_groups_dn, "groups")

            # Create KRA requests container
            self._create_ou_if_not_exists(
                ldap, self.requests_base_dn, "requests"
            )

            # Create KRA ranges container
            kra_ranges_dn = DN(("ou", "ranges"), self.kra_base_dn)
            self._create_ou_if_not_exists(ldap, kra_ranges_dn, "ranges")

            # Create KRA key repository ranges container
            kra_key_ranges_dn = DN(("ou", "keyRepository"), kra_ranges_dn)
            self._create_ou_if_not_exists(
                ldap, kra_key_ranges_dn, "keyRepository"
            )

            # Create KRA replica ranges container
            kra_replica_ranges_dn = DN(("ou", "replica"), kra_ranges_dn)
            self._create_ou_if_not_exists(
                ldap, kra_replica_ranges_dn, "replica"
            )

            # Create KRA request ranges container
            kra_request_ranges_dn = DN(("ou", "requests"), kra_ranges_dn)
            self._create_ou_if_not_exists(
                ldap, kra_request_ranges_dn, "requests"
            )

            logger.debug("KRA LDAP schema initialized successfully")

    def _get_next_key_serial(self) -> int:
        """
        Get next key serial number

        Uses a counter stored in ou=kra,o=kra,o=ipaca

        Returns:
            Next available key serial number
        """
        with self._serial_lock, self._get_ldap_connection() as ldap:

            config_dn = DN(
                ("cn", "KRAConfig"), DN(("ou", "kra"), self.kra_base_dn)
            )

            try:
                entry = ldap.get_entry(config_dn)
                current_serial = int(entry.get("serialno", ["0"])[0])
                next_serial = current_serial + 1

                entry["serialno"] = [str(next_serial)]
                ldap.update_entry(entry)

                logger.debug("Allocated key serial number: %s", next_serial)
                return next_serial

            except errors.NotFound:
                # Create config entry if it doesn't exist
                logger.debug("Creating KRA config entry: %s", config_dn)

                try:
                    entry = ldap.make_entry(
                        config_dn,
                        objectclass=[
                            "top",
                            "nsContainer",
                            "extensibleObject",
                        ],
                        cn=["KRAConfig"],
                        serialno=["1"],
                    )
                    ldap.add_entry(entry)
                    return 1
                except errors.DuplicateEntry:
                    # Race condition - someone else created it
                    return self._get_next_key_serial()

    def store_key(
        self,
        encrypted_data: bytes,
        owner: str,
        algorithm: str = "AES",
        key_size: int = 256,
        status: str = "active",
    ) -> str:
        """
        Store encrypted key in KRA LDAP storage

        Args:
            encrypted_data: Encrypted key data (encrypted with storage key)
            owner: Key owner (DN, username, or vault identifier)
            algorithm: Key algorithm (AES, 3DES, etc.)
            key_size: Key size in bits
            status: Key status (active, inactive, archived)

        Returns:
            Key ID (hex string)
        """
        with self._get_ldap_connection() as ldap:

            # Generate key ID (serial number in hex)
            key_serial = self._get_next_key_serial()
            key_id = f"0x{key_serial:x}"

            key_dn = DN(("cn", key_id), self.kra_base_dn)

            logger.debug("Storing key %s for owner: %s", key_id, owner)

            # Create key record entry
            entry_attrs = {
                "objectClass": ["top", "keyRecord"],
                "cn": [key_id],
                "serialno": [str(key_serial)],
                "privateKeyData": [encrypted_data],  # Base64-encoded by LDAP
                "ownerName": [owner],
                "algorithm": [algorithm],
                "keySize": [str(key_size)],
                "keyState": [status],  # Dogtag uses keyState, not keyStatus
                "dateOfCreate": [datetime.now(timezone.utc).isoformat()],
                "dateOfModify": [datetime.now(timezone.utc).isoformat()],
            }

            try:
                entry = ldap.make_entry(key_dn, **entry_attrs)
                ldap.add_entry(entry)
                logger.info("Stored key %s in KRA LDAP storage", key_id)
                return key_id

            except Exception as e:
                logger.error(
                    "Failed to store key %s: %s", key_id, e, exc_info=True
                )
                raise

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve key from KRA LDAP storage

        Args:
            key_id: Key identifier (hex string, e.g., "0x1a")

        Returns:
            Dictionary with key metadata and encrypted data, or None if not
            found
        """
        with self._get_ldap_connection() as ldap:
            key_dn = DN(("cn", key_id), self.kra_base_dn)

            logger.debug("Retrieving key %s from KRA LDAP storage", key_id)

            try:
                entry = ldap.get_entry(key_dn)

                # Extract key data
                encrypted_data = entry["privateKeyData"][0]
                if isinstance(encrypted_data, str):
                    # Already decoded from base64 by LDAP client
                    encrypted_data = encrypted_data.encode("latin1")

                owner = entry.get("ownerName", [None])[0]
                if isinstance(owner, bytes):
                    owner = owner.decode("utf-8")

                algorithm = entry.get("algorithm", ["AES"])[0]
                if isinstance(algorithm, bytes):
                    algorithm = algorithm.decode("utf-8")

                key_size = entry.get("keySize", ["256"])[0]
                if isinstance(key_size, bytes):
                    key_size = key_size.decode("utf-8")

                status = entry.get("keyState", ["active"])[0]
                if isinstance(status, bytes):
                    status = status.decode("utf-8")

                created = entry.get(
                    "dateOfCreate", [datetime.now(timezone.utc).isoformat()]
                )[0]
                if isinstance(created, bytes):
                    created = created.decode("utf-8")

                return {
                    "key_id": key_id,
                    "encrypted_data": encrypted_data,
                    "owner": owner,
                    "algorithm": algorithm,
                    "key_size": int(key_size),
                    "status": status,
                    "created": created,
                }

            except errors.NotFound:
                logger.warning("Key %s not found in KRA LDAP storage", key_id)
                return None

            except Exception as e:
                logger.error(
                    "Error retrieving key %s: %s", key_id, e, exc_info=True
                )
                raise

    def list_keys(
        self,
        owner: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List keys in KRA LDAP storage

        Args:
            owner: Filter by owner (optional)
            status: Filter by status (optional)
            limit: Maximum number of results

        Returns:
            List of key metadata dictionaries (without encrypted data)
        """
        with self._get_ldap_connection() as ldap:

            # Build LDAP filter
            filters = ["(objectClass=keyRecord)"]

            if owner:
                escaped_owner = escape_filter_chars(owner)
                filters.append(f"(ownerName={escaped_owner})")

            if status:
                escaped_status = escape_filter_chars(status)
                filters.append(f"(keyState={escaped_status})")

            # Combine filters
            if len(filters) > 1:
                ldap_filter = f"(&{''.join(filters)})"
            else:
                ldap_filter = filters[0]

            logger.debug("Listing keys with filter: %s", ldap_filter)

            try:
                # OPTIMIZED: Only fetch metadata attributes for key listing
                # Avoids transferring privateKeyData (encrypted key material)
                entries = ldap.get_entries(
                    self.kra_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter=ldap_filter,
                    attrs_list=[
                        "cn",
                        "ownerName",
                        "algorithm",
                        "keySize",
                        "keyState",
                        "dateOfCreate",
                    ],
                )

                results = []
                for entry in entries[:limit]:
                    key_id = entry.get("cn", [None])[0]
                    if isinstance(key_id, bytes):
                        key_id = key_id.decode("utf-8")

                    owner_val = entry.get("ownerName", [None])[0]
                    if isinstance(owner_val, bytes):
                        owner_val = owner_val.decode("utf-8")

                    algorithm = entry.get("algorithm", ["AES"])[0]
                    if isinstance(algorithm, bytes):
                        algorithm = algorithm.decode("utf-8")

                    key_size = entry.get("keySize", ["256"])[0]
                    if isinstance(key_size, bytes):
                        key_size = key_size.decode("utf-8")

                    status_val = entry.get("keyState", ["active"])[0]
                    if isinstance(status_val, bytes):
                        status_val = status_val.decode("utf-8")

                    created = entry.get(
                        "dateOfCreate",
                        [datetime.now(timezone.utc).isoformat()],
                    )[0]
                    if isinstance(created, bytes):
                        created = created.decode("utf-8")

                    results.append(
                        {
                            "key_id": key_id,
                            "owner": owner_val,
                            "algorithm": algorithm,
                            "key_size": int(key_size),
                            "status": status_val,
                            "created": created,
                        }
                    )

                logger.debug("Found %s keys", len(results))
                return results

            except errors.NotFound:
                return []

            except Exception as e:
                logger.error("Error listing keys: %s", e, exc_info=True)
                raise

    def update_key_status(self, key_id: str, status: str) -> bool:
        """
        Update key status

        Args:
            key_id: Key identifier
            status: New status (active, inactive, archived)

        Returns:
            True if successful
        """
        with self._get_ldap_connection() as ldap:
            key_dn = DN(("cn", key_id), self.kra_base_dn)

            logger.debug("Updating key %s status to: %s", key_id, status)

            try:
                entry = ldap.get_entry(key_dn)

                entry["keyState"] = [status]
                entry["dateOfModify"] = [
                    datetime.now(timezone.utc).isoformat()
                ]

                ldap.update_entry(entry)

                logger.info("Updated key %s status to %s", key_id, status)
                return True

            except errors.NotFound:
                logger.warning("Key %s not found for status update", key_id)
                return False

            except Exception as e:
                logger.error(
                    "Error updating key %s status: %s",
                    key_id,
                    e,
                    exc_info=True,
                )
                raise

    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from KRA storage

        Args:
            key_id: Key identifier

        Returns:
            True if successful
        """
        with self._get_ldap_connection() as ldap:
            key_dn = DN(("cn", key_id), self.kra_base_dn)

            logger.debug("Deleting key %s from KRA LDAP storage", key_id)

            try:
                ldap.delete_entry(key_dn)
                logger.info("Deleted key %s", key_id)
                return True

            except errors.NotFound:
                logger.warning("Key %s not found for deletion", key_id)
                return False

            except Exception as e:
                logger.error(
                    "Error deleting key %s: %s", key_id, e, exc_info=True
                )
                raise

    # ========================================================================
    # Key Request Management (for Dogtag compatibility)
    # ========================================================================

    def store_key_request(
        self, request_type: str, owner: str, status: str = "pending"
    ) -> str:
        """
        Store key archival/recovery request

        Args:
            request_type: Type of request (archival, recovery, etc.)
            owner: Request owner
            status: Request status (pending, complete, rejected)

        Returns:
            Request ID
        """
        with self._get_ldap_connection() as ldap:

            # Generate request ID
            request_serial = self._get_next_key_serial()
            request_id = str(request_serial)

            request_dn = DN(("cn", request_id), self.requests_base_dn)

            logger.debug(
                "Storing key request %s, type: %s", request_id, request_type
            )

            entry_attrs = {
                "objectClass": ["top", "request"],
                "cn": [request_id],
                "requestId": [request_id],
                "requestType": [request_type],
                "requestState": [status],
                "requestOwner": [owner],
                "dateOfCreate": [datetime.now(timezone.utc).isoformat()],
            }

            try:
                entry = ldap.make_entry(request_dn, **entry_attrs)
                ldap.add_entry(entry)
                logger.info("Stored key request %s", request_id)
                return request_id

            except Exception as e:
                logger.error(
                    "Failed to store key request %s: %s",
                    request_id,
                    e,
                    exc_info=True,
                )
                raise

    def get_key_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve key request

        Args:
            request_id: Request identifier

        Returns:
            Request data dictionary or None
        """
        with self._get_ldap_connection() as ldap:
            request_dn = DN(("cn", request_id), self.requests_base_dn)

            try:
                entry = ldap.get_entry(request_dn)

                request_type = entry.get("requestType", [None])[0]
                if isinstance(request_type, bytes):
                    request_type = request_type.decode("utf-8")

                status = entry.get("requestState", ["pending"])[0]
                if isinstance(status, bytes):
                    status = status.decode("utf-8")

                owner = entry.get("requestOwner", [None])[0]
                if isinstance(owner, bytes):
                    owner = owner.decode("utf-8")

                created = entry.get(
                    "dateOfCreate", [datetime.now(timezone.utc).isoformat()]
                )[0]
                if isinstance(created, bytes):
                    created = created.decode("utf-8")

                return {
                    "request_id": request_id,
                    "request_type": request_type,
                    "status": status,
                    "owner": owner,
                    "created": created,
                }

            except errors.NotFound:
                logger.warning("Key request %s not found", request_id)
                return None

            except Exception as e:
                logger.error(
                    "Error retrieving key request %s: %s",
                    request_id,
                    e,
                    exc_info=True,
                )
                raise

    def get_statistics(self) -> Dict[str, int]:
        """
        Get KRA statistics

        Returns:
            Dictionary with statistics
        """
        with self._get_ldap_connection() as ldap:

            stats = {
                "total_keys": 0,
                "active_keys": 0,
                "inactive_keys": 0,
                "archived_keys": 0,
                "total_requests": 0,
            }

            try:
                # Count keys - OPTIMIZED: Only fetch keyState attribute
                # Avoids transferring encrypted key data (privateKeyData)
                all_keys = ldap.get_entries(
                    self.kra_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=keyRecord)",
                    attrs_list=["keyState"],  # Only need status for counting
                )
                stats["total_keys"] = len(all_keys)

                for key_entry in all_keys:
                    status = key_entry.get("keyState", ["active"])[0]
                    if isinstance(status, bytes):
                        status = status.decode("utf-8")
                    status = status.lower()

                    if status == "active":
                        stats["active_keys"] += 1
                    elif status == "inactive":
                        stats["inactive_keys"] += 1
                    elif status == "archived":
                        stats["archived_keys"] += 1

                # Count requests - OPTIMIZED: Only fetch dn for counting
                all_requests = ldap.get_entries(
                    self.requests_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=request)",
                    attrs_list=["dn"],  # Minimal data for counting
                )
                stats["total_requests"] = len(all_requests)

            except errors.NotFound:
                pass

            return stats
