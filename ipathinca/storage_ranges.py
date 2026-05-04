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


class RangeStorage(BaseStorageBackend):
    """Storage operations"""

    def allocate_serial_range(
        self, replica_id: str, range_size: int = 10000
    ) -> Any:
        """
        Allocate a serial number range for multi-master replication

        Args:
            replica_id: Replica identifier
            range_size: Number of serials in range (default: 10000)

        Returns:
            Tuple of (begin_range, end_range)
        """
        with self._get_ldap_connection() as ldap:

            # Get global next range counter from config
            try:
                config_entry = ldap.get_entry(self.config_dn)
                next_range = int(config_entry.get("nextRange", ["1"])[0])
            except errors.NotFound:
                logger.warning(
                    "Config entry not found, initializing schema first"
                )
                self.initialize_schema()
                config_entry = ldap.get_entry(self.config_dn)
                next_range = int(config_entry.get("nextRange", ["1"])[0])

            begin_range = next_range
            end_range = next_range + range_size - 1

            # Update global counter
            config_entry["nextRange"] = [str(end_range + 1)]
            ldap.update_entry(config_entry)

            # Store range allocation
            ranges_dn = DN(("ou", "ranges"), self.base_dn)
            replica_ranges_dn = DN(("ou", "replica"), ranges_dn)

            range_dn = DN(
                ("cn", f"{replica_id}-{begin_range}"), replica_ranges_dn
            )

            range_entry = ldap.make_entry(
                range_dn,
                objectClass=["top", "extensibleObject"],
                cn=[f"{replica_id}-{begin_range}"],
                beginRange=[str(begin_range)],
                endRange=[str(end_range)],
                replicaId=[replica_id],
            )
            ldap.add_entry(range_entry)

            logger.info(
                "Allocated serial range %s-%s to replica %s",
                begin_range,
                end_range,
                replica_id,
            )
            return (begin_range, end_range)

    def get_replica_ranges(self, replica_id: str) -> List[Any]:
        """
        Get all serial ranges allocated to a replica

        Args:
            replica_id: Replica identifier

        Returns:
            List of (begin_range, end_range) tuples
        """
        with self._get_ldap_connection() as ldap:
            ranges_dn = DN(("ou", "ranges"), self.base_dn)
            replica_ranges_dn = DN(("ou", "replica"), ranges_dn)

            try:
                # OPTIMIZED: Only fetch range attributes, not metadata
                entries = ldap.get_entries(
                    replica_ranges_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter=f"(replicaId={replica_id})",
                    attrs_list=["beginRange", "endRange"],
                )

                results = []
                for entry in entries:
                    begin = int(entry["beginRange"][0])
                    end = int(entry["endRange"][0])
                    results.append((begin, end))

                return results

            except errors.NotFound:
                return []

    def list_all_ranges(self) -> List[Dict[str, Any]]:
        """
        List all allocated serial ranges across all replicas

        Returns:
            List of dictionaries with range information
        """
        with self._get_ldap_connection() as ldap:
            ranges_dn = DN(("ou", "ranges"), self.base_dn)
            replica_ranges_dn = DN(("ou", "replica"), ranges_dn)

            try:
                # OPTIMIZED: Only fetch necessary attributes for range listing
                entries = ldap.get_entries(
                    replica_ranges_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=extensibleObject)",
                    attrs_list=["replicaId", "beginRange", "endRange", "cn"],
                )

                results = []
                for entry in entries:
                    replica_id = entry.get("replicaId", [None])[0]
                    if isinstance(replica_id, bytes):
                        replica_id = replica_id.decode("utf-8")

                    begin = int(entry["beginRange"][0])
                    end = int(entry["endRange"][0])

                    results.append(
                        {
                            "replica_id": replica_id,
                            "begin_range": begin,
                            "end_range": end,
                            "range_size": end - begin + 1,
                            "cn": (
                                entry["cn"][0]
                                if isinstance(entry["cn"][0], str)
                                else entry["cn"][0].decode("utf-8")
                            ),
                        }
                    )

                # Sort by begin_range
                results.sort(key=lambda x: x["begin_range"])
                return results

            except errors.NotFound:
                return []

    def update_range(
        self, replica_id: str, old_begin_range: int, new_end_range: int
    ):
        """
        Update the end boundary of an existing serial range

        This is useful for extending a range that's running out of serials.

        Args:
            replica_id: Replica identifier
            old_begin_range: Current beginning of the range
            new_end_range: New end value for the range

        Raises:
            errors.NotFound: If the range doesn't exist
            ValueError: If new_end_range is less than current begin_range
        """
        with self._get_ldap_connection() as ldap:
            ranges_dn = DN(("ou", "ranges"), self.base_dn)
            replica_ranges_dn = DN(("ou", "replica"), ranges_dn)

            range_dn = DN(
                ("cn", f"{replica_id}-{old_begin_range}"), replica_ranges_dn
            )

            entry = ldap.get_entry(range_dn)

            current_begin = int(entry["beginRange"][0])
            current_end = int(entry["endRange"][0])

            if new_end_range < current_begin:
                raise ValueError(
                    f"New end range {new_end_range} cannot be less than "
                    f"begin range {current_begin}"
                )

            # Update the end range
            entry["endRange"] = [str(new_end_range)]
            ldap.update_entry(entry)

            logger.info(
                "Updated range %s-%s:  %s-%s → %s-%s",
                replica_id,
                old_begin_range,
                current_begin,
                current_end,
                current_begin,
                new_end_range,
            )

    def get_range_info(self, replica_id: str, begin_range: int) -> Any:
        """
        Get detailed information about a specific range

        Args:
            replica_id: Replica identifier
            begin_range: Beginning of the range

        Returns:
            Dictionary with range information or None if not found
        """
        with self._get_ldap_connection() as ldap:
            ranges_dn = DN(("ou", "ranges"), self.base_dn)
            replica_ranges_dn = DN(("ou", "replica"), ranges_dn)

            range_dn = DN(
                ("cn", f"{replica_id}-{begin_range}"), replica_ranges_dn
            )

            try:
                entry = ldap.get_entry(range_dn)

                replica_id_val = entry.get("replicaId", [None])[0]
                if isinstance(replica_id_val, bytes):
                    replica_id_val = replica_id_val.decode("utf-8")

                begin = int(entry["beginRange"][0])
                end = int(entry["endRange"][0])

                return {
                    "replica_id": replica_id_val,
                    "begin_range": begin,
                    "end_range": end,
                    "range_size": end - begin + 1,
                    "cn": (
                        entry["cn"][0]
                        if isinstance(entry["cn"][0], str)
                        else entry["cn"][0].decode("utf-8")
                    ),
                }

            except errors.NotFound:
                logger.debug("Range %s-%s not found", replica_id, begin_range)
                return None

    def delete_range(self, replica_id: str, begin_range: int):
        """
        Delete a specific serial range allocation

        Args:
            replica_id: Replica identifier
            begin_range: Beginning of the range to delete
        """
        with self._get_ldap_connection() as ldap:
            ranges_dn = DN(("ou", "ranges"), self.base_dn)
            replica_ranges_dn = DN(("ou", "replica"), ranges_dn)

            range_dn = DN(
                ("cn", f"{replica_id}-{begin_range}"), replica_ranges_dn
            )

            try:
                ldap.delete_entry(range_dn)
                logger.info(
                    "Deleted serial range %s-%s", replica_id, begin_range
                )
            except errors.NotFound:
                logger.warning(
                    "Range %s-%s not found", replica_id, begin_range
                )

    def delete_replica_ranges(self, replica_id: str):
        """
        Delete all serial ranges allocated to a specific replica

        Args:
            replica_id: Replica identifier
        """
        with self._get_ldap_connection() as ldap:
            ranges_dn = DN(("ou", "ranges"), self.base_dn)
            replica_ranges_dn = DN(("ou", "replica"), ranges_dn)

            try:
                # OPTIMIZED: Only fetch dn for deletion (no attribute data
                # needed)
                entries = ldap.get_entries(
                    replica_ranges_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter=f"(replicaId={replica_id})",
                    attrs_list=["dn"],  # Minimal fetch for deletion
                )

                deleted_count = 0
                for entry in entries:
                    ldap.delete_entry(entry)
                    deleted_count += 1

                logger.info(
                    "Deleted %s serial ranges for replica %s",
                    deleted_count,
                    replica_id,
                )

            except errors.NotFound:
                logger.debug("No ranges found for replica %s", replica_id)
