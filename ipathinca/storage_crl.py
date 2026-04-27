# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Storage module extracted from storage_ca.py for modularity
"""

from __future__ import absolute_import

import logging
from typing import Any, List
from datetime import datetime, timezone

from ipathinca.storage_base import BaseStorageBackend
from ipalib import errors
from ipapython.dn import DN

logger = logging.getLogger(__name__)


class CRLStorage(BaseStorageBackend):
    """Storage operations"""

    def store_crl(
        self,
        crl_name: str,
        crl_data: bytes,
        crl_number: int,
        this_update: datetime,
        next_update: datetime,
        crl_size: int = 0,
    ):
        """
        Store CRL in Dogtag CRL issuing point

        Args:
            crl_name: CRL issuing point name (e.g., "MasterCRL")
            crl_data: DER-encoded CRL binary data
            crl_number: CRL sequence number
            this_update: CRL issue timestamp
            next_update: CRL next update timestamp
            crl_size: Number of revoked certificates in CRL
        """
        with self._get_ldap_connection() as ldap:

            crl_dn = DN(
                ("cn", crl_name),
                DN(("ou", "crlIssuingPoints"), self.ca_base_dn),
            )

            try:
                # Try to update existing CRL issuing point
                entry = ldap.get_entry(crl_dn)

                entry["crlNumber"] = [str(crl_number)]
                entry["thisUpdate"] = [this_update.isoformat()]
                entry["nextUpdate"] = [next_update.isoformat()]
                entry["certificateRevocationList;binary"] = [crl_data]
                entry["crlSize"] = [str(crl_size)]
                entry["dateOfModify"] = [
                    datetime.now(timezone.utc).isoformat()
                ]

                ldap.update_entry(entry)
                logger.debug(f"Updated CRL issuing point: {crl_name}")

            except errors.NotFound:
                # Create new CRL issuing point
                logger.debug(f"Creating CRL issuing point: {crl_name}")

                entry_attrs = {
                    "objectClass": ["top", "crlIssuingPointRecord"],
                    "cn": [crl_name],
                    "crlNumber": [str(crl_number)],
                    "thisUpdate": [this_update.isoformat()],
                    "nextUpdate": [next_update.isoformat()],
                    "certificateRevocationList;binary": [crl_data],
                    "crlSize": [str(crl_size)],
                    "dateOfCreate": [datetime.now(timezone.utc).isoformat()],
                }

                entry = ldap.make_entry(crl_dn, **entry_attrs)
                ldap.add_entry(entry)
                logger.debug(f"Created CRL issuing point: {crl_name}")

    def get_crl(self, crl_name: str = "MasterCRL") -> Any:
        """
        Retrieve CRL binary data

        Args:
            crl_name: CRL issuing point name

        Returns:
            DER-encoded CRL binary data or None
        """
        with self._get_ldap_connection() as ldap:
            crl_dn = DN(
                ("cn", crl_name),
                DN(("ou", "crlIssuingPoints"), self.ca_base_dn),
            )

            try:
                entry = ldap.get_entry(crl_dn)

                # Try different attribute name variations
                for attr_name in [
                    "certificateRevocationList;binary",
                    "certificateRevocationList",
                    "certificaterevocationlist",
                ]:
                    if attr_name in entry:
                        return entry[attr_name][0]

                logger.warning(
                    f"CRL {crl_name} found but no CRL data attribute present"
                )
                return None

            except errors.NotFound:
                logger.debug(f"CRL issuing point {crl_name} not found")
                return None

    def get_crl_info(self, crl_name: str = "MasterCRL") -> Any:
        """
        Get CRL metadata

        Uses TTL-based caching (300s) since CRL info changes infrequently.

        Args:
            crl_name: CRL issuing point name

        Returns:
            Dictionary with CRL information or None
        """
        # Check cache first (if available)
        if (
            self._crl_info_cache is not None
            and crl_name in self._crl_info_cache
        ):
            logger.debug(
                f"Returning cached CRL info for {crl_name} (TTL cache hit)"
            )
            return self._crl_info_cache[crl_name]

        with self._get_ldap_connection() as ldap:
            crl_dn = DN(
                ("cn", crl_name),
                DN(("ou", "crlIssuingPoints"), self.ca_base_dn),
            )

            try:
                entry = ldap.get_entry(crl_dn)

                crl_number = entry.get(
                    "crlnumber", entry.get("crlNumber", ["0"])
                )[0]
                if isinstance(crl_number, bytes):
                    crl_number = crl_number.decode("utf-8")

                crl_size = entry.get("crlsize", entry.get("crlSize", ["0"]))[0]
                if isinstance(crl_size, bytes):
                    crl_size = crl_size.decode("utf-8")

                this_update = entry.get(
                    "thisupdate", entry.get("thisUpdate", [None])
                )[0]
                if this_update and isinstance(this_update, bytes):
                    this_update = this_update.decode("utf-8")

                next_update = entry.get(
                    "nextupdate", entry.get("nextUpdate", [None])
                )[0]
                if next_update and isinstance(next_update, bytes):
                    next_update = next_update.decode("utf-8")

                crl_info = {
                    "crl_name": crl_name,
                    "crl_number": int(crl_number),
                    "crl_size": int(crl_size),
                    "this_update": this_update,
                    "next_update": next_update,
                }

                # Cache the result (if caching is available)
                if self._crl_info_cache is not None:
                    self._crl_info_cache[crl_name] = crl_info
                    logger.debug(f"Cached CRL info for {crl_name} (TTL=300s)")

                return crl_info

            except errors.NotFound:
                logger.debug(f"CRL issuing point {crl_name} not found")
                return None

    def list_crl_issuing_points(self) -> List[str]:
        """
        List all CRL issuing points

        Returns:
            List of CRL issuing point names
        """
        with self._get_ldap_connection() as ldap:
            crl_base_dn = DN(("ou", "crlIssuingPoints"), self.ca_base_dn)

            try:
                # OPTIMIZED: Only fetch cn attribute for listing CRL names
                entries = ldap.get_entries(
                    crl_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=crlIssuingPointRecord)",
                    attrs_list=["cn"],  # Only need the name
                )

                return [entry["cn"][0] for entry in entries]

            except errors.NotFound:
                return []

    def delete_crl_issuing_point(self, crl_name: str):
        """
        Delete a CRL issuing point (Dogtag compatible)

        This removes the CRL issuing point record from LDAP.
        In Dogtag, this is used when removing/disabling a CRL configuration.

        Args:
            crl_name: CRL issuing point name to delete
        """
        with self._get_ldap_connection() as ldap:
            crl_dn = DN(
                ("cn", crl_name),
                DN(("ou", "crlIssuingPoints"), self.ca_base_dn),
            )

            try:
                ldap.delete_entry(crl_dn)
                logger.info(f"Deleted CRL issuing point: {crl_name}")
            except errors.NotFound:
                logger.warning(
                    f"CRL issuing point {crl_name} not found for deletion"
                )
