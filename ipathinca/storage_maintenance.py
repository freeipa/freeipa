# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Database maintenance operations (cleanup, pruning, statistics)
"""

from __future__ import absolute_import

import logging
from typing import Dict
from datetime import datetime, timezone

from ipathinca.storage_base import BaseStorageBackend
from ipalib import errors
from ipathinca.ldap_utils import get_ldap_connection

logger = logging.getLogger(__name__)


class MaintenanceStorage(BaseStorageBackend):
    """Database maintenance and cleanup operations"""

    def cleanup_old_requests(self, days: int = 90):
        """
        Clean up old completed/rejected requests (Dogtag schema)

        Args:
            days: Age in days for request cleanup
        """
        with self._get_ldap_connection() as ldap:

            from datetime import timedelta

            cutoff_date = datetime.now(timezone.utc).replace(microsecond=0)
            cutoff_date = cutoff_date - timedelta(days=days)

            logger.debug(
                f"Cleaning up requests older than {cutoff_date.isoformat()} "
                "(Dogtag schema)"
            )

            ldap_filter = (
                "(&(objectClass=request)(dateOfCreate<="
                f"{cutoff_date.isoformat()}))"
            )

            try:
                # OPTIMIZED: Only fetch requestState attribute for cleanup
                entries = ldap.get_entries(
                    self.requests_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter=ldap_filter,
                    attrs_list=[
                        "requestState"
                    ],  # Only need status to decide deletion
                )

                deleted_count = 0
                for entry in entries:
                    status = entry.get(
                        "requeststate", entry.get("requestState", [""])
                    )[0]
                    if isinstance(status, bytes):
                        status = status.decode("utf-8")
                    # Use lowercase to match PKI CertRequestStatus constants
                    if status.lower() in ["complete", "rejected", "canceled"]:
                        ldap.delete_entry(entry)
                        deleted_count += 1

                logger.debug(
                    f"Cleaned up {deleted_count} old requests (Dogtag schema)"
                )

            except errors.NotFound:
                logger.debug("No old requests found")

    def get_statistics(self) -> Dict[str, int]:
        """
        Get CA statistics from Dogtag-compatible LDAP

        Uses TTL-based caching (60s) to avoid expensive LDAP queries for
        frequently accessed statistics.

        Returns:
            Dictionary with statistics
        """
        # Check cache first (if available)
        if self._stats_cache is not None and "stats" in self._stats_cache:
            logger.debug("Returning cached statistics (TTL cache hit)")
            return self._stats_cache["stats"]

        with self._get_ldap_connection() as ldap:

            stats = {
                "total_certificates": 0,
                "valid_certificates": 0,
                "revoked_certificates": 0,
                "expired_certificates": 0,
                "total_requests": 0,
                "pending_requests": 0,
            }

            try:
                # Count certificates - OPTIMIZED: Only fetch certStatus
                # attribute
                # This avoids transferring userCertificate;binary (2-4KB per
                # cert)
                all_certs = ldap.get_entries(
                    self.certs_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=certificateRecord)",
                    attrs_list=["certStatus"],  # Only fetch what we need
                )
                stats["total_certificates"] = len(all_certs)

                for cert_entry in all_certs:
                    status = cert_entry.get(
                        "certstatus", cert_entry.get("certStatus", ["VALID"])
                    )[0]
                    if isinstance(status, bytes):
                        status = status.decode("utf-8")
                    status = status.upper()

                    if status == "VALID":
                        stats["valid_certificates"] += 1
                    elif status in ("REVOKED", "REVOKED_EXPIRED"):
                        stats["revoked_certificates"] += 1
                    elif status == "EXPIRED":
                        stats["expired_certificates"] += 1

                # Count requests - OPTIMIZED: Only fetch requestState attribute
                all_requests = ldap.get_entries(
                    self.requests_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=request)",
                    attrs_list=["requestState"],  # Only fetch what we need
                )
                stats["total_requests"] = len(all_requests)

                for req_entry in all_requests:
                    status = req_entry.get(
                        "requeststate", req_entry.get("requestState", [""])
                    )[0]
                    if isinstance(status, bytes):
                        status = status.decode("utf-8")
                    # Use lowercase to match PKI CertRequestStatus constants
                    if status.lower() == "pending":
                        stats["pending_requests"] += 1

            except errors.NotFound:
                pass

            # Cache the result (if caching is available)
            if self._stats_cache is not None:
                self._stats_cache["stats"] = stats
                logger.debug("Cached statistics (TTL=60s)")

            return stats

    def delete_old_certificates(
        self,
        cutoff_date: datetime,
        size_limit: int = 1000,
        time_limit: int = 0,
    ) -> int:
        """
        Delete certificates older than cutoff date

        Args:
            cutoff_date: Delete certificates issued before this date
            size_limit: Maximum number of entries to search (LDAP sizelimit)
            time_limit: Maximum search time in seconds (LDAP timelimit)

        Returns:
            int: Number of certificates deleted
        """
        deleted_count = 0

        with get_ldap_connection() as conn:
            # Format cutoff date as LDAP Generalized Time
            # Format: YYYYMMDDHHMMSSz (UTC timezone)
            cutoff_str = cutoff_date.strftime("%Y%m%d%H%M%S") + "Z"

            # Search for certificates issued before cutoff date
            # Only delete REVOKED or EXPIRED certificates for safety
            search_filter = (
                f"(&(objectClass=certificateRecord)"
                f"(dateOfCreate<={cutoff_str})"
                f"(|(certStatus=REVOKED)(certStatus=EXPIRED)))"
            )

            try:
                entries = conn.get_entries(
                    self.certs_base_dn,
                    filter=search_filter,
                    attrs_list=["cn"],
                    size_limit=size_limit,
                    time_limit=time_limit,
                )

                for entry in entries:
                    try:
                        conn.delete_entry(entry)
                        deleted_count += 1
                        if deleted_count % 100 == 0:
                            logger.info(
                                f"Pruning progress: {deleted_count} "
                                f"certificates deleted"
                            )
                    except Exception as e:
                        logger.error(
                            f"Failed to delete certificate {entry.dn}: {e}"
                        )

                logger.info(
                    f"Certificate pruning complete: {deleted_count} deleted"
                )

            except errors.NotFound:
                logger.debug("No certificates container found")
            except Exception as e:
                logger.error(
                    f"Error during certificate pruning: {e}", exc_info=True
                )
                raise

        return deleted_count

    def delete_old_requests(
        self,
        cutoff_date: datetime,
        size_limit: int = 1000,
        time_limit: int = 0,
    ) -> int:
        """
        Delete certificate requests older than cutoff date

        Args:
            cutoff_date: Delete requests created before this date
            size_limit: Maximum number of entries to search (LDAP sizelimit)
            time_limit: Maximum search time in seconds (LDAP timelimit)

        Returns:
            int: Number of requests deleted
        """
        deleted_count = 0

        with get_ldap_connection() as conn:
            # Format cutoff date as LDAP Generalized Time
            cutoff_str = cutoff_date.strftime("%Y%m%d%H%M%S") + "Z"

            # Search for requests created before cutoff date
            # Only delete completed requests (approved or rejected)
            search_filter = (
                f"(&(objectClass=request)"
                f"(dateOfCreate<={cutoff_str})"
                f"(|(requestState=complete)(requestState=rejected)"
                f"(requestState=canceled)))"
            )

            try:
                entries = conn.get_entries(
                    self.requests_base_dn,
                    filter=search_filter,
                    attrs_list=["cn"],
                    size_limit=size_limit,
                    time_limit=time_limit,
                )

                for entry in entries:
                    try:
                        conn.delete_entry(entry)
                        deleted_count += 1
                        if deleted_count % 100 == 0:
                            logger.info(
                                f"Pruning progress: {deleted_count} "
                                f"requests deleted"
                            )
                    except Exception as e:
                        logger.error(
                            f"Failed to delete request {entry.dn}: {e}"
                        )

                logger.info(
                    f"Request pruning complete: {deleted_count} deleted"
                )

            except errors.NotFound:
                logger.debug("No requests container found")
            except Exception as e:
                logger.error(
                    f"Error during request pruning: {e}", exc_info=True
                )
                raise

        return deleted_count
