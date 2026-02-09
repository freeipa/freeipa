# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Profile Change Monitor - LDAP Persistent Search for Profile Replication

Monitors LDAP for profile changes (add, modify, delete) and automatically
updates the ProfileManager cache. This enables multi-master replication
support similar to Dogtag PKI's LDAPProfileSubsystem.

Architecture matches Dogtag PKI's ProfileChangeMonitor:
- Background thread running persistent LDAP search
- Monitors ou=certificateProfiles,ou=ca,o=ipaca
- Tracks entryUSN to avoid unnecessary reloads
- Auto-reconnects on LDAP failure
"""

import logging
import threading
import time

from ipalib import errors
from ipapython.dn import DN

logger = logging.getLogger(__name__)


class ProfileChangeMonitor(threading.Thread):
    """
    Background thread that monitors LDAP for profile changes using
    persistent search.

    Matches Dogtag PKI's LDAPProfileSubsystem Monitor inner class.
    """

    def __init__(self, profile_manager, storage_backend):
        """Initialize the profile change monitor

        Args:
            profile_manager: ProfileManager instance to update
            storage_backend: LDAP storage backend for persistent search
        """
        super().__init__(name="ProfileChangeMonitor", daemon=True)
        self.profile_manager = profile_manager
        self.storage_backend = storage_backend
        self.stopped = False

        # Track entryUSN for each profile to avoid unnecessary reloads
        # Matches Dogtag's TreeMap<String,BigInteger> entryUSNs
        self.entry_usns = {}  # profile_id -> entryUSN

        # Track nsUniqueId for deleted entries
        # Matches Dogtag's TreeSet<String> deletedNsUniqueIds
        self.deleted_unique_ids = set()

        # Reconnection delay (matches Dogtag's 1 second retry)
        self.reconnect_delay = 1.0

    def run(self):
        """
        Main monitor loop - runs persistent LDAP search

        Matches Dogtag's LDAPProfileSubsystem.run() method (line 425-554)
        """
        logger.info("Profile change monitor: starting")

        while not self.stopped:
            try:
                self._run_persistent_search()
            except errors.NetworkError as e:
                if not self.stopped:
                    logger.warning(
                        "Profile change monitor: LDAP connection failed: "
                        f"{e}. Retrying in {self.reconnect_delay} seconds."
                    )
                    time.sleep(self.reconnect_delay)
            except Exception as e:
                if not self.stopped:
                    logger.error(
                        f"Profile change monitor: Caught exception: {e}",
                        exc_info=True,
                    )
                    time.sleep(self.reconnect_delay)

        logger.info("Profile change monitor: stopping")

    def _run_persistent_search(self):
        """
        Execute persistent LDAP search and process changes

        Uses polling-based approach compatible with IPA's LDAP infrastructure.
        In production, this could be replaced with true persistent search
        using python-ldap3.
        """
        # Note: IPA's python-ldap doesn't easily support persistent search,
        # so we implement a polling approach with short intervals.
        # This is less efficient than Dogtag's true persistent search,
        # but provides the same functional behavior.

        logger.debug("Profile change monitor: Starting search loop")

        # Get base DN for profiles
        profiles_base = DN(
            ("ou", "certificateProfiles"),
            ("ou", "ca"),
            ("o", "ipaca"),
        )

        # Initial load - get all current profiles and their USNs
        self._initial_profile_load(profiles_base)

        # Poll for changes every 5 seconds
        # (much more frequent than TTL-based cache, less than persistent
        # search)
        poll_interval = 5.0

        while not self.stopped:
            try:
                self._check_for_changes(profiles_base)
                time.sleep(poll_interval)
            except Exception as e:
                logger.warning(
                    f"Profile change monitor: Error checking for changes: {e}"
                )
                time.sleep(poll_interval)

    def _initial_profile_load(self, profiles_base: DN):
        """
        Initial load of all profiles and their entryUSNs

        Matches Dogtag's initial profile loading on startup.
        """
        logger.debug("Profile change monitor: Initial profile load")

        try:
            with self.storage_backend._get_ldap_connection() as ldap:
                # Search for all profile entries
                entries = ldap.get_entries(
                    profiles_base,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=certProfile)",
                    attrs_list=["cn", "entryUSN", "nsUniqueId"],
                )

                for entry in entries:
                    profile_id = entry.single_value.get("cn")
                    entry_usn = entry.single_value.get("entryUSN")

                    if profile_id and entry_usn:
                        # Store initial USN
                        self.entry_usns[profile_id] = int(entry_usn)
                        logger.debug(
                            f"Profile change monitor: Loaded {profile_id} "
                            f"with entryUSN={entry_usn}"
                        )

                logger.info(
                    f"Profile change monitor: Loaded {len(entries)} profiles"
                )

        except errors.NotFound:
            logger.debug(
                f"Profile change monitor: Profile container {profiles_base} "
                "not found (expected during initial installation)"
            )
        except Exception as e:
            logger.error(
                f"Profile change monitor: Failed initial load: {e}",
                exc_info=True,
            )

    def _check_for_changes(self, profiles_base: DN):
        """
        Check for profile changes by comparing entryUSNs

        This is a polling-based approximation of persistent search.
        Detects:
        - New profiles (profile_id not in entry_usns)
        - Modified profiles (entryUSN changed)
        - Deleted profiles (profile_id disappeared from LDAP)
        """
        try:
            with self.storage_backend._get_ldap_connection() as ldap:
                # Get current state of all profiles
                current_profiles = {}
                entries = ldap.get_entries(
                    profiles_base,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(objectClass=certProfile)",
                    attrs_list=["cn", "entryUSN", "nsUniqueId"],
                )

                for entry in entries:
                    profile_id = entry.single_value.get("cn")
                    entry_usn = entry.single_value.get("entryUSN")
                    ns_unique_id = entry.single_value.get("nsUniqueId")

                    if profile_id and entry_usn:
                        current_profiles[profile_id] = {
                            "usn": int(entry_usn),
                            "unique_id": ns_unique_id,
                        }

                # Detect additions and modifications
                for profile_id, data in current_profiles.items():
                    new_usn = data["usn"]
                    unique_id = data["unique_id"]

                    # Check if this is a previously deleted entry being
                    # re-added
                    if unique_id in self.deleted_unique_ids:
                        logger.debug(
                            f"Profile change monitor: Ignoring {profile_id} "
                            f"with deleted nsUniqueId {unique_id}"
                        )
                        continue

                    if profile_id not in self.entry_usns:
                        # New profile added
                        logger.info(
                            f"Profile change monitor: ADD - {profile_id}"
                        )
                        self._handle_add(profile_id, new_usn)
                    else:
                        # Check if modified
                        old_usn = self.entry_usns[profile_id]
                        if new_usn > old_usn:
                            logger.info(
                                "Profile change monitor: MODIFY - "
                                f"{profile_id} "
                                f"(USN {old_usn} -> {new_usn})"
                            )
                            self._handle_modify(profile_id, new_usn)

                # Detect deletions
                deleted_profiles = set(self.entry_usns.keys()) - set(
                    current_profiles.keys()
                )
                for profile_id in deleted_profiles:
                    logger.info(
                        f"Profile change monitor: DELETE - {profile_id}"
                    )
                    self._handle_delete(profile_id)

        except errors.NotFound:
            # Profile container doesn't exist yet (during installation)
            logger.debug("Profile change monitor: Profile container not found")
        except errors.NetworkError as e:
            # LDAP connection failed - log at debug level during expected
            # downtime (e.g., directory server restart)
            logger.debug(
                f"Profile change monitor: LDAP connection unavailable: {e}"
            )
        except Exception as e:
            logger.warning(
                f"Profile change monitor: Error checking for changes: {e}"
            )

    def _handle_add(self, profile_id: str, entry_usn: int):
        """
        Handle profile addition

        Matches Dogtag's ADD case (line 507-510)
        """
        # Update USN tracking
        self.entry_usns[profile_id] = entry_usn

        # Invalidate cache and reload
        self.profile_manager.invalidate_profile(profile_id)

        logger.debug(f"Profile change monitor: Added {profile_id} to cache")

    def _handle_modify(self, profile_id: str, entry_usn: int):
        """
        Handle profile modification

        Matches Dogtag's MODIFY case (line 515-518)
        """
        # Update USN tracking
        self.entry_usns[profile_id] = entry_usn

        # Invalidate cache (will be reloaded on next access)
        self.profile_manager.invalidate_profile(profile_id)

        logger.debug(
            f"Profile change monitor: Invalidated cache for {profile_id}"
        )

    def _handle_delete(self, profile_id: str):
        """
        Handle profile deletion

        Matches Dogtag's DELETE case (line 511-514)
        """
        # Remove from USN tracking
        if profile_id in self.entry_usns:
            del self.entry_usns[profile_id]

        # Remove from cache
        self.profile_manager.remove_profile(profile_id)

        logger.debug(
            f"Profile change monitor: Removed {profile_id} from cache"
        )

    def shutdown(self):
        """
        Stop the monitor thread

        Matches Dogtag's shutdown() method (line 381-385)
        """
        logger.info("Profile change monitor: shutdown requested")
        self.stopped = True
        # Wait for thread to finish (with timeout)
        self.join(timeout=5.0)
        if self.is_alive():
            logger.warning(
                "Profile change monitor: thread did not stop within timeout"
            )
