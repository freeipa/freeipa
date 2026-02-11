# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Certificate profile management for Python CA
"""

import logging
import re
import threading
from pathlib import Path
from typing import Dict, Optional

from ipapython import dogtag
from ipathinca.exceptions import ProfileNotFound
from ipathinca.profile_monitor import ProfileChangeMonitor

logger = logging.getLogger(__name__)


class ProfileManager:
    """Manages certificate profiles"""

    # Whitelist of required profiles for IPAthinCA
    # Only these profiles are installed to LDAP during deployment
    REQUIRED_PROFILES = [
        dogtag.DEFAULT_PROFILE,  # caIPAserviceCert - IPA service certificates
        "IECUserRoles",  # User certificates with IEC roles
        dogtag.KDC_PROFILE,  # KDCs_PKINIT_Certs - Kerberos KDC PKINIT
        "acmeIPAServerCert",  # ACME-issued server certificates
        dogtag.SUBSYSTEM_PROFILE,  # caSubsystemCert - CA subsystem certs
        dogtag.OCSP_PROFILE,  # caOCSPCert - OCSP responder certificates
        dogtag.AUDIT_PROFILE,  # caSignedLogCert - Audit log signing certs
    ]

    def __init__(
        self,
        profiles_dir: str = None,
        config=None,
        storage_backend=None,
        enable_monitoring: bool = False,
    ):
        """Initialize ProfileManager

        Args:
            profiles_dir: Directory containing .cfg profile files (optional)
            config: ConfigParser object with IPAthinCA configuration (optional)
            storage_backend: LDAP storage backend for profile persistence
                            (optional)
            enable_monitoring: Enable profile change monitoring thread
                              (default: False - only enabled for production CA)
        """
        # Primary directory: IPA-specific customized profiles
        if profiles_dir is None:
            profiles_dir = "/usr/share/ipa/profiles"
        self.profiles_dir = Path(profiles_dir)

        # Fallback directory: Standard Dogtag PKI profiles
        self.pki_profiles_dir = Path("/usr/share/pki/ca/profiles/ca")

        # Store config for variable context
        self.config = config

        # Store storage backend for LDAP profile storage
        self.storage_backend = storage_backend

        # Profile cache (Profile objects)
        # Thread-safe access via self.lock
        self.profiles = {}

        # Thread safety lock
        # Matches Dogtag's synchronized methods
        self.lock = threading.RLock()

        # Profile aliases mapping (alias_name -> actual_profile_id)
        self.profile_aliases: Dict[str, str] = {
            # caServerCert is alias for service cert
            "caServerCert": "caIPAserviceCert",
        }

        # Profile change monitor thread
        # Matches Dogtag's Monitor inner class
        self.monitor: Optional["ProfileChangeMonitor"] = None

        # Start profile change monitoring if enabled and storage backend
        # available
        if enable_monitoring and storage_backend:
            self._start_monitoring()

    def get_profile(self, profile_id: str, use_cache: bool = True):
        """Get profile from cache, LDAP, or filesystem

        Retrieves profile with intelligent caching:
        1. Check cache first
        2. If not cached, load from LDAP (production)
        3. If not in LDAP, load from filesystem (installation only)

        Thread-safe implementation matching Dogtag's synchronized readProfile()

        Args:
            profile_id: Profile identifier
            use_cache: Whether to use cached profile (default: True)

        Returns:
            Profile object

        Raises:
            ProfileNotFound: If profile not found
        """
        from ipathinca.profile_parser import ProfileParser

        # Validate input profile ID format
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_.-]*$", profile_id):
            raise ValueError(f"Invalid profile ID: {profile_id}")

        # Resolve alias first (e.g., caServerCert -> caIPAserviceCert)
        actual_profile_id = self.profile_aliases.get(profile_id, profile_id)
        if actual_profile_id != profile_id:
            logger.debug(
                "Resolved profile alias: %s -> %s",
                profile_id,
                actual_profile_id,
            )
            # Validate resolved profile ID as well
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9_.-]*$", actual_profile_id):
                raise ValueError(
                    f"Invalid resolved profile ID: {actual_profile_id}"
                )

        # Check cache first (but only if use_cache is True)
        # Thread-safe cache check
        if use_cache:
            with self.lock:
                if actual_profile_id in self.profiles:
                    logger.debug("Using cached profile: %s", actual_profile_id)
                    return self.profiles[actual_profile_id]

        # Build variable context for substitution
        context = self._get_variable_context()

        # Try to load from LDAP (production mode)
        if hasattr(self, "storage_backend") and self.storage_backend:
            try:
                profile_data = self.storage_backend.get_profile(
                    actual_profile_id
                )
                if profile_data and profile_data.get("config"):
                    logger.debug(
                        "Loading profile %s from LDAP", actual_profile_id
                    )
                    # Parse from LDAP-stored .cfg content directly
                    # (no temp file needed — ProfileParser accepts content
                    # string).  A synthetic path is used so that
                    # ProfileParser can extract the profile ID from the
                    # filename when profileId is absent from the .cfg.
                    synthetic_path = f"{actual_profile_id}.cfg"
                    parser = ProfileParser(
                        synthetic_path,
                        content=profile_data["config"],
                    )
                    profile = parser.parse(context)
                    # Override profile_id from parsed data to ensure it
                    # matches what was requested (in case .cfg doesn't
                    # have profileId)
                    profile.profile_id = actual_profile_id

                    # Cache and return (thread-safe)
                    with self.lock:
                        self.profiles[actual_profile_id] = profile
                    logger.debug(
                        "Cached profile from LDAP: %s", actual_profile_id
                    )
                    return profile
                else:
                    logger.warning(
                        "Profile %s not found in LDAP, falling back to "
                        "filesystem (should only happen during installation)",
                        actual_profile_id,
                    )
            except Exception as e:
                logger.warning(
                    "Failed to load profile %s from LDAP: %s",
                    actual_profile_id,
                    e,
                )

        # Fallback to filesystem (should only happen during installation)
        # Check IPA profiles first, then PKI profiles
        ipa_path = self.profiles_dir / f"{actual_profile_id}.cfg"
        pki_path = self.pki_profiles_dir / f"{actual_profile_id}.cfg"

        if ipa_path.exists():
            cfg_path = ipa_path
            logger.debug("Loading profile %s from LDAP", actual_profile_id)
        elif pki_path.exists():
            cfg_path = pki_path
            logger.debug("Loading profile %s from LDAP", actual_profile_id)
        else:
            raise ProfileNotFound(
                f"Profile {actual_profile_id} not found in LDAP, "
                f"{ipa_path}, or {pki_path}"
            )

        # Parse profile
        parser = ProfileParser(str(cfg_path))
        profile = parser.parse(context)

        # Cache and return (thread-safe)
        with self.lock:
            self.profiles[actual_profile_id] = profile
        logger.debug("Cached profile from filesystem: %s", actual_profile_id)
        return profile

    def store_profile_to_ldap(self, profile_id: str):
        """Store profile from filesystem to LDAP

        Reads the .cfg file from filesystem and stores it in LDAP for
        persistence and replication.

        Args:
            profile_id: Profile identifier

        Raises:
            ProfileNotFound: If profile .cfg file not found
            RuntimeError: If storage backend not available
        """
        if not self.storage_backend:
            raise RuntimeError(
                "Cannot store profile to LDAP: No storage backend available"
            )

        # Find .cfg file (check IPA profiles first, then PKI profiles)
        ipa_path = self.profiles_dir / f"{profile_id}.cfg"
        pki_path = self.pki_profiles_dir / f"{profile_id}.cfg"

        if ipa_path.exists():
            cfg_path = ipa_path
        elif pki_path.exists():
            cfg_path = pki_path
        else:
            raise ProfileNotFound(
                f"Profile {profile_id} not found at {ipa_path} or {pki_path}"
            )

        logger.debug(
            "Storing profile %s to LDAP from %s", profile_id, cfg_path
        )

        # Read cfg content
        with open(cfg_path, "r") as f:
            cfg_content = f.read()

        # Parse to get class_id
        from ipathinca.profile_parser import ProfileParser

        context = self._get_variable_context()
        parser = ProfileParser(str(cfg_path))
        profile = parser.parse(context)

        # Store to LDAP
        profile_data = {
            "profile_id": profile_id,
            "class_id": profile.class_id,
            "config": cfg_content,
            "description": profile.description,
        }

        self.storage_backend.store_profile(profile_data)
        logger.debug("Stored profile %s to LDAP", profile_id)

    def store_all_profiles_to_ldap(self):
        """Store required profiles from filesystem to LDAP

        Installs only the profiles needed for IPAthinCA operation.
        IPA-specific profiles (from /usr/share/ipa/profiles/) take priority
        over standard PKI profiles.

        Raises:
            RuntimeError: If storage backend not available
        """
        if not self.storage_backend:
            raise RuntimeError(
                "Cannot store profiles to LDAP: No storage backend available"
            )

        # Build profile map for required profiles only
        # Check IPA profiles first (priority), then PKI profiles (fallback)
        profile_map = {}  # profile_id -> path

        for profile_id in self.REQUIRED_PROFILES:
            ipa_path = self.profiles_dir / f"{profile_id}.cfg"
            pki_path = self.pki_profiles_dir / f"{profile_id}.cfg"

            if ipa_path.exists():
                profile_map[profile_id] = str(ipa_path)
                logger.debug(
                    "Found required profile %s in IPA profiles", profile_id
                )
            elif pki_path.exists():
                profile_map[profile_id] = str(pki_path)
                logger.debug(
                    "Found required profile %s in PKI profiles", profile_id
                )
            else:
                logger.warning(
                    "Required profile %s not found in %s or %s",
                    profile_id,
                    self.profiles_dir,
                    self.pki_profiles_dir,
                )

        if not profile_map:
            logger.warning(
                "No .cfg profile files found in %s or %s",
                self.profiles_dir,
                self.pki_profiles_dir,
            )
            return

        logger.debug(
            "Installing %s profiles from filesystem to LDAP", len(profile_map)
        )
        stored_count = 0
        failed_profiles = []

        # Install profiles in sorted order
        for profile_id in sorted(profile_map.keys()):
            try:
                logger.debug("  Installing profile: %s", profile_id)
                self.store_profile_to_ldap(profile_id)
                stored_count += 1
            except Exception as e:
                logger.error(
                    "  Failed to install profile %s: %s", profile_id, e
                )
                failed_profiles.append(profile_id)

        logger.debug(
            "Installed %s/%s profiles to LDAP", stored_count, len(profile_map)
        )

        if failed_profiles:
            logger.warning(
                "Failed to install profiles: %s", ", ".join(failed_profiles)
            )

    def _get_variable_context(self) -> dict:
        """Build variable substitution context for profiles

        Returns:
            Dictionary of variable names to values

        Raises:
            RuntimeError: If configuration is not available
        """
        # realm and domain must be present in the ipathinca config file
        if not self.config:
            raise RuntimeError(
                "Cannot load profiles: no configuration available. "
                "ProfileManager requires an ipathinca config with "
                "[global] realm and domain set."
            )

        try:
            realm = self.config.get("global", "realm")
            domain = self.config.get("global", "domain")
        except Exception as e:
            raise RuntimeError(
                "Cannot load profiles: [global] realm/domain missing "
                f"from ipathinca config: {e}"
            ) from e

        # Build variable substitution context
        context = {
            "DOMAIN": domain,
            "IPA_CA_RECORD": f"ipa-ca.{domain}",
            "SUBJECT_DN_O": f"O={realm}",
            "CRL_ISSUER": f"CN=Certificate Authority,O={realm}",
            "REALM": realm,
        }
        logger.debug("Profile variable context: %s", context)
        return context

    def has_profile(self, profile_id: str) -> bool:
        """Check if .cfg profile exists

        Checks both IPA profiles directory and PKI profiles directory.

        Args:
            profile_id: Profile identifier

        Returns:
            True if .cfg file exists
        """
        # Check IPA-specific profiles first (priority)
        ipa_path = self.profiles_dir / f"{profile_id}.cfg"
        if ipa_path.exists():
            return True

        # Fall back to standard PKI profiles
        pki_path = self.pki_profiles_dir / f"{profile_id}.cfg"
        return pki_path.exists()

    def clear_profile_cache(self):
        """Clear cached profiles

        This forces profiles to be reloaded with fresh variable context.
        Useful after API bootstrap or configuration changes.
        """
        with self.lock:
            logger.debug(
                "Clearing profile cache (%s profiles)", len(self.profiles)
            )
            self.profiles.clear()

    def _start_monitoring(self):
        """
        Start profile change monitoring thread

        Matches Dogtag's monitor thread initialization (line 117-118)
        """
        try:
            logger.info("Starting profile change monitoring")
            self.monitor = ProfileChangeMonitor(self, self.storage_backend)
            self.monitor.start()
            logger.info("Profile change monitor started successfully")
        except Exception as e:
            logger.warning(
                "Failed to start profile change monitor: %s. Profile "
                "replication will not work until CA restart.",
                e,
            )
            self.monitor = None

    def stop_monitoring(self):
        """
        Stop profile change monitoring thread

        Matches Dogtag's shutdown() method (line 381-385)
        """
        if self.monitor:
            logger.info("Stopping profile change monitor")
            self.monitor.shutdown()
            self.monitor = None
            logger.info("Profile change monitor stopped")

    def invalidate_profile(self, profile_id: str):
        """
        Invalidate cached profile (called by monitor thread)

        Thread-safe method to remove a profile from cache, forcing reload
        on next access.

        Args:
            profile_id: Profile identifier to invalidate
        """
        with self.lock:
            if profile_id in self.profiles:
                del self.profiles[profile_id]
                logger.debug("Invalidated cached profile: %s", profile_id)

    def remove_profile(self, profile_id: str):
        """
        Remove profile from cache (called by monitor thread on DELETE)

        Thread-safe method to remove a deleted profile from cache.

        Args:
            profile_id: Profile identifier to remove
        """
        self.invalidate_profile(profile_id)
        logger.info("Removed deleted profile from cache: %s", profile_id)

    def export_profile_cfg(self, profile_id: str) -> str:
        """Export profile configuration as .cfg file content

        Args:
            profile_id: Profile identifier

        Returns:
            Profile .cfg file content as string

        Raises:
            ProfileNotFound: If profile not found
        """
        if not self.storage_backend:
            raise RuntimeError(
                "No storage backend available for profile export"
            )

        # Get profile from LDAP storage
        cfg_content = self.storage_backend.get_profile_cfg(profile_id)
        logger.info("Exported profile %s (.cfg format)", profile_id)
        return cfg_content

    def update_profile_cfg(self, profile_id: str, cfg_content: str):
        """Update profile configuration from .cfg file content

        Args:
            profile_id: Profile identifier
            cfg_content: New .cfg file content

        Raises:
            ProfileNotFound: If profile not found
            ValueError: If .cfg content is invalid
        """
        if not self.storage_backend:
            raise RuntimeError(
                "No storage backend available for profile update"
            )

        # Parse to validate content (in-memory, no temp file needed)
        from ipathinca.profile_parser import ProfileParser

        parser = ProfileParser(f"{profile_id}.cfg", content=cfg_content)
        parser.parse()  # Validate the content

        # Update in LDAP storage
        self.storage_backend.update_profile_cfg(profile_id, cfg_content)

        # Invalidate cache
        self.invalidate_profile(profile_id)
        logger.info("Updated profile %s from .cfg content", profile_id)

    def create_profile(
        self, profile_id: str, cfg_content: str, description: str = ""
    ):
        """Create new profile from .cfg content

        Args:
            profile_id: New profile identifier
            cfg_content: Profile .cfg file content
            description: Profile description

        Raises:
            ValueError: If .cfg content is invalid or profile already exists
        """
        if not self.storage_backend:
            raise RuntimeError(
                "No storage backend available for profile creation"
            )

        # Parse to validate content (in-memory, no temp file needed)
        from ipathinca.profile_parser import ProfileParser

        parser = ProfileParser(f"{profile_id}.cfg", content=cfg_content)
        parser.parse()  # Validate the content

        # Store in LDAP
        self.storage_backend.create_profile(
            profile_id, cfg_content, description
        )
        logger.info("Created new profile %s from .cfg content", profile_id)

    def delete_profile(self, profile_id: str):
        """Delete profile

        Args:
            profile_id: Profile identifier to delete

        Raises:
            ProfileNotFound: If profile not found
        """
        if not self.storage_backend:
            raise RuntimeError(
                "No storage backend available for profile deletion"
            )

        # Remove from LDAP
        self.storage_backend.delete_profile(profile_id)

        # Remove from cache
        self.remove_profile(profile_id)
        logger.info("Deleted profile %s", profile_id)

    def list_profiles(self, required_only=False):
        """List available certificate profiles

        Args:
            required_only: Only applies during installation (no LDAP storage).
                          If True, only list required profiles to avoid loading
                          100+ PKI profiles from filesystem.
                          If False, list all filesystem profiles.
                          When LDAP storage is available, this parameter is
                          ignored and all LDAP profiles are returned.

        Returns:
            List of Profile objects
        """
        if not self.storage_backend:
            # During installation, no LDAP storage available yet
            if required_only:
                # Only return required profiles that exist
                profile_ids = []
                for profile_id in self.REQUIRED_PROFILES:
                    ipa_path = self.profiles_dir / f"{profile_id}.cfg"
                    pki_path = self.pki_profiles_dir / f"{profile_id}.cfg"
                    if ipa_path.exists() or pki_path.exists():
                        profile_ids.append(profile_id)
            else:
                # List all available filesystem profiles
                profile_ids = []
                for cfg_file in self.profiles_dir.glob("*.cfg"):
                    profile_ids.append(cfg_file.stem)
        else:
            # LDAP storage available - list all profiles in LDAP
            # (required_only is ignored; LDAP only contains explicitly
            # stored profiles)
            profile_ids = self.storage_backend.list_profiles()

        # Load each profile
        profiles = []
        for profile_id in profile_ids:
            try:
                profile = self.get_profile(profile_id)
                profiles.append(profile)
            except Exception as e:
                logger.warning("Failed to load profile %s: %s", profile_id, e)

        return profiles

    def get_profile_for_signing(self, profile_id: str):
        """Get profile for certificate signing

        Args:
            profile_id: Profile identifier

        Returns:
            Profile object

        Raises:
            ProfileNotFound: If profile not found
        """
        # Resolve alias
        actual_profile_id = self.profile_aliases.get(profile_id, profile_id)

        # Load profile from LDAP or filesystem
        if not self.has_profile(actual_profile_id):
            raise ProfileNotFound(f"Profile {profile_id} not found")

        logger.debug("Using profile for signing: %s", actual_profile_id)
        return self.get_profile(actual_profile_id)

    def get_extensions_for_profile(self, profile_id: str):
        """Get certificate extensions from profile (for legacy PythonCA)

        This method exists for backwards compatibility with PythonCA class.
        For new code using CAInternal, the policy chain is executed instead.

        Args:
            profile_id: Profile identifier

        Returns:
            List of x509.Extension objects

        Note:
            This is a simplified implementation that extracts basic extensions.
            For full policy chain execution, use CAInternal instead of
            PythonCA.
        """
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        profile = self.get_profile(profile_id)
        extensions = []

        # Extract extensions from profile policies
        for policy in profile.policies:
            default = policy.default

            # BasicConstraints
            if hasattr(default, "is_ca"):
                path_len = getattr(default, "path_length", None)
                ext = x509.Extension(
                    oid=ExtensionOID.BASIC_CONSTRAINTS,
                    critical=True,
                    value=x509.BasicConstraints(
                        ca=default.is_ca, path_length=path_len
                    ),
                )
                extensions.append(ext)

            # KeyUsage
            if hasattr(default, "digital_signature"):
                # This is KeyUsageExtDefault
                key_usage = x509.KeyUsage(
                    digital_signature=getattr(
                        default, "digital_signature", False
                    ),
                    content_commitment=getattr(
                        default, "non_repudiation", False
                    ),
                    key_encipherment=getattr(
                        default, "key_encipherment", False
                    ),
                    data_encipherment=getattr(
                        default, "data_encipherment", False
                    ),
                    key_agreement=getattr(default, "key_agreement", False),
                    key_cert_sign=getattr(default, "key_cert_sign", False),
                    crl_sign=getattr(default, "crl_sign", False),
                    encipher_only=getattr(default, "encipher_only", False),
                    decipher_only=getattr(default, "decipher_only", False),
                )
                critical = getattr(default, "critical", True)
                ext = x509.Extension(
                    oid=ExtensionOID.KEY_USAGE,
                    critical=critical,
                    value=key_usage,
                )
                extensions.append(ext)

            # ExtendedKeyUsage
            if hasattr(default, "eku_oids"):
                # This is ExtendedKeyUsageExtDefault
                from cryptography.x509.oid import ObjectIdentifier

                oids = [ObjectIdentifier(oid) for oid in default.eku_oids]
                critical = getattr(default, "critical", False)
                ext = x509.Extension(
                    oid=ExtensionOID.EXTENDED_KEY_USAGE,
                    critical=critical,
                    value=x509.ExtendedKeyUsage(oids),
                )
                extensions.append(ext)

        return extensions

    def validate_profile_for_csr(self, profile_id: str, csr) -> bool:
        """Validate CSR against profile constraints

        Args:
            profile_id: Profile identifier
            csr: Certificate signing request (cryptography object)

        Returns:
            True if valid

        Raises:
            ValueError: If validation fails (with error details)
            ProfileNotFound: If profile not found
        """
        # Load the profile
        profile = self.get_profile(profile_id)

        # Build validation context
        context = self._get_variable_context()
        context["request"] = {
            "csr": csr,
        }

        # Run constraint validations
        errors = profile.validate_csr(csr, context)

        if errors:
            error_msg = f"CSR validation failed for profile {profile_id}:\n"
            error_msg += "\n".join(f"  - {err}" for err in errors)
            raise ValueError(error_msg)

        return True
