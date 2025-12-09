# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Certificate profile management for Python CA
"""

import logging
from pathlib import Path
from typing import Dict

from ipathinca.exceptions import ProfileNotFound

logger = logging.getLogger(__name__)


class ProfileManager:
    """Manages certificate profiles"""

    # Whitelist of required profiles for IPAthinCA
    # Only these profiles are installed to LDAP during deployment
    REQUIRED_PROFILES = [
        "caIPAserviceCert",  # IPA service certificates
        "IECUserRoles",  # User certificates with IEC roles
        "KDCs_PKINIT_Certs",  # Kerberos KDC PKINIT
        "acmeIPAServerCert",  # ACME-issued server certificates
        "caSubsystemCert",  # CA subsystem certificates
        "caOCSPCert",  # OCSP responder certificates
        "caSignedLogCert",  # Audit log signing certificates
    ]

    def __init__(
        self, profiles_dir: str = None, config=None, storage_backend=None
    ):
        """Initialize ProfileManager

        Args:
            profiles_dir: Directory containing .cfg profile files (optional)
            config: ConfigParser object with IPAthinCA configuration (optional)
            storage_backend: LDAP storage backend for profile persistence
                            (optional)
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
        self.profiles = {}

        # Profile aliases mapping (alias_name -> actual_profile_id)
        self.profile_aliases: Dict[str, str] = {
            # caServerCert is alias for service cert
            "caServerCert": "caIPAserviceCert",
        }

    def get_profile(self, profile_id: str, use_cache: bool = True):
        """Get profile from cache, LDAP, or filesystem

        Retrieves profile with intelligent caching:
        1. Check cache first
        2. If not cached, load from LDAP (production)
        3. If not in LDAP, load from filesystem (installation only)

        Args:
            profile_id: Profile identifier
            use_cache: Whether to use cached profile (default: True)

        Returns:
            Profile object

        Raises:
            ProfileNotFound: If profile not found
        """
        from ipathinca.profile_parser import ProfileParser

        # Resolve alias first (e.g., caServerCert -> caIPAserviceCert)
        actual_profile_id = self.profile_aliases.get(profile_id, profile_id)
        if actual_profile_id != profile_id:
            logger.debug(
                f"Resolved profile alias: {profile_id} -> {actual_profile_id}"
            )

        # Check cache first (but only if use_cache is True)
        if use_cache and actual_profile_id in self.profiles:
            logger.debug(f"Using cached profile: {actual_profile_id}")
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
                        f"Loading profile {actual_profile_id} from LDAP"
                    )
                    # Parse from LDAP-stored .cfg content
                    import tempfile

                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".cfg", delete=False
                    ) as tmp:
                        tmp.write(profile_data["config"])
                        tmp_path = tmp.name

                    try:
                        parser = ProfileParser(tmp_path)
                        profile = parser.parse(context)
                    finally:
                        import os

                        os.unlink(tmp_path)

                    # Cache and return
                    self.profiles[actual_profile_id] = profile
                    logger.debug(
                        f"Cached profile from LDAP: {actual_profile_id}"
                    )
                    return profile
                else:
                    logger.warning(
                        f"Profile {actual_profile_id} not found in LDAP, "
                        f"falling back to filesystem (should only happen "
                        f"during installation)"
                    )
            except Exception as e:
                logger.warning(
                    f"Failed to load profile {actual_profile_id} from LDAP: "
                    f"{e}, falling back to filesystem (should only happen "
                    f"during installation)"
                )

        # Fallback to filesystem (should only happen during installation)
        # Check IPA profiles first, then PKI profiles
        ipa_path = self.profiles_dir / f"{actual_profile_id}.cfg"
        pki_path = self.pki_profiles_dir / f"{actual_profile_id}.cfg"

        if ipa_path.exists():
            cfg_path = ipa_path
            logger.debug(
                f"Loading profile {actual_profile_id} from IPA profiles "
                f"(installation mode)"
            )
        elif pki_path.exists():
            cfg_path = pki_path
            logger.debug(
                f"Loading profile {actual_profile_id} from PKI profiles "
                f"(installation mode)"
            )
        else:
            raise ProfileNotFound(
                f"Profile {actual_profile_id} not found in LDAP, "
                f"{ipa_path}, or {pki_path}"
            )

        # Parse profile
        parser = ProfileParser(str(cfg_path))
        profile = parser.parse(context)

        # Cache and return
        self.profiles[actual_profile_id] = profile
        logger.debug(f"Cached profile from filesystem: {actual_profile_id}")
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

        logger.debug(f"Storing profile {profile_id} to LDAP from {cfg_path}")

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
        logger.debug(f"Stored profile {profile_id} to LDAP")

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
                    f"Found required profile {profile_id} in IPA profiles"
                )
            elif pki_path.exists():
                profile_map[profile_id] = str(pki_path)
                logger.debug(
                    f"Found required profile {profile_id} in PKI profiles"
                )
            else:
                logger.warning(
                    f"Required profile {profile_id} not found in "
                    f"{self.profiles_dir} or {self.pki_profiles_dir}"
                )

        if not profile_map:
            logger.warning(
                f"No .cfg profile files found in {self.profiles_dir} "
                f"or {self.pki_profiles_dir}"
            )
            return

        logger.debug(
            f"Installing {len(profile_map)} profiles from filesystem "
            f"to LDAP"
        )
        stored_count = 0
        failed_profiles = []

        # Install profiles in sorted order
        for profile_id in sorted(profile_map.keys()):
            try:
                logger.debug(f"  Installing profile: {profile_id}")
                self.store_profile_to_ldap(profile_id)
                stored_count += 1
            except Exception as e:
                logger.error(f"  Failed to install profile {profile_id}: {e}")
                failed_profiles.append(profile_id)

        logger.debug(
            f"Installed {stored_count}/{len(profile_map)} profiles " f"to LDAP"
        )

        if failed_profiles:
            logger.warning(
                f"Failed to install profiles: {', '.join(failed_profiles)}"
            )

    def _get_variable_context(self) -> dict:
        """Build variable substitution context for profiles

        Returns:
            Dictionary of variable names to values

        Raises:
            RuntimeError: If configuration is not available
        """
        # Try to get realm and domain from config first
        realm = None
        domain = None

        if self.config:
            try:
                # Read from ipathinca.conf [global] section
                realm = self.config.get("global", "realm")
                domain = self.config.get("global", "domain")
            except Exception:
                pass

        # Fall back to IPA API if config not available (e.g., during
        # installation)
        if not realm or not domain:
            try:
                from ipalib import api

                if api.isdone("bootstrap"):
                    realm = api.env.realm
                    domain = api.env.domain
            except Exception:
                pass

        # If still not available, raise error
        if not realm or not domain:
            raise RuntimeError(
                "Cannot load profiles: No configuration provided. "
                "ProfileManager requires realm and domain to be available "
                "from config or IPA API."
            )

        # Build variable substitution context
        context = {
            "DOMAIN": domain,
            "IPA_CA_RECORD": f"ipa-ca.{domain}",
            "SUBJECT_DN_O": f"O={realm}",
            "CRL_ISSUER": f"CN=Certificate Authority,O={realm}",
            "REALM": realm,
        }
        logger.debug(f"Profile variable context: {context}")
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
        logger.debug(
            f"Clearing profile cache ({len(self.profiles)} " "profiles)"
        )
        self.profiles.clear()

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

        logger.debug(f"Using profile for signing: {actual_profile_id}")
        return self.get_profile(actual_profile_id)

    def list_profiles(self):
        """List all available certificate profiles

        Returns:
            List of Profile objects
        """
        if not self.storage_backend:
            # During installation, only list required profiles
            # This prevents attempting to load all 100+ PKI profiles

            # Only return profiles that exist
            profile_ids = []
            for profile_id in self.REQUIRED_PROFILES:
                ipa_path = self.profiles_dir / f"{profile_id}.cfg"
                pki_path = self.pki_profiles_dir / f"{profile_id}.cfg"
                if ipa_path.exists() or pki_path.exists():
                    profile_ids.append(profile_id)
        else:
            # Query LDAP for profile IDs
            profile_ids = self.storage_backend.list_profiles()

        # Load each profile
        profiles = []
        for profile_id in profile_ids:
            try:
                profile = self.get_profile(profile_id)
                profiles.append(profile)
            except Exception as e:
                logger.warning(f"Failed to load profile {profile_id}: {e}")

        return profiles

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
