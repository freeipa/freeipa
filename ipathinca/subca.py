# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Sub-CA Support for Python CA

This module implements subordinate Certificate Authority functionality,
allowing creation of CA hierarchies similar to Dogtag PKI.
"""

import logging
import datetime
import threading
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
import ldap as ldap_module

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID

try:
    from cachetools import TTLCache

    CACHETOOLS_AVAILABLE = True
except ImportError:
    CACHETOOLS_AVAILABLE = False

from ipalib import errors
from ipathinca import get_config_value
from ipapython.dn import DN
from ipathinca.ca import PythonCA, CertificateRequest, CertificateRecord
from ipathinca.hsm import HSMConfig, HSMKeyBackend, HSMPrivateKeyProxy
from ipaplatform.paths import paths
from ipathinca.ldap_utils import get_ldap_connection, is_internal_token
from ipathinca.exceptions import StorageConnectionError

from ipathinca.key_encryption import encrypt_private_key, decrypt_private_key
from ipathinca.x509_utils import (
    ipa_dn_to_x509_name,
    get_ca_key_usage_extension,
    get_subject_dn_str,
    get_issuer_dn_str,
)

logger = logging.getLogger(__name__)


class SubCA:
    """
    Subordinate Certificate Authority

    Represents a sub-CA in the CA hierarchy. Sub-CAs can issue certificates
    but are subordinate to a parent CA.
    """

    def __init__(
        self,
        ca_id: str,
        subject_dn: str,
        parent_ca: Optional["SubCA"] = None,
        ca_cert: Optional[x509.Certificate] = None,
        ca_key: Optional[rsa.RSAPrivateKey] = None,
    ):
        """
        Initialize Sub-CA

        Args:
            ca_id: Unique identifier for this CA
            subject_dn: Subject DN for the CA certificate
            parent_ca: Parent CA (None for root CA)
            ca_cert: CA certificate (if already exists)
            ca_key: CA private key (if already exists)
        """
        self.ca_id = ca_id
        self.subject_dn = subject_dn
        self.parent_ca = parent_ca
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.enabled = True

        # Storage paths
        # Store sub-CAs in certs directory with CA ID subdirectory
        subcas_base = Path(paths.IPATHINCA_SUBCAS_DIR)
        self.storage_path = subcas_base / ca_id
        self.cert_path = self.storage_path / "ca.crt"
        self.key_path = self.storage_path / "ca.key"

        # Create PythonCA instance for this sub-CA
        if ca_cert and ca_key:
            self.ca = PythonCA(str(self.cert_path), str(self.key_path), ca_id)
            self.ca.ca_cert = ca_cert
            self.ca.ca_private_key = ca_key
        else:
            self.ca = None

    def create(
        self,
        key_size: int = 2048,
        validity_days: int = 3650,
        path_length: Optional[int] = 0,
    ) -> x509.Certificate:
        """
        Create new sub-CA certificate and key

        Args:
            key_size: RSA key size
            validity_days: Validity period in days
            path_length: Maximum path length for sub-CAs (None = unlimited)

        Returns:
            CA certificate
        """
        logger.debug(f"Creating sub-CA: {self.ca_id}")

        # Generate private key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Parse subject DN using shared utility
        subject = ipa_dn_to_x509_name(self.subject_dn)

        # Build certificate
        now = datetime.datetime.now(datetime.timezone.utc)
        serial_number = int(uuid.uuid4().hex[:16], 16)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.public_key(self.ca_key.public_key())
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(
            now + datetime.timedelta(days=validity_days)
        )

        # Set issuer (parent CA or self for root)
        if self.parent_ca and self.parent_ca.ca_cert:
            builder = builder.issuer_name(self.parent_ca.ca_cert.subject)
            signing_key = self.parent_ca.ca_key
        else:
            # Self-signed root CA
            builder = builder.issuer_name(subject)
            signing_key = self.ca_key

        # Add CA extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )

        # Use shared CA KeyUsage extension utility
        builder = builder.add_extension(
            get_ca_key_usage_extension(), critical=True
        )

        # Subject Key Identifier
        ski = x509.SubjectKeyIdentifier.from_public_key(
            self.ca_key.public_key()
        )
        builder = builder.add_extension(ski, critical=False)

        # Authority Key Identifier
        if self.parent_ca and self.parent_ca.ca_cert:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.parent_ca.ca_cert.public_key()
            )
        else:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.ca_key.public_key()
            )
        builder = builder.add_extension(aki, critical=False)

        # Sign the certificate
        self.ca_cert = builder.sign(signing_key, hashes.SHA256())

        # Save to disk (skip if permission denied - LDAP storage is primary)
        try:
            self._save_to_disk()
        except (PermissionError, OSError) as e:
            logger.warning(
                f"Could not save sub-CA {self.ca_id} to disk "
                f"(will use LDAP only): {e}"
            )
            # Continue without disk storage - LDAP is primary storage

        # Initialize PythonCA instance
        # Use LDAP storage for the sub-CA
        self.ca = PythonCA(str(self.cert_path), str(self.key_path), self.ca_id)
        self.ca.ca_cert = self.ca_cert
        self.ca.ca_private_key = self.ca_key

        logger.debug(f"Sub-CA created successfully: {self.ca_id}")

        return self.ca_cert

    def _save_to_disk(self):
        """Save CA certificate and key to disk"""
        # Create storage directory
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o750)

        # Save certificate
        with open(self.cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        # Save private key
        with open(self.key_path, "wb") as f:
            f.write(
                self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Set restrictive permissions
        self.key_path.chmod(0o600)
        self.cert_path.chmod(0o644)

    def load_from_disk(self, storage_backend=None):
        """Load CA certificate and key from disk or HSM

        This method follows Dogtag's pattern for conditional key loading:
        - Check HSM configuration from LDAP
        - If HSM enabled: use HSMPrivateKeyProxy
        - If HSM disabled: load from PEM file

        Args:
            storage_backend: Optional storage backend for HSM config lookup
                           (will try to find main CA's storage if not provided)
        """
        if not self.cert_path.exists():
            raise errors.NotFound(
                reason=f"Sub-CA {self.ca_id} certificate not found on disk"
            )

        # Load certificate (always from disk for ipathinca)
        with open(self.cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

        # Load private key - conditional based on HSM configuration
        hsm_config = None

        # Try to get HSM config from storage backend
        if storage_backend is None:
            # Try to find storage backend from parent CA chain
            current = self
            while current.parent_ca is not None:
                current = current.parent_ca
            # If parent CA has storage, use it
            if hasattr(current, "ca") and hasattr(current.ca, "storage"):
                storage_backend = current.ca.storage

        if storage_backend and hasattr(storage_backend, "get_hsm_config"):
            try:
                hsm_config = storage_backend.get_hsm_config(self.ca_id)
            except Exception as e:
                logger.debug(
                    f"Could not retrieve HSM config for sub-CA "
                    f"{self.ca_id}: {e}"
                )
                hsm_config = None

        # Check if HSM is enabled for this sub-CA
        if hsm_config and hsm_config.get("enabled"):
            # HSM path - use HSMPrivateKeyProxy
            logger.debug(
                f"Loading sub-CA private key from HSM for {self.ca_id}"
            )

            token_name = hsm_config.get("token_name")
            if not token_name:
                raise errors.CertificateOperationError(
                    error=(
                        f"HSM enabled for sub-CA {self.ca_id} but "
                        "token_name is not configured"
                    )
                )

            # Verify this is not an internal token (Dogtag validation)
            if is_internal_token(token_name):
                logger.error(
                    f"HSM enabled for sub-CA {self.ca_id} but token_name is "
                    f"internal: {token_name}"
                )
                raise errors.CertificateOperationError(
                    error=(
                        f"HSM configuration invalid for sub-CA {self.ca_id}: "
                        "token_name cannot be 'internal' when HSM is enabled"
                    )
                )

            # Initialize HSM backend
            hsm = HSMKeyBackend(HSMConfig(hsm_config))

            # Key label follows Dogtag pattern: {ca_id}_signing
            key_label = f"{self.ca_id}_signing"

            # Create proxy that implements private key interface
            self.ca_key = HSMPrivateKeyProxy(hsm, key_label)

            logger.debug(
                f"Successfully loaded sub-CA certificate and HSM private key "
                f"(token={token_name}, label={key_label})"
            )
        else:
            # File path - load from PEM file
            if not self.key_path.exists():
                raise errors.NotFound(
                    reason=f"Sub-CA {self.ca_id} private key not found on disk"
                )

            logger.debug(
                f"Loading sub-CA private key from file for {self.ca_id}"
            )

            with open(self.key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )

            logger.debug(
                "Successfully loaded sub-CA certificate and private key from "
                "files"
            )

        # Initialize PythonCA instance
        self.ca = PythonCA(str(self.cert_path), str(self.key_path), self.ca_id)
        self.ca.ca_cert = self.ca_cert
        self.ca.ca_private_key = self.ca_key

    def get_certificate_chain(self) -> List[x509.Certificate]:
        """
        Get certificate chain from this CA to root

        Returns:
            List of certificates (leaf to root)
        """
        chain = [self.ca_cert]

        current_ca = self.parent_ca
        while current_ca:
            chain.append(current_ca.ca_cert)
            current_ca = current_ca.parent_ca

        return chain

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "ca_id": self.ca_id,
            "subject_dn": self.subject_dn,
            "parent_ca_id": self.parent_ca.ca_id if self.parent_ca else None,
            "enabled": self.enabled,
            "serial_number": (
                str(self.ca_cert.serial_number) if self.ca_cert else None
            ),
            "not_before": (
                self.ca_cert.not_valid_before_utc.isoformat()
                if self.ca_cert
                else None
            ),
            "not_after": (
                self.ca_cert.not_valid_after_utc.isoformat()
                if self.ca_cert
                else None
            ),
        }


class SubCAManager:
    """
    Manager for Sub-CAs

    Handles creation, storage, and retrieval of sub-CAs with LDAP backend.
    Uses TTLCache to prevent memory leaks from unbounded cache growth.
    """

    def __init__(self, main_ca=None, cache_maxsize=100, cache_ttl=300):
        """
        Initialize SubCA Manager with bounded TTL cache

        Args:
            main_ca: Reference to main IPA CA
            cache_maxsize: Maximum number of entries in cache (default: 100)
            cache_ttl: Time-to-live for cache entries in seconds (default:
                       300 = 5 minutes)
        """
        if CACHETOOLS_AVAILABLE:
            self.subcas = TTLCache(maxsize=cache_maxsize, ttl=cache_ttl)
            self.cache_timestamps = TTLCache(
                maxsize=cache_maxsize, ttl=cache_ttl
            )
            logger.debug(
                "Initialized SubCA cache with "
                f"maxsize={cache_maxsize}, ttl={cache_ttl}s"
            )
        else:
            logger.warning(
                "cachetools not available, using unbounded dict cache"
            )
            self.subcas: Dict[str, SubCA] = {}
            self.cache_timestamps: Dict[str, datetime.datetime] = {}

        basedn = get_config_value("global", "basedn")
        self.ldap_base_dn = DN(("cn", "cas"), ("cn", "ca"), basedn)
        self.main_ca = main_ca  # Reference to main IPA CA
        self._cache_lock = threading.RLock()

    def _get_ldap_connection(self):
        """Get LDAP connection using shared utility with pooling

        Returns:
            Context manager for pooled LDAP connection (use with 'with'
            statement)
        """
        try:
            # Use pooled connections for performance
            return get_ldap_connection(use_pool=True)
        except Exception as e:
            logger.error(
                f"SubCAManager: Failed to get LDAP connection: {e}",
                exc_info=True,
            )
            raise StorageConnectionError(
                f"Cannot connect to LDAP database for sub-CA operations: {e}"
            )

    def _parse_ldap_timestamp(self, timestamp_value) -> datetime.datetime:
        """Parse LDAP generalized time format to datetime

        LDAP timestamps can be either:
        - datetime.datetime objects (already parsed by python-ldap)
        - String format: "20251021123437Z" (YYYYMMDDHHMMSSz)

        Args:
            timestamp_value: LDAP timestamp (str or datetime.datetime)

        Returns:
            datetime object with UTC timezone
        """
        if not timestamp_value:
            return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

        # If already a datetime object, just ensure it has timezone
        if isinstance(timestamp_value, datetime.datetime):
            if timestamp_value.tzinfo is None:
                return timestamp_value.replace(tzinfo=datetime.timezone.utc)
            return timestamp_value

        # Otherwise parse string format
        try:
            # Parse LDAP generalized time: "20251021123437Z"
            return datetime.datetime.strptime(
                timestamp_value, "%Y%m%d%H%M%SZ"
            ).replace(tzinfo=datetime.timezone.utc)
        except (ValueError, TypeError) as e:
            logger.warning(
                f"Failed to parse LDAP timestamp '{timestamp_value}': {e}"
            )
            return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

    def _get_ldap_modify_timestamp(self, ca_id: str) -> datetime.datetime:
        """Get modifyTimestamp from LDAP for cache validation

        This performs a lightweight LDAP query fetching only operational
        attributes (modifyTimestamp, createTimestamp) to validate cache
        without loading the entire entry.

        Args:
            ca_id: CA identifier

        Returns:
            datetime of last modification, or datetime.max if entry not found
        """
        with self._get_ldap_connection() as ldap:
            ca_dn = DN(("cn", ca_id), self.ldap_base_dn)

            try:
                # Lightweight query: only fetch operational attributes
                entry = ldap.get_entry(
                    ca_dn, attrs_list=["modifyTimestamp", "createTimestamp"]
                )

                # modifyTimestamp format: "20251021123437Z" (LDAP generalized
                # time)
                timestamp_str = entry.get("modifyTimestamp", [None])[0]
                if not timestamp_str:
                    # Fall back to createTimestamp if no modifications yet
                    timestamp_str = entry.get("createTimestamp", [None])[0]

                return self._parse_ldap_timestamp(timestamp_str)

            except errors.NotFound:
                # Entry deleted from LDAP - cache is stale
                logger.debug(
                    f"Sub-CA {ca_id} not found in LDAP, cache is stale"
                )
                return datetime.datetime.max.replace(
                    tzinfo=datetime.timezone.utc
                )
            except Exception as e:
                logger.warning(
                    f"Failed to get LDAP timestamp for {ca_id}: {e}"
                )
                # On error, assume stale to be safe
                return datetime.datetime.max.replace(
                    tzinfo=datetime.timezone.utc
                )

    def _is_cache_valid(self, ca_id: str) -> bool:
        """Check if cached sub-CA is still fresh by comparing LDAP
        modifyTimestamp

        Performs a lightweight LDAP query to fetch only the modifyTimestamp
        and compares it with the cached timestamp. Cache is valid if LDAP
        timestamp hasn't changed since we cached the entry.

        Args:
            ca_id: CA identifier

        Returns:
            True if cache is still valid, False if stale
        """
        if ca_id not in self.cache_timestamps:
            logger.debug(f"No cached timestamp for {ca_id}, cache invalid")
            return False

        try:
            ldap_timestamp = self._get_ldap_modify_timestamp(ca_id)
            cache_timestamp = self.cache_timestamps[ca_id]

            # Cache is valid if LDAP timestamp hasn't changed
            is_valid = ldap_timestamp <= cache_timestamp

            if not is_valid:
                logger.debug(
                    f"Cache stale for {ca_id}: "
                    f"LDAP={ldap_timestamp.isoformat()} > "
                    f"cache={cache_timestamp.isoformat()}"
                )

            return is_valid

        except Exception as e:
            logger.warning(f"Failed to validate cache for {ca_id}: {e}")
            return False  # On error, invalidate cache (safe)

    def initialize_ldap_schema(self):
        """Initialize LDAP schema for sub-CA storage"""
        with self._get_ldap_connection() as ldap:

            # Create cas container
            try:
                entry = ldap.get_entry(self.ldap_base_dn)
            except errors.NotFound:
                logger.debug(f"Creating sub-CA container: {self.ldap_base_dn}")
                entry = ldap.make_entry(
                    self.ldap_base_dn,
                    objectclass=["top", "nsContainer"],
                    cn=["cas"],
                )
                ldap.add_entry(entry)
                # Reload entry after creation to add ACI
                entry = ldap.get_entry(self.ldap_base_dn)

            # Add ACI to allow ipacasrv system account to manage sub-CAs
            # This ACI allows the ipathinca service (running as ipacasrv) to
            # create, read, modify, and delete sub-CA entries
            aci_name = "Allow ipacasrv to manage sub-CAs"
            basedn = get_config_value("global", "basedn")
            ipacasrv_dn = DN(
                ("uid", "ipacasrv"),
                ("cn", "sysaccounts"),
                ("cn", "etc"),
                basedn,
            )

            # Check if ACI already exists
            dn = DN(("cn", "*"), self.ldap_base_dn)
            aci_target = f'(target = "ldap:///{dn}")'
            aci_exists = False

            if "aci" in entry:
                for existing_aci in entry.get("aci", []):
                    if aci_name in str(existing_aci):
                        aci_exists = True
                        logger.debug(f"ACI '{aci_name}' already exists")
                        break

            if not aci_exists:
                logger.debug(f"Adding ACI '{aci_name}' to {self.ldap_base_dn}")
                aci_value = (
                    f"{aci_target}"
                    '(targetattr = "*")'
                    "(version 3.0;"
                    f'acl "{aci_name}";'
                    "allow (read,search,compare,add,delete,write) "
                    f'userdn = "ldap:///{ipacasrv_dn}";)'
                )

                # Add the ACI to the container
                try:
                    ldap.conn.modify_s(
                        str(self.ldap_base_dn),
                        [
                            (
                                ldap_module.MOD_ADD,
                                "aci",
                                [aci_value.encode("utf-8")],
                            )
                        ],
                    )
                    logger.debug(
                        "Successfully added ACI for ipacasrv to manage sub-CAs"
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to add ACI (may already exist): {e}"
                    )

    def create_subca(
        self,
        ca_id: str,
        subject_dn: str,
        parent_ca_id: Optional[str] = None,
        key_size: int = 2048,
        validity_days: int = 3650,
    ) -> SubCA:
        """
        Create new sub-CA

        Args:
            ca_id: Unique identifier for the CA
            subject_dn: Subject DN for CA certificate
            parent_ca_id: Parent CA identifier (None for root)
            key_size: RSA key size
            validity_days: Validity period in days

        Returns:
            SubCA instance
        """
        logger.debug(f"Creating sub-CA {ca_id} under parent {parent_ca_id}")

        # Get parent CA if specified, otherwise use main CA
        parent_ca = None
        if parent_ca_id:
            parent_ca = self.get_subca(parent_ca_id)
            if not parent_ca:
                raise errors.NotFound(
                    reason=f"Parent CA {parent_ca_id} not found"
                )
        else:
            # Use main IPA CA as parent - create a temporary SubCA wrapper "
            # for it
            if not self.main_ca:
                raise errors.ExecutionError(
                    message="Main CA not available - cannot create sub-CA"
                )

            # Load main CA cert and key on demand
            # This loads from disk only when needed for sub-CA creation
            self.main_ca._ensure_ca_loaded()

            # Convert main CA cert subject to IPA DN format (not RFC4514)
            # This prevents backslash escaping issues
            main_ca_subject_dn = get_subject_dn_str(self.main_ca.ca_cert)

            # Create a SubCA wrapper for the main CA to use as parent
            parent_ca = SubCA(
                ca_id="ipa",
                subject_dn=main_ca_subject_dn,  # FIXED: Use IPA DN format
                parent_ca=None,
                ca_cert=self.main_ca.ca_cert,
                ca_key=self.main_ca.ca_private_key,
            )

        # Create sub-CA
        subca = SubCA(ca_id, subject_dn, parent_ca)

        # Determine path length (parent's path_length - 1)
        path_length = 0
        if parent_ca and parent_ca.ca_cert:
            # Extract path length from parent
            try:
                bc_ext = parent_ca.ca_cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                )
                parent_path_length = bc_ext.value.path_length
                if parent_path_length is not None:
                    path_length = max(0, parent_path_length - 1)
                else:
                    path_length = None  # Unlimited
            except x509.ExtensionNotFound:
                path_length = 0

        # Create certificate and key
        subca.create(key_size, validity_days, path_length)

        # Store in LDAP
        self._store_subca_in_ldap(subca)

        # Cache in memory with current LDAP timestamp
        with self._cache_lock:
            self.subcas[ca_id] = subca
            self.cache_timestamps[ca_id] = self._get_ldap_modify_timestamp(
                ca_id
            )
            logger.debug(
                f"Cached new sub-CA {ca_id} with timestamp "
                f"{self.cache_timestamps[ca_id].isoformat()}"
            )

        return subca

    def get_subca(
        self, ca_id: str, force_reload: bool = False
    ) -> Optional[SubCA]:
        """
        Get sub-CA by ID with timestamp-based cache validation

        Uses LDAP modifyTimestamp to detect changes from other servers
        (replication).
        Cache is automatically invalidated if the LDAP entry has been modified
        since we cached it.

        Args:
            ca_id: CA identifier
            force_reload: If True, bypass cache and reload from LDAP

        Returns:
            SubCA instance or None
        """
        # Ensure ca_id is a string, not a tuple
        if isinstance(ca_id, tuple):
            ca_id = ca_id[0]

        with self._cache_lock:
            # Check memory cache first (unless force_reload is True)
            if not force_reload and ca_id in self.subcas:
                # Validate cache using LDAP modifyTimestamp
                if self._is_cache_valid(ca_id):
                    logger.debug(
                        f"Cache hit for sub-CA {ca_id} (validated via "
                        "timestamp)"
                    )
                    return self.subcas[ca_id]
                else:
                    # Cache is stale, invalidate it
                    logger.debug(
                        f"Cache invalidated for sub-CA {ca_id} "
                        "(LDAP modified)"
                    )
                    del self.subcas[ca_id]
                    if ca_id in self.cache_timestamps:
                        del self.cache_timestamps[ca_id]

            # Load from LDAP under lock to prevent concurrent duplicate loads
            subca = self._load_subca_from_ldap(ca_id)

            if subca:
                # Cache in memory with current LDAP timestamp
                self.subcas[ca_id] = subca
                self.cache_timestamps[ca_id] = self._get_ldap_modify_timestamp(
                    ca_id
                )
                logger.debug(
                    f"Cached sub-CA {ca_id} with timestamp "
                    f"{self.cache_timestamps[ca_id].isoformat()}"
                )
                return subca

        return None

    def list_subcas(self) -> List[SubCA]:
        """
        List all sub-CAs

        Returns:
            List of SubCA instances (only those that can be successfully
                                     loaded)
        """
        with self._get_ldap_connection() as ldap:

            try:
                # Only query sub-CAs that have the ipathincaca objectClass
                # This filters out old Dogtag sub-CAs that ipathinca cannot
                # load
                # OPTIMIZED: Only fetch ipaCaId for listing sub-CAs
                entries = ldap.get_entries(
                    self.ldap_base_dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    filter="(&(objectClass=ipaca)(objectClass=ipathincaca))",
                    attrs_list=["ipaCaId"],  # Only need the CA ID for listing
                )

                subcas = []
                for entry in entries:
                    ca_id_list = entry.get("ipaCaId", [])
                    if not ca_id_list:
                        logger.warning(
                            "Sub-CA entry %s missing ipaCaId, skipping",
                            entry.dn,
                        )
                        continue
                    ca_id = ca_id_list[0]
                    # Skip the main IPA CA
                    if ca_id == "ipa":
                        continue

                    # Try to load the sub-CA, but skip if it fails
                    # This handles old Dogtag sub-CAs that may have incomplete
                    # data
                    try:
                        subca = self.get_subca(ca_id)
                        if subca:
                            subcas.append(subca)
                    except Exception as e:
                        logger.warning(
                            f"Skipping sub-CA {ca_id} that cannot be "
                            f"loaded: {e}"
                        )
                        continue

                return subcas

            except errors.NotFound:
                return []

    def delete_subca(self, ca_id: str):
        """
        Delete sub-CA (includes LDAP deletion and filesystem cleanup)

        Args:
            ca_id: CA identifier
        """
        # Ensure ca_id is a string, not a tuple
        if isinstance(ca_id, tuple):
            ca_id = ca_id[0]

        logger.debug(f"Deleting sub-CA: {ca_id}")

        # Remove from LDAP
        self._delete_subca_from_ldap(ca_id)

        # Remove from memory cache
        with self._cache_lock:
            self.subcas.pop(ca_id, None)
            self.cache_timestamps.pop(ca_id, None)

        # Remove files from disk
        subcas_base = Path(paths.IPATHINCA_SUBCAS_DIR)
        subca_dir = subcas_base / ca_id

        if subca_dir.exists():
            try:
                import shutil

                shutil.rmtree(subca_dir)
                logger.info(f"Removed sub-CA directory: {subca_dir}")
            except Exception as e:
                logger.warning(
                    f"Failed to remove sub-CA directory {subca_dir}: {e}"
                )

    def _store_subca_in_ldap(self, subca: SubCA):
        """
        Store sub-CA in LDAP using Dogtag storage backend

        Stores authority metadata in ou=authorities,ou=ca,o=ipaca (Dogtag
        schema).
        Private keys are always stored on filesystem (not in LDAP) for security
        and Dogtag compatibility.

        NOTE: Private key is already stored by _save_to_disk() called earlier,
        so we don't need to call _store_subca_key_on_filesystem() here.
        """
        # Use Dogtag schema via storage backend
        self._store_subca_dogtag(subca)

        # Private key already stored by _save_to_disk()
        # TODO: When encryption is re-enabled, uncomment this:
        # self._store_subca_key_on_filesystem(subca)

        logger.debug(f"Stored sub-CA {subca.ca_id} in LDAP")

    def _store_subca_dogtag(self, subca: SubCA):
        """Store sub-CA using Dogtag LDAP schema via storage backend"""

        # Convert subject and issuer to DN strings
        subject_dn_str = get_subject_dn_str(subca.ca_cert)
        issuer_dn_str = get_issuer_dn_str(subca.ca_cert)

        # Determine parent ID for Dogtag schema
        parent_id = None
        if subca.parent_ca:
            parent_id = subca.parent_ca.ca_id

        # Store the sub-CA certificate in certificateRepository first
        dummy_request = CertificateRequest.for_subca(subca.ca_id)

        # Create CertificateRecord for the sub-CA certificate
        cert_record = CertificateRecord(
            subca.ca_cert, dummy_request, principal="subca_creation"
        )
        cert_record.serial_number = subca.ca_cert.serial_number

        # Store certificate in ou=certificateRepository,ou=ca,o=ipaca
        self.main_ca.storage.store_certificate(cert_record, allow_update=False)
        logger.debug(
            f"Stored sub-CA {subca.ca_id} certificate (serial "
            f"{subca.ca_cert.serial_number}) in certificate repository"
        )

        # Use storage backend to store authority metadata
        authority_data = {
            "authority_id": subca.ca_id,
            "subject_dn": subject_dn_str,
            "parent_dn": issuer_dn_str,
            "parent_id": parent_id,
            "key_nickname": f"caSigningCert cert-pki-ca {subca.ca_id}",
            "enabled": subca.enabled,
            "serial_number": subca.ca_cert.serial_number,
            "description": f"Sub-CA {subca.ca_id}",
        }

        self.main_ca.storage.store_authority(authority_data)
        logger.debug(
            f"Stored sub-CA {subca.ca_id} authority metadata in Dogtag LDAP"
            " schema"
        )

    def _store_encrypted_subca_key_on_filesystem(self, subca: SubCA):
        """Store encrypted sub-CA private key on filesystem.

        Keys are encrypted with AES-256-GCM using the master encryption key
        before writing to disk.
        """
        subcas_base = Path(paths.IPATHINCA_SUBCAS_DIR)
        subca_dir = subcas_base / subca.ca_id
        subca_dir.mkdir(parents=True, exist_ok=True)

        # Encode private key in PEM format
        key_pem = subca.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Encrypt private key before storing
        encrypted_key = encrypt_private_key(key_pem)

        # Store encrypted key on filesystem
        key_file = subca_dir / "ca.key.enc"
        key_file.write_bytes(encrypted_key)
        key_file.chmod(0o600)

        logger.debug(f"Stored sub-CA {subca.ca_id} private key on filesystem")

    def _load_subca_from_ldap(self, ca_id: str) -> Optional[SubCA]:
        """
        Load sub-CA from LDAP using Dogtag storage backend

        Loads authority metadata from Dogtag LDAP schema and private keys from
        filesystem.
        """
        # Ensure ca_id is a string, not a tuple (can happen from dict
        # iterations)
        if isinstance(ca_id, tuple):
            ca_id = ca_id[0]

        # Use Dogtag schema via storage backend
        return self._load_subca_dogtag(ca_id)

    def _load_subca_dogtag(self, ca_id: str) -> Optional[SubCA]:
        """Load sub-CA using Dogtag LDAP schema via storage backend"""
        try:
            # Get authority metadata from storage backend
            authority_data = self.main_ca.storage.get_authority(ca_id)

            if not authority_data:
                logger.warning(
                    f"Sub-CA {ca_id} not found in Dogtag LDAP storage"
                )
                return None

            # Get certificate from storage (by serial number)
            serial_number = authority_data.get("serial_number")
            if not serial_number:
                logger.error(f"Sub-CA {ca_id} has no serial number in LDAP")
                return None

            cert_record = self.main_ca.storage.get_certificate(serial_number)
            if not cert_record:
                logger.error(
                    f"Sub-CA {ca_id} certificate not found (serial"
                    f" {serial_number})"
                )
                return None

            ca_cert = cert_record.certificate

            # Get subject DN from authority data
            subject_dn = authority_data["subject_dn"]

            # Load encrypted private key from filesystem
            ca_key = self._load_encrypted_subca_key_from_filesystem(ca_id)

            if not ca_key:
                # Continue without key (read-only mode)
                pass

            # Determine parent CA from parent_id
            parent_ca = None
            parent_id = authority_data.get("parent_id")
            if parent_id and parent_id != ca_id:
                parent_ca = self.get_subca(parent_id)

            # Create SubCA instance
            subca = SubCA(
                ca_id, subject_dn, parent_ca, ca_cert=ca_cert, ca_key=ca_key
            )

            # Set enabled status from authority data
            subca.enabled = authority_data.get("enabled", True)

            logger.debug(f"Loaded sub-CA {ca_id} from Dogtag LDAP schema")
            return subca

        except Exception as e:
            logger.error(
                f"Exception loading sub-CA {ca_id} from Dogtag storage: {e}",
                exc_info=True,
            )
            return None

    def _load_encrypted_subca_key_from_filesystem(
        self, ca_id: str
    ) -> Optional[rsa.RSAPrivateKey]:
        """Load encrypted sub-CA private key from filesystem.

        Keys are encrypted with AES-256-GCM using the master encryption key.
        """
        subcas_base = Path(paths.IPATHINCA_SUBCAS_DIR)
        key_file = subcas_base / ca_id / "ca.key.enc"

        if not key_file.exists():
            logger.debug(f"Sub-CA {ca_id} private key not found on filesystem")
            return None

        try:
            # Read encrypted key and decrypt
            encrypted_key = key_file.read_bytes()
            key_pem = decrypt_private_key(encrypted_key)

            # Load key from PEM
            ca_key = serialization.load_pem_private_key(key_pem, password=None)

            logger.debug(f"Loaded private key for {ca_id} from filesystem")
            return ca_key

        except Exception as e:
            logger.error(
                f"Failed to load private key for CA {ca_id} from"
                f" filesystem: {e}",
                exc_info=True,
            )
            return None

    def update_subca_status(self, ca_id: str, enabled: bool):
        """
        Update the enabled/disabled status of a sub-CA

        Args:
            ca_id: CA identifier
            enabled: True to enable, False to disable
        """
        # Ensure ca_id is a string, not a tuple
        if isinstance(ca_id, tuple):
            ca_id = ca_id[0]

        # Use Dogtag schema via storage backend
        self.main_ca.storage.update_authority_status(ca_id, enabled)

        # Update the in-memory cache
        with self._cache_lock:
            if ca_id in self.subcas:
                self.subcas[ca_id].enabled = enabled
                # Refresh timestamp to reflect LDAP modification
                self.cache_timestamps[ca_id] = self._get_ldap_modify_timestamp(
                    ca_id
                )
                logger.debug(
                    f"Updated sub-CA {ca_id} cache with new "
                    f"timestamp "
                    f"{self.cache_timestamps[ca_id].isoformat()}"
                )

    def _delete_subca_from_ldap(self, ca_id: str):
        """Delete sub-CA from LDAP using Dogtag storage backend"""
        # Ensure ca_id is a string, not a tuple
        if isinstance(ca_id, tuple):
            ca_id = ca_id[0]

        # Use Dogtag schema via storage backend
        self.main_ca.storage.delete_authority(ca_id)
        logger.debug(f"Deleted sub-CA {ca_id} from Dogtag LDAP schema")
