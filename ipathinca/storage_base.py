# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Base LDAP storage backend with connection pooling and schema initialization
"""

from __future__ import absolute_import

import logging

from ipalib import errors
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient

from ipathinca.ldap_utils import get_ldap_connection

# Removed: Abstract StorageBackend base class (only one implementation exists)

# Import caching library for performance optimization
try:
    from cachetools import TTLCache

    CACHETOOLS_AVAILABLE = True
except ImportError:
    # Fallback: caching disabled if cachetools not available
    TTLCache = None
    CACHETOOLS_AVAILABLE = False

# Import LDAP filter escaping to prevent injection attacks
try:
    from ldap.filter import escape_filter_chars
except ImportError:
    # Fallback implementation if python-ldap is not available
    def escape_filter_chars(text):
        """Escape LDAP filter special characters to prevent injection"""
        escape_map = {
            "\\": r"\5c",
            "*": r"\2a",
            "(": r"\28",
            ")": r"\29",
            "\x00": r"\00",
        }
        return "".join(escape_map.get(c, c) for c in text)


logger = logging.getLogger(__name__)


def biginteger_to_db(serial_number: int) -> str:
    """
    Encode serial number using Dogtag's length-prefixed format

    This matches Dogtag's BigIntegerToDB() function for LDAP storage.
    The encoding enables correct lexicographic sorting in LDAP.

    Args:
        serial_number: Serial number as integer

    Returns:
        Encoded string (e.g., 13 -> "0213")

    Examples:
        1 -> "011"
        13 -> "0213"
        100 -> "03100"
        1000000000 -> "101234567890"
    """
    serial_str = str(serial_number)
    length = len(serial_str)

    if length < 10:
        return f"0{length}{serial_str}"
    else:
        return f"{length}{serial_str}"


def biginteger_from_db(encoded_serial: str) -> int:
    """
    Decode Dogtag's length-prefixed serial number encoding

    This matches Dogtag's BigIntegerFromDB() function which always
    skips the first 2 characters. Provided for reference but not
    currently used in ipathinca (we use cn attribute for serial number).

    Args:
        encoded_serial: Encoded serial (e.g., "0213")

    Returns:
        Serial number as integer (e.g., 13), or None if invalid

    Examples:
        "011" -> 1
        "0213" -> 13
        "03100" -> 100
        "101234567890" -> 1234567890
    """
    if not encoded_serial or len(encoded_serial) < 3:
        return None

    # Dogtag always skips first 2 characters (substring(2))
    serial_str = encoded_serial[2:]

    try:
        return int(serial_str)
    except ValueError:
        logger.warning(
            f"Invalid Dogtag encoding: cannot parse '{serial_str}' "
            f"from '{encoded_serial}'"
        )
        return None


class BaseStorageBackend:
    """
    Certificate Authority Storage Backend (Dogtag-Compatible)

    This backend uses the traditional Dogtag/PKI LDAP schema for storing
    certificates and related data. It provides compatibility with existing
    Dogtag installations.

    Schema:
        o=ipaca
        ├── ou=ca,o=ipaca
        │   ├── ou=certificateRepository,ou=ca,o=ipaca
        │   │   └── cn={serial},ou=certificateRepository,ou=ca,o=ipaca
        │   ├── ou=crlIssuingPoints,ou=ca,o=ipaca
        │   ├── ou=authorities,ou=ca,o=ipaca (sub-CAs)
        │   └── cn=CAConfig,ou=ca,o=ipaca
        └── ou=requests,o=ipaca (legacy parent)
            └── ou=ca,ou=requests,o=ipaca (actual request storage)
                └── cn={request_id},ou=ca,ou=requests,o=ipaca

        Note: This schema structure matches Dogtag exactly, including the
        legacy request structure where ou=ca,ou=requests,o=ipaca is used
        (historical).
    """

    def __init__(self, ca_id="ipa", random_serial_numbers=False):
        """
        Initialize Dogtag-compatible LDAP storage backend

        Args:
            ca_id: CA identifier (for sub-CA support)
            random_serial_numbers: Use RSNv3 random serial numbers
                                       (default: False)
        """
        self.ca_id = ca_id
        self.random_serial_numbers = random_serial_numbers

        # Dogtag-style base DNs (fixed schema, not configurable)
        self.base_dn = DN(("o", "ipaca"))
        self.ca_base_dn = DN(("ou", "ca"), self.base_dn)
        self.certs_base_dn = DN(
            ("ou", "certificateRepository"), self.ca_base_dn
        )

        # Requests use legacy structure: ou=ca,ou=requests,o=ipaca
        # (not ou=requests,ou=ca,o=ipaca - Dogtag's historical structure)
        self.requests_container_dn = DN(("ou", "requests"), self.base_dn)
        self.requests_base_dn = DN(("ou", "ca"), self.requests_container_dn)

        self.config_dn = DN(("cn", "CAConfig"), self.ca_base_dn)

        # Initialize caches for frequently accessed data
        # TTL=60s for statistics (changes infrequently)
        # TTL=300s for CRL info (CRLs generated periodically)
        if CACHETOOLS_AVAILABLE:
            self._stats_cache = TTLCache(maxsize=1, ttl=60)
            self._crl_info_cache = TTLCache(maxsize=10, ttl=300)
            logger.debug("Initialized query result caches (TTL-based)")
        else:
            self._stats_cache = None
            self._crl_info_cache = None
            logger.debug(
                "Caching disabled (cachetools not available). "
                "Install cachetools for better performance."
            )

        # Thread-safe serial number allocation
        import threading

        self._serial_lock = threading.Lock()

    def _get_ldap_connection(self):
        """Get LDAP connection using shared utility with pooling

        Returns:
            Context manager for pooled LDAP connection (use with 'with'
            statement)

        Note:
            This uses connection pooling for optimal performance. The
            connection is automatically returned to the pool after use.

            Usage:
                with self._get_ldap_connection() as ldap:
                    ldap.get_entry(dn)
        """
        try:
            # Use pooled connections for performance (default behavior)
            return get_ldap_connection(use_pool=True)
        except Exception as e:
            logger.error(
                f"CAStorageBackend: Failed to get LDAP connection: {e}",
                exc_info=True,
            )
            raise Exception(f"Cannot connect to LDAP database: {e}")

    def initialize_schema(self):
        """
        Initialize Dogtag-compatible LDAP schema for CA storage
        Creates necessary organizational units and base entries
        """
        with self._get_ldap_connection() as ldap:

            logger.debug("Initializing Dogtag-compatible CA LDAP schema")

            # Create base container (o=ipaca) - usually already exists
            try:
                ldap.get_entry(self.base_dn)
                logger.debug(f"Base container already exists: {self.base_dn}")
            except errors.NotFound:
                logger.debug(f"Creating base container: {self.base_dn}")
                try:
                    entry = ldap.make_entry(
                        self.base_dn,
                        objectclass=["top", "organization"],
                        o=["ipaca"],
                    )
                    ldap.add_entry(entry)
                    logger.debug(
                        f"Base container created successfully: {self.base_dn}"
                    )

                    # Verify the entry was created and is readable
                    try:
                        ldap.get_entry(self.base_dn)
                        logger.debug(
                            "Verified base container is readable:"
                            f" {self.base_dn}"
                        )
                    except errors.NotFound:
                        logger.error(
                            "Base container was created but cannot be read"
                            f" back: {self.base_dn}"
                        )
                        raise

                except Exception as e:
                    # Ignore "Already exists" errors - race condition
                    if "already exists" not in str(e).lower():
                        logger.error(
                            "Failed to create base container"
                            f" {self.base_dn}: {e}"
                        )
                        raise

            # Create CA container (must be created before its children)
            self._create_ou_if_not_exists(ldap, self.ca_base_dn, "ca")

            # Create certificate repository under ou=ca (with serialno for
            # Dogtag compatibility)
            # Use "011" to match Dogtag exactly (even though it duplicates
            # first cert serial)
            self._create_repository_if_not_exists(
                ldap, self.certs_base_dn, "certificateRepository", "011"
            )

            # Create requests containers (Dogtag legacy structure)
            # First create ou=requests,o=ipaca (parent container)
            self._create_ou_if_not_exists(
                ldap, self.requests_container_dn, "requests"
            )
            # Then create ou=ca,ou=requests,o=ipaca (actual request storage)
            self._create_repository_if_not_exists(
                ldap, self.requests_base_dn, "ca", "010"
            )

            # Create CRL issuing points container (with serialno for Dogtag
            # compatibility)
            crl_dn = DN(("ou", "crlIssuingPoints"), self.ca_base_dn)
            self._create_repository_if_not_exists(
                ldap, crl_dn, "crlIssuingPoints", "010"
            )

            # Create authorities (sub-CA) container
            authorities_dn = DN(("ou", "authorities"), self.ca_base_dn)
            self._create_ou_if_not_exists(ldap, authorities_dn, "authorities")

            # Create certificate profiles container
            profiles_dn = DN(("ou", "certificateProfiles"), self.ca_base_dn)
            self._create_ou_if_not_exists(
                ldap, profiles_dn, "certificateProfiles"
            )

            # Create ranges containers for multi-master replication
            ranges_dn = DN(("ou", "ranges"), self.base_dn)
            self._create_ou_if_not_exists(ldap, ranges_dn, "ranges")

            # Create replica ranges container
            replica_ranges_dn = DN(("ou", "replica"), ranges_dn)
            self._create_ou_if_not_exists(ldap, replica_ranges_dn, "replica")

            # Create certificate repository ranges container
            cert_ranges_dn = DN(("ou", "certificateRepository"), ranges_dn)
            self._create_ou_if_not_exists(
                ldap, cert_ranges_dn, "certificateRepository"
            )

            # Create request ranges container
            request_ranges_dn = DN(("ou", "requests"), ranges_dn)
            self._create_ou_if_not_exists(ldap, request_ranges_dn, "requests")

            # Create replica container (for replica metadata)
            replica_dn = DN(("ou", "replica"), self.base_dn)
            self._create_ou_if_not_exists(ldap, replica_dn, "replica")

            # Create people container (for PKI user accounts)
            people_dn = DN(("ou", "people"), self.base_dn)
            self._create_ou_if_not_exists(ldap, people_dn, "people")

            # Create groups container (for PKI groups)
            groups_dn = DN(("ou", "groups"), self.base_dn)
            self._create_ou_if_not_exists(ldap, groups_dn, "groups")

            # Create Security Domain container (for multi-subsystem
            # coordination)
            security_domain_dn = DN(("ou", "Security Domain"), self.base_dn)
            self._create_ou_if_not_exists(
                ldap, security_domain_dn, "Security Domain"
            )

            # Create sessions container under Security Domain
            sessions_dn = DN(("ou", "sessions"), security_domain_dn)
            self._create_ou_if_not_exists(ldap, sessions_dn, "sessions")

            # Create CA config entry
            self._create_config_entry(ldap)

            # Add LDAP indexes for query optimization
            self._create_ldap_indexes(ldap)

            logger.debug(
                "Dogtag-compatible CA LDAP schema initialized successfully"
            )

    def _create_ou_if_not_exists(self, ldap: LDAPClient, dn: DN, ou_name: str):
        """Create organizational unit if it doesn't exist"""
        try:
            ldap.get_entry(dn)
            logger.debug(f"OU already exists: {dn}")
        except errors.NotFound:
            logger.debug(f"Creating OU: {dn}")
            try:
                entry = ldap.make_entry(
                    dn,
                    objectclass=["top", "organizationalUnit"],
                    ou=[ou_name],
                )
                ldap.add_entry(entry)
            except Exception as e:
                # Ignore "Already exists" errors - another process may have
                # created it
                if "already exists" in str(e).lower():
                    logger.debug(f"OU {dn} already exists (race condition)")
                else:
                    raise
        except Exception as e:
            # If we get permission denied on read, assume it exists
            if "Insufficient access" in str(e) or "Permission denied" in str(
                e
            ):
                logger.debug(
                    f"Cannot read {dn} (permission denied), assuming it exists"
                )
            else:
                raise

    def _create_repository_if_not_exists(
        self, ldap: LDAPClient, dn: DN, ou_name: str, initial_serialno: str
    ):
        """
        Create repository container if it doesn't exist

        Repository containers use objectClass 'repository' and include a
        serialno attribute for Dogtag compatibility. This matches Dogtag's
        schema where repository containers track metadata.

        Args:
            ldap: LDAP client connection
            dn: DN of the repository container
            ou_name: Name for the ou attribute
            initial_serialno: Initial serialno value (e.g., "011" for certs,
                              "010" for others)
        """
        try:
            ldap.get_entry(dn)
            logger.debug(f"Repository already exists: {dn}")
        except errors.NotFound:
            logger.debug(
                f"Creating repository: {dn} with serialno={initial_serialno}"
            )
            try:
                entry = ldap.make_entry(
                    dn,
                    objectclass=["top", "repository"],
                    ou=[ou_name],
                    serialno=[initial_serialno],
                )
                ldap.add_entry(entry)
            except Exception as e:
                # Ignore "Already exists" errors - another process may have
                # created it
                if "already exists" in str(e).lower():
                    logger.debug(
                        f"Repository {dn} already exists (race condition)"
                    )
                else:
                    raise
        except Exception as e:
            # If we get permission denied on read, assume it exists
            if "Insufficient access" in str(e) or "Permission denied" in str(
                e
            ):
                logger.debug(
                    f"Cannot read {dn} (permission denied), assuming it exists"
                )
            else:
                raise

    def _create_config_entry(self, ldap: LDAPClient):
        """Create CA configuration entry"""
        try:
            ldap.get_entry(self.config_dn)
            logger.debug(f"Config entry already exists: {self.config_dn}")
        except errors.NotFound:
            logger.debug(f"Creating config entry: {self.config_dn}")
            entry = ldap.make_entry(
                self.config_dn,
                objectclass=["top", "nsContainer", "extensibleObject"],
                cn=["CAConfig"],
                serialno=["0"],
                nextRange=["0"],
                lastSerialNo=["0"],
                crlNumber=["0"],
            )
            ldap.add_entry(entry)

    def _create_ldap_indexes(self, ldap: LDAPClient):
        """
        Create LDAP indexes for frequently queried attributes

        Indexes dramatically improve query performance by allowing the LDAP
        server to quickly locate entries without full table scans.

        This configures indexes on the 389 Directory Server backend for the
        ipaca database.
        """
        import ldap as ldap_module

        # Attributes that need indexing for optimal performance
        indexes_needed = {
            # Certificate repository indexes
            "serialno": ["eq", "pres"],  # Serial number lookups
            "certStatus": [
                "eq",
                "pres",
            ],  # Status filtering (VALID, REVOKED, etc.)
            "subjectName": ["sub", "pres"],  # Subject DN substring searches
            "revokedOn": ["eq", "pres"],  # Revocation date queries
            # Request repository indexes
            "requestState": ["eq", "pres"],  # Request status filtering
            "dateOfCreate": ["eq", "pres"],  # Date-based cleanup queries
            # Authority (sub-CA) indexes
            "authorityID": ["eq", "pres"],  # Authority ID lookups
            "authorityEnabled": ["eq", "pres"],  # Enabled/disabled filtering
            # Range management indexes
            "replicaId": ["eq", "pres"],  # Replica range queries
            "beginRange": ["eq", "pres"],  # Range searches
            "endRange": ["eq", "pres"],  # Range searches
            # CRL indexes
            "crlNumber": ["eq", "pres"],  # CRL number lookups
            # Profile indexes
            "cn": [
                "eq",
                "pres",
                "sub",
            ],  # Common name lookups (profiles, CRLs, etc.)
        }

        # Get the backend DN for ipaca database
        # This is where index configuration is stored in 389 DS
        try:
            backend_dn = DN(
                ("cn", "ipaca"),
                ("cn", "ldbm database"),
                ("cn", "plugins"),
                ("cn", "config"),
            )

            logger.debug(f"Configuring LDAP indexes for {backend_dn}")

            for attr_name, index_types in indexes_needed.items():
                index_dn = DN(("cn", attr_name), backend_dn)

                try:
                    # Check if index already exists
                    existing_index = ldap.conn.search_s(
                        str(index_dn),
                        ldap_module.SCOPE_BASE,
                        "(objectClass=*)",
                        ["nsIndexType"],
                    )

                    if existing_index:
                        logger.debug(f"Index for {attr_name} already exists")
                        continue

                except ldap_module.NO_SUCH_OBJECT:
                    # Index doesn't exist, create it
                    pass

                # Create index configuration
                try:
                    index_types_str = ",".join(index_types)
                    logger.debug(
                        f"Creating index for {attr_name} (types:"
                        f" {index_types_str})"
                    )

                    # Add index entry
                    ldap.conn.add_s(
                        str(index_dn),
                        [
                            ("objectClass", [b"top", b"nsIndex"]),
                            ("cn", [attr_name.encode("utf-8")]),
                            ("nsSystemIndex", [b"false"]),
                            (
                                "nsIndexType",
                                [t.encode("utf-8") for t in index_types],
                            ),
                        ],
                    )

                    logger.debug(
                        f"Created LDAP index for attribute: {attr_name}"
                    )

                except ldap_module.ALREADY_EXISTS:
                    logger.debug(
                        f"Index for {attr_name} already exists (race"
                        " condition)"
                    )
                except Exception as e:
                    # Non-fatal: indexes are optional optimization
                    logger.warning(
                        f"Failed to create index for {attr_name}: {e}. "
                        "Queries will still work but may be slower."
                    )

            logger.debug(
                "LDAP index configuration complete. Indexes will be built in"
                " background. Run 'dsconf <instance> backend index reindex"
                " ipaca' to rebuild immediately."
            )

        except Exception as e:
            # Index creation is non-fatal - queries will still work, just
            # slower
            logger.warning(
                f"Failed to configure LDAP indexes: {e}. This is not critical"
                " - queries will work but may be slower for large datasets."
            )
