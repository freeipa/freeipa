# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
ACME LDAP Database Backend for ipathinca

Provides LDAP-backed storage for ACME data, compatible with Dogtag's schema.
Stores accounts, orders, authorizations, challenges, and nonces in LDAP for
persistence and multi-master replication.

LDAP Structure:
    ou=acme,o=ipaca
    ├── ou=nonces
    ├── ou=accounts
    ├── ou=orders
    ├── ou=authorizations
    ├── ou=challenges
    └── ou=certificates
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ipalib import errors
from ipapython.dn import DN
from ipathinca.ldap_utils import get_ldap_connection
from ipathinca.storage_base import LDAPStorageMixin, escape_filter_chars

logger = logging.getLogger(__name__)


class ACMEStorageBackend(LDAPStorageMixin):
    """
    LDAP storage backend for ACME data (Dogtag-compatible)

    Provides persistent storage for ACME accounts, orders, authorizations,
    challenges, and nonces using the Dogtag ACME LDAP schema.
    """

    def __init__(self, config):
        """
        Initialize ACME database

        Args:
            config: RawConfigParser from ipathinca.conf
        """
        self.config = config
        self.base_dn = DN(("ou", "acme"), ("o", "ipaca"))

    # Container DNs
    @property
    def nonces_dn(self):
        return DN(("ou", "nonces"), self.base_dn)

    @property
    def accounts_dn(self):
        return DN(("ou", "accounts"), self.base_dn)

    @property
    def orders_dn(self):
        return DN(("ou", "orders"), self.base_dn)

    @property
    def authorizations_dn(self):
        return DN(("ou", "authorizations"), self.base_dn)

    @property
    def challenges_dn(self):
        return DN(("ou", "challenges"), self.base_dn)

    @property
    def certificates_dn(self):
        return DN(("ou", "certificates"), self.base_dn)

    def init_schema(self):
        """
        Initialize ACME LDAP schema structure

        Creates the Dogtag-compatible ACME containers in LDAP:
        - ou=acme,o=ipaca (ACME base)
        - ou=nonces,ou=acme,o=ipaca
        - ou=accounts,ou=acme,o=ipaca
        - ou=orders,ou=acme,o=ipaca
        - ou=authorizations,ou=acme,o=ipaca
        - ou=challenges,ou=acme,o=ipaca
        - ou=certificates,ou=acme,o=ipaca
        - ou=config,ou=acme,o=ipaca (extensible for configuration)
        """
        with get_ldap_connection() as ldap:
            # Create ACME base container (ou=acme,o=ipaca)
            try:
                ldap.get_entry(self.base_dn)
                logger.debug("ACME base container already exists")
            except errors.NotFound:
                entry = ldap.make_entry(
                    self.base_dn,
                    objectClass=["top", "organizationalUnit"],
                    ou=["acme"],
                )
                ldap.add_entry(entry)
                logger.debug("Created ACME base container")

            # Create standard ACME sub-containers
            containers = [
                ("nonces", self.nonces_dn),
                ("accounts", self.accounts_dn),
                ("orders", self.orders_dn),
                ("authorizations", self.authorizations_dn),
                ("challenges", self.challenges_dn),
                ("certificates", self.certificates_dn),
            ]

            for ou_name, dn in containers:
                self._create_ou_if_not_exists(ldap, dn, ou_name)

            # Create config container with extensibleObject
            config_dn = DN(("ou", "config"), self.base_dn)
            try:
                ldap.get_entry(config_dn)
            except errors.NotFound:
                entry = ldap.make_entry(
                    config_dn,
                    objectClass=[
                        "top",
                        "organizationalUnit",
                        "extensibleObject",
                    ],
                    ou=["config"],
                )
                ldap.add_entry(entry)
                logger.debug("Created ACME config container")

            logger.info("ACME LDAP schema initialization completed")

    # ========================================================================
    # Nonce Operations
    # ========================================================================

    def create_nonce(self, nonce_id: str, expires: datetime):
        """
        Create nonce in LDAP

        Args:
            nonce_id: Unique nonce identifier
            expires: Expiration datetime
        """
        try:
            with get_ldap_connection() as conn:
                entry = conn.make_entry(
                    DN(("acmeNonceId", nonce_id), self.nonces_dn),
                    objectClass=["acmeNonce"],
                    acmeNonceId=[nonce_id],
                    acmeCreated=[
                        self._format_time(datetime.now(timezone.utc))
                    ],
                    acmeExpires=[self._format_time(expires)],
                )
                conn.add_entry(entry)
                logger.debug("Created nonce: %s", nonce_id)
        except Exception as e:
            logger.error("Failed to create nonce %s: %s", nonce_id, e)
            raise

    def validate_nonce(self, nonce_id: str) -> bool:
        """
        Validate and consume nonce (one-time use)

        Args:
            nonce_id: Nonce to validate

        Returns:
            True if nonce is valid and not expired, False otherwise
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(("acmeNonceId", nonce_id), self.nonces_dn)

                try:
                    entry = conn.get_entry(dn)
                except errors.NotFound:
                    logger.debug("Nonce not found: %s", nonce_id)
                    return False

                # Check expiration
                expires_str = entry.single_value.get("acmeExpires")
                if expires_str:
                    expires = self._parse_time(expires_str)
                    if datetime.now(timezone.utc) > expires:
                        logger.debug("Nonce expired: %s", nonce_id)
                        # Delete expired nonce
                        try:
                            conn.delete_entry(dn)
                        except Exception as e:
                            logger.debug(
                                "Failed to delete expired nonce %s: %s",
                                nonce_id,
                                e,
                            )
                        return False

                # Delete nonce (one-time use, atomic consume)
                # If delete fails with NotFound, another thread consumed it
                try:
                    conn.delete_entry(dn)
                except errors.NotFound:
                    logger.debug(
                        "Nonce already consumed by concurrent request: %s",
                        nonce_id,
                    )
                    return False
                logger.debug("Validated and consumed nonce: %s", nonce_id)
                return True

        except Exception as e:
            logger.error("Failed to validate nonce %s: %s", nonce_id, e)
            return False

    # ========================================================================
    # Account Operations
    # ========================================================================

    def create_account(self, account_id: str, jwk: Dict, contacts: List[str]):
        """
        Create ACME account in LDAP

        Args:
            account_id: Unique account identifier
            jwk: JSON Web Key (account public key)
            contacts: List of contact URLs (e.g., mailto:user@example.com)
        """
        try:
            with get_ldap_connection() as conn:
                entry = conn.make_entry(
                    DN(("acmeAccountId", account_id), self.accounts_dn),
                    objectClass=["acmeAccount"],
                    acmeAccountId=[account_id],
                    acmeCreated=[
                        self._format_time(datetime.now(timezone.utc))
                    ],
                    acmeAccountKey=[json.dumps(jwk)],
                    acmeStatus=["valid"],
                    acmeAccountContact=contacts or [],
                )
                conn.add_entry(entry)
                logger.info("Created ACME account: %s", account_id)
        except Exception as e:
            logger.error("Failed to create account %s: %s", account_id, e)
            raise

    def get_account(self, account_id: str) -> Optional[Dict]:
        """
        Retrieve account from LDAP

        Args:
            account_id: Account identifier

        Returns:
            Account dict or None if not found
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(("acmeAccountId", account_id), self.accounts_dn)
                entry = conn.get_entry(dn)

                account_id_val = entry.single_value.get("acmeAccountId")
                account_key_val = entry.single_value.get("acmeAccountKey")
                created_val = entry.single_value.get("acmeCreated")
                if (
                    not account_id_val
                    or not account_key_val
                    or not created_val
                ):
                    logger.warning("Incomplete ACME account entry: %s", dn)
                    return None
                try:
                    account_key = json.loads(account_key_val)
                except json.JSONDecodeError:
                    logger.warning(
                        "Corrupt account key JSON for %s", account_id_val
                    )
                    return None
                return {
                    "account_id": account_id_val,
                    "key": account_key,
                    "status": entry.single_value.get("acmeStatus", "valid"),
                    "contact": list(entry.get("acmeAccountContact", [])),
                    "created_at": self._parse_time(created_val),
                }
        except Exception as e:
            logger.debug("Account not found: %s: %s", account_id, e)
            return None

    def get_account_by_jwk(self, jwk: Dict) -> Optional[Dict]:
        """
        Find account by JWK thumbprint

        Args:
            jwk: JSON Web Key to search for

        Returns:
            Account dict or None if not found
        """
        try:
            from ipathinca.jwk import JWK as ACMEJWKClass

            thumbprint = ACMEJWKClass.thumbprint(jwk)

            with get_ldap_connection() as conn:
                # Search for account with matching JWK thumbprint
                # The JWK is stored as JSON, so we search within the
                # JSON string
                escaped_thumbprint = escape_filter_chars(thumbprint)
                filter_str = (
                    f"(&(objectClass=acmeAccount)"
                    f"(acmeAccountKey=*{escaped_thumbprint}*))"
                )
                entries = conn.get_entries(
                    self.accounts_dn,
                    filter=filter_str,
                    scope=conn.SCOPE_ONELEVEL,
                )

                if entries:
                    entry = entries[0]
                    account_id = entry.single_value["acmeAccountId"]
                    return self.get_account(account_id)

                return None
        except Exception as e:
            logger.error("Failed to search account by JWK: %s", e)
            return None

    def update_account(
        self, account_id: str, contacts: List[str] = None, status: str = None
    ):
        """
        Update account metadata

        Args:
            account_id: Account identifier
            contacts: New contact list (optional)
            status: New status (optional)
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(("acmeAccountId", account_id), self.accounts_dn)
                entry = conn.get_entry(dn)

                if contacts is not None:
                    entry["acmeAccountContact"] = contacts
                if status is not None:
                    entry["acmeStatus"] = [status]

                conn.update_entry(entry)
                logger.info("Updated account: %s", account_id)
        except Exception as e:
            logger.error("Failed to update account %s: %s", account_id, e)
            raise

    # ========================================================================
    # Order Operations
    # ========================================================================

    def create_order(
        self,
        order_id: str,
        account_id: str,
        identifiers: List[Dict],
        authz_ids: List[str],
        expires: datetime,
    ):
        """
        Create certificate order in LDAP

        Args:
            order_id: Unique order identifier
            account_id: Account that created the order
            identifiers: List of identifiers
                (e.g., [{"type": "dns", "value": "example.com"}])
            authz_ids: List of authorization IDs
            expires: Order expiration datetime
        """
        try:
            with get_ldap_connection() as conn:
                entry = conn.make_entry(
                    DN(("acmeOrderId", order_id), self.orders_dn),
                    objectClass=["acmeOrder"],
                    acmeOrderId=[order_id],
                    acmeAccountId=[account_id],
                    acmeCreated=[
                        self._format_time(datetime.now(timezone.utc))
                    ],
                    acmeStatus=["pending"],
                    acmeIdentifier=[json.dumps(i) for i in identifiers],
                    acmeAuthorizationId=authz_ids,
                    acmeExpires=[self._format_time(expires)],
                )
                conn.add_entry(entry)
                logger.info(
                    "Created order: %s for account %s", order_id, account_id
                )
        except Exception as e:
            logger.error("Failed to create order %s: %s", order_id, e)
            raise

    def get_order(self, order_id: str) -> Optional[Dict]:
        """
        Retrieve order from LDAP

        Args:
            order_id: Order identifier

        Returns:
            Order dict or None if not found
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(("acmeOrderId", order_id), self.orders_dn)
                entry = conn.get_entry(dn)

                try:
                    identifiers = [
                        json.loads(i) for i in entry.get("acmeIdentifier", [])
                    ]
                except json.JSONDecodeError:
                    logger.warning(
                        "Corrupt identifier JSON in order %s", order_id
                    )
                    return None
                return {
                    "order_id": entry.single_value["acmeOrderId"],
                    "account_id": entry.single_value["acmeAccountId"],
                    "status": entry.single_value.get("acmeStatus", "pending"),
                    "identifiers": identifiers,
                    "authz_ids": list(entry.get("acmeAuthorizationId", [])),
                    "created_at": self._parse_time(
                        entry.single_value["acmeCreated"]
                    ),
                    "expires": self._parse_time(
                        entry.single_value["acmeExpires"]
                    ),
                    "certificate_id": entry.single_value.get(
                        "acmeCertificateId"
                    ),
                }
        except Exception as e:
            logger.debug("Order not found: %s: %s", order_id, e)
            return None

    def update_order_status(
        self, order_id: str, status: str, cert_id: str = None
    ):
        """
        Update order status in LDAP

        Args:
            order_id: Order identifier
            status: New status (pending, valid, invalid, etc.)
            cert_id: Certificate ID (optional, for valid orders)
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(("acmeOrderId", order_id), self.orders_dn)
                entry = conn.get_entry(dn)

                entry["acmeStatus"] = [status]
                if cert_id:
                    entry["acmeCertificateId"] = [cert_id]

                conn.update_entry(entry)
                logger.info("Updated order %s status to %s", order_id, status)
        except Exception as e:
            logger.error("Failed to update order %s: %s", order_id, e)
            raise

    # ========================================================================
    # Authorization Operations
    # ========================================================================

    def create_authorization(
        self,
        authz_id: str,
        account_id: str,
        identifier: Dict,
        wildcard: bool,
        expires: datetime,
    ):
        """
        Create authorization in LDAP

        Args:
            authz_id: Unique authorization identifier
            account_id: Account that owns this authorization
            identifier: Identifier dict
                (e.g., {"type": "dns", "value": "example.com"})
            wildcard: Whether this is a wildcard authorization
            expires: Authorization expiration datetime
        """
        try:
            with get_ldap_connection() as conn:
                entry = conn.make_entry(
                    DN(
                        ("acmeAuthorizationId", authz_id),
                        self.authorizations_dn,
                    ),
                    objectClass=["acmeAuthorization"],
                    acmeAuthorizationId=[authz_id],
                    acmeAccountId=[account_id],
                    acmeCreated=[
                        self._format_time(datetime.now(timezone.utc))
                    ],
                    acmeIdentifier=[json.dumps(identifier)],
                    acmeAuthorizationWildcard=[
                        "TRUE" if wildcard else "FALSE"
                    ],
                    acmeStatus=["pending"],
                    acmeExpires=[self._format_time(expires)],
                )
                conn.add_entry(entry)
                logger.debug("Created authorization: %s", authz_id)
        except Exception as e:
            logger.error("Failed to create authorization %s: %s", authz_id, e)
            raise

    def get_authorization(self, authz_id: str) -> Optional[Dict]:
        """
        Retrieve authorization from LDAP

        Args:
            authz_id: Authorization identifier

        Returns:
            Authorization dict or None if not found
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(
                    ("acmeAuthorizationId", authz_id), self.authorizations_dn
                )
                entry = conn.get_entry(dn)

                try:
                    identifier = json.loads(
                        entry.single_value["acmeIdentifier"]
                    )
                except json.JSONDecodeError:
                    logger.warning(
                        "Corrupt identifier JSON in authz %s", authz_id
                    )
                    return None
                return {
                    "authz_id": entry.single_value["acmeAuthorizationId"],
                    "account_id": entry.single_value["acmeAccountId"],
                    "identifier": identifier,
                    "wildcard": entry.single_value.get(
                        "acmeAuthorizationWildcard", "FALSE"
                    )
                    == "TRUE",
                    "status": entry.single_value.get("acmeStatus", "pending"),
                    "created_at": self._parse_time(
                        entry.single_value["acmeCreated"]
                    ),
                    "expires": self._parse_time(
                        entry.single_value["acmeExpires"]
                    ),
                }
        except Exception as e:
            logger.debug("Authorization not found: %s: %s", authz_id, e)
            return None

    def update_authorization_status(self, authz_id: str, status: str):
        """
        Update authorization status in LDAP

        Args:
            authz_id: Authorization identifier
            status: New status (pending, valid, invalid, etc.)
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(
                    ("acmeAuthorizationId", authz_id), self.authorizations_dn
                )
                entry = conn.get_entry(dn)

                entry["acmeStatus"] = [status]

                conn.update_entry(entry)
                logger.info(
                    "Updated authorization %s status to %s", authz_id, status
                )
        except Exception as e:
            logger.error("Failed to update authorization %s: %s", authz_id, e)
            raise

    # ========================================================================
    # Challenge Operations
    # ========================================================================

    def create_challenge(
        self,
        challenge_id: str,
        authz_id: str,
        account_id: str,
        challenge_type: str,
        token: str,
    ):
        """
        Create challenge in LDAP

        Args:
            challenge_id: Unique challenge identifier
            authz_id: Authorization this challenge belongs to
            account_id: Account that owns this challenge
            challenge_type: Challenge type (dns-01, http-01, etc.)
            token: Challenge token
        """
        try:
            with get_ldap_connection() as conn:
                # Determine object class based on challenge type
                if challenge_type == "dns-01":
                    object_classes = ["acmeChallenge", "acmeChallengeDns01"]
                elif challenge_type == "http-01":
                    object_classes = ["acmeChallenge", "acmeChallengeHttp01"]
                else:
                    raise ValueError(
                        f"Unsupported challenge type: {challenge_type}"
                    )

                entry = conn.make_entry(
                    DN(("acmeChallengeId", challenge_id), self.challenges_dn),
                    objectClass=object_classes,
                    acmeChallengeId=[challenge_id],
                    acmeAccountId=[account_id],
                    acmeAuthorizationId=[authz_id],
                    acmeStatus=["pending"],
                    acmeToken=[token],
                )
                conn.add_entry(entry)
                logger.debug(
                    "Created %s challenge: %s", challenge_type, challenge_id
                )
        except Exception as e:
            logger.error("Failed to create challenge %s: %s", challenge_id, e)
            raise

    def get_challenge(self, challenge_id: str) -> Optional[Dict]:
        """
        Retrieve challenge from LDAP

        Args:
            challenge_id: Challenge identifier

        Returns:
            Challenge dict or None if not found
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(("acmeChallengeId", challenge_id), self.challenges_dn)
                entry = conn.get_entry(dn)

                # Determine challenge type from object class
                object_classes = entry.get("objectClass", [])
                if "acmeChallengeDns01" in object_classes:
                    challenge_type = "dns-01"
                elif "acmeChallengeHttp01" in object_classes:
                    challenge_type = "http-01"
                else:
                    challenge_type = "unknown"

                result = {
                    "challenge_id": entry.single_value["acmeChallengeId"],
                    "authz_id": entry.single_value["acmeAuthorizationId"],
                    "account_id": entry.single_value["acmeAccountId"],
                    "challenge_type": challenge_type,
                    "token": entry.single_value.get("acmeToken"),
                    "status": entry.single_value.get("acmeStatus", "pending"),
                }

                # Add validated timestamp if present
                if "acmeValidatedAt" in entry:
                    result["validated_at"] = self._parse_time(
                        entry.single_value["acmeValidatedAt"]
                    )

                return result
        except Exception as e:
            logger.debug("Challenge not found: %s: %s", challenge_id, e)
            return None

    def update_challenge_status(
        self, challenge_id: str, status: str, validated_at: datetime = None
    ):
        """
        Update challenge validation status in LDAP

        Args:
            challenge_id: Challenge identifier
            status: New status (pending, valid, invalid, etc.)
            validated_at: Validation timestamp (optional)
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(("acmeChallengeId", challenge_id), self.challenges_dn)
                entry = conn.get_entry(dn)

                entry["acmeStatus"] = [status]
                if validated_at:
                    entry["acmeValidatedAt"] = [
                        self._format_time(validated_at)
                    ]

                conn.update_entry(entry)
                logger.info(
                    "Updated challenge %s status to %s", challenge_id, status
                )
        except Exception as e:
            logger.error("Failed to update challenge %s: %s", challenge_id, e)
            raise

    # ========================================================================
    # Certificate Operations
    # ========================================================================

    def store_certificate(self, cert_id: str, certificate_pem: str):
        """
        Store issued certificate in LDAP

        Args:
            cert_id: Certificate identifier (usually order ID)
            certificate_pem: PEM-encoded certificate
        """
        try:
            with get_ldap_connection() as conn:
                # Convert PEM to DER for storage in userCertificate attribute
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization

                cert = x509.load_pem_x509_certificate(certificate_pem.encode())
                cert_der = cert.public_bytes(serialization.Encoding.DER)

                entry = conn.make_entry(
                    DN(("acmeCertificateId", cert_id), self.certificates_dn),
                    objectClass=["acmeCertificate"],
                    acmeCertificateId=[cert_id],
                    acmeCreated=[
                        self._format_time(datetime.now(timezone.utc))
                    ],
                    userCertificate=[cert_der],
                )
                conn.add_entry(entry)
                logger.info("Stored certificate: %s", cert_id)
        except Exception as e:
            logger.error("Failed to store certificate %s: %s", cert_id, e)
            raise

    def get_certificate(self, cert_id: str) -> Optional[str]:
        """
        Retrieve certificate from LDAP

        Args:
            cert_id: Certificate identifier

        Returns:
            PEM-encoded certificate or None if not found
        """
        try:
            with get_ldap_connection() as conn:
                dn = DN(("acmeCertificateId", cert_id), self.certificates_dn)
                entry = conn.get_entry(dn)

                # Convert DER to PEM
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization

                cert_der = entry.single_value["userCertificate"]
                cert = x509.load_der_x509_certificate(cert_der)
                cert_pem = cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode()

                return cert_pem
        except Exception as e:
            logger.debug("Certificate not found: %s: %s", cert_id, e)
            return None

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _format_time(self, dt: datetime) -> str:
        """
        Format datetime for LDAP GeneralizedTime

        Args:
            dt: datetime object (must be timezone-aware)

        Returns:
            LDAP GeneralizedTime string (YYYYMMDDHHMMSSZ)
        """
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        # Convert to UTC
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.strftime("%Y%m%d%H%M%SZ")

    def _parse_time(self, time_value) -> datetime:
        """
        Parse LDAP GeneralizedTime to datetime

        Args:
            time_value: LDAP GeneralizedTime string or datetime object

        Returns:
            Timezone-aware datetime object (UTC)
        """
        # Handle case where LDAP returns datetime object directly
        if isinstance(time_value, datetime):
            # Ensure it has timezone info
            if time_value.tzinfo is None:
                return time_value.replace(tzinfo=timezone.utc)
            return time_value.astimezone(timezone.utc)

        # Handle string format
        return datetime.strptime(time_value, "%Y%m%d%H%M%SZ").replace(
            tzinfo=timezone.utc
        )

    # ── Maintenance / cleanup ──────────────────────────────────────────

    def remove_expired_nonces(self) -> int:
        """Remove expired nonces from LDAP. Returns count deleted."""
        now_str = self._format_time(datetime.now(timezone.utc))
        nonces_dn = DN(("ou", "nonces"), self.base_dn)
        deleted = 0
        try:
            conn = get_ldap_connection()
            entries = conn.get_entries(
                nonces_dn,
                scope=conn.SCOPE_ONELEVEL,
                filter=f"(&(objectClass=acmeNonce)(acmeExpires<={now_str}))",
                attrs_list=["cn"],
            )
            for entry in entries:
                try:
                    conn.delete_entry(entry)
                    deleted += 1
                except errors.NotFound:
                    pass
        except errors.NotFound:
            pass
        if deleted:
            logger.debug("Removed %d expired nonces", deleted)
        return deleted

    def remove_expired_orders(self) -> int:
        """Remove expired orders from LDAP. Returns count deleted."""
        now_str = self._format_time(datetime.now(timezone.utc))
        orders_dn = DN(("ou", "orders"), self.base_dn)
        deleted = 0
        try:
            conn = get_ldap_connection()
            entries = conn.get_entries(
                orders_dn,
                scope=conn.SCOPE_ONELEVEL,
                filter=f"(&(objectClass=acmeOrder)(acmeExpires<={now_str}))",
                attrs_list=["cn"],
            )
            for entry in entries:
                try:
                    conn.delete_entry(entry)
                    deleted += 1
                except errors.NotFound:
                    pass
        except errors.NotFound:
            pass
        if deleted:
            logger.debug("Removed %d expired orders", deleted)
        return deleted

    def remove_expired_authorizations(self) -> int:
        """Remove expired authorizations from LDAP. Returns count deleted."""
        now_str = self._format_time(datetime.now(timezone.utc))
        authz_dn = DN(("ou", "authorizations"), self.base_dn)
        deleted = 0
        try:
            conn = get_ldap_connection()
            entries = conn.get_entries(
                authz_dn,
                scope=conn.SCOPE_ONELEVEL,
                filter=f"(&(objectClass=acmeAuthorization)"
                f"(acmeExpires<={now_str}))",
                attrs_list=["cn"],
            )
            for entry in entries:
                try:
                    conn.delete_entry(entry)
                    deleted += 1
                except errors.NotFound:
                    pass
        except errors.NotFound:
            pass
        if deleted:
            logger.debug("Removed %d expired authorizations", deleted)
        return deleted
