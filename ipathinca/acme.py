# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
ACME (Automatic Certificate Management Environment) protocol implementation
RFC 8555 compliant ACME server using python-cryptography
"""

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature

from ipathinca import get_config_value
from ipathinca.ca import PythonCA, RevocationReason
from ipathinca.jwk import JWK
from ipathinca.storage_acme import ACMEStorageBackend

logger = logging.getLogger(__name__)


def _generate_token(nbytes: int = 32) -> str:
    """Generate a URL-safe base64 random token."""
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")


class JWS:
    """JSON Web Signature implementation without jose dependency"""

    @staticmethod
    def sign(payload: bytes, key, protected_header: Dict[str, Any]) -> str:
        """Create JWS signature"""
        # Encode protected header
        protected_encoded = (
            base64.urlsafe_b64encode(
                json.dumps(protected_header, separators=(",", ":")).encode()
            )
            .decode()
            .rstrip("=")
        )

        # Encode payload
        payload_encoded = (
            base64.urlsafe_b64encode(payload).decode().rstrip("=")
        )

        # Create signing input
        signing_input = f"{protected_encoded}.{payload_encoded}".encode()

        # Sign based on key type and algorithm
        algorithm = protected_header.get("alg")
        if isinstance(key, rsa.RSAPrivateKey):
            if algorithm == "RS256":
                signature = key.sign(
                    signing_input, padding.PKCS1v15(), hashes.SHA256()
                )
            elif algorithm == "PS256":
                signature = key.sign(
                    signing_input,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            else:
                raise ValueError(f"Unsupported RSA algorithm: {algorithm}")
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            if algorithm == "ES256":
                signature = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            elif algorithm == "ES384":
                signature = key.sign(signing_input, ec.ECDSA(hashes.SHA384()))
            elif algorithm == "ES512":
                signature = key.sign(signing_input, ec.ECDSA(hashes.SHA512()))
            else:
                raise ValueError(f"Unsupported EC algorithm: {algorithm}")
        else:
            raise ValueError(f"Unsupported key type: {type(key)}")

        # Encode signature
        signature_encoded = (
            base64.urlsafe_b64encode(signature).decode().rstrip("=")
        )

        # Return JWS compact serialization
        return f"{protected_encoded}.{payload_encoded}.{signature_encoded}"

    @staticmethod
    def verify(jws_token: str, key) -> tuple[Dict[str, Any], bytes]:
        """Verify JWS signature and return header and payload"""
        try:
            protected_b64, payload_b64, signature_b64 = jws_token.split(".")
        except ValueError:
            raise ValueError("Invalid JWS format")

        # Add padding if needed (use modulo to avoid adding 4 when aligned)
        protected_b64 += "=" * ((4 - len(protected_b64) % 4) % 4)
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        signature_b64 += "=" * ((4 - len(signature_b64) % 4) % 4)

        # Decode components
        try:
            protected_header = json.loads(
                base64.urlsafe_b64decode(protected_b64)
            )
            payload = base64.urlsafe_b64decode(payload_b64)
            signature = base64.urlsafe_b64decode(signature_b64)
        except Exception as e:
            raise ValueError(f"Failed to decode JWS: {e}")

        # Verify signature
        signing_input = (
            f"{protected_b64.rstrip('=')}.{payload_b64.rstrip('=')}".encode()
        )
        algorithm = protected_header.get("alg")

        try:
            if isinstance(key, rsa.RSAPublicKey):
                if algorithm == "RS256":
                    key.verify(
                        signature,
                        signing_input,
                        padding.PKCS1v15(),
                        hashes.SHA256(),
                    )
                elif algorithm == "PS256":
                    key.verify(
                        signature,
                        signing_input,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                else:
                    raise ValueError(f"Unsupported RSA algorithm: {algorithm}")
            elif isinstance(key, ec.EllipticCurvePublicKey):
                if algorithm == "ES256":
                    key.verify(
                        signature, signing_input, ec.ECDSA(hashes.SHA256())
                    )
                elif algorithm == "ES384":
                    key.verify(
                        signature, signing_input, ec.ECDSA(hashes.SHA384())
                    )
                elif algorithm == "ES512":
                    key.verify(
                        signature, signing_input, ec.ECDSA(hashes.SHA512())
                    )
                else:
                    raise ValueError(f"Unsupported EC algorithm: {algorithm}")
            else:
                raise ValueError(f"Unsupported key type: {type(key)}")
        except InvalidSignature:
            raise ValueError("Invalid signature")

        return protected_header, payload


class ACMEError(Exception):
    """Base ACME error"""

    def __init__(self, error_type: str, detail: str, status: int = 400):
        self.error_type = error_type
        self.detail = detail
        self.status = status
        super().__init__(f"{error_type}: {detail}")


class ACMEAccount:
    """ACME account representation"""

    def __init__(
        self, account_id: str, key: Dict[str, Any], contact: List[str] = None
    ):
        self.account_id = account_id
        self.key = key
        self.contact = contact or []
        self.status = "valid"
        self.created_at = datetime.now(timezone.utc)
        self.terms_of_service_agreed = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "contact": self.contact,
            "termsOfServiceAgreed": self.terms_of_service_agreed,
            "key": self.key,
        }


class ACMEOrder:
    """ACME order representation"""

    def __init__(self, account_id: str, identifiers: List[Dict[str, str]]):
        self.order_id = self._generate_id()
        self.account_id = account_id
        self.status = "pending"
        self.identifiers = identifiers
        self.authorizations = []
        self.finalize_url = f"/acme/order/{self.order_id}/finalize"
        self.certificate_url = None
        self.expires = datetime.now(timezone.utc) + timedelta(days=1)
        self.not_before = None
        self.not_after = None

        # Create authorizations for each identifier
        for identifier in identifiers:
            auth = ACMEAuthorization(self.account_id, identifier)
            self.authorizations.append(auth)

    def _generate_id(self) -> str:
        return _generate_token()

    def to_dict(self, base_url: str) -> Dict[str, Any]:
        return {
            "status": self.status,
            "expires": self.expires.isoformat() + "Z",
            "identifiers": self.identifiers,
            "authorizations": [
                f"{base_url}/acme/authz/{auth.auth_id}"
                for auth in self.authorizations
            ],
            "finalize": f"{base_url}{self.finalize_url}",
            "certificate": (
                f"{base_url}/acme/cert/{self.order_id}"
                if self.certificate_url
                else None
            ),
        }


class ACMEChallenge:
    """ACME challenge representation"""

    def __init__(self, challenge_type: str, token: str):
        self.challenge_type = challenge_type
        self.token = token
        self.status = "pending"
        self.url = f"/acme/chall/{self.token}"
        self.validated = None

    def to_dict(self, base_url: str) -> Dict[str, Any]:
        result = {
            "type": self.challenge_type,
            "status": self.status,
            "url": f"{base_url}{self.url}",
            "token": self.token,
        }
        if self.validated:
            result["validated"] = self.validated.isoformat() + "Z"
        return result


class ACMEAuthorization:
    """ACME authorization representation"""

    def __init__(self, account_id: str, identifier: Dict[str, str]):
        self.auth_id = self._generate_id()
        self.account_id = account_id
        self.identifier = identifier
        self.status = "pending"
        self.expires = datetime.now(timezone.utc) + timedelta(hours=24)
        self.challenges = []

        # Create challenges
        if identifier["type"] == "dns":
            # DNS-01 challenge
            dns_token = _generate_token()
            self.challenges.append(ACMEChallenge("dns-01", dns_token))

            # HTTP-01 challenge
            http_token = _generate_token()
            self.challenges.append(ACMEChallenge("http-01", http_token))

    def _generate_id(self) -> str:
        return _generate_token()

    def to_dict(self, base_url: str) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "status": self.status,
            "expires": self.expires.isoformat() + "Z",
            "challenges": [
                challenge.to_dict(base_url) for challenge in self.challenges
            ],
        }


class ACMEServer:
    """ACME protocol server implementation with LDAP storage"""

    def __init__(self, ca: PythonCA, base_url: str, config):
        self.ca = ca
        self.base_url = base_url.rstrip("/")
        self.config = config

        # Initialize LDAP database backend for persistent storage
        self.db = ACMEStorageBackend(config)
        logger.info("ACME server initialized with LDAP storage backend")

    def run_maintenance(self) -> Dict[str, int]:
        """Remove expired nonces, orders, and authorizations from LDAP.

        Should be called periodically (e.g. every 30 minutes) to prevent
        unbounded LDAP growth.  Safe to call concurrently from multiple
        replicas — each delete is idempotent.

        Returns:
            dict with counts of deleted items per category.
        """
        results = {}
        try:
            results["nonces"] = self.db.remove_expired_nonces()
            results["orders"] = self.db.remove_expired_orders()
            results["authorizations"] = self.db.remove_expired_authorizations()
            total = sum(results.values())
            if total:
                logger.info(
                    "ACME maintenance: removed %d expired records (%s)",
                    total,
                    results,
                )
        except Exception as e:
            logger.warning("ACME maintenance failed: %s", e)
        return results

    def start_maintenance_timer(self, interval_minutes: int = 30):
        """Start a background thread that runs maintenance periodically."""
        import threading

        def _maintenance_loop():
            while not self._maintenance_stop.is_set():
                self._maintenance_stop.wait(interval_minutes * 60)
                if not self._maintenance_stop.is_set():
                    self.run_maintenance()

        self._maintenance_stop = threading.Event()
        self._maintenance_thread = threading.Thread(
            target=_maintenance_loop,
            daemon=True,
            name="acme-maintenance",
        )
        self._maintenance_thread.start()
        logger.info(
            "ACME maintenance timer started (every %d min)",
            interval_minutes,
        )

    def stop_maintenance_timer(self):
        """Stop the background maintenance thread."""
        stop = getattr(self, "_maintenance_stop", None)
        if stop is not None:
            stop.set()

    def _generate_nonce(self) -> str:
        """Generate replay-protection nonce and store in LDAP"""
        nonce = _generate_token()

        # Store nonce in LDAP with 30-minute expiration
        expires = datetime.now(timezone.utc) + timedelta(minutes=30)
        self.db.create_nonce(nonce, expires)

        logger.debug("Generated nonce: %s...", nonce[:20])
        return nonce

    def generate_nonce(self) -> str:
        """Public interface for nonce generation"""
        return self._generate_nonce()

    def process_jws_request(
        self, jws_token: str, expected_url: str
    ) -> tuple[Dict[str, Any], bytes, str]:
        """
        Process a JWS-signed ACME request

        Returns:
            Tuple of (protected_header, payload, account_id)
        """
        try:
            # Parse JWS without verification first to get the header
            parts = jws_token.split(".")
            if len(parts) != 3:
                raise ACMEError("malformed", "Invalid JWS format")

            # Decode protected header
            protected_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            protected_header = json.loads(
                base64.urlsafe_b64decode(protected_b64)
            )

            # Verify nonce
            nonce = protected_header.get("nonce")
            if not nonce or not self._verify_nonce(nonce):
                raise ACMEError("badNonce", "Invalid or reused nonce")

            # Verify URL
            url = protected_header.get("url")
            if url != expected_url:
                raise ACMEError("malformed", "URL mismatch")

            # Get account key
            account_key = None
            account_id = None

            if "jwk" in protected_header:
                # New account registration
                account_key = protected_header["jwk"]
                # Generate account ID from key
                key_thumbprint = JWK.thumbprint(account_key)
                account_id = hashlib.sha256(
                    key_thumbprint.encode()
                ).hexdigest()
            elif "kid" in protected_header:
                # Existing account
                account_id = protected_header["kid"].split("/")[
                    -1
                ]  # Extract from URL
                # Retrieve account from LDAP
                account_data = self.db.get_account(account_id)
                if not account_data:
                    raise ACMEError("accountDoesNotExist", "Account not found")
                account_key = account_data["key"]
            else:
                raise ACMEError("malformed", "Missing jwk or kid in header")

            # Convert JWK to cryptography key for verification
            crypto_key = self._jwk_to_cryptography_key(account_key)

            # Verify JWS signature
            verified_header, payload = JWS.verify(jws_token, crypto_key)

            return verified_header, payload, account_id

        except ACMEError:
            raise
        except Exception as e:
            raise ACMEError("malformed", f"JWS processing failed: {e}")

    def _jwk_to_cryptography_key(self, jwk_dict: Dict[str, Any]):
        """Convert JWK dictionary to cryptography key object"""
        if "kty" not in jwk_dict:
            raise ValueError("Missing required JWK field: kty")

        if jwk_dict["kty"] == "RSA":
            for field in ("n", "e"):
                if field not in jwk_dict:
                    raise ValueError(
                        f"Missing required RSA JWK field: {field}"
                    )
            n = self._decode_bigint(jwk_dict["n"])
            e = self._decode_bigint(jwk_dict["e"])
            return rsa.RSAPublicNumbers(e, n).public_key()
        elif jwk_dict["kty"] == "EC":
            for field in ("crv", "x", "y"):
                if field not in jwk_dict:
                    raise ValueError(f"Missing required EC JWK field: {field}")
            x = self._decode_ec_coordinate(jwk_dict["x"])
            y = self._decode_ec_coordinate(jwk_dict["y"])

            curve_name = jwk_dict["crv"]
            if curve_name == "P-256":
                curve = ec.SECP256R1()
            elif curve_name == "P-384":
                curve = ec.SECP384R1()
            elif curve_name == "P-521":
                curve = ec.SECP521R1()
            else:
                raise ValueError(f"Unsupported curve: {curve_name}")

            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        else:
            raise ValueError(f"Unsupported key type: {jwk_dict['kty']}")

    def _decode_bigint(self, value: str) -> int:
        """Decode base64url-encoded big integer"""
        # Add padding
        value += "=" * (4 - len(value) % 4)
        decoded = base64.urlsafe_b64decode(value)
        return int.from_bytes(decoded, byteorder="big")

    def _decode_ec_coordinate(self, value: str) -> int:
        """Decode base64url-encoded EC coordinate"""
        # Add padding
        value += "=" * (4 - len(value) % 4)
        decoded = base64.urlsafe_b64decode(value)
        return int.from_bytes(decoded, byteorder="big")

    def _verify_nonce(self, nonce: str) -> bool:
        """Verify and consume nonce from LDAP"""
        logger.debug("Verifying nonce: %s...", nonce[:20])
        valid = self.db.validate_nonce(nonce)
        if valid:
            logger.debug("Nonce verified and consumed from LDAP")
        else:
            logger.warning("Nonce not found or expired in LDAP")
        return valid

    def get_directory(self) -> Dict[str, Any]:
        """Return ACME directory (RFC 8555 Section 7.1.1)"""
        return {
            "newNonce": f"{self.base_url}/acme/new-nonce",
            "newAccount": f"{self.base_url}/acme/new-account",
            "newOrder": f"{self.base_url}/acme/new-order",
            "revokeCert": f"{self.base_url}/acme/revoke-cert",
            "keyChange": f"{self.base_url}/acme/key-change",
            "meta": {
                "termsOfService": f"{self.base_url}/acme/terms",
                "website": "https://www.freeipa.org/",
                "caaIdentities": [get_config_value("global", "domain")],
            },
        }

    def create_account(
        self, payload: Dict[str, Any], account_key: Dict[str, Any]
    ) -> tuple[ACMEAccount, bool]:
        """
        Create new ACME account (RFC 8555 Section 7.3)

        Returns:
            Tuple of (ACMEAccount, is_new) where is_new indicates if account
            was created
        """

        # Generate account ID
        key_thumbprint = self._get_key_thumbprint(account_key)
        account_id = hashlib.sha256(key_thumbprint.encode()).hexdigest()

        # Check if account already exists in LDAP
        existing_account = self.db.get_account(account_id)
        if existing_account:
            # Return existing account as ACMEAccount object
            account = ACMEAccount(
                account_id=existing_account["account_id"],
                key=existing_account["key"],
                contact=existing_account["contact"],
            )
            account.status = existing_account["status"]
            account.created_at = existing_account["created_at"]
            account.terms_of_service_agreed = existing_account.get(
                "terms_of_service_agreed", False
            )
            return (account, False)  # Account already existed

        # Create new account in LDAP
        contacts = payload.get("contact", [])
        self.db.create_account(account_id, account_key, contacts)

        # Return account object
        account = ACMEAccount(
            account_id=account_id, key=account_key, contact=contacts
        )

        if payload.get("termsOfServiceAgreed"):
            account.terms_of_service_agreed = True

        logger.info("Created ACME account %s", account_id)
        return (account, True)  # New account created

    def process_new_account(
        self, payload: Dict[str, Any], account_key: Dict[str, Any]
    ) -> tuple[ACMEAccount, bool]:
        """Alias for create_account for external compatibility"""
        return self.create_account(payload, account_key)

    def create_order(
        self, account_id: str, payload: Dict[str, Any]
    ) -> ACMEOrder:
        """Create new ACME order (RFC 8555 Section 7.4)"""

        # Check if account exists in LDAP
        account = self.db.get_account(account_id)
        if not account:
            raise ACMEError("unauthorized", "Account not found", 401)

        identifiers = payload.get("identifiers", [])
        if not identifiers:
            raise ACMEError("malformed", "No identifiers specified")

        # Validate identifiers
        for identifier in identifiers:
            if identifier.get("type") != "dns":
                raise ACMEError(
                    "unsupportedIdentifier",
                    f"Unsupported identifier type: {identifier.get('type')}",
                )

        # Create order object (in-memory for now, will store components in
        # LDAP)
        order = ACMEOrder(account_id, identifiers)

        # Store order components in LDAP
        authz_ids = []

        # Store authorizations and challenges in LDAP
        for auth in order.authorizations:
            # Create authorization in LDAP
            self.db.create_authorization(
                auth.auth_id,
                account_id,
                auth.identifier,
                False,  # wildcard
                auth.expires,
            )
            authz_ids.append(auth.auth_id)

            # Store challenges in LDAP
            for challenge in auth.challenges:
                self.db.create_challenge(
                    challenge.token,  # use token as challenge ID
                    auth.auth_id,
                    account_id,
                    challenge.challenge_type,
                    challenge.token,
                )

        # Store order in LDAP
        self.db.create_order(
            order.order_id, account_id, identifiers, authz_ids, order.expires
        )

        logger.info(
            "Created ACME order %s for account %s in LDAP",
            order.order_id,
            account_id,
        )
        return order

    def process_new_order(
        self, account_id: str, payload: Dict[str, Any]
    ) -> ACMEOrder:
        """Alias for create_order for external compatibility"""
        return self.create_order(account_id, payload)

    def get_authorization(
        self, auth_id: str, account_id: str
    ) -> ACMEAuthorization:
        """Get authorization (RFC 8555 Section 7.5)"""

        # Retrieve authorization from LDAP
        auth_data = self.db.get_authorization(auth_id)
        if not auth_data:
            raise ACMEError("notFound", "Authorization not found", 404)

        if auth_data["account_id"] != account_id:
            raise ACMEError(
                "unauthorized",
                "Authorization belongs to different account",
                401,
            )

        # Reconstruct ACMEAuthorization object from LDAP data
        auth = ACMEAuthorization(account_id, auth_data["identifier"])
        auth.auth_id = auth_data["authz_id"]
        auth.status = auth_data["status"]
        auth.expires = auth_data["expires"]

        # Note: Challenges will be loaded separately when needed
        return auth

    def respond_to_challenge(
        self, token: str, account_id: str, account_key: Dict[str, Any]
    ) -> ACMEChallenge:
        """Process challenge response (RFC 8555 Section 7.5.1)"""

        # Retrieve challenge from LDAP (token is used as challenge_id)
        challenge_data = self.db.get_challenge(token)
        if not challenge_data:
            raise ACMEError("notFound", "Challenge not found", 404)

        if challenge_data["account_id"] != account_id:
            raise ACMEError(
                "unauthorized", "Challenge belongs to different account", 401
            )

        # Retrieve associated authorization from LDAP
        auth_data = self.db.get_authorization(challenge_data["authz_id"])
        if not auth_data:
            raise ACMEError("serverInternal", "Authorization not found", 500)

        # Reconstruct challenge object
        challenge = ACMEChallenge(
            challenge_data["challenge_type"], challenge_data["token"]
        )
        challenge.status = challenge_data["status"]

        # If already validated, return immediately without re-checking
        if challenge.status == "valid":
            logger.debug("Challenge %s already valid, skipping", token)
            return challenge

        # Verify challenge based on type with retry logic
        # Network-based validation can fail transiently, so retry up to 3 times
        max_attempts = 3
        retry_delay = 2  # seconds between retries
        validated = False

        if challenge.challenge_type not in ("http-01", "dns-01"):
            raise ACMEError(
                "unsupportedChallenge",
                f"Unsupported challenge type: {challenge.challenge_type}",
            )

        for attempt in range(max_attempts):
            try:
                if challenge.challenge_type == "http-01":
                    validated = self._verify_http01_challenge(
                        challenge, account_key, auth_data["identifier"]
                    )
                elif challenge.challenge_type == "dns-01":
                    validated = self._verify_dns01_challenge(
                        challenge, account_key, auth_data["identifier"]
                    )

                if validated:
                    break

            except Exception as e:
                if attempt < max_attempts - 1:
                    logger.debug(
                        "Challenge %s validation attempt %d/%d failed: %s",
                        token,
                        attempt + 1,
                        max_attempts,
                        e,
                    )
                    import time

                    time.sleep(retry_delay)
                    continue
                logger.warning(
                    "Challenge %s validation failed after %d attempts: %s",
                    token,
                    max_attempts,
                    e,
                )

        if validated:
            validated_at = datetime.now(timezone.utc)
            challenge.status = "valid"
            challenge.validated = validated_at

            # Update challenge status in LDAP
            self.db.update_challenge_status(token, "valid", validated_at)

            # Update authorization status in LDAP
            self.db.update_authorization_status(
                challenge_data["authz_id"], "valid"
            )

        return challenge

    def finalize_order(
        self, order_id: str, account_id: str, csr_der: bytes
    ) -> ACMEOrder:
        """Finalize order and issue certificate (RFC 8555 Section 7.4)"""

        # Retrieve order from LDAP
        order_data = self.db.get_order(order_id)
        if not order_data:
            raise ACMEError("notFound", "Order not found", 404)

        if order_data["account_id"] != account_id:
            raise ACMEError(
                "unauthorized", "Order belongs to different account", 401
            )

        if order_data["status"] == "invalid":
            raise ACMEError(
                "orderNotReady", "Order is invalid and cannot be finalized"
            )

        if order_data["status"] != "ready":
            # Check if all authorizations are valid
            all_valid = True
            for authz_id in order_data["authz_ids"]:
                auth_data = self.db.get_authorization(authz_id)
                if not auth_data or auth_data["status"] != "valid":
                    all_valid = False
                    break

            if not all_valid:
                raise ACMEError(
                    "orderNotReady", "Not all authorizations are valid"
                )

            # Update order status to ready
            self.db.update_order_status(order_id, "ready")

        # Parse CSR
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except Exception as e:
            raise ACMEError("badCSR", f"Invalid CSR: {e}")

        # Validate CSR against order identifiers
        self._validate_csr_identifiers(csr, order_data["identifiers"])

        # Submit certificate request to CA
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        request_id = self.ca.submit_certificate_request(
            csr_pem, "acmeIPAServerCert"
        )

        # Sign the certificate
        serial_number = self.ca.sign_certificate_request(request_id)

        # Get the issued certificate
        cert_record = self.ca.get_certificate(serial_number)
        cert_pem = cert_record.certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode()

        # Store certificate in LDAP
        self.db.store_certificate(order_id, cert_pem)

        # Update order status to valid with certificate ID
        self.db.update_order_status(order_id, "valid", cert_id=order_id)

        # Reconstruct order object for return
        order = ACMEOrder(account_id, order_data["identifiers"])
        order.order_id = order_id
        order.status = "valid"
        order.certificate_url = f"/acme/cert/{order_id}"

        logger.info(
            "Finalized ACME order %s, issued certificate %s",
            order_id,
            serial_number,
        )
        return order

    def get_certificate(self, order_id: str, account_id: str) -> str:
        """Get issued certificate (RFC 8555 Section 7.4.2)"""

        # Retrieve order from LDAP
        order_data = self.db.get_order(order_id)
        if not order_data:
            raise ACMEError("notFound", "Order not found", 404)

        if order_data["account_id"] != account_id:
            raise ACMEError(
                "unauthorized", "Order belongs to different account", 401
            )

        if order_data["status"] != "valid" or not order_data.get(
            "certificate_id"
        ):
            raise ACMEError("orderNotReady", "Certificate not ready")

        # Retrieve certificate from LDAP
        cert_pem = self.db.get_certificate(order_data["certificate_id"])
        if not cert_pem:
            raise ACMEError("notFound", "Certificate not found", 404)

        # Include certificate chain
        ca_cert_pem = self.ca.ca_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode()

        return cert_pem + ca_cert_pem

    def _get_key_thumbprint(self, key: Dict[str, Any]) -> str:
        """Calculate JWK thumbprint (RFC 7638)"""
        return JWK.thumbprint(key)

    def _verify_http01_challenge(
        self,
        challenge: ACMEChallenge,
        account_key: Dict[str, Any],
        identifier: Dict[str, str],
    ) -> bool:
        """Verify HTTP-01 challenge (RFC 8555 Section 8.3)"""

        # Construct key authorization
        key_thumbprint = self._get_key_thumbprint(account_key)
        key_authorization = f"{challenge.token}.{key_thumbprint}"

        # Try to fetch the challenge response
        # RFC 8555 §8.3: follow redirects (HTTP → HTTPS is common)
        try:
            import requests

            url = (
                f"http://{identifier['value']}/.well-known/acme-challenge/"
                f"{challenge.token}"
            )
            response = requests.get(
                url, timeout=10, allow_redirects=True, verify=True
            )

            if response.status_code != 200:
                logger.warning(
                    "HTTP-01 challenge returned status %s for %s",
                    response.status_code,
                    identifier["value"],
                )
                return False

            if secrets.compare_digest(
                response.text.strip(), key_authorization
            ):
                logger.info(
                    "HTTP-01 challenge erification successful for %s",
                    identifier["value"],
                )
                return True

            logger.warning(
                "HTTP-01 challenge response mismatch for %s",
                identifier["value"],
            )
            return False
        except requests.ConnectionError as e:
            logger.warning("HTTP-01 challenge connection failed: %s", e)
        except requests.Timeout:
            logger.warning(
                "HTTP-01 challenge timed out for %s", identifier["value"]
            )
        except Exception as e:
            logger.error("HTTP-01 challenge unexpected error: %s", e)

        return False

    def _verify_dns01_challenge(
        self,
        challenge: ACMEChallenge,
        account_key: Dict[str, Any],
        identifier: Dict[str, str],
    ) -> bool:
        """Verify DNS-01 challenge (RFC 8555 Section 8.4)"""

        # Construct key authorization
        key_thumbprint = self._get_key_thumbprint(account_key)
        key_authorization = f"{challenge.token}.{key_thumbprint}"

        # Calculate SHA256 hash
        digest = hashlib.sha256(key_authorization.encode()).digest()
        expected_txt = base64.urlsafe_b64encode(digest).decode().rstrip("=")

        # Try to resolve DNS TXT record
        try:
            import dns.resolver

            txt_name = f"_acme-challenge.{identifier['value']}"

            answers = dns.resolver.resolve(txt_name, "TXT")
            for answer in answers:
                if (
                    answer.strings
                    and answer.strings[0]
                    and secrets.compare_digest(
                        answer.strings[0].decode(), expected_txt
                    )
                ):
                    logger.info(
                        "DNS-01 challenge verification successful for %s",
                        identifier["value"],
                    )
                    return True
        except dns.resolver.NXDOMAIN:
            logger.warning(
                "DNS-01 challenge: no TXT record for _acme-challenge.%s",
                identifier["value"],
            )
        except dns.resolver.NoAnswer:
            logger.warning(
                "DNS-01 challenge: no TXT answer for _acme-challenge.%s",
                identifier["value"],
            )
        except dns.resolver.Timeout:
            logger.warning(
                "DNS-01 challenge: DNS timeout for %s", identifier["value"]
            )
        except Exception as e:
            logger.error("DNS-01 challenge unexpected error: %s", e)

        return False

    def _validate_csr_identifiers(
        self,
        csr: x509.CertificateSigningRequest,
        order_identifiers: List[Dict[str, str]],
    ):
        """Validate CSR contains the ordered identifiers"""

        # Extract SANs from CSR
        try:
            san_ext = csr.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_dns_names = []
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    san_dns_names.append(san.value)
        except x509.ExtensionNotFound:
            san_dns_names = []

        # Check that all order identifiers are present
        order_dns_names = [
            ident["value"]
            for ident in order_identifiers
            if ident["type"] == "dns"
        ]

        for dns_name in order_dns_names:
            if dns_name not in san_dns_names:
                raise ACMEError(
                    "badCSR", f"CSR missing identifier: {dns_name}"
                )

        # Check for unauthorized wildcards: CSR must not contain wildcard
        # names that weren't in the order
        for san_name in san_dns_names:
            if san_name.startswith("*.") and san_name not in order_dns_names:
                raise ACMEError(
                    "badCSR",
                    f"CSR contains unauthorized wildcard: {san_name}",
                )

    def revoke_certificate(self, certificate_der: bytes, reason: int = 0):
        """Revoke certificate (RFC 8555 Section 7.6)"""

        try:
            cert = x509.load_der_x509_certificate(certificate_der)
            serial_number = cert.serial_number

            # Map ACME reason codes to RevocationReason

            reason_map = {
                0: RevocationReason.UNSPECIFIED,
                1: RevocationReason.KEY_COMPROMISE,
                2: RevocationReason.CA_COMPROMISE,
                3: RevocationReason.AFFILIATION_CHANGED,
                4: RevocationReason.SUPERSEDED,
                5: RevocationReason.CESSATION_OF_OPERATION,
                6: RevocationReason.CERTIFICATE_HOLD,
                9: RevocationReason.PRIVILEGE_WITHDRAWN,
                10: RevocationReason.AA_COMPROMISE,
            }

            revocation_reason = reason_map.get(
                reason, RevocationReason.UNSPECIFIED
            )
            self.ca.revoke_certificate(serial_number, revocation_reason)

            logger.info("Revoked certificate %s via ACME", serial_number)

        except Exception as e:
            raise ACMEError(
                "badRevocationRequest", f"Failed to revoke certificate: {e}"
            )
