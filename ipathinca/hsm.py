# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
# pylint: disable=no-member
# PyKCS11 exposes PKCS#11 constants (CKA_*, CKF_*, CKK_*, CKM_*, CKO_*)
# dynamically at runtime; pylint cannot resolve them statically.

"""
Hardware Security Module (HSM) Support

Provides PKCS#11 integration for storing CA private keys in Hardware
Security Modules (HSMs).
"""

import logging
import os
import threading
from typing import Optional, Dict, Any, List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ipalib import errors
from ipathinca.exceptions import CAConfigurationError

logger = logging.getLogger(__name__)

# Try to import PyKCS11 (optional dependency)
try:
    import PyKCS11

    PKCS11_AVAILABLE = True
except ImportError:
    PKCS11_AVAILABLE = False
    logger.warning(
        "PyKCS11 not available - HSM support will be limited. Install with: "
        "pip install PyKCS11"
    )


class HSMConfig:
    """HSM Configuration"""

    def __init__(self, config_dict: Dict[str, Any] = None):
        """
        Initialize HSM configuration

        Args:
            config_dict: Configuration dictionary with HSM settings
        """
        config = config_dict or {}

        # PKCS#11 library path (e.g., /usr/lib64/pkcs11/libsofthsm2.so)
        self.pkcs11_library = config.get(
            "pkcs11_library", "/usr/lib64/pkcs11/libsofthsm2.so"
        )

        # Slot ID or label
        self.slot_id = config.get("slot_id")
        self.slot_label = config.get("slot_label", "IPA-CA")

        # Token PIN (required - no insecure default)
        self.token_pin = config.get("token_pin")
        if not self.token_pin:
            raise CAConfigurationError(
                "HSM token_pin must be explicitly configured"
            )

        # Key label prefix
        self.key_label_prefix = config.get("key_label_prefix", "ipa-ca")

        # Session configuration
        self.max_sessions = config.get("max_sessions", 10)
        self.session_timeout = config.get("session_timeout", 300)  # 5 minutes

        # Failover configuration
        self.failover_enabled = config.get("failover_enabled", False)
        self.failover_library = config.get("failover_library")
        self.failover_slot_id = config.get("failover_slot_id")

    def validate(self) -> bool:
        """Validate HSM configuration"""
        if not os.path.exists(self.pkcs11_library):
            logger.error("PKCS#11 library not found: %s", self.pkcs11_library)
            return False

        if not self.slot_id and not self.slot_label:
            logger.error("Either slot_id or slot_label must be specified")
            return False

        return True


class HSMSession:
    """HSM Session Manager"""

    def __init__(self, pkcs11_lib, slot_id: int, pin: str):
        """
        Initialize HSM session

        Args:
            pkcs11_lib: PKCS#11 library instance
            slot_id: HSM slot ID
            pin: Token PIN
        """
        self.pkcs11 = pkcs11_lib
        self.slot_id = slot_id
        self.pin = pin
        self.session = None
        self._lock = threading.Lock()
        self._opened_by_context = False

    def open(self):
        """Open HSM session"""
        if not PKCS11_AVAILABLE:
            raise errors.DependencyError(
                error=(
                    "PyKCS11 is not installed. Install with: pip install "
                    "PyKCS11"
                )
            )

        try:
            self.session = self.pkcs11.openSession(
                self.slot_id,
                PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION,
            )
            self.session.login(self.pin)
            logger.debug("Opened HSM session for slot %s", self.slot_id)
        except PyKCS11.PyKCS11Error as e:
            logger.error("Failed to open HSM session: %s", e)
            raise errors.CertificateOperationError(
                error=f"Failed to open HSM session: {e}"
            )

    def close(self):
        """Close HSM session"""
        if self.session:
            try:
                self.session.logout()
                self.session.closeSession()
                logger.debug("Closed HSM session")
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Error closing HSM session: %s", e)
            finally:
                self.session = None

    def __enter__(self):
        """Context manager entry"""
        self._lock.acquire()
        self._opened_by_context = not bool(self.session)
        if not self.session:
            self.open()
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit — close session if opened by this context"""
        try:
            if self._opened_by_context:
                try:
                    self.close()
                except Exception as e:  # pylint: disable=broad-exception-caught
                    logger.warning("Error closing HSM session: %s", e)
        finally:
            self._opened_by_context = False
            self._lock.release()
        return False


class HSMKeyBackend:
    """
    HSM Key Backend

    Manages CA private keys stored in Hardware Security Modules
    """

    def __init__(self, config: HSMConfig):
        """
        Initialize HSM key backend

        Args:
            config: HSM configuration
        """
        self.config = config

        if not self.config.validate():
            raise CAConfigurationError("Invalid HSM configuration")

        if not PKCS11_AVAILABLE:
            raise errors.DependencyError(
                error=(
                    "PyKCS11 is not installed. Install with: pip install "
                    "PyKCS11"
                )
            )

        # Initialize PKCS#11
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        try:
            self.pkcs11.load(self.config.pkcs11_library)
            logger.info(
                "Loaded PKCS#11 library: %s", self.config.pkcs11_library
            )
        except PyKCS11.PyKCS11Error as e:
            raise errors.CertificateOperationError(
                error=f"Failed to load PKCS#11 library: {e}"
            )

        # Find slot
        self.slot_id = self._find_slot()

        # Initialize session manager
        self.session_manager = HSMSession(
            self.pkcs11, self.slot_id, self.config.token_pin
        )

    def _find_slot(self) -> int:
        """Find HSM slot by ID or label"""
        if self.config.slot_id is not None:
            return self.config.slot_id

        # Find slot by label
        try:
            slots = self.pkcs11.getSlotList(tokenPresent=True)
            for slot in slots:
                token_info = self.pkcs11.getTokenInfo(slot)
                if token_info.label.strip() == self.config.slot_label:
                    logger.info(
                        "Found slot %s with label '%s'",
                        slot,
                        self.config.slot_label,
                    )
                    return slot

            raise errors.NotFound(
                reason=(
                    f"No HSM slot found with label '{self.config.slot_label}'"
                )
            )
        except PyKCS11.PyKCS11Error as e:
            raise errors.CertificateOperationError(
                error=f"Failed to find HSM slot: {e}"
            )

    def generate_key_pair(
        self, key_label: str, key_size: int = 2048, key_type: str = "RSA"
    ) -> Tuple[Any, Any]:
        """
        Generate key pair in HSM

        Args:
            key_label: Label for the key in HSM
            key_size: Key size in bits (default: 2048)
            key_type: Key type ("RSA" or "EC", default: "RSA")

        Returns:
            Tuple of (public_key_handle, private_key_handle)
        """
        logger.info(
            "Generating %s key pair in HSM with label: %s", key_type, key_label
        )

        with self.session_manager as session:
            try:
                if key_type == "RSA":
                    # RSA key generation
                    public_template = [
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                        (PyKCS11.CKA_TOKEN, True),
                        (PyKCS11.CKA_PRIVATE, False),
                        (PyKCS11.CKA_MODULUS_BITS, key_size),
                        (
                            PyKCS11.CKA_PUBLIC_EXPONENT,
                            (0x01, 0x00, 0x01),
                        ),  # 65537
                        (PyKCS11.CKA_ENCRYPT, True),
                        (PyKCS11.CKA_VERIFY, True),
                        (PyKCS11.CKA_WRAP, True),
                        (PyKCS11.CKA_LABEL, key_label),
                    ]

                    private_template = [
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                        (PyKCS11.CKA_TOKEN, True),
                        (PyKCS11.CKA_PRIVATE, True),
                        (PyKCS11.CKA_SENSITIVE, True),
                        (PyKCS11.CKA_DECRYPT, True),
                        (PyKCS11.CKA_SIGN, True),
                        (PyKCS11.CKA_UNWRAP, True),
                        (
                            PyKCS11.CKA_EXTRACTABLE,
                            False,
                        ),  # Cannot extract private key
                        (PyKCS11.CKA_LABEL, key_label),
                    ]

                    pub_key, priv_key = session.generateKeyPair(
                        public_template, private_template
                    )

                elif key_type == "EC":
                    # EC key generation (P-256 curve)
                    # This is a simplified example - you may want to support
                    # more curves
                    public_template = [
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_EC),
                        (PyKCS11.CKA_TOKEN, True),
                        (PyKCS11.CKA_PRIVATE, False),
                        (PyKCS11.CKA_VERIFY, True),
                        (PyKCS11.CKA_LABEL, key_label),
                        # EC parameters for P-256 curve (secp256r1)
                        (
                            PyKCS11.CKA_EC_PARAMS,
                            (
                                0x06,
                                0x08,
                                0x2A,
                                0x86,
                                0x48,
                                0xCE,
                                0x3D,
                                0x03,
                                0x01,
                                0x07,
                            ),
                        ),
                    ]

                    private_template = [
                        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_EC),
                        (PyKCS11.CKA_TOKEN, True),
                        (PyKCS11.CKA_PRIVATE, True),
                        (PyKCS11.CKA_SENSITIVE, True),
                        (PyKCS11.CKA_SIGN, True),
                        (PyKCS11.CKA_EXTRACTABLE, False),
                        (PyKCS11.CKA_LABEL, key_label),
                    ]

                    pub_key, priv_key = session.generateKeyPair(
                        public_template, private_template
                    )

                else:
                    raise ValueError(f"Unsupported key type: {key_type}")

                logger.info(
                    "Successfully generated key pair in HSM: %s", key_label
                )
                return pub_key, priv_key

            except PyKCS11.PyKCS11Error as e:
                logger.error("Failed to generate key pair in HSM: %s", e)
                raise errors.CertificateOperationError(
                    error=f"Failed to generate key pair in HSM: {e}"
                )

    def find_key(self, key_label: str) -> Optional[Any]:
        """
        Find private key in HSM by label

        Args:
            key_label: Key label

        Returns:
            Private key handle or None
        """
        with self.session_manager as session:
            try:
                template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_LABEL, key_label),
                ]

                objects = session.findObjects(template)

                if objects:
                    logger.debug("Found private key in HSM: %s", key_label)
                    return objects[0]
                logger.debug("Private key not found in HSM: %s", key_label)
                return None

            except PyKCS11.PyKCS11Error as e:
                logger.error("Error finding key in HSM: %s", e)
                return None

    def get_public_key(self, key_label: str) -> Optional[Any]:
        """
        Get public key from HSM

        Args:
            key_label: Key label

        Returns:
            Public key object (cryptography library format)
        """
        with self.session_manager as session:
            try:
                # Find public key object
                template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_LABEL, key_label),
                ]

                objects = session.findObjects(template)

                if not objects:
                    logger.warning(
                        "Public key not found in HSM: %s", key_label
                    )
                    return None

                pub_key_obj = objects[0]

                # Get key attributes
                attrs = session.getAttributeValue(
                    pub_key_obj, [PyKCS11.CKA_KEY_TYPE]
                )
                key_type = attrs[0]

                if key_type == PyKCS11.CKK_RSA:
                    # RSA public key
                    attrs = session.getAttributeValue(
                        pub_key_obj,
                        [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT],
                    )

                    modulus_bytes = bytes(attrs[0])
                    exponent_bytes = bytes(attrs[1])

                    # Convert to integers
                    n = int.from_bytes(modulus_bytes, byteorder="big")
                    e = int.from_bytes(exponent_bytes, byteorder="big")

                    # Create RSA public key
                    public_key = rsa.RSAPublicNumbers(e, n).public_key()
                    return public_key

                if key_type == PyKCS11.CKK_EC:
                    # Get EC parameters (curve OID) and EC point
                    ec_attrs = session.getAttributeValue(
                        pub_key_obj,
                        [PyKCS11.CKA_EC_PARAMS, PyKCS11.CKA_EC_POINT],
                    )
                    ec_params_der = bytes(ec_attrs[0])
                    ec_point_der = bytes(ec_attrs[1])

                    # Map common curve OIDs to cryptography curves
                    # EC params is DER-encoded OID
                    p256 = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
                    p384 = b"\x06\x05\x2b\x81\x04\x00\x22"
                    p521 = b"\x06\x05\x2b\x81\x04\x00\x23"
                    ec_curve_oids = {
                        p256: ec.SECP256R1(),
                        p384: ec.SECP384R1(),
                        p521: ec.SECP521R1(),
                    }

                    curve = ec_curve_oids.get(ec_params_der)
                    if curve is None:
                        logger.warning(
                            "Unsupported EC curve OID from HSM: %s",
                            ec_params_der.hex(),
                        )
                        return None

                    # EC point from PKCS#11 is DER OCTET STRING wrapping
                    # the uncompressed point (0x04 || x || y)
                    if ec_point_der[0] == 0x04:
                        # DER OCTET STRING: tag(0x04) + length + data
                        length_byte = ec_point_der[1]
                        if length_byte & 0x80:
                            # Long form length
                            num_len_bytes = length_byte & 0x7F
                            data_offset = 2 + num_len_bytes
                        else:
                            # Short form length
                            data_offset = 2
                        point_bytes = ec_point_der[data_offset:]
                        # Verify the inner data starts with 0x04
                        # (uncompressed point marker)
                        if not point_bytes or point_bytes[0] != 0x04:
                            # No DER wrapper — treat as raw point
                            point_bytes = ec_point_der
                    else:
                        point_bytes = ec_point_der

                    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                        curve, point_bytes
                    )
                    return public_key

                logger.warning("Unsupported key type in HSM: %s", key_type)
                return None

            except PyKCS11.PyKCS11Error as e:
                logger.error("Error getting public key from HSM: %s", e)
                return None

    def sign(
        self, key_label: str, data: bytes, hash_algorithm=hashes.SHA256()
    ) -> bytes:
        """
        Sign data using HSM private key

        Args:
            key_label: Key label in HSM
            data: Data to sign
            hash_algorithm: Hash algorithm to use

        Returns:
            Signature bytes
        """
        logger.debug("Signing data with HSM key: %s", key_label)

        with self.session_manager as session:
            try:
                # Find private key (use session directly to avoid deadlock)
                template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_LABEL, key_label),
                ]
                objects = session.findObjects(template)

                if not objects:
                    raise errors.NotFound(
                        reason=f"Private key not found in HSM: {key_label}"
                    )

                priv_key = objects[0]

                # Determine mechanism based on hash algorithm
                # Note: CKM_SHA*_RSA_PKCS mechanisms perform hashing internally
                if isinstance(hash_algorithm, hashes.SHA256):
                    mechanism = PyKCS11.Mechanism(
                        PyKCS11.CKM_SHA256_RSA_PKCS, None
                    )
                elif isinstance(hash_algorithm, hashes.SHA384):
                    mechanism = PyKCS11.Mechanism(
                        PyKCS11.CKM_SHA384_RSA_PKCS, None
                    )
                elif isinstance(hash_algorithm, hashes.SHA512):
                    mechanism = PyKCS11.Mechanism(
                        PyKCS11.CKM_SHA512_RSA_PKCS, None
                    )
                else:
                    # Fallback to SHA256
                    mechanism = PyKCS11.Mechanism(
                        PyKCS11.CKM_SHA256_RSA_PKCS, None
                    )

                # Sign the data (pass original data, not hash, as mechanism
                # includes hashing)
                signature = session.sign(priv_key, data, mechanism)

                # Convert to bytes
                signature_bytes = bytes(signature)

                logger.debug(
                    "Successfully signed data with HSM key: %s", key_label
                )
                return signature_bytes

            except PyKCS11.PyKCS11Error as e:
                logger.error("Failed to sign data with HSM: %s", e)
                raise errors.CertificateOperationError(
                    error=f"Failed to sign data with HSM: {e}"
                )

    def delete_key(self, key_label: str):
        """
        Delete key from HSM

        Args:
            key_label: Key label
        """
        logger.info("Deleting key from HSM: %s", key_label)

        with self.session_manager as session:
            try:
                # Find and delete private key (use session directly to avoid
                # deadlock)
                priv_template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_LABEL, key_label),
                ]
                priv_keys = session.findObjects(priv_template)
                for priv_key in priv_keys:
                    session.destroyObject(priv_key)
                    logger.info("Deleted private key from HSM: %s", key_label)

                # Find and delete public key
                pub_template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_LABEL, key_label),
                ]
                pub_keys = session.findObjects(pub_template)
                for pub_key in pub_keys:
                    session.destroyObject(pub_key)
                    logger.info("Deleted public key from HSM: %s", key_label)

            except PyKCS11.PyKCS11Error as e:
                logger.error("Failed to delete key from HSM: %s", e)
                raise errors.CertificateOperationError(
                    error=f"Failed to delete key from HSM: {e}"
                )

    def list_keys(self) -> List[str]:
        """
        List all keys in HSM

        Returns:
            List of key labels
        """
        with self.session_manager as session:
            try:
                template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                ]

                objects = session.findObjects(template)

                key_labels = []
                for obj in objects:
                    attrs = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL])
                    if attrs and attrs[0]:
                        # Handle both string and byte array formats
                        if isinstance(attrs[0], str):
                            label = attrs[0].strip()
                        else:
                            # Byte array format
                            label = "".join(chr(c) for c in attrs[0] if c != 0)
                        if label:  # Only append non-empty labels
                            key_labels.append(label)

                return key_labels

            except PyKCS11.PyKCS11Error as e:
                logger.error("Failed to list keys in HSM: %s", e)
                return []

    def close(self):
        """Close HSM connection"""
        if self.session_manager:
            self.session_manager.close()


class HSMPrivateKeyProxy:
    """
    Private Key Proxy for HSM-backed keys

    This class acts as a proxy for private keys stored in an HSM, making them
    compatible with the cryptography library's signing interface.
    """

    def __init__(self, hsm_backend: HSMKeyBackend, key_label: str):
        """
        Initialize HSM private key proxy

        Args:
            hsm_backend: HSM backend instance
            key_label: Label of the key in the HSM
        """
        self.hsm_backend = hsm_backend
        self.key_label = key_label
        self._public_key = None

    def sign(self, data: bytes, _padding, algorithm) -> bytes:
        """
        Sign data using HSM private key

        This method is compatible with the cryptography library's
        PrivateKey.sign() interface.

        Args:
            data: Data to sign
            padding: Padding to use (ignored for HSM, uses PKCS#1 v1.5)
            algorithm: Hash algorithm to use

        Returns:
            Signature bytes
        """
        # The HSM backend's sign method handles the signing
        return self.hsm_backend.sign(self.key_label, data, algorithm)

    def public_key(self):
        """
        Get the public key corresponding to this private key

        Returns:
            Public key object (cryptography library format)
        """
        if self._public_key is None:
            self._public_key = self.hsm_backend.get_public_key(self.key_label)
        return self._public_key

    @property
    def key_size(self) -> int:
        """
        Get key size in bits

        Returns:
            Key size in bits
        """
        # Get the public key and extract key size from it
        pub_key = self.public_key()
        if pub_key:
            if hasattr(pub_key, "key_size"):
                return pub_key.key_size
        # Default to 2048 if we can't determine
        return 2048


_HSM_BACKEND = None
_HSM_BACKEND_LOCK = threading.Lock()


def get_hsm_backend(config: HSMConfig = None) -> Optional[HSMKeyBackend]:
    """
    Get HSM backend instance

    Args:
        config: HSM configuration (optional, uses default if not provided)

    Returns:
        HSMKeyBackend instance or None if HSM not configured
    """
    global _HSM_BACKEND  # pylint: disable=global-statement

    with _HSM_BACKEND_LOCK:
        if _HSM_BACKEND is None and config:
            try:
                _HSM_BACKEND = HSMKeyBackend(config)
                logger.info("HSM backend initialized")
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Failed to initialize HSM backend: %s", e)
                return None

        return _HSM_BACKEND


def is_hsm_available() -> bool:
    """Check if HSM support is available"""
    return PKCS11_AVAILABLE


def list_pkcs11_slots(library_path: str) -> List[Dict[str, Any]]:
    """
    List all available PKCS#11 slots for a given library.

    Args:
        library_path: Path to PKCS#11 library

    Returns:
        List of slot dictionaries with slot information
    """
    if not PKCS11_AVAILABLE:
        raise ImportError(
            "PyKCS11 not available. Install with: pip install PyKCS11"
        )

    slots = []

    try:
        # Load PKCS#11 library
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(library_path)

        # Get all slots
        slot_list = pkcs11.getSlotList()

        for slot_id in slot_list:
            try:
                # Get slot info
                slot_info = pkcs11.getSlotInfo(slot_id)

                slot_data = {
                    "slot_id": slot_id,
                    "slot_description": slot_info.slotDescription.strip(),
                    "manufacturer_id": slot_info.manufacturerID.strip(),
                    "flags": slot_info.flags,
                    "token_present": bool(
                        slot_info.flags & PyKCS11.CKF_TOKEN_PRESENT
                    ),
                }

                # If token is present, get token info
                if slot_data["token_present"]:
                    try:
                        token_info = pkcs11.getTokenInfo(slot_id)

                        # Handle version tuples (PyKCS11 returns tuples)
                        hw_version = (
                            f"{token_info.hardwareVersion[0]}."
                            f"{token_info.hardwareVersion[1]}"
                        )

                        fw_version = (
                            f"{token_info.firmwareVersion[0]}."
                            f"{token_info.firmwareVersion[1]}"
                        )

                        slot_data.update(
                            {
                                "token_label": token_info.label.strip(),
                                "model": token_info.model.strip(),
                                "serial_number": (
                                    token_info.serialNumber.strip()
                                ),
                                "hardware_version": hw_version,
                                "firmware_version": fw_version,
                            }
                        )
                    except PyKCS11.PyKCS11Error as e:
                        logger.warning(
                            "Could not get token info for slot %s: %s",
                            slot_id,
                            e,
                        )

                slots.append(slot_data)

            except PyKCS11.PyKCS11Error as e:
                logger.warning(
                    "Could not get info for slot %s: %s", slot_id, e
                )
                continue

        return slots

    except PyKCS11.PyKCS11Error as e:
        logger.error("Error listing PKCS#11 slots: %s", e)
        raise CAConfigurationError(
            f"Failed to list PKCS#11 slots: {e}"
        ) from e
    except Exception as e:
        logger.error("Unexpected error listing PKCS#11 slots: %s", e)
        raise


_TOKEN_FLAG_NAMES = [
    (lambda: PyKCS11.CKF_RNG, "RNG"),
    (lambda: PyKCS11.CKF_WRITE_PROTECTED, "WRITE_PROTECTED"),
    (lambda: PyKCS11.CKF_LOGIN_REQUIRED, "LOGIN_REQUIRED"),
    (lambda: PyKCS11.CKF_USER_PIN_INITIALIZED, "USER_PIN_INITIALIZED"),
    (lambda: PyKCS11.CKF_RESTORE_KEY_NOT_NEEDED, "RESTORE_KEY_NOT_NEEDED"),
    (lambda: PyKCS11.CKF_CLOCK_ON_TOKEN, "CLOCK_ON_TOKEN"),
    (lambda: PyKCS11.CKF_PROTECTED_AUTHENTICATION_PATH,
     "PROTECTED_AUTHENTICATION_PATH"),
    (lambda: PyKCS11.CKF_DUAL_CRYPTO_OPERATIONS, "DUAL_CRYPTO_OPERATIONS"),
    (lambda: PyKCS11.CKF_TOKEN_INITIALIZED, "TOKEN_INITIALIZED"),
    (lambda: PyKCS11.CKF_SECONDARY_AUTHENTICATION,
     "SECONDARY_AUTHENTICATION"),
    (lambda: PyKCS11.CKF_USER_PIN_COUNT_LOW, "USER_PIN_COUNT_LOW"),
    (lambda: PyKCS11.CKF_USER_PIN_FINAL_TRY, "USER_PIN_FINAL_TRY"),
    (lambda: PyKCS11.CKF_USER_PIN_LOCKED, "USER_PIN_LOCKED"),
    (lambda: PyKCS11.CKF_USER_PIN_TO_BE_CHANGED, "USER_PIN_TO_BE_CHANGED"),
    (lambda: PyKCS11.CKF_SO_PIN_COUNT_LOW, "SO_PIN_COUNT_LOW"),
    (lambda: PyKCS11.CKF_SO_PIN_FINAL_TRY, "SO_PIN_FINAL_TRY"),
    (lambda: PyKCS11.CKF_SO_PIN_LOCKED, "SO_PIN_LOCKED"),
    (lambda: PyKCS11.CKF_SO_PIN_TO_BE_CHANGED, "SO_PIN_TO_BE_CHANGED"),
]


def _parse_token_flags(flags: int) -> List[str]:
    """Extract set PKCS#11 token flags as human-readable names."""
    return [name for flag_fn, name in _TOKEN_FLAG_NAMES if flags & flag_fn()]


def _get_library_info(pkcs11) -> Tuple[str, str]:
    """Get PKCS#11 library description and version."""
    try:
        lib_info = pkcs11.getInfo()
        description = lib_info.libraryDescription.strip()
        if isinstance(lib_info.libraryVersion, tuple):
            version = (
                f"{lib_info.libraryVersion[0]}."
                f"{lib_info.libraryVersion[1]}"
            )
        else:
            version = (
                f"{lib_info.libraryVersion.major}."
                f"{lib_info.libraryVersion.minor}"
            )
        return description, version
    except (PyKCS11.PyKCS11Error, AttributeError, IndexError):
        return "Unknown", "Unknown"


def _find_slot_by_label(pkcs11, slot_label: str) -> int:
    """Find a PKCS#11 slot by its token label."""
    slot_list = pkcs11.getSlotList(tokenPresent=True)
    for slot in slot_list:
        try:
            token_info = pkcs11.getTokenInfo(slot)
            if token_info.label.strip() == slot_label:
                return slot
        except PyKCS11.PyKCS11Error:
            continue
    raise ValueError(f"No slot found with label '{slot_label}'")


def _get_token_details(token_info) -> Dict[str, Any]:
    """Extract token details into a dictionary."""
    return {
        "token_label": token_info.label.strip(),
        "token_manufacturer": token_info.manufacturerID.strip(),
        "token_model": token_info.model.strip(),
        "token_serial": token_info.serialNumber.strip(),
        "hardware_version": (
            f"{token_info.hardwareVersion[0]}."
            f"{token_info.hardwareVersion[1]}"
        ),
        "firmware_version": (
            f"{token_info.firmwareVersion[0]}."
            f"{token_info.firmwareVersion[1]}"
        ),
        "total_public_memory": token_info.ulTotalPublicMemory,
        "free_public_memory": token_info.ulFreePublicMemory,
        "total_private_memory": token_info.ulTotalPrivateMemory,
        "free_private_memory": token_info.ulFreePrivateMemory,
        "max_session_count": token_info.ulMaxSessionCount,
        "session_count": token_info.ulSessionCount,
        "max_rw_session_count": token_info.ulMaxRwSessionCount,
        "rw_session_count": token_info.ulRwSessionCount,
        "max_pin_len": token_info.ulMaxPinLen,
        "min_pin_len": token_info.ulMinPinLen,
        "flags": _parse_token_flags(token_info.flags),
    }


def get_hsm_info(
    library_path: str,
    slot_id: Optional[int] = None,
    slot_label: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get detailed HSM device and token information

    Args:
        library_path: Path to PKCS#11 library
        slot_id: Slot ID (optional, will search by label if not provided)
        slot_label: Slot label (used if slot_id not provided)

    Returns:
        Dictionary with comprehensive HSM device and token information
    """
    if not PKCS11_AVAILABLE:
        raise ImportError(
            "PyKCS11 not available. Install with: pip install PyKCS11"
        )

    try:
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(library_path)

        lib_description, lib_version = _get_library_info(pkcs11)

        if slot_id is None:
            if not slot_label:
                raise ValueError(
                    "Either slot_id or slot_label must be provided"
                )
            slot_id = _find_slot_by_label(pkcs11, slot_label)

        slot_info = pkcs11.getSlotInfo(slot_id)

        hsm_info = {
            "library_path": library_path,
            "library_description": lib_description,
            "library_version": lib_version,
            "slot_id": slot_id,
            "slot_description": slot_info.slotDescription.strip(),
            "manufacturer_id": slot_info.manufacturerID.strip(),
            "token_present": bool(slot_info.flags & PyKCS11.CKF_TOKEN_PRESENT),
        }

        if hsm_info["token_present"]:
            token_info = pkcs11.getTokenInfo(slot_id)
            hsm_info.update(_get_token_details(token_info))

        return hsm_info

    except PyKCS11.PyKCS11Error as e:
        logger.error("Error getting HSM info: %s", e)
        raise CAConfigurationError(
            f"Failed to get HSM info: {e}"
        ) from e
    except Exception as e:
        logger.error("Unexpected error getting HSM info: %s", e)
        raise
