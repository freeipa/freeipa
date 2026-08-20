# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

import logging
import threading
import traceback
from functools import wraps

from cryptography import x509

from ipacta.backend import get_python_ca_backend
from ipacta.nss_utils import NSSDatabase
from ipacta.kra import get_kra
from ipacta.storage.kra import KRAStorageBackend
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

# Global CA backend instance
ca_backend = None

# Global KRA instance
kra_backend = None
kra_init_error = None

# Global configuration (loaded from ipacta.conf)
ipa_ca_config = None

# Locks for thread-safe initialization
_ca_init_lock = threading.Lock()
_kra_init_lock = threading.Lock()


def require_ca_backend(f):
    """Decorator to auto-initialize backend before endpoint execution"""

    @wraps(f)
    def wrapper(*args, **kwargs):
        init_ca()
        return f(*args, **kwargs)

    return wrapper


def init_ca():
    """Initialize CA backend (lazy, called on first request)"""
    global ca_backend
    if ca_backend is not None:
        return
    with _ca_init_lock:
        if ca_backend is not None:
            return
        try:
            logger.debug("Initializing Python CA backend...")
            ca_backend = get_python_ca_backend()
            logger.debug(
                "Python CA backend initialized successfully with LDAP storage"
            )
            _setup_reload_manager(ca_backend)
        except Exception as e:
            logger.error("Failed to initialize CA backend: %s", e)
            logger.error(traceback.format_exc())
            raise


def _setup_reload_manager(backend):
    """Set up certificate reload manager after CA init"""
    try:
        from ipacta.certificate.reload_manager import get_reload_manager

        reload_manager = get_reload_manager(backend)
        reload_manager.setup_signal_handler()
        logger.info(
            "Certificate reload manager initialized - send SIGHUP "
            "to reload certificates without service restart"
        )
    except Exception as e:
        logger.warning(
            "Failed to initialize certificate reload manager: %s", e
        )


def init_kra():
    """Initialize KRA backend"""
    global kra_backend, kra_init_error
    if kra_backend is not None:
        return
    with _kra_init_lock:
        if kra_backend is not None:
            return
        try:
            logger.info("Initializing KRA backend...")

            # Get KRA instance
            logger.debug("Getting KRA instance...")
            kra = get_kra()

            # Initialize KRA storage
            logger.debug("Initializing KRA storage backend...")
            kra_storage = KRAStorageBackend()

            # Load CA certificate and key from disk (same as enable_kra does)
            # This is needed for signing the KRA transport certificate
            try:
                logger.debug("Loading CA cert from %s", paths.IPA_CA_CRT)
                with open(paths.IPA_CA_CRT, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read())

                # Extract CA key from NSSDB (consistent with ca.py)
                logger.debug(
                    "Extracting CA key from NSSDB for KRA initialization"
                )
                nssdb = NSSDatabase()
                ca_key = nssdb.extract_private_key("caSigningCert cert-pki-ca")

                # Initialize KRA with CA keys and storage
                logger.debug("Calling kra.initialize()...")
                kra.initialize(
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                    storage_backend=kra_storage,
                )
                kra_backend = kra
                logger.info("KRA backend initialized successfully")

            except FileNotFoundError as e:
                logger.error(
                    "CA keys not found, KRA initialization failed: %s", e
                )
                logger.error(traceback.format_exc())
                kra_init_error = f"CA keys not found: {e}"
            except Exception as e:
                logger.error("Failed to load CA keys for KRA: %s", e)
                logger.error(traceback.format_exc())
                kra_init_error = f"Key load error: {e}"

        except Exception as e:
            logger.error("Failed to initialize KRA backend: %s", e)
            logger.error(traceback.format_exc())
            kra_init_error = str(e)
