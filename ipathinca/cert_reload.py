# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Certificate reload functionality for ipathinca

This module provides graceful certificate reload capabilities without service
downtime. Certificates are reloaded from disk in response to SIGHUP signal
or manual reload requests.
"""

import logging
import threading
import signal
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class CertificateReloadManager:
    """
    Manages graceful certificate reloading without service interruption

    This class handles reloading of CA certificates and server SSL certificates
    from disk when they are renewed by certmonger. It ensures thread-safe
    updates without interrupting ongoing requests.
    """

    def __init__(self, ca_backend=None):
        """
        Initialize the certificate reload manager

        Args:
            ca_backend: The CA backend instance to reload certificates for
        """
        self.ca_backend = ca_backend
        self._reload_lock = threading.Lock()
        self._signal_handler_registered = False

    def setup_signal_handler(self):
        """
        Register SIGHUP handler for certificate reload

        This sets up the signal handler so that sending SIGHUP to the
        ipathinca process will trigger a certificate reload.
        """
        if self._signal_handler_registered:
            logger.debug("Signal handler already registered")
            return

        try:
            signal.signal(signal.SIGHUP, self._handle_reload_signal)
            self._signal_handler_registered = True
            logger.info(
                "SIGHUP signal handler registered for certificate reload"
            )
        except Exception as e:
            logger.error(f"Failed to register signal handler: {e}")

    def _handle_reload_signal(self, signum, frame):
        """
        Signal handler for SIGHUP - triggers certificate reload

        This is called by the OS when SIGHUP is received.
        """
        logger.info("Received SIGHUP signal, initiating certificate reload")
        try:
            self.reload_certificates()
        except Exception as e:
            logger.error(f"Certificate reload failed in signal handler: {e}")

    def reload_certificates(self) -> dict:
        """
        Reload all certificates from disk

        This method:
        1. Loads new certificates from PEM files
        2. Updates the CA backend's certificates atomically
        3. Logs the reload status

        Returns:
            dict: Status information about the reload operation
        """
        if not self.ca_backend:
            logger.warning(
                "Cannot reload certificates: no CA backend configured"
            )
            return {"status": "error", "message": "No CA backend configured"}

        # Use a lock to ensure only one reload happens at a time
        # This prevents race conditions if multiple SIGHUPs are received
        with self._reload_lock:
            logger.info("Starting certificate reload from disk")

            results = {"status": "success", "reloaded": [], "errors": []}

            try:
                # Reload CA signing certificate if CA backend has one
                if hasattr(self.ca_backend, "ca") and hasattr(
                    self.ca_backend.ca, "ca_cert_path"
                ):
                    ca_result = self._reload_ca_cert()
                    if ca_result["status"] == "success":
                        results["reloaded"].append("CA signing certificate")
                    else:
                        results["errors"].append(ca_result["error"])

                # Reload server SSL certificate if backend uses it
                # Note: REST API certificates are handled by Gunicorn reload
                # This is mainly for CA backend's own certificate

                if results["errors"]:
                    results["status"] = (
                        "partial" if results["reloaded"] else "error"
                    )

                logger.info(
                    f"Certificate reload completed: {results['status']}"
                )
                reloaded = (
                    ", ".join(results["reloaded"])
                    if results["reloaded"]
                    else "none"
                )
                logger.info(f"Reloaded: {reloaded}")

                if results["errors"]:
                    logger.error(
                        f"Errors during reload: {'; '.join(results['errors'])}"
                    )

            except Exception as e:
                logger.error(f"Certificate reload failed: {e}", exc_info=True)
                results["status"] = "error"
                results["errors"].append(str(e))

            return results

    def _reload_ca_cert(self) -> dict:
        """
        Reload CA signing certificate from disk

        Returns:
            dict: Status of the reload operation
        """
        try:
            ca = self.ca_backend.ca

            # Get paths from CA backend
            ca_cert_path = getattr(ca, "ca_cert_path", None)
            ca_key_path = getattr(ca, "ca_key_path", None)

            if not ca_cert_path or not ca_key_path:
                return {
                    "status": "error",
                    "error": "CA certificate paths not configured",
                }

            logger.debug(f"Loading CA certificate from {ca_cert_path}")

            # Load new certificate from disk
            with open(ca_cert_path, "rb") as f:
                new_ca_cert = x509.load_pem_x509_certificate(f.read())

            # Load new key from disk
            with open(ca_key_path, "rb") as f:
                new_ca_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )

            # Verify certificate and key match
            if not self._verify_cert_key_match(new_ca_cert, new_ca_key):
                return {
                    "status": "error",
                    "error": "CA certificate and key do not match",
                }

            # Get old serial for logging
            old_serial = (
                getattr(ca.ca_cert, "serial_number", "unknown")
                if hasattr(ca, "ca_cert")
                else "unknown"
            )
            new_serial = new_ca_cert.serial_number

            # Update cert and key atomically under a lock so no thread
            # can read a mismatched cert/key pair.
            lock = getattr(ca, "_ca_load_lock", None)
            if lock:
                with lock:
                    ca.ca_private_key = new_ca_key
                    ca.ca_cert = new_ca_cert
            else:
                ca.ca_private_key = new_ca_key
                ca.ca_cert = new_ca_cert

            logger.info(
                f"CA certificate reloaded successfully "
                f"(serial changed from {old_serial} to {new_serial})"
            )

            return {"status": "success"}

        except FileNotFoundError as e:
            return {
                "status": "error",
                "error": f"Certificate file not found: {e}",
            }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Failed to reload CA certificate: {e}",
            }

    def _verify_cert_key_match(self, cert: x509.Certificate, key) -> bool:
        """
        Verify that a certificate and private key match

        Args:
            cert: X.509 certificate
            key: Private key

        Returns:
            bool: True if certificate and key match
        """
        try:
            # Compare public keys
            cert_public_key = cert.public_key()
            key_public_key = key.public_key()

            # Serialize both public keys and compare
            cert_pub_bytes = cert_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            key_pub_bytes = key_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            return cert_pub_bytes == key_pub_bytes

        except Exception as e:
            logger.error(f"Error verifying certificate/key match: {e}")
            return False

    def reload_server_ssl_cert(self, cert_path: str, key_path: str) -> dict:
        """
        Reload server SSL certificate (for Gunicorn)

        Note: Gunicorn needs to be restarted or sent USR2 signal to reload
        SSL certificates. This method just validates the new certificate.

        Args:
            cert_path: Path to server SSL certificate
            key_path: Path to server SSL private key

        Returns:
            dict: Status of validation
        """
        try:
            logger.debug(f"Validating server SSL certificate at {cert_path}")

            # Load and validate certificate
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            # Load and validate key
            with open(key_path, "rb") as f:
                key = serialization.load_pem_private_key(
                    f.read(), password=None
                )

            # Verify they match
            if not self._verify_cert_key_match(cert, key):
                return {
                    "status": "error",
                    "error": "Server certificate and key do not match",
                }

            logger.info(
                f"Server SSL certificate validated successfully "
                f"(serial: {cert.serial_number})"
            )

            return {
                "status": "success",
                "message": (
                    "Server SSL certificate validated (Gunicorn "
                    "restart required)"
                ),
            }

        except Exception as e:
            return {
                "status": "error",
                "error": f"Failed to validate server SSL certificate: {e}",
            }


# Global certificate reload manager instance
_reload_manager: Optional[CertificateReloadManager] = None


def get_reload_manager(ca_backend=None) -> CertificateReloadManager:
    """
    Get or create the global certificate reload manager

    Args:
        ca_backend: CA backend instance (only used on first call)

    Returns:
        CertificateReloadManager: The global reload manager instance
    """
    global _reload_manager

    if _reload_manager is None:
        _reload_manager = CertificateReloadManager(ca_backend)

    # Update CA backend if provided and manager exists
    elif ca_backend is not None and _reload_manager.ca_backend is None:
        _reload_manager.ca_backend = ca_backend

    return _reload_manager


def reload_certificates() -> dict:
    """
    Convenience function to reload certificates using the global manager

    Returns:
        dict: Status information about the reload operation
    """
    manager = get_reload_manager()
    return manager.reload_certificates()
