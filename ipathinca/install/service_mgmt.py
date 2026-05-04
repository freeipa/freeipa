# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Service management helper for IPAThinCAInstance.

Handles directory creation, systemd service installation, certmonger
configuration, Apache HTTP proxy setup, and service lifecycle.
"""

from __future__ import absolute_import

import logging
import os
import shutil
import time
from pathlib import Path

import requests

from ipalib.constants import CA_TRACKING_REQS, RENEWAL_CA_NAME
from ipaplatform.paths import paths
from ipapython import ipautil

from ipathinca import set_global_config
from ipathinca.backend import get_python_ca_backend

logger = logging.getLogger(__name__)


class ServiceMgmt:
    """Helper providing service management methods."""

    def __init__(
        self,
        config,
        fqdn,
        clone,
        nssdb,
        configure_certmonger_renewal_helpers_fn,
    ):
        self.config = config
        self.fqdn = fqdn
        self.clone = clone
        self._nssdb = nssdb
        self.configure_certmonger_renewal_helpers = (
            configure_certmonger_renewal_helpers_fn
        )

        # Compute paths from platform constants
        self.ipaca_dir = Path(paths.IPATHINCA_DIR)
        self.ipaca_ca_dir = Path(paths.IPATHINCA_CA_DIR)
        self.ipaca_audit_dir = Path(paths.IPATHINCA_AUDIT_DIR)
        self.ipaca_private_dir = Path(paths.IPATHINCA_PRIVATE_DIR)
        self.ipaca_certs_dir = Path(paths.IPATHINCA_CERTS_DIR)
        self.ipaca_logs_dir = Path(paths.IPATHINCA_LOG_DIR)

    @property
    def nssdb_dir(self):
        return self._nssdb.nssdb_dir

    def _create_directories(self):
        """Create required directory structure matching the manual setup."""
        logger.debug("Creating directory structure for ipathinca")

        # Create /var/lib/ipathinca
        self.ipaca_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_dir.chmod(0o750)
        shutil.chown(self.ipaca_dir, user="ipaca", group="ipaca")
        logger.debug("Created %s", self.ipaca_dir)

        # Create /var/lib/ipathinca/ca (for CA signing key - most critical
        # key)
        self.ipaca_ca_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_ca_dir.chmod(0o700)
        shutil.chown(self.ipaca_ca_dir, user="ipaca", group="ipaca")
        logger.debug("Created %s", self.ipaca_ca_dir)

        # Create /var/lib/ipathinca/audit (for audit signing key)
        self.ipaca_audit_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_audit_dir.chmod(0o700)
        shutil.chown(self.ipaca_audit_dir, user="ipaca", group="ipaca")
        logger.debug("Created %s", self.ipaca_audit_dir)

        # Create /var/lib/ipathinca/private (for operational TLS and
        # subsystem keys)
        self.ipaca_private_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_private_dir.chmod(0o700)
        shutil.chown(self.ipaca_private_dir, user="ipaca", group="ipaca")
        logger.debug("Created %s", self.ipaca_private_dir)

        # Create /var/lib/ipathinca/certs (for certificates)
        self.ipaca_certs_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_certs_dir.chmod(0o755)
        shutil.chown(self.ipaca_certs_dir, user="ipaca", group="ipaca")
        logger.debug("Created %s", self.ipaca_certs_dir)

        # Create /var/log/ipathinca (for log files)
        self.ipaca_logs_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_logs_dir.chmod(0o755)
        shutil.chown(self.ipaca_logs_dir, user="ipaca", group="ipaca")
        logger.debug("Created %s", self.ipaca_logs_dir)

        # Create /var/lib/ipathinca/profiles
        ipathinca_profiles_dir = self.ipaca_dir / "profiles"
        ipathinca_profiles_dir.mkdir(parents=True, exist_ok=True)
        ipathinca_profiles_dir.chmod(0o755)
        shutil.chown(ipathinca_profiles_dir, user="ipaca", group="ipaca")
        logger.debug("Created %s", ipathinca_profiles_dir)

        # Create /var/lib/ipa/pki-ca/publish (for CRL publication)
        # This is where CRLs are published for Apache to serve via Alias
        # directive
        # Same location as Dogtag for compatibility with existing ipa.conf
        publish_dir = Path(paths.IPA_PKI_PUBLISH_DIR)
        publish_dir.mkdir(parents=True, exist_ok=True)
        publish_dir.chmod(0o755)
        shutil.chown(publish_dir, user="ipaca", group="ipaca")
        logger.debug("Created %s", publish_dir)

        logger.debug("Directory structure created successfully")

    def _create_service_config(self):
        """Write ipathinca.conf from the pre-built configuration object.

        ``self.config`` is an ``IPAthinCAConfig`` instance assembled in
        ``IPAThinCAInstance.__init__`` from the merged PKI configuration.
        This step persists it to disk and registers it as the global config.
        """
        logger.debug("Creating service configuration")

        config_path = Path(paths.IPATHINCA_CONF)
        self.config.write_to_file(config_path)
        set_global_config(self.config)

        logger.debug("Service configuration written to %s", config_path)

    def _install_systemd_service(self):
        """Install systemd service file."""
        logger.debug("Installing systemd service for ipathinca")

        # Service file content
        service_path = Path("/etc/systemd/system/ipathinca.service")
        ipautil.copy_template_file(
            Path(paths.USR_SHARE_IPA_DIR) / "ipathinca.service.template",
            service_path,
            dict(
                SBIN_DIR="/usr/sbin",
            ),
        )
        service_path.chmod(0o644)

        # Reload systemd
        ipautil.run(["systemctl", "daemon-reload"])

        # Enable service
        ipautil.run(["systemctl", "enable", "ipathinca.service"])

        logger.debug("Systemd service installed and enabled")

    def _configure_audit_logging(self):
        """Configure audit logging (Dogtag-compatible).

        Dogtag uses the audit signing certificate from NSSDB for log signing.
        No separate symmetric key file is needed - the private key is accessed
        from NSSDB via the audit.py AuditLogger class.
        """
        logger.debug("Configuring audit logging")

        # Create audit log directory
        audit_log_dir = Path(paths.IPATHINCA_LOG_DIR)
        audit_log_dir.mkdir(parents=True, exist_ok=True)
        shutil.chown(audit_log_dir, user="ipaca", group="ipaca")

        logger.debug(
            "Audit logging configured - signing uses auditSigningCert from "
            "NSSDB"
        )

    def _install_renewal_scripts(self):
        """Install certmonger renewal helper scripts for NSSDB sync.

        These scripts are normally installed by 'make install' to
        /usr/libexec/ipa/certmonger/. This method verifies they exist,
        and if running from source tree, copies them to the destination.
        """
        logger.debug("Verifying certmonger renewal helper scripts")

        # Destination directory for certmonger helpers
        helper_dir = Path(paths.LIBEXEC_IPA_DIR) / "certmonger"
        helper_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

        # Helper scripts required
        scripts = ["stop_pkicad", "renew_ca_cert"]

        missing_scripts = []
        installed_scripts = []

        for script_name in scripts:
            dest_script = helper_dir / script_name

            # Check if script is already installed
            if dest_script.exists():
                logger.debug(
                    "Renewal script %s already installed at %s",
                    script_name,
                    dest_script,
                )
                installed_scripts.append(script_name)
                continue

            # Try to copy from source tree (development mode)
            source_dir = (
                Path(__file__).parent.parent.parent / "install" / "certmonger"
            )
            source_script = source_dir / script_name

            if source_script.exists():
                logger.debug(
                    "Installing %s from source tree to %s",
                    script_name,
                    dest_script,
                )

                # Copy script to destination
                shutil.copy2(source_script, dest_script)

                # Set executable permissions
                dest_script.chmod(0o755)

                # Set ownership to root:root
                try:
                    shutil.chown(dest_script, user="root", group="root")
                except (PermissionError, LookupError):
                    logger.warning(
                        "Could not set ownership on %s, continuing...",
                        dest_script,
                    )

                logger.debug("Installed %s successfully", script_name)
                installed_scripts.append(script_name)
            else:
                logger.warning(
                    "Renewal script %s not found at %s",
                    script_name,
                    dest_script,
                )
                missing_scripts.append(script_name)

        if missing_scripts:
            logger.warning(
                "Missing renewal scripts: %s. These scripts should be "
                "installed by 'make install'. Certificate renewal may not "
                "work correctly without them.",
                ", ".join(missing_scripts),
            )
            logger.info(
                "To manually install the scripts, run:\n"
                "  sudo cp install/certmonger/stop_pkicad "
                "/usr/libexec/ipa/certmonger/\n"
                "  sudo cp install/certmonger/renew_ca_cert "
                "/usr/libexec/ipa/certmonger/\n"
                "  sudo chmod 755 /usr/libexec/ipa/certmonger/stop_pkicad\n"
                "  sudo chmod 755 /usr/libexec/ipa/certmonger/renew_ca_cert"
            )
        else:
            logger.debug("All certmonger renewal scripts verified")

    def _configure_certmonger_renewal(self):
        """Configure certmonger renewal helpers for ipathinca."""
        # Configure renewal helpers first
        self.configure_certmonger_renewal_helpers()

        # Configure NSSDB certificate tracking
        self._configure_nssdb_tracking()

    def _configure_nssdb_tracking(self):
        """Configure certmonger tracking for NSSDB certificates."""
        logger.debug("Configuring certmonger tracking for NSSDB certificates")

        from ipalib.install import certmonger

        # First, clean up any existing tracking requests from previous
        # installation (e.g., from Dogtag migration)
        self._cleanup_existing_tracking()

        # Start tracking each certificate in NSSDB
        for nickname, profile in CA_TRACKING_REQS.items():
            try:
                logger.debug(
                    "Starting certmonger tracking for '%s' with profile '%s'",
                    nickname,
                    profile,
                )

                # Start tracking certificate in NSSDB
                # This configures certmonger to automatically renew the
                # certificate when it expires
                # Note: No pre_command needed - ipathinca uses graceful reload
                # via SIGHUP so service continues running during renewal
                certmonger.start_tracking(
                    certpath=str(self.nssdb_dir),
                    pin=certmonger.get_pin("internal"),
                    nickname=nickname,
                    ca=RENEWAL_CA_NAME,
                    profile=profile,
                    post_command=f'renew_ca_cert "{nickname}"',
                )

                logger.debug("Started tracking '%s' successfully", nickname)

            except Exception as e:
                # Don't fail installation if tracking setup fails
                # Certificates can be tracked manually later
                logger.warning(
                    "Failed to start certmonger tracking for '%s': %s",
                    nickname,
                    e,
                )

        logger.debug("Certmonger tracking configuration completed")

    def _cleanup_existing_tracking(self):
        """Clean up existing certmonger tracking requests.

        This is necessary for:
        1. Migration from Dogtag - removes old tracking requests
        2. Reinstallation - removes stale tracking requests
        """
        logger.debug("Cleaning up existing certmonger tracking requests")

        # Get all existing tracking requests
        try:
            result = ipautil.run(
                ["getcert", "list"], capture_output=True, raiseonerr=False
            )

            if result.returncode != 0:
                logger.warning("Failed to list certmonger requests")
                return

            # Parse getcert list output to find requests tracking our NSSDB
            nssdb_path = str(self.nssdb_dir)
            lines = result.output.split("\n")
            current_request_id = None

            for line in lines:
                line = line.strip()

                # Find request ID lines
                if line.startswith("Request ID"):
                    # Format: "Request ID '20251201133144':"
                    parts = line.split("'")
                    if len(parts) >= 2:
                        current_request_id = parts[1]

                # Check if this request tracks our NSSDB location
                # Format: "key pair storage: "
                #   type=NSSDB,location='/etc/pki/pki-tomcat/alias'..."
                elif current_request_id and "location=" in line:
                    if nssdb_path in line:
                        logger.debug(
                            "Removing existing certmonger tracking "
                            "request: %s",
                            current_request_id,
                        )
                        try:
                            ipautil.run(
                                [
                                    "getcert",
                                    "stop-tracking",
                                    "-i",
                                    current_request_id,
                                ],
                                raiseonerr=True,
                            )
                            logger.debug(
                                "Stopped tracking request %s",
                                current_request_id,
                            )
                        except Exception as e:
                            logger.warning(
                                "Failed to stop tracking request %s: %s",
                                current_request_id,
                                e,
                            )
                        current_request_id = None

        except Exception as e:
            logger.warning("Failed to cleanup existing tracking: %s", e)

        logger.debug("Cleanup of existing tracking requests completed")

    def _stop_certmonger_tracking(self):
        """Stop all certmonger tracking for ipathinca certificates.

        Called during uninstall to clean up certmonger tracking requests.
        """
        logger.debug("Stopping certmonger tracking for ipathinca certificates")

        # Ensure nssdb_dir is available (during uninstall the NSSDB
        # helper may not have been initialized)
        if self._nssdb.nssdb_dir is None:
            self._nssdb.nssdb_dir = Path(paths.PKI_TOMCAT_ALIAS_DIR)

        # Use the same cleanup method used during installation
        # This will stop all tracking requests for our NSSDB location
        try:
            self._cleanup_existing_tracking()
            logger.debug("Stopped all certmonger tracking for ipathinca")
        except Exception as e:
            logger.warning("Failed to stop certmonger tracking: %s", e)

    def _http_proxy(self):
        """Configure Apache HTTP proxy for ipathinca."""
        logger.debug("Configuring Apache HTTP proxy for ipathinca")

        # Create combined PEM file with RA agent cert and key for Apache proxy
        # Apache needs this to present a client cert when connecting to
        # ipathinca
        proxy_cert_dir = "/etc/httpd/alias"
        proxy_cert_file = os.path.join(proxy_cert_dir, "ipa-proxy.pem")

        # Ensure directory exists
        os.makedirs(proxy_cert_dir, mode=0o750, exist_ok=True)

        logger.debug(
            "Creating combined proxy certificate file: %s", proxy_cert_file
        )

        fd = os.open(
            proxy_cert_file,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(fd, "w") as f:
                # Write RA agent certificate
                with open(paths.RA_AGENT_PEM, "r") as cert_f:
                    f.write(cert_f.read())
                # Write RA agent private key
                with open(paths.RA_AGENT_KEY, "r") as key_f:
                    f.write(key_f.read())
        except Exception:
            try:
                os.unlink(proxy_cert_file)
            except OSError:
                pass
            raise

        os.chown(proxy_cert_file, 0, 0)  # root:root

        template_filename = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ipa-ipathinca-proxy.conf.template"
        )
        sub_dict = dict(
            CLONE="" if self.clone else "#",
            FQDN=self.fqdn,
        )

        template = ipautil.template_file(template_filename, sub_dict)
        with open(paths.HTTPD_IPA_PKI_PROXY_CONF, "w") as fd:
            fd.write(template)
            os.fchmod(fd.fileno(), 0o640)

        logger.debug("Apache HTTP proxy configured successfully")

    def _start_service(self):
        """Start ipathinca service and wait for it to be ready."""
        logger.debug("Starting ipa-ca service")

        try:
            ipautil.run(["systemctl", "start", "ipathinca.service"])
            logger.debug("ipathinca service started successfully")

            # Wait for REST API to be ready (similar to Dogtag)
            self._wait_for_ca_ready()
        except Exception as e:
            logger.error("Failed to start ipathinca service: %s", e)
            raise

    def _wait_for_ca_ready(self):
        """Wait for CA REST API to be ready to accept requests."""
        logger.debug("Waiting for CA REST API to be ready")

        # URL to check CA status
        status_url = f"https://{self.fqdn}:8443/ca/rest/info"

        max_wait = 60  # Maximum wait time in seconds
        wait_interval = 2  # Check every 2 seconds
        elapsed = 0

        while elapsed < max_wait:
            try:
                # Try to connect to the CA status endpoint
                # Use the CA certificate for verification (installed in
                # previous step)
                response = requests.get(
                    status_url, verify=paths.IPA_CA_CRT, timeout=5
                )
                if response.status_code == 200:
                    logger.debug("CA REST API is ready")
                    return
            except Exception as e:
                logger.debug("CA not ready yet: %s", e)

            time.sleep(wait_interval)
            elapsed += wait_interval

        logger.warning("CA did not become ready within %s seconds", max_wait)
        # Don't raise an error - let the installation continue and fail
        # later if the CA is truly not working

    def _generate_initial_crl(self):
        """Generate initial Certificate Revocation List.

        This creates the CRL and publishes it to /var/lib/ipa/pki-ca/publish/
        so it can be served by Apache at /ipa/crl/MasterCRL.bin.

        During installation, we call the backend directly to avoid
        authentication complexity. After installation, normal CRL updates
        go through the REST API with RA agent authentication.
        """
        logger.debug("Generating initial CRL")

        try:
            # Get CA backend instance
            backend = get_python_ca_backend()

            # Generate and publish CRL
            # This updates /var/lib/ipa/pki-ca/publish/MasterCRL.bin
            result = backend.update_crl()

            logger.debug(
                "Initial CRL generated successfully: %s", result["status"]
            )

            # Verify the published CRL exists
            publish_path = os.path.join(
                paths.IPA_PKI_PUBLISH_DIR, "MasterCRL.bin"
            )
            if os.path.exists(publish_path):
                logger.debug("CRL published to %s", publish_path)
            else:
                logger.warning(
                    "CRL generation succeeded but file not found at %s",
                    publish_path,
                )

        except Exception as e:
            logger.warning("Failed to generate initial CRL: %s", e)
            # Don't fail installation if CRL generation fails
            # CRL will be generated on first revocation or manual update
