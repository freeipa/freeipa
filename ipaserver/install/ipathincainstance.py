# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Installation module for ipathinca Python CA backend
"""

from __future__ import absolute_import

import logging
import os
import shutil
import tempfile
from pathlib import Path
import dbus
import urllib.parse
import pwd
import datetime
import secrets
import uuid
import subprocess
import json
import time
import requests
import configparser
import sys

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ipalib import api, errors
from ipalib.constants import (
    IPA_CA_CN,
    IPAAPI_GROUP,
    CA_TRACKING_REQS,
    RENEWAL_CA_NAME,
    CA_DBUS_TIMEOUT,
)
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.dn import DN
from ipapython import dogtag
from ipapython.certdb import get_ca_nickname
from ipaserver.install import service
from ipathinca import load_config, set_global_config, get_global_config
from ipathinca.ca import PythonCA, CertificateRequest, CertificateRecord
from ipaserver.install.cainstance import lookup_ldap_backend
from ipathinca.kra import KRA
from ipathinca.profiles import ProfileManager
from ipathinca.storage_ca import CAStorageBackend
from ipathinca.storage_kra import KRAStorageBackend
from ipathinca.storage_acme import ACMEStorageBackend
from ipathinca.storage_factory import get_storage_backend
from ipathinca.subca import SubCAManager
from ipathinca.x509_utils import (
    ipa_dn_to_x509_name,
    get_subject_dn_str,
    build_x509_name,
)

logger = logging.getLogger(__name__)


class IPAthinCAConfigLoader:
    """Configuration loader for IPAthinCA

    Implements four-layer configuration loading matching Dogtag PKIIniLoader:
    1. ipaca_default.ini - Immutable defaults (hardcoded baseline)
    2. ipaca_customize.ini - Customizable defaults
    3. ipaca_softhsm2.ini - HSM-specific settings (optional)
    4. User override file - pki_config_override (optional)
    """

    # Configuration file paths (matching PKIIniLoader structure)
    pki_default = "/usr/share/pki/server/etc/default.cfg"
    ipaca_default = os.path.join(paths.USR_SHARE_IPA_DIR, "ipaca_default.ini")
    ipaca_customize = os.path.join(
        paths.USR_SHARE_IPA_DIR, "ipaca_customize.ini"
    )
    ipaca_softhsm2 = os.path.join(
        paths.USR_SHARE_IPA_DIR, "ipaca_softhsm2.ini"
    )

    # Immutable keys calculated from ipaca_default.ini and code-defined keys
    _immutable_keys = None
    _immutable_code_keys = frozenset(
        {
            # Runtime parameters set by installer (as (section, key) tuples)
            ("global", "realm"),
            ("global", "host"),
            ("global", "basedn"),
            # Note: pki_ca_signing_signing_algorithm is NOT immutable - it's
            # derived via interpolation from ipa_signing_algorithm
        }
    )

    def __init__(
        self,
        realm,
        host,
        basedn,
        subject_base=None,
        ca_subject=None,
        ca_signing_algorithm=None,
        random_serial_numbers=True,
        pki_config_override=None,
        token_name=None,
    ):
        self.realm = realm
        self.host = host
        self.basedn = basedn
        self.subject_base = subject_base
        self.ca_subject = ca_subject
        self.ca_signing_algorithm = ca_signing_algorithm
        self.random_serial_numbers = random_serial_numbers
        self.pki_config_override = pki_config_override
        self.token_name = token_name

        # Derive fqdn from host
        self.fqdn = host

    @classmethod
    def get_immutable_keys(cls):
        """Get set of immutable keys

        Immutable keys are calculated from 'ipaca_default' config file
        and known keys that are defined in code.
        """
        if cls._immutable_keys is None:
            immutable = set()
            immutable.update(cls._immutable_code_keys)
            if os.path.exists(cls.ipaca_default):
                cfg = configparser.RawConfigParser()
                with open(cls.ipaca_default) as f:
                    cfg.read_file(f)
                for section in cfg.sections():
                    for k, _v in cfg.items(section, raw=True):
                        immutable.add((section, k))
            cls._immutable_keys = frozenset(immutable)
        return cls._immutable_keys

    def load_config(self):
        """Load configuration hierarchically (matching PKIIniLoader)

        Configuration layers (later layers override earlier):
        0. PKI default.cfg - Base PKI defaults
        1. ipaca_default.ini - IPA immutable defaults (can override PKI)
        2. Installer parameters - Runtime values (realm, host, etc.)
        3. ipaca_customize.ini - IPA customizable defaults
        4. ipaca_softhsm2.ini - HSM-specific settings (if using HSM)
        5. pki_config_override - User custom overrides

        Returns:
            ConfigParser object with merged configuration
        """
        # Prepare defaults dict for interpolation (matching PKIIniLoader)
        defaults = {}

        # PKI default variables (matching PKIIniLoader -
        # see dogtaginstance.py:1087-1099). These are required
        # by /usr/share/pki/server/etc/default.cfg for interpolation
        domain = self.realm.lower()
        defaults["pki_dns_domainname"] = domain
        defaults["pki_hostname"] = self.host
        defaults["pki_subsystem"] = "CA"
        defaults["pki_subsystem_type"] = "ca"
        defaults["home_dir"] = os.path.expanduser("~")

        # IPA-specific defaults (matching PKIIniLoader -
        # dogtaginstance.py:1073-1099)
        defaults["ipa_ca_pem_file"] = paths.IPA_CA_CRT
        defaults["ipa_subject_base"] = (
            str(self.subject_base) if self.subject_base else ""
        )
        defaults["ipa_ca_subject"] = (
            str(self.ca_subject) if self.ca_subject else ""
        )
        defaults["ipa_fqdn"] = self.fqdn
        defaults["pki_configuration_path"] = paths.PKI_CONFIGURATION

        # OCSP responder URI
        from ipalib.constants import IPA_CA_RECORD

        defaults["ipa_ocsp_uri"] = f"http://{IPA_CA_RECORD}.{domain}/ca/ocsp"

        # Admin user settings (IPAthinCA doesn't use Dogtag
        # admin, but referenced in configs)
        defaults["ipa_admin_cert_p12"] = paths.DOGTAG_ADMIN_P12
        defaults["ipa_admin_user"] = "admin"
        defaults["pki_admin_password"] = ""  # Not used by IPAthinCA
        defaults["pki_ds_password"] = ""  # Not used by IPAthinCA

        # HSM support
        defaults["softhsm2_so"] = paths.LIBSOFTHSM2_SO

        # FIPS mode configuration
        from ipaplatform.tasks import tasks

        defaults["fips_use_oaep_rsa_keywrap"] = str(
            tasks.is_fips_enabled()
        ).lower()

        # Generate secure AJP password
        defaults["ipa_ajp_secret"] = ipautil.ipa_generate_password(
            special=None
        )

        # Apply installer parameters to defaults
        if self.ca_signing_algorithm is not None:
            # Map CASigningAlgorithm enum to string
            if hasattr(self.ca_signing_algorithm, "value"):
                alg_str = self.ca_signing_algorithm.value
            else:
                alg_str = str(self.ca_signing_algorithm)
            # Set ipa_signing_algorithm which will interpolate into
            # ipa_ca_signing_algorithm and pki_ca_signing_signing_algorithm
            defaults["ipa_signing_algorithm"] = alg_str
            logger.debug(f"Set signing algorithm in defaults: {alg_str}")

        # Use ConfigParser with defaults to enable interpolation
        # (matching PKIIniLoader behavior - see dogtaginstance.py:1194)
        config = configparser.ConfigParser(defaults=defaults)
        config.optionxform = str  # Preserve case

        # Layer 0: Load PKI default.cfg (base PKI defaults)
        if os.path.exists(self.pki_default):
            logger.debug(f"Loading PKI defaults from {self.pki_default}")
            with open(self.pki_default) as f:
                config.read_file(f)
        else:
            logger.warning(f"PKI default.cfg not found: {self.pki_default}")

        # Layer 1: Load ipaca_default.ini (IPA immutable baseline)
        logger.debug(f"Loading IPA baseline from {self.ipaca_default}")
        if os.path.exists(self.ipaca_default):
            with open(self.ipaca_default) as f:
                config.read_file(f)
        else:
            logger.warning(
                f"ipaca_default.ini not found: {self.ipaca_default}"
            )
            # Create minimal baseline if file missing
            self._create_minimal_baseline(config)

        # Layer 2: Apply installer parameters (these override defaults)
        self._apply_installer_params(config)

        # Take snapshot of immutable settings
        immutable_snapshot = self._snapshot_immutable_settings(config)

        # Layer 3: Load ipaca_customize.ini (customizable defaults)
        logger.debug(f"Loading customizations from {self.ipaca_customize}")
        if os.path.exists(self.ipaca_customize):
            with open(self.ipaca_customize) as f:
                config.read_file(f)
            self._verify_immutable(
                config, immutable_snapshot, self.ipaca_customize
            )
        else:
            logger.warning(
                "ipaca_customize.ini not found: " f"{self.ipaca_customize}"
            )

        # Layer 4: Load ipaca_softhsm2.ini if using HSM
        if self.token_name:
            logger.debug(f"Loading HSM settings from {self.ipaca_softhsm2}")
            if os.path.exists(self.ipaca_softhsm2):
                with open(self.ipaca_softhsm2) as f:
                    config.read_file(f)
                self._verify_immutable(
                    config, immutable_snapshot, self.ipaca_softhsm2
                )
            else:
                logger.warning(
                    "ipaca_softhsm2.ini not found: " f"{self.ipaca_softhsm2}"
                )

        # Layer 5: Load user overrides if provided
        if self.pki_config_override:
            logger.info(
                "Loading user overrides from " f"{self.pki_config_override}"
            )
            with open(self.pki_config_override) as f:
                config.read_file(f)
            self._verify_immutable(
                config, immutable_snapshot, self.pki_config_override
            )

        return config

    def _create_minimal_baseline(self, config):
        """Create minimal baseline configuration
        if ipaca_default.ini is missing"""
        for section in ["CA", "global", "ldap", "server"]:
            if not config.has_section(section):
                config.add_section(section)

    def _apply_baseline_defaults(self, config):
        """Apply hardcoded baseline defaults (equivalent to ipaca_default.ini)

        These are minimal immutable settings that IPAthinCA requires.
        """
        # Ensure required sections exist (DEFAULT section always exists,
        # don't create it)
        for section in ["global", "ldap", "server"]:
            if not config.has_section(section):
                config.add_section(section)

        # Immutable global settings (convert all to strings for ConfigParser)
        config.set("global", "realm", str(self.realm))
        config.set("global", "host", str(self.host))
        config.set("global", "basedn", str(self.basedn))

        # Immutable LDAP settings (cannot be overridden for security)
        # Escape % as %% for ConfigParser interpolation
        config.set(
            "ldap",
            "uri",
            "ldapi://%%2fvar%%2frun%%2fslapd-"
            f'{self.realm.replace(".", "-")}.socket',
        )
        config.set("ldap", "base_dn", f"cn=ca,{str(self.basedn)}")

        # Immutable server settings
        config.set("server", "user", "ipaapi")
        config.set("server", "group", "ipaapi")

    def _snapshot_immutable_settings(self, config):
        """Take snapshot of immutable settings for later validation

        Returns:
            dict: Mapping of (section, key) -> value for all immutable
                  settings
        """
        snapshot = {}
        for section, key in self.get_immutable_keys():
            if section == "*":
                # Skip wildcard entries in snapshot
                continue

            if not config.has_section(section):
                continue

            if key == "*":
                # Snapshot all keys in this section
                for option_key in config.options(section):
                    snapshot[(section, option_key)] = config.get(
                        section, option_key
                    )
            else:
                # Snapshot specific key
                if config.has_option(section, key):
                    snapshot[(section, key)] = config.get(section, key)

        logger.debug(f"Immutable settings snapshot: {len(snapshot)} settings")
        return snapshot

    def _verify_immutable(self, config, immutable_snapshot, filename):
        """Verify that immutable settings haven't been changed

        Args:
            config: Current ConfigParser object
            immutable_snapshot: Dict of (section, key) -> value from before
                                file load
            filename: Name of file being validated (for error message)

        Raises:
            ValueError: If any immutable setting was changed
        """
        errors = []

        for (section, key), expected_value in immutable_snapshot.items():
            if not config.has_section(section):
                errors.append(f"[{section}] {key}: section removed")
                continue

            if not config.has_option(section, key):
                errors.append(f"[{section}] {key}: key removed")
                continue

            actual_value = config.get(section, key)
            if actual_value != expected_value:
                errors.append(
                    f"[{section}] {key}: '{actual_value}' != "
                    f"'{expected_value}'"
                )

        if errors:
            raise ValueError(
                f"{filename} attempts to override immutable settings:\n"
                + "\n".join(errors)
            )

    def _apply_installer_params(self, config):
        """Apply installer parameters to config

        These are applied to the baseline before loading any files.
        This matches Dogtag's subsystem_config application.
        """
        # Ensure [CA] section exists
        if not config.has_section("CA"):
            config.add_section("CA")

        # Note: ca_signing_algorithm is now set in defaults dict during
        # load_config() as ipa_signing_algorithm, which interpolates into
        # pki_ca_signing_signing_algorithm via ipaca_customize.ini

        # Apply random_serial_numbers
        config.set(
            "CA",
            "random_serial_numbers",
            str(self.random_serial_numbers).lower(),
        )

    def to_ini_string(self, config):
        """Convert ConfigParser to INI string"""
        from io import StringIO

        output = StringIO()
        config.write(output)
        return output.getvalue()


class IPAThinCAInstance(service.Service):
    """
    Installation and configuration module for ipathinca Python CA backend

    This module handles:
    - LDAP schema installation
    - Service configuration and setup
    - Certificate and key management
    - Integration with systemd
    """

    # Certificate tracking requests (for healthcheck compatibility)
    # IPAThinCA handles cert tracking through certmonger directly
    tracking_reqs = dict()

    @staticmethod
    def configure_certmonger_renewal_helpers():
        """
        Configure certmonger renewal helpers for ipathinca HTTPS.

        This is a static method that can be called early in the installation
        process, before any certificate requests are made.
        """
        logger = logging.getLogger(__name__)
        logger.debug("Configuring certmonger helpers for ipathinca HTTPS")

        # Start certmonger and dbus if needed
        cmonger = services.knownservices.certmonger
        cmonger.enable()
        if not services.knownservices.dbus.is_running():
            services.knownservices.dbus.start()
        cmonger.start()

        # Use the standard FreeIPA dogtag-ipa-ca-renew-agent-submit script
        # This script works with ipathinca because it uses the JSON-RPC path
        # which talks to IPA API, which in turn uses python-pki to communicate
        # with ipathinca's REST API endpoints
        helper_script = Path(paths.DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT)

        # Register the certmonger CA helpers
        bus = dbus.SystemBus()
        obj = bus.get_object(
            "org.fedorahosted.certmonger", "/org/fedorahosted/certmonger"
        )
        iface = dbus.Interface(obj, "org.fedorahosted.certmonger")

        # Register the CA helpers (same as dogtag)
        for suffix, args in [
            ("", ""),
            ("-reuse", " --force-new-key"),
            ("-selfsigned", " --force-self-signed"),
        ]:
            name = RENEWAL_CA_NAME + suffix
            path = iface.find_ca_by_nickname(name)
            if not path:
                command = str(helper_script) + args
                logger.debug(f"Registering certmonger CA helper: {name}")
                iface.add_known_ca(
                    name,
                    command,
                    dbus.Array([], dbus.Signature("s")),
                    timeout=CA_DBUS_TIMEOUT,
                )

        logger.debug("Certmonger renewal helpers configured")

    def __init__(
        self,
        realm=None,
        host_name=None,
        random_serial_numbers=False,
        ca_signing_algorithm=None,
        subject_base=None,
        ca_subject=None,
        external_ca=False,
        external_ca_type=None,
        external_ca_profile=None,
        csr_file=None,
        cert_file=None,
        cert_chain_file=None,
        pki_config_override=None,
    ):
        """Initialize ipathinca instance

        Args:
            realm: Kerberos realm name
            host_name: Fully qualified domain name
            random_serial_numbers: Enable RSNv3 random serial numbers
                                       (default: False)
            ca_signing_algorithm: CA signing algorithm
                                 (ipaserver.install.ca.CASigningAlgorithm enum)
                                 Default from
                                 install/share/ipaca_customize.ini:
                                 ipa_ca_signing_algorithm=SHA256withRSA
            subject_base: Certificate subject base DN (default: O=<realm>)
            ca_subject: CA certificate subject DN
                       (default: CN=Certificate Authority,O=<realm>)
            external_ca: Enable external CA mode (two-step installation)
            external_ca_type: External CA type (ExternalCAType.GENERIC or
                              MS_CS)
            external_ca_profile: MS Certificate Template (for MS_CS type)
            csr_file: Path to save/load CSR (default: /root/ipa.csr)
            cert_file: Path to signed CA certificate (Step 2)
            cert_chain_file: Path to external CA certificate chain (Step 2)
            pki_config_override: Path to custom PKI configuration override file
                                (INI format, merged with ipaca_customize.ini
                                 defaults)
        """
        super().__init__(
            "ipathinca",
            service_desc="IPA Python CA",
            realm_name=realm,
            service_user="ipaca",
        )

        self.subsystem = "ipathinca"
        self.realm = realm
        self.fqdn = host_name
        self.admin_password = None
        self.subject_base = subject_base
        self.ca_subject = ca_subject
        self.random_serial_numbers = random_serial_numbers
        self.ca_signing_algorithm = ca_signing_algorithm
        self.pki_config_override = pki_config_override

        # External CA support (two-step installation)
        # State: 0=none, 1=generate CSR, 2=install signed cert
        if external_ca or csr_file:
            self.external_ca_step = 1
        elif cert_file and cert_chain_file:
            self.external_ca_step = 2
        else:
            self.external_ca_step = 0

        # External CA parameters
        from ipalib import x509 as ipalib_x509

        self.external_ca_type = (
            external_ca_type or ipalib_x509.ExternalCAType.GENERIC.value
        )
        self.external_ca_profile = external_ca_profile
        self.csr_file = csr_file or paths.ROOT_IPA_CSR  # /root/ipa.csr
        self.cert_file = cert_file
        self.cert_chain_file = cert_chain_file

        self.clone = False
        self.config = None  # Config loaded during __create_service_config()
        self.pki_config = (
            None  # Merged PKI config from ipaca_customize.ini + overrides
        )

        # Paths - using ipaplatform path constants
        self.ipaca_dir = Path(paths.IPATHINCA_DIR)
        self.ipaca_private_dir = Path(paths.IPATHINCA_PRIVATE_DIR)
        self.ipaca_certs_dir = Path(paths.IPATHINCA_CERTS_DIR)
        self.ipaca_ca_dir = Path(paths.IPATHINCA_CA_DIR)
        self.ipaca_audit_dir = Path(paths.IPATHINCA_AUDIT_DIR)
        self.ipaca_logs_dir = Path(paths.IPATHINCA_LOG_DIR)

        self.ca_cert_path = Path(paths.IPA_CA_CRT)
        self.ca_key_path = Path(paths.IPATHINCA_SIGNING_KEY)
        self.ca_cert_working = self.ipaca_certs_dir / "ca.crt"

        # Audit log directory
        self.audit_log_dir = Path(paths.IPATHINCA_LOG_DIR)

    def is_installed(self):
        return self.service.is_installed()

    def is_configured(self):
        config_path = Path(paths.IPATHINCA_CONF)
        return config_path.exists()

    def is_crlgen_enabled(self):
        """Check if CRL generation is enabled

        For ipathinca, CRL generation is always enabled on the local instance.
        Unlike Dogtag, ipathinca doesn't have clustering or CRL generation
        master/replica concepts - each instance generates its own CRL.

        Returns:
            bool: True if ipathinca is installed and running
        """
        return self.is_installed()

    def _ensure_global_config(self):
        """
        Ensure global ipathinca config is initialized.

        This is needed for healthcheck and other contexts where the config
        needs to be loaded but we're not in an installation context.

        Returns:
            bool: True if config is initialized, False otherwise
        """
        try:
            # Check if already initialized
            get_global_config()
            return True
        except Exception:
            # Not initialized, try to load from file
            try:
                config_path = Path(paths.IPATHINCA_CONF)
                if not config_path.exists():
                    logger.debug(
                        "ipathinca config file does not exist, "
                        "cannot initialize global config"
                    )
                    return False

                config = load_config(str(config_path))
                set_global_config(config)
                logger.debug(
                    "Initialized ipathinca global config for healthcheck"
                )
                return True
            except Exception as e:
                logger.debug(f"Could not initialize global config: {e}")
                return False

    @property
    def hsm_enabled(self):
        """Is HSM support enabled?

        Checks LDAP storage for HSM configuration.
        Returns True if HSM is configured and enabled for this CA.

        Returns:
            bool: True if HSM is enabled, False otherwise
        """
        try:
            # Ensure global config is initialized (needed for healthcheck)
            if not self._ensure_global_config():
                logger.debug("Cannot check HSM status: config not initialized")
                return False

            backend = get_storage_backend(ca_id="ipa")
            hsm_config = backend.get_hsm_config("ipa")
            if hsm_config:
                return hsm_config.get("enabled", False)
            return False
        except Exception as e:
            logger.debug(f"Could not check HSM status: {e}")
            return False

    @property
    def token_name(self):
        """HSM token name

        Retrieves the HSM token name from LDAP storage if HSM is configured.

        Returns:
            str: Token name if HSM is configured, None otherwise
        """
        try:
            # Ensure global config is initialized (needed for healthcheck)
            if not self._ensure_global_config():
                logger.debug("Cannot get HSM token: config not initialized")
                return None

            backend = get_storage_backend(ca_id="ipa")
            hsm_config = backend.get_hsm_config("ipa")
            if hsm_config:
                return hsm_config.get("token_name")
            return None
        except Exception as e:
            logger.debug(f"Could not get HSM token name: {e}")
            return None

    def enable_client_auth_to_db(self):
        """Enable client auth to LDAP database

        For ipathinca, this is a no-op since ipathinca uses direct LDAP
        connections configured in ipathinca.conf, not Dogtag's CS.cfg.
        This method exists for compatibility with the Dogtag CA interface.
        """
        logger.debug("enable_client_auth_to_db: No-op for ipathinca")
        pass

    def stop_tracking_certificates(self):
        """Stop tracking certificates with certmonger

        Called on uninstall or upgrade. Stops certmonger from tracking:
        - RA agent certificate
        - Any other ipathinca-related certificates

        This method exists for compatibility with the Dogtag CA interface.
        """
        logger.debug("Stopping certmonger tracking for ipathinca certificates")

        from ipalib.install import certmonger

        # Ensure certmonger is running
        cmonger = services.knownservices.certmonger
        if not services.knownservices.dbus.is_running():
            try:
                services.knownservices.dbus.start()
            except Exception as e:
                logger.warning(f"Could not start dbus: {e}")
                return

        try:
            cmonger.start()
        except Exception as e:
            logger.warning(f"Could not start certmonger: {e}")
            return

        # Stop tracking RA agent certificate
        try:
            certmonger.stop_tracking(certfile=paths.RA_AGENT_PEM)
            logger.debug("Stopped tracking RA agent certificate")
        except RuntimeError as e:
            logger.debug(f"RA agent certificate not tracked or error: {e}")

        # Stop tracking any ipathinca HTTPS certificate if configured
        # (this would be tracked in the same way as Apache httpd)
        try:
            certmonger.stop_tracking(certfile=paths.HTTPD_CERT_FILE)
            logger.debug("Stopped tracking HTTPS certificate")
        except RuntimeError as e:
            logger.debug(f"HTTPS certificate not tracked or error: {e}")

    def create_instance(self, ca_signing_cert=None, ca_signing_key=None):
        """
        Create and configure ipathinca Python CA instance

        Args:
            ca_signing_cert: Path to existing CA signing certificate (PEM)
            ca_signing_key: Path to existing CA signing key (PEM)
        """
        logger.debug("Creating ipathinca Python CA instance")

        # Store parameters as instance variables for step methods
        self.ca_signing_cert = ca_signing_cert
        self.ca_signing_key = ca_signing_key

        if not self.random_serial_numbers:
            ldap_backend = lookup_ldap_backend(api)
            if ldap_backend != "bdb":
                # override selection for lmdb due to VLV performance issues.
                logger.info(
                    "Forcing random serial numbers to be enabled for the %s "
                    "backend",
                    ldap_backend,
                )
                self.random_serial_numbers = True

        self.step("creating directory structure", self.__create_directories)
        self.step("creating NSS database", self.__create_nssdb)
        self.step(
            "creating service configuration", self.__create_service_config
        )
        self.step("installing LDAP schema", self.__install_ldap_schema)
        self.step("initializing LDAP storage", self.__initialize_ldap_storage)
        self.step(
            "configuring LDAP access for ipaca", self.__configure_ldap_access
        )
        # NOTE: CA service registration moved to install_step_1 (after PKINIT)
        # to ensure PKINIT uses dogtag-submit during initial installation
        self.step(
            "configuring CA certificates and keys", self.__configure_ca_certs
        )
        self.step("storing CA certificate in LDAP", self.__store_ca_cert_ldap)
        self.step("creating IPA CA entry", self.__create_ipa_ca_entry)
        self.step(
            "initializing certificate storage schema",
            self.__init_cert_storage_schema,
        )
        self.step(
            "storing CA certificate in certificate database",
            self.__store_ca_cert_in_certdb,
        )
        self.step(
            "importing certificate profiles to LDAP",
            self.__import_profiles_ldap,
        )
        self.step("creating default CA ACL", self.__create_default_caacl)
        self.step("setting up ACME service", self.setup_acme)
        self.step(
            "installing CA certificate to system trust",
            self.__install_ca_trust,
        )
        self.step(
            "generating server SSL certificate", self.__generate_server_cert
        )
        self.step("generating RA agent certificate", self.__generate_ra_cert)
        self.step(
            "verifying RA key accessibility for replicas",
            self.__verify_ra_key_custodia,
        )
        self.step(
            "generating PKI subsystem certificates",
            self.__generate_subsystem_certs,
        )
        self.step(
            "installing certmonger renewal scripts",
            self.__install_renewal_scripts,
        )
        self.step(
            "configuring certmonger for renewals",
            self.__configure_certmonger_renewal,
        )
        self.step("installing systemd service", self.__install_systemd_service)
        self.step("configuring audit logging", self.__configure_audit_logging)
        self.step("configuring Apache HTTP proxy", self.__http_proxy)
        # Note: CA service registration in LDAP is deferred until after PKINIT
        # is configured (via enable_and_start() called from
        # ca.enable_ca_service())
        # to ensure PKINIT uses dogtag-submit during initial installation
        self.step("starting ipathinca service", self.__start_service)
        self.step("generating initial CRL", self.__generate_initial_crl)

        self.start_creation()

    def __create_directories(self):
        """Create required directory structure matching the manual setup"""
        logger.debug("Creating directory structure for ipathinca")

        # Create /var/lib/ipathinca
        self.ipaca_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_dir.chmod(0o750)
        shutil.chown(self.ipaca_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {self.ipaca_dir}")

        # Create /var/lib/ipathinca/ca (for CA signing key - most critical
        # key)
        self.ipaca_ca_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_ca_dir.chmod(0o700)
        shutil.chown(self.ipaca_ca_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {self.ipaca_ca_dir}")

        # Create /var/lib/ipathinca/audit (for audit signing key)
        self.ipaca_audit_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_audit_dir.chmod(0o700)
        shutil.chown(self.ipaca_audit_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {self.ipaca_audit_dir}")

        # Create /var/lib/ipathinca/private (for operational TLS and
        # subsystem keys)
        self.ipaca_private_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_private_dir.chmod(0o700)
        shutil.chown(self.ipaca_private_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {self.ipaca_private_dir}")

        # Create /var/lib/ipathinca/certs (for certificates)
        self.ipaca_certs_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_certs_dir.chmod(0o755)
        shutil.chown(self.ipaca_certs_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {self.ipaca_certs_dir}")

        # Create /var/lib/ipathinca/audit (for audit signing key -
        # separated for security)
        self.ipaca_audit_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_audit_dir.chmod(0o700)
        shutil.chown(self.ipaca_audit_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {self.ipaca_audit_dir}")

        # Create /var/log/ipathinca (for log files)
        self.ipaca_logs_dir.mkdir(parents=True, exist_ok=True)
        self.ipaca_logs_dir.chmod(0o755)
        shutil.chown(self.ipaca_logs_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {self.ipaca_logs_dir}")

        # Create /var/lib/ipathinca/profiles
        ipathinca_profiles_dir = self.ipaca_dir / "profiles"
        ipathinca_profiles_dir.mkdir(parents=True, exist_ok=True)
        ipathinca_profiles_dir.chmod(0o755)
        shutil.chown(ipathinca_profiles_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {ipathinca_profiles_dir}")

        # Create /var/lib/ipa/pki-ca/publish (for CRL publication)
        # This is where CRLs are published for Apache to serve via Alias
        # directive
        # Same location as Dogtag for compatibility with existing ipa.conf
        publish_dir = Path(paths.IPA_PKI_PUBLISH_DIR)
        publish_dir.mkdir(parents=True, exist_ok=True)
        publish_dir.chmod(0o755)
        shutil.chown(publish_dir, user="ipaca", group="ipaca")
        logger.debug(f"Created {publish_dir}")

        logger.debug("Directory structure created successfully")

    def __create_nssdb(self):
        """
        Create NSS database for Dogtag/certmonger compatibility

        Creates NSSDB at /etc/pki/pki-tomcat/alias/ to ensure ipathinca is a
        100% drop-in replacement for Dogtag. This allows:
        - Certmonger to track certificates by nickname
        - NSS tools (certutil, pk12util) to work
        - Smooth migration from Dogtag to ipathinca
        """
        logger.debug("Creating NSS database for certificate storage")

        # NSS database directory (same as Dogtag)
        self.nssdb_dir = Path(paths.PKI_TOMCAT_ALIAS_DIR)
        self.nssdb_password_file = Path(paths.PKI_TOMCAT_PASSWORD_CONF)

        # Create directories
        self.nssdb_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.nssdb_password_file.parent.mkdir(
            parents=True, exist_ok=True, mode=0o750
        )

        # Set ownership (same as Dogtag: ipaca:ipaca)
        shutil.chown(self.nssdb_dir, user="ipaca", group="ipaca")
        shutil.chown(
            self.nssdb_password_file.parent, user="ipaca", group="ipaca"
        )

        # Check if NSS database already exists (e.g., from previous Dogtag
        # installation)
        # Both old (cert8.db) and new (cert9.db) format files
        nssdb_files = [
            "cert9.db",
            "key4.db",
            "pkcs11.txt",
            "cert8.db",
            "key3.db",
            "secmod.db",
        ]
        existing_files = [
            f for f in nssdb_files if (self.nssdb_dir / f).exists()
        ]

        if existing_files:
            logger.info(
                "Removing existing NSSDB files from previous installation: "
                f"{existing_files}"
            )
            for filename in existing_files:
                filepath = self.nssdb_dir / filename
                try:
                    filepath.unlink()
                    logger.debug(f"Removed {filepath}")
                except Exception as e:
                    logger.warning(f"Failed to remove {filepath}: {e}")

        # Generate strong random password for NSSDB
        self.nssdb_password = ipautil.ipa_generate_password()

        # Create password file (Dogtag format: internal=password)
        with open(self.nssdb_password_file, "w") as f:
            f.write(f"internal={self.nssdb_password}\n")
        self.nssdb_password_file.chmod(0o640)
        shutil.chown(self.nssdb_password_file, user="ipaca", group="ipaca")

        # Create NSS database using certutil
        logger.debug(f"Initializing NSSDB at {self.nssdb_dir}")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as pwdfile:
            pwdfile.write(self.nssdb_password)
            pwdfile.flush()
            temp_password_file = pwdfile.name

        try:
            # Create NSSDB with certutil -N (same as Dogtag)
            ipautil.run(
                [
                    "certutil",
                    "-N",
                    "-d",
                    str(self.nssdb_dir),
                    "-f",
                    temp_password_file,
                ]
            )
            logger.debug(f"NSSDB created successfully at {self.nssdb_dir}")
        finally:
            # Clean up temporary password file
            os.unlink(temp_password_file)

        # Verify NSSDB was created
        if not (self.nssdb_dir / "cert9.db").exists():
            raise RuntimeError(f"Failed to create NSSDB at {self.nssdb_dir}")

        # Fix ownership of NSSDB files (certutil creates as root, need ipaca)
        logger.debug("Setting NSSDB file ownership to ipaca:ipaca")
        for nssdb_file in ["cert9.db", "key4.db", "pkcs11.txt"]:
            file_path = self.nssdb_dir / nssdb_file
            if file_path.exists():
                shutil.chown(file_path, user="ipaca", group="ipaca")
        logger.debug("NSSDB file ownership set to ipaca:ipaca")

        logger.debug("NSS database created and verified")

    def _load_nssdb_password(self):
        """
        Load NSSDB password from file if not already in memory

        This is needed when enable_kra() or other methods are called
        separately from create_instance() in a different execution context.
        """
        if hasattr(self, "nssdb_password") and self.nssdb_password:
            return

        # Set NSSDB paths if not already set
        if not hasattr(self, "nssdb_dir"):
            self.nssdb_dir = Path(paths.PKI_TOMCAT_ALIAS_DIR)
        if not hasattr(self, "nssdb_password_file"):
            self.nssdb_password_file = Path(paths.PKI_TOMCAT_PASSWORD_CONF)

        # Read password from file
        if self.nssdb_password_file.exists():
            with open(self.nssdb_password_file, "r") as f:
                for line in f:
                    if line.startswith("internal="):
                        self.nssdb_password = line.split("=", 1)[1].strip()
                        logger.debug("Loaded NSSDB password from file")
                        return

        raise RuntimeError(
            f"NSSDB password not found in {self.nssdb_password_file}"
        )

    def __import_cert_to_nssdb(
        self, cert_pem_path, key_pem_path, nickname, trust_flags="u,u,u"
    ):
        """
        Import certificate and private key to NSSDB

        This ensures certificates are accessible to:
        - Certmonger for certificate tracking and renewal
        - NSS tools (certutil, pk12util, modutil)

        Args:
            cert_pem_path: Path to PEM certificate file
            key_pem_path: Path to PEM private key file
            nickname: Certificate nickname in NSSDB (e.g., "caSigningCert
                      cert-pki-ca")
            trust_flags: NSS trust flags (default: u,u,u for user certs)
        """
        logger.debug(f"Importing certificate '{nickname}' to NSSDB")

        # Ensure NSSDB password is loaded
        self._load_nssdb_password()

        # Create temporary PKCS#12 file from PEM cert+key
        with tempfile.NamedTemporaryFile(
            suffix=".p12", delete=False
        ) as p12_file:
            p12_path = p12_file.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as pwdfile:
            pwdfile.write(self.nssdb_password)
            pwdfile.flush()
            temp_password_file = pwdfile.name

        try:
            # Create PKCS#12 from PEM cert+key using openssl
            logger.debug(
                f"Creating PKCS#12 from {cert_pem_path} and {key_pem_path}"
            )
            ipautil.run(
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-in",
                    str(cert_pem_path),
                    "-inkey",
                    str(key_pem_path),
                    "-out",
                    p12_path,
                    "-name",
                    nickname,
                    "-passout",
                    f"pass:{self.nssdb_password}",
                ]
            )

            # Import PKCS#12 to NSSDB using pk12util
            logger.debug(
                f"Importing PKCS#12 to NSSDB with nickname '{nickname}'"
            )
            ipautil.run(
                [
                    "pk12util",
                    "-i",
                    p12_path,
                    "-d",
                    str(self.nssdb_dir),
                    "-k",
                    temp_password_file,
                    "-w",
                    temp_password_file,
                ]
            )

            # Set trust flags if not default
            if trust_flags != "u,u,u":
                logger.debug(
                    f"Setting trust flags to '{trust_flags}' for '{nickname}'"
                )
                ipautil.run(
                    [
                        "certutil",
                        "-M",
                        "-d",
                        str(self.nssdb_dir),
                        "-n",
                        nickname,
                        "-t",
                        trust_flags,
                        "-f",
                        temp_password_file,
                    ]
                )

            # Verify certificate was imported
            result = ipautil.run(
                [
                    "certutil",
                    "-L",
                    "-d",
                    str(self.nssdb_dir),
                    "-n",
                    nickname,
                    "-f",
                    temp_password_file,
                ],
                raiseonerr=False,
            )

            if result.returncode == 0:
                logger.debug(
                    f"Certificate '{nickname}' successfully imported to NSSDB"
                )
            else:
                raise RuntimeError(
                    f"Failed to verify certificate import: {nickname}"
                )

        finally:
            # Clean up temporary files
            if os.path.exists(p12_path):
                os.unlink(p12_path)
            if os.path.exists(temp_password_file):
                os.unlink(temp_password_file)

    def __install_dogtag_schema(self):
        """
        Install Dogtag/PKI LDAP schema for dogtag backend

        When using the dogtag backend, we use Dogtag's native LDAP schema
        (certificateRecord, request objectClasses). This method installs
        the schema from PKI's schema files.
        """
        logger.debug("Installing Dogtag/PKI LDAP schema")

        # PKI schema file with OID placeholders
        schema_file = "/usr/share/pki/server/database/ds/schema.ldif"

        if not Path(schema_file).exists():
            raise RuntimeError(
                f"Dogtag schema file not found: {schema_file}. "
                "The dogtag backend requires pki-server package to be "
                "installed."
            )

        # Determine LDAP socket path from realm name
        realm_name = self.realm.replace(".", "-")
        socket_path = f"/run/slapd-{realm_name}.socket"
        socket_url = "ldapi://" + urllib.parse.quote(socket_path, safe="")

        logger.debug(f"Using LDAP socket: {socket_url}")
        logger.debug(f"Loading Dogtag schema from {schema_file}")

        # Use ldapmodify to load the schema
        # Use -c to continue on errors (in case some attributes already exist)
        result = ipautil.run(
            [
                "ldapmodify",
                "-c",  # Continue on errors
                "-Y",
                "EXTERNAL",
                "-H",
                socket_url,
                "-f",
                str(schema_file),
            ],
            raiseonerr=False,
        )

        if result.returncode == 0:
            logger.debug("Dogtag LDAP schema loaded successfully")
        elif result.returncode == 20:
            # Error code 20 = Type or value exists - schema already installed
            logger.debug("Dogtag LDAP schema already exists")
        else:
            logger.error("Failed to load Dogtag LDAP schema!")
            logger.error(f"Return code: {result.returncode}")
            logger.error(f"Stdout: {result.output}")
            logger.error(f"Error output: {result.error_output}")
            logger.error(f"Raw error: {result.raw_error_output}")

            # Don't fail installation - schema might be partially loaded
            # We'll discover missing objectClasses when we try to use them
            logger.warning(
                "Dogtag schema installation had errors but continuing. "
                "If certificate operations fail, check schema loading."
            )

    def __install_ldap_schema(self):
        """Install LDAP schema for Dogtag backend"""
        logger.debug("Installing LDAP schema for Dogtag backend")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        # Install Dogtag/PKI LDAP schema
        self.__install_dogtag_schema()

        logger.debug("LDAP schema installed successfully")

    def __create_ds_db(self):
        """
        Create LDAP backend and suffix for o=ipaca (Dogtag-compatible storage)

        This creates the LDAP database backend and mapping tree for o=ipaca,
        which is required before any Dogtag schema objects can be stored.
        This mirrors what traditional Dogtag/PKI does during installation.
        """
        logger.debug("Creating LDAP backend for o=ipaca")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        backend = "ipaca"
        suffix = DN(("o", "ipaca"))

        # Create LDAP database backend
        # This creates cn=ipaca,cn=ldbm database,cn=plugins,cn=config
        dn = DN(
            ("cn", "ipaca"),
            ("cn", "ldbm database"),
            ("cn", "plugins"),
            ("cn", "config"),
        )

        try:
            # Check if backend already exists
            api.Backend.ldap2.get_entry(dn)
            logger.debug(f"LDAP backend {backend} already exists")
        except errors.NotFound:
            # Create new backend
            logger.debug(f"Creating LDAP backend: {backend}")
            entry = api.Backend.ldap2.make_entry(
                dn,
                objectclass=["top", "extensibleObject", "nsBackendInstance"],
                cn=[backend],
            )
            entry["nsslapd-suffix"] = [suffix]
            api.Backend.ldap2.add_entry(entry)
            logger.debug(f"LDAP backend {backend} created successfully")

        # Create mapping tree entry
        # This maps o=ipaca suffix to the ipaca backend
        dn = DN(("cn", str(suffix)), ("cn", "mapping tree"), ("cn", "config"))

        try:
            # Check if mapping tree already exists
            api.Backend.ldap2.get_entry(dn)
            logger.debug(f"Mapping tree for {suffix} already exists")
        except errors.NotFound:
            # Create new mapping tree
            logger.debug(f"Creating mapping tree for suffix: {suffix}")
            entry = api.Backend.ldap2.make_entry(
                dn,
                objectclass=["top", "extensibleObject", "nsMappingTree"],
                cn=[suffix],
            )
            entry["nsslapd-state"] = ["Backend"]
            entry["nsslapd-backend"] = [backend]
            api.Backend.ldap2.add_entry(entry)
            logger.debug(f"Mapping tree for {suffix} created successfully")

        logger.debug("LDAP backend and suffix for o=ipaca initialized")

    def __initialize_ldap_storage(self):
        """Initialize LDAP storage with CA configuration"""
        logger.debug("Initializing LDAP storage for ipathinca")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        # Create LDAP backend and mapping tree for o=ipaca FIRST
        # This MUST happen before trying to create any entries under o=ipaca
        self.__create_ds_db()

        # Initialize Dogtag-compatible LDAP schema (create o=ipaca and
        # containers)
        # This MUST happen before any certificate operations
        logger.debug("Initializing Dogtag LDAP schema (creating o=ipaca)")
        try:
            storage_backend = CAStorageBackend()
            storage_backend.initialize_schema()
            logger.debug("Dogtag LDAP schema initialized successfully")
        except Exception as e:
            logger.error(
                f"Failed to initialize Dogtag LDAP schema: {e}", exc_info=True
            )
            raise RuntimeError(f"Cannot initialize ipathinca LDAP schema: {e}")

        # Configure LDAPI autobind mapping
        # This allows ipaca (Unix account) to automatically map to ipacasrv
        # (LDAP account)
        self.__configure_ldapi_autobind()

        logger.debug("LDAP storage initialized successfully")

    def __configure_ldapi_autobind(self):
        """Configure LDAPI autobind mapping for ipaca

        This enables the ipathinca service (running as Unix user ipaca) to
        automatically authenticate to LDAP using SASL EXTERNAL bind over LDAPI.
        """
        logger.debug("Configuring LDAPI autobind for ipaca")

        # Determine LDAP socket path from realm name
        realm_name = self.realm.replace(".", "-")
        socket_path = f"/run/slapd-{realm_name}.socket"
        socket_url = "ldapi://" + urllib.parse.quote(socket_path, safe="")

        logger.debug(f"Using LDAP socket: {socket_url}")

        # Create temporary LDIF file to enable autobind mapping
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False
        ) as f:
            ldif_content = f"""# Enable LDAPI autobind mapping for ipaca
dn: cn=config
changetype: modify
replace: nsslapd-ldapimaptoentries
nsslapd-ldapimaptoentries: on
-
replace: nsslapd-ldapientrysearchbase
nsslapd-ldapientrysearchbase: {api.env.basedn}
-
replace: nsslapd-localssf
nsslapd-localssf: 71
"""
            f.write(ldif_content)
            ldif_file = f.name

        try:
            # Apply LDAPI configuration
            result = ipautil.run(
                [
                    "ldapmodify",
                    "-Y",
                    "EXTERNAL",
                    "-H",
                    socket_url,
                    "-f",
                    ldif_file,
                ],
                raiseonerr=False,
            )

            if result.returncode == 0:
                logger.debug("LDAPI autobind mapping enabled successfully")
            elif result.returncode == 16 or (
                result.error_output
                and "No such attribute" in result.error_output
            ):
                logger.debug("LDAPI autobind mapping already configured")
            else:
                error_msg = (
                    result.error_output
                    if result.error_output
                    else result.raw_error_output
                )
                logger.warning(
                    f"Failed to enable LDAPI autobind mapping: {error_msg}"
                )
                # Don't fail installation - the __configure_ldap_access step
                # will handle this

        finally:
            # Clean up temporary file
            os.unlink(ldif_file)

        logger.debug("LDAPI autobind configuration completed")

    def __configure_ldap_access(self):
        """Configure LDAP access for ipaca via LDAPI autobind and sysaccount"""
        logger.debug("Configuring LDAP access for ipaca")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        ldap = api.Backend.ldap2

        # 1. Create ipacasrv sysaccount if it doesn't exist
        # This is the DN that the autobind mapping will point to
        ipacasrv_dn = DN(
            ("uid", "ipacasrv"),
            ("cn", "sysaccounts"),
            ("cn", "etc"),
            api.env.basedn,
        )

        try:
            ldap.get_entry(ipacasrv_dn)
            logger.debug(f"ipacasrv sysaccount already exists: {ipacasrv_dn}")
        except errors.NotFound:
            logger.debug(f"Creating ipacasrv sysaccount at {ipacasrv_dn}")

            # Create sysaccount entry
            entry = ldap.make_entry(
                ipacasrv_dn,
                objectClass=["account", "simplesecurityobject"],
                uid=["ipacasrv"],
                userPassword=["*"],  # No password - will use LDAPI autobind
                description=["IPA CA service account"],
            )
            ldap.add_entry(entry)
            logger.debug("ipacasrv sysaccount created successfully")

        # 2. Configure LDAPI autobind mapping for ipaca UID/GID -> ipacasrv
        # sysaccount
        # Get ipaca UID/GID
        try:
            ipaca_info = pwd.getpwnam("ipaca")
            ipaca_uid = ipaca_info.pw_uid
            ipaca_gid = ipaca_info.pw_gid
        except KeyError:
            logger.warning("ipaca not found, skipping autobind configuration")
            ipaca_info = None

        if ipaca_info:

            autobind_dn = DN(
                ("cn", "ipa-ca"), ("cn", "auto_bind"), ("cn", "config")
            )

            logger.debug(
                f"Creating LDAPI autobind mapping for ipaca "
                f"(uid={ipaca_uid}, gid={ipaca_gid})"
            )

            try:
                autobind_entry = ldap.get_entry(autobind_dn)
                logger.debug(f"Autobind entry already exists: {autobind_dn}")

                # Update if needed
                autobind_entry["uidNumber"] = [str(ipaca_uid)]
                autobind_entry["gidNumber"] = [str(ipaca_gid)]
                autobind_entry["nsslapd-authenticateAsDN"] = [str(ipacasrv_dn)]

                ldap.update_entry(autobind_entry)
                logger.debug("Updated autobind entry")

            except errors.NotFound:
                # Create autobind mapping entry
                # Note: nsslapd-authenticateAsDN has hyphen, so pass as dict
                autobind_entry = ldap.make_entry(
                    autobind_dn,
                    {
                        "objectClass": ["top", "nsLDAPIFixedAuthMap"],
                        "cn": ["ipa-ca"],
                        "uidNumber": [str(ipaca_uid)],
                        "gidNumber": [str(ipaca_gid)],
                        "nsslapd-authenticateAsDN": [str(ipacasrv_dn)],
                    },
                )
                ldap.add_entry(autobind_entry)
                logger.debug(f"Created autobind entry: {autobind_dn}")

            # Reload LDAPI mappings
            service.run_ldapi_reload_task(ldap)
            logger.debug("Reloaded LDAPI mappings")

        # 3. Add ACI to Dogtag root suffix (o=ipaca) for Dogtag schema
        # compatibility
        # This grants ipacasrv full access to all Dogtag CA data stored under
        # o=ipaca
        dogtag_suffix_dn = DN(("o", "ipaca"))

        try:
            dogtag_entry = ldap.get_entry(dogtag_suffix_dn)

            # Check if ACI already exists
            existing_acis = dogtag_entry.get("aci", [])
            has_dogtag_aci = False

            for aci in existing_acis:
                aci_str = str(aci)
                if "ipacasrv" in aci_str and "Dogtag" in aci_str:
                    has_dogtag_aci = True
                    break

            if not has_dogtag_aci:
                # Single broad ACI for all Dogtag CA data
                dogtag_aci = (
                    '(targetattr="*")(version 3.0; acl "Allow ipacasrv full '
                    'access to Dogtag CA data"; '
                    f'allow (all) userdn="ldap:///uid=ipacasrv,'
                    f'cn=sysaccounts,cn=etc,{api.env.basedn}";)'
                )
                logger.debug(
                    "Adding ACI for ipacasrv access to Dogtag root suffix "
                    f"{dogtag_suffix_dn}"
                )
                dogtag_entry.setdefault("aci", []).append(dogtag_aci)
                ldap.update_entry(dogtag_entry)
                logger.debug("Dogtag suffix ACI added successfully")
            else:
                logger.debug(
                    "ACI for ipacasrv on Dogtag suffix already exists"
                )

        except errors.NotFound:
            logger.debug(
                f"Dogtag suffix {dogtag_suffix_dn} not found - ACI will be "
                "added when Dogtag schema is initialized"
            )

        # Initialize sub-CA LDAP schema (container + ACI)
        # This creates the cn=cas,cn=ca container and sets up the ACI
        # to allow ipacasrv system account to manage sub-CA entries
        # Must be done after ipacasrv sysaccount is created above
        try:
            logger.debug("Initializing sub-CA LDAP schema")
            subca_manager = SubCAManager()
            subca_manager.initialize_ldap_schema()
            logger.debug("Sub-CA LDAP schema initialized successfully")
        except Exception as e:
            logger.warning(
                f"Failed to initialize sub-CA schema (may already exist): {e}"
            )

        logger.debug("LDAP access for ipaca configured successfully")

    def __register_ca_service(self):
        """Register CA service in LDAP under cn=masters"""
        logger.debug("Registering CA service in LDAP")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        ldap = api.Backend.ldap2

        # Create service entry:
        # cn=CA,cn={fqdn},cn=masters,cn=ipa,cn=etc,{basedn}

        service_dn = DN(
            ("cn", "CA"),
            ("cn", self.fqdn),
            ("cn", "masters"),
            ("cn", "ipa"),
            ("cn", "etc"),
            api.env.basedn,
        )

        try:
            # Check if entry already exists
            ldap.get_entry(service_dn)
            logger.debug(f"CA service entry already exists: {service_dn}")
        except errors.NotFound:
            logger.debug(f"Creating CA service entry: {service_dn}")

            # Create the entry with proper object classes
            entry = ldap.make_entry(
                service_dn,
                objectClass=["nsContainer", "ipaConfigObject"],
                cn=["CA"],
                ipaConfigString=["enabledService", "startOrder 50"],
            )
            ldap.add_entry(entry)
            logger.debug("CA service entry created successfully")

    def __configure_ca_certs(self):
        """Configure CA certificates and keys matching the manual setup"""
        logger.debug("Configuring CA certificates and keys")

        if self.ca_signing_cert and self.ca_signing_key:
            # Use existing CA certificate and key (e.g., during replica
            # install)
            logger.debug("Using existing CA certificate and key")

            # Copy CA certificate to working directory
            shutil.copy2(self.ca_signing_cert, self.ca_cert_working)
            self.ca_cert_working.chmod(0o644)
            shutil.chown(self.ca_cert_working, user="ipaca", group="ipaca")

            # Copy CA key to private directory
            shutil.copy2(self.ca_signing_key, self.ca_key_path)
            self.ca_key_path.chmod(0o640)
            shutil.chown(self.ca_key_path, user="ipaca", group="ipaca")

            # Copy CA certificate to standard IPA location
            shutil.copy2(self.ca_cert_working, self.ca_cert_path)
            self.ca_cert_path.chmod(0o644)

            logger.debug("CA certificates and keys configured successfully")

        elif self.ca_cert_working.exists() and self.ca_key_path.exists():
            # CA certificate and key already exist from manual setup
            logger.debug(
                "CA certificate and key already exist in ipathinca directories"
            )

            # Make sure they are also in standard IPA location
            if not self.ca_cert_path.exists():
                shutil.copy2(self.ca_cert_working, self.ca_cert_path)
                self.ca_cert_path.chmod(0o644)
                logger.debug("Copied CA certificate to /etc/ipa/ca.crt")

        else:
            # During fresh installation, we need to generate the CA certificate
            # Check for external CA mode
            if self.external_ca_step == 1:
                # External CA Step 1: Generate CSR and exit
                logger.debug("External CA Step 1: Generating CSR")
                self.__generate_external_ca_csr()
                # Never returns - exits after CSR generation
            elif self.external_ca_step == 2:
                # External CA Step 2: Install signed certificate
                logger.debug(
                    "External CA Step 2: Installing signed certificate"
                )
                self.__install_external_ca_cert()
                # Continue with normal installation after this
            else:
                # Normal self-signed CA installation
                logger.debug(
                    "Generating new self-signed CA certificate and key"
                )
                self.__generate_ca_certificate()

        logger.debug("CA certificate configuration step completed")

    def _get_signing_hash_algorithm(self):
        """
        Map CA signing algorithm to cryptography hash function

        Uses ipaserver.install.ca.CASigningAlgorithm enum values.
        Default from ipaca_customize.ini: SHA256withRSA

        Returns:
            cryptography.hazmat.primitives.hashes hash algorithm instance

        Raises:
            ValueError: If algorithm is unsupported
        """
        # Map CASigningAlgorithm enum to hash function
        # Default: SHA256withRSA (from ipaca_customize.ini)
        if self.ca_signing_algorithm is None:
            # Default from ipaca_customize.ini
            return hashes.SHA256()

        # Get the algorithm string value from enum
        if hasattr(self.ca_signing_algorithm, "value"):
            alg_str = self.ca_signing_algorithm.value
        else:
            alg_str = str(self.ca_signing_algorithm)

        algorithm_map = {
            "SHA1withRSA": hashes.SHA1(),
            "SHA256withRSA": hashes.SHA256(),
            "SHA384withRSA": hashes.SHA384(),
            "SHA512withRSA": hashes.SHA512(),
        }

        hash_alg = algorithm_map.get(alg_str)
        if hash_alg is None:
            raise ValueError(
                f"Unsupported CA signing algorithm: {alg_str}. "
                f"Supported algorithms: {', '.join(algorithm_map.keys())}"
            )

        logger.info(f"Using CA signing algorithm: {alg_str}")
        return hash_alg

    def __generate_external_ca_csr(self):
        """Generate CA signing CSR for external CA (Step 1 - Dogtag-compatible)

        The NSSDB at /etc/pki/pki-tomcat/alias/ persists for Step 2.
        """
        logger.info("=== External CA Step 1: Generating CA signing CSR ===")

        from ipaserver.install import installutils
        from ipaserver.install.ca import (
            subject_validator,
            VALID_SUBJECT_BASE_ATTRS,
            VALID_SUBJECT_ATTRS,
        )
        from ipalib import x509 as ipalib_x509
        from ipathinca.nss_utils import NSSDatabase

        # Set defaults for subject DNs
        if self.subject_base is None:
            self.subject_base = installutils.default_subject_base(self.realm)
        if self.ca_subject is None:
            self.ca_subject = installutils.default_ca_subject_dn(
                self.subject_base
            )

        # Validate
        subject_validator(VALID_SUBJECT_BASE_ATTRS, self.subject_base)
        subject_validator(VALID_SUBJECT_ATTRS, self.ca_subject)
        logger.info(f"CA subject DN: {self.ca_subject}")

        # Initialize NSSDB
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        ca_nickname = "caSigningCert cert-pki-ca"

        # Get CA signing key size from config
        ca_key_size, _ = self.__get_cert_params_from_config("ca_signing")

        # Generate key pair in NSSDB
        logger.info(
            f"Generating {ca_key_size}-bit RSA key in NSSDB: {ca_nickname}"
        )
        private_key = nssdb.generate_key_pair(
            ca_nickname, key_size=ca_key_size
        )

        # Build CSR
        subject_dn_x509 = ipa_dn_to_x509_name(str(self.ca_subject))
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject_dn_x509)

        # Add MS Certificate Template extension if needed
        if self.external_ca_type == ipalib_x509.ExternalCAType.MS_CS.value:
            logger.info("Adding Microsoft Certificate Template extension")
            template = self.external_ca_profile or ipalib_x509.MSCSTemplateV1(
                "SubCA"
            )
            ext_data = template.get_ext_data()
            csr_builder = csr_builder.add_extension(
                x509.UnrecognizedExtension(
                    oid=x509.ObjectIdentifier(template.ext_oid), value=ext_data
                ),
                critical=False,
            )

        # Get signing algorithm for CSR (use CA signing algorithm)
        _, signing_alg = self.__get_cert_params_from_config("ca_signing")
        hash_alg = self.__convert_signing_algorithm(signing_alg)

        # Sign CSR with configured algorithm
        logger.info(f"Signing CSR with {signing_alg}")
        csr = csr_builder.sign(
            private_key, hash_alg, backend=default_backend()
        )

        # Save CSR to file
        logger.info(f"Saving CSR to {self.csr_file}")
        with open(self.csr_file, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        os.chmod(self.csr_file, 0o644)

        # Save state for Step 2
        state_file = "/var/lib/ipa/ipathinca_external_ca.state"
        state = {
            "step": 1,
            "csr_path": self.csr_file,
            "ca_subject": str(self.ca_subject),
            "subject_base": str(self.subject_base),
            "ca_nickname": ca_nickname,
        }
        os.makedirs("/var/lib/ipa", exist_ok=True)
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
        os.chmod(state_file, 0o600)

        # Print instructions (Dogtag-style)
        print(
            "The next step is to get %s signed by your CA and re-run %s as:"
            % (self.csr_file, sys.argv[0])
        )
        print(
            "%s --external-cert-file=/path/to/signed_certificate "
            "--external-cert-file=/path/to/external_ca_certificate"
            % sys.argv[0]
        )

        logger.info("External CA Step 1 complete - exiting")
        sys.exit(0)

    def __install_external_ca_cert(self):
        """Install externally-signed CA certificate (Step 2)

        Imports signed cert to NSSDB where the key exists from Step 1.
        """
        logger.info(
            "=== External CA Step 2: Installing signed certificate ==="
        )

        from ipaserver.install import installutils
        from ipathinca.nss_utils import NSSDatabase

        # Load state from Step 1
        state_file = "/var/lib/ipa/ipathinca_external_ca.state"
        if not os.path.exists(state_file):
            raise RuntimeError(
                "External CA state file not found. "
                "Run Step 1 first (without --external-cert-file)"
            )

        with open(state_file) as f:
            state = json.load(f)

        logger.info(f"CA Subject DN: {state['ca_subject']}")
        ca_nickname = state["ca_nickname"]

        # Verify NSSDB key exists (check if cert exists - key must exist if
        # cert does)
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        if not nssdb.cert_exists(ca_nickname):
            raise RuntimeError(
                f"Certificate/key not found in NSSDB: {ca_nickname}\n"
                f"NSSDB may have been recreated. Start over with Step 1."
            )

        # Load and validate external certificate
        logger.info("Loading and validating external certificate")
        external_cert_file, external_ca_file = installutils.load_external_cert(
            [self.cert_file, self.cert_chain_file], state["ca_subject"]
        )

        # Read signed CA certificate
        with open(external_cert_file.name, "rb") as f:
            ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_data, default_backend()
            )

        # Read CA chain
        with open(external_ca_file.name, "rb") as f:
            ca_chain_pem = f.read()

        # Verify subject matches
        cert_subject_str = get_subject_dn_str(ca_cert)
        if cert_subject_str != state["ca_subject"]:
            raise ValueError(
                f"Certificate subject '{cert_subject_str}' != "
                f"CSR subject '{state['ca_subject']}'"
            )

        # Import certificate to NSSDB (key already exists from Step 1)
        logger.info(f"Importing signed certificate to NSSDB: {ca_nickname}")
        nssdb.import_certificate(
            nickname=ca_nickname, certificate=ca_cert, trust_flags="CTu,Cu,Cu"
        )

        # Export cert and key to PEM for IPAThinCA runtime
        logger.info(f"Exporting CA certificate to {self.ca_cert_path}")
        with open(self.ca_cert_path, "wb") as f:
            f.write(ca_cert_data)
        self.ca_cert_path.chmod(0o644)

        logger.info(f"Exporting CA private key to {self.ca_key_path}")
        private_key = nssdb.extract_private_key(ca_nickname)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.ca_key_path, "wb") as f:
            f.write(key_pem)
        self.ca_key_path.chmod(0o600)
        shutil.chown(self.ca_key_path, user="ipaca", group="ipaca")

        # Store full chain
        ca_chain_path = Path(paths.IPA_CA_CRT)
        with open(ca_chain_path, "wb") as f:
            f.write(ca_cert_data)
            f.write(b"\n")
            f.write(ca_chain_pem)
        ca_chain_path.chmod(0o644)

        # Clean up state file
        try:
            os.unlink(state_file)
        except Exception as e:
            logger.warning(f"Failed to remove state file: {e}")

        logger.info(
            "External CA certificate installed - continuing installation"
        )

    def __generate_ca_certificate(self):
        """
        Generate CA certificate and private key for fresh installation

        Dogtag-compatible approach: Generate key in NSSDB, extract for signing,
        import certificate back to NSSDB. No PEM key files on disk.
        """
        logger.debug(
            "Generating CA certificate and private key in NSSDB "
            "(Dogtag-compatible)"
        )

        # Import utilities for default values
        from ipaserver.install import installutils
        from ipathinca.nss_utils import NSSDatabase

        # Set defaults for subject DNs if not provided
        # User-provided values are already validated in ca.py before reaching
        # here
        if self.subject_base is None:
            self.subject_base = installutils.default_subject_base(self.realm)
            logger.debug(f"Using default subject_base: {self.subject_base}")

        if self.ca_subject is None:
            self.ca_subject = installutils.default_ca_subject_dn(
                self.subject_base
            )
            logger.debug(f"Using default ca_subject: {self.ca_subject}")

        # Use configured CA subject
        subject_dn = self.ca_subject
        logger.debug(f"CA subject DN: {subject_dn}")

        # Certificate nickname in NSSDB
        ca_nickname = "caSigningCert cert-pki-ca"

        # Get CA signing key size from config
        ca_key_size, ca_signing_alg = self.__get_cert_params_from_config(
            "ca_signing"
        )
        logger.info(
            f"CA signing certificate parameters: key_size={ca_key_size}, "
            f"signing_alg={ca_signing_alg}"
        )

        # NSSDB path - generate key in NSSDB (default)
        logger.debug("Generating CA key pair in NSSDB (default)")
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        # Generate private key (in memory, will be imported to NSSDB)
        logger.debug(
            f"Generating {ca_key_size}-bit RSA key pair for NSSDB: "
            f"{ca_nickname}"
        )
        private_key = nssdb.generate_key_pair(
            ca_nickname, key_size=ca_key_size
        )

        # Build certificate subject using shared utility
        # Convert IPA DN to x509.Name with proper RDN wrapping and ordering
        cert_subject = ipa_dn_to_x509_name(str(subject_dn))

        # Set validity period (10 years, matching OpenSSL version)
        now = datetime.datetime.now(datetime.UTC)
        not_valid_before = now
        not_valid_after = now + datetime.timedelta(days=3650)

        # Generate serial number for CA certificate
        # Use serial 1 when random serial numbers are disabled (matching
        # Dogtag)
        # Use random serial when enabled
        if self.random_serial_numbers:
            # Read serial_number_bits from config (default: 128, matching
            # Dogtag RSNv3)
            # Config is not yet loaded at this point, use default
            serial_number_bits = 128

            # Generate random number with MSB set to ensure consistent length
            # E.g., 128 bits = 32 hex digits, 160 bits = 40 hex digits
            serial_number = secrets.randbits(serial_number_bits) | (
                1 << (serial_number_bits - 1)
            )
            logger.debug(
                f"Using random serial number ({serial_number_bits} bits): "
                f"{serial_number}"
            )
        else:
            serial_number = 1
            logger.debug("Using serial number 1 for CA certificate")

        # Build certificate
        logger.debug("Building self-signed CA certificate")
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(cert_subject)
        cert_builder = cert_builder.issuer_name(cert_subject)  # Self-signed
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(serial_number)
        cert_builder = cert_builder.not_valid_before(not_valid_before)
        cert_builder = cert_builder.not_valid_after(not_valid_after)

        # Add CA extensions
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Add Subject Key Identifier
        ski = x509.SubjectKeyIdentifier.from_public_key(
            private_key.public_key()
        )
        cert_builder = cert_builder.add_extension(ski, critical=False)

        # Add Authority Key Identifier (same as SKI for self-signed)
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            private_key.public_key()
        )
        cert_builder = cert_builder.add_extension(aki, critical=False)

        # Sign the certificate with configured algorithm
        # (default: SHA256withRSA from ipaca_customize.ini)
        hash_alg = self._get_signing_hash_algorithm()
        logger.debug(f"Signing CA certificate with {hash_alg.name}")
        certificate = cert_builder.sign(
            private_key, hash_alg, backend=default_backend()
        )

        # NSSDB path - import key and certificate to NSSDB
        logger.debug(
            f"Importing CA key and certificate to NSSDB: {ca_nickname}"
        )
        nssdb.import_key_and_cert(
            ca_nickname,
            private_key,
            certificate,
            trust_flags="CTu,Cu,Cu",  # CA trust flags
        )
        logger.debug("CA private key generated in NSSDB (no PEM file created)")

        # Save certificate to file (for compatibility with IPA tools)
        logger.debug(f"Writing CA certificate to {self.ca_cert_working}")
        with open(self.ca_cert_working, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        # Set ownership and permissions on certificate
        self.ca_cert_working.chmod(0o644)
        shutil.chown(self.ca_cert_working, user="ipaca", group="ipaca")
        logger.debug(f"Set permissions on {self.ca_cert_working}")

        # Copy CA certificate to standard IPA location
        shutil.copy2(self.ca_cert_working, self.ca_cert_path)
        self.ca_cert_path.chmod(0o644)
        logger.debug(f"Installed CA certificate to {self.ca_cert_path}")

        # Note: CA certificate already imported to NSSDB above with proper
        # trust flags

        # Export CA certificate to NSSDB alias directory (Dogtag compatibility)
        # Dogtag exports ca.crt to /etc/pki/pki-tomcat/alias/ca.crt for
        # convenience
        ca_crt_alias = self.nssdb_dir / "ca.crt"
        logger.debug(
            f"Exporting CA certificate to {ca_crt_alias}"
            " (Dogtag compatibility)"
        )
        shutil.copy2(self.ca_cert_working, ca_crt_alias)
        ca_crt_alias.chmod(0o600)  # Dogtag uses -rw------- for ca.crt
        shutil.chown(ca_crt_alias, user="ipaca", group="ipaca")

        logger.debug(
            "CA certificate and private key generated successfully with "
            f"serial {serial_number}"
        )

    def __install_ca_trust(self):
        """Install CA certificate to system trust store"""
        logger.debug("Installing CA certificate to system trust store")

        try:
            # Use 'trust anchor --store' to properly add CA as a trust anchor
            # This is more reliable than copying to anchors directory
            logger.debug("Adding CA certificate as trust anchor")
            ipautil.run(["trust", "anchor", "--store", str(self.ca_cert_path)])

            logger.debug(
                "CA certificate installed to system trust successfully"
            )
        except Exception as e:
            logger.warning(f"Failed to install CA to system trust: {e}")
            # Don't fail the installation if this step fails

    def __store_ca_cert_ldap(self):
        """Store CA certificate in LDAP with proper nickname"""
        logger.debug("Storing CA certificate in LDAP")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        ldap = api.Backend.ldap2

        # Read the CA certificate
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_pem = f.read()
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem, default_backend()
            )

        # Get the proper nickname for the CA certificate
        ca_nickname = get_ca_nickname(self.realm)

        # DN for the CA certificate in LDAP
        ca_dn = DN(
            ("cn", "CAcert"), ("cn", "ipa"), ("cn", "etc"), api.env.basedn
        )

        # Ensure parent container exists
        ipa_etc_dn = DN(("cn", "ipa"), ("cn", "etc"), api.env.basedn)
        try:
            ldap.get_entry(ipa_etc_dn)
        except errors.NotFound:
            logger.debug(f"Creating parent container {ipa_etc_dn}")
            parent_entry = ldap.make_entry(
                ipa_etc_dn, objectClass=["nsContainer", "top"], cn=["ipa"]
            )
            ldap.add_entry(parent_entry)

        try:
            # Check if entry already exists
            entry = ldap.get_entry(ca_dn)
            logger.debug(f"CA certificate entry already exists at {ca_dn}")

            # Update it with our certificate (but not cn, which is the RDN)
            cert_der = ca_cert.public_bytes(serialization.Encoding.DER)

            entry["cACertificate"] = [cert_der]
            # Don't modify cn - it's the RDN and cannot be changed
            ldap.update_entry(entry)
            logger.debug("Updated CA certificate in LDAP")

        except errors.NotFound:
            # Create new entry
            logger.debug(
                "Creating CA certificate entry in LDAP with "
                f"nickname '{ca_nickname}'"
            )

            cert_der = ca_cert.public_bytes(serialization.Encoding.DER)

            entry = ldap.make_entry(
                ca_dn,
                objectClass=["nsContainer", "pkiCA", "top"],
                cn=[ca_nickname],
                cACertificate=[cert_der],
            )
            ldap.add_entry(entry)
            logger.debug("CA certificate stored in LDAP successfully")

    def __create_ipa_ca_entry(self):
        """Create IPA CA entry in cn=cas,cn=ca,{basedn} with certificate and
        key"""

        logger.debug("Creating IPA CA entry in LDAP")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        ldap = api.Backend.ldap2

        # DN for the IPA CA entry
        ipa_ca_dn = DN(
            ("cn", "ipa"), ("cn", "cas"), ("cn", "ca"), api.env.basedn
        )

        try:
            # Check if entry already exists
            ldap.get_entry(ipa_ca_dn)
            logger.debug("IPA CA entry already exists")
            return
        except errors.NotFound:
            pass

        # Read the CA certificate and private key

        with open(self.ca_cert_path, "rb") as f:
            ca_cert_pem = f.read()
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem, default_backend()
            )

        # TODO: needed?
        # with open(self.ca_key_path, "rb") as f:
        #     ca_key_pem = f.read()

        # Convert subject to proper DN string format (like Dogtag does)
        # Extract CA subject DN using shared utility
        ca_subject_str = get_subject_dn_str(ca_cert)

        logger.debug(f"CA Subject DN: {ca_subject_str}")

        # TODO: needed?
        # Convert certificate to DER format for LDAP storage
        # cert_der = ca_cert.public_bytes(serialization.Encoding.DER)

        # Generate a UUID for the CA Authority ID (like Dogtag does)
        ca_authority_id = str(uuid.uuid4())

        # Create the IPA CA entry with certificate and private key
        # This allows replicas to fetch the CA cert/key from LDAP instead of
        # Custodia
        logger.debug(
            f"Creating IPA CA entry at {ipa_ca_dn} with authority "
            f"ID {ca_authority_id}"
        )

        # Determine random serial number version (RSNv3 = 3, disabled = 0)
        rsn_version = "3" if self.random_serial_numbers else "0"

        # Build entry attributes
        entry_attrs = {
            "objectClass": ["top", "ipaca"],
            "cn": [IPA_CA_CN],
            "ipaCaId": [ca_authority_id],
            "ipaCaSubjectDN": [ca_subject_str],
            "ipaCaIssuerDN": [ca_subject_str],  # Self-signed
            # Note: ipaCertificateSubjectBase is stored globally in
            # cn=ipaConfig,cn=etc,{basedn}, not per-CA
            "ipaCaRandomSerialNumberVersion": [rsn_version],
            "description": ["IPA CA"],
        }

        entry = ldap.make_entry(ipa_ca_dn, **entry_attrs)

        ldap.add_entry(entry)
        logger.debug(
            "IPA CA entry created successfully with certificate and private "
            "key"
        )

    def __init_cert_storage_schema(self):
        """Initialize certificate storage LDAP schema"""
        logger.debug("Initializing certificate storage LDAP schema")

        try:
            # Get storage backend (Dogtag backend only)
            backend = get_storage_backend()

            # Initialize LDAP schema (creates Dogtag LDAP containers)
            backend.initialize_schema()

            logger.debug("Certificate storage schema initialized successfully")
        except Exception as e:
            logger.warning(
                f"Failed to initialize certificate storage schema: {e}"
            )
            # Don't fail installation if schema already exists
            logger.debug("Schema may already exist, continuing...")

    def __store_ca_cert_in_certdb(self):
        """Store CA certificate in certificate database using Dogtag storage
        backend"""
        logger.debug("Storing CA certificate in certificate database")

        # Read the CA certificate
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_pem = f.read()
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem, default_backend()
            )

        # Use the CA's actual serial number from the certificate
        serial_number = ca_cert.serial_number
        logger.debug(f"CA certificate serial number: {serial_number}")

        # Use storage backend to store CA certificate in Dogtag schema
        backend = get_storage_backend()

        # Check if certificate already exists
        try:
            existing_cert = backend.get_certificate(serial_number)
            if existing_cert:
                logger.debug(
                    f"CA certificate (serial {serial_number}) already in "
                    "database"
                )
                return
        except Exception:
            pass  # Certificate doesn't exist, continue to store it

        # Create a dummy request for the CA certificate
        dummy_request = CertificateRequest(csr=None, profile="caCACert")
        dummy_request.request_id = "ca-self-signed"

        # Create CertificateRecord for the CA certificate
        cert_record = CertificateRecord(
            ca_cert, dummy_request, principal="ca_installation"
        )
        cert_record.serial_number = serial_number

        # Store certificate using Dogtag backend
        backend.store_certificate(cert_record, allow_update=False)

        # Update serial number counter to prevent reuse when not using random
        # serials
        # This ensures the next certificate doesn't try to reuse serial 1
        if not self.random_serial_numbers:
            config_dn = DN("cn=CAConfig,ou=ca,o=ipaca")
            try:
                if not api.Backend.ldap2.isconnected():
                    api.Backend.ldap2.connect()
                config_entry = api.Backend.ldap2.get_entry(config_dn)
                config_entry["serialno"] = [str(serial_number)]
                config_entry["lastSerialNo"] = [str(serial_number)]
                api.Backend.ldap2.update_entry(config_entry)
                logger.info(
                    f"Updated serial number counter to {serial_number} after "
                    "storing CA certificate"
                )
            except errors.NotFound:
                logger.error(
                    f"CA config entry {config_dn} not found, serial counter "
                    "not updated - subsystem cert generation will fail!"
                )
                raise RuntimeError(
                    f"CA config entry not found at {config_dn}. Schema "
                    "initialization may have failed."
                )
            except Exception as e:
                logger.error(
                    f"Failed to update serial counter: {e}", exc_info=True
                )
                raise

        logger.debug(
            "CA certificate stored in certificate database with serial "
            f"{serial_number}"
        )

    def __import_profiles_ldap(self):
        """Import default certificate profiles to LDAP"""
        logger.debug("Importing certificate profiles to LDAP")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        ldap = api.Backend.ldap2

        # IPA stores certificate profiles at cn=certprofiles,cn=ca,{basedn}
        # This is separate from our ipathinca storage at
        # ou=profiles,ou=ca,{basedn}
        certprofiles_base = DN(
            ("cn", "certprofiles"), ("cn", "ca"), api.env.basedn
        )

        # Ensure certprofiles container exists
        try:
            ldap.get_entry(certprofiles_base)
        except errors.NotFound:
            logger.debug(
                f"Creating certprofiles container: {certprofiles_base}"
            )
            # The container should have been created by cainstance, but
            # create it if missing
            ca_base = DN(("cn", "ca"), api.env.basedn)
            try:
                ldap.get_entry(ca_base)
            except errors.NotFound:
                logger.debug(f"Creating ca container: {ca_base}")
                ca_entry = ldap.make_entry(
                    ca_base, objectClass=["top", "nsContainer"], cn=["ca"]
                )
                ldap.add_entry(ca_entry)

            certprofiles_entry = ldap.make_entry(
                certprofiles_base,
                objectClass=["top", "nsContainer"],
                cn=["certprofiles"],
            )
            ldap.add_entry(certprofiles_entry)

        # Import ipathinca profiles
        profile_manager = ProfileManager()

        # Get all default profiles
        profiles = profile_manager.list_profiles()

        for profile in profiles:
            # Store in IPA's certprofile location
            profile_dn = DN(("cn", profile.profile_id), certprofiles_base)

            try:
                # Check if profile already exists
                ldap.get_entry(profile_dn)
                logger.debug(
                    f"Profile {profile.profile_id} already exists " f"in LDAP"
                )
            except errors.NotFound:
                # Create profile entry in LDAP
                logger.debug(f"Creating profile {profile.profile_id} in LDAP")

                entry = ldap.make_entry(
                    profile_dn,
                    objectClass=["ipaCertProfile", "top"],
                    cn=[profile.profile_id],
                    description=[profile.description],
                    ipaCertProfileStoreIssued=["TRUE"],
                )

                # Store the profile configuration in a text attribute
                # IPA uses ipaCertProfileData but we'll use description for
                # now since the actual profile enforcement is in Python code
                ldap.add_entry(entry)

        logger.debug(f"Imported {len(profiles)} certificate profiles to LDAP")

        # Import Dogtag .cfg profiles to Dogtag LDAP tree
        # (ou=certificateProfiles,ou=ca,o=ipaca)
        logger.debug(
            "Importing Dogtag .cfg profiles to Dogtag LDAP tree (o=ipaca)"
        )

        # Get storage backend
        backend = get_storage_backend()

        # Create ProfileManager with storage backend and config
        profile_manager_dogtag = ProfileManager(
            config=self.config, storage_backend=backend
        )

        # Import all .cfg profiles from /usr/share/ipa/profiles/ to LDAP
        try:
            profile_manager_dogtag.store_all_dogtag_profiles_to_ldap()
            logger.info("✓ All Dogtag .cfg profiles imported to LDAP")
        except Exception as e:
            logger.error(
                f"Failed to import Dogtag profiles to LDAP: {e}",
                exc_info=True,
            )
            raise RuntimeError(f"Cannot import Dogtag profiles to LDAP: {e}")

    def __create_default_caacl(self):
        """Create default CA ACL for hosts and services"""
        logger.debug("Creating default CA ACL")

        # Check if any CA ACLs exist
        try:
            result = api.Command.caacl_find()
            if result["result"]:
                logger.debug(
                    "CA ACLs already exist, skipping default creation"
                )
                return
        except Exception as e:
            logger.debug(f"Error checking for existing CA ACLs: {e}")

        # Create default CAACL for hosts and services using caIPAserviceCert
        # profile
        try:
            logger.debug("Creating hosts_services_caIPAserviceCert CA ACL")
            api.Command.caacl_add(
                "hosts_services_caIPAserviceCert",
                hostcategory="all",
                servicecategory="all",
            )

            # Add the caIPAserviceCert profile to the ACL
            api.Command.caacl_add_profile(
                "hosts_services_caIPAserviceCert",
                certprofile=("caIPAserviceCert",),
            )

            logger.debug("Default CA ACL created successfully")

        except Exception as e:
            logger.error(f"Failed to create default CA ACL: {e}")
            raise

    def __get_cert_params_from_config(self, cert_type):
        """Get certificate key parameters from pki_config

        Args:
            cert_type: Certificate type (e.g., 'ca_signing', 'subsystem',
                       'audit_signing', 'ocsp_signing', 'sslserver')

        Returns:
            tuple: (key_size, signing_algorithm) with defaults if not in config
        """
        if not hasattr(self, "pki_config") or self.pki_config is None:
            # Fallback defaults if pki_config not available
            return (2048, "SHA256withRSA")

        # Map cert type to config keys
        config_prefix = {
            "ca_signing": "pki_ca_signing",
            "subsystem": "pki_subsystem",
            "audit_signing": "pki_audit_signing",
            "ocsp_signing": "pki_ocsp_signing",
            "sslserver": "pki_sslserver",
        }.get(
            cert_type, "pki_sslserver"
        )  # Default to sslserver

        # Get key size (default 2048)
        key_size = self.pki_config.getint(
            "CA",
            f"{config_prefix}_key_size",
            fallback=self.pki_config.getint(
                "DEFAULT", "ipa_key_size", fallback=2048
            ),
        )

        # Get signing algorithm (default SHA256withRSA)
        signing_alg = self.pki_config.get(
            "CA",
            f"{config_prefix}_signing_algorithm",
            fallback=self.pki_config.get(
                "DEFAULT", "ipa_signing_algorithm", fallback="SHA256withRSA"
            ),
        )

        return (key_size, signing_alg)

    def __convert_signing_algorithm(self, signing_alg):
        """Convert PKI signing algorithm string to cryptography hash algorithm

        Args:
            signing_alg: PKI algorithm string (e.g., 'SHA256withRSA',
                         'SHA512withRSA')

        Returns:
            cryptography hash algorithm instance
        """
        from cryptography.hazmat.primitives import hashes

        # Extract hash algorithm from PKI format (e.g., 'SHA256withRSA' ->
        # 'SHA256')
        if "SHA512" in signing_alg:
            return hashes.SHA512()
        elif "SHA384" in signing_alg:
            return hashes.SHA384()
        elif "SHA256" in signing_alg:
            return hashes.SHA256()
        elif "SHA1" in signing_alg:
            return hashes.SHA1()
        else:
            # Default to SHA256
            logger.warning(
                f"Unknown signing algorithm '{signing_alg}', "
                "defaulting to SHA256"
            )
            return hashes.SHA256()

    def __generate_subsystem_certs(self):
        """
        Generate PKI subsystem certificates through ipathinca CA

        Dogtag-compatible approach: Generate keys in NSSDB, extract for CSR,
        import certificates back to NSSDB. No PEM key files on disk.
        """
        logger.debug(
            "Generating PKI subsystem certificates through ipathinca CA "
            "(Dogtag-compatible NSSDB storage)"
        )

        # Import NSS utilities
        from ipathinca.nss_utils import NSSDatabase

        # Load CA certificate to get organization
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(
                f.read(), default_backend()
            )

        # Extract organization from CA subject for subsystem certificates
        org = None
        for attr in ca_cert.subject:
            if attr.oid == NameOID.ORGANIZATION_NAME:
                org = attr.value
                break

        if not org:
            org = self.realm

        # Initialize ipathinca CA instance for certificate issuance
        ca = PythonCA(
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path),
            ca_id="ipa",
            random_serial_numbers=self.random_serial_numbers,
        )

        # Initialize NSSDB access
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        # Define subsystem certificates to generate
        # Format: (common_name, profile, file_prefix)
        subsystem_certs = [
            ("CA Subsystem", "caSubsystemCert", "ca_subsystem"),
            ("CA Audit", "caSignedLogCert", "ca_audit"),
            ("OCSP Subsystem", "caOCSPCert", "ocsp_subsystem"),
            ("ipa-ca-agent", "caServerCert", "ipa_ca_agent"),
        ]

        # Map profile to NSSDB nickname (Dogtag-compatible naming)
        nickname_map = {
            "caSubsystemCert": "subsystemCert cert-pki-ca",
            "caSignedLogCert": "auditSigningCert cert-pki-ca",
            "caOCSPCert": "ocspSigningCert cert-pki-ca",
            "caServerCert": "ipa-ca-agent cert-pki-ca",
        }

        # Map profile to cert_type for config lookup
        cert_type_map = {
            dogtag.SUBSYSTEM_PROFILE: "subsystem",
            dogtag.AUDIT_PROFILE: "audit_signing",
            dogtag.OCSP_PROFILE: "ocsp_signing",
            # Use subsystem settings for CA agent
            dogtag.CASERVER_PROFILE: "subsystem",
        }

        for cn, profile, file_prefix in subsystem_certs:
            cert_path = self.ipaca_certs_dir / f"{file_prefix}.crt"
            nssdb_nickname = nickname_map.get(profile, f"{cn} cert-pki-ca")

            # Skip if certificate already exists in NSSDB
            if nssdb.cert_exists(nssdb_nickname):
                logger.debug(f"{cn} certificate already exists in NSSDB")
                continue

            # Get certificate parameters from config
            cert_type = cert_type_map.get(profile, "subsystem")
            key_size, signing_alg = self.__get_cert_params_from_config(
                cert_type
            )
            hash_alg = self.__convert_signing_algorithm(signing_alg)

            logger.debug(
                f"Generating {cn} certificate with profile {profile} "
                f"(key_size={key_size}, signing_alg={signing_alg})"
            )

            # Generate private key in memory (will be imported to NSSDB with
            # cert)
            logger.debug(f"Generating key pair for NSSDB: {nssdb_nickname}")
            private_key = nssdb.generate_key_pair(
                nssdb_nickname, key_size=key_size
            )

            # Build subject using shared utility
            # Attributes in natural/display order (most-specific-first)
            subject = build_x509_name([("CN", cn), ("O", org)], reverse=True)

            # Create CSR
            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(subject)

            # Sign CSR with private key using configured hash algorithm
            csr = csr_builder.sign(
                private_key, hash_alg, backend=default_backend()
            )

            # Convert CSR to PEM
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            )

            # Submit certificate request through ipathinca CA
            request_id = ca.submit_certificate_request(csr_pem, profile)
            logger.debug(
                f"Submitted certificate request {request_id} for " f"{cn}"
            )

            # Sign the request to issue certificate
            serial_number = ca.sign_certificate_request(request_id)
            logger.debug(
                f"Issued certificate with serial {serial_number} for {cn}"
            )

            # Retrieve the issued certificate
            cert_record = ca.get_certificate(serial_number)
            if not cert_record:
                raise RuntimeError(
                    f"Failed to retrieve issued certificate for {cn}"
                )

            # Import key and certificate to NSSDB
            trust_flags_map = {
                "caSubsystemCert": "u,u,u",
                "caSignedLogCert": "u,u,Pu",
                "caOCSPCert": "u,u,u",
                "caServerCert": "u,u,u",
            }
            trust_flags = trust_flags_map.get(profile, "u,u,u")

            logger.debug(
                f"Importing {cn} key and certificate to NSSDB: "
                f"{nssdb_nickname}"
            )
            nssdb.import_key_and_cert(
                nssdb_nickname,
                private_key,
                cert_record.certificate,
                trust_flags=trust_flags,
            )

            # Save certificate to file (for compatibility/reference)
            # Note: Private key is NOT saved to disk - it stays in NSSDB only
            with open(cert_path, "wb") as f:
                f.write(
                    cert_record.certificate.public_bytes(
                        serialization.Encoding.PEM
                    )
                )
            cert_path.chmod(0o644)
            shutil.chown(cert_path, user="ipaca", group="ipaca")

            logger.debug(
                f"{cn} certificate issued and saved (serial: {serial_number})"
            )

            # For subsystem cert, create pkidbuser LDAP entry (healthcheck
            # compatibility)
            if profile == "caSubsystemCert":
                self.__create_pkidbuser_entry(cert_record.certificate)

        logger.debug(
            "All PKI subsystem certificates generated through ipathinca CA"
        )

    def __create_pkidbuser_entry(self, subsystem_cert):
        """
        Create uid=pkidbuser,ou=people,o=ipaca LDAP entry with subsystem cert.

        This entry is required for healthcheck compatibility. Dogtag creates
        this user to hold the subsystem certificate used for LDAP
        authentication.

        Args:
            subsystem_cert: The CA subsystem certificate
                            (cryptography.x509.Certificate)
        """
        logger.debug(
            "Creating pkidbuser LDAP entry for healthcheck compatibility"
        )

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        # DN for pkidbuser entry
        pkidbuser_dn = DN("uid=pkidbuser", "ou=people", "o=ipaca")

        # Check if entry already exists
        try:
            api.Backend.ldap2.get_entry(pkidbuser_dn)
            logger.debug("pkidbuser entry already exists")
            return
        except errors.NotFound:
            pass

        # Encode certificate to DER format for LDAP storage
        cert_der = subsystem_cert.public_bytes(serialization.Encoding.DER)

        # Create pkidbuser entry
        # Following Dogtag's schema for this user
        entry = api.Backend.ldap2.make_entry(
            pkidbuser_dn,
            objectclass=[
                "top",
                "person",
                "organizationalPerson",
                "inetOrgPerson",
            ],
            uid=["pkidbuser"],
            sn=["pkidbuser"],
            cn=["pkidbuser"],
            userCertificate=[cert_der],
            description=[
                "CA database user - created by IPAThinCA for compatibility"
            ],
        )

        try:
            api.Backend.ldap2.add_entry(entry)
            logger.info(
                "Created pkidbuser LDAP entry with subsystem certificate for "
                "healthcheck"
            )
        except Exception as e:
            logger.warning(f"Failed to create pkidbuser entry: {e}")
            # Non-fatal - healthcheck will fail but CA continues to work

    def __generate_server_cert(self):
        """
        Generate server SSL certificate through ipathinca CA

        Note: Server certificate requires both NSSDB storage AND PEM files
        because gunicorn needs the private key to serve HTTPS. This is similar
        to the RA agent exception.
        """
        logger.debug(
            "Generating server SSL certificate through ipathinca CA "
            "(NSSDB + PEM file for gunicorn)"
        )

        from ipathinca.nss_utils import NSSDatabase

        server_cert_path = self.ipaca_certs_dir / "server.crt"
        server_key_path = Path(paths.IPATHINCA_DIR) / "private" / "server.key"
        server_nickname = "Server-Cert cert-pki-ca"

        # Initialize NSSDB access
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        # Skip if server certificate already exists in NSSDB
        if nssdb.cert_exists(server_nickname):
            logger.debug("Server SSL certificate already exists in NSSDB")
            return

        # Initialize ipathinca CA instance for certificate issuance
        ca = PythonCA(
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path),
            ca_id="ipa",
            random_serial_numbers=self.random_serial_numbers,
        )

        # Get certificate parameters from config
        key_size, signing_alg = self.__get_cert_params_from_config("sslserver")
        hash_alg = self.__convert_signing_algorithm(signing_alg)

        logger.debug(
            f"Generating server certificate (key_size={key_size}, "
            f"signing_alg={signing_alg})"
        )

        # Generate private key in memory (will be imported to NSSDB with cert)
        logger.debug(
            f"Generating server key pair for NSSDB: {server_nickname}"
        )
        private_key = nssdb.generate_key_pair(
            server_nickname, key_size=key_size
        )

        # Build subject for server certificate (CN=<fqdn>)
        subject = build_x509_name([("CN", self.fqdn)], reverse=True)

        # Create CSR with Subject Alternative Name
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject)

        # Add SAN extension to CSR (required for modern browsers)
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.fqdn)]),
            critical=False,
        )

        # Sign CSR with private key using configured hash algorithm
        csr = csr_builder.sign(
            private_key, hash_alg, backend=default_backend()
        )

        # Convert CSR to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # Submit certificate request through ipathinca CA
        # Use caIPAserviceCert profile (supports both server and client auth)
        profile = "caIPAserviceCert"
        request_id = ca.submit_certificate_request(csr_pem, profile)
        logger.debug(f"Submitted server certificate request {request_id}")

        # Sign the request to issue certificate
        serial_number = ca.sign_certificate_request(request_id)
        logger.debug(f"Issued server certificate with serial {serial_number}")

        # Retrieve the issued certificate
        cert_record = ca.get_certificate(serial_number)
        if not cert_record:
            raise RuntimeError("Failed to retrieve issued server certificate")

        # Import key and certificate to NSSDB
        logger.debug(
            f"Importing server key and certificate to NSSDB: {server_nickname}"
        )
        nssdb.import_key_and_cert(
            server_nickname,
            private_key,
            cert_record.certificate,
            trust_flags="u,u,u",
        )

        # Load CA certificate for creating chain file
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(
                f.read(), default_backend()
            )

        # Save server certificate with CA chain
        logger.debug(f"Writing server certificate to {server_cert_path}")
        with open(server_cert_path, "wb") as f:
            # Write server certificate
            f.write(
                cert_record.certificate.public_bytes(
                    serialization.Encoding.PEM
                )
            )
            # Append CA certificate for complete chain
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        server_cert_path.chmod(0o644)
        shutil.chown(server_cert_path, user="ipaca", group="ipaca")

        # Save server private key (required for gunicorn HTTPS)
        # This is an exception to the NSSDB-only policy, similar to RA agent
        logger.debug(f"Writing server private key to {server_key_path}")
        server_key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(server_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        server_key_path.chmod(0o600)
        shutil.chown(server_key_path, user="ipaca", group="ipaca")

        logger.debug(
            f"Server SSL certificate generated successfully (serial: "
            f"{serial_number})"
        )

    def __generate_ra_cert(self):
        """Generate RA agent certificate through ipathinca CA

        Uses the same issuance flow as subsystem certificates for consistency
        and automatic LDAP storage.
        """
        logger.debug("Generating RA agent certificate through ipathinca CA")

        ra_cert_path = Path(paths.RA_AGENT_PEM)
        ra_key_path = Path(paths.RA_AGENT_KEY)

        # Skip if RA certificate already exists
        if ra_cert_path.exists() and ra_key_path.exists():
            logger.debug("RA agent certificate already exists")
            return

        # Initialize ipathinca CA instance for certificate issuance
        ca = PythonCA(
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path),
            ca_id="ipa",
            random_serial_numbers=self.random_serial_numbers,
        )

        # Get certificate parameters from config (use sslserver settings for
        # RA cert)
        key_size, signing_alg = self.__get_cert_params_from_config("sslserver")
        hash_alg = self.__convert_signing_algorithm(signing_alg)

        logger.debug(
            f"Generating RA agent certificate (key_size={key_size}, "
            f"signing_alg={signing_alg})"
        )

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

        # Build subject for RA certificate
        # Simple DN: CN=IPA RA (matches what validator expects)
        ra_dn = DN(("CN", "IPA RA"))
        logger.debug(f"RA agent certificate subject: {ra_dn}")
        subject = ipa_dn_to_x509_name(str(ra_dn))

        # Create CSR
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject)

        # Sign CSR with private key using configured hash algorithm
        csr = csr_builder.sign(
            private_key, hash_alg, backend=default_backend()
        )

        # Convert CSR to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # Submit certificate request through ipathinca CA
        # Use caIPAserviceCert profile (same as ipa-ca-agent subsystem cert)
        profile = "caIPAserviceCert"
        request_id = ca.submit_certificate_request(csr_pem, profile)
        logger.debug(f"Submitted RA agent certificate request {request_id}")

        # Sign the request to issue certificate
        serial_number = ca.sign_certificate_request(request_id)
        logger.debug(
            f"Issued RA agent certificate with serial {serial_number}"
        )

        # Retrieve the issued certificate
        cert_record = ca.get_certificate(serial_number)
        if not cert_record:
            raise RuntimeError(
                "Failed to retrieve issued RA agent certificate"
            )

        # Ensure parent directories exist
        ra_cert_path.parent.mkdir(parents=True, exist_ok=True)
        ra_key_path.parent.mkdir(parents=True, exist_ok=True)

        # Save certificate to file
        logger.debug(f"Writing RA agent certificate to {ra_cert_path}")
        with open(ra_cert_path, "wb") as f:
            f.write(
                cert_record.certificate.public_bytes(
                    serialization.Encoding.PEM
                )
            )
        ra_cert_path.chmod(0o440)

        # Save private key to file
        logger.debug(f"Writing RA agent private key to {ra_key_path}")
        with open(ra_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        ra_key_path.chmod(0o440)

        # Set ownership to allow IPA API access
        group = IPAAPI_GROUP
        group.chgrp(ra_cert_path)
        group.chgrp(ra_key_path)

        # Import RA agent certificate to NSSDB for certmonger tracking
        # Note: RA agent cert is not typically in NSSDB in Dogtag, but we
        # import it for consistency and to enable certmonger tracking if
        # needed
        logger.debug("Importing RA agent certificate to NSSDB")
        self.__import_cert_to_nssdb(
            cert_pem_path=ra_cert_path,
            key_pem_path=ra_key_path,
            nickname="ipaCert",
            trust_flags="u,u,u",
        )

        logger.debug(
            f"RA agent certificate generated successfully (serial: "
            f"{serial_number})"
        )

    def __generate_kra_audit_cert(self, ca_key, ca_cert):
        """
        Generate KRA audit signing certificate in NSSDB (Dogtag-compatible)

        Dogtag KRA has a separate audit signing certificate distinct from the
        CA audit signing certificate. This generates the key in NSSDB and
        imports the certificate.

        Args:
            ca_key: CA private key for signing
            ca_cert: CA certificate (issuer)
        """
        logger.debug(
            "Generating KRA audit signing certificate "
            "(Dogtag-compatible NSSDB storage)"
        )

        from ipathinca.nss_utils import NSSDatabase

        # Certificate nickname in NSSDB
        kra_audit_nickname = "auditSigningCert cert-pki-kra"

        # Initialize NSSDB access
        nssdb = NSSDatabase(
            nssdb_dir=self.nssdb_dir,
            nssdb_password=self.nssdb_password,
        )

        # Check if already exists in NSSDB
        if nssdb.cert_exists(kra_audit_nickname):
            logger.debug("KRA audit certificate already exists in NSSDB")
            return

        # Get certificate parameters from config
        key_size, signing_alg = self.__get_cert_params_from_config(
            "audit_signing"
        )
        hash_alg = self.__convert_signing_algorithm(signing_alg)

        logger.debug(
            f"Generating KRA audit certificate (key_size={key_size}, "
            f"signing_alg={signing_alg})"
        )

        # Generate RSA key pair in memory (will be imported to NSSDB with cert)
        private_key = nssdb.generate_key_pair(
            kra_audit_nickname, key_size=key_size
        )

        # Create certificate subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.realm),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, "KRA Audit Signing Certificate"
                ),
            ]
        )

        # Build certificate (valid for 10 years like Dogtag)
        not_before = datetime.datetime.now(datetime.timezone.utc)
        not_after = not_before + datetime.timedelta(days=3650)

        # Use Dogtag-compatible audit signing key usage
        from ipathinca.x509_utils import get_audit_key_usage_extension

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                get_audit_key_usage_extension(),
                critical=True,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )

        # Sign with CA key using configured hash algorithm
        certificate = builder.sign(ca_key, hash_alg, default_backend())

        # Import key and certificate to NSSDB
        logger.debug(
            f"Importing KRA audit key and certificate to NSSDB: "
            f"{kra_audit_nickname}"
        )
        nssdb.import_key_and_cert(
            kra_audit_nickname,
            private_key,
            certificate,
            trust_flags="u,u,Pu",  # Trusted peer for audit signing
        )

        # Save certificate to file (for compatibility/reference)
        # Note: Private key is NOT saved to disk - it stays in NSSDB only
        kra_audit_dir = Path(paths.IPATHINCA_DIR) / "kra"
        kra_audit_cert_path = kra_audit_dir / "kra_audit.crt"

        with open(kra_audit_cert_path, "wb") as f:
            f.write(
                certificate.public_bytes(encoding=serialization.Encoding.PEM)
            )
        kra_audit_cert_path.chmod(0o644)
        shutil.chown(kra_audit_cert_path, user="ipaca", group="ipaca")

        logger.debug(
            "KRA audit signing certificate generated in NSSDB successfully"
        )

    def __verify_ra_key_custodia(self):
        """
        Verify that RA agent key is accessible via Custodia for replica
        installation

        This ensures that when replicas try to import the RA key via Custodia,
        the key files are properly readable and the Custodia handler can
        export them.
        """
        logger.debug("Verifying RA key accessibility for Custodia")

        ra_cert_path = paths.RA_AGENT_PEM
        ra_key_path = paths.RA_AGENT_KEY

        # Verify files exist and have correct permissions
        if not os.path.exists(ra_cert_path):
            raise RuntimeError(
                f"RA agent certificate not found: {ra_cert_path}"
            )
        if not os.path.exists(ra_key_path):
            raise RuntimeError(f"RA agent key not found: {ra_key_path}")

        # Check file permissions
        cert_stat = os.stat(ra_cert_path)
        key_stat = os.stat(ra_key_path)

        if (cert_stat.st_mode & 0o777) != 0o440:
            logger.warning(
                f"RA cert has unexpected permissions: "
                f"{oct(cert_stat.st_mode & 0o777)}, expected 0o440"
            )

        if (key_stat.st_mode & 0o777) != 0o440:
            logger.warning(
                f"RA key has unexpected permissions: "
                f"{oct(key_stat.st_mode & 0o777)}, expected 0o440"
            )

        # Check if Custodia handler script exists
        handler_script = (
            paths.LIBEXEC_IPA_DIR + "/custodia/ipa-custodia-ra-agent"
        )
        if not os.path.exists(handler_script):
            logger.warning(
                f"Custodia RA agent handler not found at {handler_script}. "
                "Skipping export verification. "
                "This is normal during development, but in production the "
                "handler should be installed. RA key files exist and have "
                "correct permissions."
            )
            logger.info(
                "To enable full Custodia verification, ensure FreeIPA is "
                "fully installed (make install) or the handler script is "
                "available."
            )
            return

        # Test that the Custodia RA agent handler can export the key
        # This simulates what happens when a replica requests the key
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                export_file = os.path.join(tmpdir, "export.json")

                # Run the Custodia RA agent export handler
                # This is the same command Custodia uses when serving the key
                result = subprocess.run(
                    [handler_script, "--export", export_file],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode != 0:
                    logger.error(f"RA key export test failed: {result.stderr}")
                    raise RuntimeError(
                        f"Failed to export RA key via Custodia handler. "
                        f"Replicas will not be able to import the RA key. "
                        f"Error: {result.stderr}"
                    )

                # Verify export file was created and contains data
                if not os.path.exists(export_file):
                    raise RuntimeError(
                        "RA key export completed but no export file was "
                        "created"
                    )

                with open(export_file, "r") as f:
                    export_data = json.load(f)

                    if "export password" not in export_data:
                        raise RuntimeError(
                            "RA key export data missing 'export password' "
                            "field"
                        )
                    if "pkcs12 data" not in export_data:
                        raise RuntimeError(
                            "RA key export data missing 'pkcs12 data' field"
                        )

                logger.debug(
                    "RA key export test successful - replicas will be able to "
                    "import the RA key via Custodia"
                )

                # Log important information for replica setup
                logger.debug(
                    "IMPORTANT: When installing replicas, ensure they are "
                    "configured to fetch the RA key from THIS master server "
                    f"({self.fqdn}). If replica installation fails with "
                    "'404 Not Found' when fetching ra/ipaCert, the replica "
                    "may be trying to fetch from the wrong server. As a "
                    "workaround, "
                    f"manually copy {ra_cert_path} and {ra_key_path} to the "
                    "replica before running ipa-replica-install."
                )

        except subprocess.TimeoutExpired:
            logger.error("RA key export test timed out")
            raise RuntimeError(
                "RA key export test timed out. Check if OpenSSL is available."
            )
        except Exception as e:
            logger.error(f"RA key export verification failed: {e}")
            raise RuntimeError(
                f"RA key is not accessible via Custodia. Replicas will not be "
                f"able to import the RA key. Error: {e}"
            )

    def __create_service_config(self):
        """
        Create service configuration files

        This creates the IPA CA configuration file which is read by the
        ipathinca WSGI application (ipathinca.wsgi:application) at startup.
        The configuration is loaded by wsgi.load_config() and passed to the
        Flask application for use by REST API endpoints.

        Uses three-layer configuration loading:
        1. ipaca_customize.ini (defaults from install/share/)
        2. Installer parameters (override defaults)
        3. pki_config_override (user overrides)
        """
        logger.debug("Creating service configuration files")

        # Load configuration using IPAthinCAConfigLoader
        # This merges ipaca_customize.ini + installer params + overrides
        loader = IPAthinCAConfigLoader(
            realm=self.realm,
            host=self.fqdn,
            basedn=api.env.basedn,
            subject_base=self.subject_base,
            ca_subject=self.ca_subject,
            ca_signing_algorithm=self.ca_signing_algorithm,
            random_serial_numbers=self.random_serial_numbers,
            pki_config_override=self.pki_config_override,
        )

        pki_config = loader.load_config()

        # Extract values from merged config for template substitution
        # All values come from PKI config hierarchy
        # (default.cfg → ipaca_*.ini → overrides)

        # Signing algorithms
        ca_signing_alg = pki_config.get(
            "CA", "pki_ca_signing_signing_algorithm", fallback="SHA256withRSA"
        )
        default_signing_alg = pki_config.get(
            "CA", "pki_ca_signing_signing_algorithm", fallback="SHA256withRSA"
        )
        crl_signing_alg = pki_config.get(
            "CA", "pki_ca_signing_signing_algorithm", fallback="SHA256withRSA"
        )
        audit_signing_alg = pki_config.get(
            "CA",
            "pki_audit_signing_signing_algorithm",
            fallback="SHA256withRSA",
        )
        ocsp_signing_alg = pki_config.get(
            "CA",
            "pki_ocsp_signing_signing_algorithm",
            fallback="SHA256withRSA",
        )

        # Key sizes
        default_rsa_key_size = pki_config.get(
            "CA", "pki_ca_signing_key_size", fallback="2048"
        )
        default_ecc_curve = pki_config.get(
            "DEFAULT", "pki_ecc_curve_default", fallback="nistp256"
        )
        ocsp_signing_key_size = pki_config.get(
            "CA", "pki_ocsp_signing_key_size", fallback="3072"
        )

        # Create ipathinca.conf from template
        # This file is read by ipathinca.wsgi:application on startup
        config_path = Path(paths.IPATHINCA_CONF)
        ipautil.copy_template_file(
            Path(paths.USR_SHARE_IPA_DIR) / "ipathinca.conf.template",
            config_path,
            dict(
                REALM=self.realm,
                DOMAIN=api.env.domain,
                FQDN=self.fqdn,
                BASEDN=api.env.basedn,
                IPA_CA_CRT=paths.IPA_CA_CRT,
                RANDOM_SERIAL_NUMBERS=str(self.random_serial_numbers).lower(),
                IPATHINCA_PID=paths.IPATHINCA_PID,
                IPATHINCA_CERTS_DIR=paths.IPATHINCA_CERTS_DIR,
                IPATHINCA_PRIVATE_DIR=paths.IPATHINCA_PRIVATE_DIR,
                IPATHINCA_LOG_DIR=paths.IPATHINCA_LOG_DIR,
                # Signing algorithms (from PKI config hierarchy)
                CA_SIGNING_ALGORITHM=ca_signing_alg,
                DEFAULT_SIGNING_ALGORITHM=default_signing_alg,
                CRL_SIGNING_ALGORITHM=crl_signing_alg,
                AUDIT_SIGNING_ALGORITHM=audit_signing_alg,
                OCSP_SIGNING_ALGORITHM=ocsp_signing_alg,
                # Key sizes (from PKI config hierarchy)
                DEFAULT_RSA_KEY_SIZE=default_rsa_key_size,
                DEFAULT_ECC_CURVE=default_ecc_curve,
                OCSP_SIGNING_KEY_SIZE=ocsp_signing_key_size,
            ),
        )
        config_path.chmod(0o644)

        # Store merged PKI config for use during installation
        self.pki_config = pki_config

        logger.debug(
            f"Service configuration created successfully at {config_path}"
        )

        # Load the config and initialize global ipathinca config
        # This allows all ipathinca modules to use get_config_value() during
        # installation
        config = load_config(str(config_path))
        set_global_config(config)
        self.config = config
        logger.debug("Initialized ipathinca global config for installation")

    def __install_systemd_service(self):
        """Install systemd service file"""
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

    def __configure_audit_logging(self):
        """
        Configure audit logging (Dogtag-compatible)

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

    def __install_renewal_scripts(self):
        """Install certmonger renewal helper scripts for NSSDB sync

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
                    f"Renewal script {script_name} already installed at "
                    f"{dest_script}"
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
                    f"Installing {script_name} from source tree to "
                    f"{dest_script}"
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
                        f"Could not set ownership on {dest_script}, "
                        "continuing..."
                    )

                logger.debug(f"Installed {script_name} successfully")
                installed_scripts.append(script_name)
            else:
                logger.warning(
                    f"Renewal script {script_name} not found at {dest_script}"
                    f" or {source_script}"
                )
                missing_scripts.append(script_name)

        if missing_scripts:
            logger.warning(
                f"Missing renewal scripts: {', '.join(missing_scripts)}. "
                "These scripts should be installed by 'make install'. "
                "Certificate renewal may not work correctly without them."
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

    def __configure_certmonger_renewal(self):
        """Configure certmonger renewal helpers for ipathinca"""
        # Configure renewal helpers first
        IPAThinCAInstance.configure_certmonger_renewal_helpers()

        # Configure NSSDB certificate tracking
        self.__configure_nssdb_tracking()

    def __configure_nssdb_tracking(self):
        """Configure certmonger tracking for NSSDB certificates"""
        logger.debug("Configuring certmonger tracking for NSSDB certificates")

        from ipalib.install import certmonger

        # First, clean up any existing tracking requests from previous
        # installation (e.g., from Dogtag migration)
        self.__cleanup_existing_tracking()

        # Start tracking each certificate in NSSDB
        for nickname, profile in CA_TRACKING_REQS.items():
            try:
                logger.debug(
                    f"Starting certmonger tracking for '{nickname}' with "
                    f"profile '{profile}'"
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

                logger.debug(f"Started tracking '{nickname}' successfully")

            except Exception as e:
                # Don't fail installation if tracking setup fails
                # Certificates can be tracked manually later
                logger.warning(
                    f"Failed to start certmonger tracking for '{nickname}': "
                    f"{e}"
                )

        logger.debug("Certmonger tracking configuration completed")

    def __cleanup_existing_tracking(self):
        """
        Clean up existing certmonger tracking requests

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
                        logger.info(
                            f"Removing existing certmonger tracking request: "
                            f"{current_request_id}"
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
                                "Stopped tracking request "
                                f"{current_request_id}"
                            )
                        except Exception as e:
                            logger.warning(
                                "Failed to stop tracking request "
                                f"{current_request_id}: {e}"
                            )
                        current_request_id = None

        except Exception as e:
            logger.warning(f"Failed to cleanup existing tracking: {e}")

        logger.debug("Cleanup of existing tracking requests completed")

    def __stop_certmonger_tracking(self):
        """
        Stop all certmonger tracking for ipathinca certificates

        Called during uninstall to clean up certmonger tracking requests
        """
        logger.debug("Stopping certmonger tracking for ipathinca certificates")

        # Set nssdb_dir if not already set (during uninstall)
        if not hasattr(self, "nssdb_dir"):
            self.nssdb_dir = Path(paths.PKI_TOMCAT_ALIAS_DIR)

        # Use the same cleanup method used during installation
        # This will stop all tracking requests for our NSSDB location
        try:
            self.__cleanup_existing_tracking()
            logger.debug("Stopped all certmonger tracking for ipathinca")
        except Exception as e:
            logger.warning(f"Failed to stop certmonger tracking: {e}")

    def __http_proxy(self):
        """Configure Apache HTTP proxy for ipathinca"""
        logger.debug("Configuring Apache HTTP proxy for ipathinca")

        # Create combined PEM file with RA agent cert and key for Apache proxy
        # Apache needs this to present a client cert when connecting to
        # ipathinca
        proxy_cert_dir = "/etc/httpd/alias"
        proxy_cert_file = os.path.join(proxy_cert_dir, "ipa-proxy.pem")

        # Ensure directory exists
        os.makedirs(proxy_cert_dir, mode=0o755, exist_ok=True)

        logger.debug(
            f"Creating combined proxy certificate file: {proxy_cert_file}"
        )

        with open(proxy_cert_file, "w") as f:
            # Write RA agent certificate
            with open(paths.RA_AGENT_PEM, "r") as cert_f:
                f.write(cert_f.read())
            # Write RA agent private key
            with open(paths.RA_AGENT_KEY, "r") as key_f:
                f.write(key_f.read())

        # Set restrictive permissions (readable only by Apache)
        os.chmod(proxy_cert_file, 0o600)
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

    def __start_service(self):
        """Start ipathinca service and wait for it to be ready"""
        logger.debug("Starting ipa-ca service")

        try:
            ipautil.run(["systemctl", "start", "ipathinca.service"])
            logger.debug("ipathinca service started successfully")

            # Wait for REST API to be ready (similar to Dogtag)
            self.__wait_for_ca_ready()
        except Exception as e:
            logger.error(f"Failed to start ipathinca service: {e}")
            raise

    def __wait_for_ca_ready(self):
        """Wait for CA REST API to be ready to accept requests"""
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
                logger.debug(f"CA not ready yet: {e}")

            time.sleep(wait_interval)
            elapsed += wait_interval

        logger.warning(f"CA did not become ready within {max_wait} seconds")
        # Don't raise an error - let the installation continue and fail
        # later if the CA is truly not working

    def __generate_initial_crl(self):
        """
        Generate initial Certificate Revocation List

        This creates the CRL and publishes it to /var/lib/ipa/pki-ca/publish/
        so it can be served by Apache at /ipa/crl/MasterCRL.bin

        During installation, we call the backend directly to avoid
        authentication complexity. After installation, normal CRL updates
        go through the REST API with RA agent authentication.
        """
        logger.debug("Generating initial CRL")

        try:
            # Import backend to call CRL generation directly
            from ipathinca.backend import get_python_ca_backend

            # Get CA backend instance
            backend = get_python_ca_backend()

            # Generate and publish CRL
            # This updates /var/lib/ipa/pki-ca/publish/MasterCRL.bin
            result = backend.update_crl()

            logger.debug(
                f"Initial CRL generated successfully: {result['status']}"
            )

            # Verify the published CRL exists
            publish_path = os.path.join(
                paths.IPA_PKI_PUBLISH_DIR, "MasterCRL.bin"
            )
            if os.path.exists(publish_path):
                logger.debug(f"CRL published to {publish_path}")
            else:
                logger.warning(
                    f"CRL generation succeeded but file not found at "
                    f"{publish_path}"
                )

        except Exception as e:
            logger.warning(f"Failed to generate initial CRL: {e}")
            # Don't fail installation if CRL generation fails
            # CRL will be generated on first revocation or manual update

    def uninstall(self):
        """Uninstall ipathinca instance"""
        if self.is_installed():
            self.print_msg("Unconfiguring %s" % self.subsystem)

        logger.debug("Uninstalling ipathinca Python CA instance")

        # Stop certmonger tracking for all ipathinca certificates
        self.__stop_certmonger_tracking()

        # Disable service first to prevent automatic restart
        try:
            ipautil.run(["systemctl", "disable", "ipathinca.service"])
            logger.debug("ipathinca service disabled")
        except Exception as e:
            logger.debug(f"Failed to disable ipathinca service: {e}")

        # Stop service
        try:
            ipautil.run(["systemctl", "stop", "ipathinca.service"])
            logger.debug("ipathinca service stopped")
        except Exception as e:
            logger.debug(f"Failed to stop ipathinca service: {e}")

        # Mask the service to prevent any activation
        try:
            ipautil.run(["systemctl", "mask", "ipathinca.service"])
            logger.debug("ipathinca service masked")
        except Exception as e:
            logger.debug(f"Failed to mask ipathinca service: {e}")

        # Remove service file
        service_path = Path("/etc/systemd/system/ipathinca.service")
        if service_path.exists():
            service_path.unlink()
            logger.debug("ipathinca service file removed")

        # Unmask after removing service file
        try:
            ipautil.run(["systemctl", "unmask", "ipathinca.service"])
            logger.debug("ipathinca service unmasked")
        except Exception as e:
            logger.debug(f"Failed to unmask ipathinca service: {e}")

        # Reload systemd
        try:
            ipautil.run(["systemctl", "daemon-reload"])
            logger.debug("systemd reloaded")
        except Exception as e:
            logger.debug(f"Failed to reload systemd: {e}")

        # Reset any failed state
        try:
            ipautil.run(["systemctl", "reset-failed", "ipathinca.service"])
            logger.debug("ipathinca service state reset")
        except Exception as e:
            logger.debug(f"Failed to reset ipathinca service: {e}")

        # Remove configuration
        config_path = Path(paths.IPATHINCA_CONF)
        if config_path.exists():
            config_path.unlink()
            logger.debug("ipathinca configuration removed")

        # Clean up ipathinca directories
        # Remove /var/lib/ipa/ipathinca directory tree
        if self.ipaca_dir.exists():
            try:
                shutil.rmtree(self.ipaca_dir)
                logger.debug(f"Removed {self.ipaca_dir}")
            except Exception as e:
                logger.warning(f"Failed to remove {self.ipaca_dir}: {e}")

        # Remove audit logs
        if self.audit_log_dir.exists():
            try:
                shutil.rmtree(self.audit_log_dir)
                logger.debug(f"Removed {self.audit_log_dir}")
            except Exception as e:
                logger.warning(f"Failed to remove {self.audit_log_dir}: {e}")

        # Note: We don't remove LDAP data (cn=ca,{basedn}) for safety and
        # audit reasons
        # This allows re-installation to preserve certificate history

        logger.debug("ipathinca uninstalled successfully")

    def enable_and_start(self):
        """
        Enable and register CA service in LDAP (called from install_step_1)

        This is called AFTER PKINIT is configured to ensure that during
        initial installation, PKINIT uses dogtag-submit to contact the CA
        directly instead of going through the IPA framework.
        """
        logger.debug("Registering CA service in LDAP")
        self.__register_ca_service()
        logger.debug("CA service registered successfully")

    def start(self):
        """Start ipathinca service"""
        services.knownservices["ipathinca"].start()

    def stop(self):
        """Stop ipathinca service"""
        services.knownservices["ipathinca"].stop()

    def restart(self):
        """Restart ipathinca service"""
        services.knownservices["ipathinca"].restart()

    def is_running(self):
        """Check if ipathinca service is running"""
        try:
            return services.knownservices["ipathinca"].is_running()
        except Exception:
            return False

    def enable_kra(self):
        """
        Enable KRA functionality in ipathinca

        This initializes the KRA (Key Recovery Authority) subsystem,
        generating transport and storage keys. Similar to how Dogtag
        handles KRA as a subsystem within pki-tomcat, ipathinca handles
        KRA as functionality within the ipathinca service.
        """
        logger.info("Enabling KRA in ipathinca")

        # Load NSSDB paths and password if not already set
        # (needed when enable_kra is called separately from create_instance)
        self._load_nssdb_password()

        # Create KRA directory
        kra_dir = Path(paths.IPATHINCA_DIR) / "kra"
        kra_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        try:
            shutil.chown(kra_dir, user="ipaca", group="ipaca")
        except Exception as e:
            logger.warning(f"Could not set ownership on {kra_dir}: {e}")

        # Get storage backend for LDAP access and HSM support
        storage_backend = get_storage_backend(ca_id="kra")

        # Initialize KRA with storage backend (enables HSM support)
        kra = KRA(storage_backend=storage_backend, kra_id="kra")

        # Load CA certificate and extract CA key from NSSDB
        # (Dogtag-compatible: keys are in NSSDB, not PEM files)
        from ipathinca.nss_utils import NSSDatabase

        # Load CA certificate from file
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(
                f.read(), default_backend()
            )

        # Extract CA private key from NSSDB
        nssdb = NSSDatabase()
        ca_nickname = "caSigningCert cert-pki-ca"
        logger.debug(f"Extracting CA private key from NSSDB: {ca_nickname}")
        ca_key = nssdb.extract_private_key(ca_nickname)

        # Initialize KRA LDAP schema (creates o=kra,o=ipaca containers)
        kra_storage = KRAStorageBackend()
        kra_storage.init_schema()

        # Initialize KRA (generates/loads transport and storage keys)
        # KRA keys are generated directly in NSSDB (Dogtag-compatible)
        # No PEM file import needed - keys are already in NSSDB
        kra.initialize(ca_key, ca_cert, storage_backend)

        logger.debug(
            "KRA transport and storage certificates already in NSSDB "
            "(generated by kra.initialize)"
        )

        # Generate and import KRA audit signing certificate
        self.__generate_kra_audit_cert(ca_key, ca_cert)

        # Create vault container structure in LDAP (same as Dogtag KRA)
        # This creates cn=kra,{basedn} and cn=vaults,cn=kra,{basedn}
        self._add_vault_container()

        # Register KRA service in LDAP (required for kra_is_enabled checks)
        self._register_kra_service()

        logger.info("KRA enabled successfully in ipathinca")
        logger.info("KRA REST API endpoints are now available")

    def _add_vault_container(self):
        """Create vault container structure in LDAP (same as Dogtag KRA)"""
        logger.debug("Creating vault container structure in LDAP")
        self._ldap_mod(
            "vault.ldif", {"SUFFIX": api.env.basedn}, raise_on_err=True
        )
        logger.debug("Vault container structure created successfully")

    def _register_kra_service(self):
        """Register KRA service in LDAP masters container"""
        logger.debug("Registering KRA service in LDAP")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        ldap = api.Backend.ldap2

        # Create KRA service entry:
        # cn=KRA,cn={fqdn},cn=masters,cn=ipa,cn=etc,{basedn}
        service_dn = DN(
            ("cn", "KRA"),
            ("cn", self.fqdn),
            ("cn", "masters"),
            ("cn", "ipa"),
            ("cn", "etc"),
            api.env.basedn,
        )

        try:
            # Check if entry already exists
            ldap.get_entry(service_dn)
            logger.debug(f"KRA service entry already exists: {service_dn}")
        except errors.NotFound:
            logger.debug(f"Creating KRA service entry: {service_dn}")

            # Create the entry with proper object classes
            entry = ldap.make_entry(
                service_dn,
                objectClass=["nsContainer", "ipaConfigObject"],
                cn=["KRA"],
                ipaConfigString=["enabledService", "startOrder 51"],
            )
            ldap.add_entry(entry)
            logger.debug("KRA service entry created successfully")

    def setup_acme(self):
        """
        Set up ACME service with LDAP storage backend

        This method:
        1. Installs ACME LDAP schema from PKI
        2. Creates ACME container structure in LDAP (ou=acme,o=ipaca)
        3. Creates ACME configuration entry (disabled by default)
        """
        logger.info("Setting up ACME service with LDAP storage")

        # Install ACME LDAP schema from pki-acme package
        logger.debug("Installing ACME LDAP schema from PKI")
        self._ldap_mod("/usr/share/pki/acme/database/ds/schema.ldif")
        logger.debug("ACME LDAP schema installed successfully")

        # Initialize ACME LDAP schema (creates ou=acme,o=ipaca containers)
        acme_storage = ACMEStorageBackend(self.config)
        acme_storage.init_schema()
        logger.debug("ACME LDAP container structure created successfully")

        # Create ACME configuration entry (disabled by default)
        self._create_acme_config()

        logger.info("ACME service setup completed successfully")

    def _create_acme_config(self):
        """Create ACME configuration entry (disabled by default)"""
        logger.debug("Creating ACME configuration entry")

        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        ldap = api.Backend.ldap2

        # Configuration entry DN
        config_dn = DN(("ou", "config"), ("ou", "acme"), ("o", "ipaca"))

        try:
            # Check if configuration already exists
            entry = ldap.get_entry(config_dn)
            logger.debug("ACME configuration entry already exists")

            # Ensure acmeEnabled attribute is set
            if "acmeEnabled" not in entry:
                entry["acmeEnabled"] = ["FALSE"]
                ldap.update_entry(entry)
                logger.debug("Added acmeEnabled=FALSE to existing config")
        except errors.NotFound:
            # Create configuration entry with extensibleObject to allow
            # custom attributes
            logger.debug(f"Creating ACME configuration entry at {config_dn}")
            entry = ldap.make_entry(
                config_dn,
                objectClass=["top", "organizationalUnit", "extensibleObject"],
                ou=["config"],
                acmeEnabled=["FALSE"],
            )
            ldap.add_entry(entry)
            logger.debug(
                "ACME configuration entry created (disabled by default)"
            )

        logger.debug("ACME configuration completed")
