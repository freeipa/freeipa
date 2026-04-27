# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Installation module for ipathinca Python CA backend.

``IPAThinCAInstance`` is an IPA ``service.Service`` subclass that drives the
installation and lifecycle of the ipathinca CA.  It uses composition with
focused helper classes provided by the ``ipathinca.install`` package:

- ``ServiceMgmt``  — directories, systemd, certmonger, Apache proxy
- ``Certs``        — CA / subsystem / server / RA certificate generation
- ``LDAPSetup``    — LDAP schema, storage init, profile and ACL import
- ``Replication``  — clone / replica replication setup
- ``KRAInstall``   — KRA subsystem (enable_kra, vault, service entry)
- ``ACME``         — ACME LDAP schema and configuration
- ``LWCA``         — Lightweight CA key retrieval infrastructure
- ``NSSDB``        — NSS database creation and certificate import

``_PKIConfigBuilder`` (private to this module) implements the six-layer
PKI configuration loading that matches Dogtag's ``PKIIniLoader`` and
translates PKI key names into the ipathinca-native values stored in
``IPAthinCAConfig``.
"""

from __future__ import absolute_import

import configparser
import logging
import os
import pwd
import re
from pathlib import Path

import dbus

from ipalib import api, errors
from ipalib.constants import (
    CA_DBUS_TIMEOUT,
    PKI_GSSAPI_SERVICE_NAME,
    RENEWAL_CA_NAME,
)
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.dn import DN
from ipaserver.install import service
from ipaserver.install.cainstance import lookup_ldap_backend
from ipathinca import load_config, set_global_config, get_global_config
from ipathinca.config import IPAthinCAConfig
from ipathinca.storage_factory import get_storage_backend
from ipathinca.install import (
    ACME,
    Certs,
    KRAInstall,
    LDAPSetup,
    LWCA,
    NSSDB,
    Replication,
    ServiceMgmt,
)

logger = logging.getLogger(__name__)

__all__ = ["IPAThinCAInstance"]


# ---------------------------------------------------------------------------
# PKI configuration builder
#
# Contains all PKI-specific knowledge (pki_* key names, ini file paths,
# immutability rules) so that ipathinca/config.py stays free of those
# details.  The build() classmethod returns a merged ConfigParser; the
# extract_ipathinca_params() classmethod translates the PKI key names into
# the ipathinca-native names accepted by IPAthinCAConfig.from_install_params().
# ---------------------------------------------------------------------------


class _PKIConfigBuilder:
    """Build Dogtag-style four-layer PKI configuration."""

    _pki_default = "/usr/share/pki/server/etc/default.cfg"
    _ipaca_default = os.path.join(paths.USR_SHARE_IPA_DIR, "ipaca_default.ini")
    _ipaca_customize = os.path.join(
        paths.USR_SHARE_IPA_DIR, "ipaca_customize.ini"
    )
    _ipaca_softhsm2 = os.path.join(
        paths.USR_SHARE_IPA_DIR, "ipaca_softhsm2.ini"
    )

    # Maps (pki_section, pki_key) → (ipathinca_param_name, default_value).
    # Only the keys that ipathinca actually reads are listed here.
    _PKI_TO_IPATHINCA = {
        ("CA", "pki_ca_signing_signing_algorithm"): (
            "ca_signing_algorithm",
            "SHA256withRSA",
        ),
        ("CA", "pki_ca_signing_key_size"): (
            "ca_signing_key_size",
            "3072",
        ),
        ("CA", "pki_ocsp_signing_signing_algorithm"): (
            "ocsp_signing_algorithm",
            "SHA256withRSA",
        ),
        ("CA", "pki_ocsp_signing_key_size"): (
            "ocsp_signing_key_size",
            "3072",
        ),
        ("CA", "pki_audit_signing_signing_algorithm"): (
            "audit_signing_algorithm",
            "SHA256withRSA",
        ),
        ("DEFAULT", "pki_ecc_curve_default"): (
            "ecc_curve",
            "nistp256",
        ),
    }

    # Immutable keys (loaded lazily from ipaca_default.ini + code)
    _immutable_keys_cache = None
    _immutable_code_keys = frozenset(
        {
            ("global", "realm"),
            ("global", "host"),
            ("global", "basedn"),
        }
    )

    @classmethod
    def build(
        cls,
        realm,
        host,
        subject_base,
        ca_subject,
        ca_signing_algorithm,
        random_serial_numbers,
        pki_config_override,
        token_name,
    ):
        """Build the merged PKI ConfigParser (layers 0-5).

        Layers (later overrides earlier):
        0. PKI default.cfg
        1. ipaca_default.ini (IPA immutable baseline)
        2. Installer parameters
        3. ipaca_customize.ini (IPA customisable defaults)
        4. ipaca_softhsm2.ini (if using HSM)
        5. pki_config_override (user custom overrides)

        Returns:
            configparser.ConfigParser with merged configuration.
        """
        domain = realm.lower()
        defaults = {}

        defaults["pki_dns_domainname"] = domain
        defaults["pki_hostname"] = host
        defaults["pki_subsystem"] = "CA"
        defaults["pki_subsystem_type"] = "ca"
        defaults["home_dir"] = os.path.expanduser("~")

        defaults["ipa_ca_pem_file"] = paths.IPA_CA_CRT
        defaults["ipa_subject_base"] = (
            str(subject_base) if subject_base else ""
        )
        defaults["ipa_ca_subject"] = str(ca_subject) if ca_subject else ""
        defaults["ipa_fqdn"] = host
        defaults["pki_configuration_path"] = paths.PKI_CONFIGURATION

        from ipalib.constants import IPA_CA_RECORD

        defaults["ipa_ocsp_uri"] = f"http://{IPA_CA_RECORD}.{domain}/ca/ocsp"

        defaults["ipa_admin_cert_p12"] = paths.DOGTAG_ADMIN_P12
        defaults["ipa_admin_user"] = "admin"
        defaults["pki_admin_password"] = ""
        defaults["pki_ds_password"] = ""
        defaults["softhsm2_so"] = paths.LIBSOFTHSM2_SO

        from ipaplatform.tasks import tasks

        defaults["fips_use_oaep_rsa_keywrap"] = str(
            tasks.is_fips_enabled()
        ).lower()
        defaults["ipa_ajp_secret"] = ipautil.ipa_generate_password(
            special=None
        )

        if ca_signing_algorithm is not None:
            alg_str = (
                ca_signing_algorithm.value
                if hasattr(ca_signing_algorithm, "value")
                else str(ca_signing_algorithm)
            )
            defaults["ipa_signing_algorithm"] = alg_str

        config = configparser.ConfigParser(defaults=defaults)
        config.optionxform = str  # Preserve case

        # Seed with service defaults so the keys are always present even
        # when the PKI ini files are absent.  Files loaded below may
        # override these values.
        for (section, key), (
            _,
            default_value,
        ) in cls._PKI_TO_IPATHINCA.items():
            if section == "DEFAULT":
                config.defaults()[key] = default_value
            else:
                if not config.has_section(section):
                    config.add_section(section)
                config.set(section, key, default_value)

        # Layer 0: PKI default.cfg
        if os.path.exists(cls._pki_default):
            with open(cls._pki_default) as f:
                config.read_file(f)
        else:
            logger.warning("PKI default.cfg not found: %s", cls._pki_default)

        # Layer 1: ipaca_default.ini (IPA immutable baseline)
        if os.path.exists(cls._ipaca_default):
            with open(cls._ipaca_default) as f:
                config.read_file(f)
        else:
            logger.warning(
                "ipaca_default.ini not found: %s", cls._ipaca_default
            )
            cls._create_minimal_baseline(config)

        # Layer 2: installer parameters
        if not config.has_section("CA"):
            config.add_section("CA")
        config.set(
            "CA", "random_serial_numbers", str(random_serial_numbers).lower()
        )

        immutable_snapshot = cls._snapshot_immutable(config)

        # Layer 3: ipaca_customize.ini
        if os.path.exists(cls._ipaca_customize):
            with open(cls._ipaca_customize) as f:
                config.read_file(f)
            cls._verify_immutable(
                config, immutable_snapshot, cls._ipaca_customize
            )
        else:
            logger.warning(
                "ipaca_customize.ini not found: %s", cls._ipaca_customize
            )

        # Layer 4: ipaca_softhsm2.ini (if using HSM)
        if token_name:
            if os.path.exists(cls._ipaca_softhsm2):
                with open(cls._ipaca_softhsm2) as f:
                    config.read_file(f)
                cls._verify_immutable(
                    config, immutable_snapshot, cls._ipaca_softhsm2
                )
            else:
                logger.warning(
                    "ipaca_softhsm2.ini not found: %s", cls._ipaca_softhsm2
                )

        # Layer 5: user overrides
        if pki_config_override:
            with open(pki_config_override) as f:
                config.read_file(f)
            cls._verify_immutable(
                config, immutable_snapshot, pki_config_override
            )

        return config

    @classmethod
    def extract_ipathinca_params(cls, pki_config):
        """Translate PKI config values to ipathinca-native param names.

        Args:
            pki_config: ConfigParser returned by :meth:`build`.

        Returns:
            dict suitable for ``**kwargs`` in
            ``IPAthinCAConfig.from_install_params()``.
        """
        result = {}
        for (section, pki_key), (
            ipathinca_name,
            default,
        ) in cls._PKI_TO_IPATHINCA.items():
            result[ipathinca_name] = pki_config.get(
                section, pki_key, fallback=default
            )
        return result

    # -- immutability helpers ------------------------------------------------

    @classmethod
    def _get_immutable_keys(cls):
        if cls._immutable_keys_cache is None:
            immutable = set(cls._immutable_code_keys)
            if os.path.exists(cls._ipaca_default):
                cfg = configparser.RawConfigParser()
                with open(cls._ipaca_default) as f:
                    cfg.read_file(f)
                for section in cfg.sections():
                    for k, _v in cfg.items(section, raw=True):
                        immutable.add((section, k))
            cls._immutable_keys_cache = frozenset(immutable)
        return cls._immutable_keys_cache

    @classmethod
    def _create_minimal_baseline(cls, config):
        for section in ["CA", "global", "ldap", "server"]:
            if not config.has_section(section):
                config.add_section(section)

    @classmethod
    def _snapshot_immutable(cls, config):
        snapshot = {}
        for section, key in cls._get_immutable_keys():
            if section == "*" or key == "*":
                continue
            if config.has_section(section) and config.has_option(section, key):
                snapshot[(section, key)] = config.get(section, key)
        logger.debug("Immutable settings snapshot: %d settings", len(snapshot))
        return snapshot

    @classmethod
    def _verify_immutable(cls, config, snapshot, filename):
        errors = []
        for (section, key), expected in snapshot.items():
            if not config.has_section(section):
                errors.append(f"[{section}] {key}: section removed")
                continue
            if not config.has_option(section, key):
                errors.append(f"[{section}] {key}: key removed")
                continue
            actual = config.get(section, key)
            if actual != expected:
                errors.append(f"[{section}] {key}: '{actual}' != '{expected}'")
        if errors:
            raise ValueError(
                f"{filename} attempts to override immutable settings:\n"
                + "\n".join(errors)
            )


class IPAThinCAInstance(service.Service):
    """Installation and configuration module for ipathinca Python CA backend.

    Uses composition with helper classes from ``ipathinca.install``.
    The public API matches ``DogtagCAInstance`` so that the rest of IPA
    can treat the two interchangeably.
    """

    # Certificate tracking requests (for healthcheck compatibility)
    tracking_reqs = dict()

    @staticmethod
    def configure_certmonger_renewal_helpers():
        """Configure certmonger renewal helpers for ipathinca HTTPS.

        This is a static method that can be called early in the installation
        process, before any certificate requests are made.
        """
        _logger = logging.getLogger(__name__)
        _logger.debug("Configuring certmonger helpers for ipathinca HTTPS")

        # Start certmonger and dbus if needed
        cmonger = services.knownservices.certmonger
        cmonger.enable()
        if not services.knownservices.dbus.is_running():
            services.knownservices.dbus.start()
        cmonger.start()

        # Use the standard FreeIPA dogtag-ipa-ca-renew-agent-submit script
        helper_script = Path(paths.DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT)

        # Register the certmonger CA helpers
        bus = dbus.SystemBus()
        obj = bus.get_object(
            "org.fedorahosted.certmonger", "/org/fedorahosted/certmonger"
        )
        iface = dbus.Interface(obj, "org.fedorahosted.certmonger")

        for suffix, args in [
            ("", ""),
            ("-reuse", " --force-new-key"),
            ("-selfsigned", " --force-self-signed"),
        ]:
            name = RENEWAL_CA_NAME + suffix
            path = iface.find_ca_by_nickname(name)
            if not path:
                command = str(helper_script) + args
                _logger.debug(f"Registering certmonger CA helper: {name}")
                iface.add_known_ca(
                    name,
                    command,
                    dbus.Array([], dbus.Signature("s")),
                    timeout=CA_DBUS_TIMEOUT,
                )

        _logger.debug("Certmonger renewal helpers configured")

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
        token_name=None,
        token_library_path=None,
        token_password=None,
        pkcs12_info=None,
        master_host=None,
        promote=False,
    ):
        super().__init__(
            "ipathinca",
            service_desc="IPA Python CA",
            realm_name=realm,
            service_user="ipaca",
        )

        self.subsystem = "ipathinca"
        self.realm = realm
        self.fqdn = host_name
        self.basedn = api.env.basedn
        self.domain = api.env.domain
        self.ldap = api.Backend.ldap2
        self.admin_password = None
        self.subject_base = subject_base
        self.ca_subject = ca_subject

        # Resolve subject DN defaults and validate early so
        # mixin methods can use self.subject_base /
        # self.ca_subject without ipaserver imports.
        if self.realm:
            from ipaserver.install import installutils
            from ipaserver.install.ca import (
                subject_validator,
                VALID_SUBJECT_BASE_ATTRS,
                VALID_SUBJECT_ATTRS,
            )

            if self.subject_base is None:
                self.subject_base = installutils.default_subject_base(
                    self.realm
                )
            if self.ca_subject is None:
                self.ca_subject = installutils.default_ca_subject_dn(
                    self.subject_base
                )
            subject_validator(VALID_SUBJECT_BASE_ATTRS, str(self.subject_base))
            subject_validator(VALID_SUBJECT_ATTRS, str(self.ca_subject))

        self.random_serial_numbers = random_serial_numbers
        self.ca_signing_algorithm = ca_signing_algorithm
        self.pki_config_override = pki_config_override

        # Build PKI config hierarchy and derive ipathinca-native config
        # from it.  self.pki_config holds the full merged ConfigParser for
        # install steps that still need raw PKI values; self.config holds
        # the translated IPAthinCAConfig used by everything else.
        # Both realm and host_name are required — callers that only pass
        # realm (e.g. topology/status queries) skip the PKI build entirely.
        if self.realm and host_name:
            self.pki_config = _PKIConfigBuilder.build(
                realm=realm,
                host=host_name,
                subject_base=self.subject_base,
                ca_subject=self.ca_subject,
                ca_signing_algorithm=ca_signing_algorithm,
                random_serial_numbers=random_serial_numbers,
                pki_config_override=pki_config_override,
                token_name=token_name,
            )
            self.config = IPAthinCAConfig.from_install_params(
                realm=realm,
                host=host_name,
                basedn=api.env.basedn,
                random_serial_numbers=random_serial_numbers,
                **_PKIConfigBuilder.extract_ipathinca_params(self.pki_config),
            )
        else:
            self.pki_config = None
            self.config = None

        # External CA support (two-step installation)
        if external_ca or csr_file:
            self.external_ca_step = 1
        elif cert_file and cert_chain_file:
            self.external_ca_step = 2
        else:
            self.external_ca_step = 0

        from ipalib import x509 as ipalib_x509

        self.external_ca_type = (
            external_ca_type or ipalib_x509.ExternalCAType.GENERIC.value
        )
        self.external_ca_profile = external_ca_profile
        self.csr_file = csr_file or paths.ROOT_IPA_CSR
        self.cert_file = cert_file
        self.cert_chain_file = cert_chain_file

        # HSM support
        self.tokenname = token_name
        self.token_library_path = token_library_path
        self.token_password = token_password

        if self.tokenname:
            from ipaserver.install.ca import hsm_validator

            hsm_validator(
                self.tokenname, self.token_library_path, self.token_password
            )
            logger.debug(
                f"HSM configuration validated: token={self.tokenname}"
            )

        # Clone / replica / promote state
        self.pkcs12_info = pkcs12_info
        self.master_host = master_host
        self.clone = bool(pkcs12_info)
        self.no_db_setup = promote

        # Paths
        self.ipaca_dir = Path(paths.IPATHINCA_DIR)
        self.ipaca_private_dir = Path(paths.IPATHINCA_PRIVATE_DIR)
        self.ipaca_certs_dir = Path(paths.IPATHINCA_CERTS_DIR)
        self.ipaca_ca_dir = Path(paths.IPATHINCA_CA_DIR)
        self.ipaca_audit_dir = Path(paths.IPATHINCA_AUDIT_DIR)
        self.ipaca_logs_dir = Path(paths.IPATHINCA_LOG_DIR)

        self.ca_cert_path = Path(paths.IPA_CA_CRT)
        self.ca_key_path = Path(paths.IPATHINCA_SIGNING_KEY)
        self.ca_cert_working = self.ipaca_certs_dir / "ca.crt"

        self.audit_log_dir = Path(paths.IPATHINCA_LOG_DIR)

        # ---------------------------------------------------------------
        # Composition helpers
        # ---------------------------------------------------------------
        self._nssdb = NSSDB()
        self._repl = Replication(self.basedn, self._ldap_mod)

        if self.realm and host_name:
            self._svc = ServiceMgmt(
                self.config,
                self.fqdn,
                self.clone,
                self._nssdb,
                self.configure_certmonger_renewal_helpers,
            )
            self._ldap_setup = LDAPSetup(
                self.ldap,
                self.config,
                self.realm,
                self.basedn,
                self.clone,
                self.fqdn,
            )
            self._certs = Certs(
                ldap=self.ldap,
                config=self.config,
                pki_config=self.pki_config,
                nssdb=self._nssdb,
                subject_base=self.subject_base,
                ca_subject=self.ca_subject,
                realm=self.realm,
                fqdn=self.fqdn,
                basedn=self.basedn,
                random_serial_numbers=self.random_serial_numbers,
                ca_signing_algorithm=self.ca_signing_algorithm,
                external_ca_step=self.external_ca_step,
                external_ca_type=self.external_ca_type,
                external_ca_profile=self.external_ca_profile,
                csr_file=self.csr_file,
                cert_file=self.cert_file,
                cert_chain_file=self.cert_chain_file,
                tokenname=self.tokenname,
                token_library_path=self.token_library_path,
                token_password=self.token_password,
                load_external_cert_fn=self._load_external_cert,
            )
            self._kra = KRAInstall(
                self.ldap,
                self._nssdb,
                self.ca_cert_path,
                self.realm,
                self.basedn,
                self.fqdn,
                self.pki_config,
                self._ldap_mod,
            )
            self._acme = ACME(self.ldap, self.config, self._ldap_mod)
            self._lwca = LWCA(self.ldap, self.basedn)
        else:
            self._svc = None
            self._ldap_setup = None
            self._certs = None
            self._kra = None
            self._acme = None
            self._lwca = None

    # -----------------------------------------------------------------------
    # Status queries
    # -----------------------------------------------------------------------

    def is_installed(self):
        return self.service.is_installed()

    def is_configured(self):
        config_path = Path(paths.IPATHINCA_CONF)
        return config_path.exists()

    def is_crlgen_enabled(self):
        """Check if CRL generation is enabled.

        For ipathinca, CRL generation is always enabled on the local instance.
        """
        return self.is_installed()

    def is_renewal_master(self, fqdn=None):
        """Check if this host is the CA renewal master."""
        if fqdn is None:
            fqdn = api.env.host

        dn = DN(
            ("cn", "CA"),
            ("cn", fqdn),
            api.env.container_masters,
            api.env.basedn,
        )
        renewal_filter = "(ipaConfigString=caRenewalMaster)"
        try:
            api.Backend.ldap2.get_entries(
                base_dn=dn, filter=renewal_filter, attrs_list=[]
            )
        except errors.NotFound:
            return False

        return True

    def set_renewal_master(self, fqdn=None):
        """Designate a host as the CA renewal master."""
        if fqdn is None:
            fqdn = api.env.host

        base_dn = DN(api.env.container_masters, api.env.basedn)
        renewal_filter = "(&(cn=CA)(ipaConfigString=caRenewalMaster))"
        try:
            entries = api.Backend.ldap2.get_entries(
                base_dn=base_dn,
                filter=renewal_filter,
                attrs_list=["ipaConfigString"],
            )
        except errors.NotFound:
            entries = []

        dn = DN(("cn", "CA"), ("cn", fqdn), base_dn)
        try:
            master_entry = api.Backend.ldap2.get_entry(dn, ["ipaConfigString"])
        except errors.NotFound:
            logger.warning(
                "CA service entry not found for %s, cannot set "
                "renewal master",
                fqdn,
            )
            return

        for entry in entries:
            if master_entry is not None and entry.dn == master_entry.dn:
                master_entry = None
                continue
            config_strings = entry.get("ipaConfigString", [])
            entry["ipaConfigString"] = [
                x for x in config_strings if x.lower() != "carenewalmaster"
            ]
            api.Backend.ldap2.update_entry(entry)

        if master_entry is not None:
            master_entry.setdefault("ipaConfigString", []).append(
                "caRenewalMaster"
            )
            api.Backend.ldap2.update_entry(master_entry)

    def _configure_ldap_access(self):
        """Configure LDAP access for ipaca via LDAPI autobind
        and sysaccount."""
        logger.debug("Configuring LDAP access for ipaca")

        if not self.ldap.isconnected():
            self.ldap.connect()

        ldap = self.ldap

        # 1. Create ipacasrv sysaccount if it doesn't exist
        # This is the DN that the autobind mapping will point to
        ipacasrv_dn = DN(
            ("uid", "ipacasrv"),
            ("cn", "sysaccounts"),
            ("cn", "etc"),
            self.basedn,
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
            from ipaserver.install import service as ipaservice

            ipaservice.run_ldapi_reload_task(ldap)
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
                # Construct userdn via DN to ensure proper escaping
                ipacasrv_dn = DN(
                    ("uid", "ipacasrv"),
                    ("cn", "sysaccounts"),
                    ("cn", "etc"),
                    self.basedn,
                )
                dogtag_aci = (
                    '(targetattr="*")(version 3.0; acl "Allow ipacasrv full '
                    'access to Dogtag CA data"; '
                    f'allow (all) userdn="ldap:///{ipacasrv_dn}";)'
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
            from ipathinca.subca import SubCAManager

            subca_manager = SubCAManager()
            subca_manager.initialize_ldap_schema()
            logger.debug("Sub-CA LDAP schema initialized successfully")
        except Exception as e:
            logger.warning(
                f"Failed to initialize sub-CA schema (may already exist): {e}"
            )

        logger.debug("LDAP access for ipaca configured successfully")

    def _load_external_cert(self, cert_files, ca_subject):
        """Load and validate an externally-signed CA certificate.

        Wraps ``installutils.load_external_cert`` so that
        ``ipathinca.install.certs`` does not need to import from ipaserver.
        """
        from ipaserver.install import installutils

        return installutils.load_external_cert(cert_files, ca_subject)

    def _create_default_caacl(self):
        """Create default CA ACL for hosts and services.

        CA ACLs are an IPA concept — they control which IPA principals (hosts,
        services, users) may request certificates using which profiles.
        """
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
        try:
            logger.debug("Creating hosts_services_caIPAserviceCert CA ACL")
            api.Command.caacl_add(
                "hosts_services_caIPAserviceCert",
                hostcategory="all",
                servicecategory="all",
            )
            api.Command.caacl_add_profile(
                "hosts_services_caIPAserviceCert",
                certprofile=("caIPAserviceCert",),
            )
            logger.debug("Default CA ACL created successfully")
        except Exception as e:
            logger.error(f"Failed to create default CA ACL: {e}")
            raise

    def _setup_replication(self):
        """Set up LDAP replication for the o=ipaca suffix.

        Called during replica promotion.  Uses CAReplicationManager to create
        bidirectional replication agreements between this host and
        self.master_host, then activates the topology segment.
        """
        from ipaserver.install import replication

        logger.debug(
            "Setting up CA replication from master %s", self.master_host
        )
        repl = replication.CAReplicationManager(self.realm, self.fqdn)
        repl.setup_cs_replication(self.master_host)
        self._repl.update_topology()
        logger.debug("CA replication setup complete")

    def finalize_replica_config(self):
        """Switch replication from aggressive (install) to production settings.

        Called after the CA service has started on the new replica.  Adjusts
        replication timeouts on both ends to production values (matching
        Dogtag's cainstance.py behaviour).
        """
        from ipaserver.install import replication

        logger.debug(
            "Finalizing CA replica config with master %s", self.master_host
        )
        repl = replication.CAReplicationManager(self.realm, self.fqdn)
        repl.finalize_replica_config(self.master_host)
        logger.debug("CA replica config finalized")

    def _setup_lightweight_ca_key_retrieval_kerberos(self):
        """Create the dogtag/<fqdn>@REALM Kerberos principal for LWCA."""
        from ipaserver.install import installutils

        lwca_principal = "{}/{}".format(PKI_GSSAPI_SERVICE_NAME, self.fqdn)
        keytab = os.path.join(
            paths.PKI_TOMCAT, PKI_GSSAPI_SERVICE_NAME + ".keytab"
        )

        logger.debug("Creating LWCA Kerberos principal: %s", lwca_principal)
        installutils.kadmin_addprinc(lwca_principal)
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.move_service(lwca_principal)

        logger.debug("Extracting LWCA keytab to %s", keytab)
        installutils.create_keytab(keytab, lwca_principal)
        os.chmod(keytab, 0o600)
        self.service_user.chown(keytab)

    def _setup_lightweight_ca_key_retrieval_custodia(self):
        """Create Custodia LDAP containers and generate wrapping keys."""
        from ipaserver.secrets.kem import IPAKEMKeys

        logger.debug("Creating Custodia key wrapping infrastructure")

        custodia_basedn = DN(
            ("cn", "custodia"), ("cn", "ipa"), ("cn", "etc"), self.basedn
        )
        for dn, cn in [
            (custodia_basedn, "custodia"),
            (
                DN(("cn", PKI_GSSAPI_SERVICE_NAME), custodia_basedn),
                PKI_GSSAPI_SERVICE_NAME,
            ),
        ]:
            entry = self.ldap.make_entry(
                dn, objectclass=["top", "nsContainer"], cn=[cn]
            )
            try:
                self.ldap.add_entry(entry)
            except errors.DuplicateEntry:
                pass

        keyfile = os.path.join(
            paths.PKI_TOMCAT, PKI_GSSAPI_SERVICE_NAME + ".keys"
        )
        keystore = IPAKEMKeys({"server_keys": keyfile})
        keystore.generate_keys(PKI_GSSAPI_SERVICE_NAME)
        os.chmod(keyfile, 0o600)
        self.service_user.chown(keyfile)
        logger.debug("Custodia key file created: %s", keyfile)

    # -----------------------------------------------------------------------
    # Delegation methods (public API for external callers)
    # -----------------------------------------------------------------------

    def enable_kra(self):
        """Enable KRA functionality — delegates to KRAInstall helper."""
        if self._kra is None:
            self._kra = KRAInstall(
                self.ldap,
                self._nssdb,
                self.ca_cert_path,
                self.realm,
                self.basedn,
                self.fqdn,
                self.pki_config,
                self._ldap_mod,
            )
        self._kra.enable_kra()

    def setup_acme(self):
        """Set up ACME service — delegates to ACME helper."""
        if self._acme is None:
            self._acme = ACME(self.ldap, self.config, self._ldap_mod)
        self._acme.setup_acme()

    def ensure_lightweight_cas_container(self):
        """Create LWCA authorities container — delegates to LWCA helper."""
        if self._lwca is None:
            self._lwca = LWCA(self.ldap, self.basedn)
        self._lwca.ensure_lightweight_cas_container()

    def add_lightweight_ca_tracking_requests(self):
        """Register LWCA certs with certmonger — delegates to LWCA helper."""
        if self._lwca is None:
            self._lwca = LWCA(self.ldap, self.basedn)
        self._lwca.add_lightweight_ca_tracking_requests()

    def setup_lightweight_ca_key_retrieval(self):
        """Set up LWCA private key retrieval infrastructure."""
        logger.debug("Setting up lightweight CA key retrieval")
        self._setup_lightweight_ca_key_retrieval_kerberos()
        self._setup_lightweight_ca_key_retrieval_custodia()
        logger.debug("Lightweight CA key retrieval setup complete")

    # -----------------------------------------------------------------------
    # CRL publishing (Apache RewriteRule management)
    # -----------------------------------------------------------------------

    # Regex patterns for managing the CRL RewriteRule in the Apache proxy conf.
    _crl_rewrite_pattern = (
        r"^\s*(RewriteRule\s+\^/ipa/crl/MasterCRL\.bin\s.*)$"
    )
    _crl_rewrite_comment = r"^#\s*RewriteRule\s+\^/ipa/crl/MasterCRL\.bin\s.*$"
    _crl_rewriterule = (
        "\nRewriteRule ^/ipa/crl/MasterCRL.bin "
        "https://{}/ca/ee/ca/getCRL?"
        "op=getCRL&crlIssuingPoint=MasterCRL "
        "[L,R=301,NC]"
    )

    def setup_crlgen(self, setup_crlgen):
        """Configure this host for CRL generation.

        On a CRL-generating master: the Apache RewriteRule that redirects
        /ipa/crl/MasterCRL.bin is commented out so Apache serves the
        published CRL file directly.

        On a clone: the RewriteRule is activated, redirecting requests to
        the CRL-generating master.
        """
        if self.is_crlgen_enabled() == setup_crlgen:
            logger.info(
                "Nothing to do, CRL generation already %s",
                "enabled" if setup_crlgen else "disabled",
            )
            return

        proxy_conf = paths.HTTPD_IPA_PKI_PROXY_CONF

        def comment_rewriterule():
            """Comment out the CRL RewriteRule (master mode)."""
            logger.info("Editing %s", proxy_conf)
            p = re.compile(self._crl_rewrite_pattern, re.MULTILINE)
            with open(proxy_conf) as f:
                content = f.read()
            with open(proxy_conf, "w") as f:
                f.write(p.sub(r"#\1", content))

        def uncomment_rewriterule():
            """Activate the CRL RewriteRule (clone/redirect mode)."""
            logger.info("Editing %s", proxy_conf)
            p = re.compile(self._crl_rewrite_pattern, re.MULTILINE)
            with open(proxy_conf) as f:
                content = f.read()
            present = p.search(content)
            p_comment = re.compile(self._crl_rewrite_comment, re.MULTILINE)
            new_content = p_comment.sub("", content)
            if not present:
                new_content += self._crl_rewriterule.format(api.env.host)
            with open(proxy_conf, "w") as f:
                f.write(new_content)

        try:
            if setup_crlgen:
                comment_rewriterule()
            else:
                uncomment_rewriterule()
        except IOError:
            raise RuntimeError("Unable to access {}".format(proxy_conf))

        http_service = services.knownservices.httpd
        logger.info("Restarting %s", http_service.service_name)
        http_service.restart()
        logger.debug("%s successfully restarted", http_service.service_name)

    # -----------------------------------------------------------------------
    # Config helpers
    # -----------------------------------------------------------------------

    def _ensure_global_config(self):
        """Ensure global ipathinca config is initialized.

        Needed for healthcheck and other contexts where the config
        needs to be loaded but we're not in an installation context.
        """
        try:
            get_global_config()
            return True
        except Exception:
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
        """Is HSM support enabled?"""
        try:
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
        """HSM token name."""
        try:
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

    # -----------------------------------------------------------------------
    # Dogtag interface compatibility stubs
    # -----------------------------------------------------------------------

    def enable_client_auth_to_db(self):
        """Enable client auth to LDAP database (no-op for ipathinca)."""
        logger.debug("enable_client_auth_to_db: No-op for ipathinca")

    def stop_tracking_certificates(self):
        """Stop tracking certificates with certmonger."""
        logger.debug("Stopping certmonger tracking for ipathinca certificates")

        from ipalib.install import certmonger

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

        try:
            certmonger.stop_tracking(certfile=paths.RA_AGENT_PEM)
            logger.debug("Stopped tracking RA agent certificate")
        except RuntimeError as e:
            logger.debug(f"RA agent certificate not tracked or error: {e}")

        try:
            certmonger.stop_tracking(certfile=paths.HTTPD_CERT_FILE)
            logger.debug("Stopped tracking HTTPS certificate")
        except RuntimeError as e:
            logger.debug(f"HTTPS certificate not tracked or error: {e}")

    # -----------------------------------------------------------------------
    # Main installation orchestrator
    # -----------------------------------------------------------------------

    def create_instance(
        self, ca_signing_cert=None, ca_signing_key=None, promote=False
    ):
        """Create and configure ipathinca Python CA instance.

        Args:
            ca_signing_cert: Path to existing CA signing certificate (PEM)
            ca_signing_key: Path to existing CA signing key (PEM)
            promote: True when promoting an existing replica to have a CA.
        """
        logger.debug("Creating ipathinca Python CA instance")

        self._certs.ca_signing_cert = ca_signing_cert
        self._certs.ca_signing_key = ca_signing_key

        if not self.random_serial_numbers:
            ldap_backend = lookup_ldap_backend(api)
            if ldap_backend != "bdb":
                logger.info(
                    "Forcing random serial numbers to be enabled for the %s "
                    "backend",
                    ldap_backend,
                )
                self.random_serial_numbers = True

        # Promote path: set up o=ipaca replication BEFORE the main steps so
        # that LDAP data (CA certs, profiles, etc.) is already present.
        if promote:
            self.no_db_setup = True
            self.step(
                "creating certificate server db",
                self._ldap_setup._create_ds_db,
            )
            self.step("setting up CA replication", self._setup_replication)

        self.step(
            "creating directory structure", self._svc._create_directories
        )
        self.step("creating NSS database", self._nssdb.create_nssdb)
        self.step(
            "creating service configuration",
            self._svc._create_service_config,
        )
        if not self.no_db_setup:
            self.step(
                "installing LDAP schema",
                self._ldap_setup._install_ldap_schema,
            )
            self.step(
                "initializing LDAP storage",
                self._ldap_setup._initialize_ldap_storage,
            )
        self.step(
            "configuring LDAP access for ipaca", self._configure_ldap_access
        )
        self.step(
            "configuring CA certificates and keys",
            self._certs._configure_ca_certs,
        )
        self.step(
            "storing CA certificate in LDAP",
            self._certs._store_ca_cert_ldap,
        )
        self.step("creating IPA CA entry", self._certs._create_ipa_ca_entry)
        self.step(
            "initializing certificate storage schema",
            self._certs._init_cert_storage_schema,
        )
        self.step(
            "storing CA certificate in certificate database",
            self._certs._store_ca_cert_in_certdb,
        )
        if not self.clone:
            self.step(
                "importing certificate profiles to LDAP",
                self._ldap_setup._import_profiles_ldap,
            )
            self.step("creating default CA ACL", self._create_default_caacl)
            self.step(
                "creating lightweight CA container",
                self._lwca.ensure_lightweight_cas_container,
            )
            self.step("setting up ACME service", self._acme.setup_acme)
        self.step(
            "installing CA certificate to system trust",
            self._certs._install_ca_trust,
        )
        self.step(
            "generating server SSL certificate",
            self._certs._generate_server_cert,
        )
        self.step(
            "generating RA agent certificate",
            self._certs._generate_ra_cert,
        )
        self.step(
            "verifying RA key accessibility for replicas",
            self._certs._verify_ra_key_custodia,
        )
        self.step(
            "generating PKI subsystem certificates",
            self._certs._generate_subsystem_certs,
        )
        self.step(
            "installing certmonger renewal scripts",
            self._svc._install_renewal_scripts,
        )
        self.step(
            "configuring certmonger for renewals",
            self._svc._configure_certmonger_renewal,
        )
        self.step(
            "installing systemd service",
            self._svc._install_systemd_service,
        )
        self.step(
            "configuring audit logging",
            self._svc._configure_audit_logging,
        )
        self.step("configuring Apache HTTP proxy", self._svc._http_proxy)
        self.step("starting ipathinca service", self._svc._start_service)
        self.step("generating initial CRL", self._svc._generate_initial_crl)

        if promote:
            self.step(
                "finalizing replica config", self.finalize_replica_config
            )

        self.start_creation()

    # -----------------------------------------------------------------------
    # Service lifecycle
    # -----------------------------------------------------------------------

    def enable_and_start(self):
        """Enable and register CA service in LDAP (called from install_step_1).

        This is called AFTER PKINIT is configured to ensure that during
        initial installation, PKINIT uses dogtag-submit to contact the CA
        directly instead of going through the IPA framework.
        """
        logger.debug("Registering CA service in LDAP")
        self._ldap_setup._register_ca_service()
        logger.debug("CA service registered successfully")

    def start(self):
        """Start ipathinca service."""
        services.knownservices["ipathinca"].start()

    def stop(self):
        """Stop ipathinca service."""
        services.knownservices["ipathinca"].stop()

    def restart(self):
        """Restart ipathinca service."""
        services.knownservices["ipathinca"].restart()

    def is_running(self):
        """Check if ipathinca service is running."""
        try:
            return services.knownservices["ipathinca"].is_running()
        except Exception:
            return False

    def uninstall(self):
        """Uninstall ipathinca instance."""
        if self.is_installed():
            self.print_msg("Unconfiguring %s" % self.subsystem)

        logger.debug("Uninstalling ipathinca Python CA instance")

        # Stop certmonger tracking for all ipathinca certificates
        if self._svc is None:
            # Minimal ServiceMgmt for uninstall
            self._svc = ServiceMgmt(
                None,
                self.fqdn,
                False,
                self._nssdb,
                self.configure_certmonger_renewal_helpers,
            )
        self._svc._stop_certmonger_tracking()

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

        try:
            ipautil.run(["systemctl", "daemon-reload"])
            logger.debug("systemd reloaded")
        except Exception as e:
            logger.debug(f"Failed to reload systemd: {e}")

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
        if self.ipaca_dir.exists():
            try:
                import shutil

                shutil.rmtree(self.ipaca_dir)
                logger.debug(f"Removed {self.ipaca_dir}")
            except Exception as e:
                logger.warning(f"Failed to remove {self.ipaca_dir}: {e}")

        # Remove audit logs
        if self.audit_log_dir.exists():
            try:
                import shutil

                shutil.rmtree(self.audit_log_dir)
                logger.debug(f"Removed {self.audit_log_dir}")
            except Exception as e:
                logger.warning(f"Failed to remove {self.audit_log_dir}: {e}")

        logger.debug("ipathinca uninstalled successfully")
