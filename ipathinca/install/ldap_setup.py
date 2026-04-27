# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""LDAP setup helper for IPAThinCAInstance.

Handles LDAP schema installation, o=ipaca database setup, LDAPI autobind
configuration, CA service registration, profile import, and CA ACL creation.
"""

from __future__ import absolute_import

import logging
import os
import tempfile
import urllib.parse
from pathlib import Path

from ipalib import errors
from ipapython import ipautil
from ipapython.dn import DN

from ipathinca.profiles import ProfileManager
from ipathinca.storage_ca import CAStorageBackend
from ipathinca.storage_factory import get_storage_backend

logger = logging.getLogger(__name__)


class LDAPSetup:
    """Helper providing LDAP schema and access configuration methods."""

    def __init__(self, ldap, config, realm, basedn, clone, fqdn):
        self.ldap = ldap
        self.config = config
        self.realm = realm
        self.basedn = basedn
        self.clone = clone
        self.fqdn = fqdn

    def _install_dogtag_schema(self):
        """Install Dogtag/PKI LDAP schema for dogtag backend.

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

            raise RuntimeError(
                f"Dogtag LDAP schema installation failed "
                f"(returncode={result.returncode}). "
                f"Cannot proceed without required schema."
            )

    def _install_ldap_schema(self):
        """Install LDAP schema for Dogtag backend."""
        logger.debug("Installing LDAP schema for Dogtag backend")

        if not self.ldap.isconnected():
            self.ldap.connect()

        # Install Dogtag/PKI LDAP schema
        self._install_dogtag_schema()

        logger.debug("LDAP schema installed successfully")

    def _create_ds_db(self):
        """Create LDAP backend and suffix for o=ipaca.

        This creates the LDAP database backend and mapping tree for o=ipaca,
        which is required before any Dogtag schema objects can be stored.
        This mirrors what traditional Dogtag/PKI does during installation.
        """
        logger.debug("Creating LDAP backend for o=ipaca")

        if not self.ldap.isconnected():
            self.ldap.connect()

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
            self.ldap.get_entry(dn)
            logger.debug(f"LDAP backend {backend} already exists")
        except errors.NotFound:
            # Create new backend
            logger.debug(f"Creating LDAP backend: {backend}")
            entry = self.ldap.make_entry(
                dn,
                objectclass=["top", "extensibleObject", "nsBackendInstance"],
                cn=[backend],
            )
            entry["nsslapd-suffix"] = [suffix]
            self.ldap.add_entry(entry)
            logger.debug(f"LDAP backend {backend} created successfully")

        # Create mapping tree entry
        # This maps o=ipaca suffix to the ipaca backend
        dn = DN(("cn", str(suffix)), ("cn", "mapping tree"), ("cn", "config"))

        try:
            # Check if mapping tree already exists
            self.ldap.get_entry(dn)
            logger.debug(f"Mapping tree for {suffix} already exists")
        except errors.NotFound:
            # Create new mapping tree
            logger.debug(f"Creating mapping tree for suffix: {suffix}")
            entry = self.ldap.make_entry(
                dn,
                objectclass=["top", "extensibleObject", "nsMappingTree"],
                cn=[suffix],
            )
            entry["nsslapd-state"] = ["Backend"]
            entry["nsslapd-backend"] = [backend]
            self.ldap.add_entry(entry)
            logger.debug(f"Mapping tree for {suffix} created successfully")

        logger.debug("LDAP backend and suffix for o=ipaca initialized")

    def _initialize_ldap_storage(self):
        """Initialize LDAP storage with CA configuration."""
        logger.debug("Initializing LDAP storage for ipathinca")

        if not self.ldap.isconnected():
            self.ldap.connect()

        # Create LDAP backend and mapping tree for o=ipaca FIRST
        # This MUST happen before trying to create any entries under o=ipaca
        self._create_ds_db()

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
        self._configure_ldapi_autobind()

        logger.debug("LDAP storage initialized successfully")

    def _configure_ldapi_autobind(self):
        """Configure LDAPI autobind mapping for ipaca.

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
nsslapd-ldapientrysearchbase: {self.basedn}
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
                # Don't fail installation - the _configure_ldap_access step
                # will handle this

        finally:
            # Clean up temporary file
            os.unlink(ldif_file)

        logger.debug("LDAPI autobind configuration completed")

    def _register_ca_service(self):
        """Register CA service in LDAP under cn=masters."""
        logger.debug("Registering CA service in LDAP")

        if not self.ldap.isconnected():
            self.ldap.connect()

        ldap = self.ldap

        # Create service entry:
        # cn=CA,cn={fqdn},cn=masters,cn=ipa,cn=etc,{basedn}

        service_dn = DN(
            ("cn", "CA"),
            ("cn", self.fqdn),
            ("cn", "masters"),
            ("cn", "ipa"),
            ("cn", "etc"),
            self.basedn,
        )

        try:
            # Check if entry already exists
            ldap.get_entry(service_dn)
            logger.debug(f"CA service entry already exists: {service_dn}")
        except errors.NotFound:
            logger.debug(f"Creating CA service entry: {service_dn}")

            # Build ipaConfigString - non-clone installs become renewal master
            ipa_config = ["enabledService", "startOrder 50"]
            if not self.clone:
                ipa_config.append("caRenewalMaster")

            # Create the entry with proper object classes
            entry = ldap.make_entry(
                service_dn,
                objectClass=["nsContainer", "ipaConfigObject"],
                cn=["CA"],
                ipaConfigString=ipa_config,
            )
            ldap.add_entry(entry)
            logger.debug("CA service entry created successfully")

    def _import_profiles_ldap(self):
        """Import default certificate profiles to LDAP."""
        logger.debug("Importing certificate profiles to LDAP")

        if not self.ldap.isconnected():
            self.ldap.connect()

        ldap = self.ldap

        # IPA stores certificate profiles at cn=certprofiles,cn=ca,{basedn}
        # This is separate from our ipathinca storage at
        # ou=profiles,ou=ca,{basedn}
        certprofiles_base = DN(
            ("cn", "certprofiles"), ("cn", "ca"), self.basedn
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
            ca_base = DN(("cn", "ca"), self.basedn)
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
        # Use standard IPA profile metadata from dogtag.INCLUDED_PROFILES
        from ipapython import dogtag

        # Note: Only INCLUDED_PROFILES go in IPA tree
        # Infrastructure profiles (subsystem, OCSP, audit) only go in
        # Dogtag tree (ou=certificateProfiles,ou=ca,o=ipaca)

        profile_manager = ProfileManager(config=self.config)

        # Import only the standard IPA profiles to IPA tree
        # (Infrastructure profiles are only in Dogtag tree)
        for profile_entry in dogtag.INCLUDED_PROFILES:
            profile_id = profile_entry.profile_id

            # Load profile to get full details
            try:
                _ = profile_manager.get_profile(profile_id)
            except Exception as e:
                logger.warning(
                    f"Failed to load profile {profile_id}: {e}, skipping"
                )
                continue
            # Store in IPA's certprofile location
            profile_dn = DN(("cn", profile_id), certprofiles_base)

            try:
                # Check if profile already exists
                ldap.get_entry(profile_dn)
                logger.debug(f"Profile {profile_id} already exists in LDAP")
            except errors.NotFound:
                # Create profile entry in LDAP
                logger.debug(f"Creating profile {profile_id} in LDAP")

                entry = ldap.make_entry(
                    profile_dn,
                    objectClass=["ipacertprofile", "top"],
                    cn=[profile_id],
                    description=[profile_entry.description],
                    ipacertprofilestoreissued=[
                        "TRUE" if profile_entry.store_issued else "FALSE"
                    ],
                )

                ldap.add_entry(entry)

        logger.debug(
            f"Imported {len(dogtag.INCLUDED_PROFILES)} certificate profiles "
            "to IPA tree"
        )

        # Import certificate profiles to LDAP
        # (ou=certificateProfiles,ou=ca,o=ipaca)
        logger.debug("Importing certificate profiles to LDAP (o=ipaca)")

        # Get storage backend
        backend = get_storage_backend()

        # Create ProfileManager with storage backend and config
        profile_manager_profiles = ProfileManager(
            config=self.config, storage_backend=backend
        )

        # Import all .cfg profiles from /usr/share/ipa/profiles/ to LDAP
        try:
            profile_manager_profiles.store_all_profiles_to_ldap()
            logger.debug("All certificate profiles imported to LDAP")
        except Exception as e:
            logger.error(
                f"Failed to import certificate profiles to LDAP: {e}",
                exc_info=True,
            )
            raise RuntimeError(
                f"Cannot import certificate profiles to LDAP: {e}"
            )
