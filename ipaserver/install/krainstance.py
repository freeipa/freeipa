# Authors: Ade Lee <alee@redhat.com>
#
# Copyright (C) 2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import ConfigParser
import os
import pwd
import shutil
import sys
import tempfile

from ipalib import api
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython import dogtag
from ipapython import ipautil
from ipapython.dn import DN
from ipaserver.install import certs
from ipaserver.install import cainstance
from ipaserver.install import ldapupdate
from ipaserver.install import service
from ipaserver.install.dogtaginstance import DogtagInstance
from ipaserver.install.dogtaginstance import DEFAULT_DSPORT, PKI_USER
from ipapython.ipa_log_manager import log_mgr

# When IPA is installed with DNS support, this CNAME should hold all IPA
# replicas with KRA configured
IPA_KRA_RECORD = "ipa-kra"


class KRAInstance(DogtagInstance):
    """
    We assume that the CA has already been installed, and we use the
    same tomcat instance to host both the CA and KRA.
    The mod_nss database will contain the RA agent cert that will be used
    to do authenticated requests against dogtag.  The RA agent cert will
    be the same for both the CA and KRA.
    """

    tracking_reqs = (('auditSigningCert cert-pki-kra', None),
                     ('transportCert cert-pki-kra', None),
                     ('storageCert cert-pki-kra', None))

    def __init__(self, realm, dogtag_constants=None):
        if dogtag_constants is None:
            dogtag_constants = dogtag.configured_constants()

        super(KRAInstance, self).__init__(
            realm=realm,
            subsystem="KRA",
            service_desc="KRA server",
            dogtag_constants=dogtag_constants
        )

        self.basedn = DN(('o', 'kra'), ('o', 'ipaca'))
        self.log = log_mgr.get_logger(self)

    def configure_instance(self, realm_name, host_name, domain, dm_password,
                           admin_password, ds_port=DEFAULT_DSPORT,
                           pkcs12_info=None, master_host=None,
                           master_replication_port=None,
                           subject_base=None):
        """Create a KRA instance.

           To create a clone, pass in pkcs12_info.
        """
        self.fqdn = host_name
        self.domain = domain
        self.dm_password = dm_password
        self.admin_password = admin_password
        self.ds_port = ds_port
        self.pkcs12_info = pkcs12_info
        if self.pkcs12_info is not None:
            self.clone = True
        self.master_host = master_host
        self.master_replication_port = master_replication_port
        if subject_base is None:
            self.subject_base = DN(('O', self.realm))
        else:
            self.subject_base = subject_base
        self.realm = realm_name
        self.suffix = ipautil.realm_to_suffix(realm_name)

        # Confirm that a KRA does not already exist
        if self.is_installed():
            raise RuntimeError(
                "KRA already installed.")
        # Confirm that a Dogtag 10 CA instance already exists
        ca = cainstance.CAInstance(
            api.env.realm, certs.NSS_DIR,
            dogtag_constants=dogtag.Dogtag10Constants)
        if not ca.is_installed():
            raise RuntimeError(
                "KRA configuration failed.  "
                "A Dogtag CA must be installed first")

        self.step("configuring KRA instance", self.__spawn_instance)
        if not self.clone:
            self.step("add RA user to KRA agent group",
                      self.__add_ra_user_to_agent_group)
        self.step("restarting KRA", self.restart_instance)
        self.step("configure certmonger for renewals",
                  self.configure_certmonger_renewal)
        self.step("configure certificate renewals", self.configure_renewal)
        self.step("configure HTTP to proxy connections",
                  self.http_proxy)
        self.step("add vault container", self.__add_vault_container)

        self.start_creation(runtime=126)

    def __spawn_instance(self):
        """
        Create and configure a new KRA instance using pkispawn.
        Creates a configuration file with IPA-specific
        parameters and passes it to the base class to call pkispawn
        """

        # Create an empty and secured file
        (cfg_fd, cfg_file) = tempfile.mkstemp()
        os.close(cfg_fd)
        pent = pwd.getpwnam(PKI_USER)
        os.chown(cfg_file, pent.pw_uid, pent.pw_gid)

        # Create KRA configuration
        config = ConfigParser.ConfigParser()
        config.optionxform = str
        config.add_section("KRA")

        # Security Domain Authentication
        config.set("KRA", "pki_security_domain_https_port", "443")
        config.set("KRA", "pki_security_domain_password", self.admin_password)
        config.set("KRA", "pki_security_domain_user", "admin")

        # issuing ca
        config.set("KRA", "pki_issuing_ca_uri", "https://%s" %
                   ipautil.format_netloc(self.fqdn, 443))

        # Server
        config.set("KRA", "pki_enable_proxy", "True")
        config.set("KRA", "pki_restart_configured_instance", "False")
        config.set("KRA", "pki_backup_keys", "True")
        config.set("KRA", "pki_backup_password", self.admin_password)

        # Client security database
        config.set("KRA", "pki_client_database_dir", self.agent_db)
        config.set("KRA", "pki_client_database_password", self.admin_password)
        config.set("KRA", "pki_client_database_purge", "False")
        config.set("KRA", "pki_client_pkcs12_password", self.admin_password)

        # Administrator
        config.set("KRA", "pki_admin_name", "admin")
        config.set("KRA", "pki_admin_uid", "admin")
        config.set("KRA", "pki_admin_email", "root@localhost")
        config.set("KRA", "pki_admin_password", self.admin_password)
        config.set("KRA", "pki_admin_nickname", "ipa-ca-agent")
        config.set("KRA", "pki_admin_subject_dn",
                   str(DN(('cn', 'ipa-ca-agent'), self.subject_base)))
        config.set("KRA", "pki_import_admin_cert", "True")
        config.set("KRA", "pki_admin_cert_file", paths.ADMIN_CERT_PATH)
        config.set("KRA", "pki_client_admin_cert_p12", paths.DOGTAG_ADMIN_P12)

        # Directory server
        config.set("KRA", "pki_ds_ldap_port", str(self.ds_port))
        config.set("KRA", "pki_ds_password", self.dm_password)
        config.set("KRA", "pki_ds_base_dn", self.basedn)
        config.set("KRA", "pki_ds_database", "ipaca")
        config.set("KRA", "pki_ds_create_new_db", "False")

        # Certificate subject DNs
        config.set("KRA", "pki_subsystem_subject_dn",
                   str(DN(('cn', 'CA Subsystem'), self.subject_base)))
        config.set("KRA", "pki_ssl_server_subject_dn",
                   str(DN(('cn', self.fqdn), self.subject_base)))
        config.set("KRA", "pki_audit_signing_subject_dn",
                   str(DN(('cn', 'KRA Audit'), self.subject_base)))
        config.set(
            "KRA", "pki_transport_subject_dn",
            str(DN(('cn', 'KRA Transport Certificate'), self.subject_base)))
        config.set(
            "KRA", "pki_storage_subject_dn",
            str(DN(('cn', 'KRA Storage Certificate'), self.subject_base)))

        # Certificate nicknames
        # Note that both the server certs and subsystem certs reuse
        # the ca certs.
        config.set("KRA", "pki_subsystem_nickname",
                   "subsystemCert cert-pki-ca")
        config.set("KRA", "pki_ssl_server_nickname",
                   "Server-Cert cert-pki-ca")
        config.set("KRA", "pki_audit_signing_nickname",
                   "auditSigningCert cert-pki-kra")
        config.set("KRA", "pki_transport_nickname",
                   "transportCert cert-pki-kra")
        config.set("KRA", "pki_storage_nickname",
                   "storageCert cert-pki-kra")

        # Shared db settings
        # Needed because CA and KRA share the same database
        # We will use the dbuser created for the CA
        config.set("KRA", "pki_share_db", "True")
        config.set(
            "KRA", "pki_share_dbuser_dn",
            str(DN(('uid', 'pkidbuser'), ('ou', 'people'), ('o', 'ipaca'))))

        _p12_tmpfile_handle, p12_tmpfile_name = tempfile.mkstemp(dir=paths.TMP)
        if self.clone:
            krafile = self.pkcs12_info[0]
            shutil.copy(krafile, p12_tmpfile_name)
            pent = pwd.getpwnam(PKI_USER)
            os.chown(p12_tmpfile_name, pent.pw_uid, pent.pw_gid)

            # create admin cert file if it does not exist
            cert = DogtagInstance.get_admin_cert(self)
            with open(paths.ADMIN_CERT_PATH, "w") as admin_path:
                admin_path.write(cert)

            # Security domain registration
            config.set("KRA", "pki_security_domain_hostname", self.master_host)
            config.set("KRA", "pki_security_domain_https_port", "443")
            config.set("KRA", "pki_security_domain_user", "admin")
            config.set("KRA", "pki_security_domain_password",
                       self.admin_password)

            # Clone
            config.set("KRA", "pki_clone", "True")
            config.set("KRA", "pki_clone_pkcs12_path", p12_tmpfile_name)
            config.set("KRA", "pki_clone_pkcs12_password", self.dm_password)
            config.set("KRA", "pki_clone_setup_replication", "False")
            config.set(
                "KRA", "pki_clone_uri",
                "https://%s" % ipautil.format_netloc(self.master_host, 443))

        # Generate configuration file
        with open(cfg_file, "wb") as f:
            config.write(f)

        try:
            DogtagInstance.spawn_instance(self, cfg_file)
        finally:
            os.remove(p12_tmpfile_name)
            os.remove(cfg_file)

        shutil.move(paths.KRA_BACKUP_KEYS_P12, paths.KRACERT_P12)
        self.log.debug("completed creating KRA instance")

    def __add_ra_user_to_agent_group(self):
        """
        Add RA agent created for CA to KRA agent group.
        """

        # import CA certificate into temporary security database
        args = ["/usr/bin/pki",
            "-d", self.agent_db,
            "-c", self.admin_password,
            "client-cert-import",
            "--pkcs12", paths.KRACERT_P12,
            "--pkcs12-password", self.admin_password]
        ipautil.run(args)

        # trust CA certificate
        args = ["/usr/bin/pki",
            "-d", self.agent_db,
            "-c", self.admin_password,
            "client-cert-mod", "Certificate Authority - %s" % api.env.realm,
            "--trust", "CT,c,"]
        ipautil.run(args)

        # import Dogtag admin certificate into temporary security database
        args = ["/usr/bin/pki",
            "-d", self.agent_db,
            "-c", self.admin_password,
            "client-cert-import",
            "--pkcs12", paths.DOGTAG_ADMIN_P12,
            "--pkcs12-password", self.admin_password]
        ipautil.run(args)

        # as Dogtag admin, create ipakra user in KRA
        args = ["/usr/bin/pki",
            "-d", self.agent_db,
            "-c", self.admin_password,
            "-n", "ipa-ca-agent",
            "kra-user-add", "ipakra",
            "--fullName", "IPA KRA User"]
        ipautil.run(args)

        # as Dogtag admin, add ipakra into KRA agents group
        args = ["/usr/bin/pki",
            "-d", self.agent_db,
            "-c", self.admin_password,
            "-n", "ipa-ca-agent",
            "kra-user-membership-add", "ipakra", "Data Recovery Manager Agents"]
        ipautil.run(args)

        # assign ipaCert to ipakra
        (file, filename) = tempfile.mkstemp()
        os.close(file)
        try:
            # export ipaCert without private key
            args = ["/usr/bin/pki",
                "-d", paths.HTTPD_ALIAS_DIR,
                "-C", paths.ALIAS_PWDFILE_TXT,
                "client-cert-show", "ipaCert",
                "--cert", filename]
            ipautil.run(args)

            # as Dogtag admin, upload and assign ipaCert to ipakra
            args = ["/usr/bin/pki",
                "-d", self.agent_db,
                "-c", self.admin_password,
                "-n", "ipa-ca-agent",
                "kra-user-cert-add", "ipakra",
                "--input", filename]
            ipautil.run(args)

        finally:
            os.remove(filename)

        # export ipaCert with private key for client authentication
        args = ["/usr/bin/pki",
            "-d", paths.HTTPD_ALIAS_DIR,
            "-C", paths.ALIAS_PWDFILE_TXT,
            "client-cert-show", "ipaCert",
            "--client-cert", paths.KRA_AGENT_PEM]
        ipautil.run(args)

    def __add_vault_container(self):
        sub_dict = {
            'SUFFIX': self.suffix,
        }

        ld = ldapupdate.LDAPUpdate(dm_password=self.dm_password,
                                   sub_dict=sub_dict)
        ld.update([paths.VAULT_UPDATE])

    @staticmethod
    def update_cert_config(nickname, cert, dogtag_constants=None):
        """
        When renewing a KRA subsystem certificate the configuration file
        needs to get the new certificate as well.

        nickname is one of the known nicknames.
        cert is a DER-encoded certificate.
        """

        if dogtag_constants is None:
            dogtag_constants = dogtag.configured_constants()

        # The cert directive to update per nickname
        directives = {
            'auditSigningCert cert-pki-kra': 'kra.audit_signing.cert',
            'storageCert cert-pki-kra': 'kra.storage.cert',
            'transportCert cert-pki-kra': 'kra.transport.cert',
            'subsystemCert cert-pki-kra': 'kra.subsystem.cert',
            'Server-Cert cert-pki-ca': 'kra.sslserver.cert'}

        DogtagInstance.update_cert_cs_cfg(
            nickname, cert, directives,
            dogtag.configured_constants().KRA_CS_CFG_PATH,
            dogtag_constants)


def install_replica_kra(config, postinstall=False):
    """
    Install a KRA on a replica.

    There are two modes of doing this controlled:
      - While the replica is being installed
      - Post-replica installation

    config is a ReplicaConfig object

    Returns a KRA instance
    """
    # note that the cacert.p12 file is regenerated during the
    # ipa-replica-prepare process and should include all the certs
    # for the CA and KRA
    krafile = config.dir + "/cacert.p12"

    if not ipautil.file_exists(krafile):
        raise RuntimeError(
            "Unable to clone KRA."
            "  cacert.p12 file not found in replica file")

    _kra = KRAInstance(config.realm_name,
                       dogtag_constants=dogtag.install_constants)
    _kra.dm_password = config.dirman_password
    _kra.subject_base = config.subject_base
    if _kra.is_installed():
        sys.exit("A KRA is already configured on this system.")

    _kra.configure_instance(config.realm_name,
                            config.host_name, config.domain_name,
                            config.dirman_password, config.dirman_password,
                            pkcs12_info=(krafile,),
                            master_host=config.master_host_name,
                            master_replication_port=config.ca_ds_port,
                            subject_base=config.subject_base)

    # Restart httpd since we changed it's config and added ipa-pki-proxy.conf
    if postinstall:
        services.knownservices.httpd.restart()

    # The dogtag DS instance needs to be restarted after installation.
    # The procedure for this is: stop dogtag, stop DS, start DS, start
    # dogtag

    service.print_msg("Restarting the directory and KRA servers")
    _kra.stop(dogtag.install_constants.PKI_INSTANCE_NAME)
    services.knownservices.dirsrv.restart()
    _kra.start(dogtag.install_constants.PKI_INSTANCE_NAME)

    return _kra
