# Authors: Rob Crittenden <rcritten@redhat.com>
#          Ade Lee <alee@redhat.com>
#          Andrew Wnuk <awnuk@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

import array
import base64
import binascii
import ConfigParser
import dbus
import httplib
import ldap
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import syslog
import time
import tempfile
import urllib
import xml.dom.minidom
import shlex
import pipes

from ipalib import api
from ipalib import pkcs10, x509
from ipalib import errors

from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks

from ipapython import dogtag
from ipapython import certmonger
from ipapython import ipautil
from ipapython import ipaldap
from ipapython.certdb import get_ca_nickname
from ipapython.dn import DN
from ipapython.ipa_log_manager import log_mgr,\
    standard_logging_setup, root_logger

from ipaserver.install import certs
from ipaserver.install import dsinstance
from ipaserver.install import installutils
from ipaserver.install import service
from ipaserver.install.dogtaginstance import DogtagInstance
from ipaserver.install.dogtaginstance import PKI_USER, DEFAULT_DSPORT
from ipaserver.plugins import ldap2


# When IPA is installed with DNS support, this CNAME should hold all IPA
# replicas with CA configured
IPA_CA_RECORD = "ipa-ca"

# We need to reset the template because the CA uses the regular boot
# information
INF_TEMPLATE = """
[General]
FullMachineName=   $FQDN
SuiteSpotUserID=   $USER
SuiteSpotGroup=    $GROUP
ServerRoot=    $SERVER_ROOT
[slapd]
ServerPort=   $DSPORT
ServerIdentifier=   $SERVERID
Suffix=   $SUFFIX
RootDN=   cn=Directory Manager
RootDNPwd= $PASSWORD
ConfigFile = /usr/share/pki/ca/conf/database.ldif
"""


def check_port():
    """
    Check that dogtag port (8443) is available.

    Returns True when the port is free, False if it's taken.
    """
    return not ipautil.host_port_open(None, 8443)

def get_preop_pin(instance_root, instance_name):
    # Only used for Dogtag 9
    preop_pin = None

    filename = instance_root + "/" + instance_name + "/conf/CS.cfg"

    # read the config file and get the preop pin
    try:
        f = open(filename)
    except IOError, e:
        root_logger.error("Cannot open configuration file." + str(e))
        raise e
    data = f.read()
    data = data.split('\n')
    pattern = re.compile("preop.pin=(.*)")
    for line in data:
        match = re.search(pattern, line)
        if match:
            preop_pin = match.group(1)
            break

    if preop_pin is None:
        raise RuntimeError(
            "Unable to find preop.pin in %s. Is your CA already configured?" %
            filename)

    return preop_pin


def import_pkcs12(input_file, input_passwd, cert_database,
                  cert_passwd):
    ipautil.run([paths.PK12UTIL, "-d", cert_database,
                 "-i", input_file,
                 "-k", cert_passwd,
                 "-w", input_passwd])


def get_value(s):
    """
    Parse out a name/value pair from a Javascript variable.
    """
    try:
        expr = s.split('=', 1)
        value = expr[1]
        value = value.replace('\"', '')
        value = value.replace(';', '')
        value = value.replace('\\n', '\n')
        value = value.replace('\\r', '\r')
        return value
    except IndexError:
        return None


def find_substring(data, value):
    """
    Scan through a list looking for a string that starts with value.
    """
    for d in data:
        if d.startswith(value):
            return get_value(d)


def get_defList(data):
    """
    Return a dictionary of defList name/value pairs.

    A certificate signing request is specified as a series of these.
    """
    varname = None
    value = None
    skip = False
    defdict = {}
    for d in data:
        if d.startswith("defList = new Object"):
            varname = None
            value = None
            skip = False
        if d.startswith("defList.defId"):
            varname = get_value(d)
        if d.startswith("defList.defVal"):
            value = get_value(d)
            if skip:
                varname = None
                value = None
                skip = False
        if d.startswith("defList.defConstraint"):
            ctype = get_value(d)
            if ctype == "readonly":
                skip = True

        if varname and value:
            defdict[varname] = value
            varname = None
            value = None

    return defdict


def get_outputList(data):
    """
    Return a dictionary of outputList name/value pairs.

    The output from issuing a certificate is a series of these.
    """
    varname = None
    value = None
    outputdict = {}
    for d in data:
        if d.startswith("outputList = new"):
            varname = None
            value = None
        if d.startswith("outputList.outputId"):
            varname = get_value(d)
        if d.startswith("outputList.outputVal"):
            value = get_value(d)

        if varname and value:
            outputdict[varname] = value
            varname = None
            value = None

    return outputdict


def get_crl_files(path=None):
    """
    Traverse dogtag's CRL files in default CRL publish directory or in chosen
    target directory.

    @param path Custom target directory
    """
    if path is None:
        path = dogtag.configured_constants().CRL_PUBLISH_PATH

    files = os.listdir(path)
    for f in files:
        if f == "MasterCRL.bin":
            yield os.path.join(path, f)
        elif f.endswith(".der"):
            yield os.path.join(path, f)


def is_step_one_done():
    """Read CS.cfg and determine if step one of an external CA install is done
    """
    path = dogtag.install_constants.CS_CFG_PATH
    if not os.path.exists(path):
        return False
    test = installutils.get_directive(path, 'preop.ca.type', '=')
    if test == "otherca":
        return True
    return False


def is_ca_installed_locally():
    """Check if CA is installed locally by checking for existence of CS.cfg
    :return:True/False
    """
    path = dogtag.install_constants.CS_CFG_PATH
    return os.path.exists(path)


def create_ca_user():
    """Create PKI user/group if it doesn't exist yet."""
    tasks.create_system_user(
        name=PKI_USER,
        group=PKI_USER,
        homedir=paths.VAR_LIB,
        shell=paths.NOLOGIN,
    )


class CADSInstance(service.Service):
    """Certificate Authority DS instance

    The CA DS was used with Dogtag 9. Only upgraded installations still use it.
    Thus this class only does uninstallation.
    """
    def __init__(self, host_name=None, realm_name=None, domain_name=None, dm_password=None, dogtag_constants=None):
        service.Service.__init__(
            self, "pkids",
            service_desc="directory server for the CA",
            dm_password=dm_password,
            ldapi=False,
            autobind=ipaldap.AUTOBIND_DISABLED)

        self.serverid = "PKI-IPA"
        self.realm = realm_name
        self.sub_dict = None
        self.domain = domain_name
        self.fqdn = host_name
        self.dercert = None
        self.pkcs12_info = None
        self.ds_port = None
        self.master_host = None
        self.nickname = 'Server-Cert'
        self.subject_base = None

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring CA directory server")

        enabled = self.restore_state("enabled")
        serverid = self.restore_state("serverid")

        # Just eat this state if it exists
        self.restore_state("running")

        if not enabled is None and not enabled:
            services.knownservices.dirsrv.disable()

        if serverid is not None:
            # drop the trailing / off the config_dirname so the directory
            # will match what is in certmonger
            dirname = dsinstance.config_dirname(serverid)[:-1]
            dsdb = certs.CertDB(self.realm, nssdir=dirname)
            dsdb.untrack_server_cert("Server-Cert")
            try:
                dsinstance.remove_ds_instance(serverid)
            except ipautil.CalledProcessError:
                root_logger.error("Failed to remove CA DS instance. You may "
                                  "need to remove instance data manually")

        self.restore_state("user_exists")

        # At one time we removed this user on uninstall. That can potentially
        # orphan files, or worse, if another useradd runs in the interim,
        # cause files to have a new owner.


class CAInstance(DogtagInstance):
    """
    When using a dogtag CA the DS database contains just the
    server cert for DS. The mod_nss database will contain the RA agent
    cert that will be used to do authenticated requests against dogtag.

    This is done because we use python-nss and will inherit the opened
    NSS database in mod_python. In nsslib.py we do an nssinit but this will
    return success if the database is already initialized. It doesn't care
    if the database is different or not.

    external is a state machine:
       0 = not an externally signed CA
       1 = generating CSR to be signed
       2 = have signed cert, continue installation
    """

    tracking_reqs = (('auditSigningCert cert-pki-ca', None),
                     ('ocspSigningCert cert-pki-ca', None),
                     ('subsystemCert cert-pki-ca', None),
                     ('caSigningCert cert-pki-ca', 'ipaCACertRenewal'))
    server_cert_name = 'Server-Cert cert-pki-ca'

    def __init__(self, realm=None, ra_db=None, dogtag_constants=None,
                 host_name=None, dm_password=None, ldapi=True):
        if dogtag_constants is None:
            dogtag_constants = dogtag.configured_constants()

        super(CAInstance, self).__init__(
            realm=realm,
            subsystem="CA",
            service_desc="certificate server",
            dogtag_constants=dogtag_constants,
            host_name=host_name,
            dm_password=dm_password,
            ldapi=ldapi
        )

        # for external CAs
        self.external = 0
        self.csr_file = None
        self.cert_file = None
        self.cert_chain_file = None
        self.create_ra_agent_db = True

        if realm is not None:
            self.canickname = get_ca_nickname(realm)
        else:
            self.canickname = None
        self.ra_agent_db = ra_db
        if self.ra_agent_db is not None:
            self.ra_agent_pwd = self.ra_agent_db + "/pwdfile.txt"
        else:
            self.ra_agent_pwd = None
        self.ra_cert = None
        self.requestId = None
        self.log = log_mgr.get_logger(self)

    def configure_instance(self, host_name, domain, dm_password,
                           admin_password, ds_port=DEFAULT_DSPORT,
                           pkcs12_info=None, master_host=None, csr_file=None,
                           cert_file=None, cert_chain_file=None,
                           master_replication_port=None,
                           subject_base=None, ca_signing_algorithm=None,
                           ca_type=None):
        """Create a CA instance.

           For Dogtag 9, this may involve creating the pki-ca instance.

           To create a clone, pass in pkcs12_info.

           Creating a CA with an external signer is a 2-step process. In
           step 1 we generate a CSR. In step 2 we are given the cert and
           chain and actually proceed to create the CA. For step 1 set
           csr_file. For step 2 set cert_file and cert_chain_file.
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
        if ca_signing_algorithm is None:
            self.ca_signing_algorithm = 'SHA256withRSA'
        else:
            self.ca_signing_algorithm = ca_signing_algorithm
        if ca_type is not None:
            self.ca_type = ca_type
        else:
            self.ca_type = 'generic'

        # Determine if we are installing as an externally-signed CA and
        # what stage we're in.
        if csr_file is not None:
            self.csr_file = csr_file
            self.external = 1
        elif cert_file is not None:
            self.cert_file = cert_file
            self.cert_chain_file = cert_chain_file
            self.external = 2

        self.step("creating certificate server user", create_ca_user)
        if self.dogtag_constants.DOGTAG_VERSION >= 10:
            self.step("configuring certificate server instance", self.__spawn_instance)
        else:
            if not ipautil.dir_exists(paths.VAR_LIB_PKI_CA_DIR):
                self.step("creating pki-ca instance", self.create_instance)
            self.step("configuring certificate server instance", self.__configure_instance)
        self.step("stopping certificate server instance to update CS.cfg", self.stop_instance)
        self.step("backing up CS.cfg", self.backup_config)
        self.step("disabling nonces", self.__disable_nonce)
        self.step("set up CRL publishing", self.__enable_crl_publish)
        self.step("enable PKIX certificate path discovery and validation", self.enable_pkix)
        self.step("starting certificate server instance", self.start_instance)
        # Step 1 of external is getting a CSR so we don't need to do these
        # steps until we get a cert back from the external CA.
        if self.external != 1:
            if self.dogtag_constants.DOGTAG_VERSION < 10 and not self.clone:
                self.step("creating CA agent PKCS#12 file in /root", self.__create_ca_agent_pkcs12)
            if self.create_ra_agent_db:
                self.step("creating RA agent certificate database", self.__create_ra_agent_db)
            self.step("importing CA chain to RA certificate database", self.__import_ca_chain)
            self.step("fixing RA database permissions", self.fix_ra_perms)
            self.step("setting up signing cert profile", self.__setup_sign_profile)
            self.step("setting audit signing renewal to 2 years", self.set_audit_renewal)
            if not self.clone:
                self.step("restarting certificate server", self.restart_instance)
                self.step("requesting RA certificate from CA", self.__request_ra_certificate)
                self.step("issuing RA agent certificate", self.__issue_ra_cert)
                self.step("adding RA agent as a trusted user", self.__configure_ra)
                self.step("authorizing RA to modify profiles", self.__configure_profiles_acl)
            self.step("configure certmonger for renewals", self.configure_certmonger_renewal)
            self.step("configure certificate renewals", self.configure_renewal)
            if not self.clone:
                self.step("configure RA certificate renewal", self.configure_agent_renewal)
            self.step("configure Server-Cert certificate renewal", self.track_servercert)
            self.step("Configure HTTP to proxy connections",
                      self.http_proxy)
            if not self.clone:
                self.step("restarting certificate server", self.restart_instance)
                self.step("Importing IPA certificate profiles", import_included_profiles)

        self.start_creation(runtime=210)

    def __spawn_instance(self):
        """
        Create and configure a new CA instance using pkispawn.
        Creates the config file with IPA specific parameters
        and passes it to the base class to call pkispawn
        """

        # Create an empty and secured file
        (cfg_fd, cfg_file) = tempfile.mkstemp()
        os.close(cfg_fd)
        pent = pwd.getpwnam(PKI_USER)
        os.chown(cfg_file, pent.pw_uid, pent.pw_gid)

        # Create CA configuration
        config = ConfigParser.ConfigParser()
        config.optionxform = str
        config.add_section("CA")

        # Server
        config.set("CA", "pki_security_domain_name", self.security_domain_name)
        config.set("CA", "pki_enable_proxy", "True")
        config.set("CA", "pki_restart_configured_instance", "False")
        config.set("CA", "pki_backup_keys", "True")
        config.set("CA", "pki_backup_password", self.admin_password)
        config.set("CA", "pki_profiles_in_ldap", "True")

        # Client security database
        config.set("CA", "pki_client_database_dir", self.agent_db)
        config.set("CA", "pki_client_database_password", self.admin_password)
        config.set("CA", "pki_client_database_purge", "False")
        config.set("CA", "pki_client_pkcs12_password", self.admin_password)

        # Administrator
        config.set("CA", "pki_admin_name", "admin")
        config.set("CA", "pki_admin_uid", "admin")
        config.set("CA", "pki_admin_email", "root@localhost")
        config.set("CA", "pki_admin_password", self.admin_password)
        config.set("CA", "pki_admin_nickname", "ipa-ca-agent")
        config.set("CA", "pki_admin_subject_dn",
            str(DN(('cn', 'ipa-ca-agent'), self.subject_base)))
        config.set("CA", "pki_client_admin_cert_p12", paths.DOGTAG_ADMIN_P12)

        # Directory server
        config.set("CA", "pki_ds_ldap_port", str(self.ds_port))
        config.set("CA", "pki_ds_password", self.dm_password)
        config.set("CA", "pki_ds_base_dn", self.basedn)
        config.set("CA", "pki_ds_database", "ipaca")

        # Certificate subject DN's
        config.set("CA", "pki_subsystem_subject_dn",
            str(DN(('cn', 'CA Subsystem'), self.subject_base)))
        config.set("CA", "pki_ocsp_signing_subject_dn",
            str(DN(('cn', 'OCSP Subsystem'), self.subject_base)))
        config.set("CA", "pki_ssl_server_subject_dn",
            str(DN(('cn', self.fqdn), self.subject_base)))
        config.set("CA", "pki_audit_signing_subject_dn",
            str(DN(('cn', 'CA Audit'), self.subject_base)))
        config.set("CA", "pki_ca_signing_subject_dn",
            str(DN(('cn', 'Certificate Authority'), self.subject_base)))

        # Certificate nicknames
        config.set("CA", "pki_subsystem_nickname", "subsystemCert cert-pki-ca")
        config.set("CA", "pki_ocsp_signing_nickname", "ocspSigningCert cert-pki-ca")
        config.set("CA", "pki_ssl_server_nickname", "Server-Cert cert-pki-ca")
        config.set("CA", "pki_audit_signing_nickname", "auditSigningCert cert-pki-ca")
        config.set("CA", "pki_ca_signing_nickname", "caSigningCert cert-pki-ca")

        # CA key algorithm
        config.set("CA", "pki_ca_signing_key_algorithm", self.ca_signing_algorithm)

        if self.clone:
            cafile = self.pkcs12_info[0]
            shutil.copy(cafile, paths.TMP_CA_P12)
            pent = pwd.getpwnam(PKI_USER)
            os.chown(paths.TMP_CA_P12, pent.pw_uid, pent.pw_gid)

            # Security domain registration
            config.set("CA", "pki_security_domain_hostname", self.master_host)
            config.set("CA", "pki_security_domain_https_port", "443")
            config.set("CA", "pki_security_domain_user", "admin")
            config.set("CA", "pki_security_domain_password", self.admin_password)

            # Clone
            config.set("CA", "pki_clone", "True")
            config.set("CA", "pki_clone_pkcs12_path", paths.TMP_CA_P12)
            config.set("CA", "pki_clone_pkcs12_password", self.dm_password)
            config.set("CA", "pki_clone_replication_security", "TLS")
            config.set("CA", "pki_clone_replication_master_port", str(self.master_replication_port))
            config.set("CA", "pki_clone_replication_clone_port", dogtag.install_constants.DS_PORT)
            config.set("CA", "pki_clone_replicate_schema", "False")
            config.set("CA", "pki_clone_uri", "https://%s" % ipautil.format_netloc(self.master_host, 443))

        # External CA
        if self.external == 1:
            config.set("CA", "pki_external", "True")
            config.set("CA", "pki_external_csr_path", self.csr_file)

            if self.ca_type == 'ms-cs':
                # Include MS template name extension in the CSR
                config.set("CA", "pki_req_ext_add", "True")
                config.set("CA", "pki_req_ext_oid", "1.3.6.1.4.1.311.20.2")
                config.set("CA", "pki_req_ext_critical", "False")
                config.set("CA", "pki_req_ext_data", "1E0A00530075006200430041")

        elif self.external == 2:
            cert = x509.load_certificate_from_file(self.cert_file)
            cert_file = tempfile.NamedTemporaryFile()
            x509.write_certificate(cert.der_data, cert_file.name)
            cert_file.flush()

            cert_chain, stderr, rc = ipautil.run(
                [paths.OPENSSL, 'crl2pkcs7',
                 '-certfile', self.cert_chain_file,
                 '-nocrl'])
            # Dogtag chokes on the header and footer, remove them
            # https://bugzilla.redhat.com/show_bug.cgi?id=1127838
            cert_chain = re.search(
                r'(?<=-----BEGIN PKCS7-----).*?(?=-----END PKCS7-----)',
                cert_chain, re.DOTALL).group(0)
            cert_chain_file = ipautil.write_tmp_file(cert_chain)

            config.set("CA", "pki_external", "True")
            config.set("CA", "pki_external_ca_cert_path", cert_file.name)
            config.set("CA", "pki_external_ca_cert_chain_path", cert_chain_file.name)
            config.set("CA", "pki_external_step_two", "True")

        # Generate configuration file
        with open(cfg_file, "wb") as f:
            config.write(f)

        self.backup_state('installed', True)
        try:
            DogtagInstance.spawn_instance(self, cfg_file)
        finally:
            os.remove(cfg_file)

        if self.external == 1:
            print "The next step is to get %s signed by your CA and re-run %s as:" % (self.csr_file, sys.argv[0])
            print "%s --external-cert-file=/path/to/signed_certificate --external-cert-file=/path/to/external_ca_certificate" % sys.argv[0]
            sys.exit(0)
        else:
            shutil.move(paths.CA_BACKUP_KEYS_P12,
                        paths.CACERT_P12)

        self.log.debug("completed creating ca instance")

    def create_instance(self):
        """
        If for some reason the instance doesn't exist, create a new one."
        """
        # Only used for Dogtag 9

        args = [paths.PKICREATE,
                '-pki_instance_root', paths.VAR_LIB,
                '-pki_instance_name',
                        self.dogtag_constants.PKI_INSTANCE_NAME,
                '-subsystem_type', 'ca',
                '-agent_secure_port',
                        str(self.dogtag_constants.AGENT_SECURE_PORT),
                '-ee_secure_port',
                        str(self.dogtag_constants.EE_SECURE_PORT),
                '-admin_secure_port',
                        str(self.dogtag_constants.ADMIN_SECURE_PORT),
                '-ee_secure_client_auth_port',
                        str(self.dogtag_constants.EE_CLIENT_AUTH_PORT),
                '-unsecure_port', str(self.dogtag_constants.UNSECURE_PORT),
                '-tomcat_server_port',
                        str(self.dogtag_constants.TOMCAT_SERVER_PORT),
                '-redirect', 'conf=/etc/pki-ca',
                '-redirect', 'logs=/var/log/pki-ca',
                '-enable_proxy'
        ]
        self.backup_state('installed', True)
        ipautil.run(args, env={'PKI_HOSTNAME':self.fqdn})

    def __configure_instance(self):
        # Only used for Dogtag 9
        preop_pin = get_preop_pin(
            self.server_root, self.dogtag_constants.PKI_INSTANCE_NAME)

        try:
            args = [paths.PERL, paths.PKISILENT,  "ConfigureCA",
                    "-cs_hostname", self.fqdn,
                    "-cs_port", str(self.dogtag_constants.ADMIN_SECURE_PORT),
                    "-client_certdb_dir", self.agent_db,
                    "-client_certdb_pwd", self.admin_password,
                    "-preop_pin" , preop_pin,
                    "-domain_name", self.security_domain_name,
                    "-admin_user", "admin",
                    "-admin_email",  "root@localhost",
                    "-admin_password", self.admin_password,
                    "-agent_name", "ipa-ca-agent",
                    "-agent_key_size", "2048",
                    "-agent_key_type", "rsa",
                    "-agent_cert_subject", str(DN(('CN', 'ipa-ca-agent'), self.subject_base)),
                    "-ldap_host", self.fqdn,
                    "-ldap_port", str(self.ds_port),
                    "-bind_dn", "cn=Directory Manager",
                    "-bind_password", self.dm_password,
                    "-base_dn", str(self.basedn),
                    "-db_name", "ipaca",
                    "-key_size", "2048",
                    "-key_type", "rsa",
                    "-key_algorithm", self.ca_signing_algorithm,
                    "-signing_algorithm", "SHA256withRSA",
                    "-save_p12", "true",
                    "-backup_pwd", self.admin_password,
                    "-subsystem_name", self.service_name,
                    "-token_name", "internal",
                    "-ca_subsystem_cert_subject_name", str(DN(('CN', 'CA Subsystem'), self.subject_base)),
                    "-ca_subsystem_cert_subject_name", str(DN(('CN', 'CA Subsystem'), self.subject_base)),
                    "-ca_ocsp_cert_subject_name", str(DN(('CN', 'OCSP Subsystem'), self.subject_base)),
                    "-ca_server_cert_subject_name", str(DN(('CN', self.fqdn), self.subject_base)),
                    "-ca_audit_signing_cert_subject_name", str(DN(('CN', 'CA Audit'), self.subject_base)),
                    "-ca_sign_cert_subject_name", str(DN(('CN', 'Certificate Authority'), self.subject_base)) ]
            if self.external == 1:
                args.append("-external")
                args.append("true")
                args.append("-ext_csr_file")
                args.append(self.csr_file)
            elif self.external == 2:
                cert = x509.load_certificate_from_file(self.cert_file)
                cert_file = tempfile.NamedTemporaryFile()
                x509.write_certificate(cert.der_data, cert_file.name)
                cert_file.flush()

                args.append("-external")
                args.append("true")
                args.append("-ext_ca_cert_file")
                args.append(cert_file.name)
                args.append("-ext_ca_cert_chain_file")
                args.append(self.cert_chain_file)
            else:
                args.append("-external")
                args.append("false")
            if self.clone:
                """sd = security domain -->  all CS systems get registered to
                   a security domain. This is set to the hostname and port of
                   the master CA.
                """
                # The install wizard expects the file to be here.
                cafile = self.pkcs12_info[0]
                shutil.copy(cafile, paths.PKI_ALIAS_CA_P12)
                pent = pwd.getpwnam(PKI_USER)
                os.chown(paths.PKI_ALIAS_CA_P12, pent.pw_uid, pent.pw_gid )
                args.append("-clone")
                args.append("true")
                args.append("-clone_p12_file")
                args.append("ca.p12")
                args.append("-clone_p12_password")
                args.append(self.dm_password)
                args.append("-sd_hostname")
                args.append(self.master_host)
                args.append("-sd_admin_port")
                args.append("443")
                args.append("-sd_admin_name")
                args.append("admin")
                args.append("-sd_admin_password")
                args.append(self.admin_password)
                args.append("-clone_master_port")
                args.append(str(self.master_replication_port))
                args.append("-clone_start_tls")
                args.append("true")
                args.append("-clone_uri")
                args.append("https://%s" % ipautil.format_netloc(self.master_host, 443))
            else:
                args.append("-clone")
                args.append("false")

            # Define the things we don't want logged
            nolog = (self.admin_password, self.dm_password,)

            ipautil.run(args, env={'PKI_HOSTNAME':self.fqdn}, nolog=nolog)
        except ipautil.CalledProcessError, e:
            self.handle_setup_error(e)

        if self.external == 1:
            print "The next step is to get %s signed by your CA and re-run %s as:" % (self.csr_file, sys.argv[0])
            print "%s --external-cert-file=/path/to/signed_certificate --external-cert-file=/path/to/external_ca_certificate" % sys.argv[0]
            sys.exit(0)

        # pkisilent makes a copy of the CA PKCS#12 file for us but gives
        # it a lousy name.
        if ipautil.file_exists(paths.ROOT_TMP_CA_P12):
            shutil.move(paths.ROOT_TMP_CA_P12, paths.CACERT_P12)

        self.log.debug("completed creating ca instance")

    def backup_config(self):
        try:
            backup_config(self.dogtag_constants)
        except Exception, e:
            root_logger.warning("Failed to backup CS.cfg: %s", e)

    def __disable_nonce(self):
        # Turn off Nonces
        update_result = installutils.update_file(
            self.dogtag_constants.CS_CFG_PATH, 'ca.enableNonces=true',
            'ca.enableNonces=false')
        if update_result != 0:
            raise RuntimeError("Disabling nonces failed")
        pent = pwd.getpwnam(PKI_USER)
        os.chown(self.dogtag_constants.CS_CFG_PATH,
                 pent.pw_uid, pent.pw_gid)

    def enable_pkix(self):
        installutils.set_directive(self.dogtag_constants.SYSCONFIG_FILE_PATH,
                                   'NSS_ENABLE_PKIX_VERIFY', '1',
                                   quotes=False, separator='=')

    def __issue_ra_cert(self):
        # The CA certificate is in the agent DB but isn't trusted
        (admin_fd, admin_name) = tempfile.mkstemp()
        os.write(admin_fd, self.admin_password)
        os.close(admin_fd)

        # Look through the cert chain to get all the certs we need to add
        # trust for
        p = subprocess.Popen([paths.CERTUTIL, "-d", self.agent_db,
                              "-O", "-n", "ipa-ca-agent"], stdout=subprocess.PIPE)

        chain = p.stdout.read()
        chain = chain.split("\n")

        root_nickname=[]
        for i in xrange(len(chain)):
            m = re.match('\ *"(.*)" \[.*', chain[i])
            if m:
                nick = m.groups(0)[0]
                if nick != "ipa-ca-agent" and nick[:7] != "Builtin":
                    root_nickname.append(m.groups()[0])

        try:
            for nick in root_nickname:
                self.__run_certutil(
                    ['-M', '-t', 'CT,C,C', '-n',
                     nick],
                     database=self.agent_db, pwd_file=self.admin_password)
        finally:
            os.remove(admin_name)

        # Retrieve the certificate request so we can get the values needed
        # to issue a certificate. Use sslget here because this is a
        # temporary database and nsslib doesn't currently support gracefully
        # opening and closing an NSS database. This would leave the installer
        # process stuck using this database during the entire cycle. We need
        # to use the final RA agent database when issuing certs for DS and
        # mod_nss.
        args = [
            paths.SSLGET,
            '-v',
            '-n', 'ipa-ca-agent',
            '-p', self.admin_password,
            '-d', self.agent_db,
            '-r', '/ca/agent/ca/profileReview?requestId=%s' % self.requestId,
            '%s' % ipautil.format_netloc(
                self.fqdn, self.dogtag_constants.AGENT_SECURE_PORT),
        ]
        (stdout, _stderr, _returncode) = ipautil.run(
            args, nolog=(self.admin_password,))

        data = stdout.split(self.dogtag_constants.RACERT_LINE_SEP)
        params = get_defList(data)
        params['requestId'] = find_substring(data, "requestId")
        params['op'] = 'approve'
        params['submit'] = 'submit'
        params['requestNotes'] = ''
        params = urllib.urlencode(params)

        # Now issue the RA certificate.
        args = [
            paths.SSLGET,
            '-v',
            '-n', 'ipa-ca-agent',
            '-p', self.admin_password,
            '-d', self.agent_db,
            '-e', params,
            '-r', '/ca/agent/ca/profileProcess',
            '%s' % ipautil.format_netloc(
                self.fqdn, self.dogtag_constants.AGENT_SECURE_PORT),
        ]
        (stdout, _stderr, _returncode) = ipautil.run(
            args, nolog=(self.admin_password,))

        data = stdout.split(self.dogtag_constants.RACERT_LINE_SEP)
        outputList = get_outputList(data)

        self.ra_cert = outputList['b64_cert']

        # Strip certificate headers and convert it to proper line ending
        self.ra_cert = x509.strip_header(self.ra_cert)
        self.ra_cert = "\n".join(line.strip() for line
                                 in self.ra_cert.splitlines() if line.strip())

        # Add the new RA cert to the database in /etc/httpd/alias
        (agent_fd, agent_name) = tempfile.mkstemp()
        os.write(agent_fd, self.ra_cert)
        os.close(agent_fd)
        try:
            self.__run_certutil(
                ['-A', '-t', 'u,u,u', '-n', 'ipaCert', '-a',
                 '-i', agent_name]
            )
        finally:
            os.remove(agent_name)

    def import_ra_cert(self, rafile):
        """
        Cloned RAs will use the same RA agent cert as the master so we
        need to import from a PKCS#12 file.

        Used when setting up replication
        """
        # Add the new RA cert to the database in /etc/httpd/alias
        (agent_fd, agent_name) = tempfile.mkstemp()
        os.write(agent_fd, self.dm_password)
        os.close(agent_fd)
        try:
            import_pkcs12(rafile, agent_name, self.ra_agent_db, self.ra_agent_pwd)
        finally:
            os.remove(agent_name)

        self.configure_agent_renewal()

    def __configure_ra(self):
        # Create an RA user in the CA LDAP server and add that user to
        # the appropriate groups so it can issue certificates without
        # manual intervention.
        conn = ipaldap.IPAdmin(self.fqdn, self.ds_port)
        conn.do_simple_bind(DN(('cn', 'Directory Manager')), self.dm_password)

        decoded = base64.b64decode(self.ra_cert)

        entry_dn = DN(('uid', "ipara"), ('ou', 'People'), self.basedn)
        entry = conn.make_entry(
            entry_dn,
            objectClass=['top', 'person', 'organizationalPerson',
                         'inetOrgPerson', 'cmsuser'],
            uid=["ipara"],
            sn=["ipara"],
            cn=["ipara"],
            usertype=["agentType"],
            userstate=["1"],
            userCertificate=[decoded],
            description=['2;%s;%s;%s' % (
                str(self.requestId),
                DN(('CN', 'Certificate Authority'), self.subject_base),
                DN(('CN', 'IPA RA'), self.subject_base))])

        conn.add_entry(entry)

        dn = DN(('cn', 'Certificate Manager Agents'), ('ou', 'groups'), self.basedn)
        modlist = [(0, 'uniqueMember', '%s' % entry_dn)]
        conn.modify_s(dn, modlist)

        dn = DN(('cn', 'Registration Manager Agents'), ('ou', 'groups'), self.basedn)
        modlist = [(0, 'uniqueMember', '%s' % entry_dn)]
        conn.modify_s(dn, modlist)

        conn.unbind()

    def __configure_profiles_acl(self):
        """Allow the Certificate Manager Agents group to modify profiles."""
        configure_profiles_acl()

    def __run_certutil(self, args, database=None, pwd_file=None, stdin=None):
        if not database:
            database = self.ra_agent_db
        if not pwd_file:
            pwd_file = self.ra_agent_pwd
        new_args = [paths.CERTUTIL, "-d", database, "-f", pwd_file]
        new_args = new_args + args
        return ipautil.run(new_args, stdin, nolog=(pwd_file,))

    def __create_ra_agent_db(self):
        if ipautil.file_exists(self.ra_agent_db + "/cert8.db"):
            ipautil.backup_file(self.ra_agent_db + "/cert8.db")
            ipautil.backup_file(self.ra_agent_db + "/key3.db")
            ipautil.backup_file(self.ra_agent_db + "/secmod.db")
            ipautil.backup_file(self.ra_agent_db + "/pwdfile.txt")

        if not ipautil.dir_exists(self.ra_agent_db):
            os.mkdir(self.ra_agent_db)

        # Create the password file for this db
        hex_str = binascii.hexlify(os.urandom(10))
        f = os.open(self.ra_agent_pwd, os.O_CREAT | os.O_RDWR)
        os.write(f, hex_str)
        os.close(f)
        os.chmod(self.ra_agent_pwd, stat.S_IRUSR)

        self.__run_certutil(["-N"])

    def __get_ca_chain(self):
        try:
            return dogtag.get_ca_certchain(ca_host=self.fqdn,
                dogtag_constants=self.dogtag_constants)
        except Exception, e:
            raise RuntimeError("Unable to retrieve CA chain: %s" % str(e))

    def __create_ca_agent_pkcs12(self):
        # Only used for Dogtag 9
        (pwd_fd, pwd_name) = tempfile.mkstemp()
        os.write(pwd_fd, self.admin_password)
        os.close(pwd_fd)
        try:
            ipautil.run([paths.PK12UTIL,
                         "-n", "ipa-ca-agent",
                         "-o", paths.DOGTAG_ADMIN_P12,
                         "-d", self.agent_db,
                         "-k", pwd_name,
                         "-w", pwd_name])
        finally:
            os.remove(pwd_name)

    def __import_ca_chain(self):
        chain = self.__get_ca_chain()

        # If this chain contains multiple certs then certutil will only import
        # the first one. So we have to pull them all out and import them
        # separately. Unfortunately no NSS tool can do this so we have to
        # use openssl.

        # Convert to DER because the chain comes back as one long string which
        # makes openssl throw up.
        data = base64.b64decode(chain)

        (certlist, _stderr, _returncode) = ipautil.run(
            [paths.OPENSSL,
             "pkcs7",
             "-inform",
             "DER",
             "-print_certs",
             ], stdin=data)

        # Ok, now we have all the certificates in certs, walk through it
        # and pull out each certificate and add it to our database

        st = 1
        en = 0
        subid = 0
        ca_dn = DN(('CN','Certificate Authority'), self.subject_base)
        while st > 0:
            st = certlist.find('-----BEGIN', en)
            en = certlist.find('-----END', en+1)
            if st > 0:
                try:
                    (chain_fd, chain_name) = tempfile.mkstemp()
                    os.write(chain_fd, certlist[st:en+25])
                    os.close(chain_fd)
                    (_rdn, subject_dn) = certs.get_cert_nickname(certlist[st:en+25])
                    if subject_dn == ca_dn:
                        nick = get_ca_nickname(self.realm)
                        trust_flags = 'CT,C,C'
                    else:
                        nick = str(subject_dn)
                        trust_flags = ',,'
                    self.__run_certutil(
                        ['-A', '-t', trust_flags, '-n', nick, '-a',
                         '-i', chain_name]
                    )
                finally:
                    os.remove(chain_name)
                    subid += 1

    def __request_ra_certificate(self):
        # Create a noise file for generating our private key
        noise = array.array('B', os.urandom(128))
        (noise_fd, noise_name) = tempfile.mkstemp()
        os.write(noise_fd, noise)
        os.close(noise_fd)

        # Generate our CSR. The result gets put into stdout
        try:
            (stdout, _stderr, _returncode) = self.__run_certutil(
                ["-R", "-k", "rsa", "-g", "2048", "-s",
                 str(DN(('CN', 'IPA RA'), self.subject_base)),
                 "-z", noise_name, "-a"])
        finally:
            os.remove(noise_name)

        csr = pkcs10.strip_header(stdout)

        # Send the request to the CA
        conn = httplib.HTTPConnection(
            self.fqdn, self.dogtag_constants.UNSECURE_PORT)
        params = urllib.urlencode({'profileId': 'caServerCert',
                'cert_request_type': 'pkcs10',
                'requestor_name': 'IPA Installer',
                'cert_request': csr,
                'xmlOutput': 'true'})
        headers = {"Content-type": "application/x-www-form-urlencoded",
                   "Accept": "text/plain"}

        conn.request("POST", "/ca/ee/ca/profileSubmit", params, headers)
        res = conn.getresponse()
        if res.status == 200:
            data = res.read()
            conn.close()
            doc = xml.dom.minidom.parseString(data)
            item_node = doc.getElementsByTagName("RequestId")
            self.requestId = item_node[0].childNodes[0].data
            doc.unlink()
            self.requestId = self.requestId.strip()
            if self.requestId is None:
                raise RuntimeError("Unable to determine RA certificate requestId")
        else:
            conn.close()
            raise RuntimeError("Unable to submit RA cert request")

    def fix_ra_perms(self):
        os.chmod(self.ra_agent_db + "/cert8.db", 0640)
        os.chmod(self.ra_agent_db + "/key3.db", 0640)
        os.chmod(self.ra_agent_db + "/secmod.db", 0640)

        pent = pwd.getpwnam("apache")
        os.chown(self.ra_agent_db + "/cert8.db", 0, pent.pw_gid )
        os.chown(self.ra_agent_db + "/key3.db", 0, pent.pw_gid )
        os.chown(self.ra_agent_db + "/secmod.db", 0, pent.pw_gid )
        os.chown(self.ra_agent_pwd, pent.pw_uid, pent.pw_gid)

    def __setup_sign_profile(self):
        # Tell the profile to automatically issue certs for RAs
        installutils.set_directive(self.dogtag_constants.SIGN_PROFILE,
                'auth.instance_id', 'raCertAuth', quotes=False, separator='=')

    def prepare_crl_publish_dir(self):
        """
        Prepare target directory for CRL publishing

        Returns a path to the CRL publishing directory
        """
        publishdir = self.dogtag_constants.CRL_PUBLISH_PATH

        if not os.path.exists(publishdir):
            os.mkdir(publishdir)

        os.chmod(publishdir, 0775)
        pent = pwd.getpwnam(PKI_USER)
        os.chown(publishdir, 0, pent.pw_gid)

        tasks.restore_context(publishdir)

        return publishdir


    def __enable_crl_publish(self):
        """
        Enable file-based CRL publishing and disable LDAP publishing.

        https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Certificate_System/8.0/html/Admin_Guide/Setting_up_Publishing.html
        """
        caconfig = self.dogtag_constants.CS_CFG_PATH

        publishdir = self.prepare_crl_publish_dir()

        # Enable file publishing, disable LDAP
        installutils.set_directive(caconfig, 'ca.publish.enable', 'true', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.ldappublish.enable', 'false', quotes=False, separator='=')

        # Create the file publisher, der only, not b64
        installutils.set_directive(caconfig, 'ca.publish.publisher.impl.FileBasedPublisher.class','com.netscape.cms.publish.publishers.FileBasedPublisher', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.crlLinkExt', 'bin', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.directory', publishdir, quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.latestCrlLink', 'true', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.pluginName', 'FileBasedPublisher', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.timeStamp', 'LocalTime', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.zipCRLs', 'false', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.zipLevel', '9', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.Filename.b64', 'false', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.publisher.instance.FileBaseCRLPublisher.Filename.der', 'true', quotes=False, separator='=')

        # The publishing rule
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.FileCrlRule.enable', 'true', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.FileCrlRule.mapper', 'NoMap', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.FileCrlRule.pluginName', 'Rule', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.FileCrlRule.predicate=', '', quotes=False, separator='')
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.FileCrlRule.publisher', 'FileBaseCRLPublisher', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.FileCrlRule.type', 'crl', quotes=False, separator='=')

        # Now disable LDAP publishing
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.LdapCaCertRule.enable', 'false', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.LdapCrlRule.enable', 'false', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.LdapUserCertRule.enable', 'false', quotes=False, separator='=')
        installutils.set_directive(caconfig, 'ca.publish.rule.instance.LdapXCertRule.enable', 'false', quotes=False, separator='=')

        # If we are the initial master then we are the CRL generator, otherwise
        # we point to that master for CRLs.
        if not self.clone:
            # These next two are defaults, but I want to be explicit that the
            # initial master is the CRL generator.
            installutils.set_directive(caconfig, 'ca.crl.MasterCRL.enableCRLCache', 'true', quotes=False, separator='=')
            installutils.set_directive(caconfig, 'ca.crl.MasterCRL.enableCRLUpdates', 'true', quotes=False, separator='=')
            installutils.set_directive(caconfig, 'ca.listenToCloneModifications', 'true', quotes=False, separator='=')
        else:
            installutils.set_directive(caconfig, 'ca.crl.MasterCRL.enableCRLCache', 'false', quotes=False, separator='=')
            installutils.set_directive(caconfig, 'ca.crl.MasterCRL.enableCRLUpdates', 'false', quotes=False, separator='=')
            installutils.set_directive(caconfig, 'ca.listenToCloneModifications', 'false', quotes=False, separator='=')

    def uninstall(self):
        # just eat state
        self.restore_state("enabled")

        if self.dogtag_constants.DOGTAG_VERSION >= 10:
            DogtagInstance.uninstall(self)
        else:
            if self.is_configured():
                self.print_msg("Unconfiguring CA")

            try:
                ipautil.run([paths.PKIREMOVE,
                             "-pki_instance_root=%s" % paths.VAR_LIB,
                             "-pki_instance_name=%s" %
                                self.dogtag_constants.PKI_INSTANCE_NAME,
                             "--force"])
            except ipautil.CalledProcessError, e:
                self.log.critical("failed to uninstall CA instance %s", e)

        self.restore_state("installed")

        # At one time we removed this user on uninstall. That can potentially
        # orphan files, or worse, if another useradd runs in the interim,
        # cause files to have a new owner.
        self.restore_state("user_exists")

        services.knownservices.messagebus.start()
        cmonger = services.knownservices.certmonger
        cmonger.start()

        bus = dbus.SystemBus()
        obj = bus.get_object('org.fedorahosted.certmonger',
                             '/org/fedorahosted/certmonger')
        iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
        path = iface.find_ca_by_nickname('dogtag-ipa-ca-renew-agent')
        if path:
            iface.remove_known_ca(path)

        helper = self.restore_state('certmonger_dogtag_helper')
        if helper:
            path = iface.find_ca_by_nickname('dogtag-ipa-renew-agent')
            if path:
                ca_obj = bus.get_object('org.fedorahosted.certmonger', path)
                ca_iface = dbus.Interface(ca_obj,
                                          'org.freedesktop.DBus.Properties')
                ca_iface.Set('org.fedorahosted.certmonger.ca',
                             'external-helper', helper)

        cmonger.stop()

        # remove CRL files
        self.log.info("Remove old CRL files")
        try:
            for f in get_crl_files():
                self.log.debug("Remove %s", f)
                installutils.remove_file(f)
        except OSError, e:
            self.log.warning("Error while removing old CRL files: %s", e)

        # remove CRL directory
        self.log.info("Remove CRL directory")
        if os.path.exists(self.dogtag_constants.CRL_PUBLISH_PATH):
            try:
                shutil.rmtree(self.dogtag_constants.CRL_PUBLISH_PATH)
            except OSError, e:
                self.log.warning("Error while removing CRL publish "
                                    "directory: %s", e)

    def publish_ca_cert(self, location):
        args = ["-L", "-n", self.canickname, "-a"]
        (cert, _err, _returncode) = self.__run_certutil(args)
        fd = open(location, "w+")
        fd.write(cert)
        fd.close()
        os.chmod(location, 0444)


    def configure_certmonger_renewal(self):
        super(CAInstance, self).configure_certmonger_renewal()

        self.configure_certmonger_renewal_guard()

    def configure_certmonger_renewal_guard(self):
        if not self.is_configured():
            return

        bus = dbus.SystemBus()
        obj = bus.get_object('org.fedorahosted.certmonger',
                             '/org/fedorahosted/certmonger')
        iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
        path = iface.find_ca_by_nickname('dogtag-ipa-renew-agent')
        if path:
            ca_obj = bus.get_object('org.fedorahosted.certmonger', path)
            ca_iface = dbus.Interface(ca_obj,
                                      'org.freedesktop.DBus.Properties')
            helper = ca_iface.Get('org.fedorahosted.certmonger.ca',
                                  'external-helper')
            if helper:
                args = shlex.split(helper)
                if args[0] != paths.IPA_SERVER_GUARD:
                    self.backup_state('certmonger_dogtag_helper', helper)
                    args = [paths.IPA_SERVER_GUARD] + args
                    helper = ' '.join(pipes.quote(a) for a in args)
                    ca_iface.Set('org.fedorahosted.certmonger.ca',
                                 'external-helper', helper)

    def configure_agent_renewal(self):
        try:
            certmonger.dogtag_start_tracking(
                ca='dogtag-ipa-ca-renew-agent',
                nickname='ipaCert',
                pin=None,
                pinfile=paths.ALIAS_PWDFILE_TXT,
                secdir=paths.HTTPD_ALIAS_DIR,
                pre_command=None,
                post_command='renew_ra_cert')
        except RuntimeError, e:
            self.log.error(
                "certmonger failed to start tracking certificate: %s", e)

    def stop_tracking_certificates(self):
        """Stop tracking our certificates. Called on uninstall.
        """
        super(CAInstance, self).stop_tracking_certificates(False)

        try:
            certmonger.stop_tracking(paths.HTTPD_ALIAS_DIR, nickname='ipaCert')
        except RuntimeError, e:
            root_logger.error(
                "certmonger failed to stop tracking certificate: %s", e)

        services.knownservices.certmonger.stop()


    def set_audit_renewal(self):
        """
        The default renewal time for the audit signing certificate is
        six months rather than two years. Fix it. This is BZ 843979.
        """
        # Check the default validity period of the audit signing cert
        # and set it to 2 years if it is 6 months.
        cert_range = installutils.get_directive(
            '%s/caSignedLogCert.cfg' % self.dogtag_constants.SERVICE_PROFILE_DIR,
            'policyset.caLogSigningSet.2.default.params.range',
            separator='='
        )
        self.log.debug(
            'caSignedLogCert.cfg profile validity range is %s', cert_range)
        if cert_range == "180":
            installutils.set_directive(
                '%s/caSignedLogCert.cfg' % self.dogtag_constants.SERVICE_PROFILE_DIR,
                'policyset.caLogSigningSet.2.default.params.range',
                '720',
                quotes=False,
                separator='='
            )
            installutils.set_directive(
                '%s/caSignedLogCert.cfg' % self.dogtag_constants.SERVICE_PROFILE_DIR,
                'policyset.caLogSigningSet.2.constraint.params.range',
                '720',
                quotes=False,
                separator='='
            )
            self.log.debug(
                'updated caSignedLogCert.cfg profile validity range to 720')
            return True
        return False

    def is_renewal_master(self, fqdn=None):
        if fqdn is None:
            fqdn = api.env.host

        if not self.admin_conn:
            self.ldap_connect()

        dn = DN(('cn', 'CA'), ('cn', fqdn), ('cn', 'masters'), ('cn', 'ipa'),
                ('cn', 'etc'), api.env.basedn)
        renewal_filter = '(ipaConfigString=caRenewalMaster)'
        try:
            self.admin_conn.get_entries(base_dn=dn, filter=renewal_filter,
                                        attrs_list=[])
        except errors.NotFound:
            return False

        return True

    def set_renewal_master(self, fqdn=None):
        if fqdn is None:
            fqdn = api.env.host

        if not self.admin_conn:
            self.ldap_connect()

        base_dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
                     api.env.basedn)
        filter = '(&(cn=CA)(ipaConfigString=caRenewalMaster))'
        try:
            entries = self.admin_conn.get_entries(
                base_dn=base_dn, filter=filter, attrs_list=['ipaConfigString'])
        except errors.NotFound:
            entries = []

        dn = DN(('cn', 'CA'), ('cn', fqdn), base_dn)
        master_entry = self.admin_conn.get_entry(dn, ['ipaConfigString'])

        for entry in entries:
            if master_entry is not None and entry.dn == master_entry.dn:
                master_entry = None
                continue

            entry['ipaConfigString'] = [x for x in entry['ipaConfigString']
                                        if x.lower() != 'carenewalmaster']
            self.admin_conn.update_entry(entry)

        if master_entry is not None:
            master_entry['ipaConfigString'].append('caRenewalMaster')
            self.admin_conn.update_entry(master_entry)

    @staticmethod
    def update_cert_config(nickname, cert, dogtag_constants=None):
        """
        When renewing a CA subsystem certificate the configuration file
        needs to get the new certificate as well.

        nickname is one of the known nicknames.
        cert is a DER-encoded certificate.
        """

        if dogtag_constants is None:
            dogtag_constants = dogtag.configured_constants()

        # The cert directive to update per nickname
        directives = {'auditSigningCert cert-pki-ca': 'ca.audit_signing.cert',
                      'ocspSigningCert cert-pki-ca': 'ca.ocsp_signing.cert',
                      'caSigningCert cert-pki-ca': 'ca.signing.cert',
                      'subsystemCert cert-pki-ca': 'ca.subsystem.cert',
                      'Server-Cert cert-pki-ca': 'ca.sslserver.cert'}

        try:
            backup_config(dogtag_constants)
        except Exception, e:
            syslog.syslog(syslog.LOG_ERR, "Failed to backup CS.cfg: %s" % e)

        DogtagInstance.update_cert_cs_cfg(
            nickname, cert, directives,
            dogtag.configured_constants().CS_CFG_PATH,
            dogtag_constants)

def replica_ca_install_check(config):
    if not config.setup_ca:
        return

    cafile = config.dir + "/cacert.p12"
    if not ipautil.file_exists(cafile):
        # Replica of old "self-signed" master - CA won't be installed
        return

    # Exit if we have an old-style (Dogtag 9) CA already installed
    ca = CAInstance(config.realm_name, certs.NSS_DIR,
        dogtag_constants=dogtag.Dogtag9Constants)
    if ca.is_installed():
        root_logger.info('Dogtag 9 style CA instance found')
        sys.exit("A CA is already configured on this system.")

    if config.ca_ds_port != dogtag.Dogtag9Constants.DS_PORT:
        root_logger.debug(
            'Installing CA Replica from master with a merged database')
        return

    # Check if the master has the necessary schema in its CA instance
    ca_ldap_url = 'ldap://%s:%s' % (config.master_host_name, config.ca_ds_port)
    objectclass = 'ipaObject'
    root_logger.debug('Checking if IPA schema is present in %s', ca_ldap_url)
    try:
        with ipaldap.LDAPClient(ca_ldap_url,
                                start_tls=True,
                                force_schema_updates=False) as connection:
            connection.simple_bind(DN(('cn', 'Directory Manager')),
                                   config.dirman_password)
            rschema = connection.schema
            result = rschema.get_obj(ldap.schema.models.ObjectClass,
                                     objectclass)
    except Exception:
        root_logger.critical(
            'CA DS schema check failed. Make sure the PKI service on the '
            'remote master is operational.')
        raise
    if result:
        root_logger.debug('Check OK')
    else:
        root_logger.critical(
            'The master CA directory server does not have necessary schema. '
            'Please copy the following script to all CA masters and run it '
            'on them: %s\n'
            'If you are certain that this is a false positive, use '
            '--skip-schema-check.',
                os.path.join(ipautil.SHARE_DIR, 'copy-schema-to-ca.py'))
        exit('IPA schema missing on master CA directory server')


def install_replica_ca(config, postinstall=False):
    """
    Install a CA on a replica.

    There are two modes of doing this controlled:
      - While the replica is being installed
      - Post-replica installation

    config is a ReplicaConfig object

    Returns a tuple of the CA and CADS instances
    """
    cafile = config.dir + "/cacert.p12"

    if not ipautil.file_exists(cafile):
        # Replica of old "self-signed" master - skip installing CA
        return None

    if not config.setup_ca:
        # We aren't configuring the CA in this step but we still need
        # a minimum amount of information on the CA for this IPA install.
        ca = CAInstance(config.realm_name, certs.NSS_DIR,
            dogtag_constants=dogtag.install_constants)
        ca.dm_password = config.dirman_password
        ca.subject_base = config.subject_base
        return ca

    ca = CAInstance(config.realm_name, certs.NSS_DIR,
        dogtag_constants=dogtag.install_constants)
    ca.dm_password = config.dirman_password
    ca.subject_base = config.subject_base
    if ca.is_installed():
        sys.exit("A CA is already configured on this system.")

    ca = CAInstance(config.realm_name, certs.NSS_DIR,
            dogtag_constants=dogtag.install_constants)
    if postinstall:
        # If installing this afterward the Apache NSS database already
        # exists, don't remove it.
        ca.create_ra_agent_db = False
    ca.configure_instance(config.host_name, config.domain_name,
                          config.dirman_password, config.dirman_password,
                          pkcs12_info=(cafile,),
                          master_host=config.master_host_name,
                          master_replication_port=config.ca_ds_port,
                          subject_base=config.subject_base)

    # Restart httpd since we changed it's config and added ipa-pki-proxy.conf
    # Without the restart, CA service status check would fail due to missing
    # proxy
    if postinstall:
        services.knownservices.httpd.restart()


    # The dogtag DS instance needs to be restarted after installation.
    # The procedure for this is: stop dogtag, stop DS, start DS, start
    # dogtag
    #
    #
    # The service_name trickery is due to the service naming we do
    # internally. In the case of the dogtag DS the name doesn't match the
    # unix service.

    service.print_msg("Restarting the directory and certificate servers")
    ca.stop(dogtag.install_constants.PKI_INSTANCE_NAME)

    services.knownservices.dirsrv.restart()

    ca.start(dogtag.install_constants.PKI_INSTANCE_NAME)

    return ca

def backup_config(dogtag_constants=None):
    """
    Create a backup copy of CS.cfg
    """
    if dogtag_constants is None:
        dogtag_constants = dogtag.configured_constants()

    if services.knownservices[dogtag_constants.SERVICE_NAME].is_running(
        dogtag_constants.PKI_INSTANCE_NAME):
        raise RuntimeError("Dogtag must be stopped when creating backup of %s"
                           % dogtag_constants.CS_CFG_PATH)
    shutil.copy(dogtag_constants.CS_CFG_PATH,
                dogtag_constants.CS_CFG_PATH + '.ipabkp')

def update_people_entry(dercert):
    """
    Update the userCerticate for an entry in the dogtag ou=People. This
    is needed when a certificate is renewed.

    dercert: An X509.3 certificate in DER format

    Logging is done via syslog

    Returns True or False
    """
    base_dn = DN(('ou','People'), ('o','ipaca'))
    serial_number = x509.get_serial_number(dercert, datatype=x509.DER)
    subject = x509.get_subject(dercert, datatype=x509.DER)
    issuer = x509.get_issuer(dercert, datatype=x509.DER)

    attempts = 0
    server_id = installutils.realm_to_serverid(api.env.realm)
    dogtag_uri = 'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % server_id
    updated = False

    while attempts < 10:
        conn = None
        try:
            conn = ldap2.ldap2(api, ldap_uri=dogtag_uri)
            conn.connect(autobind=True)

            db_filter = conn.make_filter(
                {'description': ';%s;%s' % (issuer, subject)},
                exact=False, trailing_wildcard=False)
            try:
                entries = conn.get_entries(base_dn, conn.SCOPE_SUBTREE, db_filter)
            except errors.NotFound:
                entries = []

            updated = True

            for entry in entries:
                syslog.syslog(
                    syslog.LOG_NOTICE, 'Updating entry %s' % str(entry.dn))

                try:
                    entry['usercertificate'].append(dercert)
                    entry['description'] = '2;%d;%s;%s' % (
                        serial_number, issuer, subject)

                    conn.update_entry(entry)
                except errors.EmptyModlist:
                    pass
                except Exception, e:
                    syslog.syslog(
                        syslog.LOG_ERR,
                        'Updating entry %s failed: %s' % (str(entry.dn), e))
                    updated = False

            break
        except errors.NetworkError:
            syslog.syslog(
                syslog.LOG_ERR,
                'Connection to %s failed, sleeping 30s' % dogtag_uri)
            time.sleep(30)
            attempts += 1
        except Exception, e:
            syslog.syslog(syslog.LOG_ERR, 'Caught unhandled exception: %s' % e)
            break
        finally:
            if conn is not None and conn.isconnected():
                conn.disconnect()

    if not updated:
        syslog.syslog(syslog.LOG_ERR, 'Update failed.')
        return False

    return True

def ensure_ldap_profiles_container():
    server_id = installutils.realm_to_serverid(api.env.realm)
    dogtag_uri = 'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % server_id

    conn = ldap2.ldap2(api, ldap_uri=dogtag_uri)
    if not conn.isconnected():
        conn.connect(autobind=True)

    dn = DN(('ou', 'certificateProfiles'), ('ou', 'ca'), ('o', 'ipaca'))
    try:
        conn.get_entry(dn)
    except errors.NotFound:
        # entry doesn't exist; add it
        entry = conn.make_entry(
            dn,
            objectclass=['top', 'organizationalUnit'],
            ou=['certificateProfiles'],
        )
        conn.add_entry(entry)

    conn.disconnect()


def configure_profiles_acl():
    server_id = installutils.realm_to_serverid(api.env.realm)
    dogtag_uri = 'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % server_id
    updated = False

    dn = DN(('cn', 'aclResources'), ('o', 'ipaca'))
    rule = (
        'certServer.profile.configuration:read,modify:allow (read,modify) '
        'group="Certificate Manager Agents":'
        'Certificate Manager agents may modify (create/update/delete) and read profiles'
    )
    modlist = [(ldap.MOD_ADD, 'resourceACLS', [rule])]

    conn = ldap2.ldap2(api, ldap_uri=dogtag_uri)
    if not conn.isconnected():
        conn.connect(autobind=True)
    rules = conn.get_entry(dn).get('resourceACLS', [])
    if rule not in rules:
        conn.conn.modify_s(str(dn), modlist)
        updated = True

    conn.disconnect()
    return updated

def import_included_profiles():
    sub_dict = dict(
        DOMAIN=ipautil.format_netloc(api.env.domain),
        IPA_CA_RECORD=IPA_CA_RECORD,
        CRL_ISSUER='CN=Certificate Authority,o=ipaca',
        SUBJECT_DN_O=dsinstance.DsInstance().find_subject_base(),
    )

    server_id = installutils.realm_to_serverid(api.env.realm)
    dogtag_uri = 'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % server_id
    conn = ldap2.ldap2(api, ldap_uri=dogtag_uri)
    if not conn.isconnected():
        conn.connect(autobind=True)

    api.Backend.ra_certprofile._read_password()
    api.Backend.ra_certprofile.override_port = 8443

    for (profile_id, desc, store_issued) in dogtag.INCLUDED_PROFILES:
        dn = DN(('cn', profile_id),
            api.env.container_certprofile, api.env.basedn)
        try:
            conn.get_entry(dn)
            continue  # the profile is present
        except errors.NotFound:
            # profile not found; add it
            entry = conn.make_entry(
                dn,
                objectclass=['ipacertprofile'],
                cn=[profile_id],
                description=[desc],
                ipacertprofilestoreissued=['TRUE' if store_issued else 'FALSE'],
            )
            conn.add_entry(entry)
            profile_data = ipautil.template_file(
                '/usr/share/ipa/profiles/{}.cfg'.format(profile_id), sub_dict)
            _create_dogtag_profile(profile_id, profile_data)
            root_logger.info("Imported profile '%s'", profile_id)

    api.Backend.ra_certprofile.override_port = None
    conn.disconnect()


def migrate_profiles_to_ldap():
    """Migrate profiles from filesystem to LDAP.

    This must be run *after* switching to the LDAPProfileSubsystem
    and restarting the CA.

    The profile might already exist, e.g. if a replica was already
    upgraded, so this case is ignored.

    """
    ensure_ldap_profiles_container()

    api.Backend.ra_certprofile._read_password()
    api.Backend.ra_certprofile.override_port = 8443

    with open(dogtag.configured_constants().CS_CFG_PATH) as f:
        cs_cfg = f.read()
    match = re.search(r'^profile\.list=(\S*)', cs_cfg, re.MULTILINE)
    profile_ids = match.group(1).split(',')

    for profile_id in profile_ids:
        match = re.search(
            r'^profile\.{}\.config=(\S*)'.format(profile_id),
            cs_cfg, re.MULTILINE
        )
        if match is None:
            root_logger.info("No file for profile '%s'; skipping", profile_id)
            continue
        filename = match.group(1)

        match = re.search(
            r'^profile\.{}\.class_id=(\S*)'.format(profile_id),
            cs_cfg, re.MULTILINE
        )
        if match is None:
            root_logger.info("No class_id for profile '%s'; skipping", profile_id)
            continue
        class_id = match.group(1)

        root_logger.info("Migrating profile '%s' to LDAP", profile_id)
        with open(filename) as f:
            profile_data = f.read()
            if profile_data[-1] != '\n':
                profile_data += '\n'
            profile_data += 'profileId={}\n'.format(profile_id)
            profile_data += 'classId={}\n'.format(class_id)
            _create_dogtag_profile(profile_id, profile_data)

    api.Backend.ra_certprofile.override_port = None


def _create_dogtag_profile(profile_id, profile_data):
    with api.Backend.ra_certprofile as profile_api:
        # import the profile
        try:
            profile_api.create_profile(profile_data)
        except errors.RemoteRetrieveError:
            # conflicting profile; replace it if we are
            # installing IPA, but keep it for upgrades
            if api.env.context == 'installer':
                try:
                    profile_api.disable_profile(profile_id)
                except errors.RemoteRetrieveError:
                    root_logger.debug(
                        "Failed to disable profile '%s' "
                        "(it is probably already disabled)")
                profile_api.delete_profile(profile_id)
                profile_api.create_profile(profile_data)

        # enable the profile
        try:
            profile_api.enable_profile(profile_id)
        except errors.RemoteRetrieveError:
            root_logger.debug(
                "Failed to enable profile '%s' "
                "(it is probably already enabled)")


if __name__ == "__main__":
    standard_logging_setup("install.log")
    ds = dsinstance.DsInstance()

    ca = CAInstance("EXAMPLE.COM", paths.HTTPD_ALIAS_DIR)
    ca.configure_instance("catest.example.com", "example.com", "password", "password")
