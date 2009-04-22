# Authors: Rob Crittenden <rcritten@redhat.com>
#          Ade Lee <alee@redhat.com>
#          Andrew Wnuk <awnuk@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import logging
import pwd
import os
import sys
import re
import time
import ldap
import base64
import array
import tempfile
import binascii
import shutil
import httplib
import urllib
import xml.dom.minidom
import stat
from ipapython import dogtag

from nss.error import NSPRError
import nss.nss as nss

from ipapython import ipautil
from ipapython import nsslib

from ipaserver.install import service
from ipaserver.install import installutils
from ipaserver import ipaldap
from ipaserver.install import dsinstance
from ipalib import util

DEFAULT_DSPORT=7389

# We need to reset the template because the CA uses the regular boot
# information
INF_TEMPLATE = """
[General]
FullMachineName=   $FQHN
SuiteSpotUserID=   $USER
ServerRoot=    $SERVER_ROOT
[slapd]
ServerPort=   $DSPORT
ServerIdentifier=   $SERVERID
Suffix=   $SUFFIX
RootDN=   cn=Directory Manager
RootDNPwd= $PASSWORD
"""

def get_preop_pin(instance_root, instance_name):
    preop_pin = None

    filename = instance_root + "/" + instance_name + "/conf/CS.cfg"

    # read the config file and get the preop pin
    try:
        f=open(filename)
    except IOError, e:
        logging.error("Cannot open configuration file." + str(e))
        raise e
    data = f.read()
    data = data.split('\n')
    pattern = re.compile("preop.pin=(.*)" )
    for line in data:
        match = re.search(pattern, line)
        if (match):
            preop_pin=match.group(1)
            break

    return preop_pin

def export_pkcs12(output_file, output_passwd, nickname, cert_database,
                  cert_passwd):
    ipautil.run(["/usr/bin/pk12util", "-d", cert_database,
                 "-o", output_file,
                 "-n", nickname,
                 "-k", cert_passwd,
                 "-w", output_passwd])

def client_auth_data_callback(ca_names, chosen_nickname, password, certdb):
    cert = None
    if chosen_nickname:
        try:
            cert = nss.find_cert_from_nickname(chosen_nickname, password)
            priv_key = nss.find_key_by_any_cert(cert, password)
            return cert, priv_key
        except NSPRError, e:
            logging.debug("client auth callback failed %s" % str(e))
            return False
    else:
        nicknames = nss.get_cert_nicknames(certdb, nss.SEC_CERT_NICKNAMES_USER)
        for nickname in nicknames:
            try:
                cert = nss.find_cert_from_nickname(nickname, password)
                if cert.check_valid_times():
                    if cert.has_signer_in_ca_names(ca_names):
                        priv_key = nss.find_key_by_any_cert(cert, password)
                        return cert, priv_key
            except NSPRError, e:
                logging.debug("client auth callback failed %s" % str(e))
                return False
        return False

def get_value(s):
    """
    Parse out a name/value pair from a Javascript variable.
    """
    try:
        expr = s.split('=',1)
        value = expr[1]
        value = value.replace('\"', '')
        value = value.replace(';','')
        value = value.replace('\\n','\n')
        value = value.replace('\\r','\r')
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

    A certificate signing request is specfied as a series of these.
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

class CADSInstance(service.Service):
    def __init__(self, realm_name=None, domain_name=None, dm_password=None):
        service.Service.__init__(self, "pkids")
        self.realm_name = realm_name
        self.dm_password = dm_password
        self.sub_dict = None
        self.domain = domain_name
        self.serverid = None
        self.host_name = None
        self.pkcs12_info = None
        self.ds_user = None
        self.ds_port = None
        if realm_name:
            self.suffix = util.realm_to_suffix(self.realm_name)
            self.__setup_sub_dict()
        else:
            self.suffix = None

    def create_instance(self, ds_user, realm_name, host_name, domain_name, dm_password, pkcs12_info=None, ds_port=DEFAULT_DSPORT):
        self.ds_user = ds_user
        self.ds_port = ds_port
        self.realm_name = realm_name.upper()
        self.serverid = "PKI-IPA"
        self.suffix = util.realm_to_suffix(self.realm_name)
        self.host_name = host_name
        self.dm_password = dm_password
        self.domain = domain_name
        self.pkcs12_info = pkcs12_info
        self.__setup_sub_dict()

        self.step("creating directory server user", self.__create_ds_user)
        self.step("creating directory server instance", self.__create_instance)
        self.step("configuring directory to start on boot", self.__enable)
        self.step("restarting directory server", self.__restart_instance)

        self.start_creation("Configuring directory server for the CA:")

    def __setup_sub_dict(self):
        server_root = dsinstance.find_server_root()
        self.sub_dict = dict(FQHN=self.host_name, SERVERID=self.serverid,
                             PASSWORD=self.dm_password, SUFFIX=self.suffix.lower(),
                             REALM=self.realm_name, USER=self.ds_user,
                             SERVER_ROOT=server_root, DOMAIN=self.domain,
                             TIME=int(time.time()), DSPORT=self.ds_port)

    def __enable(self):
        name = self.service_name
        self.service_name="dirsrv"
        self.backup_state("enabled", self.is_enabled())
        self.chkconfig_on()
        self.service_name = name

    def __create_ds_user(self):
        user_exists = True
        try:
            pwd.getpwnam(self.ds_user)
            logging.debug("ds user %s exists" % self.ds_user)
        except KeyError:
            user_exists = False
            logging.debug("adding ds user %s" % self.ds_user)
            args = ["/usr/sbin/useradd", "-c", "DS System User", "-d", "/var/lib/dirsrv", "-M", "-r", "-s", "/sbin/nologin", self.ds_user]
            try:
                ipautil.run(args)
                logging.debug("done adding user")
            except ipautil.CalledProcessError, e:
                logging.critical("failed to add user %s" % e)

        self.backup_state("user", self.ds_user)
        self.backup_state("user_exists", user_exists)

    def __create_instance(self):
        self.backup_state("running", dsinstance.is_ds_running())
        self.backup_state("serverid", self.serverid)

        inf_txt = ipautil.template_str(INF_TEMPLATE, self.sub_dict)
        logging.debug("writing inf template")
        inf_fd = ipautil.write_tmp_file(inf_txt)
        inf_txt = re.sub(r"RootDNPwd=.*\n", "", inf_txt)
        logging.debug(inf_txt)
        if ipautil.file_exists("/usr/sbin/setup-ds.pl"):
            args = ["/usr/sbin/setup-ds.pl", "--silent", "--logfile", "-", "-f", inf_fd.name]
            logging.debug("calling setup-ds.pl")
        else:
            args = ["/usr/bin/ds_newinst.pl", inf_fd.name]
            logging.debug("calling ds_newinst.pl")
        try:
            ipautil.run(args)
            logging.debug("completed creating ds instance")
        except ipautil.CalledProcessError, e:
            logging.critical("failed to restart ds instance %s" % e)
        inf_fd.close()

    def __restart_instance(self):
        try:
            # Have to trick the base class to use the right service name
            sav_name = self.service_name
            self.service_name="dirsrv"
            self.restart(self.serverid)
            self.service_name=sav_name
            if not dsinstance.is_ds_running():
                logging.critical("Failed to restart the directory server. See the installation log for details.")
                sys.exit(1)
        except Exception:
            # TODO: roll back here?
            logging.critical("Failed to restart the directory server. See the installation log for details.")

    def uninstall(self):
        running = self.restore_state("running")
        enabled = self.restore_state("enabled")
        serverid = self.restore_state("serverid")
        sav_name = self.service_name
        self.service_name="dirsrv"

        if not running is None:
            self.stop(serverid)

        if not enabled is None and not enabled:
            self.chkconfig_off()

        if not serverid is None:
            dsinstance.erase_ds_instance_data(serverid)

        ds_user = self.restore_state("user")
        user_exists = self.restore_state("user_exists")

        if not ds_user is None and not user_exists is None and not user_exists:
            try:
                ipautil.run(["/usr/sbin/userdel", ds_user])
            except ipautil.CalledProcessError, e:
                logging.critical("failed to delete user %s" % e)
        self.service_name = sav_name


class CAInstance(service.Service):
    """
    In the self-signed case (all done in certs.py) the CA exists in the DS
    database. When using a dogtag CA the DS database contains just the
    server cert for DS. The mod_nss database will contain the RA agent
    cert that will be used to do authenticated requests against dogtag.

    This is done because we use python-nss and will inherit the opened
    NSS database in mod_python. In nsslib.py we do an nssinit but this will
    return success if the database is already initialized. It doesn't care
    if the database is different or not.
    """

    def __init__(self):
        service.Service.__init__(self, "pki-ca")
        self.pki_user = None
        self.dm_password = None
        self.admin_password = None
        self.host_name = None

        # The same database is used for mod_nss because the NSS context
        # will already have been initialized by Apache by the time
        # mod_python wants to do things.
        self.canickname = "CA certificate"
        self.basedn = "o=ipaca"
        self.ca_agent_db = tempfile.mkdtemp(prefix = "tmp-")
        self.ra_agent_db = "/etc/httpd/alias"
        self.ra_agent_pwd = self.ra_agent_db + "/pwdfile.txt"
        self.ds_port = DEFAULT_DSPORT
        self.domain_name = "IPA"
        self.server_root = "/var/lib"
        self.secure_port = 9444
        self.ra_cert = None
        self.requestId = None

    def __del__(self):
        shutil.rmtree(self.ca_agent_db, ignore_errors=True)

    def configure_instance(self, pki_user, host_name, dm_password, admin_password, ds_port=DEFAULT_DSPORT):
        self.pki_user = pki_user
        self.host_name = host_name
        self.dm_password = dm_password
        self.admin_password = admin_password
        self.ds_port = ds_port

        if not ipautil.dir_exists("/var/lib/pki-ca"):
            self.step("creating pki-ca instance", self.create_instance)
        self.step("creating certificate server user", self.__create_ca_user)
        self.step("configuring certificate server instance", self.__configure_instance)
        self.step("creating CA agent PKCS#12 file in /root", self.__create_ca_agent_pkcs12)
        self.step("creating RA agent certificate database", self.__create_ra_agent_db)
        self.step("importing CA chain to RA certificate database", self.__import_ca_chain)
        self.step("requesting RA certificate from CA", self.__request_ra_certificate)
        self.step("issuing RA agent certificate", self.__issue_ra_cert)
        self.step("adding RA agent as a trusted user", self.__configure_ra)
        self.step("fixing RA database permissions", self.__fix_ra_perms)
        self.step("setting up signing cert profile", self.__setup_sign_profile)
        self.step("configuring certificate server to start on boot", self.__enable)
        self.step("restarting certificate server", self.__restart_instance)

        self.start_creation("Configuring certificate server:")

    def create_instance(self):
        """
        If for some reason the instance doesn't exist, create a new one."

        These values come from /usr/share/pki/ca/setup/postinstall
        """
        PKI_INSTANCE_NAME="pki-ca"
        AGENT_SECURE_PORT="9443"
        EE_SECURE_PORT="9444"
        ADMIN_SECURE_PORT="9445"
        UNSECURE_PORT="9180"
        TOMCAT_SERVER_PORT="9701"

        args = ['/usr/bin/pkicreate',
                '-pki_instance_root', '/var/lib',
                '-pki_instance_name', PKI_INSTANCE_NAME,
                '-subsystem_type', 'ca',
                '-agent_secure_port', AGENT_SECURE_PORT,
                '-ee_secure_port', EE_SECURE_PORT,
                '-admin_secure_port', ADMIN_SECURE_PORT,
                '-unsecure_port', UNSECURE_PORT,
                '-tomcat_server_port', TOMCAT_SERVER_PORT,
                '-redirect', 'conf=/etc/pki-ca',
                '-redirect', 'logs=/var/log/pki-ca',
        ]
        ipautil.run(args)

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        self.chkconfig_on()

    def __create_ca_user(self):
        user_exists = True
        try:
            pwd.getpwnam(self.pki_user)
            logging.debug("ca user %s exists" % self.pki_user)
        except KeyError:
            user_exists = False
            logging.debug("adding ca user %s" % self.pki_user)
            args = ["/usr/sbin/useradd", "-c", "CA System User", "-d", "/var/lib", "-M", "-r", "-s", "/sbin/nologin", self.pki_user]
            try:
                ipautil.run(args)
                logging.debug("done adding user")
            except ipautil.CalledProcessError, e:
                logging.critical("failed to add user %s" % e)

        self.backup_state("user", self.pki_user)
        self.backup_state("user_exists", user_exists)

    def __configure_instance(self):
#--skipcreate -u pkiuser -g pkiuser -p password -a password -d --hostname `hostname` -n IPA

        preop_pin = get_preop_pin(self.server_root, self.service_name)

        try:
            args = ["/usr/bin/perl", "/usr/bin/pkisilent",  "ConfigureCA",
                    "-cs_hostname", self.host_name,
                    "-cs_port", str(self.secure_port),
                    "-client_certdb_dir", self.ca_agent_db,
                    "-client_certdb_pwd", self.admin_password,
                    "-preop_pin" , preop_pin,
                    "-domain_name", self.domain_name,
                    "-admin_user", "admin",
                    "-admin_email",  "root@localhost",
                    "-admin_password", self.admin_password,
                    "-agent_name", "ipa-ca-agent",
                    "-agent_key_size", "2048",
                    "-agent_key_type", "rsa",
                    "-agent_cert_subject", "\"CN=ipa-ca-agent,O=" + self.domain_name + "\"",
                    "-ldap_host", self.host_name,
                    "-ldap_port", str(self.ds_port),
                    "-bind_dn", "\"cn=Directory Manager\"",
                    "-bind_password", self.dm_password,
                    "-base_dn", self.basedn,
                    "-db_name", "ipaca",
                    "-key_size", "2048",
                    "-key_type", "rsa",
                    "-save_p12", "true",
                    "-backup_pwd", self.admin_password,
                    "-subsystem_name", self.service_name,
                    "-token_name", "internal",
                    "-ca_subsystem_cert_subject_name", "\"CN=CA Subsystem Certificate,O=" + self.domain_name + "\"",
                    "-ca_ocsp_cert_subject_name", "\"CN=OCSP Signing Certificate,O=" + self.domain_name + "\"",
                    "-ca_server_cert_subject_name", "CN=" + self.host_name + ",O=" + self.domain_name,
                    "-ca_audit_signing_cert_subject_name", "\"CN=CA Audit Signing Certificate,O=" + self.domain_name + "\"",
                    "-ca_sign_cert_subject_name", "\"CN=Certificate Authority,O=" + self.domain_name + "\"" ]
#            if (options.external):
#                pass
#                args.append("-external")
#                args.append("true")
#                args.append("-ext_csr_file")
#                args.append(ext_csr_file)
#                if (options.cacertfile):
#                    args.append("-ext_ca_cert_file")
#                    args.append(options.cacertfile)
#                if (options.cacertchainfile):
#                    args.append("-ext_ca_cert_chain_file")
#                    args.append(options.cacertchainfile)
#            else:
#                args.append("-external")
#                args.append("false")
#            if (options.clone):
#                pass
#                args.append("-clone")
#                args.append("true")
#                args.append("-clone_p12_file")
#                args.append(options.clonefile)
#                args.append("-clone_p12_password")
#                args.append(options.clonepasswd)
#                args.append("-clone_uri")
#                args.append(options.cloneURI)
#                args.append("-sd_hostname")
#                args.append(options.sd_hostname)
#                args.append("-sd_ssl_port")
#                args.append(options.sd_ssl_port)
#                args.append("-sd_admin_name")
#                args.append(options.sd_admin_name)
#                args.append("-sd_admin_password")
#                args.append(options.sd_admin_password)
#            else:
#                args.append("-clone")
#                args.append("false")

            # FIXME
            args.append("-external")
            args.append("false")
            args.append("-clone")
            args.append("false")

            logging.debug(args)
            ipautil.run(args)
            logging.debug("completed creating ca instance")
        except ipautil.CalledProcessError, e:
            logging.critical("failed to restart ca instance %s" % e)
        logging.debug("restarting ca instance")
        try:
            self.restart()
            logging.debug("done restarting ca instance")
        except ipautil.CalledProcessError, e:
            print "failed to restart ca instance", e
            logging.debug("failed to restart ca instance %s" % e)

    def __restart_instance(self):
        try:
            self.restart()
        except Exception, e:
            # TODO: roll back here?
            logging.critical("Failed to restart the certificate server. See the installation log for details.")

    def __get_agent_cert(self, nickname):
        args = ["/usr/bin/certutil", "-L", "-d", self.ca_agent_db, "-n", nickname, "-a"]
        (out, err) = ipautil.run(args)
        out = out.replace('-----BEGIN CERTIFICATE-----', '')
        out = out.replace('-----END CERTIFICATE-----', '')
        return out

    def __issue_ra_cert(self):
        # The CA certificate is in the agent DB but isn't trusted
        (admin_fd, admin_name) = tempfile.mkstemp()
        os.write(admin_fd, self.admin_password)
        os.close(admin_fd)

        try:
            self.__run_certutil(
                ['-M', '-t', 'CT,C,C', '-n',
                 'Certificate Authority - %s' % self.domain_name
                 ], database=self.ca_agent_db, pwd_file=self.admin_password)
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
            '/usr/bin/sslget',
            '-n', 'ipa-ca-agent',
            '-p', self.admin_password,
            '-d', self.ca_agent_db,
            '-r', '/ca/agent/ca/profileReview?requestId=%s' % self.requestId,
            '%s:%d' % (self.host_name, 9443),
        ]
        logging.debug("running sslget %s" % args)
        (stdout, stderr) = ipautil.run(args)

        data = stdout.split('\r\n')
        params = get_defList(data)
        params['requestId'] = find_substring(data, "requestId")
        params['op'] = 'approve'
        params['submit'] = 'submit'
        params['requestNotes'] = ''
        params = urllib.urlencode(params)
        headers = {"Content-type": "application/x-www-form-urlencoded",
                   "Accept": "text/plain"}

        # Now issue the RA certificate.
        args = [
            '/usr/bin/sslget',
            '-n', 'ipa-ca-agent',
            '-p', self.admin_password,
            '-d', self.ca_agent_db,
            '-e', params,
            '-r', '/ca/agent/ca/profileProcess',
            '%s:%d' % (self.host_name, 9443),
        ]
        logging.debug("running sslget %s" % args)
        (stdout, stderr) = ipautil.run(args)

        data = stdout.split('\r\n')
        outputList = get_outputList(data)

        self.ra_cert = outputList['b64_cert']
        self.ra_cert = self.ra_cert.replace('\\n','')
        self.ra_cert = self.ra_cert.replace('-----BEGIN CERTIFICATE-----','')
        self.ra_cert = self.ra_cert.replace('-----END CERTIFICATE-----','')

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

    def __configure_ra(self):
        # Create an RA user in the CA LDAP server and add that user to
        # the appropriate groups so it can issue certificates without
        # manual intervention.
        ld = ldap.initialize("ldap://%s:%d" % (self.host_name, self.ds_port))
        ld.protocol_version=ldap.VERSION3
        ld.simple_bind_s("cn=Directory Manager", self.dm_password)

        decoded = base64.b64decode(self.ra_cert)

        entry_dn = "uid=%s,ou=People,%s" % ("ipara", self.basedn)
        entry = [
        ('objectClass', ['top', 'person', 'organizationalPerson', 'inetOrgPerson', 'cmsuser']),
        ('uid', "ipara"),
        ('sn', "ipara"),
        ('cn', "ipara"),
        ('usertype', "agentType"),
        ('userstate', "1"),
        ('userCertificate;binary', decoded),
        ('description', '2;7;CN=Certificate Authority,O=%s;CN=RA Subsystem Certificate,OU=pki-ipa,O=%s' % (self.domain_name, self.domain_name)),]

        ld.add_s(entry_dn, entry)

        dn = "cn=Certificate Manager Agents,ou=groups,%s" % self.basedn
        modlist = [(0, 'uniqueMember', '%s' % entry_dn)]
        ld.modify_s(dn, modlist)

        dn = "cn=Registration Manager Agents,ou=groups,%s" % self.basedn
        modlist = [(0, 'uniqueMember', '%s' % entry_dn)]
        ld.modify_s(dn, modlist)

        ld.unbind_s()

    def __run_certutil(self, args, database=None, pwd_file=None,stdin=None):
        if not database:
            database = self.ra_agent_db
        if not pwd_file:
            pwd_file = self.ra_agent_pwd
        new_args = ["/usr/bin/certutil", "-d", database, "-f", pwd_file]
        new_args = new_args + args
        return ipautil.run(new_args, stdin)

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

        stdout, stderr = self.__run_certutil(["-N"])

    def __get_ca_chain(self):
        try:
            return dogtag.get_ca_certchain()
        except:
            raise RuntimeError("Unable to retrieve CA chain")

    def __create_ca_agent_pkcs12(self):
        (pwd_fd, pwd_name) = tempfile.mkstemp()
        os.write(pwd_fd, self.admin_password)
        os.close(pwd_fd)
        try:
            ipautil.run(["/usr/bin/pk12util",
                         "-n", "ipa-ca-agent",
                         "-o", "/root/ca-agent.p12",
                         "-d", self.ca_agent_db,
                         "-k", pwd_name,
                         "-w", pwd_name])
        finally:
            os.remove(pwd_name)

    def __import_ca_chain(self):
        chain = self.__get_ca_chain()
        (chain_fd, chain_name) = tempfile.mkstemp()
        os.write(chain_fd, chain)
        os.close(chain_fd)
        try:
            self.__run_certutil(
                ['-A', '-t', 'CT,C,C', '-n', self.canickname, '-a',
                 '-i', chain_name]
            )
        finally:
            os.remove(chain_name)

    def __request_ra_certificate(self):
        # Create a noise file for generating our private key
        noise = array.array('B', os.urandom(128))
        (noise_fd, noise_name) = tempfile.mkstemp()
        os.write(noise_fd, noise)
        os.close(noise_fd)

        # Generate our CSR. The result gets put into stdout
        try:
            (stdout, stderr) = self.__run_certutil(["-R", "-k", "rsa", "-g", "2048", "-s", "CN=RA Subsystem Certificate,OU=pki-ipa,O=%s" % self.domain_name, "-z", noise_name, "-a"])
        finally:
            os.remove(noise_name)

        csr = stdout.find("-----BEGIN NEW CERTIFICATE REQUEST-----")
        if csr >= 0:
            csr = stdout[csr:]

        # Send the request to the CA
        conn = httplib.HTTPConnection(self.host_name, 9180)
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

    def __fix_ra_perms(self):
        os.chmod(self.ra_agent_db + "/cert8.db", 0640)
        os.chmod(self.ra_agent_db + "/key3.db", 0640)
        os.chmod(self.ra_agent_db + "/secmod.db", 0640)

        pent = pwd.getpwnam("apache")
        os.chown(self.ra_agent_db + "/cert8.db", 0, pent.pw_gid )
        os.chown(self.ra_agent_db + "/key3.db", 0, pent.pw_gid )
        os.chown(self.ra_agent_db + "/secmod.db", 0, pent.pw_gid )
        os.chown(self.ra_agent_pwd, 0, pent.pw_gid)

    def __setup_sign_profile(self):
        caconfig = "/var/lib/pki-ca/conf/CS.cfg"

        if not ipautil.file_exists('/var/lib/pki-ca/profiles/ca/caJarSigningCert.cfg'):
            profile = ipautil.template_file(ipautil.SHARE_DIR + "caJarSigningCert.cfg.template", {})
            fd = open("/var/lib/pki-ca/profiles/ca/caJarSigningCert.cfg", "w")
            fd.write(profile)
            fd.close()

        profilelist = installutils.get_directive(caconfig, "profile.list", separator="=")
        if profilelist.find('caJarSigningCert') < 0:
            profilelist = profilelist + ',caJarSigningCert'
            installutils.set_directive(caconfig, 'profile.list', profilelist, quotes=False, separator='=')
            installutils.set_directive(caconfig, 'profile.caJarSigningCert.class_id', 'caEnrollImpl', quotes=False, separator='=')
            installutils.set_directive(caconfig, 'profile.caJarSigningCert.config', '/var/lib/pki-ca/profiles/ca/caJarSigningCert.cfg', quotes=False, separator='=')

    def uninstall(self):
        try:
            ipautil.run(["/usr/bin/pkiremove", "-pki_instance_root=/var/lib",
                         "-pki_instance_name=pki-ca", "--force"])
        except ipautil.CalledProcessError, e:
            logging.critical("failed to uninstall CA instance %s" % e)

if __name__ == "__main__":
    installutils.standard_logging_setup("install.log", False)
    cs = CADSInstance()
    cs.create_instance("dirsrv", "GREYOAK.COM", "catest.greyoak.com", "greyoak.com", "password")
    ca = CAInstance()
    ca.configure_instance("pkiuser", "catest.greyoak.com", "password", "password")
