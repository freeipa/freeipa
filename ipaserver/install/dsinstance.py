# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
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

import shutil
import logging
import pwd
import glob
import sys
import os
import re
import time

from ipapython import ipautil

import service
import installutils
import certs
import ldap
from ipaserver import ipaldap
from ipaserver.install import ldapupdate
from ipaserver.install import httpinstance
from ipalib import util

SERVER_ROOT_64 = "/usr/lib64/dirsrv"
SERVER_ROOT_32 = "/usr/lib/dirsrv"

def find_server_root():
    if ipautil.dir_exists(SERVER_ROOT_64):
        return SERVER_ROOT_64
    else:
        return SERVER_ROOT_32

def realm_to_serverid(realm_name):
    return "-".join(realm_name.split("."))

def config_dirname(serverid):
    return "/etc/dirsrv/slapd-" + serverid + "/"

def schema_dirname(serverid):
    return config_dirname(serverid) + "/schema/"

def erase_ds_instance_data(serverid):
    try:
        shutil.rmtree("/etc/dirsrv/slapd-%s" % serverid)
    except:
        pass
    try:
        shutil.rmtree("/usr/lib/dirsrv/slapd-%s" % serverid)
    except:
        pass
    try:
        shutil.rmtree("/usr/lib64/dirsrv/slapd-%s" % serverid)
    except:
        pass
    try:
        shutil.rmtree("/var/lib/dirsrv/slapd-%s" % serverid)
    except:
        pass
    try:
        shutil.rmtree("/var/lock/dirsrv/slapd-%s" % serverid)
    except:
        pass
#    try:
#        shutil.rmtree("/var/log/dirsrv/slapd-%s" % serverid)
#    except:
#        pass

def check_existing_installation():
    dirs = glob.glob("/etc/dirsrv/slapd-*")
    if not dirs:
        return []

    serverids = []
    for d in dirs:
        serverids.append(os.path.basename(d).split("slapd-", 1)[1])

    return serverids

def check_ports():
    ds_unsecure = installutils.port_available(389)
    ds_secure = installutils.port_available(636)
    return (ds_unsecure, ds_secure)

def is_ds_running():
    """The DS init script always returns 0 when requesting status so it cannot
       be used to determine if the server is running. We have to look at the
       output.
    """
    ret = True
    try:
        (sout, serr, rcode) = ipautil.run(["/sbin/service", "dirsrv", "status"])
        if sout.find("is stopped") >= 0:
            ret = False
    except ipautil.CalledProcessError:
        ret = False
    return ret


INF_TEMPLATE = """
[General]
FullMachineName=   $FQHN
SuiteSpotUserID=   $USER
ServerRoot=    $SERVER_ROOT
[slapd]
ServerPort=   389
ServerIdentifier=   $SERVERID
Suffix=   $SUFFIX
RootDN=   cn=Directory Manager
RootDNPwd= $PASSWORD
InstallLdifFile= /var/lib/dirsrv/boot.ldif
"""

BASE_TEMPLATE = """
dn: $SUFFIX
objectClass: top
objectClass: domain
objectClass: pilotObject
dc: $BASEDC
info: IPA V2.0
"""

class DsInstance(service.Service):
    def __init__(self, realm_name=None, domain_name=None, dm_password=None):
        service.Service.__init__(self, "dirsrv", dm_password=dm_password)
        self.realm_name = realm_name
        self.sub_dict = None
        self.domain = domain_name
        self.serverid = None
        self.host_name = None
        self.pkcs12_info = None
        self.ds_user = None
        self.dercert = None
        if realm_name:
            self.suffix = util.realm_to_suffix(self.realm_name)
            self.__setup_sub_dict()
        else:
            self.suffix = None

    def create_instance(self, ds_user, realm_name, host_name, domain_name, dm_password, pkcs12_info=None, self_signed_ca=False, uidstart=1100, gidstart=1100, subject_base=None):
        self.ds_user = ds_user
        self.realm_name = realm_name.upper()
        self.serverid = realm_to_serverid(self.realm_name)
        self.suffix = util.realm_to_suffix(self.realm_name)
        self.host_name = host_name
        self.dm_password = dm_password
        self.domain = domain_name
        self.pkcs12_info = pkcs12_info
        self.self_signed_ca = self_signed_ca
        self.uidstart = uidstart
        self.gidstart = gidstart
        self.principal = "ldap/%s@%s" % (self.host_name, self.realm_name)
        self.subject_base = subject_base
        self.__setup_sub_dict()

        self.step("creating directory server user", self.__create_ds_user)
        self.step("creating directory server instance", self.__create_instance)
        self.step("adding default schema", self.__add_default_schemas)
        self.step("enabling memberof plugin", self.__add_memberof_module)
        self.step("enabling referential integrity plugin", self.__add_referint_module)
        self.step("enabling winsync plugin", self.__add_winsync_module)
        self.step("enabling IPA enrollment plugin", self.__add_enrollment_module)
        self.step("enabling ldapi", self.__enable_ldapi)
        self.step("configuring uniqueness plugin", self.__set_unique_attrs)
        self.step("creating indices", self.__create_indices)
        self.step("configuring ssl for ds instance", self.__enable_ssl)
        self.step("configuring certmap.conf", self.__certmap_conf)
        self.step("restarting directory server", self.__restart_instance)
        self.step("adding default layout", self.__add_default_layout)
        self.step("adding delegation layout", self.__add_delegation_layout)
        self.step("configuring Posix uid/gid generation as first master",
                  self.__config_uidgid_gen_first_master)
        self.step("adding master entry as first master",
                  self.__add_master_entry_first_master)
        self.step("initializing group membership",
                  self.init_memberof)

        self.step("configuring directory to start on boot", self.__enable)

        self.start_creation("Configuring directory server:")

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        self.chkconfig_on()

    def __setup_sub_dict(self):
        server_root = find_server_root()
        self.sub_dict = dict(FQHN=self.host_name, SERVERID=self.serverid,
                             PASSWORD=self.dm_password, SUFFIX=self.suffix.lower(),
                             REALM=self.realm_name, USER=self.ds_user,
                             SERVER_ROOT=server_root, DOMAIN=self.domain,
                             TIME=int(time.time()), UIDSTART=self.uidstart,
                             GIDSTART=self.gidstart, HOST=self.host_name)

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
        self.backup_state("running", is_ds_running())
        self.backup_state("serverid", self.serverid)

        self.sub_dict['BASEDC'] = self.realm_name.split('.')[0].lower()
        base_txt = ipautil.template_str(BASE_TEMPLATE, self.sub_dict)
        logging.debug(base_txt)
        base_fd = file("/var/lib/dirsrv/boot.ldif", "w")
        base_fd.write(base_txt)
        base_fd.flush()
        base_fd.close()

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
        logging.debug("restarting ds instance")
        try:
            self.restart(self.serverid)
            logging.debug("done restarting ds instance")
        except ipautil.CalledProcessError, e:
            print "failed to restart ds instance", e
            logging.debug("failed to restart ds instance %s" % e)
        inf_fd.close()
        os.remove("/var/lib/dirsrv/boot.ldif")

    def __add_default_schemas(self):
        shutil.copyfile(ipautil.SHARE_DIR + "60kerberos.ldif",
                        schema_dirname(self.serverid) + "60kerberos.ldif")
        shutil.copyfile(ipautil.SHARE_DIR + "60samba.ldif",
                        schema_dirname(self.serverid) + "60samba.ldif")
        shutil.copyfile(ipautil.SHARE_DIR + "60radius.ldif",
                        schema_dirname(self.serverid) + "60radius.ldif")
        shutil.copyfile(ipautil.SHARE_DIR + "60ipaconfig.ldif",
                        schema_dirname(self.serverid) + "60ipaconfig.ldif")
        shutil.copyfile(ipautil.SHARE_DIR + "60basev2.ldif",
                        schema_dirname(self.serverid) + "60basev2.ldif")
        shutil.copyfile(ipautil.SHARE_DIR + "60policyv2.ldif",
                        schema_dirname(self.serverid) + "60policyv2.ldif")
        try:
            shutil.move(schema_dirname(self.serverid) + "05rfc2247.ldif",
                            schema_dirname(self.serverid) + "05rfc2247.ldif.old")
            shutil.copyfile(ipautil.SHARE_DIR + "05rfc2247.ldif",
                            schema_dirname(self.serverid) + "05rfc2247.ldif")
        except IOError:
            # Does not apply with newer DS releases
            pass

    def __restart_instance(self):
        try:
            self.restart(self.serverid)
            if not is_ds_running():
                logging.critical("Failed to restart the directory server. See the installation log for details.")
                sys.exit(1)
        except SystemExit, e:
            raise e
        except Exception, e:
            # TODO: roll back here?
            logging.critical("Failed to restart the directory server. See the installation log for details.")

    def __add_memberof_module(self):
        self._ldap_mod("memberof-conf.ldif")

    def init_memberof(self):
        self._ldap_mod("memberof-task.ldif", self.sub_dict)

    def apply_updates(self):
        ld = ldapupdate.LDAPUpdate(dm_password=self.dm_password)
        files = ld.get_all_files(ldapupdate.UPDATES_DIR)
        ld.update(files)

    def __add_referint_module(self):
        self._ldap_mod("referint-conf.ldif")

    def __set_unique_attrs(self):
        self._ldap_mod("unique-attributes.ldif", self.sub_dict)

    def __config_uidgid_gen_first_master(self):
        self._ldap_mod("dna-posix.ldif", self.sub_dict)

    def __add_master_entry_first_master(self):
        self._ldap_mod("master-entry.ldif", self.sub_dict)

    def __add_winsync_module(self):
        self._ldap_mod("ipa-winsync-conf.ldif")

    def __add_enrollment_module(self):
        self._ldap_mod("enrollment-conf.ldif", self.sub_dict)

    def __enable_ssl(self):
        dirname = config_dirname(self.serverid)
        dsdb = certs.CertDB(dirname, subject_base=self.subject_base)
        if self.pkcs12_info:
            dsdb.create_from_pkcs12(self.pkcs12_info[0], self.pkcs12_info[1])
            server_certs = dsdb.find_server_certs()
            if len(server_certs) == 0:
                raise RuntimeError("Could not find a suitable server cert in import in %s" % self.pkcs12_info[0])

            # We only handle one server cert
            nickname = server_certs[0][0]
            self.dercert = dsdb.get_cert_from_db(nickname)
        else:
            nickname = "Server-Cert"
            cadb = certs.CertDB(httpinstance.NSS_DIR, host_name=self.host_name, subject_base=self.subject_base)
            if self.self_signed_ca:
                cadb.create_self_signed()
                dsdb.create_from_cacert(cadb.cacert_fname, passwd=None)
                self.dercert = dsdb.create_server_cert("Server-Cert", self.host_name, cadb)
                dsdb.create_pin_file()
            else:
                # FIXME, need to set this nickname in the RA plugin
                cadb.export_ca_cert('ipaCert', False)
                dsdb.create_from_cacert(cadb.cacert_fname, passwd=None)
                self.dercert = dsdb.create_server_cert("Server-Cert", self.host_name, cadb)
                dsdb.create_pin_file()

        conn = ipaldap.IPAdmin("127.0.0.1")
        conn.simple_bind_s("cn=directory manager", self.dm_password)

        mod = [(ldap.MOD_REPLACE, "nsSSLClientAuth", "allowed"),
               (ldap.MOD_REPLACE, "nsSSL3Ciphers",
                "-rsa_null_md5,+rsa_rc4_128_md5,+rsa_rc4_40_md5,+rsa_rc2_40_md5,\
+rsa_des_sha,+rsa_fips_des_sha,+rsa_3des_sha,+rsa_fips_3des_sha,+fortezza,\
+fortezza_rc4_128_sha,+fortezza_null,+tls_rsa_export1024_with_rc4_56_sha,\
+tls_rsa_export1024_with_des_cbc_sha")]
        conn.modify_s("cn=encryption,cn=config", mod)

        mod = [(ldap.MOD_ADD, "nsslapd-security", "on"),
               (ldap.MOD_REPLACE, "nsslapd-ssl-check-hostname", "off")]
        conn.modify_s("cn=config", mod)

        entry = ipaldap.Entry("cn=RSA,cn=encryption,cn=config")

        entry.setValues("objectclass", "top", "nsEncryptionModule")
        entry.setValues("cn", "RSA")
        entry.setValues("nsSSLPersonalitySSL", nickname)
        entry.setValues("nsSSLToken", "internal (software)")
        entry.setValues("nsSSLActivation", "on")

        conn.addEntry(entry)

        conn.unbind()

    def __add_default_layout(self):
        self._ldap_mod("bootstrap-template.ldif", self.sub_dict)

    def __add_delegation_layout(self):
        self._ldap_mod("delegation.ldif", self.sub_dict)

    def __create_indices(self):
        self._ldap_mod("indices.ldif")

    def __certmap_conf(self):
        shutil.copyfile(ipautil.SHARE_DIR + "certmap.conf.template",
                        config_dirname(self.serverid) + "certmap.conf")

    def __enable_ldapi(self):
        self._ldap_mod("ldapi.ldif", self.sub_dict)

    def change_admin_password(self, password):
        logging.debug("Changing admin password")
        dirname = config_dirname(self.serverid)
        if ipautil.dir_exists("/usr/lib64/mozldap"):
            app = "/usr/lib64/mozldap/ldappasswd"
        else:
            app = "/usr/lib/mozldap/ldappasswd"
        args = [app,
                "-D", "cn=Directory Manager", "-w", self.dm_password,
                "-P", dirname+"/cert8.db", "-ZZZ", "-s", password,
                "uid=admin,cn=users,cn=accounts,"+self.suffix]
        try:
            ipautil.run(args)
            logging.debug("ldappasswd done")
        except ipautil.CalledProcessError, e:
            print "Unable to set admin password", e
            logging.debug("Unable to set admin password %s" % e)

    def uninstall(self):
        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if not running is None:
            self.stop()

        if not enabled is None and not enabled:
            self.chkconfig_off()

        serverid = self.restore_state("serverid")
        if not serverid is None:
            erase_ds_instance_data(serverid)

        ds_user = self.restore_state("user")
        user_exists = self.restore_state("user_exists")

        if not ds_user is None and not user_exists is None and not user_exists:
            try:
                ipautil.run(["/usr/sbin/userdel", ds_user])
            except ipautil.CalledProcessError, e:
                logging.critical("failed to delete user %s" % e)

        if self.restore_state("running"):
            self.start()

    # we could probably move this function into the service.Service
    # class - it's very generic - all we need is a way to get an
    # instance of a particular Service
    def add_ca_cert(self, cacert_fname, cacert_name=''):
        """Add a CA certificate to the directory server cert db.  We
        first have to shut down the directory server in case it has
        opened the cert db read-only.  Then we use the CertDB class
        to add the CA cert.  We have to provide a nickname, and we
        do not use 'CA certificate' since that's the default, so
        we use 'Imported CA' if none specified.  Then we restart
        the server."""
        # first make sure we have a valid cacert_fname
        try:
            if not os.access(cacert_fname, os.R_OK):
                logging.critical("The given CA cert file named [%s] could not be read" %
                                 cacert_fname)
                return False
        except OSError, e:
            logging.critical("The given CA cert file named [%s] could not be read: %s" %
                             (cacert_fname, str(e)))
            return False
        # ok - ca cert file can be read
        # shutdown the server
        self.stop()

        dirname = config_dirname(realm_to_serverid(self.realm_name))
        certdb = certs.CertDB(dirname, subject_base=self.subject_base)
        if not cacert_name or len(cacert_name) == 0:
            cacert_name = "Imported CA"
        # we can't pass in the nickname, so we set the instance variable
        certdb.cacert_name = cacert_name
        status = True
        try:
            certdb.load_cacert(cacert_fname)
        except ipautil.CalledProcessError, e:
            logging.critical("Error importing CA cert file named [%s]: %s" %
                             (cacert_fname, str(e)))
            status = False
        # restart the directory server
        self.start()

        return status
