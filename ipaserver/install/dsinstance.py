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
import grp
import glob
import sys
import os
import re
import time
import tempfile

from ipapython import ipautil

import service
import installutils
import certs
import ldap
from ldap.dn import escape_dn_chars
from ipaserver import ipaldap
from ipaserver.install import ldapupdate
from ipaserver.install import httpinstance
from ipalib import util, errors
from ipaserver.plugins.ldap2 import ldap2

SERVER_ROOT_64 = "/usr/lib64/dirsrv"
SERVER_ROOT_32 = "/usr/lib/dirsrv"
CACERT="/usr/share/ipa/html/ca.crt"

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
    try:
        os.unlink("/var/run/slapd-%s.socket" % serverid)
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

def has_managed_entries(host_name, dm_password):
    """Check to see if the Managed Entries plugin is available"""
    ldapuri = 'ldap://%s' % host_name
    conn = None
    try:
        conn = ldap2(shared_instance=False, ldap_uri=ldapuri, base_dn='cn=config')
        conn.connect(bind_dn='cn=Directory Manager', bind_pw=dm_password)
        (dn, attrs) = conn.get_entry('cn=Managed Entries,cn=plugins',
                      ['*'], time_limit=2, size_limit=3000)
        return True
    except errors.NotFound:
        return False
    except errors.ExecutionError, e:
        logging.critical("Could not connect to the Directory Server on %s" % host_name)
        raise e
    finally:
        if conn.isconnected():
            conn.disconnect()


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
inst_dir=   /var/lib/dirsrv/scripts-$SERVERID
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
        self.fqdn = None
        self.pkcs12_info = None
        self.ds_user = None
        self.dercert = None
        self.uidstart = 1100
        self.gidstart = 1100
        if realm_name:
            self.suffix = util.realm_to_suffix(self.realm_name)
            self.__setup_sub_dict()
        else:
            self.suffix = None

    def create_instance(self, ds_user, realm_name, fqdn, domain_name, dm_password, pkcs12_info=None, self_signed_ca=False, uidstart=1100, gidstart=1100, subject_base=None, hbac_allow=True):
        self.ds_user = ds_user
        self.realm_name = realm_name.upper()
        self.serverid = realm_to_serverid(self.realm_name)
        self.suffix = util.realm_to_suffix(self.realm_name)
        self.fqdn = fqdn
        self.dm_password = dm_password
        self.domain = domain_name
        self.pkcs12_info = pkcs12_info
        self.self_signed_ca = self_signed_ca
        self.uidstart = uidstart
        self.gidstart = gidstart
        self.principal = "ldap/%s@%s" % (self.fqdn, self.realm_name)
        self.subject_base = subject_base
        self.__setup_sub_dict()

        self.step("creating directory server user", self.__create_ds_user)
        self.step("creating directory server instance", self.__create_instance)
        self.step("adding default schema", self.__add_default_schemas)
        self.step("enabling memberof plugin", self.__add_memberof_module)
        self.step("enabling referential integrity plugin", self.__add_referint_module)
        self.step("enabling winsync plugin", self.__add_winsync_module)
        if self.uidstart == self.gidstart:
            self.step("configuring user private groups", self.__user_private_groups)
        self.step("configuring replication version plugin", self.__config_version_module)
        self.step("enabling IPA enrollment plugin", self.__add_enrollment_module)
        self.step("enabling ldapi", self.__enable_ldapi)
        self.step("configuring uniqueness plugin", self.__set_unique_attrs)
        self.step("configuring uuid plugin", self.__config_uuid_module)
        self.step("configuring modrdn plugin", self.__config_modrdn_module)
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
        if hbac_allow:
            self.step("creating default HBAC rule allow_all", self.add_hbac)
        self.step("enabling compatibility plugin",
                  self.__enable_compat_plugin)

        self.step("configuring directory to start on boot", self.__enable)

        self.start_creation("Configuring directory server", 60)

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        self.chkconfig_on()

    def __setup_sub_dict(self):
        server_root = find_server_root()
        self.sub_dict = dict(FQHN=self.fqdn, SERVERID=self.serverid,
                             PASSWORD=self.dm_password, SUFFIX=self.suffix.lower(),
                             REALM=self.realm_name, USER=self.ds_user,
                             SERVER_ROOT=server_root, DOMAIN=self.domain,
                             TIME=int(time.time()), UIDSTART=self.uidstart,
                             GIDSTART=self.gidstart, HOST=self.fqdn,
                             ESCAPED_SUFFIX= escape_dn_chars(self.suffix.lower()),
                         )

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
                # if the group already exists we need to request to add it,
                # otherwise useradd will create it for us
                grp.getgrnam(self.ds_user)
                args.append("-g")
                args.append(self.ds_user)
            except KeyError:
                pass
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
        shutil.copyfile(ipautil.SHARE_DIR + "60ipasudo.ldif",
                        schema_dirname(self.serverid) + "60ipasudo.ldif")
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
        ld = ldapupdate.LDAPUpdate(dm_password=self.dm_password, sub_dict=self.sub_dict)
        files = ld.get_all_files(ldapupdate.UPDATES_DIR)
        ld.update(files)

    def __add_referint_module(self):
        self._ldap_mod("referint-conf.ldif")

    def __set_unique_attrs(self):
        self._ldap_mod("unique-attributes.ldif", self.sub_dict)

    def __config_uidgid_gen_first_master(self):
        if (self.uidstart == self.gidstart and
            has_managed_entries(self.fqdn, self.dm_password)):
            self._ldap_mod("dna-upg.ldif", self.sub_dict)
        else:
            self._ldap_mod("dna-posix.ldif", self.sub_dict)

    def __add_master_entry_first_master(self):
        self._ldap_mod("master-entry.ldif", self.sub_dict)

    def __add_winsync_module(self):
        self._ldap_mod("ipa-winsync-conf.ldif")

    def __enable_compat_plugin(self):
        ld = ldapupdate.LDAPUpdate(dm_password=self.dm_password, sub_dict=self.sub_dict)
        rv = ld.update(['/usr/share/ipa/schema_compat.uldif'])
        if not rv:
            raise RuntimeError("Enabling compatibility plugin failed")

    def __config_version_module(self):
        self._ldap_mod("version-conf.ldif")

    def __config_uuid_module(self):
        self._ldap_mod("uuid-conf.ldif")
        self._ldap_mod("uuid-ipauniqueid.ldif", self.sub_dict)

    def __config_modrdn_module(self):
        self._ldap_mod("modrdn-conf.ldif")
        self._ldap_mod("modrdn-krbprinc.ldif", self.sub_dict)

    def __user_private_groups(self):
        if has_managed_entries(self.fqdn, self.dm_password):
            self._ldap_mod("user_private_groups.ldif", self.sub_dict)

    def __add_enrollment_module(self):
        self._ldap_mod("enrollment-conf.ldif", self.sub_dict)

    def __enable_ssl(self):
        dirname = config_dirname(self.serverid)
        dsdb = certs.CertDB(dirname, self.realm_name, subject_base=self.subject_base)
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
            cadb = certs.CertDB(httpinstance.NSS_DIR, self.realm_name, host_name=self.fqdn, subject_base=self.subject_base)
            if self.self_signed_ca:
                cadb.create_self_signed()
                dsdb.create_from_cacert(cadb.cacert_fname, passwd=None)
                self.dercert = dsdb.create_server_cert("Server-Cert", self.fqdn, cadb)
                dsdb.track_server_cert("Server-Cert", self.principal, dsdb.passwd_fname)
                dsdb.create_pin_file()
            else:
                # FIXME, need to set this nickname in the RA plugin
                cadb.export_ca_cert('ipaCert', False)
                dsdb.create_from_cacert(cadb.cacert_fname, passwd=None)
                self.dercert = dsdb.create_server_cert("Server-Cert", self.fqdn, cadb)
                dsdb.track_server_cert("Server-Cert", self.principal, dsdb.passwd_fname)
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

    def add_hbac(self):
        self._ldap_mod("default-hbac.ldif", self.sub_dict)

    def change_admin_password(self, password):
        logging.debug("Changing admin password")
        dirname = config_dirname(self.serverid)
        dmpwdfile = ""
        admpwdfile = ""

        try:
            (dmpwdfd, dmpwdfile) = tempfile.mkstemp(dir='/var/lib/ipa')
            os.write(dmpwdfd, self.dm_password)
            os.close(dmpwdfd)

            (admpwdfd, admpwdfile) = tempfile.mkstemp(dir='/var/lib/ipa')
            os.write(admpwdfd, password)
            os.close(admpwdfd)

            args = ["/usr/bin/ldappasswd", "-h", self.fqdn,
                    "-ZZ", "-x", "-D", "cn=Directory Manager",
                    "-y", dmpwdfile, "-T", admpwdfile,
                    "uid=admin,cn=users,cn=accounts,"+self.suffix]
            try:
                env = { 'LDAPTLS_CACERTDIR':os.path.dirname(CACERT),
                        'LDAPTLS_CACERT':CACERT }
                ipautil.run(args, env=env)
                logging.debug("ldappasswd done")
            except ipautil.CalledProcessError, e:
                print "Unable to set admin password", e
                logging.debug("Unable to set admin password %s" % e)

        finally:
            if os.path.isfile(dmpwdfile):
                os.remove(dmpwdfile)
            if os.path.isfile(admpwdfile):
                os.remove(admpwdfile)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring directory server")

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if not running is None:
            self.stop()

        if not enabled is None and not enabled:
            self.chkconfig_off()

        serverid = self.restore_state("serverid")
        if not serverid is None:
            # drop the trailing / off the config_dirname so the directory
            # will match what is in certmonger
            dirname = config_dirname(serverid)[:-1]
            dsdb = certs.CertDB(dirname, self.realm_name)
            dsdb.untrack_server_cert("Server-Cert")
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
        do not use 'IPA CA' since that's the default, so
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
        certdb = certs.CertDB(dirname, self.realm_name, subject_base=self.subject_base)
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
