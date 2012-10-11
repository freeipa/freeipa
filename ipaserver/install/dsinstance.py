# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
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

import shutil
from ipapython.ipa_log_manager import *
import pwd
import glob
import sys
import os
import re
import time
import tempfile

from ipapython import ipautil
from ipapython import sysrestore
from ipapython import services as ipaservices

import service
import installutils
import certs
import ldap
from ipaserver import ipaldap
from ipaserver.install import ldapupdate
from ipaserver.install import httpinstance
from ipaserver.install import replication
from ipalib import util, errors
from ipapython.dn import DN
from ipaserver.plugins.ldap2 import ldap2

SERVER_ROOT_64 = "/usr/lib64/dirsrv"
SERVER_ROOT_32 = "/usr/lib/dirsrv"
CACERT="/etc/ipa/ca.crt"

DS_USER = 'dirsrv'
DS_GROUP = 'dirsrv'

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
    installutils.rmtree("/etc/dirsrv/slapd-%s" % serverid)

    installutils.rmtree("/usr/lib/dirsrv/slapd-%s" % serverid)

    installutils.rmtree("/usr/lib64/dirsrv/slapd-%s" % serverid)

    installutils.rmtree("/var/lib/dirsrv/slapd-%s" % serverid)

    installutils.rmtree("/var/lock/dirsrv/slapd-%s" % serverid)

    installutils.remove_file("/var/run/slapd-%s.socket" % serverid)

    installutils.rmtree("/var/lib/dirsrv/scripts-%s" % serverid)

    installutils.remove_file("/etc/dirsrv/ds.keytab")

    installutils.remove_file("/etc/sysconfig/dirsrv-%s" % serverid)

#    try:
#        shutil.rmtree("/var/log/dirsrv/slapd-%s" % serverid)
#    except:
#        pass

def get_ds_instances():
    '''
    Return a sorted list of all 389ds instances.

    If the instance name ends with '.removed' it is ignored. This
    matches 389ds behavior.
    '''

    dirsrv_instance_dir='/etc/dirsrv'
    instance_prefix = 'slapd-'

    instances = []

    for basename in os.listdir(dirsrv_instance_dir):
        pathname = os.path.join(dirsrv_instance_dir, basename)
        # Must be a directory
        if os.path.isdir(pathname):
            # Must start with prefix and not end with .removed
            if basename.startswith(instance_prefix) and not basename.endswith('.removed'):
                # Strip off prefix
                instance = basename[len(instance_prefix):]
                # Must be non-empty
                if instance:
                    instances.append(instance)

    instances.sort()
    return instances

def check_ports():
    """
    Check of Directory server ports are open.

    Returns a tuple with two booleans, one for unsecure port 389 and one for
    secure port 636. True means that the port is free, False means that the
    port is taken.
    """
    ds_unsecure = not ipautil.host_port_open(None, 389)
    ds_secure = not ipautil.host_port_open(None, 636)
    return (ds_unsecure, ds_secure)

def is_ds_running(server_id=''):
    return ipaservices.knownservices.dirsrv.is_running(instance_name=server_id)

INF_TEMPLATE = """
[General]
FullMachineName=   $FQDN
SuiteSpotUserID=   $USER
SuiteSpotGroup=    $GROUP
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
    def __init__(self, realm_name=None, domain_name=None, dm_password=None, fstore=None):
        service.Service.__init__(self, "dirsrv", dm_password=dm_password, ldapi=False, autobind=service.DISABLED)
        self.realm_name = realm_name
        self.sub_dict = None
        self.domain = domain_name
        self.serverid = None
        self.fqdn = None
        self.pkcs12_info = None
        self.dercert = None
        self.idstart = None
        self.idmax = None
        self.subject_base = None
        self.open_ports = []
        self.run_init_memberof = True
        if realm_name:
            self.suffix = ipautil.realm_to_suffix(self.realm_name)
            self.__setup_sub_dict()
        else:
            self.suffix = DN()

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')


    subject_base = ipautil.dn_attribute_property('_subject_base')

    def __common_setup(self):

        self.step("creating directory server user", self.__create_ds_user)
        self.step("creating directory server instance", self.__create_instance)
        self.step("adding default schema", self.__add_default_schemas)
        self.step("enabling memberof plugin", self.__add_memberof_module)
        self.step("enabling winsync plugin", self.__add_winsync_module)
        self.step("configuring replication version plugin", self.__config_version_module)
        self.step("enabling IPA enrollment plugin", self.__add_enrollment_module)
        self.step("enabling ldapi", self.__enable_ldapi)
        self.step("disabling betxn plugins", self.__disable_betxn)
        self.step("configuring uniqueness plugin", self.__set_unique_attrs)
        self.step("configuring uuid plugin", self.__config_uuid_module)
        self.step("configuring modrdn plugin", self.__config_modrdn_module)
        self.step("enabling entryUSN plugin", self.__enable_entryusn)
        self.step("configuring lockout plugin", self.__config_lockout_module)
        self.step("creating indices", self.__create_indices)
        self.step("enabling referential integrity plugin", self.__add_referint_module)
        self.step("configuring ssl for ds instance", self.__enable_ssl)
        self.step("configuring certmap.conf", self.__certmap_conf)
        self.step("configure autobind for root", self.__root_autobind)
        self.step("configure new location for managed entries", self.__repoint_managed_entries)
        self.step("restarting directory server", self.__restart_instance)

    def __common_post_setup(self):
        self.step("initializing group membership", self.init_memberof)
        self.step("adding master entry", self.__add_master_entry)
        self.step("configuring Posix uid/gid generation",
                  self.__config_uidgid_gen)
        self.step("enabling compatibility plugin",
                  self.__enable_compat_plugin)
        self.step("tuning directory server", self.__tuning)

        self.step("configuring directory to start on boot", self.__enable)

    def create_instance(self, realm_name, fqdn, domain_name,
                        dm_password, pkcs12_info=None, self_signed_ca=False,
                        idstart=1100, idmax=999999, subject_base=None,
                        hbac_allow=True):
        self.realm_name = realm_name.upper()
        self.serverid = realm_to_serverid(self.realm_name)
        self.suffix = ipautil.realm_to_suffix(self.realm_name)
        self.fqdn = fqdn
        self.dm_password = dm_password
        self.domain = domain_name
        self.pkcs12_info = pkcs12_info
        self.self_signed_ca = self_signed_ca
        self.idstart = idstart
        self.idmax = idmax
        self.principal = "ldap/%s@%s" % (self.fqdn, self.realm_name)
        self.subject_base = subject_base

        self.__setup_sub_dict()
        self.__common_setup()

        self.step("adding default layout", self.__add_default_layout)
        self.step("adding delegation layout", self.__add_delegation_layout)
        self.step("adding replication acis", self.__add_replication_acis)
        self.step("creating container for managed entries", self.__managed_entries)
        self.step("configuring user private groups", self.__user_private_groups)
        self.step("configuring netgroups from hostgroups", self.__host_nis_groups)
        self.step("creating default Sudo bind user", self.__add_sudo_binduser)
        self.step("creating default Auto Member layout", self.__add_automember_config)
        self.step("adding range check plugin", self.__add_range_check_plugin)
        if hbac_allow:
            self.step("creating default HBAC rule allow_all", self.add_hbac)

        self.__common_post_setup()

        self.start_creation("Configuring directory server", 60)

    def create_replica(self, realm_name, master_fqdn, fqdn,
                       domain_name, dm_password, pkcs12_info=None):
        self.realm_name = realm_name.upper()
        self.serverid = realm_to_serverid(self.realm_name)
        self.suffix = ipautil.realm_to_suffix(self.realm_name)
        self.master_fqdn = master_fqdn
        self.fqdn = fqdn
        self.dm_password = dm_password
        self.domain = domain_name
        self.pkcs12_info = pkcs12_info
        self.principal = "ldap/%s@%s" % (self.fqdn, self.realm_name)

        self.self_signed_ca = False
        self.subject_base = None
        # idstart and idmax are configured so that the range is seen as
        # depleted by the DNA plugin and the replica will go and get a
        # new range from the master.
        # This way all servers use the initially defined range by default.
        self.idstart = 1101
        self.idmax = 1100

        self.__setup_sub_dict()
        self.__common_setup()

        self.step("setting up initial replication", self.__setup_replica)
        self.step("adding replication acis", self.__add_replication_acis)
        # See LDIFs for automember configuration during replica install
        self.step("setting Auto Member configuration", self.__add_replica_automember_config)
        self.step("enabling S4U2Proxy delegation", self.__setup_s4u2proxy)

        self.__common_post_setup()

        self.start_creation("Configuring directory server", 60)


    def __setup_replica(self):
        replication.enable_replication_version_checking(self.fqdn,
            self.realm_name,
            self.dm_password)

        repl = replication.ReplicationManager(self.realm_name,
                                              self.fqdn,
                                              self.dm_password)
        repl.setup_replication(self.master_fqdn,
                               r_binddn=DN(('cn', 'Directory Manager')),
                               r_bindpw=self.dm_password)
        self.run_init_memberof = repl.needs_memberof_fixup()

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # At the end of the installation ipa-server-install will enable the
        # 'ipa' service wich takes care of starting/stopping dirsrv
        self.disable()

    def __setup_sub_dict(self):
        server_root = find_server_root()
        try:
            idrange_size = self.idmax - self.idstart + 1
        except TypeError:
            idrange_size = None
        self.sub_dict = dict(FQDN=self.fqdn, SERVERID=self.serverid,
                             PASSWORD=self.dm_password,
                             RANDOM_PASSWORD=self.generate_random(),
                             SUFFIX=self.suffix,
                             REALM=self.realm_name, USER=DS_USER,
                             SERVER_ROOT=server_root, DOMAIN=self.domain,
                             TIME=int(time.time()), IDSTART=self.idstart,
                             IDMAX=self.idmax, HOST=self.fqdn,
                             ESCAPED_SUFFIX=str(self.suffix),
                             GROUP=DS_GROUP,
                             IDRANGE_SIZE=idrange_size
                         )

    def __create_ds_user(self):
        try:
            pwd.getpwnam(DS_USER)
            root_logger.debug("ds user %s exists" % DS_USER)
        except KeyError:
            root_logger.debug("adding ds user %s" % DS_USER)
            args = ["/usr/sbin/useradd", "-g", DS_GROUP,
                                         "-c", "DS System User",
                                         "-d", "/var/lib/dirsrv",
                                         "-s", "/sbin/nologin",
                                         "-M", "-r", DS_USER]
            try:
                ipautil.run(args)
                root_logger.debug("done adding user")
            except ipautil.CalledProcessError, e:
                root_logger.critical("failed to add user %s" % e)

    def __create_instance(self):
        pent = pwd.getpwnam(DS_USER)

        self.backup_state("serverid", self.serverid)
        self.fstore.backup_file("/etc/sysconfig/dirsrv")

        self.sub_dict['BASEDC'] = self.realm_name.split('.')[0].lower()
        base_txt = ipautil.template_str(BASE_TEMPLATE, self.sub_dict)
        root_logger.debug(base_txt)

        target_fname = '/var/lib/dirsrv/boot.ldif'
        base_fd = open(target_fname, "w")
        base_fd.write(base_txt)
        base_fd.close()

        # Must be readable for dirsrv
        os.chmod(target_fname, 0440)
        os.chown(target_fname, pent.pw_uid, pent.pw_gid)

        inf_txt = ipautil.template_str(INF_TEMPLATE, self.sub_dict)
        root_logger.debug("writing inf template")
        inf_fd = ipautil.write_tmp_file(inf_txt)
        inf_txt = re.sub(r"RootDNPwd=.*\n", "", inf_txt)
        root_logger.debug(inf_txt)
        if ipautil.file_exists("/usr/sbin/setup-ds.pl"):
            args = ["/usr/sbin/setup-ds.pl", "--silent", "--logfile", "-", "-f", inf_fd.name]
            root_logger.debug("calling setup-ds.pl")
        else:
            args = ["/usr/bin/ds_newinst.pl", inf_fd.name]
            root_logger.debug("calling ds_newinst.pl")
        try:
            ipautil.run(args)
            root_logger.debug("completed creating ds instance")
        except ipautil.CalledProcessError, e:
            root_logger.critical("failed to create ds instance %s" % e)

        # check for open port 389 from now on
        self.open_ports.append(389)

        root_logger.debug("restarting ds instance")
        try:
            self.__restart_instance()
            root_logger.debug("done restarting ds instance")
        except ipautil.CalledProcessError, e:
            print "failed to restart ds instance", e
            root_logger.debug("failed to restart ds instance %s" % e)
        inf_fd.close()
        os.remove("/var/lib/dirsrv/boot.ldif")

    def __add_default_schemas(self):
        pent = pwd.getpwnam(DS_USER)
        for schema_fname in ("60kerberos.ldif",
                             "60samba.ldif",
                             "60ipaconfig.ldif",
                             "60basev2.ldif",
                             "60basev3.ldif",
                             "60ipadns.ldif",
                             "61kerberos-ipav3.ldif",
                             "65ipasudo.ldif"):
            target_fname = schema_dirname(self.serverid) + schema_fname
            shutil.copyfile(ipautil.SHARE_DIR + schema_fname, target_fname)
            os.chmod(target_fname, 0440)    # read access for dirsrv user/group
            os.chown(target_fname, pent.pw_uid, pent.pw_gid)

        try:
            shutil.move(schema_dirname(self.serverid) + "05rfc2247.ldif",
                            schema_dirname(self.serverid) + "05rfc2247.ldif.old")

            target_fname = schema_dirname(self.serverid) + "05rfc2247.ldif"
            shutil.copyfile(ipautil.SHARE_DIR + "05rfc2247.ldif", target_fname)
            os.chmod(target_fname, 0440)
            os.chown(target_fname, pent.pw_uid, pent.pw_gid)
        except IOError:
            # Does not apply with newer DS releases
            pass

    def restart(self, instance=''):
        try:
            super(DsInstance, self).restart(instance)
            if not is_ds_running(instance):
                root_logger.critical("Failed to restart the directory server. See the installation log for details.")
                sys.exit(1)
        except SystemExit, e:
            raise e
        except Exception, e:
            # TODO: roll back here?
            root_logger.critical("Failed to restart the directory server (%s). See the installation log for details." % e)

    def __restart_instance(self):
        self.restart(self.serverid)

    def __enable_entryusn(self):
        self._ldap_mod("entryusn.ldif")

    def __add_memberof_module(self):
        self._ldap_mod("memberof-conf.ldif")

    def init_memberof(self):

        if not self.run_init_memberof:
            return

        self._ldap_mod("memberof-task.ldif", self.sub_dict)
        # Note, keep dn in sync with dn in install/share/memberof-task.ldif
        dn = DN(('cn', 'IPA install %s' % self.sub_dict["TIME"]), ('cn', 'memberof task'),
                ('cn', 'tasks'), ('cn', 'config'))
        root_logger.debug("Waiting for memberof task to complete.")
        conn = ipaldap.IPAdmin("127.0.0.1")
        if self.dm_password:
            conn.simple_bind_s(DN(('cn', 'directory manager')), self.dm_password)
        else:
            conn.do_sasl_gssapi_bind()
        conn.checkTask(dn, dowait=True)
        conn.unbind()

    def apply_updates(self):
        ld = ldapupdate.LDAPUpdate(dm_password=self.dm_password, sub_dict=self.sub_dict, plugins=True)
        files = ld.get_all_files(ldapupdate.UPDATES_DIR)
        ld.update(files)

    def __add_referint_module(self):
        self._ldap_mod("referint-conf.ldif")

    def __disable_betxn(self):
        self._ldap_mod("disable-betxn.ldif", self.sub_dict)

    def __set_unique_attrs(self):
        self._ldap_mod("unique-attributes.ldif", self.sub_dict)

    def __config_uidgid_gen(self):
        self._ldap_mod("dna.ldif", self.sub_dict)

    def __add_master_entry(self):
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

    def __config_lockout_module(self):
        self._ldap_mod("lockout-conf.ldif")

    def __repoint_managed_entries(self):
        self._ldap_mod("repoint-managed-entries.ldif", self.sub_dict)

    def __managed_entries(self):
        self._ldap_mod("managed-entries.ldif", self.sub_dict)

    def __user_private_groups(self):
        self._ldap_mod("user_private_groups.ldif", self.sub_dict)

    def __host_nis_groups(self):
        self._ldap_mod("host_nis_groups.ldif", self.sub_dict)

    def __add_enrollment_module(self):
        self._ldap_mod("enrollment-conf.ldif", self.sub_dict)

    def generate_random(self):
        return ipautil.ipa_generate_password()

    def __enable_ssl(self):
        dirname = config_dirname(self.serverid)
        dsdb = certs.CertDB(self.realm_name, nssdir=dirname, subject_base=self.subject_base)
        if self.pkcs12_info:
            dsdb.create_from_pkcs12(self.pkcs12_info[0], self.pkcs12_info[1])
            server_certs = dsdb.find_server_certs()
            if len(server_certs) == 0:
                raise RuntimeError("Could not find a suitable server cert in import in %s" % self.pkcs12_info[0])

            # We only handle one server cert
            nickname = server_certs[0][0]
            self.dercert = dsdb.get_cert_from_db(nickname, pem=False)
            dsdb.track_server_cert(nickname, self.principal, dsdb.passwd_fname, 'restart_dirsrv %s' % self.serverid )
        else:
            nickname = "Server-Cert"
            cadb = certs.CertDB(self.realm_name, host_name=self.fqdn, subject_base=self.subject_base)
            if self.self_signed_ca:
                dsdb.create_from_cacert(cadb.cacert_fname, passwd=None)
                self.dercert = dsdb.create_server_cert("Server-Cert", self.fqdn, cadb)
                dsdb.track_server_cert("Server-Cert", self.principal, dsdb.passwd_fname, 'restart_dirsrv %s' % self.serverid)
                dsdb.create_pin_file()
            else:
                # FIXME, need to set this nickname in the RA plugin
                cadb.export_ca_cert('ipaCert', False)
                dsdb.create_from_cacert(cadb.cacert_fname, passwd=None)
                self.dercert = dsdb.create_server_cert("Server-Cert", self.fqdn, cadb)
                dsdb.track_server_cert("Server-Cert", self.principal, dsdb.passwd_fname, 'restart_dirsrv %s' % self.serverid)
                dsdb.create_pin_file()

        conn = ipaldap.IPAdmin("127.0.0.1")
        conn.simple_bind_s(DN(('cn', 'directory manager')), self.dm_password)

        mod = [(ldap.MOD_REPLACE, "nsSSLClientAuth", "allowed"),
               (ldap.MOD_REPLACE, "nsSSL3Ciphers",
                "-rsa_null_md5,+rsa_rc4_128_md5,+rsa_rc4_40_md5,+rsa_rc2_40_md5,\
+rsa_des_sha,+rsa_fips_des_sha,+rsa_3des_sha,+rsa_fips_3des_sha,+fortezza,\
+fortezza_rc4_128_sha,+fortezza_null,+tls_rsa_export1024_with_rc4_56_sha,\
+tls_rsa_export1024_with_des_cbc_sha")]
        conn.modify_s(DN(('cn', 'encryption'), ('cn', 'config')), mod)

        mod = [(ldap.MOD_ADD, "nsslapd-security", "on")]
        conn.modify_s(DN(('cn', 'config')), mod)

        entry = ipaldap.Entry(DN(('cn', 'RSA'), ('cn', 'encryption'), ('cn', 'config')))

        entry.setValues("objectclass", "top", "nsEncryptionModule")
        entry.setValues("cn", "RSA")
        entry.setValues("nsSSLPersonalitySSL", nickname)
        entry.setValues("nsSSLToken", "internal (software)")
        entry.setValues("nsSSLActivation", "on")

        conn.addEntry(entry)

        conn.unbind()

        # check for open secure port 636 from now on
        self.open_ports.append(636)

    def __add_default_layout(self):
        self._ldap_mod("bootstrap-template.ldif", self.sub_dict)

    def __add_delegation_layout(self):
        self._ldap_mod("delegation.ldif", self.sub_dict)

    def __add_replication_acis(self):
        self._ldap_mod("replica-acis.ldif", self.sub_dict)

    def __setup_s4u2proxy(self):
        self._ldap_mod("replica-s4u2proxy.ldif", self.sub_dict)

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
        root_logger.debug("Changing admin password")
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
                    "-ZZ", "-x", "-D", str(DN(('cn', 'Directory Manager'))),
                    "-y", dmpwdfile, "-T", admpwdfile,
                    str(DN(('uid', 'admin'), ('cn', 'users'), ('cn', 'accounts'), self.suffix))]
            try:
                env = { 'LDAPTLS_CACERTDIR':os.path.dirname(CACERT),
                        'LDAPTLS_CACERT':CACERT }
                ipautil.run(args, env=env)
                root_logger.debug("ldappasswd done")
            except ipautil.CalledProcessError, e:
                print "Unable to set admin password", e
                root_logger.debug("Unable to set admin password %s" % e)

        finally:
            if os.path.isfile(dmpwdfile):
                os.remove(dmpwdfile)
            if os.path.isfile(admpwdfile):
                os.remove(admpwdfile)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring directory server")

        enabled = self.restore_state("enabled")

        # Just eat this state if it exists
        running = self.restore_state("running")

        try:
            self.fstore.restore_file("/etc/security/limits.conf")
            self.fstore.restore_file("/etc/sysconfig/dirsrv")
        except ValueError, error:
            root_logger.debug(error)
            pass

        if not enabled is None and not enabled:
            self.disable()

        serverid = self.restore_state("serverid")
        if not serverid is None:
            # drop the trailing / off the config_dirname so the directory
            # will match what is in certmonger
            dirname = config_dirname(serverid)[:-1]
            dsdb = certs.CertDB(self.realm_name, nssdir=dirname)
            dsdb.untrack_server_cert("Server-Cert")
            erase_ds_instance_data(serverid)

        # At one time we removed this user on uninstall. That can potentially
        # orphan files, or worse, if another useradd runs in the intermim,
        # cause files to have a new owner.
        user_exists = self.restore_state("user_exists")

        # Make sure some upgrade-related state is removed. This could cause
        # re-installation problems.
        self.restore_state('nsslapd-port')
        self.restore_state('nsslapd-security')
        self.restore_state('nsslapd-ldapiautobind')

        # If any dirsrv instances remain after we've removed ours then
        # (re)start them.
        for ds_instance in get_ds_instances():
            try:
                ipaservices.knownservices.dirsrv.restart(ds_instance, wait=False)
            except Exception, e:
                root_logger.error('Unable to restart ds instance %s: %s', ds_instance, e)

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
                root_logger.critical("The given CA cert file named [%s] could not be read" %
                                             cacert_fname)
                return False
        except OSError, e:
            root_logger.critical("The given CA cert file named [%s] could not be read: %s" %
                                         (cacert_fname, str(e)))
            return False
        # ok - ca cert file can be read
        # shutdown the server
        self.stop()

        dirname = config_dirname(realm_to_serverid(self.realm_name))
        certdb = certs.CertDB(self.realm_name, nssdir=dirname, subject_base=self.subject_base)
        if not cacert_name or len(cacert_name) == 0:
            cacert_name = "Imported CA"
        # we can't pass in the nickname, so we set the instance variable
        certdb.cacert_name = cacert_name
        status = True
        try:
            certdb.load_cacert(cacert_fname)
        except ipautil.CalledProcessError, e:
            root_logger.critical("Error importing CA cert file named [%s]: %s" %
                                         (cacert_fname, str(e)))
            status = False
        # restart the directory server
        self.start()

        return status

    def tune_nofile(self, num=8192):
        """
        Increase the number of files descriptors available to directory server
        from the default 1024 to 8192. This will allow to support a greater
        number of clients out of the box.
        """

        # check limits.conf
        need_limits = True
        fd = open("/etc/security/limits.conf", "r")
        lines = fd.readlines()
        fd.close()
        for line in lines:
            sline = line.strip()
            if not sline.startswith(DS_USER):
                continue
            if sline.find('nofile') == -1:
                continue
            # ok we already have an explicit entry for user/nofile
            need_limits = False

        # check sysconfig/dirsrv
        need_sysconf = True
        fd = open("/etc/sysconfig/dirsrv", "r")
        lines = fd.readlines()
        fd.close()
        for line in lines:
            sline = line.strip()
            if not sline.startswith('ulimit'):
                continue
            if sline.find('-n') == -1:
                continue
            # ok we already have an explicit entry for file limits
            need_sysconf = False

        #if sysconf or limits are set avoid messing up and defer to the admin
        if need_sysconf and need_limits:
            self.fstore.backup_file("/etc/security/limits.conf")
            fd = open("/etc/security/limits.conf", "a+")
            fd.write('%s\t\t-\tnofile\t\t%s\n' % (DS_USER, str(num)))
            fd.close()

            fd = open("/etc/sysconfig/dirsrv", "a+")
            fd.write('ulimit -n %s\n' % str(num))
            fd.close()

        else:
            root_logger.info("Custom file limits are already set! Skipping\n")
            print "Custom file limits are already set! Skipping\n"
            return

        # finally change also DS configuration
        # NOTE: dirsrv will not allow you to set max file descriptors unless
        # the user limits allow it, so we have to restart dirsrv before
        # attempting to change them in cn=config
        self.__restart_instance()

        nf_sub_dict = dict(NOFILES=str(num))
        self._ldap_mod("ds-nfiles.ldif", nf_sub_dict)

    def __tuning(self):
        self.tune_nofile(8192)

    def __root_autobind(self):
        self._ldap_mod("root-autobind.ldif")

    def __add_sudo_binduser(self):
        self._ldap_mod("sudobind.ldif", self.sub_dict)

    def __add_automember_config(self):
        self._ldap_mod("automember.ldif", self.sub_dict)

    def __add_replica_automember_config(self):
        self._ldap_mod("replica-automember.ldif", self.sub_dict)

    def __add_range_check_plugin(self):
        self._ldap_mod("range-check-conf.ldif", self.sub_dict)

    def replica_populate(self):
        self.ldap_connect()

        dn = DN(('cn', 'default'), ('ou', 'profile'), self.suffix)
        try:
            entry = self.admin_conn.getEntry(dn, ldap.SCOPE_BASE, '(objectclass=*)')
            srvlist = entry.getValue('defaultServerList', '')
            srvlist = srvlist.split()
            if not self.fqdn in srvlist:
                srvlist.append(self.fqdn)
                attr = ' '.join(srvlist)
                mod = [(ldap.MOD_REPLACE, 'defaultServerList', attr)]
                self.admin_conn.modify_s(dn, mod)
        except errors.NotFound:
            pass
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass

        self.ldap_disconnect()
