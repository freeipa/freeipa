# Authors: Simo Sorce <ssorce@redhat.com>
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
import logging
import fileinput
import re
import sys
import os
import pwd
import socket

import service
import installutils
from ipapython import sysrestore
from ipapython import ipautil
from ipalib import util
from ipalib import errors

from ipaserver import ipaldap
from ipaserver.install import replication
from ipaserver.install import dsinstance

import ldap
from ldap import LDAPError
from ldap import ldapobject

from pyasn1.type import univ, namedtype
import pyasn1.codec.ber.encoder
import pyasn1.codec.ber.decoder
import struct

import certs
from distutils import version

KRBMKEY_DENY_ACI = '(targetattr = "krbMKey")(version 3.0; acl "No external access"; deny (read,write,search,compare) userdn != "ldap:///uid=kdc,cn=sysaccounts,cn=etc,$SUFFIX";)'

def update_key_val_in_file(filename, key, val):
    if os.path.exists(filename):
        pattern = "^[\s#]*%s\s*=\s*%s\s*" % (re.escape(key), re.escape(val))
        p = re.compile(pattern)
        for line in fileinput.input(filename):
            if p.search(line):
                fileinput.close()
                return
        fileinput.close()

        pattern = "^[\s#]*%s\s*=" % re.escape(key)
        p = re.compile(pattern)
        for line in fileinput.input(filename, inplace=1):
            if not p.search(line):
                sys.stdout.write(line)
        fileinput.close()
    f = open(filename, "a")
    f.write("%s=%s\n" % (key, val))
    f.close()

class KpasswdInstance(service.SimpleServiceInstance):
    def __init__(self):
        service.SimpleServiceInstance.__init__(self, "ipa_kpasswd")

class KrbInstance(service.Service):
    def __init__(self, fstore=None):
        service.Service.__init__(self, "krb5kdc")
        self.fqdn = None
        self.realm = None
        self.domain = None
        self.host = None
        self.admin_password = None
        self.master_password = None
        self.suffix = None
        self.kdc_password = None
        self.sub_dict = None
        self.pkcs12_info = None
        self.self_signed_ca = None

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def move_service_to_host(self, principal):
        """
        Used to move a host/ service principal created by kadmin.local from
        cn=kerberos to reside under the host entry.
        """

        service_dn = "krbprincipalname=%s,cn=%s,cn=kerberos,%s" % (principal, self.realm, self.suffix)
        service_entry = self.admin_conn.getEntry(service_dn, ldap.SCOPE_BASE)
        self.admin_conn.deleteEntry(service_dn)

        # Create a host entry for this master
        host_dn = "fqdn=%s,cn=computers,cn=accounts,%s" % (self.fqdn, self.suffix)
        host_entry = ipaldap.Entry(host_dn)
        host_entry.setValues('objectclass', ['top', 'ipaobject', 'nshost', 'ipahost', 'ipaservice', 'pkiuser', 'krbprincipalaux', 'krbprincipal', 'krbticketpolicyaux'])
        host_entry.setValues('krbextradata', service_entry.getValues('krbextradata'))
        host_entry.setValue('krblastpwdchange', service_entry.getValue('krblastpwdchange'))
        host_entry.setValue('krbpasswordexpiration', service_entry.getValue('krbpasswordexpiration'))
        host_entry.setValue('krbprincipalname', service_entry.getValue('krbprincipalname'))
        if 'krbticketflags' in service_entry.toDict():
            host_entry.setValue('krbticketflags', service_entry.getValue('krbticketflags'))
        host_entry.setValue('krbprincipalkey', service_entry.getValue('krbprincipalkey'))
        host_entry.setValue('serverhostname', self.fqdn.split('.',1)[0])
        host_entry.setValue('cn', self.fqdn)
        host_entry.setValue('fqdn', self.fqdn)
        host_entry.setValue('ipauniqueid', 'autogenerate')
        host_entry.setValue('managedby', host_dn)
        self.admin_conn.addEntry(host_entry)

    def __common_setup(self, realm_name, host_name, domain_name, admin_password):
        self.fqdn = host_name
        self.realm = realm_name.upper()
        self.host = host_name.split(".")[0]
        self.ip = socket.getaddrinfo(host_name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)[0][4][0]
        self.domain = domain_name
        self.suffix = util.realm_to_suffix(self.realm)
        self.kdc_password = ipautil.ipa_generate_password()
        self.admin_password = admin_password
        self.dm_password = admin_password

        self.__setup_sub_dict()

        # get a connection to the DS
        self.ldap_connect()

        self.backup_state("running", self.is_running())
        try:
            self.stop()
        except:
            # It could have been not running
            pass

    def __common_post_setup(self):
        self.step("starting the KDC", self.__start_instance)
        self.step("configuring KDC to start on boot", self.__enable)

    def create_instance(self, realm_name, host_name, domain_name, admin_password, master_password, setup_pkinit=False, pkcs12_info=None, self_signed_ca=False, subject_base=None):
        self.master_password = master_password
        self.pkcs12_info = pkcs12_info
        self.self_signed_ca = self_signed_ca
        self.subject_base = subject_base

        self.__common_setup(realm_name, host_name, domain_name, admin_password)

        self.step("setting KDC account password", self.__configure_kdc_account_password)
        self.step("adding sasl mappings to the directory", self.__configure_sasl_mappings)
        self.step("adding kerberos entries to the DS", self.__add_krb_entries)
        self.step("adding default ACIs", self.__add_default_acis)
        self.step("configuring KDC", self.__create_instance)
        self.step("adding default keytypes", self.__add_default_keytypes)
        self.step("adding default password policy", self.__add_default_pwpolicy)
        self.step("creating a keytab for the directory", self.__create_ds_keytab)
        self.step("creating a keytab for the machine", self.__create_host_keytab)
        self.step("exporting the kadmin keytab", self.__export_kadmin_changepw_keytab)
        self.step("adding the password extension to the directory", self.__add_pwd_extop_module)
        self.step("adding the kerberos master key to the directory", self.__add_master_key)
        if setup_pkinit:
            self.step("creating X509 Certificate for PKINIT", self.__setup_pkinit)
            self.step("creating principal for anonymous PKINIT", self.__add_anonymous_pkinit_principal)

        self.__common_post_setup()

        self.start_creation("Configuring Kerberos KDC", 30)

        self.kpasswd = KpasswdInstance()
        self.kpasswd.create_instance('KPASSWD', self.fqdn, self.admin_password, self.suffix)

    def create_replica(self, realm_name,
                       master_fqdn, host_name,
                       domain_name, admin_password,
                       ldap_passwd_filename, kpasswd_filename,
                       setup_pkinit=False, pkcs12_info=None,
                       self_signed_ca=False, subject_base=None):
        self.pkcs12_info = pkcs12_info
        self.self_signed_ca = self_signed_ca
        self.subject_base = subject_base
        self.__copy_ldap_passwd(ldap_passwd_filename)
        self.__copy_kpasswd_keytab(kpasswd_filename)
        self.master_fqdn = master_fqdn

        self.__common_setup(realm_name, host_name, domain_name, admin_password)

        self.step("adding sasl mappings to the directory", self.__configure_sasl_mappings)
        self.step("writing stash file from DS", self.__write_stash_from_ds)
        self.step("configuring KDC", self.__create_replica_instance)
        self.step("creating a keytab for the directory", self.__create_ds_keytab)
        self.step("creating a keytab for the machine", self.__create_host_keytab)
        self.step("adding the password extension to the directory", self.__add_pwd_extop_module)
        if setup_pkinit:
            self.step("installing X509 Certificate for PKINIT", self.__setup_pkinit)
        self.step("enable GSSAPI for replication", self.__convert_to_gssapi_replication)

        self.__common_post_setup()

        self.start_creation("Configuring Kerberos KDC", 30)

        self.kpasswd = KpasswdInstance()
        self.kpasswd.create_instance('KPASSWD', self.fqdn, self.admin_password, self.suffix)

    def __copy_ldap_passwd(self, filename):
        self.fstore.backup_file("/var/kerberos/krb5kdc/ldappwd")
        shutil.copy(filename, "/var/kerberos/krb5kdc/ldappwd")
        os.chmod("/var/kerberos/krb5kdc/ldappwd", 0600)

    def __copy_kpasswd_keytab(self, filename):
        self.fstore.backup_file("/var/kerberos/krb5kdc/kpasswd.keytab")
        shutil.copy(filename, "/var/kerberos/krb5kdc/kpasswd.keytab")
        os.chmod("/var/kerberos/krb5kdc/kpasswd.keytab", 0600)


    def __configure_kdc_account_password(self):
        hexpwd = ''
	for x in self.kdc_password:
            hexpwd += (hex(ord(x))[2:])
        self.fstore.backup_file("/var/kerberos/krb5kdc/ldappwd")
        pwd_fd = open("/var/kerberos/krb5kdc/ldappwd", "w")
        pwd_fd.write("uid=kdc,cn=sysaccounts,cn=etc,"+self.suffix+"#{HEX}"+hexpwd+"\n")
        pwd_fd.close()
        os.chmod("/var/kerberos/krb5kdc/ldappwd", 0600)

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        self.ldap_enable('KDC', self.fqdn, self.admin_password, self.suffix)

    def __start_instance(self):
        try:
            self.start()
        except:
            logging.critical("krb5kdc service failed to start")

    def __setup_sub_dict(self):
        self.sub_dict = dict(FQDN=self.fqdn,
                             IP=self.ip,
                             PASSWORD=self.kdc_password,
                             SUFFIX=self.suffix,
                             DOMAIN=self.domain,
                             HOST=self.host,
                             SERVER_ID=dsinstance.realm_to_serverid(self.realm),
                             REALM=self.realm)

    def __configure_sasl_mappings(self):
        # we need to remove any existing SASL mappings in the directory as otherwise they
        # they may conflict.

        try:
            res = self.admin_conn.search_s("cn=mapping,cn=sasl,cn=config",
                                     ldap.SCOPE_ONELEVEL,
                                     "(objectclass=nsSaslMapping)")
            for r in res:
                try:
                    self.admin_conn.delete_s(r.dn)
                except LDAPError, e:
                    logging.critical("Error during SASL mapping removal: %s" % str(e))
                    raise e
        except LDAPError, e:
            logging.critical("Error while enumerating SASL mappings %s" % str(e))
            raise e

        entry = ipaldap.Entry("cn=Full Principal,cn=mapping,cn=sasl,cn=config")
        entry.setValues("objectclass", "top", "nsSaslMapping")
        entry.setValues("cn", "Full Principal")
        entry.setValues("nsSaslMapRegexString", '\(.*\)@\(.*\)')
        entry.setValues("nsSaslMapBaseDNTemplate", self.suffix)
        entry.setValues("nsSaslMapFilterTemplate", '(krbPrincipalName=\\1@\\2)')

        try:
            self.admin_conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            logging.critical("failed to add Full Principal Sasl mapping")
            raise e

        entry = ipaldap.Entry("cn=Name Only,cn=mapping,cn=sasl,cn=config")
        entry.setValues("objectclass", "top", "nsSaslMapping")
        entry.setValues("cn", "Name Only")
        entry.setValues("nsSaslMapRegexString", '^[^:@]+$')
        entry.setValues("nsSaslMapBaseDNTemplate", self.suffix)
        entry.setValues("nsSaslMapFilterTemplate", '(krbPrincipalName=&@%s)' % self.realm)

        try:
            self.admin_conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            logging.critical("failed to add Name Only Sasl mapping")
            raise e

    def __add_krb_entries(self):
        self._ldap_mod("kerberos.ldif", self.sub_dict)

    def __add_default_acis(self):
        self._ldap_mod("default-aci.ldif", self.sub_dict)

    def __add_default_keytypes(self):
        self._ldap_mod("default-keytypes.ldif", self.sub_dict)

    def __add_default_pwpolicy(self):
        self._ldap_mod("default-pwpolicy.ldif", self.sub_dict)

    def __create_replica_instance(self):
        self.__create_instance(replica=True)

    def __template_file(self, path, chmod=0644):
        template = os.path.join(ipautil.SHARE_DIR, os.path.basename(path) + ".template")
        conf = ipautil.template_file(template, self.sub_dict)
        self.fstore.backup_file(path)
        fd = open(path, "w+")
        fd.write(conf)
        fd.close()
        if chmod is not None:
            os.chmod(path, chmod)

    def __create_instance(self, replica=False):
        self.__template_file("/var/kerberos/krb5kdc/kdc.conf", chmod=None)
        self.__template_file("/etc/krb5.conf")
        self.__template_file("/usr/share/ipa/html/krb5.ini")
        self.__template_file("/usr/share/ipa/html/krb.con")
        self.__template_file("/usr/share/ipa/html/krbrealm.con")

        if not replica:
            #populate the directory with the realm structure
            args = ["kdb5_ldap_util", "-D", "uid=kdc,cn=sysaccounts,cn=etc,"+self.suffix, "-w", self.kdc_password, "create", "-s", "-P", self.master_password, "-r", self.realm, "-subtrees", self.suffix, "-sscope", "sub"]
            try:
                ipautil.run(args, nolog=(self.kdc_password, self.master_password))
            except ipautil.CalledProcessError, e:
                print "Failed to populate the realm structure in kerberos", e

        MIN_KRB5KDC_WITH_WORKERS = "1.9"
        cpus = os.sysconf('SC_NPROCESSORS_ONLN')
        workers = False
        (stdout, stderr, rc) = ipautil.run(['klist', '-V'], raiseonerr=False)
        if rc == 0:
            verstr = stdout.split()[-1]
            ver = version.LooseVersion(verstr)
            min = version.LooseVersion(MIN_KRB5KDC_WITH_WORKERS)
            if ver >= min:
                workers = True
        if workers and cpus > 1:
            #read in memory, find KRB5KDC_ARGS, check/change it, then overwrite file
            self.fstore.backup_file("/etc/sysconfig/krb5kdc")

            need_w = True
            fd = open("/etc/sysconfig/krb5kdc", "r")
            lines = fd.readlines()
            fd.close()
            for line in lines:
                sline = line.strip()
                if not sline.startswith('KRB5KDC_ARGS'):
                    continue
                sline = sline.replace('"', '')
                if sline.find("-w") != -1:
                    need_w = False

            if need_w:
                fd = open("/etc/sysconfig/krb5kdc", "w")
                for line in lines:
                    fd.write(line)
                fd.write('KRB5KDC_ARGS="${KRB5KDC_ARGS} -w %s"\n' % str(cpus))
                fd.close()

    def __write_stash_from_ds(self):
        try:
            entry = self.admin_conn.getEntry("cn=%s, cn=kerberos, %s" % (self.realm, self.suffix), ldap.SCOPE_SUBTREE)
        except errors.NotFound, e:
            logging.critical("Could not find master key in DS")
            raise e

        krbMKey = pyasn1.codec.ber.decoder.decode(entry.krbmkey)
        keytype = int(krbMKey[0][1][0])
        keydata = str(krbMKey[0][1][1])

        format = '=hi%ss' % len(keydata)
        s = struct.pack(format, keytype, len(keydata), keydata)
        try:
            fd = open("/var/kerberos/krb5kdc/.k5."+self.realm, "w")
            fd.write(s)
            fd.close()
        except os.error, e:
            logging.critical("failed to write stash file")
            raise e

    #add the password extop module
    def __add_pwd_extop_module(self):
        self._ldap_mod("pwd-extop-conf.ldif", self.sub_dict)

    def __add_master_key(self):
        #check for a keytab file by checking if the header magic is for a keytab
        def __is_keytab(header):
            if header == 0x0502 or header == 0x0501 or header == 0x0205 or header == 0x0105:
                return 1
            else:
                return 0
        #check whether a keytab file is v1 or v2
        def __keytab_version(header):
            if header == 0x0502 or header == 0x0205:
                return 2
            elif header == 0x0501 or header == 0x0105:
                return 1
            else:
                return 0
        #get the Master Key from the stash file
        try:
            stash = open("/var/kerberos/krb5kdc/.k5."+self.realm, "r")
            keytype = struct.unpack('h', stash.read(2))[0]
            if __is_keytab(keytype):
                #in v2, all numbers are stored in network order
                if __keytab_version(keytype) > 1:
                    __endian = '!'
                else:
                    __endian = ''
                #walk the first entry (there should only be one)
                keyentrylen = struct.unpack(__endian + 'i', stash.read(4))[0]
                #number of components in the principal name
                keyprinccomps = struct.unpack(__endian + 'h', stash.read(2))[0]
                #version 1 counted the realm as a component, version 2 doesn't
                if __keytab_version(keytype) == 1:
                    keyprinccomps = keyprinccomps - 1
                keyprinc = []
                #read the components. the realm goes first, so we should
                #end up with (realm, "K", "M")
                for i in range(keyprinccomps + 1):
                    keyprinccompsize = struct.unpack(__endian + 'h', stash.read(2))[0]
                    keyprinc = keyprinc + [stash.read(keyprinccompsize)]
                #version 2 added the principal name type, otherwise we just
                #assume it's a regular old principal name
                if __keytab_version(keytype) > 1:
                    keyprinctype = struct.unpack(__endian + 'i', stash.read(4))[0]
                else:
                    keyprinctype = 1
                #date the key was added to this keytab
                keydate = struct.unpack(__endian + 'i', stash.read(4))[0]
                #kvno
                keyversion = struct.unpack('B', stash.read(1))[0]
                #read the real enctype
                keytype = struct.unpack(__endian + 'h', stash.read(2))[0]
                keylen = struct.unpack(__endian + 'h', stash.read(2))[0]
                keydata = stash.read(keylen)
                #check that we parsed the whole file, so no surprises
                keyoffset = stash.tell()
                stash.seek(0,2)
                if stash.tell() != keyoffset:
                    logging.critical("Unexpected unprocessed data in Stash file (processed %ld bytes, %ld left)." % (keyoffset, stash.tell() - keyoffset))
            else:
                keyversion = 1
                keyprinctype = 1
                keyprinc = [self.realm,"K","M"]
                keylen = struct.unpack('i', stash.read(4))[0]
                keydata = stash.read(keylen)
        except os.error:
            logging.critical("Failed to retrieve Master Key from Stash file: %s")
	#encode it in the asn.1 attribute
        MasterKey = univ.Sequence()
        MasterKey.setComponentByPosition(0, univ.Integer(keytype))
        MasterKey.setComponentByPosition(1, univ.OctetString(keydata))
        krbMKey = univ.Sequence()
        krbMKey.setComponentByPosition(0, univ.Integer(keyversion))
        krbMKey.setComponentByPosition(1, MasterKey)
        asn1key = pyasn1.codec.ber.encoder.encode(krbMKey)

        dn = "cn="+self.realm+",cn=kerberos,"+self.suffix
        #protect the master key by adding an appropriate deny rule along with the key
        mod = [(ldap.MOD_ADD, 'aci', ipautil.template_str(KRBMKEY_DENY_ACI, self.sub_dict)),
               (ldap.MOD_ADD, 'krbMKey', str(asn1key))]
        try:
            self.admin_conn.modify_s(dn, mod)
        except ldap.TYPE_OR_VALUE_EXISTS, e:
            logging.critical("failed to add master key to kerberos database\n")
            raise e

    def __create_ds_keytab(self):
        ldap_principal = "ldap/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(ldap_principal)
        self.move_service(ldap_principal)

        self.fstore.backup_file("/etc/dirsrv/ds.keytab")
        installutils.create_keytab("/etc/dirsrv/ds.keytab", ldap_principal)

        update_key_val_in_file("/etc/sysconfig/dirsrv", "export KRB5_KTNAME", "/etc/dirsrv/ds.keytab")
        pent = pwd.getpwnam(dsinstance.DS_USER)
        os.chown("/etc/dirsrv/ds.keytab", pent.pw_uid, pent.pw_gid)

    def __create_host_keytab(self):
        host_principal = "host/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(host_principal)

        self.fstore.backup_file("/etc/krb5.keytab")
        installutils.create_keytab("/etc/krb5.keytab", host_principal)

        # Make sure access is strictly reserved to root only for now
        os.chown("/etc/krb5.keytab", 0, 0)
        os.chmod("/etc/krb5.keytab", 0600)

        self.move_service_to_host(host_principal)

    def __export_kadmin_changepw_keytab(self):
        installutils.kadmin_modprinc("kadmin/changepw", "+requires_preauth")

        self.fstore.backup_file("/var/kerberos/krb5kdc/kpasswd.keytab")
        installutils.create_keytab("/var/kerberos/krb5kdc/kpasswd.keytab", "kadmin/changepw")

    def __setup_pkinit(self):
        if self.self_signed_ca:
            ca_db = certs.CertDB(self.realm,
                                 subject_base=self.subject_base)
        else:
            ca_db = certs.CertDB(self.realm, host_name=self.fqdn,
                                 subject_base=self.subject_base)

        if self.pkcs12_info:
            ca_db.install_pem_from_p12(self.pkcs12_info[0],
                                       self.pkcs12_info[1],
                                       "/var/kerberos/krb5kdc/kdc.pem")
        else:
            if self.self_signed_ca:
                ca_db.create_kdc_cert("KDC-Cert", self.fqdn,
                                      "/var/kerberos/krb5kdc")
            else:
                raise RuntimeError("PKI not supported yet\n")

        # Finally copy the cacert in the krb directory so we don't
        # have any selinux issues with the file context
        shutil.copyfile("/etc/ipa/ca.crt", "/var/kerberos/krb5kdc/cacert.pem")

    def __add_anonymous_pkinit_principal(self):
        princ = "WELLKNOWN/ANONYMOUS"
        princ_realm = "%s@%s" % (princ, self.realm)

        # Create the special anonymous principal
        installutils.kadmin_addprinc(princ_realm)
        dn = "krbprincipalname=%s,cn=%s,cn=kerberos,%s" % (princ_realm, self.realm, self.suffix)
        self.admin_conn.inactivateEntry(dn, False)

    def __convert_to_gssapi_replication(self):
        repl = replication.ReplicationManager(self.realm,
                                              self.fqdn,
                                              self.dm_password)
        repl.convert_to_gssapi_replication(self.master_fqdn,
                                           r_binddn="cn=Directory Manager",
                                           r_bindpw=self.dm_password)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        try:
            self.stop()
        except:
            pass

        for f in ["/var/kerberos/krb5kdc/ldappwd", "/var/kerberos/krb5kdc/kdc.conf", "/etc/krb5.conf"]:
            try:
                self.fstore.restore_file(f)
            except ValueError, error:
                logging.debug(error)
                pass

        if not enabled is None and not enabled:
            self.chkconfig_off()

        if not running is None and running:
            self.start()

        self.kpasswd = KpasswdInstance()
        self.kpasswd.uninstall()
