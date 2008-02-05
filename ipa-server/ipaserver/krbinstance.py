# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
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

import subprocess
import string
import tempfile
import shutil
import logging
import fileinput
import re
import sys
import os
import pwd
import socket
import shutil

import service
import sysrestore
import installutils
from ipa import ipautil
from ipa import ipaerror

import ipaldap

import ldap
from ldap import LDAPError
from ldap import ldapobject

from pyasn1.type import univ, namedtype
import pyasn1.codec.ber.encoder
import pyasn1.codec.ber.decoder
import struct
import base64

def host_to_domain(fqdn):
    s = fqdn.split(".")
    return ".".join(s[1:])

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
    def __init__(self):
        service.Service.__init__(self, "krb5kdc")
        self.ds_user = None
        self.fqdn = None
        self.realm = None
	self.domain = None
        self.host = None
        self.admin_password = None
        self.master_password = None
        self.suffix = None
        self.kdc_password = None
        self.sub_dict = None

        self.kpasswd = KpasswdInstance()

    def __common_setup(self, ds_user, realm_name, host_name, admin_password):
        self.ds_user = ds_user
        self.fqdn = host_name        
        self.realm = realm_name.upper()
        self.host = host_name.split(".")[0]
        self.ip = socket.gethostbyname(host_name)
        self.domain = host_to_domain(host_name)        
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.kdc_password = ipautil.ipa_generate_password()
        self.admin_password = admin_password

        self.__setup_sub_dict()

        # get a connection to the DS
        try:
            self.conn = ipaldap.IPAdmin(self.fqdn)
            self.conn.do_simple_bind(bindpw=self.admin_password)
        except ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR), e:
            logging.critical("Could not connect to DS")
            raise e

        self.backup_state("running", self.is_running())
        try:
            self.stop()
        except:
            # It could have been not running
            pass

    def __common_post_setup(self):
        self.step("starting the KDC", self.__start_instance)
        self.step("configuring KDC to start on boot", self.__enable)

    def create_instance(self, ds_user, realm_name, host_name, admin_password, master_password):
        self.master_password = master_password

        self.__common_setup(ds_user, realm_name, host_name, admin_password)

        self.step("setting KDC account password", self.__configure_kdc_account_password)
        self.step("adding sasl mappings to the directory", self.__configure_sasl_mappings)
        self.step("adding kerberos entries to the DS", self.__add_krb_entries)
        self.step("adding default ACIs", self.__add_default_acis)
        self.step("configuring KDC", self.__create_instance)
        self.step("adding default keytypes", self.__add_default_keytypes)
        self.step("creating a keytab for the directory", self.__create_ds_keytab)
        self.step("creating a keytab for the machine", self.__create_host_keytab)
        self.step("exporting the kadmin keytab", self.__export_kadmin_changepw_keytab)
        self.step("adding the password extenstion to the directory", self.__add_pwd_extop_module)

        self.__common_post_setup()

        self.start_creation("Configuring Kerberos KDC")

        self.kpasswd.create_instance()

    def create_replica(self, ds_user, realm_name, host_name, admin_password, ldap_passwd_filename):
        self.__copy_ldap_passwd(ldap_passwd_filename)

        self.__common_setup(ds_user, realm_name, host_name, admin_password)

        self.step("adding sasl mappings to the directory", self.__configure_sasl_mappings)
        self.step("writing stash file from DS", self.__write_stash_from_ds)
        self.step("configuring KDC", self.__create_replica_instance)
        self.step("creating a keytab for the directory", self.__create_ds_keytab)
        self.step("creating a keytab for the machine", self.__create_host_keytab)
        self.step("exporting the kadmin keytab", self.__export_kadmin_changepw_keytab)

        self.__common_post_setup()

        self.start_creation("Configuring Kerberos KDC")

        self.kpasswd.create_instance()

    def __copy_ldap_passwd(self, filename):
        sysrestore.backup_file("/var/kerberos/krb5kdc/ldappwd")
        shutil.copy(filename, "/var/kerberos/krb5kdc/ldappwd")
        os.chmod("/var/kerberos/krb5kdc/ldappwd", 0600)
        
        
    def __configure_kdc_account_password(self):
        hexpwd = ''
	for x in self.kdc_password:
            hexpwd += (hex(ord(x))[2:])
        sysrestore.backup_file("/var/kerberos/krb5kdc/ldappwd")
        pwd_fd = open("/var/kerberos/krb5kdc/ldappwd", "w")
        pwd_fd.write("uid=kdc,cn=sysaccounts,cn=etc,"+self.suffix+"#{HEX}"+hexpwd+"\n")
        pwd_fd.close()
        os.chmod("/var/kerberos/krb5kdc/ldappwd", 0600)

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        self.chkconfig_on()

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
                             REALM=self.realm)

    def __ldap_mod(self, ldif):
        txt = ipautil.template_file(ipautil.SHARE_DIR + ldif, self.sub_dict)
        fd = ipautil.write_tmp_file(txt)

        args = ["/usr/bin/ldapmodify", "-h", "127.0.0.1", "-xv",
                "-D", "cn=Directory Manager", "-w", self.admin_password, "-f", fd.name]

        try:
            ipautil.run(args)
        except ipautil.CalledProcessError, e:
            logging.critical("Failed to load %s: %s" % (ldif, str(e)))

        fd.close()

    def __configure_sasl_mappings(self):
        # we need to remove any existing SASL mappings in the directory as otherwise they
        # they may conflict. There is no way to define the order they are used in atm.

        # FIXME: for some reason IPAdmin dies here, so we switch
        # it out for a regular ldapobject.
        conn = self.conn
        self.conn = ldapobject.SimpleLDAPObject("ldap://127.0.0.1/")
        self.conn.bind("cn=directory manager", self.admin_password)
        try:
            msgid = self.conn.search("cn=mapping,cn=sasl,cn=config", ldap.SCOPE_ONELEVEL, "(objectclass=nsSaslMapping)")
            res = self.conn.result(msgid)
            for r in res[1]:
                mid = self.conn.delete_s(r[0])
        #except LDAPError, e:
        #    logging.critical("Error during SASL mapping removal: %s" % str(e))
        except Exception, e:
            print type(e)
            print dir(e)
            raise e
            
        self.conn = conn

        entry = ipaldap.Entry("cn=Full Principal,cn=mapping,cn=sasl,cn=config")
        entry.setValues("objectclass", "top", "nsSaslMapping")
        entry.setValues("cn", "Full Principal")
        entry.setValues("nsSaslMapRegexString", '\(.*\)@\(.*\)')
        entry.setValues("nsSaslMapBaseDNTemplate", self.suffix)
        entry.setValues("nsSaslMapFilterTemplate", '(krbPrincipalName=\\1@\\2)')

        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            logging.critical("failed to add Full Principal Sasl mapping")
            raise e

        entry = ipaldap.Entry("cn=Name Only,cn=mapping,cn=sasl,cn=config")
        entry.setValues("objectclass", "top", "nsSaslMapping")
        entry.setValues("cn", "Name Only")
        entry.setValues("nsSaslMapRegexString", '\(.*\)')
        entry.setValues("nsSaslMapBaseDNTemplate", self.suffix)
        entry.setValues("nsSaslMapFilterTemplate", '(krbPrincipalName=\\1@%s)' % self.realm)

        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            logging.critical("failed to add Name Only Sasl mapping")
            raise e

    def __add_krb_entries(self):
        self.__ldap_mod("kerberos.ldif")

    def __add_default_acis(self):
        self.__ldap_mod("default-aci.ldif")

    def __add_default_keytypes(self):
        self.__ldap_mod("default-keytypes.ldif")

    def __create_replica_instance(self):
        self.__create_instance(replica=True)

    def __template_file(self, path):
        template = os.path.join(ipautil.SHARE_DIR, os.path.basename(path) + ".template")
        conf = ipautil.template_file(template, self.sub_dict)
        sysrestore.backup_file(path)
        fd = open(path, "w+")
        fd.write(conf)
        fd.close()

    def __create_instance(self, replica=False):
        self.__template_file("/var/kerberos/krb5kdc/kdc.conf")
        self.__template_file("/etc/krb5.conf")
        self.__template_file("/usr/share/ipa/html/krb5.ini")
        self.__template_file("/usr/share/ipa/html/krb.con")
        self.__template_file("/usr/share/ipa/html/krbrealm.con")

        if not replica:
            #populate the directory with the realm structure
            args = ["/usr/kerberos/sbin/kdb5_ldap_util", "-D", "uid=kdc,cn=sysaccounts,cn=etc,"+self.suffix, "-w", self.kdc_password, "create", "-s", "-P", self.master_password, "-r", self.realm, "-subtrees", self.suffix, "-sscope", "sub"]
            try:
                ipautil.run(args)
            except ipautil.CalledProcessError, e:
                print "Failed to populate the realm structure in kerberos", e

    def __write_stash_from_ds(self):
        try:
            entry = self.conn.getEntry("cn=%s, cn=kerberos, %s" % (self.realm, self.suffix), ldap.SCOPE_SUBTREE)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND), e:
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
        except os.error, e:
            logging.critical("failed to write stash file")
            raise e

    #add the password extop module
    def __add_pwd_extop_module(self):
        self.__ldap_mod("pwd-extop-conf.ldif")

        #get the Master Key from the stash file
        try:
            stash = open("/var/kerberos/krb5kdc/.k5."+self.realm, "r")
            keytype = struct.unpack('h', stash.read(2))[0]
            keylen = struct.unpack('i', stash.read(4))[0]
            keydata = stash.read(keylen)
        except os.error:
            logging.critical("Failed to retrieve Master Key from Stash file: %s")
	#encode it in the asn.1 attribute
        MasterKey = univ.Sequence()
        MasterKey.setComponentByPosition(0, univ.Integer(keytype))
        MasterKey.setComponentByPosition(1, univ.OctetString(keydata))
        krbMKey = univ.Sequence()
        krbMKey.setComponentByPosition(0, univ.Integer(0)) #we have no kvno
        krbMKey.setComponentByPosition(1, MasterKey)
        asn1key = pyasn1.codec.ber.encoder.encode(krbMKey)

        entry = ipaldap.Entry("cn="+self.realm+",cn=kerberos,"+self.suffix)
        dn = "cn="+self.realm+",cn=kerberos,"+self.suffix
        mod = [(ldap.MOD_ADD, 'krbMKey', str(asn1key))]
        try:
            self.conn.modify_s(dn, mod)
        except ldap.TYPE_OR_VALUE_EXISTS, e:
            logging.critical("failed to add master key to kerberos database\n")
            raise e

    def __create_ds_keytab(self):
        ldap_principal = "ldap/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(ldap_principal)

        sysrestore.backup_file("/etc/dirsrv/ds.keytab")
        installutils.create_keytab("/etc/dirsrv/ds.keytab", ldap_principal)

        sysrestore.backup_file("/etc/sysconfig/dirsrv")
        update_key_val_in_file("/etc/sysconfig/dirsrv", "export KRB5_KTNAME", "/etc/dirsrv/ds.keytab")
        pent = pwd.getpwnam(self.ds_user)
        os.chown("/etc/dirsrv/ds.keytab", pent.pw_uid, pent.pw_gid)

    def __create_host_keytab(self):
        host_principal = "host/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(host_principal)

        sysrestore.backup_file("/etc/krb5.keytab")
        installutils.create_keytab("/etc/krb5.keytab", host_principal)

        # Make sure access is strictly reserved to root only for now
        os.chown("/etc/krb5.keytab", 0, 0)
        os.chmod("/etc/krb5.keytab", 0600)

    def __export_kadmin_changepw_keytab(self):
        installutils.kadmin_modprinc("kadmin/changepw", "+requires_preauth")

        sysrestore.backup_file("/var/kerberos/krb5kdc/kpasswd.keytab")
        installutils.create_keytab("/var/kerberos/krb5kdc/kpasswd.keytab", "kadmin/changepw")

        sysrestore.backup_file("/etc/sysconfig/ipa_kpasswd")
        update_key_val_in_file("/etc/sysconfig/ipa_kpasswd", "export KRB5_KTNAME", "/var/kerberos/krb5kdc/kpasswd.keytab")
        pent = pwd.getpwnam(self.ds_user)
        os.chown("/var/kerberos/krb5kdc/kpasswd.keytab", pent.pw_uid, pent.pw_gid)

    def uninstall(self):
        self.kpasswd.uninstall()

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if not running is None:
            self.stop()

        if not enabled is None and not enabled:
            self.chkconfig_off()

        for f in ["/var/kerberos/krb5kdc/ldappwd",
                  "/var/kerberos/krb5kdc/kdc.conf",
                  "/etc/krb5.conf",
                  "/usr/share/ipa/html/krb5.ini",
                  "/usr/share/ipa/html/krb.con",
                  "/usr/share/ipa/html/krbrealm.con",
                  "/etc/dirsrv/ds.keytab",
                  "/etc/sysconfig/dirsrv",
                  "/etc/krb5.keytab",
                  "/var/kerberos/krb5kdc/kpasswd.keytab",
                  "/etc/sysconfig/ipa_kpasswd"]:
            sysrestore.restore_file(f)

        if not running is None and running:
            self.start()
