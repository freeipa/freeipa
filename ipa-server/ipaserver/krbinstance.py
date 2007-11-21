#! /usr/bin/python -E
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
from random import Random
from time import gmtime
import os
import pwd
import socket
import time
import shutil

import service
from ipa.ipautil import *
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

def generate_kdc_password():
    rndpwd = ''
    r = Random()
    r.seed(gmtime())
    for x in range(12):
#        rndpwd += chr(r.randint(32,126))
        rndpwd += chr(r.randint(65,90)) #stricter set for testing
    return rndpwd

def ldap_mod(fd, dn, pwd):
    args = ["/usr/bin/ldapmodify", "-h", "127.0.0.1", "-xv", "-D", dn, "-w", pwd, "-f", fd.name]
    run(args)

def update_key_val_in_file(filename, key, val):
    if os.path.exists(filename):
        pattern = "^[\s#]*%s\s*=" % re.escape(key)
        p = re.compile(pattern)
        for line in fileinput.input(filename, inplace=1):
            if not p.search(line):
                sys.stdout.write(line)
        fileinput.close()
    f = open(filename, "a")
    f.write("%s=%s\n" % (key, val))
    f.close()
    
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

    def __common_setup(self, ds_user, realm_name, host_name, admin_password):
        self.ds_user = ds_user
        self.fqdn = host_name        
        self.realm = realm_name.upper()
        self.host = host_name.split(".")[0]
        self.ip = socket.gethostbyname(host_name)
        self.domain = host_to_domain(host_name)        
	self.suffix = realm_to_suffix(self.realm)
        self.kdc_password = generate_kdc_password()
        self.admin_password = admin_password

        self.__setup_sub_dict()

        # get a connection to the DS
        try:
            self.conn = ipaldap.IPAdmin(self.fqdn)
            self.conn.do_simple_bind(bindpw=self.admin_password)
        except ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR), e:
            logging.critical("Could not connect to DS")
            raise e

        try:
            self.stop()
        except:
            # It could have been not running
            pass

    def __common_post_setup(self):
        try:
            self.step("starting the KDC")
            self.start()
        except:
            logging.critical("krb5kdc service failed to start")

        self.step("configuring KDC to start on boot")
        self.chkconfig_on()

        self.step("configuring ipa-kpasswd to start on boot")
        service.chkconfig_on("ipa-kpasswd")

        self.step("starting ipa-kpasswd")
        service.start("ipa-kpasswd")


    def create_instance(self, ds_user, realm_name, host_name, admin_password, master_password):
        self.master_password = master_password

        self.__common_setup(ds_user, realm_name, host_name, admin_password)

        self.start_creation(11, "Configuring Kerberos KDC")
        
	self.__configure_kdc_account_password()
        self.__configure_sasl_mappings()
        self.__add_krb_entries()
        self.__create_instance()
        self.__create_ds_keytab()
        self.__export_kadmin_changepw_keytab()
        self.__add_pwd_extop_module()

        self.__common_post_setup()

        self.done_creation()


    def create_replica(self, ds_user, realm_name, host_name, admin_password, ldap_passwd_filename):
        
        self.__common_setup(ds_user, realm_name, host_name, admin_password)

        self.start_creation(9, "Configuring Kerberos KDC")
        self.__copy_ldap_passwd(ldap_passwd_filename)
        self.__configure_sasl_mappings()
        self.__write_stash_from_ds()
        self.__create_instance(replica=True)
        self.__create_ds_keytab()
        self.__export_kadmin_changepw_keytab()

        self.__common_post_setup()

        self.done_creation()


    def __copy_ldap_passwd(self, filename):
        shutil.copy(filename, "/var/kerberos/krb5kdc/ldappwd")
        
        
    def __configure_kdc_account_password(self):
        self.step("setting KDC account password")
        hexpwd = ''
	for x in self.kdc_password:
            hexpwd += (hex(ord(x))[2:])
        pwd_fd = open("/var/kerberos/krb5kdc/ldappwd", "w")
        pwd_fd.write("uid=kdc,cn=sysaccounts,cn=etc,"+self.suffix+"#{HEX}"+hexpwd+"\n")
        pwd_fd.close()

    def __setup_sub_dict(self):
        self.sub_dict = dict(FQDN=self.fqdn,
                             IP=self.ip,
                             PASSWORD=self.kdc_password,
                             SUFFIX=self.suffix,
                             DOMAIN=self.domain,
                             HOST=self.host,
                             REALM=self.realm)

    def __configure_sasl_mappings(self):
        self.step("adding sasl mappings to the directory")
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
        self.step("adding kerberos entries to the DS")

        #TODO: test that the ldif is ok with any random charcter we may use in the password
        kerberos_txt = template_file(SHARE_DIR + "kerberos.ldif", self.sub_dict)
        kerberos_fd = write_tmp_file(kerberos_txt)
        try:
            ldap_mod(kerberos_fd, "cn=Directory Manager", self.admin_password)
        except subprocess.CalledProcessError, e:
            logging.critical("Failed to load kerberos.ldif: %s" % str(e))
        kerberos_fd.close()

	#Change the default ACL to avoid anonimous access to kerberos keys and othe hashes
        aci_txt = template_file(SHARE_DIR + "default-aci.ldif", self.sub_dict)
        aci_fd = write_tmp_file(aci_txt) 
        try:
            ldap_mod(aci_fd, "cn=Directory Manager", self.admin_password)
        except subprocess.CalledProcessError, e:
            logging.critical("Failed to load default-aci.ldif: %s" % str(e))
        aci_fd.close()

    def __create_instance(self, replica=False):
        self.step("configuring KDC")
        kdc_conf = template_file(SHARE_DIR+"kdc.conf.template", self.sub_dict)
        kdc_fd = open("/var/kerberos/krb5kdc/kdc.conf", "w+")
        kdc_fd.write(kdc_conf)
        kdc_fd.close()

        krb5_conf = template_file(SHARE_DIR+"krb5.conf.template", self.sub_dict)
        krb5_fd = open("/etc/krb5.conf", "w+")
        krb5_fd.write(krb5_conf)
        krb5_fd.close()

        # Windows configuration files
        krb5_ini = template_file(SHARE_DIR+"krb5.ini.template", self.sub_dict)
        krb5_fd = open("/usr/share/ipa/html/krb5.ini", "w+")
        krb5_fd.write(krb5_ini)
        krb5_fd.close()

        krb_con = template_file(SHARE_DIR+"krb.con.template", self.sub_dict)
        krb_fd = open("/usr/share/ipa/html/krb.con", "w+")
        krb_fd.write(krb_con)
        krb_fd.close()

        krb_realm = template_file(SHARE_DIR+"krbrealm.con.template", self.sub_dict)
        krb_fd = open("/usr/share/ipa/html/krbrealm.con", "w+")
        krb_fd.write(krb_realm)
        krb_fd.close()

        if not replica:
            #populate the directory with the realm structure
            args = ["/usr/kerberos/sbin/kdb5_ldap_util", "-D", "uid=kdc,cn=sysaccounts,cn=etc,"+self.suffix, "-w", self.kdc_password, "create", "-s", "-P", self.master_password, "-r", self.realm, "-subtrees", self.suffix, "-sscope", "sub"]
            try:
                run(args)
            except subprocess.CalledProcessError, e:
                print "Failed to populate the realm structure in kerberos", e

    def __write_stash_from_ds(self):
        self.step("writing stash file from DS")
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
        self.step("adding the password extenstion to the directory")
        extop_txt = template_file(SHARE_DIR + "pwd-extop-conf.ldif", self.sub_dict)
        extop_fd = write_tmp_file(extop_txt)
        try:
            ldap_mod(extop_fd, "cn=Directory Manager", self.admin_password)
        except subprocess.CalledProcessError, e:
            logging.critical("Failed to load pwd-extop-conf.ldif: %s" % str(e))
        extop_fd.close()

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
        self.step("creating a keytab for the directory")
        try:
            if file_exists("/etc/dirsrv/ds.keytab"):
                os.remove("/etc/dirsrv/ds.keytab")
        except os.error:
            logging.critical("Failed to remove /etc/dirsrv/ds.keytab.")
        (kwrite, kread, kerr) = os.popen3("/usr/kerberos/sbin/kadmin.local")
        kwrite.write("addprinc -randkey ldap/"+self.fqdn+"@"+self.realm+"\n")
        kwrite.flush()
        kwrite.write("ktadd -k /etc/dirsrv/ds.keytab ldap/"+self.fqdn+"@"+self.realm+"\n")
        kwrite.flush()
        kwrite.close()
        kread.close()
        kerr.close()

        # give kadmin time to actually write the file before we go on
	retry = 0
        while not file_exists("/etc/dirsrv/ds.keytab"):
            time.sleep(1)
            retry += 1
            if retry > 15:
                logging.critical("Error timed out waiting for kadmin to finish operations")
                sys.exit(1)

        update_key_val_in_file("/etc/sysconfig/dirsrv", "export KRB5_KTNAME", "/etc/dirsrv/ds.keytab")
        pent = pwd.getpwnam(self.ds_user)
        os.chown("/etc/dirsrv/ds.keytab", pent.pw_uid, pent.pw_gid)

    def __export_kadmin_changepw_keytab(self):
        self.step("exporting the kadmin keytab")
        (kwrite, kread, kerr) = os.popen3("/usr/kerberos/sbin/kadmin.local")
        kwrite.write("modprinc +requires_preauth kadmin/changepw\n")
        kwrite.flush()
        kwrite.close()
        kread.close()
        kerr.close()

        (kwrite, kread, kerr) = os.popen3("/usr/kerberos/sbin/kadmin.local")
        kwrite.write("ktadd -k /var/kerberos/krb5kdc/kpasswd.keytab kadmin/changepw\n")
        kwrite.flush()
        kwrite.close()
        kread.close()
        kerr.close()

        # give kadmin time to actually write the file before we go on
	retry = 0
        while not file_exists("/var/kerberos/krb5kdc/kpasswd.keytab"):
            time.sleep(1)
            retry += 1
            if retry > 15:
                logging.critical("Error timed out waiting for kadmin to finish operations")
                sys.exit(1)

        update_key_val_in_file("/etc/sysconfig/ipa-kpasswd", "export KRB5_KTNAME", "/var/kerberos/krb5kdc/kpasswd.keytab")
        pent = pwd.getpwnam(self.ds_user)
        os.chown("/var/kerberos/krb5kdc/kpasswd.keytab", pent.pw_uid, pent.pw_gid)


