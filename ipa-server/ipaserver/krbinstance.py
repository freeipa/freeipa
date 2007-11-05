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

import service
from ipa.ipautil import *

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

    def create_instance(self, ds_user, realm_name, host_name, admin_password, master_password):
        self.ds_user = ds_user
        self.fqdn = host_name
        self.ip = socket.gethostbyname(host_name)
        self.realm = realm_name.upper()
        self.host = host_name.split(".")[0]
        self.domain = host_to_domain(host_name)
        self.admin_password = admin_password
        self.master_password = master_password
        
	self.suffix = realm_to_suffix(self.realm)
        self.kdc_password = generate_kdc_password()

        try:
            self.stop()
        except:
            # It could have been not running
            pass

        self.start_creation(10, "Configuring Kerberos KDC")

	self.__configure_kdc_account_password()

        self.__setup_sub_dict()

        self.__configure_ldap()

        self.__create_instance()

        self.__create_ds_keytab()

        self.__export_kadmin_changepw_keytab()

        self.__add_pwd_extop_module()

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

        self.done_creation()

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

    def __configure_ldap(self):
        self.step("adding kerberos configuration to the directory")
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

    def __create_instance(self):
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

        #populate the directory with the realm structure
        args = ["/usr/kerberos/sbin/kdb5_ldap_util", "-D", "uid=kdc,cn=sysaccounts,cn=etc,"+self.suffix, "-w", self.kdc_password, "create", "-s", "-P", self.master_password, "-r", self.realm, "-subtrees", self.suffix, "-sscope", "sub"]
        try:
            run(args)
        except subprocess.CalledProcessError, e:
            print "Failed to populate the realm structure in kerberos", e

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

        #add an ACL to let the DS user read the master key
        args = ["/usr/bin/setfacl", "-m", "u:"+self.ds_user+":r", "/var/kerberos/krb5kdc/.k5."+self.realm]
        try:
            run(args)
        except subprocess.CalledProcessError, e:
            logging.critical("Failed to set the ACL on the master key: %s" % str(e))

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


