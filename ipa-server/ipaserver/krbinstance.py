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
from random import Random
from time import gmtime
import os
import pwd
import socket
import time
from util import *

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

class KrbInstance:
    def __init__(self):
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
	self.__configure_kdc_account_password()

        self.__setup_sub_dict()

        self.__configure_ldap()

        self.__create_instance()

        self.__create_ds_keytab()

        self.__create_http_keytab()

        self.__create_sample_bind_zone()

        self.start()

    def stop(self):
        run(["/sbin/service", "krb5kdc", "stop"])

    def start(self):
        run(["/sbin/service", "krb5kdc", "start"])

    def restart(self):
        run(["/sbin/service", "krb5kdc", "restart"])

    def __configure_kdc_account_password(self):
        hexpwd = ''
	for x in self.kdc_password:
            hexpwd += (hex(ord(x))[2:])
        pwd_fd = open("/var/kerberos/krb5kdc/ldappwd", "a+")
        pwd_fd.write("uid=kdc,cn=kerberos,"+self.suffix+"#{HEX}"+hexpwd+"\n")
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

	#TODO: test that the ldif is ok with any random charcter we may use in the password
        kerberos_txt = template_file(SHARE_DIR + "kerberos.ldif", self.sub_dict)
        kerberos_fd = write_tmp_file(kerberos_txt)
        ldap_mod(kerberos_fd, "cn=Directory Manager", self.admin_password)
        kerberos_fd.close()

	#Change the default ACL to avoid anonimous access to kerberos keys and othe hashes
        aci_txt = template_file(SHARE_DIR + "default-aci.ldif", self.sub_dict)
        aci_fd = write_tmp_file(aci_txt) 
        ldap_mod(aci_fd, "cn=Directory Manager", self.admin_password)
        aci_fd.close()

    def __create_instance(self):
        kdc_conf = template_file(SHARE_DIR+"kdc.conf.template", self.sub_dict)
        kdc_fd = open("/var/kerberos/krb5kdc/kdc.conf", "w+")
        kdc_fd.write(kdc_conf)
        kdc_fd.close()

        krb5_conf = template_file(SHARE_DIR+"krb5.conf.template", self.sub_dict)
        krb5_fd = open("/etc/krb5.conf", "w+")
        krb5_fd.write(krb5_conf)
        krb5_fd.close()

        #populate the directory with the realm structure
        args = ["/usr/kerberos/sbin/kdb5_ldap_util", "-D", "uid=kdc,cn=kerberos,"+self.suffix, "-w", self.kdc_password, "create", "-s", "-P", self.master_password, "-r", self.realm, "-subtrees", self.suffix, "-sscope", "sub"]
        run(args)

    # TODO: NOT called yet, need to find out how to make sure the plugin is available first
    def __add_pwd_extop_module(self):
	#add the password extop module
	extop_txt = template_file(SHARE_DIR + "ipapwd_extop_plugin.ldif", self.sub_dict)
	extop_fd = write_tmp_file(extop_txt)
	ldap_mod(extop_fd, "cn=Directory Manager", self.admin_password)
	extop_fd.close()

	#add an ACL to let the DS user read the master key
	args = ["/usr/bin/setfacl", "-m", "u:"+self.ds_user+":r", "/var/kerberos/krb5kdc/.k5."+self.realm]
	run(args)

    def __create_sample_bind_zone(self):
        bind_txt = template_file(SHARE_DIR + "bind.zone.db.template", self.sub_dict)
        [bind_fd, bind_name] = tempfile.mkstemp(".db","sample.zone.")
        os.write(bind_fd, bind_txt)
        os.close(bind_fd)
        print "Sample zone file for bind has been created in "+bind_name

    def __create_ds_keytab(self):
        (kwrite, kread, kerr) = os.popen3("/usr/kerberos/sbin/kadmin.local")
        kwrite.write("addprinc -randkey ldap/"+self.fqdn+"@"+self.realm+"\n")
        kwrite.flush()
        kwrite.write("ktadd -k /etc/fedora-ds/ds.keytab ldap/"+self.fqdn+"@"+self.realm+"\n")
        kwrite.flush()
        kwrite.close()
        kread.close()
        kerr.close()

	cfg_fd = open("/etc/sysconfig/fedora-ds", "a")
        cfg_fd.write("export KRB5_KTNAME=/etc/fedora-ds/ds.keytab\n")
        cfg_fd.close()
	pent = pwd.getpwnam(self.ds_user)
        os.chown("/etc/sysconfig/fedora-ds", pent.pw_uid, pent.pw_gid)

    def __create_http_keytab(self):
        (kwrite, kread, kerr) = os.popen3("/usr/kerberos/sbin/kadmin.local")
        kwrite.write("addprinc -randkey HTTP/"+self.fqdn+"@"+self.realm+"\n")
        kwrite.flush()
        kwrite.write("ktadd -k /etc/httpd/conf/ipa.keytab HTTP/"+self.fqdn+"@"+self.realm+"\n")
        kwrite.flush()
        kwrite.close()
        kread.close()
        kerr.close()

        while not file_exists("/etc/httpd/conf/ipa.keytab"):
            time.sleep(1)
        pent = pwd.getpwnam("apache")
        os.chown("/etc/httpd/conf/ipa.keytab", pent.pw_uid, pent.pw_gid)
