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

SHARE_DIR = "/usr/share/ipa/"

def realm_to_suffix(realm_name):
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)

def generate_kdc_password():
    rndpwd = ''
    r = Random()
    r.seed(gmtime())
    for x in range(12):
#        rndpwd += chr(r.randint(32,126))
        rndpwd += chr(r.randint(65,90)) #stricter set for testing
    return rndpwd

def template_str(txt, vars):
    return string.Template(txt).substitute(vars)

def template_file(infilename, vars):
    txt = open(infilename).read()
    return template_str(txt, vars)

def write_tmp_file(txt):
    fd = tempfile.NamedTemporaryFile()
    fd.write(txt)
    fd.flush()

    return fd

def ldap_mod(fd, dn, pwd):
    args = ["/usr/bin/ldapmodify", "-h", "127.0.0.1", "-xv", "-D", dn, "-w", pwd, "-f", fd.name]
    run(args)

def run(args, stdin=None):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if stdin:
        stdout,stderr = p.communicate(stdin)
    else:
        stdout,stderr = p.communicate()
    logging.info(stdout)
    logging.info(stderr)

    if p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, args[0])
    
class KrbInstance:
    def __init__(self):
        self.realm_name = None
        self.host_name = None
        self.admin_password = None
        self.master_password = None
        self.suffix = None
        self.kdc_password = None
        self.sub_dict = None

    def create_instance(self, realm_name, host_name, admin_password, master_password):
        self.realm_name = realm_name.upper()
        self.host_name = host_name
        self.admin_password = admin_password
        self.master_password = master_password
        
	self.suffix = realm_to_suffix(self.realm_name)
        self.kdc_password = generate_kdc_password()
	self.__configure_kdc_account_password()

        self.__setup_sub_dict()

        self.__configure_ldap()

        self.__create_instance()

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
        pwd_fd.write("#test:"+self.kdc_password+"\n")
        pwd_fd.close()

    def __setup_sub_dict(self):
	#FIXME: can DOMAIN be different than REALM ?
        self.sub_dict = dict(FQHN=self.host_name,
                             PASSWORD=self.kdc_password,
                             SUFFIX=self.suffix,
                             DOMAIN= self.realm_name.lower(),
                             REALM=self.realm_name)

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
        args = ["/usr/kerberos/sbin/kdb5_ldap_util", "-D", "uid=kdc,cn=kerberos,"+self.suffix, "-w", self.kdc_password, "create", "-s", "-r", self.realm_name, "-subtrees", self.suffix, "-sscope", "sub"]
        run(args)
