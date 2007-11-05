#! /usr/bin/python -E
# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
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
import pwd
from ipa.ipautil import *

SERVER_ROOT_64 = "/usr/lib64/dirsrv"
SERVER_ROOT_32 = "/usr/lib/dirsrv"

def ldap_mod(fd, dn, pwd):
    args = ["/usr/bin/ldapmodify", "-h", "127.0.0.1", "-xv", "-D", dn, "-w", pwd, "-f", fd.name]
    run(args)

def realm_to_suffix(realm_name):
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)

def find_server_root():
    if dir_exists(SERVER_ROOT_64):
        return SERVER_ROOT_64
    else:
        return SERVER_ROOT_32

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
"""

class DsInstance:
    def __init__(self):
        self.serverid = None
        self.realm_name = None
        self.suffix = None
        self.host_name = None
        self.dm_password = None
        self.sub_dict = None

    def create_instance(self, ds_user, realm_name, host_name, dm_password):
        self.ds_user = ds_user
        self.realm_name = realm_name.upper()
        self.serverid = "-".join(self.realm_name.split("."))
        self.suffix = realm_to_suffix(self.realm_name)
        self.host_name = host_name
        self.dm_password = dm_password
        self.__setup_sub_dict()

        self.__create_ds_user()
        self.__create_instance()
        self.__add_default_schemas()
        self.__add_memberof_module()
        self.__add_referint_module()
        self.__create_indeces()
        self.__enable_ssl()
        self.__certmap_conf()
        try:
            self.restart()
        except:
            # TODO: roll back here?
            print "Failed to restart the ds instance"
        self.__add_default_layout()

    def config_dirname(self):
        if not self.serverid:
            raise RuntimeError("serverid not set")
        return "/etc/dirsrv/slapd-" + self.serverid + "/"

    def schema_dirname(self):
        return self.config_dirname() + "/schema/"

    def stop(self):
        run(["/sbin/service", "dirsrv", "stop"])

    def start(self):
        run(["/sbin/service", "dirsrv", "start"])

    def restart(self):
        run(["/sbin/service", "dirsrv", "restart"])

    def __setup_sub_dict(self):
        server_root = find_server_root()
        self.sub_dict = dict(FQHN=self.host_name, SERVERID=self.serverid,
                             PASSWORD=self.dm_password, SUFFIX=self.suffix,
                             REALM=self.realm_name, USER=self.ds_user,
                             SERVER_ROOT=server_root)

    def __create_ds_user(self):
	try:
            pwd.getpwnam(self.ds_user)
            logging.debug("ds user %s exists" % self.ds_user)
	except KeyError:
            logging.debug("adding ds user %s" % self.ds_user)
            args = ["/usr/sbin/useradd", "-c", "DS System User", "-d", "/var/lib/dirsrv", "-M", "-r", "-s", "/sbin/nologin", self.ds_user]
            try:
                run(args)
                logging.debug("done adding user")
            except subprocess.CalledProcessError, e:
                print "Failed to add user", e
                logging.debug("failed to add user %s" % e)

    def __create_instance(self):
        logging.debug("creating ds instance . . . ")
        inf_txt = template_str(INF_TEMPLATE, self.sub_dict)
        logging.debug(inf_txt)
        inf_fd = write_tmp_file(inf_txt)
        logging.debug("writing inf template")
        if file_exists("/usr/sbin/setup-ds.pl"):
            args = ["/usr/sbin/setup-ds.pl", "--silent", "--logfile", "-", "-f", inf_fd.name]
            logging.debug("calling setup-ds.pl")
        else:
            args = ["/usr/bin/ds_newinst.pl", inf_fd.name]
            logging.debug("calling ds_newinst.pl")
        try:
            run(args)
            logging.debug("completed creating ds instance")
        except subprocess.CalledProcessError, e:
            print "failed to restart ds instance", e
            logging.debug("failed to restart ds instance %s" % e)
        logging.debug("restarting ds instance")
        try:
            self.restart()
            logging.debug("done restarting ds instance")
        except subprocess.CalledProcessError, e:
            print "failed to restart ds instance", e
            logging.debug("failed to restart ds instance %s" % e)

    def __add_default_schemas(self):
        shutil.copyfile(SHARE_DIR + "60kerberos.ldif",
                        self.schema_dirname() + "60kerberos.ldif")
        shutil.copyfile(SHARE_DIR + "60samba.ldif",
                        self.schema_dirname() + "60samba.ldif")

    def __add_memberof_module(self):
        memberof_txt = template_file(SHARE_DIR + "memberof-conf.ldif", self.sub_dict)
        memberof_fd = write_tmp_file(memberof_txt)
        try:
            ldap_mod(memberof_fd, "cn=Directory Manager", self.dm_password)
        except subprocess.CalledProcessError, e:
            print "Failed to load memberof-conf.ldif", e
        memberof_fd.close()

    def __add_referint_module(self):
        referint_txt = template_file(SHARE_DIR + "referint-conf.ldif", self.sub_dict)
        referint_fd = write_tmp_file(referint_txt)
        try:
            ldap_mod(referint_fd, "cn=Directory Manager", self.dm_password)
        except subprocess.CalledProcessError, e:
            print "Failed to load referint-conf.ldif", e
        referint_fd.close()

    def __enable_ssl(self):
        logging.debug("configuring ssl for ds instance")
        dirname = self.config_dirname()
        args = ["/usr/share/ipa/ipa-server-setupssl", self.dm_password,
                dirname, self.host_name]
        try:
            run(args)
            logging.debug("done configuring ssl for ds instance")
        except subprocess.CalledProcessError, e:
            print "Failed to enable ssl in ds instance", e
            logging.debug("Failed to configure ssl in ds instance %s" % e)
        
    def __add_default_layout(self):
        txt = template_file(SHARE_DIR + "bootstrap-template.ldif", self.sub_dict)
        inf_fd = write_tmp_file(txt)
        logging.debug("adding default ds layout")
        args = ["/usr/bin/ldapmodify", "-xv", "-D", "cn=Directory Manager",
                "-w", self.dm_password, "-f", inf_fd.name]
        try:
            run(args)
            logging.debug("done adding default ds layout")
        except subprocess.CalledProcessError, e:
            print "Failed to add default ds layout", e
            logging.debug("Failed to add default ds layout %s" % e)
        
    def __create_indeces(self):
        txt = template_file(SHARE_DIR + "indeces.ldif", self.sub_dict)
        inf_fd = write_tmp_file(txt)
        logging.debug("adding/updating indeces")
        args = ["/usr/bin/ldapmodify", "-xv", "-D", "cn=Directory Manager",
                "-w", self.dm_password, "-f", inf_fd.name]
        try:
            run(args)
            logging.debug("done adding/updating indeces")
        except subprocess.CalledProcessError, e:
            print "Failed to add default ds layout", e
            logging.debug("Failed to add/update indeces %s" % e)

    def __certmap_conf(self):
        logging.debug("configuring certmap.conf for ds instance")
        dirname = self.config_dirname()
        certmap_conf = template_file(SHARE_DIR+"certmap.conf.template", self.sub_dict)
        certmap_fd = open(dirname+"certmap.conf", "w+")
        certmap_fd.write(certmap_conf)
        certmap_fd.close()
        logging.debug("done configuring certmap.conf for ds instance")

    def change_admin_password(self, password):
        logging.debug("Changing admin password")
        dirname = self.config_dirname()
        if dir_exists("/usr/lib64/mozldap"):
            app = "/usr/lib64/mozldap/ldappasswd"
        else:
            app = "/usr/lib/mozldap/ldappasswd"
        args = [app,
                "-D", "cn=Directory Manager", "-w", self.dm_password,
                "-P", dirname+"/cert8.db", "-ZZZ", "-s", password,
                "uid=admin,cn=sysaccounts,cn=etc,"+self.suffix]
        try:
            run(args)
            logging.debug("ldappasswd done")
        except subprocess.CalledProcessError, e:
            print "Unable to set admin password", e
            logging.debug("Unable to set admin password %s" % e)

