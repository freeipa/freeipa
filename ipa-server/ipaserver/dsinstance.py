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

import shutil
import logging
import pwd
import glob
import sys
import os

from ipa import ipautil

import service
import installutils

SERVER_ROOT_64 = "/usr/lib64/dirsrv"
SERVER_ROOT_32 = "/usr/lib/dirsrv"

def ldap_mod(fd, dn, pwd):
    args = ["/usr/bin/ldapmodify", "-h", "127.0.0.1", "-xv", "-D", dn, "-w", pwd, "-f", fd.name]
    ipautil.run(args)

def realm_to_suffix(realm_name):
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)

def find_server_root():
    if ipautil.dir_exists(SERVER_ROOT_64):
        return SERVER_ROOT_64
    else:
        return SERVER_ROOT_32

def realm_to_serverid(realm_name):
    return "-".join(realm_name.split("."))

def config_dirname(realm_name):
    return "/etc/dirsrv/slapd-" + realm_to_serverid(realm_name) + "/"

def schema_dirname(realm_name):
    return config_dirname(realm_name) + "/schema/"

def erase_ds_instance_data(serverid):
    try:
        shutil.rmtree("/etc/dirsrv/slapd-%s" % serverid)
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

def check_existing_installation():
    dirs = glob.glob("/etc/dirsrv/slapd-*")
    if not dirs:
        return
    print ""
    print "An existing Directory Server has been detected."
    yesno = raw_input("Do you wish to remove it and create a new one? [no]: ")
    if not yesno or yesno.lower()[0] != "y":
        sys.exit(1)

    try:
        ipautil.run(["/sbin/service", "dirsrv", "stop"])
    except:
        pass
    for d in dirs:
        serverid = os.path.basename(d).split("slapd-", 1)[1]
        if serverid:
            erase_ds_instance_data(serverid)

def check_ports():
    ds_unsecure = installutils.port_available(389)
    ds_secure = installutils.port_available(636)
    if not ds_unsecure or not ds_secure:
        print "IPA requires ports 389 and 636 for the Directory Server."
        print "These are currently in use:"
        if not ds_unsecure:
            print "\t389"
        if not ds_secure:
            print "\t636"
        sys.exit(1)


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

class DsInstance(service.Service):
    def __init__(self):
        service.Service.__init__(self, "dirsrv")
        self.serverid = None
        self.realm_name = None
        self.suffix = None
        self.host_name = None
        self.dm_password = None
        self.sub_dict = None
        self.domain = None

    def create_instance(self, ds_user, realm_name, host_name, dm_password, ro_replica=False):
        self.ds_user = ds_user
        self.realm_name = realm_name.upper()
        self.serverid = realm_to_serverid(self.realm_name)
        self.suffix = realm_to_suffix(self.realm_name)
        self.host_name = host_name
        self.dm_password = dm_password
        self.domain = host_name[host_name.find(".")+1:]
        self.__setup_sub_dict()
        
        if ro_replica:
            self.start_creation(15, "Configuring directory server:")
        else:
            self.start_creation(15, "Configuring directory server:")

        self.__create_ds_user()
        self.__create_instance()
        self.__add_default_schemas()
        if not ro_replica:
            self.__add_memberof_module()
        self.__add_referint_module()
        self.__add_dna_module()
        self.__create_indeces()
        self.__enable_ssl()
        self.__certmap_conf()
        try:
            self.step("restarting directory server")
            self.restart()
        except:
            # TODO: roll back here?
            logging.critical("Failed to restart the ds instance")
        self.__add_default_layout()
        if not ro_replica:
            self.__config_uidgid_gen_first_master()
            self.__add_master_entry_first_master()
            self.__init_memberof()


        self.step("configuring directoy to start on boot")
        self.chkconfig_on()

        self.done_creation()

    def __setup_sub_dict(self):
        server_root = find_server_root()
        self.sub_dict = dict(FQHN=self.host_name, SERVERID=self.serverid,
                             PASSWORD=self.dm_password, SUFFIX=self.suffix.lower(),
                             REALM=self.realm_name, USER=self.ds_user,
                             SERVER_ROOT=server_root, DOMAIN=self.domain)

    def __create_ds_user(self):
        self.step("creating directory server user")
	try:
            pwd.getpwnam(self.ds_user)
            logging.debug("ds user %s exists" % self.ds_user)
	except KeyError:
            logging.debug("adding ds user %s" % self.ds_user)
            args = ["/usr/sbin/useradd", "-c", "DS System User", "-d", "/var/lib/dirsrv", "-M", "-r", "-s", "/sbin/nologin", self.ds_user]
            try:
                ipautil.run(args)
                logging.debug("done adding user")
            except ipautil.CalledProcessError, e:
                logging.critical("failed to add user %s" % e)

    def __create_instance(self):
        self.step("creating directory server instance")
        inf_txt = ipautil.template_str(INF_TEMPLATE, self.sub_dict)
        logging.debug(inf_txt)
        inf_fd = ipautil.write_tmp_file(inf_txt)
        logging.debug("writing inf template")
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
            self.restart()
            logging.debug("done restarting ds instance")
        except ipautil.CalledProcessError, e:
            print "failed to restart ds instance", e
            logging.debug("failed to restart ds instance %s" % e)

    def __add_default_schemas(self):
        self.step("adding default schema")
        shutil.copyfile(ipautil.SHARE_DIR + "60kerberos.ldif",
                        schema_dirname(self.realm_name) + "60kerberos.ldif")
        shutil.copyfile(ipautil.SHARE_DIR + "60samba.ldif",
                        schema_dirname(self.realm_name) + "60samba.ldif")
        shutil.copyfile(ipautil.SHARE_DIR + "60radius.ldif",
                        schema_dirname(self.realm_name) + "60radius.ldif")
        shutil.copyfile(ipautil.SHARE_DIR + "60ipaconfig.ldif",
                        schema_dirname(self.realm_name) + "60ipaconfig.ldif")

    def __add_memberof_module(self):
        self.step("enabling memboerof plugin")
        memberof_txt = ipautil.template_file(ipautil.SHARE_DIR + "memberof-conf.ldif", self.sub_dict)
        memberof_fd = ipautil.write_tmp_file(memberof_txt)
        try:
            ldap_mod(memberof_fd, "cn=Directory Manager", self.dm_password)
        except ipautil.CalledProcessError, e:
            logging.critical("Failed to load memberof-conf.ldif: %s" % str(e))
        memberof_fd.close()

    def __init_memberof(self):
        self.step("initializing group membership")
        memberof_txt = ipautil.template_file(ipautil.SHARE_DIR + "memberof-task.ldif", self.sub_dict)
        memberof_fd = ipautil.write_tmp_file(memberof_txt)
        try:
            ldap_mod(memberof_fd, "cn=Directory Manager", self.dm_password)
        except ipautil.CalledProcessError, e:
            logging.critical("Failed to load memberof-conf.ldif: %s" % str(e))
        memberof_fd.close()

    def __add_referint_module(self):
        self.step("enabling referential integrity plugin")
        referint_txt = ipautil.template_file(ipautil.SHARE_DIR + "referint-conf.ldif", self.sub_dict)
        referint_fd = ipautil.write_tmp_file(referint_txt)
        try:
            ldap_mod(referint_fd, "cn=Directory Manager", self.dm_password)
        except ipautil.CalledProcessError, e:
            print "Failed to load referint-conf.ldif", e
        referint_fd.close()

    def __add_dna_module(self):
        self.step("enabling distributed numeric assignment plugin")
        dna_txt = ipautil.template_file(ipautil.SHARE_DIR + "dna-conf.ldif", self.sub_dict)
        dna_fd = ipautil.write_tmp_file(dna_txt)
        try:
            ldap_mod(dna_fd, "cn=Directory Manager", self.dm_password)
        except ipautil.CalledProcessError, e:
            print "Failed to load dna-conf.ldif", e
        dna_fd.close()

    def __config_uidgid_gen_first_master(self):
        self.step("configuring Posix uid/gid generation as first master")
        dna_txt = ipautil.template_file(ipautil.SHARE_DIR + "dna-posix.ldif", self.sub_dict)
        dna_fd = ipautil.write_tmp_file(dna_txt)
        try:
            ldap_mod(dna_fd, "cn=Directory Manager", self.dm_password)
        except ipautil.CalledProcessError, e:
            print "Failed to configure Posix uid/gid generation with dna-posix.ldif", e
        dna_fd.close()

    def __add_master_entry_first_master(self):
        self.step("adding master entry as first master")
        master_txt = ipautil.template_file(ipautil.SHARE_DIR + "master-entry.ldif", self.sub_dict)
        master_fd = ipautil.write_tmp_file(master_txt)
        try:
            ldap_mod(master_fd, "cn=Directory Manager", self.dm_password)
        except ipautil.CalledProcessError, e:
            print "Failed to add master-entry.ldif", e
        master_fd.close()

    def __enable_ssl(self):
        self.step("configuring ssl for ds instance")
        dirname = config_dirname(self.realm_name)
        args = ["/usr/share/ipa/ipa-server-setupssl", self.dm_password,
                dirname, self.host_name]
        try:
            ipautil.run(args)
            logging.debug("done configuring ssl for ds instance")
        except ipautil.CalledProcessError, e:
            logging.critical("Failed to configure ssl in ds instance %s" % e)
        
    def __add_default_layout(self):
        self.step("adding default layout")
        txt = ipautil.template_file(ipautil.SHARE_DIR + "bootstrap-template.ldif", self.sub_dict)
        inf_fd = ipautil.write_tmp_file(txt)
        logging.debug("adding default dfrom ipa.ipautil import *s layout")
        args = ["/usr/bin/ldapmodify", "-xv", "-D", "cn=Directory Manager",
                "-w", self.dm_password, "-f", inf_fd.name]
        try:
            ipautil.run(args)
            logging.debug("done adding default ds layout")
        except ipautil.CalledProcessError, e:
            print "Failed to add default ds layout", e
            logging.critical("Failed to add default ds layout %s" % e)
        
    def __create_indeces(self):
        self.step("creating indeces")
        txt = ipautil.template_file(ipautil.SHARE_DIR + "indeces.ldif", self.sub_dict)
        inf_fd = ipautil.write_tmp_file(txt)
        logging.debug("adding/updating indeces")
        args = ["/usr/bin/ldapmodify", "-xv", "-D", "cn=Directory Manager",
                "-w", self.dm_password, "-f", inf_fd.name]
        try:
            ipautil.run(args)
            logging.debug("done adding/updating indeces")
        except ipautil.CalledProcessError, e:
            logging.critical("Failed to add/update indeces %s" % str(e))

    def __certmap_conf(self):
        self.step("configuring certmap.conf")
        dirname = config_dirname(self.realm_name)
        certmap_conf = ipautil.template_file(ipautil.SHARE_DIR + "certmap.conf.template", self.sub_dict)
        certmap_fd = open(dirname+"certmap.conf", "w+")
        certmap_fd.write(certmap_conf)
        certmap_fd.close()

    def change_admin_password(self, password):
        logging.debug("Changing admin password")
        dirname = config_dirname(self.realm_name)
        if ipautil.dir_exists("/usr/lib64/mozldap"):
            app = "/usr/lib64/mozldap/ldappasswd"
        else:
            app = "/usr/lib/mozldap/ldappasswd"
        args = [app,
                "-D", "cn=Directory Manager", "-w", self.dm_password,
                "-P", dirname+"/cert8.db", "-ZZZ", "-s", password,
                "uid=admin,cn=sysaccounts,cn=etc,"+self.suffix]
        try:
            ipautil.run(args)
            logging.debug("ldappasswd done")
        except ipautil.CalledProcessError, e:
            print "Unable to set admin password", e
            logging.debug("Unable to set admin password %s" % e)

