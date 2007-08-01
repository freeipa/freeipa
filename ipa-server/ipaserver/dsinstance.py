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
from util import *


SHARE_DIR = "/usr/share/ipa/"
SERVER_ROOT_64 = "/usr/lib64/fedora-ds-base"
SERVER_ROOT_32 = "/usr/lib/fedora-ds-base"


def generate_serverid():
    """Generate a UUID (universally unique identifier) suitable
    for use as a unique identifier for a DS instance.
    """
    try:
        import uuid
        id = str(uuid.uuid1())
    except ImportError:
        import commands
        id = commands.getoutput("/usr/bin/uuidgen")
    return id

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
        self.host_name = None
        self.admin_password = None
        self.sub_dict = None

    def create_instance(self, ds_user, realm_name, host_name, admin_password):
        self.ds_user = ds_user
        self.serverid = generate_serverid()
        self.realm_name = realm_name.upper()
        self.host_name = host_name
        self.admin_password = admin_password
        self.__setup_sub_dict()

        self.__create_ds_user()
        self.__create_instance()
        self.__add_default_schemas()
        self.__enable_ssl()
        self.restart()
        self.__add_default_layout()

    def config_dirname(self):
        if not self.serverid:
            raise RuntimeError("serverid not set")
        return "/etc/fedora-ds/slapd-" + self.serverid + "/"

    def schema_dirname(self):
        return self.config_dirname() + "/schema/"

    def stop(self):
        run(["/sbin/service", "fedora-ds", "stop"])

    def start(self):
        run(["/sbin/service", "fedora-ds", "start"])

    def restart(self):
        run(["/sbin/service", "fedora-ds", "restart"])

    def __setup_sub_dict(self):
        suffix = realm_to_suffix(self.realm_name)
        server_root = find_server_root()
        self.sub_dict = dict(FQHN=self.host_name, SERVERID=self.serverid,
                             PASSWORD=self.admin_password, SUFFIX=suffix,
                             REALM=self.realm_name, USER=self.ds_user,
                             SERVER_ROOT=server_root)

    def __create_ds_user(self):
	try:
            pwd.getpwnam(self.ds_user)
            logging.debug("ds user %s exists" % self.ds_user)
	except KeyError:
            logging.debug("adding ds user %s" % self.ds_user)
            args = ["/usr/sbin/useradd", "-c", "DS System User", "-d", "/var/lib/fedora-ds", "-M", "-r", "-s", "/sbin/nologin", self.ds_user]
            run(args)
            logging.debug("done adding user")

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
            args = ["/usr/sbin/ds_newinst.pl", inf_fd.name]
            logging.debug("calling ds_newinst.pl")
        run(args)
        logging.debug("completed creating ds instance")
        logging.debug("restarting ds instance")
        self.restart()
        logging.debug("done restarting ds instance")

    def __add_default_schemas(self):
        shutil.copyfile(SHARE_DIR + "60kerberos.ldif",
                        self.schema_dirname() + "60kerberos.ldif")
        shutil.copyfile(SHARE_DIR + "60samba.ldif",
                        self.schema_dirname() + "60samba.ldif")

    def __enable_ssl(self):
        logging.debug("configuring ssl for ds instance")
        dirname = self.config_dirname()
        args = ["/usr/sbin/ipa-server-setupssl", self.admin_password,
                dirname, self.host_name]
        run(args)
        logging.debug("done configuring ssl for ds instance")
        
    def __add_default_layout(self):
        txt = template_file(SHARE_DIR + "bootstrap-template.ldif", self.sub_dict)
        inf_fd = write_tmp_file(txt)
        logging.debug("adding default ds layout")
        args = ["/usr/bin/ldapmodify", "-xv", "-D", "cn=Directory Manager",
                "-w", self.admin_password, "-f", inf_fd.name]
        run(args)
        logging.debug("done adding default ds layout")
