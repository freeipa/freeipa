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

SHARE_DIR = "/usr/share/ipa/"

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
    

INF_TEMPLATE = """
[General]
FullMachineName=   $FQHN
SuiteSpotUserID=   nobody
ServerRoot=    /usr/lib/fedora-ds-base
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

    def create_instance(self, realm_name, host_name, admin_password):
        self.serverid = generate_serverid()
        self.realm_name = realm_name.upper()
        self.host_name = host_name
        self.admin_password = admin_password
        self.__setup_sub_dict()

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
        self.sub_dict = dict(FQHN=self.host_name, SERVERID=self.serverid,
                             PASSWORD=self.admin_password, SUFFIX=suffix,
                             REALM=self.realm_name)

    def __create_instance(self):
        inf_txt = template_str(INF_TEMPLATE, self.sub_dict)
        inf_fd = write_tmp_file(inf_txt)
        args = ["/usr/bin/ds_newinst.pl", inf_fd.name]
        run(args)

    def __add_default_schemas(self):
        shutil.copyfile(SHARE_DIR + "60kerberos.ldif",
                        self.schema_dirname() + "60kerberos.ldif")
        shutil.copyfile(SHARE_DIR + "60samba.ldif",
                        self.schema_dirname() + "60samba.ldif")

    def __enable_ssl(self):
        dirname = self.config_dirname()
        args = ["/usr/sbin/ipa-server-setupssl", self.admin_password,
                dirname, self.host_name]
        run(args)
        
    def __add_default_layout(self):
        txt = template_file(SHARE_DIR + "bootstrap-template.ldif", self.sub_dict)
        inf_fd = write_tmp_file(txt)
        args = ["/usr/bin/ldapmodify", "-xv", "-D", "cn=Directory Manager",
                "-w", self.admin_password, "-f", inf_fd.name]
        run(args)

        
        

