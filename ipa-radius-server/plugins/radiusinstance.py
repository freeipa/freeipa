#! /usr/bin/python -E
# Authors: John Dennis <jdennis@redhat.com>
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

import sys
sys.path.append("/usr/share/ipa")

import subprocess
import string
import tempfile
import shutil
import logging
import pwd
import time
import sys
from ipa import ipautil
from ipa import radius_util

from ipaserver import service

import os
import re

IPA_RADIUS_VERSION  = '0.0.0'

# FIXME there should a utility to get the user base dn
from ipaserver.funcs import DefaultUserContainer, DefaultGroupContainer

#-------------------------------------------------------------------------------

def get_radius_version():
    version = None
    try:
        p = subprocess.Popen([radius_util.RADIUSD, '-v'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        status =  p.returncode

        if status == 0:
            match = re.search("radiusd: FreeRADIUS Version (.+), for host", stdout)
            if match:
                version = match.group(1)
    except Exception, e:
        pass
    return version


#-------------------------------------------------------------------------------

class RadiusInstance(service.Service):
    def __init__(self):
        service.Service.__init__(self, "radiusd")
        self.fqdn        = None
        self.realm       = None
        self.principal   = None

    def create_instance(self, realm_name, host_name, ldap_server):
        self.realm        = realm_name.upper()
        self.suffix       = ipautil.realm_to_suffix(self.realm)
        self.fqdn         = host_name
        self.ldap_server  = ldap_server
        self.principal    = "%s/%s@%s" % (radius_util.RADIUS_SERVICE_NAME, self.fqdn, self.realm)
        self.basedn       = self.suffix
        self.user_basedn  = "%s,%s" % (DefaultUserContainer, self.basedn) # FIXME, should be utility to get this
        self.radius_version = get_radius_version()
        self.start_creation(4, "Configuring radiusd")

        try:
            self.stop()
        except:
            # It could have been not running
            pass

        self.__create_radius_keytab()
        self.__radiusd_conf()

        try:
            self.step("starting radiusd")
            self.start()
        except:
            logging.error("radiusd service failed to start")

        self.step("configuring radiusd to start on boot")
        self.chkconfig_on()


    def __radiusd_conf(self):
        self.step('configuring radiusd.conf for radius instance')

        version = 'IPA_RADIUS_VERSION=%s FREE_RADIUS_VERSION=%s' % (IPA_RADIUS_VERSION, self.radius_version)
        sub_dict = {'CONFIG_FILE_VERSION_INFO' : version,
                    'LDAP_SERVER'              : self.ldap_server,
                    'RADIUS_KEYTAB'            : radius_util.RADIUS_IPA_KEYTAB_FILEPATH,
                    'RADIUS_PRINCIPAL'         : self.principal,
                    'RADIUS_USER_BASE_DN'      : self.user_basedn,
                    'ACCESS_ATTRIBUTE'         : '',
                    'ACCESS_ATTRIBUTE_DEFAULT' : 'TRUE',
                    'CLIENTS_BASEDN'           : radius_util.radius_clients_basedn(None, self.suffix),
                    'SUFFIX'                   : self.suffix,
                    }
        try:
            radiusd_conf = ipautil.template_file(radius_util.RADIUSD_CONF_TEMPLATE_FILEPATH, sub_dict)
            radiusd_fd = open(radius_util.RADIUSD_CONF_FILEPATH, 'w+')
            radiusd_fd.write(radiusd_conf)
            radiusd_fd.close()
        except Exception, e:
            logging.error("could not create %s: %s", radius_util.RADIUSD_CONF_FILEPATH, e)

    def __create_radius_keytab(self):
        self.step("creating a keytab for radiusd")
        try:
            if ipautil.file_exists(radius_util.RADIUS_IPA_KEYTAB_FILEPATH):
                os.remove(radius_util.RADIUS_IPA_KEYTAB_FILEPATH)
        except os.error:
            logging.error("Failed to remove %s", radius_util.RADIUS_IPA_KEYTAB_FILEPATH)

        (kwrite, kread, kerr) = os.popen3("/usr/kerberos/sbin/kadmin.local")
        kwrite.write("addprinc -randkey %s\n" % (self.principal))
        kwrite.flush()
        kwrite.write("ktadd -k %s %s\n" % (radius_util.RADIUS_IPA_KEYTAB_FILEPATH, self.principal))
        kwrite.flush()
        kwrite.close()
        kread.close()
        kerr.close()

        # give kadmin time to actually write the file before we go on
        retry = 0
        while not ipautil.file_exists(radius_util.RADIUS_IPA_KEYTAB_FILEPATH):
            time.sleep(1)
            retry += 1
            if retry > 15:
                print "Error timed out waiting for kadmin to finish operations\n"
                sys.exit(1)
        try:
            pent = pwd.getpwnam(radius_util.RADIUS_USER)
            os.chown(radius_util.RADIUS_IPA_KEYTAB_FILEPATH, pent.pw_uid, pent.pw_gid)
        except Exception, e:
            logging.error("could not chown on %s to %s: %s", radius_util.RADIUS_IPA_KEYTAB_FILEPATH, radius_util.RADIUS_USER, e)

    def __ldap_mod(self, step, ldif):
        self.step(step)

        txt = iputil.template_file(ipautil.SHARE_DIR + ldif, self.sub_dict)
        fd = ipautil.write_tmp_file(txt)

        args = ["/usr/bin/ldapmodify", "-h", "127.0.0.1", "-xv",
                "-D", "cn=Directory Manager", "-w", self.dm_password, "-f", fd.name]

        try:
            ipautil.run(args)
        except ipautil.CalledProcessError, e:
            logging.critical("Failed to load %s: %s" % (ldif, str(e)))

        fd.close()

    #FIXME, should use IPAdmin method
    def __set_ldap_encrypted_attributes(self):
        self.__ldap_mod("setting ldap encrypted attributes",
                        "encrypted_attribute.ldif", {"ENCRYPTED_ATTRIBUTE" : "radiusClientSecret"})

#-------------------------------------------------------------------------------

