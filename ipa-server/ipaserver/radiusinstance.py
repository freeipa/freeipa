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

import subprocess
import string
import tempfile
import shutil
import logging
import pwd
import time
from ipa.ipautil import *

import service

import os
import re

IPA_RADIUS_VERSION  = '0.0.0'
PKG_NAME            = 'freeradius'
PKG_CONFIG_DIR      = '/etc/raddb'

RADIUS_SERVICE_NAME = 'radius'
RADIUS_USER         = 'radiusd'

IPA_KEYTAB_FILEPATH            = os.path.join(PKG_CONFIG_DIR, 'ipa.keytab')
LDAP_ATTR_MAP_FILEPATH         = os.path.join(PKG_CONFIG_DIR, 'ldap.attrmap')
RADIUSD_CONF_FILEPATH          = os.path.join(PKG_CONFIG_DIR, 'radiusd.conf')
RADIUSD_CONF_TEMPLATE_FILEPATH = os.path.join(SHARE_DIR,       'radius.radiusd.conf.template')

# FIXME there should a utility to get the user base dn
from ipaserver.funcs import DefaultUserContainer, DefaultGroupContainer

#-------------------------------------------------------------------------------

class RadiusInstance(service.Service):
    def __init__(self):
        service.Service.__init__(self, "radiusd")
        self.fqdn        = None
        self.realm       = None
        self.principal   = None

    def create_instance(self, realm_name, host_name, ldap_server):
        self.realm        = realm_name.upper()
        self.fqdn         = host_name
        self.ldap_server  = ldap_server
        self.principal    = "%s/%s@%s" % (RADIUS_SERVICE_NAME, self.fqdn, self.realm)
        self.basedn       = realm_to_suffix(self.realm)
        self.user_basedn  = "%s,%s" % (DefaultUserContainer, self.basedn) # FIXME, should be utility to get this
        self.rpm_nvr = get_rpm_nvr_by_name(PKG_NAME)
        if self.rpm_nvr is not None:
            self.rpm_name, self.rpm_version, self.rpm_release = split_rpm_nvr(self.rpm_nvr)
        else:
            self.rpm_name = self.rpm_version = self.rpm_release = None

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

        version = 'IPA_RADIUS_VERSION=%s RADIUS_PACKAGE_VERSION=%s' % (IPA_RADIUS_VERSION, self.rpm_nvr)
        sub_dict = {'CONFIG_FILE_VERSION_INFO' : version,
                    'LDAP_SERVER'              : self.ldap_server,
                    'RADIUS_KEYTAB'            : IPA_KEYTAB_FILEPATH,
                    'RADIUS_PRINCIPAL'         : self.principal,
                    'RADIUS_USER_BASE_DN'      : self.user_basedn,
                    'ACCESS_ATTRIBUTE'         : 'dialupAccess' 
                    }
        try:
            radiusd_conf = template_file(RADIUSD_CONF_TEMPLATE_FILEPATH, sub_dict)
            radiusd_fd = open(RADIUSD_CONF_FILEPATH, 'w+')
            radiusd_fd.write(radiusd_conf)
            radiusd_fd.close()
        except Exception, e:
            logging.error("could not create %s: %s", RADIUSD_CONF_FILEPATH, e)

    def __create_radius_keytab(self):
        self.step("create radiusd keytab")
        try:
            if file_exists(IPA_KEYTAB_FILEPATH):
                os.remove(IPA_KEYTAB_FILEPATH)
        except os.error:
            logging.error("Failed to remove %s", IPA_KEYTAB_FILEPATH)

        (kwrite, kread, kerr) = os.popen3("/usr/kerberos/sbin/kadmin.local")
        kwrite.write("addprinc -randkey %s\n" % (self.principal))
        kwrite.flush()
        kwrite.write("ktadd -k %s %s\n" % (IPA_KEYTAB_FILEPATH, self.principal))
        kwrite.flush()
        kwrite.close()
        kread.close()
        kerr.close()

        # give kadmin time to actually write the file before we go on
        retry = 0
        while not file_exists(IPA_KEYTAB_FILEPATH):
            time.sleep(1)
            retry += 1
            if retry > 15:
                print "Error timed out waiting for kadmin to finish operations\n"
                os.exit()
                
        try:
            pent = pwd.getpwnam(RADIUS_USER)
            os.chown(IPA_KEYTAB_FILEPATH, pent.pw_uid, pent.pw_gid)
        except Exception, e:
            logging.error("could not chown on %s to %s: %s", IPA_KEYTAB_FILEPATH, RADIUS_USER, e)

#-------------------------------------------------------------------------------

# FIXME: this should be in a common area so it can be shared
def get_ldap_attr_translations():
    comment_re = re.compile('#.*$')
    radius_attr_to_ldap_attr = {}
    ldap_attr_to_radius_attr = {}
    try:
        f = open(LDAP_ATTR_MAP_FILEPATH)
        for line in f.readlines():
            line = comment_re.sub('', line).strip()
            if not line: continue
            attr_type, radius_attr, ldap_attr = line.split()
            print 'type="%s" radius="%s" ldap="%s"' % (attr_type, radius_attr, ldap_attr)
            radius_attr_to_ldap_attr[radius_attr] = {'ldap_attr':ldap_attr, 'attr_type':attr_type}
            ldap_attr_to_radius_attr[ldap_attr] = {'radius_attr':radius_attr, 'attr_type':attr_type}
        f.close()
    except Exception, e:
        logging.error('cold not read radius ldap attribute map file (%s): %s', LDAP_ATTR_MAP_FILEPATH, e)
        pass                    # FIXME

    #for k,v in radius_attr_to_ldap_attr.items():
    #    print '%s --> %s' % (k,v)
    #for k,v in ldap_attr_to_radius_attr.items():
    #    print '%s --> %s' % (k,v)

