# Authors: Rob Crittenden <rcritten@redhat.com>
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
import fileinput
import sys

HTTPD_DIR = "/etc/httpd"
SSL_CONF = HTTPD_DIR + "/conf.d/ssl.conf"
NSS_CONF = HTTPD_DIR + "/conf.d/nss.conf"

def update_file(filename, orig, subst):
    if os.path.exists(filename):
        pattern = "%s" % re.escape(orig)
        p = re.compile(pattern)
        for line in fileinput.input(filename, inplace=1):
            if not p.search(line):
                sys.stdout.write(line)
            else:
                sys.stdout.write(p.sub(subst, line))
        fileinput.close()

class HTTPInstance:
    def __init__(self):
        pass 

    def create_instance(self):
        self.__disable_mod_ssl()
        self.__set_mod_nss_port()
        try:
            self.restart()
        except:
            # TODO: roll back here?
            print "Failed to restart httpd"

    def stop(self):
        run(["/sbin/service", "httpd", "stop"])

    def start(self):
        run(["/sbin/service", "httpd", "start"])

    def restart(self):
        run(["/sbin/service", "httpd", "restart"])

    def __disable_mod_ssl(self):
        logging.debug("disabling mod_ssl in httpd")
        if os.path.exists(SSL_CONF):
            os.rename(SSL_CONF, "%s.moved_by_ipa" % SSL_CONF)
        logging.debug("done disabling mod_ssl")

    def __set_mod_nss_port(self):
        logging.debug("Setting mod_nss port to 443")
        update_file(NSS_CONF, '8443', '443')
        logging.debug("done setting mod_nss port")
