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
import logging
import pwd
import fileinput
import sys
import time

import service
from ipa.ipautil import *

HTTPD_DIR = "/etc/httpd"
SSL_CONF = HTTPD_DIR + "/conf.d/ssl.conf"
NSS_CONF = HTTPD_DIR + "/conf.d/nss.conf"

selinux_warning = """WARNING: could not set selinux boolean httpd_can_network_connect to true.
The web interface may not function correctly until this boolean is
successfully change with the command:
   /usr/sbin/setsebool -P httpd_can_network_connect true
Try updating the policycoreutils and selinux-policy packages.
"""

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

class HTTPInstance(service.Service):
    def __init__(self):
        service.Service.__init__(self, "httpd")

    def create_instance(self, realm, fqdn):
        self.sub_dict = { "REALM" : realm }
        self.fqdn = fqdn
        self.realm = realm
        
        self.start_creation(6, "Configuring the web interface")
        
        self.__disable_mod_ssl()
        self.__set_mod_nss_port()
        self.__configure_http()
        self.__create_http_keytab()

        self.step("restarting httpd")
        self.restart()

        self.step("configuring httpd to start on boot")
        self.chkconfig_on()

        self.done_creation()

    def __selinux_config(self):
        self.step("configuring SELinux for httpd")
        selinux=0
        try:
            if (os.path.exists('/usr/sbin/selinuxenabled')):
                run(["/usr/sbin/selinuxenabled"])
                selinux=1
        except subprocess.CalledProcessError:
            # selinuxenabled returns 1 if not enabled
            pass

        if selinux:
            # Allow apache to connect to the turbogears web gui
            # This can still fail even if selinux is enabled
            try:
                run(["/usr/sbin/setsebool", "-P", "httpd_can_network_connect", "true"])
            except:
                self.print_msg(selinux_warning)
                
    def __create_http_keytab(self):
        self.step("creating a keytab for httpd")
        try:
            if file_exists("/etc/httpd/conf/ipa.keytab"):
                os.remove("/etc/httpd/conf/ipa.keytab")
        except os.error:
            print "Failed to remove /etc/httpd/conf/ipa.keytab."
        (kwrite, kread, kerr) = os.popen3("/usr/kerberos/sbin/kadmin.local")
        kwrite.write("addprinc -randkey HTTP/"+self.fqdn+"@"+self.realm+"\n")
        kwrite.flush()
        kwrite.write("ktadd -k /etc/httpd/conf/ipa.keytab HTTP/"+self.fqdn+"@"+self.realm+"\n")
        kwrite.flush()
        kwrite.close()
        kread.close()
        kerr.close()

        # give kadmin time to actually write the file before we go on
	retry = 0
        while not file_exists("/etc/httpd/conf/ipa.keytab"):
            time.sleep(1)
            retry += 1
            if retry > 15:
                print "Error timed out waiting for kadmin to finish operations\n"
                sys.exit(1)

        pent = pwd.getpwnam("apache")
        os.chown("/etc/httpd/conf/ipa.keytab", pent.pw_uid, pent.pw_gid)

    def __configure_http(self):
        self.step("configuring httpd")
        http_txt = template_file(SHARE_DIR + "ipa.conf", self.sub_dict)
        http_fd = open("/etc/httpd/conf.d/ipa.conf", "w")
        http_fd.write(http_txt)
        http_fd.close()                


    def __disable_mod_ssl(self):
        self.step("disabling mod_ssl in httpd")
        if os.path.exists(SSL_CONF):
            os.rename(SSL_CONF, "%s.moved_by_ipa" % SSL_CONF)

    def __set_mod_nss_port(self):
        self.step("Setting mod_nss port to 443")
        update_file(NSS_CONF, '8443', '443')
