# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
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

import os
import os.path
import subprocess
import string
import tempfile
import logging
import pwd
import fileinput
import sys
import shutil

import service
import certs
import dsinstance
import installutils
from ipa import sysrestore
from ipa import ipautil

HTTPD_DIR = "/etc/httpd"
SSL_CONF = HTTPD_DIR + "/conf.d/ssl.conf"
NSS_CONF = HTTPD_DIR + "/conf.d/nss.conf"
NSS_DIR  = HTTPD_DIR + "/alias"

selinux_warning = """WARNING: could not set selinux boolean httpd_can_network_connect to true.
The web interface may not function correctly until this boolean is
successfully change with the command:
   /usr/sbin/setsebool -P httpd_can_network_connect true
Try updating the policycoreutils and selinux-policy packages.
"""

class WebGuiInstance(service.SimpleServiceInstance):
    def __init__(self):
        service.SimpleServiceInstance.__init__(self, "ipa_webgui")

class HTTPInstance(service.Service):
    def __init__(self, fstore = None):
        service.Service.__init__(self, "httpd")
        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def create_instance(self, realm, fqdn, domain_name, autoconfig=True, pkcs12_info=None):
        self.fqdn = fqdn
        self.realm = realm
        self.domain = domain_name
        self.pkcs12_info = pkcs12_info
        self.sub_dict = { "REALM" : realm, "FQDN": fqdn, "DOMAIN" : self.domain }

        self.step("disabling mod_ssl in httpd", self.__disable_mod_ssl)
        self.step("Setting mod_nss port to 443", self.__set_mod_nss_port)
        self.step("Adding URL rewriting rules", self.__add_include)
        self.step("configuring httpd", self.__configure_http)
        self.step("creating a keytab for httpd", self.__create_http_keytab)
        self.step("Setting up ssl", self.__setup_ssl)
        if autoconfig:
            self.step("Setting up browser autoconfig", self.__setup_autoconfig)
        self.step("configuring SELinux for httpd", self.__selinux_config)
        self.step("restarting httpd", self.__start)
        self.step("configuring httpd to start on boot", self.__enable)

        self.start_creation("Configuring the web interface")

    def __start(self):
        self.backup_state("running", self.is_running())
        self.restart()

    def __enable(self):
        self.backup_state("enabled", self.is_running())
        self.chkconfig_on()

    def __selinux_config(self):
        selinux=0
        try:
            if (os.path.exists('/usr/sbin/selinuxenabled')):
                ipautil.run(["/usr/sbin/selinuxenabled"])
                selinux=1
        except ipautil.CalledProcessError:
            # selinuxenabled returns 1 if not enabled
            pass

        if selinux:
            try:
                # returns e.g. "httpd_can_network_connect --> off"
                (stdout, stderr) = ipautils.run(["/usr/sbin/getsebool",
                                                 "httpd_can_network_connect"])
                self.backup_state("httpd_can_network_connect", stdout.split()[2])
            except:
                pass

            # Allow apache to connect to the turbogears web gui
            # This can still fail even if selinux is enabled
            try:
                ipautil.run(["/usr/sbin/setsebool", "-P", "httpd_can_network_connect", "true"])
            except:
                self.print_msg(selinux_warning)

    def __create_http_keytab(self):
        http_principal = "HTTP/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(http_principal)
        installutils.create_keytab("/etc/httpd/conf/ipa.keytab", http_principal)

        pent = pwd.getpwnam("apache")
        os.chown("/etc/httpd/conf/ipa.keytab", pent.pw_uid, pent.pw_gid)

    def __configure_http(self):
        http_txt = ipautil.template_file(ipautil.SHARE_DIR + "ipa.conf", self.sub_dict)
        self.fstore.backup_file("/etc/httpd/conf.d/ipa.conf")
        http_fd = open("/etc/httpd/conf.d/ipa.conf", "w")
        http_fd.write(http_txt)
        http_fd.close()

        http_txt = ipautil.template_file(ipautil.SHARE_DIR + "ipa-rewrite.conf", self.sub_dict)
        self.fstore.backup_file("/etc/httpd/conf.d/ipa-rewrite.conf")
        http_fd = open("/etc/httpd/conf.d/ipa-rewrite.conf", "w")
        http_fd.write(http_txt)
        http_fd.close()

    def __disable_mod_ssl(self):
        if os.path.exists(SSL_CONF):
            self.fstore.backup_file(SSL_CONF)
            os.unlink(SSL_CONF)

    def __set_mod_nss_port(self):
        self.fstore.backup_file(NSS_CONF)
        if installutils.update_file(NSS_CONF, '8443', '443') != 0:
            print "Updating port in %s failed." % NSS_CONF

    def __add_include(self):
        """This should run after __set_mod_nss_port so is already backed up"""
        if installutils.update_file(NSS_CONF, '</VirtualHost>', 'Include conf.d/ipa-rewrite.conf\n</VirtualHost>') != 0:
            print "Adding Include conf.d/ipa-rewrite to %s failed." % NSS_CONF

    def __setup_ssl(self):
        ds_ca = certs.CertDB(dsinstance.config_dirname(dsinstance.realm_to_serverid(self.realm)))
        ca = certs.CertDB(NSS_DIR)
        if self.pkcs12_info:
            ca.create_from_pkcs12(self.pkcs12_info[0], self.pkcs12_info[1], passwd=False)
        else:
            ca.create_from_cacert(ds_ca.cacert_fname)
            ca.create_server_cert("Server-Cert", "cn=%s,ou=Apache Web Server" % self.fqdn, ds_ca)
            ca.create_signing_cert("Signing-Cert", "cn=%s,ou=Signing Certificate,o=Identity Policy Audit" % self.fqdn, ds_ca)

    def __setup_autoconfig(self):
        prefs_txt = ipautil.template_file(ipautil.SHARE_DIR + "preferences.html.template", self.sub_dict)
        prefs_fd = open("/usr/share/ipa/html/preferences.html", "w")
        prefs_fd.write(prefs_txt)
        prefs_fd.close()

        # The signing cert is generated in __setup_ssl
        ds_ca = certs.CertDB(dsinstance.config_dirname(dsinstance.realm_to_serverid(self.realm)))
        ca = certs.CertDB(NSS_DIR)

        # Publish the CA certificate
        shutil.copy(ds_ca.cacert_fname, "/usr/share/ipa/html/ca.crt")
        os.chmod("/usr/share/ipa/html/ca.crt", 0444)

        tmpdir = tempfile.mkdtemp(prefix = "tmp-")
        shutil.copy("/usr/share/ipa/html/preferences.html", tmpdir)
        ca.run_signtool(["-k", "Signing-Cert",
                         "-Z", "/usr/share/ipa/html/configure.jar",
                         "-e", ".html",
                         tmpdir])
        shutil.rmtree(tmpdir)

    def uninstall(self):
        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if not running is None:
            self.stop()

        if not enabled is None and not enabled:
            self.chkconfig_off()

        for f in ["/etc/httpd/conf.d/ipa.conf", SSL_CONF, NSS_CONF]:
            try:
                self.fstore.restore_file(f)
            except ValueError, error:
                logging.debug(error)
                pass

        sebool_state = self.restore_state("httpd_can_network_connect")
        if not sebool_state is None:
            try:
                ipautil.run(["/usr/sbin/setsebool", "-P", "httpd_can_network_connect", sebool_state])
            except:
                self.print_msg(selinux_warning)

        if not running is None and running:
            self.start()
