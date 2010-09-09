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
import tempfile
import logging
import pwd
import shutil

import service
import certs
import dsinstance
import installutils
from ipapython import sysrestore
from ipapython import ipautil
from ipalib import util

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

    def create_instance(self, realm, fqdn, domain_name, dm_password=None, autoconfig=True, pkcs12_info=None, self_signed_ca=False, subject_base=None):
        self.fqdn = fqdn
        self.realm = realm
        self.domain = domain_name
        self.dm_password = dm_password
        self.suffix = util.realm_to_suffix(self.realm)
        self.pkcs12_info = pkcs12_info
        self.self_signed_ca = self_signed_ca
        self.principal = "HTTP/%s@%s" % (self.fqdn, self.realm)
        self.dercert = None
        self.subject_base = subject_base
        self.sub_dict = { "REALM" : realm, "FQDN": fqdn, "DOMAIN" : self.domain }

        self.step("disabling mod_ssl in httpd", self.__disable_mod_ssl)
        self.step("Setting mod_nss port to 443", self.__set_mod_nss_port)
        self.step("Setting mod_nss password file", self.__set_mod_nss_passwordfile)
        self.step("Adding URL rewriting rules", self.__add_include)
        self.step("configuring httpd", self.__configure_http)
        self.step("Setting up ssl", self.__setup_ssl)
        if autoconfig:
            self.step("Setting up browser autoconfig", self.__setup_autoconfig)
        self.step("publish CA cert", self.__publish_ca_cert)
        self.step("creating a keytab for httpd", self.__create_http_keytab)
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
                (stdout, stderr, returncode) = ipautil.run(["/usr/sbin/getsebool",
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
        installutils.kadmin_addprinc(self.principal)
        installutils.create_keytab("/etc/httpd/conf/ipa.keytab", self.principal)
        self.move_service(self.principal)
        self.add_cert_to_service()

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

    def __set_mod_nss_nickname(self, nickname):
        installutils.set_directive(NSS_CONF, 'NSSNickname', nickname)

    def __set_mod_nss_passwordfile(self):
        installutils.set_directive(NSS_CONF, 'NSSPassPhraseDialog', 'file:/etc/httpd/conf/password.conf')

    def __add_include(self):
        """This should run after __set_mod_nss_port so is already backed up"""
        if installutils.update_file(NSS_CONF, '</VirtualHost>', 'Include conf.d/ipa-rewrite.conf\n</VirtualHost>') != 0:
            print "Adding Include conf.d/ipa-rewrite to %s failed." % NSS_CONF

    def __setup_ssl(self):
        if self.self_signed_ca:
            ca_db = certs.CertDB(NSS_DIR, subject_base=self.subject_base)
        else:
            ca_db = certs.CertDB(NSS_DIR, host_name=self.fqdn, subject_base=self.subject_base)
        db = certs.CertDB(NSS_DIR, subject_base=self.subject_base)
        if self.pkcs12_info:
            db.create_from_pkcs12(self.pkcs12_info[0], self.pkcs12_info[1], passwd="")
            server_certs = db.find_server_certs()
            if len(server_certs) == 0:
                raise RuntimeError("Could not find a suitable server cert in import in %s" % self.pkcs12_info[0])

            db.create_password_conf()
            # We only handle one server cert
            nickname = server_certs[0][0]
            self.dercert = db.get_cert_from_db(nickname)

            self.__set_mod_nss_nickname(nickname)
        else:
            if self.self_signed_ca:
                db.create_from_cacert(ca_db.cacert_fname)
                db.create_password_conf()
                self.dercert = db.create_server_cert("Server-Cert", self.fqdn, ca_db)
                db.track_server_cert("Server-Cert", self.principal, db.passwd_fname)
                db.create_signing_cert("Signing-Cert", "Object Signing Cert", ca_db)
            else:
                self.dercert = db.create_server_cert("Server-Cert", self.fqdn, ca_db)
                db.track_server_cert("Server-Cert", self.principal, db.passwd_fname)
                db.create_signing_cert("Signing-Cert", "Object Signing Cert", ca_db)
                db.create_password_conf()

        # Fix the database permissions
        os.chmod(NSS_DIR + "/cert8.db", 0660)
        os.chmod(NSS_DIR + "/key3.db", 0660)
        os.chmod(NSS_DIR + "/secmod.db", 0660)
        os.chmod(NSS_DIR + "/pwdfile.txt", 0660)

        pent = pwd.getpwnam("apache")
        os.chown(NSS_DIR + "/cert8.db", 0, pent.pw_gid )
        os.chown(NSS_DIR + "/key3.db", 0, pent.pw_gid )
        os.chown(NSS_DIR + "/secmod.db", 0, pent.pw_gid )
        os.chown(NSS_DIR + "/pwdfile.txt", 0, pent.pw_gid )

        # Fix SELinux permissions on the database
        ipautil.run(["/sbin/restorecon", NSS_DIR + "/cert8.db"])
        ipautil.run(["/sbin/restorecon", NSS_DIR + "/key3.db"])

        # In case this got generated as part of the install, reset the
        # context
        if ipautil.file_exists(certs.CA_SERIALNO):
            ipautil.run(["/sbin/restorecon", certs.CA_SERIALNO])
            os.chown(certs.CA_SERIALNO, 0, pent.pw_gid)
            os.chmod(certs.CA_SERIALNO, 0664)

    def __setup_autoconfig(self):
        prefs_txt = ipautil.template_file(ipautil.SHARE_DIR + "preferences.html.template", self.sub_dict)
        prefs_fd = open("/usr/share/ipa/html/preferences.html", "w")
        prefs_fd.write(prefs_txt)
        prefs_fd.close()

        # The signing cert is generated in __setup_ssl
        db = certs.CertDB(NSS_DIR, subject_base=self.subject_base)

        pwdfile = open(db.passwd_fname)
        pwd = pwdfile.read()
        pwdfile.close()

        tmpdir = tempfile.mkdtemp(prefix = "tmp-")
        shutil.copy("/usr/share/ipa/html/preferences.html", tmpdir)
        db.run_signtool(["-k", "Signing-Cert",
                         "-Z", "/usr/share/ipa/html/configure.jar",
                         "-e", ".html", "-p", pwd,
                         tmpdir])
        shutil.rmtree(tmpdir)

    def __publish_ca_cert(self):
        ca_db = certs.CertDB(NSS_DIR)
        shutil.copy(ca_db.cacert_fname, "/usr/share/ipa/html/ca.crt")
        os.chmod("/usr/share/ipa/html/ca.crt", 0444)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring web server")

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if not running is None:
            self.stop()

        db = certs.CertDB(NSS_DIR)
        db.untrack_server_cert("Server-Cert")
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
