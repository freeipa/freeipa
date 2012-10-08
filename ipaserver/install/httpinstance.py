# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import os.path
import tempfile
from ipapython.ipa_log_manager import *
import pwd
import shutil

import service
import certs
import dsinstance
import installutils
from ipapython import sysrestore
from ipapython import ipautil
from ipapython import services as ipaservices
from ipapython import dogtag
from ipalib import util, api

HTTPD_DIR = "/etc/httpd"
SSL_CONF = HTTPD_DIR + "/conf.d/ssl.conf"
NSS_CONF = HTTPD_DIR + "/conf.d/nss.conf"

selinux_warning = """
WARNING: could not set selinux boolean(s) %(var)s to true.  The web
interface may not function correctly until this boolean is successfully
change with the command:
   /usr/sbin/setsebool -P %(var)s true
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

    subject_base = ipautil.dn_attribute_property('_subject_base')

    def create_instance(self, realm, fqdn, domain_name, dm_password=None, autoconfig=True, pkcs12_info=None, self_signed_ca=False, subject_base=None, auto_redirect=True):
        self.fqdn = fqdn
        self.realm = realm
        self.domain = domain_name
        self.dm_password = dm_password
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.pkcs12_info = pkcs12_info
        self.self_signed_ca = self_signed_ca
        self.principal = "HTTP/%s@%s" % (self.fqdn, self.realm)
        self.dercert = None
        self.subject_base = subject_base
        self.sub_dict = dict(
            REALM=realm,
            FQDN=fqdn,
            DOMAIN=self.domain,
            AUTOREDIR='' if auto_redirect else '#',
            CRL_PUBLISH_PATH=dogtag.install_constants.CRL_PUBLISH_PATH,
        )

        # get a connection to the DS
        self.ldap_connect()


        self.step("disabling mod_ssl in httpd", self.__disable_mod_ssl)
        self.step("setting mod_nss port to 443", self.__set_mod_nss_port)
        self.step("setting mod_nss password file", self.__set_mod_nss_passwordfile)
        self.step("enabling mod_nss renegotiate", self.enable_mod_nss_renegotiate)
        self.step("adding URL rewriting rules", self.__add_include)
        self.step("configuring httpd", self.__configure_http)
        self.step("setting up ssl", self.__setup_ssl)
        if autoconfig:
            self.step("setting up browser autoconfig", self.__setup_autoconfig)
        self.step("publish CA cert", self.__publish_ca_cert)
        self.step("creating a keytab for httpd", self.__create_http_keytab)
        self.step("clean up any existing httpd ccache", self.remove_httpd_ccache)
        self.step("configuring SELinux for httpd", self.configure_selinux_for_httpd)
        self.step("restarting httpd", self.__start)
        self.step("configuring httpd to start on boot", self.__enable)

        self.start_creation("Configuring the web interface", 60)

    def __start(self):
        self.backup_state("running", self.is_running())
        self.restart()

    def __enable(self):
        self.backup_state("enabled", self.is_running())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        self.ldap_enable('HTTP', self.fqdn, self.dm_password, self.suffix)

    def configure_selinux_for_httpd(self):
        def get_setsebool_args(changes):
            if len(changes) == 1:
                # workaround https://bugzilla.redhat.com/show_bug.cgi?id=825163
                updates = changes.items()[0]
            else:
                updates = ["%s=%s" % update for update in changes.iteritems()]

            args = ["/usr/sbin/setsebool", "-P"]
            args.extend(updates)

            return args

        selinux = False
        try:
            if (os.path.exists('/usr/sbin/selinuxenabled')):
                ipautil.run(["/usr/sbin/selinuxenabled"])
                selinux = True
        except ipautil.CalledProcessError:
            # selinuxenabled returns 1 if not enabled
            pass

        if selinux:
            # Don't assume all vars are available
            updated_vars = {}
            failed_vars = {}
            required_settings = (("httpd_can_network_connect", "on"),
                                 ("httpd_manage_ipa", "on"))
            for setting, state in required_settings:
                try:
                    (stdout, stderr, returncode) = ipautil.run(["/usr/sbin/getsebool", setting])
                    original_state = stdout.split()[2]
                    self.backup_state(setting, original_state)

                    if original_state != state:
                        updated_vars[setting] = state
                except ipautil.CalledProcessError, e:
                    root_logger.debug("Cannot get SELinux boolean '%s': %s", setting, e)
                    failed_vars[setting] = state

            # Allow apache to connect to the dogtag UI and the session cache
            # This can still fail even if selinux is enabled. Execute these
            # together so it is speedier.
            if updated_vars:
                args = get_setsebool_args(updated_vars)
                try:
                    ipautil.run(args)
                except ipautil.CalledProcessError:
                    failed_vars.update(updated_vars)

            if failed_vars:
                args = get_setsebool_args(failed_vars)
                names = [update[0] for update in updated_vars]
                message = ['WARNING: could not set the following SELinux boolean(s):']
                for update in failed_vars.iteritems():
                    message.append('  %s -> %s' % update)
                message.append('The web interface may not function correctly until the booleans')
                message.append('are successfully changed with the command:')
                message.append(' '.join(args))
                message.append('Try updating the policycoreutils and selinux-policy packages.')

                self.print_msg("\n".join(message))

    def __create_http_keytab(self):
        installutils.kadmin_addprinc(self.principal)
        installutils.create_keytab("/etc/httpd/conf/ipa.keytab", self.principal)
        self.move_service(self.principal)
        self.add_cert_to_service()

        pent = pwd.getpwnam("apache")
        os.chown("/etc/httpd/conf/ipa.keytab", pent.pw_uid, pent.pw_gid)

    def remove_httpd_ccache(self):
        # Clean up existing ccache
        pent = pwd.getpwnam("apache")
        installutils.remove_file('/tmp/krb5cc_%d' % pent.pw_uid)

    def __configure_http(self):
        target_fname = '/etc/httpd/conf.d/ipa.conf'
        http_txt = ipautil.template_file(ipautil.SHARE_DIR + "ipa.conf", self.sub_dict)
        self.fstore.backup_file("/etc/httpd/conf.d/ipa.conf")
        http_fd = open(target_fname, "w")
        http_fd.write(http_txt)
        http_fd.close()
        os.chmod(target_fname, 0644)

        target_fname = '/etc/httpd/conf.d/ipa-rewrite.conf'
        http_txt = ipautil.template_file(ipautil.SHARE_DIR + "ipa-rewrite.conf", self.sub_dict)
        self.fstore.backup_file("/etc/httpd/conf.d/ipa-rewrite.conf")
        http_fd = open(target_fname, "w")
        http_fd.write(http_txt)
        http_fd.close()
        os.chmod(target_fname, 0644)

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

    def enable_mod_nss_renegotiate(self):
        installutils.set_directive(NSS_CONF, 'NSSRenegotiation', 'on', False)
        installutils.set_directive(NSS_CONF, 'NSSRequireSafeNegotiation', 'on', False)

    def __set_mod_nss_passwordfile(self):
        installutils.set_directive(NSS_CONF, 'NSSPassPhraseDialog', 'file:/etc/httpd/conf/password.conf')

    def __add_include(self):
        """This should run after __set_mod_nss_port so is already backed up"""
        if installutils.update_file(NSS_CONF, '</VirtualHost>', 'Include conf.d/ipa-rewrite.conf\n</VirtualHost>') != 0:
            print "Adding Include conf.d/ipa-rewrite to %s failed." % NSS_CONF

    def __setup_ssl(self):
        fqdn = None
        if not self.self_signed_ca:
            fqdn = self.fqdn

        ca_db = certs.CertDB(self.realm, host_name=fqdn, subject_base=self.subject_base)

        db = certs.CertDB(self.realm, subject_base=self.subject_base)
        if self.pkcs12_info:
            db.create_from_pkcs12(self.pkcs12_info[0], self.pkcs12_info[1], passwd=None)
            server_certs = db.find_server_certs()
            if len(server_certs) == 0:
                raise RuntimeError("Could not find a suitable server cert in import in %s" % self.pkcs12_info[0])

            db.create_password_conf()
            # We only handle one server cert
            nickname = server_certs[0][0]
            self.dercert = db.get_cert_from_db(nickname, pem=False)
            db.track_server_cert(nickname, self.principal, db.passwd_fname, 'restart_httpd')

            self.__set_mod_nss_nickname(nickname)
        else:
            if self.self_signed_ca:
                db.create_from_cacert(ca_db.cacert_fname)

            db.create_password_conf()
            self.dercert = db.create_server_cert("Server-Cert", self.fqdn, ca_db)
            db.track_server_cert("Server-Cert", self.principal, db.passwd_fname, 'restart_httpd')
            db.create_signing_cert("Signing-Cert", "Object Signing Cert", ca_db)

        # Fix the database permissions
        os.chmod(certs.NSS_DIR + "/cert8.db", 0660)
        os.chmod(certs.NSS_DIR + "/key3.db", 0660)
        os.chmod(certs.NSS_DIR + "/secmod.db", 0660)
        os.chmod(certs.NSS_DIR + "/pwdfile.txt", 0660)

        pent = pwd.getpwnam("apache")
        os.chown(certs.NSS_DIR + "/cert8.db", 0, pent.pw_gid )
        os.chown(certs.NSS_DIR + "/key3.db", 0, pent.pw_gid )
        os.chown(certs.NSS_DIR + "/secmod.db", 0, pent.pw_gid )
        os.chown(certs.NSS_DIR + "/pwdfile.txt", 0, pent.pw_gid )

        # Fix SELinux permissions on the database
        ipaservices.restore_context(certs.NSS_DIR + "/cert8.db")
        ipaservices.restore_context(certs.NSS_DIR + "/key3.db")

        # In case this got generated as part of the install, reset the
        # context
        if ipautil.file_exists(certs.CA_SERIALNO):
            ipaservices.restore_context(certs.CA_SERIALNO)
            os.chown(certs.CA_SERIALNO, 0, pent.pw_gid)
            os.chmod(certs.CA_SERIALNO, 0664)

    def __setup_autoconfig(self):
        target_fname = '/usr/share/ipa/html/preferences.html'
        ipautil.copy_template_file(
            ipautil.SHARE_DIR + "preferences.html.template",
            target_fname, self.sub_dict)
        os.chmod(target_fname, 0644)

        # The signing cert is generated in __setup_ssl
        db = certs.CertDB(self.realm, subject_base=self.subject_base)
        with open(db.passwd_fname) as pwdfile:
            pwd = pwdfile.read()

        # Setup configure.jar
        tmpdir = tempfile.mkdtemp(prefix="tmp-")
        target_fname = '/usr/share/ipa/html/configure.jar'
        shutil.copy("/usr/share/ipa/html/preferences.html", tmpdir)
        db.run_signtool(["-k", "Signing-Cert",
                         "-Z", target_fname,
                         "-e", ".html", "-p", pwd,
                         tmpdir])
        shutil.rmtree(tmpdir)
        os.chmod(target_fname, 0644)

        self.setup_firefox_extension(self.realm, self.domain, force=True)

    def setup_firefox_extension(self, realm, domain, force=False):
        """Set up the signed browser configuration extension

        If the extension is already set up, skip the installation unless
        ``force`` is true.
        """

        target_fname = '/usr/share/ipa/html/krb.js'
        if os.path.exists(target_fname) and not force:
            root_logger.info(
                '%s exists, skipping install of Firefox extension',
                    target_fname)
            return

        sub_dict = dict(REALM=realm, DOMAIN=domain)
        db = certs.CertDB(realm)
        with open(db.passwd_fname) as pwdfile:
            pwd = pwdfile.read()

        ipautil.copy_template_file(ipautil.SHARE_DIR + "krb.js.template",
            target_fname, sub_dict)
        os.chmod(target_fname, 0644)

        # Setup extension
        tmpdir = tempfile.mkdtemp(prefix="tmp-")
        extdir = tmpdir + "/ext"
        target_fname = "/usr/share/ipa/html/kerberosauth.xpi"
        shutil.copytree("/usr/share/ipa/ffextension", extdir)
        if db.has_nickname('Signing-Cert'):
            db.run_signtool(["-k", "Signing-Cert",
                                "-p", pwd,
                                "-X", "-Z", target_fname,
                                extdir])
        else:
            root_logger.warning('Object-signing certificate was not found. '
                'Creating unsigned Firefox configuration extension.')
            filenames = os.listdir(extdir)
            ipautil.run(['/usr/bin/zip', '-r', target_fname] + filenames,
                cwd=extdir)
        shutil.rmtree(tmpdir)
        os.chmod(target_fname, 0644)

    def __publish_ca_cert(self):
        ca_db = certs.CertDB(self.realm)
        ca_db.publish_ca_cert("/usr/share/ipa/html/ca.crt")

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring web server")

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if not running is None:
            self.stop()

        db = certs.CertDB(api.env.realm)
        db.untrack_server_cert("Server-Cert")
        if not enabled is None and not enabled:
            self.disable()

        for f in ["/etc/httpd/conf.d/ipa.conf", SSL_CONF, NSS_CONF]:
            try:
                self.fstore.restore_file(f)
            except ValueError, error:
                root_logger.debug(error)
                pass

        # Remove the configuration files we create
        installutils.remove_file("/etc/httpd/conf.d/ipa-rewrite.conf")
        installutils.remove_file("/etc/httpd/conf.d/ipa.conf")
        installutils.remove_file("/etc/httpd/conf.d/ipa-pki-proxy.conf")

        for var in ["httpd_can_network_connect", "httpd_manage_ipa"]:
            sebool_state = self.restore_state(var)
            if not sebool_state is None:
                try:
                    ipautil.run(["/usr/sbin/setsebool", "-P", var, sebool_state])
                except ipautil.CalledProcessError, e:
                    self.print_msg("Cannot restore SELinux boolean '%s' back to '%s': %s" \
                            % (var, sebool_state, e))

        if not running is None and running:
            self.start()
