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

from __future__ import print_function

import os
import os.path
import pwd
import re
import dbus
import shlex
import pipes
import locale

import six

from ipalib.constants import IPAAPI_USER
from ipalib.install import certmonger
from ipaserver.install import service
from ipaserver.install import certs
from ipaserver.install import installutils
from ipapython import dogtag
from ipapython import ipautil
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger
import ipapython.errors
from ipaserver.install import sysupgrade
from ipalib import api
from ipalib import errors
from ipalib.constants import ANON_USER
from ipaplatform.constants import constants
from ipaplatform.tasks import tasks
from ipaplatform.paths import paths
from ipaplatform import services

SELINUX_BOOLEAN_SETTINGS = dict(
    httpd_can_network_connect='on',
    httpd_manage_ipa='on',
    httpd_run_ipa='on',
    httpd_dbus_sssd='on',
)

HTTPD_USER = constants.HTTPD_USER
KDCPROXY_USER = constants.KDCPROXY_USER

# See contrib/nsscipersuite/nssciphersuite.py
NSS_CIPHER_SUITE = [
    '+aes_128_sha_256', '+aes_256_sha_256',
    '+ecdhe_ecdsa_aes_128_gcm_sha_256', '+ecdhe_ecdsa_aes_128_sha',
    '+ecdhe_ecdsa_aes_256_gcm_sha_384', '+ecdhe_ecdsa_aes_256_sha',
    '+ecdhe_rsa_aes_128_gcm_sha_256', '+ecdhe_rsa_aes_128_sha',
    '+ecdhe_rsa_aes_256_gcm_sha_384', '+ecdhe_rsa_aes_256_sha',
    '+rsa_aes_128_gcm_sha_256', '+rsa_aes_128_sha',
    '+rsa_aes_256_gcm_sha_384', '+rsa_aes_256_sha'
]
NSS_CIPHER_REVISION = '20160129'


def httpd_443_configured():
    """
    We now allow mod_ssl to be installed so don't automatically disable it.
    However it can't share the same listen port as mod_nss, so check for that.

    Returns True if something other than mod_nss is listening on 443.
    False otherwise.
    """
    try:
        result = ipautil.run([paths.HTTPD, '-t', '-D', 'DUMP_VHOSTS'],
                             capture_output=True)
    except ipautil.CalledProcessError as e:
        service.print_msg("WARNING: cannot check if port 443 is already configured")
        service.print_msg("httpd returned error when checking: %s" % e)
        return False

    port_line_re = re.compile(r'(?P<address>\S+):(?P<port>\d+)')
    stdout = result.raw_output
    if six.PY3:
        stdout = stdout.decode(locale.getpreferredencoding(), errors='replace')
    for line in stdout.splitlines():
        m = port_line_re.match(line)
        if m and int(m.group('port')) == 443:
            service.print_msg("Apache is already configured with a listener on port 443:")
            service.print_msg(line)
            return True

    return False


def create_kdcproxy_user():
    """Create KDC proxy user/group if it doesn't exist yet."""
    tasks.create_system_user(
        name=KDCPROXY_USER,
        group=KDCPROXY_USER,
        homedir=paths.VAR_LIB_KDCPROXY,
        shell=paths.NOLOGIN,
        comment="IPA KDC Proxy User",
        create_homedir=True,
    )


class WebGuiInstance(service.SimpleServiceInstance):
    def __init__(self):
        service.SimpleServiceInstance.__init__(self, "ipa_webgui")

class HTTPInstance(service.Service):
    def __init__(self, fstore=None, cert_nickname='Server-Cert',
                 api=api):
        super(HTTPInstance, self).__init__(
            "httpd",
            service_desc="the web interface",
            fstore=fstore,
            api=api,
            service_prefix=u'HTTP',
            service_user=HTTPD_USER,
            keytab=paths.HTTP_KEYTAB)

        self.cert_nickname = cert_nickname
        self.ca_is_configured = True
        self.keytab_user = constants.GSSPROXY_USER

    subject_base = ipautil.dn_attribute_property('_subject_base')

    def create_instance(self, realm, fqdn, domain_name, pkcs12_info=None,
                        subject_base=None, auto_redirect=True, ca_file=None,
                        ca_is_configured=None, promote=False):
        self.fqdn = fqdn
        self.realm = realm
        self.domain = domain_name
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.pkcs12_info = pkcs12_info
        self.dercert = None
        self.subject_base = subject_base
        self.sub_dict = dict(
            REALM=realm,
            FQDN=fqdn,
            DOMAIN=self.domain,
            AUTOREDIR='' if auto_redirect else '#',
            CRL_PUBLISH_PATH=paths.PKI_CA_PUBLISH_DIR,
        )
        self.ca_file = ca_file
        if ca_is_configured is not None:
            self.ca_is_configured = ca_is_configured
        self.promote = promote

        self.step("setting mod_nss port to 443", self.__set_mod_nss_port)
        self.step("setting mod_nss cipher suite",
                  self.set_mod_nss_cipher_suite)
        self.step("setting mod_nss protocol list to TLSv1.0 - TLSv1.2",
                  self.set_mod_nss_protocol)
        self.step("setting mod_nss password file", self.__set_mod_nss_passwordfile)
        self.step("enabling mod_nss renegotiate", self.enable_mod_nss_renegotiate)
        self.step("adding URL rewriting rules", self.__add_include)
        self.step("configuring httpd", self.__configure_http)
        self.step("setting up httpd keytab", self.request_service_keytab)
        self.step("retrieving anonymous keytab", self.request_anon_keytab)
        self.step("configuring Gssproxy", self.configure_gssproxy)
        self.step("setting up ssl", self.__setup_ssl)
        if self.ca_is_configured:
            self.step("configure certmonger for renewals",
                      self.configure_certmonger_renewal_guard)
        self.step("importing CA certificates from LDAP", self.__import_ca_certs)
        self.step("clean up any existing httpd ccaches",
                  self.remove_httpd_ccaches)
        self.step("configuring SELinux for httpd", self.configure_selinux_for_httpd)
        if not self.is_kdcproxy_configured():
            self.step("create KDC proxy user", create_kdcproxy_user)
            self.step("create KDC proxy config", self.create_kdcproxy_conf)
            self.step("enable KDC proxy", self.enable_kdcproxy)
        self.step("restarting httpd", self.__start)
        self.step("configuring httpd to start on boot", self.__enable)
        self.step("enabling oddjobd", self.enable_and_start_oddjobd)

        self.start_creation()

    def __start(self):
        self.backup_state("running", self.is_running())
        self.restart()

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        self.ldap_enable('HTTP', self.fqdn, None, self.suffix)

    def configure_selinux_for_httpd(self):
        try:
            tasks.set_selinux_booleans(SELINUX_BOOLEAN_SETTINGS,
                                       self.backup_state)
        except ipapython.errors.SetseboolError as e:
            self.print_msg(e.format_service_warning('web interface'))

    def remove_httpd_ccaches(self):
        # Clean up existing ccaches
        # Make sure that empty env is passed to avoid passing KRB5CCNAME from
        # current env
        installutils.remove_file(paths.HTTP_CCACHE)
        for f in os.listdir(paths.IPA_CCACHES):
            os.remove(os.path.join(paths.IPA_CCACHES, f))

    def __configure_http(self):
        self.update_httpd_service_ipa_conf()

        target_fname = paths.HTTPD_IPA_CONF
        http_txt = ipautil.template_file(
            os.path.join(paths.USR_SHARE_IPA_DIR, "ipa.conf"), self.sub_dict)
        self.fstore.backup_file(paths.HTTPD_IPA_CONF)
        http_fd = open(target_fname, "w")
        http_fd.write(http_txt)
        http_fd.close()
        os.chmod(target_fname, 0o644)

        target_fname = paths.HTTPD_IPA_REWRITE_CONF
        http_txt = ipautil.template_file(
            os.path.join(paths.USR_SHARE_IPA_DIR, "ipa-rewrite.conf"),
            self.sub_dict)
        self.fstore.backup_file(paths.HTTPD_IPA_REWRITE_CONF)
        http_fd = open(target_fname, "w")
        http_fd.write(http_txt)
        http_fd.close()
        os.chmod(target_fname, 0o644)

    def configure_gssproxy(self):
        tasks.configure_http_gssproxy_conf()
        services.knownservices.gssproxy.restart()

    def change_mod_nss_port_from_http(self):
        # mod_ssl enforces SSLEngine on for vhost on 443 even though
        # the listener is mod_nss. This then crashes the httpd as mod_nss
        # listened port obviously does not match mod_ssl requirements.
        #
        # The workaround for this was to change port to http. It is no longer
        # necessary, as mod_nss now ships with default configuration which
        # sets SSLEngine off when mod_ssl is installed.
        #
        # Remove the workaround.
        if sysupgrade.get_upgrade_state('nss.conf', 'listen_port_updated'):
            installutils.set_directive(paths.HTTPD_NSS_CONF, 'Listen', '443', quotes=False)
            sysupgrade.set_upgrade_state('nss.conf', 'listen_port_updated', False)

    def __set_mod_nss_port(self):
        self.fstore.backup_file(paths.HTTPD_NSS_CONF)
        if installutils.update_file(paths.HTTPD_NSS_CONF, '8443', '443') != 0:
            print("Updating port in %s failed." % paths.HTTPD_NSS_CONF)

    def __set_mod_nss_nickname(self, nickname):
        quoted_nickname = installutils.quote_directive_value(
            nickname, quote_char="'")
        installutils.set_directive(
            paths.HTTPD_NSS_CONF, 'NSSNickname', quoted_nickname, quotes=False)

    def set_mod_nss_protocol(self):
        installutils.set_directive(paths.HTTPD_NSS_CONF, 'NSSProtocol', 'TLSv1.0,TLSv1.1,TLSv1.2', False)

    def enable_mod_nss_renegotiate(self):
        installutils.set_directive(paths.HTTPD_NSS_CONF, 'NSSRenegotiation', 'on', False)
        installutils.set_directive(paths.HTTPD_NSS_CONF, 'NSSRequireSafeNegotiation', 'on', False)

    def set_mod_nss_cipher_suite(self):
        ciphers = ','.join(NSS_CIPHER_SUITE)
        installutils.set_directive(paths.HTTPD_NSS_CONF, 'NSSCipherSuite', ciphers, False)

    def __set_mod_nss_passwordfile(self):
        installutils.set_directive(paths.HTTPD_NSS_CONF, 'NSSPassPhraseDialog', 'file:' + paths.HTTPD_PASSWORD_CONF)

    def __add_include(self):
        """This should run after __set_mod_nss_port so is already backed up"""
        if installutils.update_file(paths.HTTPD_NSS_CONF, '</VirtualHost>', 'Include {path}\n</VirtualHost>'.format(path=paths.HTTPD_IPA_REWRITE_CONF)) != 0:
            print("Adding Include conf.d/ipa-rewrite to %s failed." % paths.HTTPD_NSS_CONF)

    def configure_certmonger_renewal_guard(self):
        certmonger = services.knownservices.certmonger
        certmonger_stopped = not certmonger.is_running()

        if certmonger_stopped:
            certmonger.start()
        try:
            bus = dbus.SystemBus()
            obj = bus.get_object('org.fedorahosted.certmonger',
                                 '/org/fedorahosted/certmonger')
            iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
            path = iface.find_ca_by_nickname('IPA')
            if path:
                ca_obj = bus.get_object('org.fedorahosted.certmonger', path)
                ca_iface = dbus.Interface(ca_obj,
                                          'org.freedesktop.DBus.Properties')
                helper = ca_iface.Get('org.fedorahosted.certmonger.ca',
                                      'external-helper')
                if helper:
                    args = shlex.split(helper)
                    if args[0] != paths.IPA_SERVER_GUARD:
                        self.backup_state('certmonger_ipa_helper', helper)
                        args = [paths.IPA_SERVER_GUARD] + args
                        helper = ' '.join(pipes.quote(a) for a in args)
                        ca_iface.Set('org.fedorahosted.certmonger.ca',
                                     'external-helper', helper)
        finally:
            if certmonger_stopped:
                certmonger.stop()

    def request_anon_keytab(self):
        parent = os.path.dirname(paths.ANON_KEYTAB)
        if not os.path.exists(parent):
            os.makedirs(parent, 0o755)

        self.clean_previous_keytab(keytab=paths.ANON_KEYTAB)
        self.run_getkeytab(self.api.env.ldap_uri, paths.ANON_KEYTAB, ANON_USER)

        pent = pwd.getpwnam(IPAAPI_USER)
        os.chmod(parent, 0o700)
        os.chown(parent, pent.pw_uid, pent.pw_gid)

        self.set_keytab_owner(keytab=paths.ANON_KEYTAB, owner=IPAAPI_USER)

    def create_password_conf(self):
        """
        This is the format of mod_nss pin files.
        """
        pwd_conf = paths.HTTPD_PASSWORD_CONF
        ipautil.backup_file(pwd_conf)

        passwd_fname = os.path.join(paths.HTTPD_ALIAS_DIR, 'pwdfile.txt')
        with open(passwd_fname, 'r') as pwdfile:
            password = pwdfile.read()

        with open(pwd_conf, "w") as f:
            f.write("internal:")
            f.write(password)
            f.write("\nNSS FIPS 140-2 Certificate DB:")
            f.write(password)
            # make sure other processes can access the file contents ASAP
            f.flush()
        pent = pwd.getpwnam(constants.HTTPD_USER)
        os.chown(pwd_conf, pent.pw_uid, pent.pw_gid)
        os.chmod(pwd_conf, 0o400)

    def __setup_ssl(self):
        db = certs.CertDB(self.realm, nssdir=paths.HTTPD_ALIAS_DIR,
                          subject_base=self.subject_base, user="root",
                          group=constants.HTTPD_GROUP,
                          truncate=(not self.promote))
        if self.pkcs12_info:
            if self.ca_is_configured:
                trust_flags = 'CT,C,C'
            else:
                trust_flags = None
            db.init_from_pkcs12(self.pkcs12_info[0], self.pkcs12_info[1],
                                ca_file=self.ca_file,
                                trust_flags=trust_flags)
            server_certs = db.find_server_certs()
            if len(server_certs) == 0:
                raise RuntimeError("Could not find a suitable server cert in import in %s" % self.pkcs12_info[0])

            self.create_password_conf()

            # We only handle one server cert
            nickname = server_certs[0][0]
            if nickname == 'ipaCert':
                nickname = server_certs[1][0]
            self.dercert = db.get_cert_from_db(nickname, pem=False)

            if self.ca_is_configured:
                db.track_server_cert(nickname, self.principal, db.passwd_fname, 'restart_httpd')

            self.__set_mod_nss_nickname(nickname)
            self.add_cert_to_service()

        else:
            if not self.promote:
                self.create_password_conf()
                ca_args = [
                    paths.CERTMONGER_DOGTAG_SUBMIT,
                    '--ee-url', 'https://%s:8443/ca/ee/ca' % self.fqdn,
                    '--certfile', paths.RA_AGENT_PEM,
                    '--keyfile', paths.RA_AGENT_KEY,
                    '--cafile', paths.IPA_CA_CRT,
                    '--agent-submit'
                ]
                helper = " ".join(ca_args)
                prev_helper = certmonger.modify_ca_helper('IPA', helper)

                try:
                    certmonger.request_and_wait_for_cert(
                        certpath=db.secdir,
                        nickname=self.cert_nickname,
                        principal=self.principal,
                        passwd_fname=db.passwd_fname,
                        subject=str(DN(('CN', self.fqdn), self.subject_base)),
                        ca='IPA',
                        profile=dogtag.DEFAULT_PROFILE,
                        dns=[self.fqdn],
                        post_command='restart_httpd')
                    self.dercert = db.get_cert_from_db(
                        self.cert_nickname, pem=False)
                finally:
                    certmonger.modify_ca_helper('IPA', prev_helper)

                self.add_cert_to_service()

            # Verify we have a valid server cert
            server_certs = db.find_server_certs()
            if not server_certs:
                raise RuntimeError("Could not find a suitable server cert.")

    def __import_ca_certs(self):
        db = certs.CertDB(self.realm, nssdir=paths.HTTPD_ALIAS_DIR,
                          subject_base=self.subject_base)
        self.import_ca_certs(db, self.ca_is_configured)

    def is_kdcproxy_configured(self):
        """Check if KDC proxy has already been configured in the past"""
        return os.path.isfile(paths.HTTPD_IPA_KDCPROXY_CONF)

    def enable_kdcproxy(self):
        """Add ipaConfigString=kdcProxyEnabled to cn=KDC"""
        entry_name = DN(('cn', 'KDC'), ('cn', self.fqdn), ('cn', 'masters'),
                        ('cn', 'ipa'), ('cn', 'etc'), self.suffix)
        attr_name = 'kdcProxyEnabled'

        try:
            entry = api.Backend.ldap2.get_entry(
                entry_name, ['ipaConfigString'])
        except errors.NotFound:
            pass
        else:
            if any(attr_name.lower() == val.lower()
                   for val in entry.get('ipaConfigString', [])):
                root_logger.debug("service KDCPROXY already enabled")
                return

            entry.setdefault('ipaConfigString', []).append(attr_name)
            try:
                api.Backend.ldap2.update_entry(entry)
            except errors.EmptyModlist:
                root_logger.debug("service KDCPROXY already enabled")
                return
            except:
                root_logger.debug("failed to enable service KDCPROXY")
                raise

            root_logger.debug("service KDCPROXY enabled")
            return

        entry = api.Backend.ldap2.make_entry(
            entry_name,
            objectclass=["nsContainer", "ipaConfigObject"],
            cn=['KDC'],
            ipaconfigstring=[attr_name]
        )

        try:
            api.Backend.ldap2.add_entry(entry)
        except errors.DuplicateEntry:
            root_logger.debug("failed to add service KDCPROXY entry")
            raise

    def create_kdcproxy_conf(self):
        """Create ipa-kdc-proxy.conf in /etc/ipa/kdcproxy"""
        target_fname = paths.HTTPD_IPA_KDCPROXY_CONF
        sub_dict = dict(KDCPROXY_CONFIG=paths.KDCPROXY_CONFIG)
        http_txt = ipautil.template_file(
            os.path.join(paths.USR_SHARE_IPA_DIR,
                         "ipa-kdc-proxy.conf.template"),
            sub_dict)
        self.fstore.backup_file(target_fname)
        with open(target_fname, 'w') as f:
            f.write(http_txt)
        os.chmod(target_fname, 0o644)

    def enable_and_start_oddjobd(self):
        oddjobd = services.service('oddjobd', api)
        self.sstore.backup_state('oddjobd', 'running', oddjobd.is_running())
        self.sstore.backup_state('oddjobd', 'enabled', oddjobd.is_enabled())

        try:
            oddjobd.enable()
            oddjobd.start()
        except Exception as e:
            root_logger.critical("Unable to start oddjobd: {0}".format(str(e)))

    def update_httpd_service_ipa_conf(self):
        tasks.configure_httpd_service_ipa_conf()

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring web server")

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        # Restore oddjobd to its original state
        oddjobd = services.service('oddjobd', api)

        if not self.sstore.restore_state('oddjobd', 'running'):
            try:
                oddjobd.stop()
            except Exception:
                pass

        if not self.sstore.restore_state('oddjobd', 'enabled'):
            try:
                oddjobd.disable()
            except Exception:
                pass

        self.stop_tracking_certificates()

        helper = self.restore_state('certmonger_ipa_helper')
        if helper:
            bus = dbus.SystemBus()
            obj = bus.get_object('org.fedorahosted.certmonger',
                                 '/org/fedorahosted/certmonger')
            iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
            path = iface.find_ca_by_nickname('IPA')
            if path:
                ca_obj = bus.get_object('org.fedorahosted.certmonger', path)
                ca_iface = dbus.Interface(ca_obj,
                                          'org.freedesktop.DBus.Properties')
                ca_iface.Set('org.fedorahosted.certmonger.ca',
                             'external-helper', helper)

        for f in [paths.HTTPD_IPA_CONF, paths.HTTPD_SSL_CONF, paths.HTTPD_NSS_CONF]:
            try:
                self.fstore.restore_file(f)
            except ValueError as error:
                root_logger.debug(error)

        installutils.remove_keytab(self.keytab)
        installutils.remove_file(paths.HTTP_CCACHE)

        # Remove the configuration files we create
        installutils.remove_file(paths.HTTPD_IPA_REWRITE_CONF)
        installutils.remove_file(paths.HTTPD_IPA_CONF)
        installutils.remove_file(paths.HTTPD_IPA_PKI_PROXY_CONF)
        installutils.remove_file(paths.HTTPD_IPA_KDCPROXY_CONF_SYMLINK)
        installutils.remove_file(paths.HTTPD_IPA_KDCPROXY_CONF)
        tasks.remove_httpd_service_ipa_conf()

        # Restore SELinux boolean states
        boolean_states = {name: self.restore_state(name)
                          for name in SELINUX_BOOLEAN_SETTINGS}
        try:
            tasks.set_selinux_booleans(boolean_states)
        except ipapython.errors.SetseboolError as e:
            self.print_msg('WARNING: ' + str(e))

        if running:
            self.restart()

        # disabled by default, by ldap_enable()
        if enabled:
            self.enable()

    def stop_tracking_certificates(self):
        db = certs.CertDB(api.env.realm, nssdir=paths.HTTPD_ALIAS_DIR)
        db.untrack_server_cert(self.cert_nickname)

    def start_tracking_certificates(self):
        db = certs.CertDB(self.realm, nssdir=paths.HTTPD_ALIAS_DIR)
        db.track_server_cert(self.cert_nickname, self.principal,
                             db.passwd_fname, 'restart_httpd')
