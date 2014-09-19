# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2008-2012  Red Hat
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
import shutil
import tempfile
import time
from optparse import OptionGroup
from ConfigParser import SafeConfigParser

import dns.resolver

from ipaserver.install import certs, installutils, bindinstance, dsinstance
from ipaserver.install.replication import enable_replication_version_checking
from ipaserver.plugins.ldap2 import ldap2
from ipaserver.install.bindinstance import (
    add_zone, add_fwd_rr, add_ptr_rr, dns_container_exists)
from ipapython import ipautil, admintool, dogtag
from ipapython.dn import DN
from ipapython import version
from ipalib import api
from ipalib import errors
from ipaplatform.paths import paths
from ipalib.constants import CACERT


class ReplicaPrepare(admintool.AdminTool):
    command_name = 'ipa-replica-prepare'

    usage = "%prog [options] <replica-fqdn>"

    description = "Prepare a file for replica installation."

    @classmethod
    def add_options(cls, parser):
        super(ReplicaPrepare, cls).add_options(parser, debug_option=True)

        parser.add_option("-p", "--password", dest="password",
            help="Directory Manager password (for the existing master)")
        parser.add_option("--ip-address", dest="ip_address", type="ip",
            help="add A and PTR records of the future replica")
        parser.add_option("--reverse-zone", dest="reverse_zone",
            help="the reverse DNS zone to use")
        parser.add_option("--no-reverse", dest="no_reverse",
            action="store_true", default=False,
            help="do not create reverse DNS zone")
        parser.add_option("--no-pkinit", dest="setup_pkinit",
            action="store_false", default=True,
            help="disables pkinit setup steps")
        parser.add_option("--ca", dest="ca_file", default=paths.CACERT_P12,
            metavar="FILE",
            help="location of CA PKCS#12 file, default /root/cacert.p12")
        parser.add_option('--no-wait-for-dns', dest='wait_for_dns',
            action='store_false', default=True,
            help="do not wait until the replica is resolvable in DNS")

        group = OptionGroup(parser, "SSL certificate options",
            "Only used if the server was installed using custom SSL certificates")
        group.add_option("--dirsrv_pkcs12", dest="dirsrv_pkcs12",
            metavar="FILE",
            help="install certificate for the directory server")
        group.add_option("--http_pkcs12", dest="http_pkcs12",
            metavar="FILE",
            help="install certificate for the http server")
        group.add_option("--pkinit_pkcs12", dest="pkinit_pkcs12",
            metavar="FILE",
            help="install certificate for the KDC")
        group.add_option("--dirsrv_pin", dest="dirsrv_pin", metavar="PIN",
            help="PIN for the Directory Server PKCS#12 file")
        group.add_option("--http_pin", dest="http_pin", metavar="PIN",
            help="PIN for the Apache Server PKCS#12 file")
        group.add_option("--pkinit_pin", dest="pkinit_pin", metavar="PIN",
            help="PIN for the KDC pkinit PKCS#12 file")
        parser.add_option_group(group)

    def validate_options(self):
        options = self.options
        super(ReplicaPrepare, self).validate_options(needs_root=True)
        installutils.check_server_configuration()

        if not options.ip_address:
            if options.reverse_zone:
                self.option_parser.error("You cannot specify a --reverse-zone "
                    "option without the --ip-address option")
            if options.no_reverse:
                self.option_parser.error("You cannot specify a --no-reverse "
                    "option without the --ip-address option")
        elif options.reverse_zone and options.no_reverse:
            self.option_parser.error("You cannot specify a --reverse-zone "
                "option together with --no-reverse")

        #Automatically disable pkinit w/ dogtag until that is supported
        options.setup_pkinit = False

        # If any of the PKCS#12 options are selected, all are required.
        pkcs12_req = (options.dirsrv_pkcs12, options.http_pkcs12)
        pkcs12_opt = (options.pkinit_pkcs12,)
        if any(pkcs12_req + pkcs12_opt) and not all(pkcs12_req):
            self.option_parser.error(
                "--dirsrv_pkcs12 and --http_pkcs12 are required if any "
                "PKCS#12 options are used.")

        if len(self.args) < 1:
            self.option_parser.error(
                "must provide the fully-qualified name of the replica")
        elif len(self.args) > 1:
            self.option_parser.error(
                "must provide exactly one name for the replica")
        else:
            [self.replica_fqdn] = self.args

        api.bootstrap(in_server=True)
        api.finalize()

        if api.env.host == self.replica_fqdn:
            raise admintool.ScriptError("You can't create a replica on itself")

        if not api.env.enable_ra and not options.http_pkcs12:
            raise admintool.ScriptError(
                "Cannot issue certificates: a CA is not installed. Use the "
                "--http_pkcs12, --dirsrv_pkcs12 options to provide custom "
                "certificates.")

        config_dir = dsinstance.config_dirname(
            dsinstance.realm_to_serverid(api.env.realm))
        if not ipautil.dir_exists(config_dir):
            raise admintool.ScriptError(
                "could not find directory instance: %s" % config_dir)

    def check_pkcs12(self, pkcs12_file, pkcs12_pin):
        return installutils.check_pkcs12(
            pkcs12_info=(pkcs12_file, pkcs12_pin),
            ca_file=CACERT,
            hostname=self.replica_fqdn)

    def ask_for_options(self):
        options = self.options
        super(ReplicaPrepare, self).ask_for_options()

        # get the directory manager password
        self.dirman_password = options.password
        if not options.password:
            self.dirman_password = installutils.read_password(
                "Directory Manager (existing master)",
                confirm=False, validate=False)
            if self.dirman_password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

        # Try out the password & get the subject base
        suffix = ipautil.realm_to_suffix(api.env.realm)
        try:
            conn = ldap2(shared_instance=False, base_dn=suffix)
            conn.connect(bind_dn=DN(('cn', 'directory manager')),
                         bind_pw=self.dirman_password)
            entry_attrs = conn.get_ipa_config()
            conn.disconnect()
        except errors.ACIError:
            raise admintool.ScriptError("The password provided is incorrect "
                "for LDAP server %s" % api.env.host)
        except errors.LDAPError:
            raise admintool.ScriptError(
                "Unable to connect to LDAP server %s" % api.env.host)
        except errors.DatabaseError, e:
            raise admintool.ScriptError(e.desc)

        self.subject_base = entry_attrs.get(
            'ipacertificatesubjectbase', [None])[0]
        if self.subject_base is not None:
            self.subject_base = DN(self.subject_base)

        # Validate more options using the password
        try:
            installutils.verify_fqdn(self.replica_fqdn, local_hostname=False)
        except installutils.BadHostError, e:
            msg = str(e)
            if isinstance(e, installutils.HostLookupError):
                if options.ip_address is None:
                    if dns_container_exists(
                            api.env.host, api.env.basedn,
                            dm_password=self.dirman_password,
                            ldapi=True, realm=api.env.realm):
                        self.log.info('Add the --ip-address argument to '
                            'create a DNS entry.')
                    raise
                else:
                    # The host doesn't exist in DNS but we're adding it.
                    pass
            else:
                raise

        if options.ip_address:
            if not dns_container_exists(api.env.host, api.env.basedn,
                                        dm_password=self.dirman_password,
                                        ldapi=True, realm=api.env.realm):
                self.log.error(
                    "It is not possible to add a DNS record automatically "
                    "because DNS is not managed by IPA. Please create DNS "
                    "record manually and then omit --ip-address option.")
                raise admintool.ScriptError("Cannot add DNS record")
            if options.reverse_zone and not bindinstance.verify_reverse_zone(
                    options.reverse_zone, options.ip_address):
                raise admintool.ScriptError("Invalid reverse zone")

        if options.http_pkcs12:
            if options.http_pin is None:
                options.http_pin = installutils.read_password(
                    "Enter %s unlock" % options.http_pkcs12,
                    confirm=False, validate=False)
                if options.http_pin is None:
                    raise admintool.ScriptError(
                        "%s unlock password required" % options.http_pkcs12)
            http_ca_cert = self.check_pkcs12(
                options.http_pkcs12, options.http_pin)

        if options.dirsrv_pkcs12:
            if options.dirsrv_pin is None:
                options.dirsrv_pin = installutils.read_password(
                    "Enter %s unlock" % options.dirsrv_pkcs12,
                    confirm=False, validate=False)
                if options.dirsrv_pin is None:
                    raise admintool.ScriptError(
                        "%s unlock password required" % options.dirsrv_pkcs12)
            dirsrv_ca_cert = self.check_pkcs12(
                options.dirsrv_pkcs12, options.dirsrv_pin)

        if options.pkinit_pkcs12:
            if options.pkinit_pin is None:
                options.pkinit_pin = installutils.read_password(
                    "Enter %s unlock" % options.pkinit_pkcs12,
                    confirm=False, validate=False)
                if options.pkinit_pin is None:
                    raise admintool.ScriptError(
                        "%s unlock password required" % options.pkinit_pkcs12)

        if (options.http_pkcs12 and options.dirsrv_pkcs12 and
            http_ca_cert != dirsrv_ca_cert):
            raise admintool.ScriptError(
                "%s and %s are not signed by the same CA certificate" %
                (options.http_pkcs12, options.dirsrv_pkcs12))

        if (not ipautil.file_exists(
                    dogtag.configured_constants().CS_CFG_PATH) and
                options.dirsrv_pin is None):
            self.log.info("If you installed IPA with your own certificates "
                "using PKCS#12 files you must provide PKCS#12 files for any "
                "replicas you create as well.")
            raise admintool.ScriptError("The replica must be created on the "
                "primary IPA server.")

    def run(self):
        options = self.options
        super(ReplicaPrepare, self).run()

        self.log.info("Preparing replica for %s from %s",
            self.replica_fqdn, api.env.host)
        enable_replication_version_checking(api.env.host, api.env.realm,
            self.dirman_password)

        self.top_dir = tempfile.mkdtemp("ipa")
        self.dir = os.path.join(self.top_dir, "realm_info")
        os.mkdir(self.dir, 0700)
        try:
            self.copy_ds_certificate()

            self.copy_httpd_certificate()

            if options.setup_pkinit:
                self.copy_pkinit_certificate()

            self.copy_misc_files()

            self.save_config()

            self.package_replica_file()
        finally:
            shutil.rmtree(self.top_dir)

        if options.ip_address:
            self.add_dns_records()

        if options.wait_for_dns:
            self.wait_for_dns()

    def copy_ds_certificate(self):
        options = self.options

        passwd_fname = os.path.join(self.dir, "dirsrv_pin.txt")
        with open(passwd_fname, "w") as fd:
            fd.write("%s\n" % (options.dirsrv_pin or ''))

        if options.dirsrv_pkcs12:
            self.log.info(
                "Copying SSL certificate for the Directory Server from %s",
                options.dirsrv_pkcs12)
            self.copy_info_file(options.dirsrv_pkcs12, "dscert.p12")
        else:
            if ipautil.file_exists(options.ca_file):
                # Since it is possible that the Directory Manager password
                # has changed since ipa-server-install, we need to regenerate
                # the CA PKCS#12 file and update the pki admin user password
                self.regenerate_ca_file(options.ca_file)
                self.update_pki_admin_password()
                self.copy_info_file(options.ca_file, "cacert.p12")
            else:
                raise admintool.ScriptError("Root CA PKCS#12 not "
                    "found in %s" % options.ca_file)

            self.log.info(
                "Creating SSL certificate for the Directory Server")
            self.export_certdb("dscert", passwd_fname)

        if not options.dirsrv_pkcs12:
            self.log.info(
                "Creating SSL certificate for the dogtag Directory Server")
            self.export_certdb("dogtagcert", passwd_fname)
            self.log.info("Saving dogtag Directory Server port")
            port_fname = os.path.join(
                self.dir, "dogtag_directory_port.txt")
            with open(port_fname, "w") as fd:
                fd.write("%s\n" % str(dogtag.configured_constants().DS_PORT))

    def copy_httpd_certificate(self):
        options = self.options

        passwd_fname = os.path.join(self.dir, "http_pin.txt")
        with open(passwd_fname, "w") as fd:
            fd.write("%s\n" % (options.http_pin or ''))

        if options.http_pkcs12:
            self.log.info(
                "Copying SSL certificate for the Web Server from %s",
                options.http_pkcs12)
            self.copy_info_file(options.http_pkcs12, "httpcert.p12")
        else:
            self.log.info("Creating SSL certificate for the Web Server")
            self.export_certdb("httpcert", passwd_fname)

            self.log.info("Exporting RA certificate")
            self.export_ra_pkcs12()

    def copy_pkinit_certificate(self):
        options = self.options

        passwd_fname = os.path.join(self.dir, "pkinit_pin.txt")
        with open(passwd_fname, "w") as fd:
            fd.write("%s\n" % (options.pkinit_pin or ''))

        if options.pkinit_pkcs12:
            self.log.info(
                "Copying SSL certificate for the KDC from %s",
                options.pkinit_pkcs12)
            self.copy_info_file(options.pkinit_pkcs12, "pkinitcert.p12")
        else:
            self.log.info("Creating SSL certificate for the KDC")
            self.export_certdb("pkinitcert", passwd_fname, is_kdc=True)

    def copy_misc_files(self):
        self.log.info("Copying additional files")

        self.copy_info_file(CACERT, "ca.crt")
        preferences_filename = paths.PREFERENCES_HTML
        if ipautil.file_exists(preferences_filename):
            self.copy_info_file(preferences_filename, "preferences.html")
            self.copy_info_file(paths.KRB_JS, "krb.js")
            self.copy_info_file(
                paths.KERBEROSAUTH_XPI, "kerberosauth.xpi")
        jar_filename = paths.CONFIGURE_JAR
        if ipautil.file_exists(jar_filename):
            self.copy_info_file(jar_filename, "configure.jar")
        cacert_filename = paths.CACERT_PEM
        if ipautil.file_exists(cacert_filename):
            self.copy_info_file(cacert_filename, "cacert.pem")

    def save_config(self):
        self.log.info("Finalizing configuration")

        config = SafeConfigParser()
        config.add_section("realm")
        config.set("realm", "realm_name", api.env.realm)
        config.set("realm", "master_host_name", api.env.host)
        config.set("realm", "domain_name", api.env.domain)
        config.set("realm", "destination_host", self.replica_fqdn)
        config.set("realm", "subject_base", str(self.subject_base))
        config.set("realm", "version", str(version.NUM_VERSION))

        with open(os.path.join(self.dir, "realm_info"), "w") as fd:
            config.write(fd)

    def package_replica_file(self):
        replicafile = paths.REPLICA_INFO_TEMPLATE % self.replica_fqdn
        encfile = "%s.gpg" % replicafile

        self.log.info("Packaging replica information into %s", encfile)
        ipautil.run(
            [paths.TAR, "cf", replicafile, "-C", self.top_dir, "realm_info"])
        ipautil.encrypt_file(
            replicafile, encfile, self.dirman_password, self.top_dir)

        os.chmod(encfile, 0600)

        installutils.remove_file(replicafile)

    def add_dns_records(self):
        options = self.options

        self.log.info("Adding DNS records for %s", self.replica_fqdn)
        api.Backend.ldap2.connect(
            bind_dn=DN(('cn', 'Directory Manager')),
            bind_pw=self.dirman_password)

        name, domain = self.replica_fqdn.split(".", 1)

        ip = options.ip_address
        ip_address = str(ip)

        if options.reverse_zone:
            reverse_zone = bindinstance.normalize_zone(options.reverse_zone)
        else:
            reverse_zone = bindinstance.find_reverse_zone(ip)
            if reverse_zone is None and not options.no_reverse:
                reverse_zone = bindinstance.get_reverse_zone_default(ip)

        try:
            add_zone(domain)
        except errors.PublicError, e:
            raise admintool.ScriptError(
                "Could not create forward DNS zone for the replica: %s" % e)

        try:
            add_fwd_rr(domain, name, ip_address)
        except errors.PublicError, e:
            raise admintool.ScriptError(
                "Could not add forward DNS record for the replica: %s" % e)

        if reverse_zone is not None:
            self.log.info("Using reverse zone %s", reverse_zone)
            try:
                add_zone(reverse_zone)
            except errors.PublicError, e:
                raise admintool.ScriptError(
                    "Could not create reverse DNS zone for replica: %s" % e)
            try:
                add_ptr_rr(reverse_zone, ip_address, self.replica_fqdn)
            except errors.PublicError, e:
                raise admintool.ScriptError(
                    "Could not add reverse DNS record for the replica: %s" % e)

    def check_dns(self, replica_fqdn):
        """Return true if the replica hostname is resolvable"""
        resolver = dns.resolver.Resolver()
        exceptions = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                      dns.resolver.Timeout, dns.resolver.NoNameservers)

        try:
            dns_answer = resolver.query(replica_fqdn, 'A', 'IN')
        except exceptions:
            try:
                dns_answer = resolver.query(replica_fqdn, 'AAAA', 'IN')
            except exceptions:
                return False
        except Exception as e:
            self.log.warn('Exception while waiting for DNS record: %s: %s',
                          type(e).__name__, e)

        return True

    def wait_for_dns(self):
        options = self.options

        # Make sure replica_fqdn has a trailing dot, so the
        # 'search' directive in /etc/resolv.conf doesn't apply
        replica_fqdn = self.replica_fqdn
        if not replica_fqdn.endswith('.'):
            replica_fqdn += '.'

        if self.check_dns(replica_fqdn):
            self.log.debug('%s A/AAAA record resolvable', replica_fqdn)
            return

        self.log.info('Waiting for %s A or AAAA record to be resolvable',
                      replica_fqdn)
        print 'This can be safely interrupted (Ctrl+C)'

        try:
            while not self.check_dns(replica_fqdn):
                time.sleep(1)
        except KeyboardInterrupt:
            self.log.info('Interrupted')
        else:
            self.log.debug('%s A/AAAA record resolvable', replica_fqdn)

    def copy_info_file(self, source, dest):
        """Copy a file into the info directory

        :param source: The source file (an absolute path)
        :param dest: The destination file (relative to the info directory)
        """
        dest_path = os.path.join(self.dir, dest)
        self.log.debug('Copying %s to %s', source, dest_path)
        try:
            shutil.copy(source, dest_path)
        except IOError, e:
            raise admintool.ScriptError("File copy failed: %s" % e)

    def remove_info_file(self, filename):
        """Remove a file from the info directory

        :param filename: The unneeded file (relative to the info directory)
        """
        installutils.remove_file(os.path.join(self.dir, filename))

    def export_certdb(self, fname, passwd_fname, is_kdc=False):
        """Export a cert database

        :param fname: The file to export to (relative to the info directory)
        :param passwd_fname: File that holds the cert DB password
        :param is_kdc: True if we're exporting KDC certs
        """
        options = self.options
        hostname = self.replica_fqdn
        subject_base = self.subject_base

        if is_kdc:
            nickname = "KDC-Cert"
        else:
            nickname = "Server-Cert"

        try:
            db = certs.CertDB(
                api.env.realm, nssdir=self.dir, subject_base=subject_base)
            db.create_passwd_file()
            ca_db = certs.CertDB(
                api.env.realm, host_name=api.env.host,
                subject_base=subject_base)
            db.create_from_cacert(ca_db.cacert_fname)
            db.create_server_cert(nickname, hostname, ca_db)

            pkcs12_fname = os.path.join(self.dir, fname + ".p12")

            try:
                if is_kdc:
                    ca_db.export_pem_p12(pkcs12_fname, passwd_fname,
                        nickname, os.path.join(self.dir, "kdc.pem"))
                else:
                    db.export_pkcs12(pkcs12_fname, passwd_fname, nickname)
            except ipautil.CalledProcessError, e:
                self.log.info("error exporting Server certificate: %s", e)
                installutils.remove_file(pkcs12_fname)
                installutils.remove_file(passwd_fname)

            self.remove_info_file("cert8.db")
            self.remove_info_file("key3.db")
            self.remove_info_file("secmod.db")
            self.remove_info_file("noise.txt")

            if is_kdc:
                self.remove_info_file("kdc.pem")

            orig_filename = passwd_fname + ".orig"
            if ipautil.file_exists(orig_filename):
                installutils.remove_file(orig_filename)
        except errors.CertificateOperationError, e:
            raise admintool.ScriptError(str(e))

    def export_ra_pkcs12(self):
        agent_fd, agent_name = tempfile.mkstemp()
        os.write(agent_fd, self.dirman_password)
        os.close(agent_fd)

        try:
            db = certs.CertDB(api.env.realm, host_name=api.env.host)

            if db.has_nickname("ipaCert"):
                pkcs12_fname = os.path.join(self.dir, "ra.p12")
                db.export_pkcs12(pkcs12_fname, agent_name, "ipaCert")
        finally:
            os.remove(agent_name)

    def update_pki_admin_password(self):
        ldap = ldap2(shared_instance=False)
        ldap.connect(
            bind_dn=DN(('cn', 'directory manager')),
            bind_pw=self.dirman_password
        )
        dn = DN('uid=admin', 'ou=people', 'o=ipaca')
        ldap.modify_password(dn, self.dirman_password)
        ldap.disconnect()

    def regenerate_ca_file(self, ca_file):
        dm_pwd_fd = ipautil.write_tmp_file(self.dirman_password)

        keydb_pwd = ''
        with open(paths.PKI_TOMCAT_PASSWORD_CONF) as f:
            for line in f.readlines():
                key, value = line.strip().split('=')
                if key == 'internal':
                    keydb_pwd = value
                    break

        keydb_pwd_fd = ipautil.write_tmp_file(keydb_pwd)

        ipautil.run([
            paths.PKCS12EXPORT,
            '-d', paths.PKI_TOMCAT_ALIAS_DIR,
            '-p', keydb_pwd_fd.name,
            '-w', dm_pwd_fd.name,
            '-o', ca_file
        ])
