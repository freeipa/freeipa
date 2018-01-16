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

from __future__ import absolute_import
from __future__ import print_function

import logging
import os
import shutil
import tempfile
import time
# pylint: disable=deprecated-module
from optparse import OptionGroup, SUPPRESS_HELP
# pylint: enable=deprecated-module

import dns.resolver
import six

from ipaserver.install import certs, installutils, bindinstance, dsinstance, ca
from ipaserver.install.replication import enable_replication_version_checking
from ipaserver.install.server.replicainstall import install_ca_cert
from ipaserver.install.bindinstance import (
    add_zone, add_fwd_rr, add_ptr_rr, dns_container_exists)
from ipapython import ipautil, admintool, certdb
from ipapython.dn import DN
from ipapython import version
from ipalib import api
from ipalib import errors
from ipaplatform.paths import paths
from ipalib.constants import DOMAIN_LEVEL_0

# pylint: disable=import-error
if six.PY3:
    # The SafeConfigParser class has been renamed to ConfigParser in Py3
    from configparser import ConfigParser as SafeConfigParser
else:
    from ConfigParser import SafeConfigParser
# pylint: enable=import-error


logger = logging.getLogger(__name__)

UNSUPPORTED_DOMAIN_LEVEL_TEMPLATE = """
Replica creation using '{command_name}' to generate replica file
is supported only in {domain_level}-level IPA domain.

The current IPA domain level is {curr_domain_level} and thus the replica must
be created by promoting an existing IPA client.

To set up a replica use the following procedure:
    1.) set up a client on the host using 'ipa-client-install'
    2.) promote the client to replica running 'ipa-replica-install'
        *without* replica file specified
"""


class ReplicaPrepare(admintool.AdminTool):
    command_name = 'ipa-replica-prepare'

    usage = "%prog [options] <replica-fqdn>"

    description = "Prepare a file for replica installation."

    @classmethod
    def add_options(cls, parser):
        super(ReplicaPrepare, cls).add_options(parser, debug_option=True)

        parser.add_option("-p", "--password", dest="password",
            help="Directory Manager password (for the existing master)")
        parser.add_option("--ip-address", dest="ip_addresses", type="ip",
            action="append", default=[], metavar="IP_ADDRESS",
            help="add A and PTR records of the future replica. This option can be used multiple times")
        parser.add_option("--reverse-zone", dest="reverse_zones",
            action="append", default=[], metavar="REVERSE_ZONE",
            help="the reverse DNS zone to use. This option can be used multiple times")
        parser.add_option("--no-reverse", dest="no_reverse",
            action="store_true", default=False,
            help="do not create reverse DNS zone")
        parser.add_option("--auto-reverse", dest="auto_reverse", default=False,
            action="store_true", help="create necessary DNS zones")
        parser.add_option("--allow-zone-overlap", dest="allow_zone_overlap",
            action="store_true", default=False, help="create DNS "
            "zone even if it already exists")
        parser.add_option("--ca", dest="ca_file", default=paths.CACERT_P12,
            metavar="FILE",
            help="location of CA PKCS#12 file, default /root/cacert.p12")
        parser.add_option('--no-wait-for-dns', dest='wait_for_dns',
            action='store_false', default=True,
            help="do not wait until the replica is resolvable in DNS")

        group = OptionGroup(parser, "SSL certificate options",
            "Only used if the server was installed using custom SSL certificates")
        group.add_option("--dirsrv-cert-file", dest="dirsrv_cert_files",
            action="append", metavar="FILE",
            help="File containing the Directory Server SSL certificate and private key")
        group.add_option("--dirsrv_pkcs12", dest="dirsrv_cert_files",
            action="append",
            help=SUPPRESS_HELP)
        group.add_option("--http-cert-file", dest="http_cert_files",
            action="append", metavar="FILE",
            help="File containing the Apache Server SSL certificate and private key")
        group.add_option("--http_pkcs12", dest="http_cert_files",
            action="append",
            help=SUPPRESS_HELP)
        group.add_option("--dirsrv-pin", dest="dirsrv_pin", sensitive=True,
            metavar="PIN",
            help="The password to unlock the Directory Server private key")
        group.add_option("--dirsrv_pin", dest="dirsrv_pin", sensitive=True,
            help=SUPPRESS_HELP)
        group.add_option("--http-pin", dest="http_pin", sensitive=True,
            metavar="PIN",
            help="The password to unlock the Apache Server private key")
        group.add_option("--http_pin", dest="http_pin", sensitive=True,
            help=SUPPRESS_HELP)
        group.add_option("--dirsrv-cert-name", dest="dirsrv_cert_name",
            metavar="NAME",
            help="Name of the Directory Server SSL certificate to install")
        group.add_option("--http-cert-name", dest="http_cert_name",
            metavar="NAME",
            help="Name of the Apache Server SSL certificate to install")
        parser.add_option_group(group)

    def validate_options(self):
        options = self.options
        super(ReplicaPrepare, self).validate_options(needs_root=True)
        installutils.check_server_configuration()

        if not options.ip_addresses:
            if options.reverse_zones:
                self.option_parser.error("You cannot specify a --reverse-zone "
                    "option without the --ip-address option")
            if options.no_reverse:
                self.option_parser.error("You cannot specify a --no-reverse "
                    "option without the --ip-address option")
        elif options.reverse_zones and options.no_reverse:
            self.option_parser.error("You cannot specify a --reverse-zone "
                "option together with --no-reverse")

        # If any of the PKCS#12 options are selected, all are required.
        cert_file_req = (options.dirsrv_cert_files, options.http_cert_files)
        if any(cert_file_req) and not all(cert_file_req):
            self.option_parser.error(
                "--dirsrv-cert-file and --http-cert-file are required if any "
                "key file options are used."
            )

        if len(self.args) < 1:
            self.option_parser.error(
                "must provide the fully-qualified name of the replica")
        elif len(self.args) > 1:
            self.option_parser.error(
                "must provide exactly one name for the replica")
        else:
            [self.replica_fqdn] = self.args

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        # Connect to LDAP, connection is closed at the end of run()
        api.Backend.ldap2.connect()

        self.check_for_supported_domain_level()

        if api.env.host == self.replica_fqdn:
            raise admintool.ScriptError("You can't create a replica on itself")

        config_dir = dsinstance.config_dirname(
            installutils.realm_to_serverid(api.env.realm))
        if not os.path.isdir(config_dir):
            raise admintool.ScriptError(
                "could not find directory instance: %s" % config_dir)

    def load_pkcs12(self, cert_files, key_password, key_nickname):
        return installutils.load_pkcs12(
            cert_files=cert_files,
            key_password=key_password,
            key_nickname=key_nickname,
            ca_cert_files=[paths.IPA_CA_CRT],
            host_name=self.replica_fqdn)

    def ask_for_options(self):
        options = self.options
        super(ReplicaPrepare, self).ask_for_options()
        http_ca_cert = None
        dirsrv_ca_cert = None

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
        api.Backend.ldap2.disconnect()
        try:
            api.Backend.ldap2.connect(bind_pw=self.dirman_password)

            entry_attrs = api.Backend.ldap2.get_ipa_config()
            self.subject_base = entry_attrs.get(
                'ipacertificatesubjectbase', [None])[0]

            ca_enabled = api.Command.ca_is_enabled()['result']
        except errors.ACIError:
            raise admintool.ScriptError("The password provided is incorrect "
                                        "for LDAP server %s" % api.env.host)
        except errors.LDAPError:
            raise admintool.ScriptError(
                "Unable to connect to LDAP server %s" % api.env.host)
        except errors.DatabaseError as e:
            raise admintool.ScriptError(e.desc)

        if ca_enabled and not os.path.isfile(paths.CA_CS_CFG_PATH):
            raise admintool.ScriptError(
                "CA is not installed on this server. "
                "ipa-replica-prepare must be run on an IPA server with CA.")
        if not ca_enabled and not options.http_cert_files:
            raise admintool.ScriptError(
                "Cannot issue certificates: a CA is not installed. Use the "
                "--http-cert-file, --dirsrv-cert-file options to provide "
                "custom certificates.")

        if self.subject_base is not None:
            self.subject_base = DN(self.subject_base)

        # Validate more options using the password
        try:
            installutils.verify_fqdn(self.replica_fqdn, local_hostname=False)
        except installutils.BadHostError as e:
            if isinstance(e, installutils.HostLookupError):
                if not options.ip_addresses:
                    if dns_container_exists(api.env.basedn):
                        logger.info('You might use the --ip-address option '
                                    'to create a DNS entry if the DNS zone '
                                    'is managed by IPA.')
                    raise
                else:
                    # The host doesn't exist in DNS but we're adding it.
                    pass
            else:
                raise

        if options.ip_addresses:
            if not dns_container_exists(api.env.basedn):
                logger.error(
                    "It is not possible to add a DNS record automatically "
                    "because DNS is not managed by IPA. Please create DNS "
                    "record manually and then omit --ip-address option.")
                raise admintool.ScriptError("Cannot add DNS record")

            options.reverse_zones = bindinstance.check_reverse_zones(
                options.ip_addresses, options.reverse_zones, options, False,
                True)

            _host, zone = self.replica_fqdn.split('.', 1)
            if not bindinstance.dns_zone_exists(zone, api=api):
                logger.error("DNS zone %s does not exist in IPA managed DNS "
                             "server. Either create DNS zone or omit "
                             "--ip-address option.", zone)
                raise admintool.ScriptError("Cannot add DNS record")

        self.http_pin = self.dirsrv_pin = None

        if options.http_cert_files:
            if options.http_pin is None:
                options.http_pin = installutils.read_password(
                    "Enter Apache Server private key unlock",
                    confirm=False, validate=False, retry=False)
                if options.http_pin is None:
                    raise admintool.ScriptError(
                        "Apache Server private key unlock password required")
            http_pkcs12_file, http_pin, http_ca_cert = self.load_pkcs12(
                options.http_cert_files, options.http_pin,
                options.http_cert_name)
            self.http_pkcs12_file = http_pkcs12_file
            self.http_pin = http_pin

        if options.dirsrv_cert_files:
            if options.dirsrv_pin is None:
                options.dirsrv_pin = installutils.read_password(
                    "Enter Directory Server private key unlock",
                    confirm=False, validate=False, retry=False)
                if options.dirsrv_pin is None:
                    raise admintool.ScriptError(
                        "Directory Server private key unlock password required")
            dirsrv_pkcs12_file, dirsrv_pin, dirsrv_ca_cert = self.load_pkcs12(
                options.dirsrv_cert_files, options.dirsrv_pin,
                options.dirsrv_cert_name)
            self.dirsrv_pkcs12_file = dirsrv_pkcs12_file
            self.dirsrv_pin = dirsrv_pin

        if (options.http_cert_files and options.dirsrv_cert_files and
            http_ca_cert != dirsrv_ca_cert):
            raise admintool.ScriptError(
                "Apache Server SSL certificate and Directory Server SSL "
                 "certificate are not signed by the same CA certificate")


    def run(self):
        options = self.options
        super(ReplicaPrepare, self).run()

        logger.info("Preparing replica for %s from %s",
                    self.replica_fqdn, api.env.host)
        enable_replication_version_checking(
            api.env.realm,
            self.dirman_password)

        self.top_dir = tempfile.mkdtemp("ipa")
        self.dir = os.path.join(self.top_dir, "realm_info")
        os.mkdir(self.dir)
        os.chmod(self.dir, 0o700)
        try:
            self.copy_ds_certificate()
            self.copy_httpd_certificate()

            self.retrieve_ca_certs()
            self.copy_misc_files()

            self.save_config()

            self.package_replica_file()
        finally:
            shutil.rmtree(self.top_dir)

        if options.ip_addresses:
            self.add_dns_records()

        if options.wait_for_dns:
            self.wait_for_dns()

        # Close LDAP connection that was opened in validate_options()
        api.Backend.ldap2.disconnect()

    def copy_ds_certificate(self):
        options = self.options

        passwd_fname = os.path.join(self.dir, "dirsrv_pin.txt")
        with open(passwd_fname, "w") as fd:
            fd.write("%s\n" % (self.dirsrv_pin or ''))

        if options.dirsrv_cert_files:
            logger.info("Copying SSL certificate for the Directory Server")
            self.copy_info_file(self.dirsrv_pkcs12_file.name, "dscert.p12")
        else:
            if os.path.isfile(options.ca_file):
                # Since it is possible that the Directory Manager password
                # has changed since ipa-server-install, we need to regenerate
                # the CA PKCS#12 file and update the pki admin user password
                self.regenerate_ca_file(options.ca_file)
                self.update_pki_admin_password()
                self.copy_info_file(options.ca_file, "cacert.p12")
            else:
                raise admintool.ScriptError("Root CA PKCS#12 not "
                    "found in %s" % options.ca_file)

            logger.info(
                "Creating SSL certificate for the Directory Server")
            self.export_certdb("dscert", passwd_fname)

        if not options.dirsrv_cert_files:
            logger.info(
                "Creating SSL certificate for the dogtag Directory Server")
            self.export_certdb("dogtagcert", passwd_fname)
            logger.info("Saving dogtag Directory Server port")
            port_fname = os.path.join(
                self.dir, "dogtag_directory_port.txt")
            with open(port_fname, "w") as fd:
                fd.write("389\n")

    def copy_httpd_certificate(self):
        options = self.options

        passwd_fname = os.path.join(self.dir, "http_pin.txt")
        with open(passwd_fname, "w") as fd:
            fd.write("%s\n" % (self.http_pin or ''))

        if options.http_cert_files:
            logger.info("Copying SSL certificate for the Web Server")
            self.copy_info_file(self.http_pkcs12_file.name, "httpcert.p12")
        else:
            logger.info("Creating SSL certificate for the Web Server")
            self.export_certdb("httpcert", passwd_fname)

            logger.info("Exporting RA certificate")
            self.export_ra_pkcs12()

    def copy_misc_files(self):
        logger.info("Copying additional files")

        cacert_filename = paths.CACERT_PEM
        if os.path.isfile(cacert_filename):
            self.copy_info_file(cacert_filename, "cacert.pem")
        self.copy_info_file(paths.IPA_DEFAULT_CONF, "default.conf")

    def retrieve_ca_certs(self):
        logger.info("Retrieving CA certificates")
        dest = os.path.join(self.dir, "ca.crt")
        install_ca_cert(api.Backend.ldap2, api.env.basedn,
                        api.env.realm, paths.IPA_CA_CRT, destfile=dest)

    def save_config(self):
        logger.info("Finalizing configuration")

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

        logger.info("Packaging replica information into %s", encfile)
        ipautil.run(
            [paths.TAR, "cf", replicafile, "-C", self.top_dir, "realm_info"])
        installutils.encrypt_file(
            replicafile, encfile, self.dirman_password, self.top_dir)

        os.chmod(encfile, 0o600)

        installutils.remove_file(replicafile)

    def add_dns_records(self):
        options = self.options

        logger.info("Adding DNS records for %s", self.replica_fqdn)
        name, domain = self.replica_fqdn.split(".", 1)

        for reverse_zone in options.reverse_zones:
            logger.info("Adding reverse zone %s", reverse_zone)
            add_zone(reverse_zone)

        for ip in options.ip_addresses:
            ip_address = str(ip)
            try:
                add_fwd_rr(domain, name, ip_address)
            except errors.PublicError as e:
                raise admintool.ScriptError(
                    "Could not add A/AAAA DNS record for the replica: %s" % e)

            if not options.no_reverse:
                reverse_zone = bindinstance.find_reverse_zone(ip)
                if reverse_zone is None:
                    logger.warning(
                        "Could not find any IPA managed reverse zone. "
                        "Not creating PTR records")
                    return
                try:
                    add_ptr_rr(reverse_zone, ip_address, self.replica_fqdn)
                except errors.PublicError as e:
                    raise admintool.ScriptError(
                        "Could not add PTR DNS record for the replica: %s"
                        % e)

    def check_dns(self, replica_fqdn):
        """Return true if the replica hostname is resolvable"""
        resolver = dns.resolver.Resolver()
        exceptions = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                      dns.resolver.Timeout, dns.resolver.NoNameservers)

        try:
            resolver.query(replica_fqdn, 'A', 'IN')
        except exceptions:
            try:
                resolver.query(replica_fqdn, 'AAAA', 'IN')
            except exceptions:
                return False
        except Exception as e:
            logger.warning('Exception while waiting for DNS record: %s: %s',
                           type(e).__name__, e)

        return True

    def wait_for_dns(self):
        # Make sure replica_fqdn has a trailing dot, so the
        # 'search' directive in /etc/resolv.conf doesn't apply
        replica_fqdn = self.replica_fqdn
        if not replica_fqdn.endswith('.'):
            replica_fqdn += '.'

        if self.check_dns(replica_fqdn):
            logger.debug('%s A/AAAA record resolvable', replica_fqdn)
            return

        logger.info('Waiting for %s A or AAAA record to be resolvable',
                    replica_fqdn)
        print('This can be safely interrupted (Ctrl+C)')

        try:
            while not self.check_dns(replica_fqdn):
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info('Interrupted')
        else:
            logger.debug('%s A/AAAA record resolvable', replica_fqdn)

    def copy_info_file(self, source, dest):
        """Copy a file into the info directory

        :param source: The source file (an absolute path)
        :param dest: The destination file (relative to the info directory)
        """
        dest_path = os.path.join(self.dir, dest)
        logger.debug('Copying %s to %s', source, dest_path)
        try:
            shutil.copy(source, dest_path)
        except IOError as e:
            raise admintool.ScriptError("File copy failed: %s" % e)

    def remove_info_file(self, filename):
        """Remove a file from the info directory

        :param filename: The unneeded file (relative to the info directory)
        """
        installutils.remove_file(os.path.join(self.dir, filename))

    def export_certdb(self, fname, passwd_fname):
        """Export a cert database

        :param fname: The file to export to (relative to the info directory)
        :param passwd_fname: File that holds the cert DB password
        """
        hostname = self.replica_fqdn
        subject_base = self.subject_base
        ca_subject = ca.lookup_ca_subject(api, subject_base)
        nickname = "Server-Cert"

        try:
            db = certs.CertDB(
                api.env.realm, nssdir=self.dir, host_name=api.env.host,
                subject_base=subject_base, ca_subject=ca_subject)
            db.create_passwd_file()
            db.create_from_cacert()
            db.create_server_cert(nickname, hostname)

            pkcs12_fname = os.path.join(self.dir, fname + ".p12")

            try:
                db.export_pkcs12(pkcs12_fname, passwd_fname, nickname)
            except ipautil.CalledProcessError as e:
                logger.info("error exporting Server certificate: %s", e)
                installutils.remove_file(pkcs12_fname)
                installutils.remove_file(passwd_fname)

            for fname in (certdb.NSS_DBM_FILES + certdb.NSS_SQL_FILES):
                self.remove_info_file(fname)
            self.remove_info_file("noise.txt")

            orig_filename = passwd_fname + ".orig"
            if os.path.isfile(orig_filename):
                installutils.remove_file(orig_filename)
        except errors.CertificateOperationError as e:
            raise admintool.ScriptError(str(e))

    def export_ra_pkcs12(self):
        if (os.path.exists(paths.RA_AGENT_PEM) and
           os.path.exists(paths.RA_AGENT_KEY)):
            with ipautil.write_tmp_file(self.dirman_password) as f:
                ipautil.run([
                    paths.OPENSSL,
                    "pkcs12", "-export",
                    "-inkey", paths.RA_AGENT_KEY,
                    "-in", paths.RA_AGENT_PEM,
                    "-out", os.path.join(self.dir, "ra.p12"),
                    "-passout", "file:{pwfile}".format(pwfile=f.name)
                ])

    def update_pki_admin_password(self):
        dn = DN('uid=admin', 'ou=people', 'o=ipaca')
        api.Backend.ldap2.modify_password(dn, self.dirman_password)

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

    def check_for_supported_domain_level(self):
        """
        check if we are in 0-level topology. If not, raise an error pointing
        the user to the replica promotion pathway
        """

        domain_level = dsinstance.get_domain_level(api)
        if domain_level > DOMAIN_LEVEL_0:
            logger.error(
                '%s',
                UNSUPPORTED_DOMAIN_LEVEL_TEMPLATE.format(
                    command_name=self.command_name,
                    domain_level=DOMAIN_LEVEL_0,
                    curr_domain_level=domain_level
                )
            )
            raise errors.InvalidDomainLevelError(
                reason="'{command}' is allowed only in domain level "
                "{prep_domain_level}".format(
                    command=self.command_name,
                    prep_domain_level=DOMAIN_LEVEL_0
                )
            )
