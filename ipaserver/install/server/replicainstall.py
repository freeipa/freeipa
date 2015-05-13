#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import dns.exception as dnsexception
import dns.name as dnsname
import dns.resolver as dnsresolver
import dns.reversename as dnsreversename
import os
import shutil
import socket
import sys
import tempfile

from ipapython import dogtag, ipautil, sysrestore
from ipapython.dn import DN
from ipapython.install import common, core
from ipapython.install.common import step
from ipapython.install.core import Knob
from ipapython.ipa_log_manager import root_logger
from ipaplatform import services
from ipaplatform.tasks import tasks
from ipaplatform.paths import paths
from ipalib import api, certstore, constants, create_api, errors, x509
import ipaclient.ntpconf
from ipaserver.install import (
    bindinstance, ca, cainstance, certs, dns, dsinstance, httpinstance,
    installutils, kra, krbinstance, memcacheinstance, ntpinstance,
    otpdinstance, service)
from ipaserver.install.installutils import create_replica_config
from ipaserver.install.replication import (
    ReplicationManager, replica_conn_check)

DIRMAN_DN = DN(('cn', 'directory manager'))


def get_dirman_password():
    return installutils.read_password("Directory Manager (existing master)",
                                      confirm=False, validate=False)


def make_pkcs12_info(directory, cert_name, password_name):
    """Make pkcs12_info

    :param directory: Base directory (config.dir)
    :param cert_name: Cert filename (e.g. "dscert.p12")
    :param password_name: Cert filename (e.g. "dirsrv_pin.txt")
    :return: a (full cert path, password) tuple, or None if cert is not found
    """
    cert_path = os.path.join(directory, cert_name)
    if ipautil.file_exists(cert_path):
        password_file = os.path.join(directory, password_name)
        password = open(password_file).read().strip()
        return cert_path, password
    else:
        return None


def install_replica_ds(config):
    dsinstance.check_ports()

    # if we have a pkcs12 file, create the cert db from
    # that. Otherwise the ds setup will create the CA
    # cert
    pkcs12_info = make_pkcs12_info(config.dir, "dscert.p12", "dirsrv_pin.txt")

    ds = dsinstance.DsInstance()
    ds.create_replica(
        realm_name=config.realm_name,
        master_fqdn=config.master_host_name,
        fqdn=config.host_name,
        domain_name=config.domain_name,
        dm_password=config.dirman_password,
        subject_base=config.subject_base,
        pkcs12_info=pkcs12_info,
        ca_is_configured=ipautil.file_exists(config.dir + "/cacert.p12"),
        ca_file=config.dir + "/ca.crt",
    )

    return ds


def install_krb(config, setup_pkinit=False):
    krb = krbinstance.KrbInstance()

    # pkinit files
    pkcs12_info = make_pkcs12_info(config.dir, "pkinitcert.p12",
                                   "pkinit_pin.txt")

    krb.create_replica(config.realm_name,
                       config.master_host_name, config.host_name,
                       config.domain_name, config.dirman_password,
                       setup_pkinit, pkcs12_info)

    return krb


def install_ca_cert(ldap, base_dn, realm, cafile):
    try:
        try:
            certs = certstore.get_ca_certs(ldap, base_dn, realm, False)
        except errors.NotFound:
            shutil.copy(cafile, constants.CACERT)
        else:
            certs = [c[0] for c in certs if c[2] is not False]
            x509.write_certificate_list(certs, constants.CACERT)

        os.chmod(constants.CACERT, 0444)
    except Exception, e:
        print "error copying files: " + str(e)
        sys.exit(1)


def install_http(config, auto_redirect):
    # if we have a pkcs12 file, create the cert db from
    # that. Otherwise the ds setup will create the CA
    # cert
    pkcs12_info = make_pkcs12_info(config.dir, "httpcert.p12", "http_pin.txt")

    memcache = memcacheinstance.MemcacheInstance()
    memcache.create_instance('MEMCACHE', config.host_name,
                             config.dirman_password,
                             ipautil.realm_to_suffix(config.realm_name))

    http = httpinstance.HTTPInstance()
    http.create_instance(
        config.realm_name, config.host_name, config.domain_name,
        config.dirman_password, False, pkcs12_info,
        auto_redirect=auto_redirect, ca_file=config.dir + "/ca.crt",
        ca_is_configured=ipautil.file_exists(config.dir + "/cacert.p12"))

    # Now copy the autoconfiguration files
    try:
        if ipautil.file_exists(config.dir + "/preferences.html"):
            shutil.copy(config.dir + "/preferences.html",
                        paths.PREFERENCES_HTML)
        if ipautil.file_exists(config.dir + "/configure.jar"):
            shutil.copy(config.dir + "/configure.jar",
                        paths.CONFIGURE_JAR)
    except Exception, e:
        print "error copying files: " + str(e)
        sys.exit(1)

    http.setup_firefox_extension(config.realm_name, config.domain_name)

    return http


def install_dns_records(config, options, remote_api):

    if not bindinstance.dns_container_exists(
            config.master_host_name,
            ipautil.realm_to_suffix(config.realm_name),
            dm_password=config.dirman_password):
        return

    try:
        bind = bindinstance.BindInstance(dm_password=config.dirman_password,
                                         api=remote_api)
        for ip in config.ips:
            reverse_zone = bindinstance.find_reverse_zone(ip, remote_api)

            bind.add_master_dns_records(config.host_name,
                                        str(ip),
                                        config.realm_name,
                                        config.domain_name,
                                        reverse_zone,
                                        not options.no_ntp,
                                        options.setup_ca)
    except errors.NotFound, e:
        root_logger.debug('Replica DNS records could not be added '
                          'on master: %s', str(e))

    # we should not fail here no matter what
    except Exception, e:
        root_logger.info('Replica DNS records could not be added '
                         'on master: %s', str(e))


def check_dirsrv():
    (ds_unsecure, ds_secure) = dsinstance.check_ports()
    if not ds_unsecure or not ds_secure:
        print "IPA requires ports 389 and 636 for the Directory Server."
        print "These are currently in use:"
        if not ds_unsecure:
            print "\t389"
        if not ds_secure:
            print "\t636"
        sys.exit(1)


def check_dns_resolution(host_name, dns_servers):
    """Check forward and reverse resolution of host_name using dns_servers
    """
    # Point the resolver at specified DNS server
    server_ips = []
    for dns_server in dns_servers:
        try:
            server_ips = list(
                a[4][0] for a in socket.getaddrinfo(dns_server, None))
        except socket.error:
            pass
        else:
            break
    if not server_ips:
        root_logger.error(
            'Could not resolve any DNS server hostname: %s', dns_servers)
        return False
    resolver = dnsresolver.Resolver()
    resolver.nameservers = server_ips

    root_logger.debug('Search DNS server %s (%s) for %s',
                      dns_server, server_ips, host_name)

    # Get IP addresses of host_name
    addresses = set()
    for rtype in 'A', 'AAAA':
        try:
            result = resolver.query(host_name, rtype)
        except dnsexception.DNSException:
            rrset = []
        else:
            rrset = result.rrset
        if rrset:
            addresses.update(r.address for r in result.rrset)

    if not addresses:
        root_logger.error(
            'Could not resolve hostname %s using DNS. '
            'Clients may not function properly. '
            'Please check your DNS setup. '
            '(Note that this check queries IPA DNS directly and '
            'ignores /etc/hosts.)',
            host_name)
        return False

    no_errors = True

    # Check each of the IP addresses
    checked = set()
    for address in addresses:
        if address in checked:
            continue
        checked.add(address)
        try:
            root_logger.debug('Check reverse address %s (%s)',
                              address, host_name)
            revname = dnsreversename.from_address(address)
            rrset = resolver.query(revname, 'PTR').rrset
        except Exception, e:
            root_logger.debug('Check failed: %s %s', type(e).__name__, e)
            root_logger.error(
                'Reverse DNS resolution of address %s (%s) failed. '
                'Clients may not function properly. '
                'Please check your DNS setup. '
                '(Note that this check queries IPA DNS directly and '
                'ignores /etc/hosts.)',
                address, host_name)
            no_errors = False
        else:
            host_name_obj = dnsname.from_text(host_name)
            if rrset:
                names = [r.target.to_text() for r in rrset]
            else:
                names = []
            root_logger.debug(
                'Address %s resolves to: %s. ', address, ', '.join(names))
            if not rrset or not any(
                    r.target == host_name_obj for r in rrset):
                root_logger.error(
                    'The IP address %s of host %s resolves to: %s. '
                    'Clients may not function properly. '
                    'Please check your DNS setup. '
                    '(Note that this check queries IPA DNS directly and '
                    'ignores /etc/hosts.)',
                    address, host_name, ', '.join(names))
                no_errors = False

    return no_errors


def remove_replica_info_dir(installer):
    # always try to remove decrypted replica file
    try:
        if installer._top_dir is not None:
            shutil.rmtree(installer._top_dir)
    except OSError:
        pass


def common_cleanup(func):
    def decorated(installer):
        try:
            try:
                func(installer)
            except BaseException:
                remove_replica_info_dir(installer)
                raise
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception:
            print(
                "Your system may be partly configured.\n"
                "Run /usr/sbin/ipa-server-install --uninstall to clean up.\n")
            raise

    return decorated


@common_cleanup
def install_check(installer):
    options = installer
    filename = installer.replica_file

    tasks.check_selinux_status()

    client_fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    if client_fstore.has_files():
        sys.exit("IPA client is already configured on this system.\n"
                 "Please uninstall it first before configuring the replica, "
                 "using 'ipa-client-install --uninstall'.")

    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    # Check to see if httpd is already configured to listen on 443
    if httpinstance.httpd_443_configured():
        sys.exit("Aborting installation")

    check_dirsrv()

    if not options.no_ntp:
        try:
            ipaclient.ntpconf.check_timedate_services()
        except ipaclient.ntpconf.NTPConflictingService, e:
            print("WARNING: conflicting time&date synchronization service '%s'"
                  " will" % e.conflicting_service)
            print "be disabled in favor of ntpd"
            print ""
        except ipaclient.ntpconf.NTPConfigurationError:
            pass

    # get the directory manager password
    dirman_password = options.password
    if not dirman_password:
        try:
            dirman_password = get_dirman_password()
        except KeyboardInterrupt:
            sys.exit(0)
        if dirman_password is None:
            sys.exit("Directory Manager password required")

    config = create_replica_config(dirman_password, filename, options)
    installer._top_dir = config.top_dir
    config.setup_ca = options.setup_ca
    config.setup_kra = options.setup_kra

    # Create the management framework config file
    # Note: We must do this before bootstraping and finalizing ipalib.api
    old_umask = os.umask(022)   # must be readable for httpd
    try:
        fd = open(paths.IPA_DEFAULT_CONF, "w")
        fd.write("[global]\n")
        fd.write("host=%s\n" % config.host_name)
        fd.write("basedn=%s\n" %
                 str(ipautil.realm_to_suffix(config.realm_name)))
        fd.write("realm=%s\n" % config.realm_name)
        fd.write("domain=%s\n" % config.domain_name)
        fd.write("xmlrpc_uri=https://%s/ipa/xml\n" %
                 ipautil.format_netloc(config.host_name))
        fd.write("ldap_uri=ldapi://%%2fvar%%2frun%%2fslapd-%s.socket\n" %
                 installutils.realm_to_serverid(config.realm_name))
        if ipautil.file_exists(config.dir + "/cacert.p12"):
            fd.write("enable_ra=True\n")
            fd.write("ra_plugin=dogtag\n")
            fd.write("dogtag_version=%s\n" %
                     dogtag.install_constants.DOGTAG_VERSION)
        else:
            fd.write("enable_ra=False\n")
            fd.write("ra_plugin=none\n")

        fd.write("mode=production\n")
        fd.close()
    finally:
        os.umask(old_umask)

    api.bootstrap(in_server=True, context='installer')
    api.finalize()

    installutils.verify_fqdn(config.master_host_name, options.no_host_dns)

    cafile = config.dir + "/ca.crt"
    if not ipautil.file_exists(cafile):
        raise RuntimeError("CA cert file is not available. Please run "
                           "ipa-replica-prepare to create a new replica file.")

    ldapuri = 'ldaps://%s' % ipautil.format_netloc(config.master_host_name)
    remote_api = create_api(mode=None)
    remote_api.bootstrap(in_server=True, context='installer',
                         ldap_uri=ldapuri)
    remote_api.finalize()
    conn = remote_api.Backend.ldap2
    replman = None
    try:
        # Try out the password
        conn.connect(bind_dn=DIRMAN_DN, bind_pw=config.dirman_password,
                     tls_cacertfile=cafile)
        replman = ReplicationManager(config.realm_name,
                                     config.master_host_name,
                                     config.dirman_password)

        # Check that we don't already have a replication agreement
        if replman.get_replication_agreement(config.host_name):
            root_logger.info('Error: A replication agreement for this '
                             'host already exists.')
            print('A replication agreement for this host already exists. '
                  'It needs to be removed.')
            print "Run this on the master that generated the info file:"
            print("    %% ipa-replica-manage del %s --force" %
                  config.host_name)
            sys.exit(3)

        # Detect the current domain level
        try:
            current = remote_api.Command['domainlevel_get']()['result']
        except errors.NotFound:
            # If we're joining an older master, domain entry is not
            # available
            current = 0

        # Detect if current level is out of supported range
        # for this IPA version
        under_lower_bound = current < constants.MIN_DOMAIN_LEVEL
        above_upper_bound = current > constants.MAX_DOMAIN_LEVEL

        if under_lower_bound or above_upper_bound:
            message = ("This version of FreeIPA does not support "
                       "the Domain Level which is currently set for "
                       "this domain. The Domain Level needs to be "
                       "raised before installing a replica with "
                       "this version is allowed to be installed "
                       "within this domain.")
            root_logger.error(message)
            print(message)
            sys.exit(3)

        # Check pre-existing host entry
        try:
            entry = conn.find_entries(u'fqdn=%s' % config.host_name,
                                      ['fqdn'], DN(api.env.container_host,
                                                   api.env.basedn))
        except errors.NotFound:
            pass
        else:
            root_logger.info('Error: Host %s already exists on the master '
                             'server.' % config.host_name)
            print('The host %s already exists on the master server.' %
                  config.host_name)
            print "You should remove it before proceeding:"
            print "    %% ipa host-del %s" % config.host_name
            sys.exit(3)

        dns_masters = remote_api.Object['dnsrecord'].get_dns_masters()
        if dns_masters:
            if not options.no_host_dns:
                master = config.master_host_name
                root_logger.debug('Check forward/reverse DNS resolution')
                resolution_ok = (
                    check_dns_resolution(master, dns_masters) and
                    check_dns_resolution(config.host_name, dns_masters))
                if not resolution_ok and installer.interactive:
                    if not ipautil.user_input("Continue?", False):
                        sys.exit(0)
        else:
            root_logger.debug('No IPA DNS servers, '
                              'skipping forward/reverse resolution check')

        if options.setup_ca:
            options.realm_name = config.realm_name
            options.host_name = config.host_name
            options.subject = config.subject_base
            ca.install_check(False, config, options)

        if config.setup_kra:
            try:
                kra.install_check(remote_api, config, options)
            except RuntimeError as e:
                print str(e)
                sys.exit(1)
    except errors.ACIError:
        sys.exit("\nThe password provided is incorrect for LDAP server "
                 "%s" % config.master_host_name)
    except errors.LDAPError:
        sys.exit("\nUnable to connect to LDAP server %s" %
                 config.master_host_name)
    finally:
        if replman and replman.conn:
            replman.conn.unbind()
        if conn.isconnected():
            conn.disconnect()

    if options.setup_dns:
        dns.install_check(False, True, options, config.host_name)
    else:
        installutils.get_server_ip_address(config.host_name, fstore,
                                           not installer.interactive, False,
                                           options.ip_addresses)

    # check connection
    if not options.skip_conncheck:
        replica_conn_check(
            config.master_host_name, config.host_name, config.realm_name,
            options.setup_ca, config.ca_ds_port, options.admin_password)

    installer._remote_api = remote_api
    installer._fstore = fstore
    installer._sstore = sstore
    installer._config = config


@common_cleanup
def install(installer):
    options = installer
    fstore = installer._fstore
    sstore = installer._sstore
    config = installer._config

    dogtag_constants = dogtag.install_constants

    # Create DS user/group if it doesn't exist yet
    dsinstance.create_ds_user()

    cafile = config.dir + "/ca.crt"

    remote_api = installer._remote_api
    conn = remote_api.Backend.ldap2
    try:
        conn.connect(bind_dn=DIRMAN_DN, bind_pw=config.dirman_password,
                     tls_cacertfile=cafile)

        # Install CA cert so that we can do SSL connections with ldap
        install_ca_cert(conn, api.env.basedn, api.env.realm, cafile)

        # Configure ntpd
        if not options.no_ntp:
            ipaclient.ntpconf.force_ntpd(sstore)
            ntp = ntpinstance.NTPInstance()
            ntp.create_instance()

        # Configure dirsrv
        ds = install_replica_ds(config)

        # Always try to install DNS records
        install_dns_records(config, options, remote_api)
    finally:
        if conn.isconnected():
            conn.disconnect()

    options.dm_password = config.dirman_password

    if config.setup_ca:
        options.realm_name = config.realm_name
        options.domain_name = config.domain_name
        options.host_name = config.host_name

        ca.install(False, config, options)

    krb = install_krb(config, setup_pkinit=not options.no_pkinit)
    http = install_http(config, auto_redirect=not options.no_ui_redirect)

    otpd = otpdinstance.OtpdInstance()
    otpd.create_instance('OTPD', config.host_name, config.dirman_password,
                         ipautil.realm_to_suffix(config.realm_name))

    CA = cainstance.CAInstance(
        config.realm_name, certs.NSS_DIR,
        dogtag_constants=dogtag_constants)
    CA.dm_password = config.dirman_password

    CA.configure_certmonger_renewal()
    CA.import_ra_cert(config.dir + "/ra.p12")
    CA.fix_ra_perms()

    # The DS instance is created before the keytab, add the SSL cert we
    # generated
    ds.add_cert_to_service()

    # Apply any LDAP updates. Needs to be done after the replica is synced-up
    service.print_msg("Applying LDAP updates")
    ds.apply_updates()

    if options.setup_kra:
        kra.install(api, config, options)
    else:
        service.print_msg("Restarting the directory server")
        ds.restart()

    service.print_msg("Restarting the KDC")
    krb.restart()

    if config.setup_ca:
        dogtag_service = services.knownservices[dogtag_constants.SERVICE_NAME]
        dogtag_service.restart(dogtag_constants.PKI_INSTANCE_NAME)

    if options.setup_dns:
        api.Backend.ldap2.connect(autobind=True)
        dns.install(False, True, options)

    # Restart httpd to pick up the new IPA configuration
    service.print_msg("Restarting the web server")
    http.restart()

    # Call client install script
    try:
        args = [paths.IPA_CLIENT_INSTALL, "--on-master", "--unattended",
                "--domain", config.domain_name, "--server", config.host_name,
                "--realm", config.realm_name]
        if options.no_dns_sshfp:
            args.append("--no-dns-sshfp")
        if options.ssh_trust_dns:
            args.append("--ssh-trust-dns")
        if options.no_ssh:
            args.append("--no-ssh")
        if options.no_sshd:
            args.append("--no-sshd")
        if options.mkhomedir:
            args.append("--mkhomedir")
        ipautil.run(args)
    except Exception, e:
        print "Configuration of client side components failed!"
        print "ipa-client-install returned: " + str(e)
        raise RuntimeError("Failed to configure the client")

    ds.replica_populate()

    # Everything installed properly, activate ipa service.
    services.knownservices.ipa.enable()

    remove_replica_info_dir(installer)


class ReplicaCA(common.Installable, core.Group, core.Composite):
    description = "certificate system"

    no_pkinit = Knob(
        bool, False,
        description="disables pkinit setup steps",
    )

    skip_schema_check = Knob(
        bool, False,
        description="skip check for updated CA DS schema on the remote master",
    )


class ReplicaDNS(common.Installable, core.Group, core.Composite):
    description = "DNS"

    setup_dns = Knob(
        bool, False,
        description="configure bind with our zone",
    )

    forwarders = Knob(
        (list, 'ip'), None,
        description=("Add a DNS forwarder. This option can be used multiple "
                     "times"),
        cli_name='forwarder',
    )

    no_forwarders = Knob(
        bool, False,
        description="Do not add any DNS forwarders, use root servers instead",
    )

    reverse_zones = Knob(
        (list, str), [],
        description=("The reverse DNS zone to use. This option can be used "
                     "multiple times"),
        cli_name='reverse-zone',
    )

    no_reverse = Knob(
        bool, False,
        description="Do not create new reverse DNS zone",
    )

    no_dnssec_validation = Knob(
        bool, False,
        description="Disable DNSSEC validation",
    )

    dnssec_master = Knob(
        bool, False,
        initializable=False,
        description="Setup server to be DNSSEC key master",
    )

    disable_dnssec_master = Knob(
        bool, False,
        initializable=False,
        description="Disable the DNSSEC master on this server",
    )

    force = Knob(
        bool, False,
        initializable=False,
        description="Force install",
    )

    kasp_db_file = Knob(
        str, None,
        initializable=False,
        description="Copy OpenDNSSEC metadata from the specified file (will "
                    "not create a new kasp.db file)",
    )

    no_host_dns = Knob(
        bool, False,
        description="Do not use DNS for hostname lookup during installation",
    )

    no_dns_sshfp = Knob(
        bool, False,
        description="do not automatically create DNS SSHFP records",
    )


class Replica(common.Installable, common.Interactive, core.Composite):
    replica_file = Knob(
        str, None,
        description="a file generated by ipa-replica-prepare",
    )

    setup_ca = Knob(
        bool, False,
        initializable=False,
        description="configure a dogtag CA",
    )

    setup_kra = Knob(
        bool, False,
        initializable=False,
        description="configure a dogtag KRA",
    )

    ip_addresses = Knob(
        (list, 'ip-local'), None,
        description=("Replica server IP Address. This option can be used "
                     "multiple times"),
        cli_name='ip-address',
    )

    password = Knob(
        str, None,
        sensitive=True,
        description="Directory Manager (existing master) password",
        cli_short_name='p',
    )

    admin_password = Knob(
        str, None,
        sensitive=True,
        description="Admin user Kerberos password used for connection check",
        cli_short_name='w',
    )

    mkhomedir = Knob(
        bool, False,
        description="create home directories for users on their first login",
    )

    no_ntp = Knob(
        bool, False,
        description="do not configure ntp",
    )

    no_ui_redirect = Knob(
        bool, False,
        description="Do not automatically redirect to the Web UI",
    )

    ssh_trust_dns = Knob(
        bool, False,
        description="configure OpenSSH client to trust DNS SSHFP records",
    )

    no_ssh = Knob(
        bool, False,
        description="do not configure OpenSSH client",
    )

    no_sshd = Knob(
        bool, False,
        description="do not configure OpenSSH server",
    )

    skip_conncheck = Knob(
        bool, False,
        description="skip connection check to remote master",
    )

    def __init__(self, **kwargs):
        super(Replica, self).__init__(**kwargs)

        self._top_dir = None
        self._config = None

        #pylint: disable=no-member

        if self.replica_file is None:
            raise RuntimeError(
                "you must provide a file generated by ipa-replica-prepare")
        if not ipautil.file_exists(self.replica_file):
            raise RuntimeError(
                "Replica file %s does not exist" % self.replica_file)

        if not self.dns.setup_dns:
            if self.dns.forwarders:
                raise RuntimeError(
                    "You cannot specify a --forwarder option without the "
                    "--setup-dns option")
            if self.dns.no_forwarders:
                raise RuntimeError(
                    "You cannot specify a --no-forwarders option without the "
                    "--setup-dns option")
            if self.dns.reverse_zones:
                raise RuntimeError(
                    "You cannot specify a --reverse-zone option without the "
                    "--setup-dns option")
            if self.dns.no_reverse:
                raise RuntimeError(
                    "You cannot specify a --no-reverse option without the "
                    "--setup-dns option")
            if self.dns.no_dnssec_validation:
                raise RuntimeError(
                    "You cannot specify a --no-dnssec-validation option "
                    "without the --setup-dns option")
        elif self.dns.forwarders and self.dns.no_forwarders:
            raise RuntimeError(
                "You cannot specify a --forwarder option together with "
                "--no-forwarders")
        elif not self.dns.forwarders and not self.dns.no_forwarders:
            raise RuntimeError(
                "You must specify at least one --forwarder option or "
                "--no-forwarders option")
        elif self.dns.reverse_zones and self.dns.no_reverse:
            raise RuntimeError(
                "You cannot specify a --reverse-zone option together with "
                "--no-reverse")

        # Automatically disable pkinit w/ dogtag until that is supported
        self.ca.no_pkinit = True

        self.external_ca = False
        self.external_cert_files = None
        self.no_pkinit = self.ca.no_pkinit
        self.skip_schema_check = self.ca.skip_schema_check

        self.setup_dns = self.dns.setup_dns
        self.forwarders = self.dns.forwarders
        self.no_forwarders = self.dns.no_forwarders
        self.reverse_zones = self.dns.reverse_zones
        self.no_reverse = self.dns.no_reverse
        self.no_dnssec_validation = self.dns.no_dnssec_validation
        self.dnssec_master = self.dns.dnssec_master
        self.disable_dnssec_master = self.dns.disable_dnssec_master
        self.kasp_db_file = self.dns.kasp_db_file
        self.force = self.dns.force
        self.zonemgr = None
        self.no_host_dns = self.dns.no_host_dns
        self.no_dns_sshfp = self.dns.no_dns_sshfp

        self.unattended = not self.interactive

    @step()
    def main(self):
        install_check(self)
        yield
        install(self)

    ca = core.Component(ReplicaCA)
    dns = core.Component(ReplicaDNS)
