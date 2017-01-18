#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

import collections
from distutils.version import LooseVersion
import dns.exception as dnsexception
import dns.name as dnsname
import dns.resolver as dnsresolver
import dns.reversename as dnsreversename
import os
import shutil
import socket
import tempfile

import six

from ipapython import ipaldap, ipautil, sysrestore
from ipapython.dn import DN
from ipapython.install.common import step
from ipapython.install.core import Knob
from ipapython.ipa_log_manager import root_logger
from ipapython.admintool import ScriptError
from ipaplatform import services
from ipaplatform.tasks import tasks
from ipaplatform.paths import paths
from ipalib import api, certstore, constants, create_api, errors, rpc, x509
from ipalib.util import (
    network_ip_address_warning,
    broadcast_ip_address_warning,
)
import ipaclient.ipachangeconf
import ipaclient.ntpconf
from ipaserver.install import (
    bindinstance, ca, cainstance, certs, dns, dsinstance, httpinstance,
    installutils, kra, krainstance, krbinstance, memcacheinstance,
    ntpinstance, otpdinstance, custodiainstance, service)
from ipaserver.install.installutils import (
    create_replica_config, ReplicaConfig, load_pkcs12, is_ipa_configured)
from ipaserver.install.replication import (
    ReplicationManager, replica_conn_check, wait_for_entry)
import SSSDConfig
from subprocess import CalledProcessError
from binascii import hexlify

from .common import BaseServer

if six.PY3:
    unicode = str

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


def install_http_certs(config, fstore, remote_api):

    # Obtain keytab for the HTTP service
    fstore.backup_file(paths.IPA_KEYTAB)
    try:
        os.unlink(paths.IPA_KEYTAB)
    except OSError:
        pass

    principal = 'HTTP/%s@%s' % (config.host_name, config.realm_name)
    installutils.install_service_keytab(remote_api,
                                        principal,
                                        config.master_host_name,
                                        paths.IPA_KEYTAB,
                                        force_service_add=True)
    dn = DN(
        ('krbprincipalname', principal),
        api.env.container_service, api.env.basedn
    )
    conn = ipaldap.IPAdmin(realm=config.realm_name, ldapi=True)
    conn.do_external_bind()
    wait_for_entry(conn, dn)
    conn.unbind()

    # Obtain certificate for the HTTP service
    nssdir = certs.NSS_DIR
    subject = DN(('O', config.realm_name))
    db = certs.CertDB(config.realm_name, nssdir=nssdir, subject_base=subject)
    db.request_service_cert('Server-Cert', principal, config.host_name, True)
    # FIXME: need Signing-Cert too ?


def install_replica_ds(config, options, ca_is_configured, remote_api,
                       promote=False, pkcs12_info=None):
    dsinstance.check_ports()

    # if we have a pkcs12 file, create the cert db from
    # that. Otherwise the ds setup will create the CA
    # cert
    if pkcs12_info is None:
        pkcs12_info = make_pkcs12_info(config.dir, "dscert.p12",
                                       "dirsrv_pin.txt")

    if promote:
        ca_file = paths.IPA_CA_CRT
    else:
        ca_file = os.path.join(config.dir, "ca.crt")

    ds = dsinstance.DsInstance(
        config_ldif=options.dirsrv_config_file)
    ds.create_replica(
        realm_name=config.realm_name,
        master_fqdn=config.master_host_name,
        fqdn=config.host_name,
        domain_name=config.domain_name,
        dm_password=config.dirman_password,
        subject_base=config.subject_base,
        pkcs12_info=pkcs12_info,
        ca_is_configured=ca_is_configured,
        ca_file=ca_file,
        promote=promote,
        api=remote_api,
    )

    return ds


def install_krb(config, setup_pkinit=False, promote=False):
    krb = krbinstance.KrbInstance()

    # pkinit files
    pkcs12_info = make_pkcs12_info(config.dir, "pkinitcert.p12",
                                   "pkinit_pin.txt")

    krb.create_replica(config.realm_name,
                       config.master_host_name, config.host_name,
                       config.domain_name, config.dirman_password,
                       setup_pkinit, pkcs12_info, promote=promote)

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

        os.chmod(constants.CACERT, 0o444)
    except Exception as e:
        raise ScriptError("error copying files: " + str(e))


def install_http(config, auto_redirect, ca_is_configured, promote=False,
                 pkcs12_info=None):
    # if we have a pkcs12 file, create the cert db from
    # that. Otherwise the ds setup will create the CA
    # cert
    if pkcs12_info is None:
        pkcs12_info = make_pkcs12_info(config.dir, "httpcert.p12",
                                       "http_pin.txt")

    if promote:
        ca_file = paths.IPA_CA_CRT
    else:
        ca_file = os.path.join(config.dir, "ca.crt")

    memcache = memcacheinstance.MemcacheInstance()
    memcache.create_instance('MEMCACHE', config.host_name,
                             config.dirman_password,
                             ipautil.realm_to_suffix(config.realm_name))

    http = httpinstance.HTTPInstance()
    http.create_instance(
        config.realm_name, config.host_name, config.domain_name,
        config.dirman_password, False, pkcs12_info,
        auto_redirect=auto_redirect, ca_file=ca_file,
        ca_is_configured=ca_is_configured, promote=promote)

    http.setup_firefox_extension(config.realm_name, config.domain_name)

    return http


def install_dns_records(config, options, remote_api):

    if not bindinstance.dns_container_exists(
            config.host_name,
            ipautil.realm_to_suffix(config.realm_name),
            realm=config.realm_name, ldapi=True,
            autobind=ipaldap.AUTOBIND_ENABLED):
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
                                        reverse_zone)
    except errors.NotFound as e:
        root_logger.debug('Replica DNS records could not be added '
                          'on master: %s', str(e))

    # we should not fail here no matter what
    except Exception as e:
        root_logger.info('Replica DNS records could not be added '
                         'on master: %s', str(e))


def check_dirsrv():
    (ds_unsecure, ds_secure) = dsinstance.check_ports()
    if not ds_unsecure or not ds_secure:
        msg = ("IPA requires ports 389 and 636 for the Directory Server.\n"
               "These are currently in use:\n")
        if not ds_unsecure:
            msg += "\t389\n"
        if not ds_secure:
            msg += "\t636\n"
        raise ScriptError(msg)


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
        except Exception as e:
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


def configure_certmonger():
    messagebus = services.knownservices.messagebus
    try:
        messagebus.start()
    except Exception as e:
        raise ScriptError("Messagebus service unavailable: %s" % str(e),
                          rval=3)

    # Ensure that certmonger has been started at least once to generate the
    # cas files in /var/lib/certmonger/cas.
    cmonger = services.knownservices.certmonger
    try:
        cmonger.restart()
    except Exception as e:
        raise ScriptError("Certmonger service unavailable: %s" % str(e),
                          rval=3)

    try:
        cmonger.enable()
    except Exception as e:
        raise ScriptError("Failed to enable Certmonger: %s" % str(e),
                          rval=3)


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
            raise ScriptError()
        except Exception:
            print(
                "Your system may be partly configured.\n"
                "Run /usr/sbin/ipa-server-install --uninstall to clean up.\n")
            raise

    return decorated


def preserve_enrollment_state(func):
    """
    Makes sure the machine is unenrollled if the decorated function
    failed.
    """
    def decorated(installer):
        try:
            func(installer)
        except BaseException:
            if installer._enrollment_performed:
                uninstall_client()
            raise

    return decorated


def uninstall_client():
    """
    Attempts to unenroll the IPA client using the ipa-client-install utility.

    An unsuccessful attempt to uninstall is ignored (no exception raised).
    """

    print("Removing client side components")
    ipautil.run([paths.IPA_CLIENT_INSTALL, "--unattended", "--uninstall"],
                raiseonerr=False, redirect_output=True)
    print()


def promote_sssd(host_name):
    sssdconfig = SSSDConfig.SSSDConfig()
    sssdconfig.import_config()
    domains = sssdconfig.list_active_domains()

    ipa_domain = None

    for name in domains:
        domain = sssdconfig.get_domain(name)
        try:
            hostname = domain.get_option('ipa_hostname')
            if hostname == host_name:
                ipa_domain = domain
        except SSSDConfig.NoOptionError:
            continue

    if ipa_domain is None:
        raise RuntimeError("Couldn't find IPA domain in sssd.conf")
    else:
        domain.set_option('ipa_server', host_name)
        domain.set_option('ipa_server_mode', True)
        sssdconfig.save_domain(domain)
        sssdconfig.write()

        sssd = services.service('sssd')
        try:
            sssd.restart()
        except CalledProcessError:
            root_logger.warning("SSSD service restart was unsuccessful.")


def promote_openldap_conf(hostname, master):
    """
    Reset the URI directive in openldap-client configuration file to point to
    newly promoted replica. If this directive was set by third party, then
    replace the added comment with the one pointing to replica

    :param hostname: replica FQDN
    :param master: FQDN of remote master
    """

    ldap_conf = paths.OPENLDAP_LDAP_CONF

    ldap_change_conf = ipaclient.ipachangeconf.IPAChangeConf(
        "IPA replica installer")
    ldap_change_conf.setOptionAssignment((" ", "\t"))

    new_opts = []

    with open(ldap_conf, 'r') as f:
        old_opts = ldap_change_conf.parse(f)

        for opt in old_opts:
            if opt['type'] == 'comment' and master in opt['value']:
                continue
            elif (opt['type'] == 'option' and opt['name'] == 'URI' and
                    master in opt['value']):
                continue
            new_opts.append(opt)

    change_opts = [
        {'action': 'addifnotset',
         'name': 'URI',
         'type': 'option',
         'value': 'ldaps://' + hostname}
    ]

    try:
        ldap_change_conf.newConf(ldap_conf, new_opts)
        ldap_change_conf.changeConf(ldap_conf, change_opts)
    except Exception as e:
        root_logger.info("Failed to update {}: {}".format(ldap_conf, e))


def check_remote_version(api):
    client = rpc.jsonclient(api)
    client.finalize()

    client.connect()
    try:
        env = client.forward(u'env', u'version')['result']
    finally:
        client.disconnect()

    remote_version = env['version']
    version = api.env.version
    if LooseVersion(remote_version) > LooseVersion(version):
        raise RuntimeError(
            "Cannot install replica of a server of higher version ({}) than"
            "the local version ({})".format(remote_version, version))


@common_cleanup
def install_check(installer):
    options = installer
    filename = installer.replica_file

    if ipautil.is_fips_enabled():
        raise RuntimeError(
            "Installing IPA server in FIPS mode is not supported")

    tasks.check_selinux_status()

    if is_ipa_configured():
        raise ScriptError(
            "IPA server is already configured on this system.\n"
            "If you want to reinstall the IPA server, please uninstall "
            "it first using 'ipa-server-install --uninstall'.")

    client_fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    if client_fstore.has_files():
        raise ScriptError(
            "IPA client is already configured on this system.\n"
            "Please uninstall it first before configuring the replica, "
            "using 'ipa-client-install --uninstall'.")

    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    # Check to see if httpd is already configured to listen on 443
    if httpinstance.httpd_443_configured():
        raise ScriptError("Aborting installation")

    check_dirsrv()

    if not options.no_ntp:
        try:
            ipaclient.ntpconf.check_timedate_services()
        except ipaclient.ntpconf.NTPConflictingService as e:
            print(("WARNING: conflicting time&date synchronization service '%s'"
                  " will" % e.conflicting_service))
            print("be disabled in favor of ntpd")
            print("")
        except ipaclient.ntpconf.NTPConfigurationError:
            pass

    # get the directory manager password
    dirman_password = options.password
    if not dirman_password:
        try:
            dirman_password = get_dirman_password()
        except KeyboardInterrupt:
            raise ScriptError(rval=0)
        if dirman_password is None:
            raise ScriptError("Directory Manager password required")

    config = create_replica_config(dirman_password, filename, options)
    installer._top_dir = config.top_dir
    config.setup_ca = options.setup_ca
    config.setup_kra = options.setup_kra

    ca_enabled = ipautil.file_exists(config.dir + "/cacert.p12")

    # Create the management framework config file
    # Note: We must do this before bootstraping and finalizing ipalib.api
    old_umask = os.umask(0o22)   # must be readable for httpd
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
        if ca_enabled:
            fd.write("enable_ra=True\n")
            fd.write("ra_plugin=dogtag\n")
            fd.write("dogtag_version=10\n")

            if not config.setup_ca:
                fd.write("ca_host={0}\n".format(config.master_host_name))
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

    for pkcs12_name, pin_name in (('dscert.p12', 'dirsrv_pin.txt'),
                                  ('httpcert.p12', 'http_pin.txt')):
        pkcs12_info = make_pkcs12_info(config.dir, pkcs12_name, pin_name)
        tmp_db_dir = tempfile.mkdtemp('ipa')
        try:
            tmp_db = certs.CertDB(config.realm_name,
                                  nssdir=tmp_db_dir,
                                  subject_base=config.subject_base)
            if ca_enabled:
                trust_flags = 'CT,C,C'
            else:
                trust_flags = None
            tmp_db.create_from_pkcs12(pkcs12_info[0], pkcs12_info[1],
                                      ca_file=cafile,
                                      trust_flags=trust_flags)
            if not tmp_db.find_server_certs():
                raise RuntimeError(
                    "Could not find a suitable server cert in import in %s" %
                    pkcs12_info[0])
        except Exception as e:
            root_logger.error('%s', e)
            raise RuntimeError(
                "Server cert is not valid. Please run ipa-replica-prepare to "
                "create a new replica file.")
        finally:
            shutil.rmtree(tmp_db_dir)

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
            msg = ("A replication agreement for this host already exists. "
                   "It needs to be removed.\n"
                   "Run this on the master that generated the info file:\n"
                   "    %% ipa-replica-manage del %s --force" %
                   config.host_name)
            raise ScriptError(msg, rval=3)

        # Detect the current domain level
        try:
            current = remote_api.Command['domainlevel_get']()['result']
        except errors.NotFound:
            # If we're joining an older master, domain entry is not
            # available
            current = constants.DOMAIN_LEVEL_0

        if current != constants.DOMAIN_LEVEL_0:
            raise RuntimeError(
                "You cannot use a replica file to join a replica when the "
                "domain is above level 0. Please join the system to the "
                "domain by running ipa-client-install first, the try again "
                "without a replica file."
            )

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
            raise ScriptError(message, rval=3)

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
            msg = ("The host %s already exists on the master server.\n"
                   "You should remove it before proceeding:\n"
                   "    %% ipa host-del %s" %
                   (config.host_name, config.host_name))
            raise ScriptError(msg, rval=3)

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
                        raise ScriptError(rval=0)
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
                raise ScriptError(e)

        if options.setup_dns:
            dns.install_check(False, remote_api, True, options,
                              config.host_name)
            config.ips = dns.ip_addresses
        else:
            config.ips = installutils.get_server_ip_address(
                config.host_name, not installer.interactive, False,
                options.ip_addresses)

            # check addresses here, dns module is doing own check
            network_ip_address_warning(config.ips)
            broadcast_ip_address_warning(config.ips)

    except errors.ACIError:
        raise ScriptError("\nThe password provided is incorrect for LDAP server "
                          "%s" % config.master_host_name)
    except errors.LDAPError:
        raise ScriptError("\nUnable to connect to LDAP server %s" %
                          config.master_host_name)
    finally:
        if replman and replman.conn:
            replman.conn.unbind()
        if conn.isconnected():
            conn.disconnect()

    # installer needs to update hosts file when DNS subsystem will be
    # installed or custom addresses are used
    if options.setup_dns or options.ip_addresses:
        installer._update_hosts_file = True

    # check connection
    if not options.skip_conncheck:
        replica_conn_check(
            config.master_host_name, config.host_name, config.realm_name,
            options.setup_ca, config.ca_ds_port, options.admin_password,
            ca_cert_file=cafile)

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

    if installer._update_hosts_file:
        installutils.update_hosts_file(config.ips, config.host_name, fstore)

    ca_enabled = ipautil.file_exists(config.dir + "/cacert.p12")

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
        ds = install_replica_ds(config, options, ca_enabled, remote_api)

        ntpinstance.ntp_ldap_enable(config.host_name, ds.suffix, api.env.realm)

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

        if ca_enabled:
            options.ra_p12 = config.dir + "/ra.p12"

        ca.install_step_0(False, config, options)

    krb = install_krb(config, setup_pkinit=not options.no_pkinit)
    http = install_http(config, auto_redirect=not options.no_ui_redirect,
                        ca_is_configured=ca_enabled)

    if config.setup_ca:
        # Done after install_krb() because lightweight CA key
        # retrieval setup needs to create kerberos principal.
        ca.install_step_1(False, config, options)

    otpd = otpdinstance.OtpdInstance()
    otpd.create_instance('OTPD', config.host_name, config.dirman_password,
                         ipautil.realm_to_suffix(config.realm_name))

    if ca_enabled:
        CA = cainstance.CAInstance(config.realm_name, certs.NSS_DIR)
        CA.dm_password = config.dirman_password

        CA.configure_certmonger_renewal()
        CA.import_ra_cert(config.dir + "/ra.p12")
        CA.fix_ra_perms()

    custodia = custodiainstance.CustodiaInstance(config.host_name,
                                                 config.realm_name)
    custodia.create_instance(config.dirman_password)

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
        services.knownservices['pki_tomcatd'].restart('pki-tomcat')

    api.Backend.ldap2.connect(autobind=True)
    if options.setup_dns:
        dns.install(False, True, options)
    else:
        api.Command.dns_update_system_records()

    # Restart httpd to pick up the new IPA configuration
    service.print_msg("Restarting the web server")
    http.restart()

    # Call client install script
    service.print_msg("Configuring client side components")
    try:
        args = [paths.IPA_CLIENT_INSTALL, "--on-master", "--unattended",
                "--domain", config.domain_name, "--server", config.host_name,
                "--realm", config.realm_name, "--no-ntp"]
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
        ipautil.run(args, redirect_output=True)
        print()
    except Exception:
        print("Configuration of client side components failed!")
        raise RuntimeError("Failed to configure the client")

    ds.replica_populate()

    # update DNA shared config entry is done as far as possible
    # from restart to avoid waiting for its creation
    ds.update_dna_shared_config()

    # Everything installed properly, activate ipa service.
    services.knownservices.ipa.enable()

    remove_replica_info_dir(installer)


def ensure_enrolled(installer):
    config = installer._config

    # Call client install script
    service.print_msg("Configuring client side components")
    try:
        installer._enrollment_performed = True

        args = [paths.IPA_CLIENT_INSTALL, "--unattended", "--no-ntp"]
        stdin = None

        if installer.domain_name:
            args.extend(["--domain", installer.domain_name])
        if installer.server:
            args.extend(["--server", installer.server])
        if installer.realm_name:
            args.extend(["--realm", installer.realm_name])
        if installer.host_name:
            args.extend(["--hostname", installer.host_name])

        if installer.password:
            args.extend(["--password", installer.password])
        else:
            if installer.admin_password:
                # Always set principal if password was set explicitly,
                # the password itself gets passed directly via stdin
                args.extend(["--principal", installer.principal or "admin"])
                stdin = installer.admin_password
            if installer.keytab:
                args.extend(["--keytab", installer.keytab])

        if installer.no_dns_sshfp:
            args.append("--no-dns-sshfp")
        if installer.ssh_trust_dns:
            args.append("--ssh-trust-dns")
        if installer.no_ssh:
            args.append("--no-ssh")
        if installer.no_sshd:
            args.append("--no-sshd")
        if installer.mkhomedir:
            args.append("--mkhomedir")

        ipautil.run(args, stdin=stdin, redirect_output=True)
        print()
    except Exception:
        raise ScriptError("Configuration of client side components failed!")


def promotion_check_ipa_domain(master_ldap_conn, basedn):
    entry = master_ldap_conn.get_entry(basedn, ['associatedDomain'])
    if not 'associatedDomain' in entry:
        raise RuntimeError('IPA domain not found in LDAP.')

    if len(entry['associatedDomain']) > 1:
        root_logger.critical(
            "Multiple IPA domains found. We are so sorry :-(, you are "
            "probably experiencing this bug "
            "https://fedorahosted.org/freeipa/ticket/5976. Please contact us "
            "for help.")
        raise RuntimeError(
            'Multiple IPA domains found in LDAP database ({domains}). '
            'Only one domain is allowed.'.format(
                domains=u', '.join(entry['associatedDomain'])
            ))

    if entry['associatedDomain'][0] != api.env.domain:
        raise RuntimeError(
            "Cannot promote this client to a replica. Local domain "
            "'{local}' does not match IPA domain '{ipadomain}'. ".format(
                local=api.env.domain,
                ipadomain=entry['associatedDomain'][0]
        ))


@common_cleanup
@preserve_enrollment_state
def promote_check(installer):
    options = installer

    installer._enrollment_performed = False
    installer._top_dir = tempfile.mkdtemp("ipa")

    tasks.check_selinux_status()

    if is_ipa_configured():
        raise ScriptError(
            "IPA server is already configured on this system.\n"
            "If you want to reinstall the IPA server, please uninstall "
            "it first using 'ipa-server-install --uninstall'.")

    client_fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    if not client_fstore.has_files():
        ensure_enrolled(installer)
    else:
        if (options.domain_name or options.server or options.realm_name or
                options.host_name or options.password or options.keytab):
            print("IPA client is already configured on this system, ignoring "
                  "the --domain, --server, --realm, --hostname, --password "
                  "and --keytab options.")

    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    # Check to see if httpd is already configured to listen on 443
    if httpinstance.httpd_443_configured():
        raise ScriptError("Aborting installation")

    check_dirsrv()

    if not options.no_ntp:
        try:
            ipaclient.ntpconf.check_timedate_services()
        except ipaclient.ntpconf.NTPConflictingService as e:
            print("WARNING: conflicting time&date synchronization service '%s'"
                  " will" % e.conflicting_service)
            print("be disabled in favor of ntpd")
            print("")
        except ipaclient.ntpconf.NTPConfigurationError:
            pass

    api.bootstrap(in_server=True, context='installer')
    api.finalize()

    config = ReplicaConfig()
    config.realm_name = api.env.realm
    config.host_name = api.env.host
    config.domain_name = api.env.domain
    config.master_host_name = api.env.server
    config.ca_host_name = api.env.ca_host
    config.setup_ca = options.setup_ca
    config.setup_kra = options.setup_kra
    config.dir = installer._top_dir

    http_pkcs12_file = None
    http_pkcs12_info = None
    dirsrv_pkcs12_file = None
    dirsrv_pkcs12_info = None
    pkinit_pkcs12_file = None
    pkinit_pkcs12_info = None

    if options.http_cert_files:
        if options.http_pin is None:
            options.http_pin = installutils.read_password(
                "Enter Apache Server private key unlock",
                confirm=False, validate=False)
            if options.http_pin is None:
                raise ScriptError(
                    "Apache Server private key unlock password required")
        http_pkcs12_file, http_pin, http_ca_cert = load_pkcs12(
            cert_files=options.http_cert_files,
            key_password=options.http_pin,
            key_nickname=options.http_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=config.host_name)
        http_pkcs12_info = (http_pkcs12_file.name, http_pin)

    if options.dirsrv_cert_files:
        if options.dirsrv_pin is None:
            options.dirsrv_pin = installutils.read_password(
                "Enter Directory Server private key unlock",
                confirm=False, validate=False)
            if options.dirsrv_pin is None:
                raise ScriptError(
                    "Directory Server private key unlock password required")
        dirsrv_pkcs12_file, dirsrv_pin, dirsrv_ca_cert = load_pkcs12(
            cert_files=options.dirsrv_cert_files,
            key_password=options.dirsrv_pin,
            key_nickname=options.dirsrv_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=config.host_name)
        dirsrv_pkcs12_info = (dirsrv_pkcs12_file.name, dirsrv_pin)

    if options.pkinit_cert_files:
        if options.pkinit_pin is None:
            options.pkinit_pin = installutils.read_password(
                "Enter Kerberos KDC private key unlock",
                confirm=False, validate=False)
            if options.pkinit_pin is None:
                raise ScriptError(
                    "Kerberos KDC private key unlock password required")
        pkinit_pkcs12_file, pkinit_pin, pkinit_ca_cert = load_pkcs12(
            cert_files=options.pkinit_cert_files,
            key_password=options.pkinit_pin,
            key_nickname=options.pkinit_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=config.host_name)
        pkinit_pkcs12_info = (pkinit_pkcs12_file.name, pkinit_pin)

    if (options.http_cert_files and options.dirsrv_cert_files and
            http_ca_cert != dirsrv_ca_cert):
        raise RuntimeError("Apache Server SSL certificate and Directory "
                           "Server SSL certificate are not signed by the same"
                           " CA certificate")

    installutils.verify_fqdn(config.host_name, options.no_host_dns)
    installutils.verify_fqdn(config.master_host_name, options.no_host_dns)

    ccache = os.environ['KRB5CCNAME']
    ipautil.kinit_keytab('host/{env.host}@{env.realm}'.format(env=api.env),
                         paths.KRB5_KEYTAB,
                         ccache)

    cafile = paths.IPA_CA_CRT
    if not ipautil.file_exists(cafile):
        raise RuntimeError("CA cert file is not available! Please reinstall"
                           "the client and try again.")

    ldapuri = 'ldaps://%s' % ipautil.format_netloc(config.master_host_name)
    xmlrpc_uri = 'https://{}/ipa/xml'.format(
        ipautil.format_netloc(config.master_host_name))
    remote_api = create_api(mode=None)
    remote_api.bootstrap(in_server=True, context='installer',
                         ldap_uri=ldapuri, xmlrpc_uri=xmlrpc_uri)
    remote_api.finalize()

    check_remote_version(remote_api)

    conn = remote_api.Backend.ldap2
    replman = None
    try:
        # Try out authentication
        conn.connect(ccache=ccache)
        replman = ReplicationManager(config.realm_name,
                                     config.master_host_name, None)

        # Detect the current domain level
        try:
            current = remote_api.Command['domainlevel_get']()['result']
        except errors.NotFound:
            # If we're joining an older master, domain entry is not
            # available
            current = constants.DOMAIN_LEVEL_0

        if current == constants.DOMAIN_LEVEL_0:
            raise RuntimeError(
                "You must provide a file generated by ipa-replica-prepare to "
                "create a replica when the domain is at level 0."
            )

        # Check authorization
        result = remote_api.Command['hostgroup_find'](
            cn=u'ipaservers',
            host=[unicode(api.env.host)]
        )['result']
        add_to_ipaservers = not result

        if add_to_ipaservers:
            if options.password and not options.admin_password:
                raise errors.ACIError(info="Not authorized")

            if installer._ccache is None:
                del os.environ['KRB5CCNAME']
            else:
                os.environ['KRB5CCNAME'] = installer._ccache

            try:
                installutils.check_creds(options, config.realm_name)
                installer._ccache = os.environ.get('KRB5CCNAME')
            finally:
                os.environ['KRB5CCNAME'] = ccache

            conn.disconnect()
            conn.connect(ccache=installer._ccache)

            try:
                result = remote_api.Command['hostgroup_show'](
                    u'ipaservers',
                    all=True,
                    rights=True
                )['result']

                if 'w' not in result['attributelevelrights']['member']:
                    raise errors.ACIError(info="Not authorized")
            finally:
                conn.disconnect()
                conn.connect(ccache=ccache)

        promotion_check_ipa_domain(conn, remote_api.env.basedn)

        # Check that we don't already have a replication agreement
        try:
            (acn, adn) = replman.agreement_dn(config.host_name)
            entry = conn.get_entry(adn, ['*'])
        except errors.NotFound:
            pass
        else:
            root_logger.info('Error: A replication agreement for this '
                             'host already exists.')
            print('A replication agreement for this host already exists. '
                  'It needs to be removed.')
            print("Run this command:")
            print("    %% ipa-replica-manage del %s --force" %
                  config.host_name)
            raise ScriptError(rval=3)

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
            raise ScriptError(rval=3)

        # Detect if the other master can handle replication managers
        # cn=replication managers,cn=sysaccounts,cn=etc,$SUFFIX
        dn = DN(('cn', 'replication managers'), ('cn', 'sysaccounts'),
                ('cn', 'etc'), ipautil.realm_to_suffix(config.realm_name))
        try:
            entry = conn.get_entry(dn)
        except errors.NotFound:
            msg = ("The Replication Managers group is not available in "
                   "the domain. Replica promotion requires the use of "
                   "Replication Managers to be able to replicate data. "
                   "Upgrade the peer master or use the ipa-replica-prepare "
                   "command on the master and use a prep file to install "
                   "this replica.")
            root_logger.error(msg)
            raise ScriptError(rval=3)

        dns_masters = remote_api.Object['dnsrecord'].get_dns_masters()
        if dns_masters:
            if not options.no_host_dns:
                root_logger.debug('Check forward/reverse DNS resolution')
                resolution_ok = (
                    check_dns_resolution(config.master_host_name,
                                         dns_masters) and
                    check_dns_resolution(config.host_name, dns_masters))
                if not resolution_ok and installer.interactive:
                    if not ipautil.user_input("Continue?", False):
                        raise ScriptError(rval=0)
        else:
            root_logger.debug('No IPA DNS servers, '
                              'skipping forward/reverse resolution check')

        entry_attrs = conn.get_ipa_config()
        subject_base = entry_attrs.get('ipacertificatesubjectbase', [None])[0]
        if subject_base is not None:
            config.subject_base = DN(subject_base)

        # Find if any server has a CA
        ca_host = service.find_providing_server('CA', conn, api.env.server)
        if ca_host is not None:
            config.ca_host_name = ca_host
            ca_enabled = True
            if options.dirsrv_cert_files:
                root_logger.error("Certificates could not be provided when "
                                  "CA is present on some master.")
                raise ScriptError(rval=3)
        else:
            ca_enabled = False
            if not options.dirsrv_cert_files:
                root_logger.error("Cannot issue certificates: a CA is not "
                                  "installed. Use the --http-cert-file, "
                                  "--dirsrv-cert-file options to provide "
                                  "custom certificates.")
                raise ScriptError(rval=3)

        config.kra_host_name = service.find_providing_server('KRA', conn,
                                                             api.env.server)
        if options.setup_kra and config.kra_host_name is None:
            root_logger.error("There is no KRA server in the domain, can't "
                              "setup a KRA clone")
            raise ScriptError(rval=3)

        if options.setup_ca:
            if not ca_enabled:
                root_logger.error("The remote master does not have a CA "
                                  "installed, can't set up CA")
                raise ScriptError(rval=3)

            options.realm_name = config.realm_name
            options.host_name = config.host_name
            options.subject = config.subject_base
            ca.install_check(False, None, options)

        if config.setup_kra:
            try:
                kra.install_check(remote_api, config, options)
            except RuntimeError as e:
                raise ScriptError(e)

        if options.setup_dns:
            dns.install_check(False, remote_api, True, options,
                              config.host_name)
            config.ips = dns.ip_addresses
        else:
            config.ips = installutils.get_server_ip_address(
                config.host_name, not installer.interactive,
                False, options.ip_addresses)

            # check addresses here, dns module is doing own check
            network_ip_address_warning(config.ips)
            broadcast_ip_address_warning(config.ips)

    except errors.ACIError:
        raise ScriptError("\nInsufficient privileges to promote the server.")
    except errors.LDAPError:
        raise ScriptError("\nUnable to connect to LDAP server %s" %
                          config.master_host_name)
    finally:
        if replman and replman.conn:
            replman.conn.unbind()
        if conn.isconnected():
            conn.disconnect()

    # check connection
    if not options.skip_conncheck:
        if add_to_ipaservers:
            # use user's credentials when the server host is not ipaservers
            if installer._ccache is None:
                del os.environ['KRB5CCNAME']
            else:
                os.environ['KRB5CCNAME'] = installer._ccache

        try:
            replica_conn_check(
                config.master_host_name, config.host_name, config.realm_name,
                options.setup_ca, 389,
                options.admin_password, principal=options.principal,
                ca_cert_file=cafile)
        finally:
            if add_to_ipaservers:
                os.environ['KRB5CCNAME'] = ccache

    if not ipautil.file_exists(cafile):
        raise RuntimeError("CA cert file is not available.")

    installer._ca_enabled = ca_enabled
    installer._fstore = fstore
    installer._sstore = sstore
    installer._config = config
    installer._remote_api = remote_api
    installer._add_to_ipaservers = add_to_ipaservers
    installer._dirsrv_pkcs12_file = dirsrv_pkcs12_file
    installer._dirsrv_pkcs12_info = dirsrv_pkcs12_info
    installer._http_pkcs12_file = http_pkcs12_file
    installer._http_pkcs12_info = http_pkcs12_info
    installer._pkinit_pkcs12_file = pkinit_pkcs12_file
    installer._pkinit_pkcs12_info = pkinit_pkcs12_info


@common_cleanup
def promote(installer):
    options = installer
    fstore = installer._fstore
    sstore = installer._sstore
    config = installer._config
    dirsrv_pkcs12_file = installer._dirsrv_pkcs12_file
    dirsrv_pkcs12_info = installer._dirsrv_pkcs12_info
    http_pkcs12_file = installer._http_pkcs12_file
    http_pkcs12_info = installer._http_pkcs12_info
    pkinit_pkcs12_file = installer._pkinit_pkcs12_file
    pkinit_pkcs12_info = installer._pkinit_pkcs12_info

    ccache = os.environ['KRB5CCNAME']
    remote_api = installer._remote_api
    conn = remote_api.Backend.ldap2
    if installer._add_to_ipaservers:
        try:
            conn.connect(ccache=installer._ccache)

            remote_api.Command['hostgroup_add_member'](
                u'ipaservers',
                host=[unicode(api.env.host)],
            )
        finally:
            if conn.isconnected():
                conn.disconnect()
            os.environ['KRB5CCNAME'] = ccache

    # Save client file and merge in server directives
    target_fname = paths.IPA_DEFAULT_CONF
    fstore.backup_file(target_fname)
    ipaconf = ipaclient.ipachangeconf.IPAChangeConf("IPA Replica Promote")
    ipaconf.setOptionAssignment(" = ")
    ipaconf.setSectionNameDelimiters(("[", "]"))

    config.promote = installer.promote
    config.dirman_password = hexlify(ipautil.ipa_generate_password())

    # FIXME: allow to use passed in certs instead
    if installer._ca_enabled:
        configure_certmonger()

    # Create DS user/group if it doesn't exist yet
    dsinstance.create_ds_user()

    # Configure ntpd
    if not options.no_ntp:
        ipaclient.ntpconf.force_ntpd(sstore)
        ntp = ntpinstance.NTPInstance()
        ntp.create_instance()

    try:
        conn.connect(ccache=ccache)

        # Configure dirsrv
        ds = install_replica_ds(config, options, installer._ca_enabled,
                                remote_api,
                                promote=True, pkcs12_info=dirsrv_pkcs12_info)

        # Always try to install DNS records
        install_dns_records(config, options, remote_api)

        # Must install http certs before changing ipa configuration file
        # or certmonger will fail to contact the peer master
        install_http_certs(config, fstore, remote_api)

        ntpinstance.ntp_ldap_enable(config.host_name, ds.suffix,
                                    remote_api.env.realm)

    finally:
        if conn.isconnected():
            conn.disconnect()

        # Create the management framework config file
        # do this regardless of the state of DS installation. Even if it fails,
        # we need to have master-like configuration in order to perform a
        # successful uninstallation
        ldapi_uri = installutils.realm_to_ldapi_uri(config.realm_name)

        gopts = [
            ipaconf.setOption('host', config.host_name),
            ipaconf.rmOption('server'),
            ipaconf.setOption('xmlrpc_uri',
                              'https://%s/ipa/xml' %
                              ipautil.format_netloc(config.host_name)),
            ipaconf.setOption('ldap_uri', ldapi_uri),
            ipaconf.setOption('mode', 'production')
        ]

        if installer._ca_enabled:
            gopts.extend([
                ipaconf.setOption('enable_ra', 'True'),
                ipaconf.setOption('ra_plugin', 'dogtag'),
                ipaconf.setOption('dogtag_version', '10')
            ])

            if not options.setup_ca:
                gopts.append(ipaconf.setOption('ca_host', config.ca_host_name))
        else:
            gopts.extend([
                ipaconf.setOption('enable_ra', 'False'),
                ipaconf.setOption('ra_plugin', 'None')
            ])

        opts = [ipaconf.setSection('global', gopts)]

        ipaconf.changeConf(target_fname, opts)
        os.chmod(target_fname, 0o644)   # must be readable for httpd

    custodia = custodiainstance.CustodiaInstance(config.host_name,
                                                 config.realm_name,
                                                 installer._ca_enabled)
    custodia.create_replica(config.master_host_name)

    if installer._ca_enabled:
        CA = cainstance.CAInstance(config.realm_name, certs.NSS_DIR)

        CA.configure_certmonger_renewal()
        CA.configure_agent_renewal()
        cainstance.export_kra_agent_pem()
        CA.fix_ra_perms()

    krb = install_krb(config,
                      setup_pkinit=not options.no_pkinit,
                      promote=True)

    http = install_http(config,
                        auto_redirect=not options.no_ui_redirect,
                        promote=True, pkcs12_info=http_pkcs12_info,
                        ca_is_configured=installer._ca_enabled)

    # Apply any LDAP updates. Needs to be done after the replica is synced-up
    service.print_msg("Applying LDAP updates")
    ds.apply_updates()

    otpd = otpdinstance.OtpdInstance()
    otpd.create_instance('OTPD', config.host_name, config.dirman_password,
                         ipautil.realm_to_suffix(config.realm_name))

    if config.setup_ca:
        options.realm_name = config.realm_name
        options.domain_name = config.domain_name
        options.host_name = config.host_name
        options.dm_password = config.dirman_password
        ca_data = (os.path.join(config.dir, 'cacert.p12'),
                   config.dirman_password)
        custodia.get_ca_keys(config.ca_host_name, ca_data[0], ca_data[1])

        ca = cainstance.CAInstance(config.realm_name, certs.NSS_DIR,
                                   host_name=config.host_name,
                                   dm_password=config.dirman_password)
        ca.configure_replica(config.ca_host_name,
                             subject_base=config.subject_base,
                             ca_cert_bundle=ca_data)

    if options.setup_kra:
        ca_data = (os.path.join(config.dir, 'kracert.p12'),
                   config.dirman_password)
        custodia.get_kra_keys(config.kra_host_name, ca_data[0], ca_data[1])

        kra = krainstance.KRAInstance(config.realm_name)
        kra.configure_replica(config.host_name, config.kra_host_name,
                              config.dirman_password,
                              kra_cert_bundle=ca_data)


    ds.replica_populate()

    # update DNA shared config entry is done as far as possible
    # from restart to avoid waiting for its creation
    ds.update_dna_shared_config()

    custodia.import_dm_password(config.master_host_name)

    promote_sssd(config.host_name)
    promote_openldap_conf(config.host_name, config.master_host_name)

    # Switch API so that it uses the new servr configuration
    server_api = create_api(mode=None)
    server_api.bootstrap(in_server=True, context='installer')
    server_api.finalize()

    server_api.Backend.ldap2.connect(autobind=True)
    if options.setup_dns:
        dns.install(False, True, options, server_api)
    else:
        server_api.Command.dns_update_system_records()

    # Everything installed properly, activate ipa service.
    services.knownservices.ipa.enable()


class Replica(BaseServer):
    replica_file = Knob(
        str, None,
        description="a file generated by ipa-replica-prepare",
    )

    setup_ca = Knob(BaseServer.setup_ca)
    setup_kra = Knob(BaseServer.setup_kra)
    setup_dns = Knob(BaseServer.setup_dns)

    ip_addresses = Knob(
        BaseServer.ip_addresses,
        description=("Replica server IP Address. This option can be used "
                     "multiple times"),
    )

    dm_password = None

    password = Knob(
        BaseServer.dm_password,
        description=("Password to join the IPA realm. Assumes bulk password "
                     "unless principal is also set. (domain level 1+)\n"
                     "Directory Manager (existing master) password. "
                     "(domain level 0)"),
    )

    admin_password = Knob(
        BaseServer.admin_password,
        description="Kerberos password for the specified admin principal",
        cli_short_name='w',
    )

    server = Knob(
        str, None,
        description="fully qualified name of IPA server to enroll to",
    )

    mkhomedir = Knob(BaseServer.mkhomedir)
    no_host_dns = Knob(BaseServer.no_host_dns)
    no_ntp = Knob(BaseServer.no_ntp)
    no_pkinit = Knob(BaseServer.no_pkinit)
    no_ui_redirect = Knob(BaseServer.no_ui_redirect)
    ssh_trust_dns = Knob(BaseServer.ssh_trust_dns)
    no_ssh = Knob(BaseServer.no_ssh)
    no_sshd = Knob(BaseServer.no_sshd)
    no_dns_sshfp = Knob(BaseServer.no_dns_sshfp)

    skip_conncheck = Knob(
        bool, False,
        description="skip connection check to remote master",
    )

    principal = Knob(
        str, None,
        sensitive=True,
        description="User Principal allowed to promote replicas "
                    "and join IPA realm",
        cli_short_name='P',
    )

    keytab = Knob(
        str, None,
        description="path to backed up keytab from previous enrollment",
        cli_short_name='k',
    )

    promote = False

    # ca
    external_ca = None
    external_ca_type = None
    external_cert_files = None
    ca_cert_files = None
    subject = None
    ca_signing_algorithm = None

    # dns
    dnssec_master = None
    disable_dnssec_master = None
    kasp_db_file = None
    force = None
    zonemgr = None

    def __init__(self, **kwargs):
        super(Replica, self).__init__(**kwargs)

        self._ccache = os.environ.get('KRB5CCNAME')

        self._top_dir = None
        self._config = None
        self._update_hosts_file = False
        self._dirsrv_pkcs12_file = None
        self._http_pkcs12_file = None
        self._pkinit_pkcs12_file = None
        self._dirsrv_pkcs12_info = None
        self._http_pkcs12_info = None
        self._pkinit_pkcs12_info = None

        # pylint: disable=no-member

        cert_file_req = (self.ca.dirsrv_cert_files, self.ca.http_cert_files)
        cert_file_opt = (self.ca.pkinit_cert_files,)

        if self.replica_file is None:
            self.promote = True

            if self.principal and not self.admin_password:
                self.admin_password = self.password
                self.password = None

            # If any of the PKCS#12 options are selected, all are required.
            if any(cert_file_req + cert_file_opt) and not all(cert_file_req):
                raise RuntimeError("--dirsrv-cert-file and --http-cert-file "
                                   "are required if any PKCS#12 options are "
                                   "used")

            if self.server and not self.domain_name:
                raise RuntimeError("The --server option cannot be used "
                                   "without providing domain via the --domain "
                                   "option")

        else:
            if not ipautil.file_exists(self.replica_file):
                raise RuntimeError("Replica file %s does not exist"
                                   % self.replica_file)

            if any(cert_file_req + cert_file_opt):
                raise RuntimeError("You cannot specify any of "
                                   "--dirsrv-cert-file, --http-cert-file, or "
                                   "--pkinit-cert-file together with replica "
                                   "file")

            CLIKnob = collections.namedtuple('CLIKnob', ('value', 'name'))

            conflicting_knobs = (
                CLIKnob(self.realm_name, '--realm'),
                CLIKnob(self.domain_name, '--domain'),
                CLIKnob(self.host_name, '--hostname'),
                CLIKnob(self.server, '--server'),
                CLIKnob(self.principal, '--principal'),
            )

            if any([k.value is not None for k in conflicting_knobs]):
                conflicting_knob_names = [
                    knob.name for knob in conflicting_knobs
                    if knob.value is not None
                ]

                raise RuntimeError(
                    "You cannot specify '{0}' option(s) with replica file."
                    .format(", ".join(conflicting_knob_names))
                    )

        if self.setup_dns:
            if (not self.dns.forwarders and not self.dns.no_forwarders
                and not self.dns.auto_forwarders):
                raise RuntimeError(
                    "You must specify at least one of --forwarder, "
                    "--auto-forwarders, or --no-forwarders options")

    @step()
    def main(self):
        if self.promote:
            promote_check(self)
            yield
            promote(self)
        else:
            install_check(self)
            yield
            install(self)
