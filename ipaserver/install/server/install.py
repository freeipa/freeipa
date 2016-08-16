#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

import errno
import os
import pickle
import shutil
import sys
import tempfile
import textwrap

import six

from ipalib.install import certmonger, sysrestore
from ipapython import ipautil
from ipapython.ipa_log_manager import root_logger
from ipapython.ipautil import (
    format_netloc, ipa_generate_password, run, user_input)
from ipapython.admintool import ScriptError
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipalib import api, constants, errors, x509
from ipalib.util import (
    validate_domain_name,
    network_ip_address_warning,
    broadcast_ip_address_warning,
)
import ipaclient.install.ntpconf
from ipaserver.install import (
    bindinstance, ca, certs, dns, dsinstance,
    httpinstance, installutils, kra, krbinstance,
    ntpinstance, otpdinstance, custodiainstance, replication, service,
    sysupgrade)
from ipaserver.install.installutils import (
    IPA_MODULES, BadHostError, get_fqdn, get_server_ip_address,
    is_ipa_configured, load_pkcs12, read_password, verify_fqdn,
    update_hosts_file, create_ipaapi_user)

if six.PY3:
    unicode = str

try:
    from ipaserver.install import adtrustinstance
    _server_trust_ad_installed = True
except ImportError:
    _server_trust_ad_installed = False

NoneType = type(None)

SYSRESTORE_DIR_PATH = paths.SYSRESTORE


def validate_dm_password(password):
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if any(ord(c) < 0x20 for c in password):
        raise ValueError("Password must not contain control characters")
    if any(ord(c) >= 0x7F for c in password):
        raise ValueError("Password must only contain ASCII characters")

    # Disallow characters that pkisilent doesn't process properly:
    bad_characters = '\\'
    if any(c in bad_characters for c in password):
        raise ValueError('Password must not contain these characters: %s' %
                         ', '.join('"%s"' % c for c in bad_characters))

    # TODO: Check https://fedorahosted.org/389/ticket/47849
    # Actual behavior of setup-ds.pl is that it does not accept white
    # space characters in password when called interactively but does when
    # provided such password in INF file. But it ignores leading and trailing
    # white spaces in INF file.

    # Disallow leading/trailing whaitespaces
    if password.strip() != password:
        raise ValueError('Password must not start or end with whitespace.')


def validate_admin_password(password):
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if any(ord(c) < 0x20 for c in password):
        raise ValueError("Password must not contain control characters")
    if any(ord(c) >= 0x7F for c in password):
        raise ValueError("Password must only contain ASCII characters")

    # Disallow characters that pkisilent doesn't process properly:
    bad_characters = '\\'
    if any(c in bad_characters for c in password):
        raise ValueError('Password must not contain these characters: %s' %
                         ', '.join('"%s"' % c for c in bad_characters))


def read_cache(dm_password):
    """
    Returns a dict of cached answers or empty dict if no cache file exists.
    """
    if not ipautil.file_exists(paths.ROOT_IPA_CACHE):
        return {}

    top_dir = tempfile.mkdtemp("ipa")
    fname = "%s/cache" % top_dir
    try:
        installutils.decrypt_file(paths.ROOT_IPA_CACHE,
                                  fname,
                                  dm_password,
                                  top_dir)
    except Exception as e:
        shutil.rmtree(top_dir)
        raise Exception("Decryption of answer cache in %s failed, please "
                        "check your password." % paths.ROOT_IPA_CACHE)

    try:
        with open(fname, 'rb') as f:
            try:
                optdict = pickle.load(f)
            except Exception as e:
                raise Exception("Parse error in %s: %s" %
                                (paths.ROOT_IPA_CACHE, str(e)))
    except IOError as e:
        raise Exception("Read error in %s: %s" %
                        (paths.ROOT_IPA_CACHE, str(e)))
    finally:
        shutil.rmtree(top_dir)

    # These are the only ones that may be overridden
    try:
        del optdict['external_cert_files']
    except KeyError:
        pass

    return optdict


def write_cache(options):
    """
    Takes a dict as input and writes a cached file of answers
    """
    top_dir = tempfile.mkdtemp("ipa")
    fname = "%s/cache" % top_dir
    try:
        with open(fname, 'wb') as f:
            pickle.dump(options, f)
        installutils.encrypt_file(fname,
                                  paths.ROOT_IPA_CACHE,
                                  options['dm_password'],
                                  top_dir)
    except IOError as e:
        raise Exception("Unable to cache command-line options %s" % str(e))
    finally:
        shutil.rmtree(top_dir)


def read_host_name(host_default, no_host_dns=False):
    print("Enter the fully qualified domain name of the computer")
    print("on which you're setting up server software. Using the form")
    print("<hostname>.<domainname>")
    print("Example: master.example.com.")
    print("")
    print("")
    if host_default == "":
        host_default = "master.example.com"
    host_name = user_input("Server host name", host_default, allow_empty=False)
    print("")
    verify_fqdn(host_name, no_host_dns)

    return host_name


def read_domain_name(domain_name, unattended):
    print("The domain name has been determined based on the host name.")
    print("")
    if not unattended:
        domain_name = str(user_input("Please confirm the domain name",
                                     domain_name))
        print("")
    return domain_name


def read_realm_name(domain_name, unattended):
    print("The kerberos protocol requires a Realm name to be defined.")
    print("This is typically the domain name converted to uppercase.")
    print("")

    if unattended:
        return domain_name.upper()
    realm_name = str(user_input("Please provide a realm name",
                                domain_name.upper()))
    upper_dom = realm_name.upper()
    if upper_dom != realm_name:
        print("An upper-case realm name is required.")
        if not user_input("Do you want to use " + upper_dom +
                          " as realm name?", True):
            raise ScriptError(
                "An upper-case realm name is required. Unable to continue.")
        else:
            realm_name = upper_dom
        print("")
    return realm_name


def read_dm_password():
    print("Certain directory server operations require an administrative user.")
    print("This user is referred to as the Directory Manager and has full "
          "access")
    print("to the Directory for system management tasks and will be added to "
          "the")
    print("instance of directory server created for IPA.")
    print("The password must be at least 8 characters long.")
    print("")
    # TODO: provide the option of generating a random password
    dm_password = read_password("Directory Manager",
                                validator=validate_dm_password)
    return dm_password


def read_admin_password():
    print("The IPA server requires an administrative user, named 'admin'.")
    print("This user is a regular system account used for IPA server "
          "administration.")
    print("")
    # TODO: provide the option of generating a random password
    admin_password = read_password("IPA admin",
                                   validator=validate_admin_password)
    return admin_password


def check_dirsrv(unattended):
    (ds_unsecure, ds_secure) = dsinstance.check_ports()
    if not ds_unsecure or not ds_secure:
        msg = ("IPA requires ports 389 and 636 for the Directory Server.\n"
               "These are currently in use:\n")
        if not ds_unsecure:
            msg += "\t389\n"
        if not ds_secure:
            msg += "\t636\n"
        raise ScriptError(msg)


def common_cleanup(func):
    def decorated(installer):
        success = False

        try:
            func(installer)
            success = True
        except KeyboardInterrupt:
            ds = installer._ds
            print("\nCleaning up...")
            if ds:
                print("Removing configuration for %s instance" % ds.serverid)
                ds.stop()
                if ds.serverid:
                    try:
                        dsinstance.remove_ds_instance(ds.serverid)
                    except ipautil.CalledProcessError:
                        root_logger.error("Failed to remove DS instance. You "
                                          "may need to remove instance data "
                                          "manually")
            raise ScriptError()
        finally:
            if not success and installer._installation_cleanup:
                # Do a cautious clean up as we don't know what failed and
                # what is the state of the environment
                try:
                    installer._fstore.restore_file(paths.HOSTS)
                except Exception:
                    pass

    return decorated


def remove_master_from_managed_topology(api_instance, options):
    try:
        # we may force the removal
        server_del_options = dict(
            force=True,
            ignore_topology_disconnect=options.ignore_topology_disconnect,
            ignore_last_of_role=options.ignore_last_of_role
        )

        replication.run_server_del_as_cli(
            api_instance, api_instance.env.host, **server_del_options)
    except errors.ServerRemovalError as e:
        raise ScriptError(str(e))
    except Exception as e:
        # if the master was already deleted we will just get a warning
        root_logger.warning("Failed to delete master: {}".format(e))


@common_cleanup
def install_check(installer):
    options = installer
    dirsrv_pkcs12_file = installer._dirsrv_pkcs12_file
    http_pkcs12_file = installer._http_pkcs12_file
    pkinit_pkcs12_file = installer._pkinit_pkcs12_file
    dirsrv_pkcs12_info = installer._dirsrv_pkcs12_info
    http_pkcs12_info = installer._http_pkcs12_info
    pkinit_pkcs12_info = installer._pkinit_pkcs12_info
    external_cert_file = installer._external_cert_file
    external_ca_file = installer._external_ca_file
    http_ca_cert = installer._ca_cert

    if tasks.is_fips_enabled():
        raise RuntimeError(
            "Installing IPA server in FIPS mode is not supported")

    tasks.check_selinux_status()

    if options.master_password:
        msg = ("WARNING:\noption '-P/--master-password' is deprecated. "
               "KDC master password of sufficient strength is autogenerated "
               "during IPA server installation and should not be set "
               "manually.")
        print(textwrap.fill(msg, width=79, replace_whitespace=False))

    installer._installation_cleanup = True

    print("\nThe log file for this installation can be found in "
          "/var/log/ipaserver-install.log")
    if (not options.external_ca and not options.external_cert_files and
            is_ipa_configured()):
        installer._installation_cleanup = False
        raise ScriptError(
            "IPA server is already configured on this system.\n"
            "If you want to reinstall the IPA server, please uninstall "
            "it first using 'ipa-server-install --uninstall'.")

    client_fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    if client_fstore.has_files():
        installer._installation_cleanup = False
        raise ScriptError(
            "IPA client is already configured on this system.\n"
            "Please uninstall it before configuring the IPA server, "
            "using 'ipa-client-install --uninstall'")

    fstore = sysrestore.FileStore(SYSRESTORE_DIR_PATH)
    sstore = sysrestore.StateFile(SYSRESTORE_DIR_PATH)

    # This will override any settings passed in on the cmdline
    if ipautil.file_exists(paths.ROOT_IPA_CACHE):
        if options.dm_password is not None:
            dm_password = options.dm_password
        else:
            dm_password = read_password("Directory Manager", confirm=False)
        if dm_password is None:
            raise ScriptError("Directory Manager password required")
        try:
            cache_vars = read_cache(dm_password)
            options.__dict__.update(cache_vars)
            if cache_vars.get('external_ca', False):
                options.external_ca = False
                options.interactive = False
        except Exception as e:
            raise ScriptError("Cannot process the cache file: %s" % str(e))

    # We only set up the CA if the PKCS#12 options are not given.
    if options.dirsrv_cert_files:
        setup_ca = False
    else:
        setup_ca = True
    options.setup_ca = setup_ca

    if not setup_ca and options.ca_subject:
        raise ScriptError(
            "--ca-subject cannot be used with CA-less installation")
    if not setup_ca and options.subject_base:
        raise ScriptError(
            "--subject-base cannot be used with CA-less installation")

    # first instance of KRA must be installed by ipa-kra-install
    options.setup_kra = False

    print("======================================="
          "=======================================")
    print("This program will set up the FreeIPA Server.")
    print("")
    print("This includes:")
    if setup_ca:
        print("  * Configure a stand-alone CA (dogtag) for certificate "
              "management")
    if not options.no_ntp:
        print("  * Configure the Network Time Daemon (ntpd)")
    print("  * Create and configure an instance of Directory Server")
    print("  * Create and configure a Kerberos Key Distribution Center (KDC)")
    print("  * Configure Apache (httpd)")
    if options.setup_dns:
        print("  * Configure DNS (bind)")
    if not options.no_pkinit:
        print("  * Configure the KDC to enable PKINIT")
    if options.no_ntp:
        print("")
        print("Excluded by options:")
        print("  * Configure the Network Time Daemon (ntpd)")
    if installer.interactive:
        print("")
        print("To accept the default shown in brackets, press the Enter key.")
    print("")

    if not options.external_cert_files:
        # Make sure the 389-ds ports are available
        check_dirsrv(not installer.interactive)

    if not options.no_ntp:
        try:
            ipaclient.install.ntpconf.check_timedate_services()
        except ipaclient.install.ntpconf.NTPConflictingService as e:
            print(("WARNING: conflicting time&date synchronization service '%s'"
                  " will be disabled" % e.conflicting_service))
            print("in favor of ntpd")
            print("")
        except ipaclient.install.ntpconf.NTPConfigurationError:
            pass

    # Check to see if httpd is already configured to listen on 443
    if httpinstance.httpd_443_configured():
        raise ScriptError("Aborting installation")

    if not options.setup_dns and installer.interactive:
        if ipautil.user_input("Do you want to configure integrated DNS "
                              "(BIND)?", False):
            options.setup_dns = True
        print("")

    # check bind packages are installed
    if options.setup_dns:
        # Don't require an external DNS to say who we are if we are
        # setting up a local DNS server.
        options.no_host_dns = True

    # check the hostname is correctly configured, it must be as the kldap
    # utilities just use the hostname as returned by getaddrinfo to set
    # up some of the standard entries

    if options.host_name:
        host_default = options.host_name
    else:
        host_default = get_fqdn()

    try:
        if not installer.interactive or options.host_name:
            verify_fqdn(host_default, options.no_host_dns)
            host_name = host_default
        else:
            host_name = read_host_name(host_default, options.no_host_dns)
    except BadHostError as e:
        raise ScriptError(e)

    host_name = host_name.lower()
    root_logger.debug("will use host_name: %s\n" % host_name)

    if not options.domain_name:
        domain_name = read_domain_name(host_name[host_name.find(".")+1:],
                                       not installer.interactive)
        root_logger.debug("read domain_name: %s\n" % domain_name)
        try:
            validate_domain_name(domain_name)
        except ValueError as e:
            raise ScriptError("Invalid domain name: %s" % unicode(e))
    else:
        domain_name = options.domain_name

    domain_name = domain_name.lower()

    if not options.realm_name:
        realm_name = read_realm_name(domain_name, not installer.interactive)
        root_logger.debug("read realm_name: %s\n" % realm_name)
    else:
        realm_name = options.realm_name.upper()

    if not options.subject_base:
        options.subject_base = installutils.default_subject_base(realm_name)

    if not options.ca_subject:
        options.ca_subject = \
            installutils.default_ca_subject_dn(options.subject_base)

    if options.http_cert_files:
        if options.http_pin is None:
            options.http_pin = installutils.read_password(
                "Enter Apache Server private key unlock",
                confirm=False, validate=False, retry=False)
            if options.http_pin is None:
                raise ScriptError(
                    "Apache Server private key unlock password required")
        http_pkcs12_file, http_pin, http_ca_cert = load_pkcs12(
            cert_files=options.http_cert_files,
            key_password=options.http_pin,
            key_nickname=options.http_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=host_name)
        http_pkcs12_info = (http_pkcs12_file.name, http_pin)

    if options.dirsrv_cert_files:
        if options.dirsrv_pin is None:
            options.dirsrv_pin = read_password(
                "Enter Directory Server private key unlock",
                confirm=False, validate=False, retry=False)
            if options.dirsrv_pin is None:
                raise ScriptError(
                    "Directory Server private key unlock password required")
        dirsrv_pkcs12_file, dirsrv_pin, dirsrv_ca_cert = load_pkcs12(
            cert_files=options.dirsrv_cert_files,
            key_password=options.dirsrv_pin,
            key_nickname=options.dirsrv_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=host_name)
        dirsrv_pkcs12_info = (dirsrv_pkcs12_file.name, dirsrv_pin)

    if options.pkinit_cert_files:
        if not options.no_pkinit:
            raise ScriptError("Cannot create KDC PKINIT certificate and use "
                              "provided external PKINIT certificate at the "
                              "same time. Please choose one of them.")

        if options.pkinit_pin is None:
            options.pkinit_pin = read_password(
                "Enter Kerberos KDC private key unlock",
                confirm=False, validate=False, retry=False)
            if options.pkinit_pin is None:
                raise ScriptError(
                    "Kerberos KDC private key unlock password required")
        pkinit_pkcs12_file, pkinit_pin, _pkinit_ca_cert = load_pkcs12(
            cert_files=options.pkinit_cert_files,
            key_password=options.pkinit_pin,
            key_nickname=options.pkinit_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=host_name)
        pkinit_pkcs12_info = (pkinit_pkcs12_file.name, pkinit_pin)

    if (options.http_cert_files and options.dirsrv_cert_files and
            http_ca_cert != dirsrv_ca_cert):
        raise ScriptError(
            "Apache Server SSL certificate and Directory Server SSL "
            "certificate are not signed by the same CA certificate")

    if not options.dm_password:
        dm_password = read_dm_password()

        if dm_password is None:
            raise ScriptError("Directory Manager password required")
    else:
        dm_password = options.dm_password

    if not options.master_password:
        master_password = ipa_generate_password()
    else:
        master_password = options.master_password

    if not options.admin_password:
        admin_password = read_admin_password()
        if admin_password is None:
            raise ScriptError("IPA admin password required")
    else:
        admin_password = options.admin_password

    # Configuration for ipalib, we will bootstrap and finalize later, after
    # we are sure we have the configuration file ready.
    cfg = dict(
        context='installer',
        confdir=paths.ETC_IPA,
        in_server=True,
        # make sure host name specified by user is used instead of default
        host=host_name,
    )
    if setup_ca:
        # we have an IPA-integrated CA
        cfg['ca_host'] = host_name

    # Create the management framework config file and finalize api
    target_fname = paths.IPA_DEFAULT_CONF
    fd = open(target_fname, "w")
    fd.write("[global]\n")
    fd.write("host=%s\n" % host_name)
    fd.write("basedn=%s\n" % ipautil.realm_to_suffix(realm_name))
    fd.write("realm=%s\n" % realm_name)
    fd.write("domain=%s\n" % domain_name)
    fd.write("xmlrpc_uri=https://%s/ipa/xml\n" % format_netloc(host_name))
    fd.write("ldap_uri=ldapi://%%2fvar%%2frun%%2fslapd-%s.socket\n" %
             installutils.realm_to_serverid(realm_name))
    if setup_ca:
        fd.write("enable_ra=True\n")
        fd.write("ra_plugin=dogtag\n")
        fd.write("dogtag_version=10\n")
    else:
        fd.write("enable_ra=False\n")
        fd.write("ra_plugin=none\n")
    fd.write("mode=production\n")
    fd.close()

    # Must be readable for everyone
    os.chmod(target_fname, 0o644)

    api.bootstrap(**cfg)
    api.finalize()

    if setup_ca:
        ca.install_check(False, None, options)
        kra.install_check(api, None, options)

    if options.setup_dns:
        dns.install_check(False, api, False, options, host_name)
        ip_addresses = dns.ip_addresses
    else:
        ip_addresses = get_server_ip_address(host_name,
                                             not installer.interactive, False,
                                             options.ip_addresses)

        # check addresses here, dns module is doing own check
        network_ip_address_warning(ip_addresses)
        broadcast_ip_address_warning(ip_addresses)

    # installer needs to update hosts file when DNS subsystem will be
    # installed or custom addresses are used
    if options.ip_addresses or options.setup_dns:
        installer._update_hosts_file = True

    print()
    print("The IPA Master Server will be configured with:")
    print("Hostname:       %s" % host_name)
    print("IP address(es): %s" % ", ".join(str(ip) for ip in ip_addresses))
    print("Domain name:    %s" % domain_name)
    print("Realm name:     %s" % realm_name)
    print()

    if options.setup_dns:
        print("BIND DNS server will be configured to serve IPA domain with:")
        print("Forwarders:       %s" % (
            "No forwarders" if not options.forwarders
            else ", ".join([str(ip) for ip in options.forwarders])
        ))
        print('Forward policy:   %s' % options.forward_policy)
        print("Reverse zone(s):  %s" % (
            "No reverse zone" if options.no_reverse or not dns.reverse_zones
            else ", ".join(str(rz) for rz in dns.reverse_zones)
        ))
        print()

    # If domain name and realm does not match, IPA server will not be able
    # to estabilish trust with Active Directory. Print big fat warning.

    realm_not_matching_domain = (domain_name.upper() != realm_name)

    if realm_not_matching_domain:
        print("WARNING: Realm name does not match the domain name.\n"
              "You will not be able to estabilish trusts with Active "
              "Directory unless\nthe realm name of the IPA server matches "
              "its domain name.\n\n")

    if installer.interactive and not user_input(
            "Continue to configure the system with these values?", False):
        raise ScriptError("Installation aborted")

    options.realm_name = realm_name
    options.domain_name = domain_name
    options.dm_password = dm_password
    options.master_password = master_password
    options.admin_password = admin_password
    options._host_name_overridden = bool(options.host_name)
    options.host_name = host_name
    options.ip_addresses = ip_addresses

    installer._fstore = fstore
    installer._sstore = sstore
    installer._dirsrv_pkcs12_file = dirsrv_pkcs12_file
    installer._http_pkcs12_file = http_pkcs12_file
    installer._pkinit_pkcs12_file = pkinit_pkcs12_file
    installer._dirsrv_pkcs12_info = dirsrv_pkcs12_info
    installer._http_pkcs12_info = http_pkcs12_info
    installer._pkinit_pkcs12_info = pkinit_pkcs12_info
    installer._external_cert_file = external_cert_file
    installer._external_ca_file = external_ca_file
    installer._ca_cert = http_ca_cert


@common_cleanup
def install(installer):
    options = installer
    fstore = installer._fstore
    sstore = installer._sstore
    dirsrv_pkcs12_info = installer._dirsrv_pkcs12_info
    http_pkcs12_info = installer._http_pkcs12_info
    pkinit_pkcs12_info = installer._pkinit_pkcs12_info
    http_ca_cert = installer._ca_cert

    realm_name = options.realm_name
    domain_name = options.domain_name
    dm_password = options.dm_password
    master_password = options.master_password
    admin_password = options.admin_password
    host_name = options.host_name
    ip_addresses = options.ip_addresses
    setup_ca = options.setup_ca

    # Installation has started. No IPA sysrestore items are restored in case of
    # failure to enable root cause investigation
    installer._installation_cleanup = False

    if installer.interactive:
        print("")
        print("The following operations may take some minutes to complete.")
        print("Please wait until the prompt is returned.")
        print("")

    # set hostname (transient and static) if user instructed us to do so
    if options._host_name_overridden:
        tasks.backup_hostname(fstore, sstore)
        tasks.set_hostname(host_name)

    if installer._update_hosts_file:
        update_hosts_file(ip_addresses, host_name, fstore)

    # Make sure tmpfiles dir exist before installing components
    create_ipaapi_user()
    tasks.create_tmpfiles_dirs()

    # create NSS Databases
    http_instance = httpinstance.HTTPInstance()
    http_instance.create_cert_dbs()

    # Create DS user/group if it doesn't exist yet
    dsinstance.create_ds_user()

    # Create a directory server instance
    if not options.external_cert_files:
        # Configure ntpd
        if not options.no_ntp:
            ipaclient.install.ntpconf.force_ntpd(sstore)
            ntp = ntpinstance.NTPInstance(fstore)
            if not ntp.is_configured():
                ntp.create_instance()

        if options.dirsrv_cert_files:
            ds = dsinstance.DsInstance(fstore=fstore,
                                       domainlevel=options.domainlevel,
                                       config_ldif=options.dirsrv_config_file)
            installer._ds = ds
            ds.create_instance(realm_name, host_name, domain_name,
                               dm_password, dirsrv_pkcs12_info,
                               idstart=options.idstart, idmax=options.idmax,
                               subject_base=options.subject_base,
                               ca_subject=options.ca_subject,
                               hbac_allow=not options.no_hbac_allow)
        else:
            ds = dsinstance.DsInstance(fstore=fstore,
                                       domainlevel=options.domainlevel,
                                       config_ldif=options.dirsrv_config_file)
            installer._ds = ds
            ds.create_instance(realm_name, host_name, domain_name,
                               dm_password,
                               idstart=options.idstart, idmax=options.idmax,
                               subject_base=options.subject_base,
                               ca_subject=options.ca_subject,
                               hbac_allow=not options.no_hbac_allow)

        ntpinstance.ntp_ldap_enable(host_name, ds.suffix, realm_name)

    else:
        api.Backend.ldap2.connect()
        ds = dsinstance.DsInstance(fstore=fstore,
                                   domainlevel=options.domainlevel)
        installer._ds = ds
        ds.init_info(
            realm_name, host_name, domain_name, dm_password,
            options.subject_base, options.ca_subject, 1101, 1100, None)

    if setup_ca:
        if not options.external_cert_files and options.external_ca:
            # stage 1 of external CA installation
            options.realm_name = realm_name
            options.domain_name = domain_name
            options.master_password = master_password
            options.dm_password = dm_password
            options.admin_password = admin_password
            options.host_name = host_name
            options.reverse_zones = dns.reverse_zones
            cache_vars = {n: options.__dict__[n] for o, n in installer.knobs()
                          if n in options.__dict__}
            write_cache(cache_vars)

        ca.install_step_0(False, None, options)

        # Now put the CA cert where other instances exepct it
        ca_db = certs.CertDB(realm_name)
        ca_db.publish_ca_cert(paths.IPA_CA_CRT)
    else:
        # Put the CA cert where other instances expect it
        x509.write_certificate(http_ca_cert, paths.IPA_CA_CRT)
        os.chmod(paths.IPA_CA_CRT, 0o444)

    # we now need to enable ssl on the ds
    ds.enable_ssl()

    krb = krbinstance.KrbInstance(fstore)
    krb.create_instance(realm_name, host_name, domain_name,
                        dm_password, master_password,
                        setup_pkinit=not options.no_pkinit,
                        pkcs12_info=pkinit_pkcs12_info,
                        subject_base=options.subject_base)

    # restart DS to enable ipa-pwd-extop plugin
    print("Restarting directory server to enable password extension plugin")
    ds.restart()

    if setup_ca:
        ca.install_step_1(False, None, options)
        kra.install(api, None, options)

    # The DS instance is created before the keytab, add the SSL cert we
    # generated
    ds.add_cert_to_service()

    otpd = otpdinstance.OtpdInstance()
    otpd.create_instance('OTPD', host_name,
                         ipautil.realm_to_suffix(realm_name))

    custodia = custodiainstance.CustodiaInstance(host_name, realm_name)
    custodia.create_instance()

    # Create a HTTP instance
    http = httpinstance.HTTPInstance(fstore)
    if options.http_cert_files:
        http.create_instance(
            realm_name, host_name, domain_name,
            pkcs12_info=http_pkcs12_info, subject_base=options.subject_base,
            auto_redirect=not options.no_ui_redirect,
            ca_is_configured=setup_ca)
    else:
        http.create_instance(
            realm_name, host_name, domain_name,
            subject_base=options.subject_base,
            auto_redirect=not options.no_ui_redirect,
            ca_is_configured=setup_ca)
    tasks.restore_context(paths.CACHE_IPA_SESSIONS)

    ca.set_subject_base_in_config(options.subject_base)

    # Apply any LDAP updates. Needs to be done after the configuration file
    # is created. DS is restarted in the process.
    service.print_msg("Applying LDAP updates")
    ds.apply_updates()

    # Restart krb after configurations have been changed
    service.print_msg("Restarting the KDC")
    krb.restart()

    if options.setup_dns:
        dns.install(False, False, options)
    else:
        # Create a BIND instance
        bind = bindinstance.BindInstance(fstore)
        bind.setup(host_name, ip_addresses, realm_name,
                   domain_name, (), 'first', (),
                   zonemgr=options.zonemgr,
                   no_dnssec_validation=options.no_dnssec_validation)
        bind.create_file_with_system_records()

    # Set the admin user kerberos password
    ds.change_admin_password(admin_password)

    # Call client install script
    service.print_msg("Configuring client side components")
    try:
        args = [paths.IPA_CLIENT_INSTALL, "--on-master", "--unattended",
                "--domain", domain_name, "--server", host_name,
                "--realm", realm_name, "--hostname", host_name]
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
        run(args, redirect_output=True)
        print()
    except Exception:
        raise ScriptError("Configuration of client side components failed!")

    # Make sure the files we crated in /var/run are recreated at startup
    tasks.configure_tmpfiles()

    # Everything installed properly, activate ipa service.
    services.knownservices.ipa.enable()

    print("======================================="
          "=======================================")
    print("Setup complete")
    print("")
    print("Next steps:")
    print("\t1. You must make sure these network ports are open:")
    print("\t\tTCP Ports:")
    print("\t\t  * 80, 443: HTTP/HTTPS")
    print("\t\t  * 389, 636: LDAP/LDAPS")
    print("\t\t  * 88, 464: kerberos")
    if options.setup_dns:
        print("\t\t  * 53: bind")
    print("\t\tUDP Ports:")
    print("\t\t  * 88, 464: kerberos")
    if options.setup_dns:
        print("\t\t  * 53: bind")
    if not options.no_ntp:
        print("\t\t  * 123: ntp")
    print("")
    print("\t2. You can now obtain a kerberos ticket using the command: "
          "'kinit admin'")
    print("\t   This ticket will allow you to use the IPA tools (e.g., ipa "
          "user-add)")
    print("\t   and the web user interface.")

    if not services.knownservices.ntpd.is_running():
        print("\t3. Kerberos requires time synchronization between clients")
        print("\t   and servers for correct operation. You should consider "
              "enabling ntpd.")

    print("")
    if setup_ca:
        print(("Be sure to back up the CA certificates stored in " +
              paths.CACERT_P12))
        print("These files are required to create replicas. The password for "
              "these")
        print("files is the Directory Manager password")
    else:
        print("In order for Firefox autoconfiguration to work you will need to")
        print("use a SSL signing certificate. See the IPA documentation for "
              "more details.")

    if ipautil.file_exists(paths.ROOT_IPA_CACHE):
        os.remove(paths.ROOT_IPA_CACHE)


@common_cleanup
def uninstall_check(installer):
    options = installer

    tasks.check_selinux_status()

    installer._installation_cleanup = False

    if not is_ipa_configured():
        print("WARNING:\nIPA server is not configured on this system. "
              "If you want to install the\nIPA server, please install "
              "it using 'ipa-server-install'.")

    fstore = sysrestore.FileStore(SYSRESTORE_DIR_PATH)
    sstore = sysrestore.StateFile(SYSRESTORE_DIR_PATH)

    # Configuration for ipalib, we will bootstrap and finalize later, after
    # we are sure we have the configuration file ready.
    cfg = dict(
        context='installer',
        confdir=paths.ETC_IPA,
        in_server=True,
    )

    # We will need at least api.env, finalize api now. This system is
    # already installed, so the configuration file is there.
    api.bootstrap(**cfg)
    api.finalize()

    if installer.interactive:
        print("\nThis is a NON REVERSIBLE operation and will delete all data "
              "and configuration!\nIt is highly recommended to take a backup of "
              "existing data and configuration using ipa-backup utility "
              "before proceeding.\n")
        if not user_input("Are you sure you want to continue with the "
                          "uninstall procedure?", False):
            raise ScriptError("Aborting uninstall operation.")

    try:
        api.Backend.ldap2.connect(autobind=True)

        domain_level = dsinstance.get_domain_level(api)
    except Exception:
        msg = ("\nWARNING: Failed to connect to Directory Server to find "
               "information about replication agreements. Uninstallation "
               "will continue despite the possible existing replication "
               "agreements.\n\n"
               "If this server is the last instance of CA, KRA, or DNSSEC "
               "master, uninstallation may result in data loss.\n\n"
        )
        print(textwrap.fill(msg, width=80, replace_whitespace=False))

        if (installer.interactive and not user_input(
                "Are you sure you want to continue with the uninstall "
                "procedure?", False)):
            raise ScriptError("Aborting uninstall operation.")
    else:
        dns.uninstall_check(options)

        if domain_level == constants.DOMAIN_LEVEL_0:
            rm = replication.ReplicationManager(
                realm=api.env.realm,
                hostname=api.env.host,
                dirman_passwd=None,
                conn=api.Backend.ldap2
            )
            agreements = rm.find_ipa_replication_agreements()

            if agreements:
                other_masters = [a.get('cn')[0][4:] for a in agreements]
                msg = (
                    "\nReplication agreements with the following IPA masters "
                    "found: %s. Removing any replication agreements before "
                    "uninstalling the server is strongly recommended. You can "
                    "remove replication agreements by running the following "
                    "command on any other IPA master:\n" % ", ".join(
                        other_masters)
                )
                cmd = "$ ipa-replica-manage del %s\n" % api.env.host
                print(textwrap.fill(msg, width=80, replace_whitespace=False))
                print(cmd)
                if (installer.interactive and
                        not user_input("Are you sure you want to continue with"
                                       " the uninstall procedure?", False)):
                    raise ScriptError("Aborting uninstall operation.")
        else:
            remove_master_from_managed_topology(api, options)

        api.Backend.ldap2.disconnect()

    installer._fstore = fstore
    installer._sstore = sstore


@common_cleanup
def uninstall(installer):
    fstore = installer._fstore
    sstore = installer._sstore

    rv = 0

    print("Shutting down all IPA services")
    try:
        run([paths.IPACTL, "stop"], raiseonerr=False)
    except Exception:
        pass

    ntpinstance.NTPInstance(fstore).uninstall()

    kra.uninstall(False)

    ca.uninstall()

    dns.uninstall()

    httpinstance.HTTPInstance(fstore).uninstall()
    krbinstance.KrbInstance(fstore).uninstall()
    dsinstance.DsInstance(fstore=fstore).uninstall()
    if _server_trust_ad_installed:
        adtrustinstance.ADTRUSTInstance(fstore).uninstall()
    custodiainstance.CustodiaInstance().uninstall()
    otpdinstance.OtpdInstance().uninstall()
    tasks.restore_hostname(fstore, sstore)
    fstore.restore_all_files()
    try:
        os.remove(paths.ROOT_IPA_CACHE)
    except Exception:
        pass
    try:
        os.remove(paths.ROOT_IPA_CSR)
    except Exception:
        pass

    # ipa-client-install removes /etc/ipa/default.conf

    sstore._load()

    ipaclient.install.ntpconf.restore_forced_ntpd(sstore)

    # Clean up group_exists (unused since IPA 2.2, not being set since 4.1)
    sstore.restore_state("install", "group_exists")

    services.knownservices.ipa.disable()

    # remove upgrade state file
    sysupgrade.remove_upgrade_file()

    if fstore.has_files():
        root_logger.error('Some files have not been restored, see '
                          '%s/sysrestore.index' % SYSRESTORE_DIR_PATH)
    has_state = False
    for module in IPA_MODULES:  # from installutils
        if sstore.has_state(module):
            root_logger.error('Some installation state for %s has not been '
                              'restored, see %s/sysrestore.state' %
                              (module, SYSRESTORE_DIR_PATH))
            has_state = True
            rv = 1

    if has_state:
        root_logger.error('Some installation state has not been restored.\n'
                          'This may cause re-installation to fail.\n'
                          'It should be safe to remove %s/sysrestore.state '
                          'but it may\n'
                          'mean your system hasn\'t be restored to its '
                          'pre-installation state.' % SYSRESTORE_DIR_PATH)

    # Note that this name will be wrong after the first uninstall.
    dirname = dsinstance.config_dirname(
        installutils.realm_to_serverid(api.env.realm))
    dirs = [dirname, paths.PKI_TOMCAT_ALIAS_DIR, paths.HTTPD_ALIAS_DIR,
            paths.IPA_RADB_DIR]
    ids = certmonger.check_state(dirs)
    if ids:
        root_logger.error('Some certificates may still be tracked by '
                          'certmonger.\n'
                          'This will cause re-installation to fail.\n'
                          'Start the certmonger service and list the '
                          'certificates being tracked\n'
                          ' # getcert list\n'
                          'These may be untracked by executing\n'
                          ' # getcert stop-tracking -i <request_id>\n'
                          'for each id in: %s' % ', '.join(ids))

    # Remove the cert renewal lock file
    try:
        os.remove(paths.IPA_RENEWAL_LOCK)
    except OSError as e:
        if e.errno != errno.ENOENT:
            root_logger.warning("Failed to remove file %s: %s",
                                paths.IPA_RENEWAL_LOCK, e)

    print("Removing IPA client configuration")
    try:
        result = run([paths.IPA_CLIENT_INSTALL, "--on-master",
                      "--unattended", "--uninstall"],
                     raiseonerr=False, redirect_output=True)
        if result.returncode not in [0, 2]:
            raise RuntimeError("Failed to configure the client")
    except Exception:
        rv = 1
        print("Uninstall of client side components failed!")

    sys.exit(rv)


def init(installer):
    installer.unattended = not installer.interactive

    installer.domainlevel = installer.domain_level

    installer._installation_cleanup = True
    installer._ds = None

    installer._dirsrv_pkcs12_file = None
    installer._http_pkcs12_file = None
    installer._pkinit_pkcs12_file = None
    installer._dirsrv_pkcs12_info = None
    installer._http_pkcs12_info = None
    installer._pkinit_pkcs12_info = None
    installer._external_cert_file = None
    installer._external_ca_file = None
    installer._ca_cert = None
    installer._update_hosts_file = False
