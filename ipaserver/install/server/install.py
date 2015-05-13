#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import os
import pickle
import pwd
import random
import shutil
import sys
import tempfile
import textwrap

from ipapython import certmonger, dogtag, ipaldap, ipautil, sysrestore
from ipapython.dn import DN
from ipapython.install import common, core
from ipapython.install.common import step
from ipapython.install.core import Knob
from ipapython.ipa_log_manager import root_logger
from ipapython.ipautil import (
    decrypt_file, format_netloc, ipa_generate_password, run, user_input)
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipalib import api, constants, errors, x509
from ipalib.constants import CACERT
from ipalib.util import validate_domain_name
import ipaclient.ntpconf
from ipaserver.install import (
    bindinstance, ca, cainstance, certs, dns, dsinstance, httpinstance,
    installutils, kra, krbinstance, memcacheinstance, ntpinstance,
    otpdinstance, replication, service, sysupgrade)
from ipaserver.install.installutils import (
    IPA_MODULES, BadHostError, get_fqdn, get_server_ip_address,
    is_ipa_configured, load_pkcs12, read_password, verify_fqdn)
from ipaserver.plugins.ldap2 import ldap2
try:
    from ipaserver.install import adtrustinstance
    _server_trust_ad_installed = True
except ImportError:
    _server_trust_ad_installed = False

SYSRESTORE_DIR_PATH = paths.SYSRESTORE

VALID_SUBJECT_ATTRS = ['st', 'o', 'ou', 'dnqualifier', 'c',
                       'serialnumber', 'l', 'title', 'sn', 'givenname',
                       'initials', 'generationqualifier', 'dc', 'mail',
                       'uid', 'postaladdress', 'postalcode', 'postofficebox',
                       'houseidentifier', 'e', 'street', 'pseudonym',
                       'incorporationlocality', 'incorporationstate',
                       'incorporationcountry', 'businesscategory']


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
        decrypt_file(paths.ROOT_IPA_CACHE, fname, dm_password, top_dir)
    except Exception, e:
        shutil.rmtree(top_dir)
        raise Exception("Decryption of answer cache in %s failed, please "
                        "check your password." % paths.ROOT_IPA_CACHE)

    try:
        with open(fname, 'rb') as f:
            try:
                optdict = pickle.load(f)
            except Exception, e:
                raise Exception("Parse error in %s: %s" %
                                (paths.ROOT_IPA_CACHE, str(e)))
    except IOError, e:
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
        ipautil.encrypt_file(fname, paths.ROOT_IPA_CACHE,
                             options['dm_password'], top_dir)
    except IOError, e:
        raise Exception("Unable to cache command-line options %s" % str(e))
    finally:
        shutil.rmtree(top_dir)


def read_host_name(host_default, no_host_dns=False):
    host_name = ""

    print "Enter the fully qualified domain name of the computer"
    print "on which you're setting up server software. Using the form"
    print "<hostname>.<domainname>"
    print "Example: master.example.com."
    print ""
    print ""
    if host_default == "":
        host_default = "master.example.com"
    host_name = user_input("Server host name", host_default, allow_empty=False)
    print ""
    verify_fqdn(host_name, no_host_dns)

    return host_name


def read_domain_name(domain_name, unattended):
    print "The domain name has been determined based on the host name."
    print ""
    if not unattended:
        domain_name = str(user_input("Please confirm the domain name",
                                     domain_name))
        print ""
    return domain_name


def read_realm_name(domain_name, unattended):
    print "The kerberos protocol requires a Realm name to be defined."
    print "This is typically the domain name converted to uppercase."
    print ""

    if unattended:
        return domain_name.upper()
    realm_name = str(user_input("Please provide a realm name",
                                domain_name.upper()))
    upper_dom = realm_name.upper()
    if upper_dom != realm_name:
        print "An upper-case realm name is required."
        if not user_input("Do you want to use " + upper_dom +
                          " as realm name?", True):
            print ""
            print "An upper-case realm name is required. Unable to continue."
            sys.exit(1)
        else:
            realm_name = upper_dom
        print ""
    return realm_name


def read_dm_password():
    print "Certain directory server operations require an administrative user."
    print("This user is referred to as the Directory Manager and has full "
          "access")
    print("to the Directory for system management tasks and will be added to "
          "the")
    print "instance of directory server created for IPA."
    print "The password must be at least 8 characters long."
    print ""
    # TODO: provide the option of generating a random password
    dm_password = read_password("Directory Manager",
                                validator=validate_dm_password)
    return dm_password


def read_admin_password():
    print "The IPA server requires an administrative user, named 'admin'."
    print("This user is a regular system account used for IPA server "
          "administration.")
    print ""
    # TODO: provide the option of generating a random password
    admin_password = read_password("IPA admin",
                                   validator=validate_admin_password)
    return admin_password


def check_dirsrv(unattended):
    (ds_unsecure, ds_secure) = dsinstance.check_ports()
    if not ds_unsecure or not ds_secure:
        print "IPA requires ports 389 and 636 for the Directory Server."
        print "These are currently in use:"
        if not ds_unsecure:
            print "\t389"
        if not ds_secure:
            print "\t636"
        sys.exit(1)


def set_subject_in_config(realm_name, dm_password, suffix, subject_base):
        ldapuri = 'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % (
            installutils.realm_to_serverid(realm_name)
        )
        try:
            conn = ldap2(api, ldap_uri=ldapuri)
            conn.connect(bind_dn=DN(('cn', 'directory manager')),
                         bind_pw=dm_password)
        except errors.ExecutionError, e:
            root_logger.critical("Could not connect to the Directory Server "
                                 "on %s" % realm_name)
            raise e
        entry_attrs = conn.get_ipa_config()
        if 'ipacertificatesubjectbase' not in entry_attrs:
            entry_attrs['ipacertificatesubjectbase'] = [str(subject_base)]
            conn.update_entry(entry_attrs)
        conn.disconnect()


def common_cleanup(func):
    def decorated(installer):
        success = False

        try:
            func(installer)
            success = True
        except KeyboardInterrupt:
            ds = installer._ds
            print "\nCleaning up..."
            if ds:
                print "Removing configuration for %s instance" % ds.serverid
                ds.stop()
                if ds.serverid:
                    try:
                        dsinstance.remove_ds_instance(ds.serverid)
                    except ipautil.CalledProcessError:
                        root_logger.error("Failed to remove DS instance. You "
                                          "may need to remove instance data "
                                          "manually")
            sys.exit(1)
        finally:
            if not success and installer._installation_cleanup:
                # Do a cautious clean up as we don't know what failed and
                # what is the state of the environment
                try:
                    installer._fstore.restore_file(paths.HOSTS)
                except:
                    pass

    return decorated


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

    dogtag_constants = dogtag.install_constants

    tasks.check_selinux_status()

    if options.master_password:
        msg = ("WARNING:\noption '-P/--master-password' is deprecated. "
               "KDC master password of sufficient strength is autogenerated "
               "during IPA server installation and should not be set "
               "manually.")
        print textwrap.fill(msg, width=79, replace_whitespace=False)

    installer._installation_cleanup = True

    print("\nThe log file for this installation can be found in "
          "/var/log/ipaserver-install.log")
    if (not options.external_ca and not options.external_cert_files and
            is_ipa_configured()):
        installer._installation_cleanup = False
        sys.exit("IPA server is already configured on this system.\n"
                 "If you want to reinstall the IPA server, please uninstall "
                 "it first using 'ipa-server-install --uninstall'.")

    client_fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    if client_fstore.has_files():
        installer._installation_cleanup = False
        sys.exit("IPA client is already configured on this system.\n"
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
            sys.exit("Directory Manager password required")
        try:
            cache_vars = read_cache(dm_password)
            for name, value in cache_vars.iteritems():
                if name not in options.__dict__:
                    options.__dict__[name] = value
            if cache_vars.get('external_ca', False):
                options.external_ca = False
                options.interactive = False
        except Exception, e:
            sys.exit("Cannot process the cache file: %s" % str(e))

    # We only set up the CA if the PKCS#12 options are not given.
    if options.dirsrv_cert_files:
        setup_ca = False
        setup_kra = False
    else:
        setup_ca = True
        # setup_kra is set to False until Dogtag 10.2 is available for IPA to
        # consume. Until then users that want to install the KRA need to use
        # ipa-install-kra
        # TODO set setup_kra = True when Dogtag 10.2 is available
        setup_kra = False
    options.setup_ca = setup_ca
    options.setup_kra = setup_kra

    print("======================================="
          "=======================================")
    print "This program will set up the FreeIPA Server."
    print ""
    print "This includes:"
    if setup_ca:
        print("  * Configure a stand-alone CA (dogtag) for certificate "
              "management")
    if setup_kra:
        print "  * Configure a stand-alone KRA (dogtag) for key storage"
    if not options.no_ntp:
        print "  * Configure the Network Time Daemon (ntpd)"
    print "  * Create and configure an instance of Directory Server"
    print "  * Create and configure a Kerberos Key Distribution Center (KDC)"
    print "  * Configure Apache (httpd)"
    if options.setup_dns:
        print "  * Configure DNS (bind)"
    if not options.no_pkinit:
        print "  * Configure the KDC to enable PKINIT"
    if options.no_ntp:
        print ""
        print "Excluded by options:"
        print "  * Configure the Network Time Daemon (ntpd)"
    if installer.interactive:
        print ""
        print "To accept the default shown in brackets, press the Enter key."
    print ""

    if not options.external_cert_files:
        # Make sure the 389-ds ports are available
        check_dirsrv(not installer.interactive)

    if not options.no_ntp:
        try:
            ipaclient.ntpconf.check_timedate_services()
        except ipaclient.ntpconf.NTPConflictingService, e:
            print("WARNING: conflicting time&date synchronization service '%s'"
                  " will be disabled" % e.conflicting_service)
            print "in favor of ntpd"
            print ""
        except ipaclient.ntpconf.NTPConfigurationError:
            pass

    # Check to see if httpd is already configured to listen on 443
    if httpinstance.httpd_443_configured():
        sys.exit("Aborting installation")

    if not options.setup_dns and installer.interactive:
        if ipautil.user_input("Do you want to configure integrated DNS "
                              "(BIND)?", False):
            options.setup_dns = True
        print ""

    # check bind packages are installed
    if options.setup_dns:
        # Don't require an external DNS to say who we are if we are
        # setting up a local DNS server.
        options.no_host_dns = True

    # check the hostname is correctly configured, it must be as the kldap
    # utilities just use the hostname as returned by getaddrinfo to set
    # up some of the standard entries

    host_default = ""
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
    except BadHostError, e:
        sys.exit(str(e) + "\n")

    host_name = host_name.lower()
    root_logger.debug("will use host_name: %s\n" % host_name)

    system_hostname = get_fqdn()
    if host_name != system_hostname:
        print >>sys.stderr
        print >>sys.stderr, ("Warning: hostname %s does not match system "
                             "hostname %s." % (host_name, system_hostname))
        print >>sys.stderr, ("System hostname will be updated during the "
                             "installation process")
        print >>sys.stderr, "to prevent service failures."
        print >>sys.stderr

    if not options.domain_name:
        domain_name = read_domain_name(host_name[host_name.find(".")+1:],
                                       not installer.interactive)
        root_logger.debug("read domain_name: %s\n" % domain_name)
        try:
            validate_domain_name(domain_name)
        except ValueError, e:
            sys.exit("Invalid domain name: %s" % unicode(e))
    else:
        domain_name = options.domain_name

    domain_name = domain_name.lower()

    if not options.realm_name:
        realm_name = read_realm_name(domain_name, not installer.interactive)
        root_logger.debug("read realm_name: %s\n" % realm_name)
    else:
        realm_name = options.realm_name.upper()

    if not options.subject:
        options.subject = DN(('O', realm_name))

    if options.http_cert_files:
        if options.http_pin is None:
            options.http_pin = installutils.read_password(
                "Enter Apache Server private key unlock",
                confirm=False, validate=False)
            if options.http_pin is None:
                sys.exit(
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
                confirm=False, validate=False)
            if options.dirsrv_pin is None:
                sys.exit(
                    "Directory Server private key unlock password required")
        dirsrv_pkcs12_file, dirsrv_pin, dirsrv_ca_cert = load_pkcs12(
            cert_files=options.dirsrv_cert_files,
            key_password=options.dirsrv_pin,
            key_nickname=options.dirsrv_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=host_name)
        dirsrv_pkcs12_info = (dirsrv_pkcs12_file.name, dirsrv_pin)

    if options.pkinit_cert_files:
        if options.pkinit_pin is None:
            options.pkinit_pin = read_password(
                "Enter Kerberos KDC private key unlock",
                confirm=False, validate=False)
            if options.pkinit_pin is None:
                sys.exit(
                    "Kerberos KDC private key unlock password required")
        pkinit_pkcs12_file, pkinit_pin, pkinit_ca_cert = load_pkcs12(
            cert_files=options.pkinit_cert_files,
            key_password=options.pkinit_pin,
            key_nickname=options.pkinit_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=host_name)
        pkinit_pkcs12_info = (pkinit_pkcs12_file.name, pkinit_pin)

    if (options.http_cert_files and options.dirsrv_cert_files and
            http_ca_cert != dirsrv_ca_cert):
        sys.exit("Apache Server SSL certificate and Directory Server SSL "
                 "certificate are not signed by the same CA certificate")

    if not options.dm_password:
        dm_password = read_dm_password()

        if dm_password is None:
            sys.exit("Directory Manager password required")
    else:
        dm_password = options.dm_password

    if not options.master_password:
        master_password = ipa_generate_password()
    else:
        master_password = options.master_password

    if not options.admin_password:
        admin_password = read_admin_password()
        if admin_password is None:
            sys.exit("IPA admin password required")
    else:
        admin_password = options.admin_password

    # Configuration for ipalib, we will bootstrap and finalize later, after
    # we are sure we have the configuration file ready.
    cfg = dict(
        context='installer',
        in_server=True,
    )

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
        fd.write("dogtag_version=%s\n" % dogtag_constants.DOGTAG_VERSION)
    else:
        fd.write("enable_ra=False\n")
        fd.write("ra_plugin=none\n")
    fd.write("mode=production\n")
    fd.close()

    # Must be readable for everyone
    os.chmod(target_fname, 0644)

    system_hostname = get_fqdn()
    if host_name != system_hostname:
        root_logger.debug("Chosen hostname (%s) differs from system hostname "
                          "(%s) - change it" % (host_name, system_hostname))
        # update `api.env.ca_host` to correct hostname
        # https://fedorahosted.org/freeipa/ticket/4936
        api.env.ca_host = host_name

    api.bootstrap(**cfg)
    api.finalize()

    if setup_ca:
        ca.install_check(False, None, options)

    if setup_kra:
        try:
            kra.install_check(api, None, options)
        except RuntimeError as e:
            print str(e)
            sys.exit(1)

    if options.setup_dns:
        dns.install_check(False, False, options, host_name)
        ip_addresses = dns.ip_addresses
    else:
        ip_addresses = get_server_ip_address(host_name, fstore,
                                             not installer.interactive, False,
                                             options.ip_addresses)

    print
    print "The IPA Master Server will be configured with:"
    print "Hostname:       %s" % host_name
    print "IP address(es): %s" % ", ".join(str(ip) for ip in ip_addresses)
    print "Domain name:    %s" % domain_name
    print "Realm name:     %s" % realm_name
    print

    if options.setup_dns:
        print "BIND DNS server will be configured to serve IPA domain with:"
        print "Forwarders:    %s" % (
            "No forwarders" if not dns.dns_forwarders
            else ", ".join([str(ip) for ip in dns.dns_forwarders])
        )
        print "Reverse zone(s):  %s" % (
            "No reverse zone" if options.no_reverse or not dns.reverse_zones
            else ", ".join(str(rz) for rz in dns.reverse_zones)
        )
        print

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
        sys.exit("Installation aborted")

    options.realm_name = realm_name
    options.domain_name = domain_name
    options.dm_password = dm_password
    options.master_password = master_password
    options.admin_password = admin_password
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
    dirsrv_pkcs12_file = installer._dirsrv_pkcs12_file
    http_pkcs12_file = installer._http_pkcs12_file
    pkinit_pkcs12_file = installer._pkinit_pkcs12_file
    dirsrv_pkcs12_info = installer._dirsrv_pkcs12_info
    http_pkcs12_info = installer._http_pkcs12_info
    pkinit_pkcs12_info = installer._pkinit_pkcs12_info
    external_cert_file = installer._external_cert_file
    external_ca_file = installer._external_ca_file
    http_ca_cert = installer._ca_cert

    realm_name = options.realm_name
    domain_name = options.domain_name
    dm_password = options.dm_password
    master_password = options.master_password
    admin_password = options.admin_password
    host_name = options.host_name
    ip_addresses = options.ip_addresses
    setup_ca = options.setup_ca
    setup_kra = options.setup_kra

    dogtag_constants = dogtag.install_constants

    # Installation has started. No IPA sysrestore items are restored in case of
    # failure to enable root cause investigation
    installer._installation_cleanup = False

    if installer.interactive:
        print ""
        print "The following operations may take some minutes to complete."
        print "Please wait until the prompt is returned."
        print ""

    system_hostname = get_fqdn()
    if host_name != system_hostname:
        # configure /etc/sysconfig/network to contain the custom hostname
        tasks.backup_and_replace_hostname(fstore, sstore, host_name)

    # Create DS user/group if it doesn't exist yet
    dsinstance.create_ds_user()

    # Create a directory server instance
    if not options.external_cert_files:
        # Configure ntpd
        if not options.no_ntp:
            ipaclient.ntpconf.force_ntpd(sstore)
            ntp = ntpinstance.NTPInstance(fstore)
            if not ntp.is_configured():
                ntp.create_instance()

        if options.dirsrv_cert_files:
            ds = dsinstance.DsInstance(fstore=fstore,
                                       domainlevel=options.domainlevel)
            installer._ds = ds
            ds.create_instance(realm_name, host_name, domain_name,
                               dm_password, dirsrv_pkcs12_info,
                               idstart=options.idstart, idmax=options.idmax,
                               subject_base=options.subject,
                               hbac_allow=not options.no_hbac_allow)
        else:
            ds = dsinstance.DsInstance(fstore=fstore,
                                       domainlevel=options.domainlevel)
            installer._ds = ds
            ds.create_instance(realm_name, host_name, domain_name,
                               dm_password,
                               idstart=options.idstart, idmax=options.idmax,
                               subject_base=options.subject,
                               hbac_allow=not options.no_hbac_allow)
    else:
        ds = dsinstance.DsInstance(fstore=fstore,
                                   domainlevel=options.domainlevel)
        installer._ds = ds
        ds.init_info(
            realm_name, host_name, domain_name, dm_password,
            options.subject, 1101, 1100, None)

    if setup_ca:
        if not options.external_cert_files and options.external_ca:
            # stage 1 of external CA installation
            options.realm_name = realm_name
            options.domain_name = domain_name
            options.master_password = master_password
            options.dm_password = dm_password
            options.admin_password = admin_password
            options.host_name = host_name
            options.forwarders = dns.dns_forwarders
            options.reverse_zones = dns.reverse_zones
            cache_vars = {n: getattr(options, n) for o, n in installer.knobs()}
            write_cache(cache_vars)

        ca.install_step_0(False, None, options)

        # Now put the CA cert where other instances exepct it
        ca_instance = cainstance.CAInstance(realm_name, certs.NSS_DIR,
                                            dogtag_constants=dogtag_constants)
        ca_instance.publish_ca_cert(CACERT)
    else:
        # Put the CA cert where other instances expect it
        x509.write_certificate(http_ca_cert, CACERT)
        os.chmod(CACERT, 0444)

    # we now need to enable ssl on the ds
    ds.enable_ssl()

    if setup_ca:
        ca.install_step_1(False, None, options)

    krb = krbinstance.KrbInstance(fstore)
    if options.pkinit_cert_files:
        krb.create_instance(realm_name, host_name, domain_name,
                            dm_password, master_password,
                            setup_pkinit=not options.no_pkinit,
                            pkcs12_info=pkinit_pkcs12_info,
                            subject_base=options.subject)
    else:
        krb.create_instance(realm_name, host_name, domain_name,
                            dm_password, master_password,
                            setup_pkinit=not options.no_pkinit,
                            subject_base=options.subject)

    # The DS instance is created before the keytab, add the SSL cert we
    # generated
    ds.add_cert_to_service()

    memcache = memcacheinstance.MemcacheInstance()
    memcache.create_instance('MEMCACHE', host_name, dm_password,
                             ipautil.realm_to_suffix(realm_name))

    otpd = otpdinstance.OtpdInstance()
    otpd.create_instance('OTPD', host_name, dm_password,
                         ipautil.realm_to_suffix(realm_name))

    # Create a HTTP instance
    http = httpinstance.HTTPInstance(fstore)
    if options.http_cert_files:
        http.create_instance(
            realm_name, host_name, domain_name, dm_password,
            pkcs12_info=http_pkcs12_info, subject_base=options.subject,
            auto_redirect=not options.no_ui_redirect,
            ca_is_configured=setup_ca)
    else:
        http.create_instance(
            realm_name, host_name, domain_name, dm_password,
            subject_base=options.subject,
            auto_redirect=not options.no_ui_redirect,
            ca_is_configured=setup_ca)
    tasks.restore_context(paths.CACHE_IPA_SESSIONS)

    # Export full CA chain
    ca_db = certs.CertDB(realm_name)
    os.chmod(CACERT, 0644)
    ca_db.publish_ca_cert(CACERT)

    set_subject_in_config(realm_name, dm_password,
                          ipautil.realm_to_suffix(realm_name), options.subject)

    # Apply any LDAP updates. Needs to be done after the configuration file
    # is created
    service.print_msg("Applying LDAP updates")
    ds.apply_updates()

    # Restart ds and krb after configurations have been changed
    service.print_msg("Restarting the directory server")
    ds.restart()

    service.print_msg("Restarting the KDC")
    krb.restart()

    if setup_ca:
        dogtag_service = services.knownservices[dogtag_constants.SERVICE_NAME]
        dogtag_service.restart(dogtag_constants.PKI_INSTANCE_NAME)

    if options.setup_dns:
        api.Backend.ldap2.connect(autobind=True)
        dns.install(False, False, options)
    else:
        # Create a BIND instance
        bind = bindinstance.BindInstance(fstore, dm_password)
        bind.setup(host_name, ip_addresses, realm_name,
                   domain_name, (), not options.no_ntp, (),
                   zonemgr=options.zonemgr, ca_configured=setup_ca,
                   no_dnssec_validation=options.no_dnssec_validation)
        bind.create_sample_bind_zone()

    # Restart httpd to pick up the new IPA configuration
    service.print_msg("Restarting the web server")
    http.restart()

    if setup_kra:
        kra.install(api, None, options)

    # Set the admin user kerberos password
    ds.change_admin_password(admin_password)

    # Call client install script
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
        run(args)
    except Exception, e:
        sys.exit("Configuration of client side components failed!\n"
                 "ipa-client-install returned: " + str(e))

    # Everything installed properly, activate ipa service.
    services.knownservices.ipa.enable()

    print("======================================="
          "=======================================")
    print "Setup complete"
    print ""
    print "Next steps:"
    print "\t1. You must make sure these network ports are open:"
    print "\t\tTCP Ports:"
    print "\t\t  * 80, 443: HTTP/HTTPS"
    print "\t\t  * 389, 636: LDAP/LDAPS"
    print "\t\t  * 88, 464: kerberos"
    if options.setup_dns:
        print "\t\t  * 53: bind"
    print "\t\tUDP Ports:"
    print "\t\t  * 88, 464: kerberos"
    if options.setup_dns:
        print "\t\t  * 53: bind"
    if not options.no_ntp:
        print "\t\t  * 123: ntp"
    print ""
    print("\t2. You can now obtain a kerberos ticket using the command: "
          "'kinit admin'")
    print("\t   This ticket will allow you to use the IPA tools (e.g., ipa "
          "user-add)")
    print "\t   and the web user interface."

    if not services.knownservices.ntpd.is_running():
        print "\t3. Kerberos requires time synchronization between clients"
        print("\t   and servers for correct operation. You should consider "
              "enabling ntpd.")

    print ""
    if setup_ca:
        print("Be sure to back up the CA certificates stored in " +
              paths.CACERT_P12)
        if setup_kra:
            print "and the KRA certificates stored in " + paths.KRACERT_P12
        print("These files are required to create replicas. The password for "
              "these")
        print "files is the Directory Manager password"
    else:
        print "In order for Firefox autoconfiguration to work you will need to"
        print("use a SSL signing certificate. See the IPA documentation for "
              "more details.")

    if ipautil.file_exists(paths.ROOT_IPA_CACHE):
        os.remove(paths.ROOT_IPA_CACHE)


@common_cleanup
def uninstall_check(installer):
    options = installer

    tasks.check_selinux_status()

    if options.master_password:
        msg = ("WARNING:\noption '-P/--master-password' is deprecated. "
               "KDC master password of sufficient strength is autogenerated "
               "during IPA server installation and should not be set "
               "manually.")
        print textwrap.fill(msg, width=79, replace_whitespace=False)

    installer._installation_cleanup = False

    fstore = sysrestore.FileStore(SYSRESTORE_DIR_PATH)
    sstore = sysrestore.StateFile(SYSRESTORE_DIR_PATH)

    # Configuration for ipalib, we will bootstrap and finalize later, after
    # we are sure we have the configuration file ready.
    cfg = dict(
        context='installer',
        in_server=True,
    )

    # We will need at least api.env, finalize api now. This system is
    # already installed, so the configuration file is there.
    api.bootstrap(**cfg)
    api.finalize()

    if installer.interactive:
        print("\nThis is a NON REVERSIBLE operation and will delete all data "
              "and configuration!\n")
        if not user_input("Are you sure you want to continue with the "
                          "uninstall procedure?", False):
            print ""
            print "Aborting uninstall operation."
            sys.exit(1)

    try:
        conn = ipaldap.IPAdmin(
            api.env.host,
            ldapi=True,
            realm=api.env.realm
        )
        conn.do_external_bind(pwd.getpwuid(os.geteuid()).pw_name)
    except Exception:
        msg = ("\nWARNING: Failed to connect to Directory Server to find "
               "information about replication agreements. Uninstallation "
               "will continue despite the possible existing replication "
               "agreements.\n\n")
        print textwrap.fill(msg, width=80, replace_whitespace=False)
    else:
        api.Backend.ldap2.connect(autobind=True)
        dns.uninstall_check(options)

        rm = replication.ReplicationManager(
            realm=api.env.realm,
            hostname=api.env.host,
            dirman_passwd=None,
            conn=conn
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
            print textwrap.fill(msg, width=80, replace_whitespace=False)
            print cmd
            if (installer.interactive and
                not user_input("Are you sure you want to continue with the "
                               "uninstall procedure?", False)):
                print ""
                print "Aborting uninstall operation."
                sys.exit(1)

    installer._fstore = fstore
    installer._sstore = sstore


@common_cleanup
def uninstall(installer):
    fstore = installer._fstore
    sstore = installer._sstore

    rv = 0

    print "Shutting down all IPA services"
    try:
        (stdout, stderr, rc) = run([paths.IPACTL, "stop"], raiseonerr=False)
    except Exception, e:
        pass

    # Need to get dogtag info before /etc/ipa/default.conf is removed
    dogtag_constants = dogtag.configured_constants()

    print "Removing IPA client configuration"
    try:
        (stdout, stderr, rc) = run([paths.IPA_CLIENT_INSTALL, "--on-master",
                                    "--unattended", "--uninstall"],
                                   raiseonerr=False)
        if rc not in [0, 2]:
            root_logger.debug("ipa-client-install returned %d" % rc)
            raise RuntimeError(stdout)
    except Exception, e:
        rv = 1
        print "Uninstall of client side components failed!"
        print "ipa-client-install returned: " + str(e)

    ntpinstance.NTPInstance(fstore).uninstall()

    kra.uninstall(False)

    ca.uninstall(dogtag_constants)

    dns.uninstall()

    httpinstance.HTTPInstance(fstore).uninstall()
    krbinstance.KrbInstance(fstore).uninstall()
    dsinstance.DsInstance(fstore=fstore).uninstall()
    if _server_trust_ad_installed:
        adtrustinstance.ADTRUSTInstance(fstore).uninstall()
    memcacheinstance.MemcacheInstance().uninstall()
    otpdinstance.OtpdInstance().uninstall()
    tasks.restore_network_configuration(fstore, sstore)
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

    ipaclient.ntpconf.restore_forced_ntpd(sstore)

    # Clean up group_exists (unused since IPA 2.2, not being set since 4.1)
    sstore.restore_state("install", "group_exists")

    services.knownservices.ipa.disable()

    ipautil.restore_hostname(sstore)

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
    dirs = [dirname, dogtag_constants.ALIAS_DIR, certs.NSS_DIR]
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

    sys.exit(rv)


class ServerCA(common.Installable, core.Group, core.Composite):
    description = "certificate system"

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

    external_ca = Knob(
        bool, False,
        description=("Generate a CSR for the IPA CA certificate to be signed "
                     "by an external CA"),
    )

    external_ca_type = Knob(
        {'generic', 'ms-cs'}, None,
        description="Type of the external CA",
    )

    external_cert_files = Knob(
        (list, str), None,
        description=("File containing the IPA CA certificate and the external "
                     "CA certificate chain (can be specified multiple times)"),
        cli_name='external-cert-file',
        cli_aliases=['external_cert_file', 'external_ca_file'],
        cli_metavar='FILE',
    )

    @external_cert_files.validator
    def external_cert_files(self, value):
        if any(not os.path.isabs(path) for path in value):
            raise ValueError("must use an absolute path")

    no_pkinit = Knob(
        bool, False,
        description="disables pkinit setup steps",
    )

    dirsrv_cert_files = Knob(
        (list, str), None,
        description=("File containing the Directory Server SSL certificate "
                     "and private key"),
        cli_name='dirsrv-cert-file',
        cli_aliases=['dirsrv_pkcs12'],
        cli_metavar='FILE',
    )

    http_cert_files = Knob(
        (list, str), None,
        description=("File containing the Apache Server SSL certificate and "
                     "private key"),
        cli_name='http-cert-file',
        cli_aliases=['http_pkcs12'],
        cli_metavar='FILE',
    )

    pkinit_cert_files = Knob(
        (list, str), None,
        description=("File containing the Kerberos KDC SSL certificate and "
                     "private key"),
        cli_name='pkinit-cert-file',
        cli_aliases=['pkinit_pkcs12'],
        cli_metavar='FILE',
    )

    dirsrv_pin = Knob(
        str, None,
        sensitive=True,
        description="The password to unlock the Directory Server private key",
        cli_aliases=['dirsrv_pin'],
        cli_metavar='PIN',
    )

    http_pin = Knob(
        str, None,
        sensitive=True,
        description="The password to unlock the Apache Server private key",
        cli_aliases=['http_pin'],
        cli_metavar='PIN',
    )

    pkinit_pin = Knob(
        str, None,
        sensitive=True,
        description="The password to unlock the Kerberos KDC private key",
        cli_aliases=['pkinit_pin'],
        cli_metavar='PIN',
    )

    dirsrv_cert_name = Knob(
        str, None,
        description="Name of the Directory Server SSL certificate to install",
        cli_metavar='NAME',
    )

    http_cert_name = Knob(
        str, None,
        description="Name of the Apache Server SSL certificate to install",
        cli_metavar='NAME',
    )

    pkinit_cert_name = Knob(
        str, None,
        description="Name of the Kerberos KDC SSL certificate to install",
        cli_metavar='NAME',
    )

    ca_cert_files = Knob(
        (list, str), None,
        description=("File containing CA certificates for the service "
                     "certificate files"),
        cli_name='ca-cert-file',
        cli_aliases=['root-ca-file'],
        cli_metavar='FILE',
    )

    subject = Knob(
        str, None,
        description="The certificate subject base (default O=<realm-name>)",
    )

    @subject.validator
    def subject(self, value):
        v = unicode(value, 'utf-8')
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("must not contain control characters")
        if '&' in v:
            raise ValueError("must not contain an ampersand (\"&\")")
        try:
            dn = DN(v)
            for rdn in dn:
                if rdn.attr.lower() not in VALID_SUBJECT_ATTRS:
                    raise ValueError("invalid attribute: \"%s\"" % rdn.attr)
        except ValueError, e:
            raise ValueError("invalid subject base format: %s" % e)

    ca_signing_algorithm = Knob(
        {'SHA1withRSA', 'SHA256withRSA', 'SHA512withRSA'}, None,
        description="Signing algorithm of the IPA CA certificate",
    )


class ServerDNS(common.Installable, core.Group, core.Composite):
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
        description="Do not create reverse DNS zone",
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

    kasp_db_file = Knob(
        str, None,
        initializable=False,
        description="Copy OpenDNSSEC metadata from the specified file (will "
                    "not create a new kasp.db file)",
    )

    force = Knob(
        bool, False,
        initializable=False,
        description="Force install",
    )

    zonemgr = Knob(
        str, None,
        description=("DNS zone manager e-mail address. Defaults to "
                     "hostmaster@DOMAIN"),
    )

    @zonemgr.validator
    def zonemgr(self, value):
        # validate the value first
        try:
            # IDNA support requires unicode
            encoding = getattr(sys.stdin, 'encoding', None)
            if encoding is None:
                encoding = 'utf-8'
            value = value.decode(encoding)
            bindinstance.validate_zonemgr_str(value)
        except ValueError, e:
            # FIXME we can do this in better way
            # https://fedorahosted.org/freeipa/ticket/4804
            # decode to proper stderr encoding
            stderr_encoding = getattr(sys.stderr, 'encoding', None)
            if stderr_encoding is None:
                stderr_encoding = 'utf-8'
            error = unicode(e).encode(stderr_encoding)
            raise ValueError(error)

    no_host_dns = Knob(
        bool, False,
        description="Do not use DNS for hostname lookup during installation",
    )

    no_dns_sshfp = Knob(
        bool, False,
        description="Do not automatically create DNS SSHFP records",
    )


class Server(common.Installable, common.Interactive, core.Composite):
    realm_name = Knob(
        str, None,
        description="realm name",
        cli_name='realm',
        cli_short_name='r',
    )

    domain_name = Knob(
        str, None,
        description="domain name",
        cli_name='domain',
        cli_short_name='n',
    )

    @domain_name.validator
    def domain_name(self, value):
        validate_domain_name(value)

    dm_password = Knob(
        str, None,
        sensitive=True,
        description="Directory Manager password",
        cli_name='ds-password',
        cli_short_name='p',
    )

    @dm_password.validator
    def dm_password(self, value):
        validate_dm_password(value)

    master_password = Knob(
        str, None,
        sensitive=True,
        deprecated=True,
        description="kerberos master password (normally autogenerated)",
        cli_short_name='P',
    )

    admin_password = Knob(
        str, None,
        sensitive=True,
        description="admin user kerberos password",
        cli_short_name='a',
    )

    @admin_password.validator
    def admin_password(self, value):
        validate_admin_password(value)

    mkhomedir = Knob(
        bool, False,
        description="create home directories for users on their first login",
    )

    host_name = Knob(
        str, None,
        description="fully qualified name of server",
        cli_name='hostname',
    )

    domainlevel = Knob(
        int, constants.MAX_DOMAIN_LEVEL,
        description="IPA domain level",
        cli_name='domain-level',
    )

    @domainlevel.validator
    def domainlevel(self, value):
        # Check that Domain Level is within the allowed range
        if value < constants.MIN_DOMAIN_LEVEL:
            raise ValueError(
                "Domain Level cannot be lower than {0}".format(
                    constants.MIN_DOMAIN_LEVEL))
        elif value > constants.MAX_DOMAIN_LEVEL:
            raise ValueError(
                "Domain Level cannot be higher than {0}".format(
                    constants.MAX_DOMAIN_LEVEL))

    ip_addresses = Knob(
        (list, 'ip-local'), None,
        description=("Master Server IP Address. This option can be used "
                     "multiple times"),
        cli_name='ip-address',
    )

    no_ntp = Knob(
        bool, False,
        description="do not configure ntp",
    )

    idstart = Knob(
        int, random.randint(1, 10000) * 200000,
        description="The starting value for the IDs range (default random)",
    )

    idmax = Knob(
        int,
        description=("The max value for the IDs range (default: "
                     "idstart+199999)"),
    )

    @idmax.default_getter
    def idmax(self):
        return self.idstart + 200000 - 1

    no_hbac_allow = Knob(
        bool, False,
        description="Don't install allow_all HBAC rule",
        cli_name='no_hbac_allow',
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

    def __init__(self, **kwargs):
        super(Server, self).__init__(**kwargs)

        self._installation_cleanup = True
        self._ds = None

        self._dirsrv_pkcs12_file = None
        self._http_pkcs12_file = None
        self._pkinit_pkcs12_file = None
        self._dirsrv_pkcs12_info = None
        self._http_pkcs12_info = None
        self._pkinit_pkcs12_info = None
        self._external_cert_file = None
        self._external_ca_file = None
        self._ca_cert = None

        #pylint: disable=no-member

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
        elif self.dns.reverse_zones and self.dns.no_reverse:
            raise RuntimeError(
                "You cannot specify a --reverse-zone option together with "
                "--no-reverse")

        if self.uninstalling:
            if (self.realm_name or self.admin_password or
                    self.master_password):
                raise RuntimeError(
                    "In uninstall mode, -a, -r and -P options are not allowed")
        elif not self.interactive:
            if (not self.realm_name or not self.dm_password or
                    not self.admin_password):
                raise RuntimeError(
                    "In unattended mode you need to provide at least -r, -p "
                    "and -a options")
            if self.dns.setup_dns:
                if not self.dns.forwarders and not self.dns.no_forwarders:
                    raise RuntimeError(
                        "You must specify at least one --forwarder option or "
                        "--no-forwarders option")

        # If any of the key file options are selected, all are required.
        cert_file_req = (self.ca.dirsrv_cert_files, self.ca.http_cert_files)
        cert_file_opt = (self.ca.pkinit_cert_files,)
        if any(cert_file_req + cert_file_opt) and not all(cert_file_req):
            raise RuntimeError(
                "--dirsrv-cert-file and --http-cert-file are required if any "
                "key file options are used.")

        if not self.interactive:
            if self.ca.dirsrv_cert_files and self.ca.dirsrv_pin is None:
                raise RuntimeError(
                    "You must specify --dirsrv-pin with --dirsrv-cert-file")
            if self.ca.http_cert_files and self.ca.http_pin is None:
                raise RuntimeError(
                    "You must specify --http-pin with --http-cert-file")
            if self.ca.pkinit_cert_files and self.ca.pkinit_pin is None:
                raise RuntimeError(
                    "You must specify --pkinit-pin with --pkinit-cert-file")

        if self.ca.external_cert_files and self.ca.dirsrv_cert_files:
            raise RuntimeError(
                "Service certificate file options cannot be used with the "
                "external CA options.")

        if self.ca.external_ca_type and not self.ca.external_ca:
            raise RuntimeError(
                "You cannot specify --external-ca-type without --external-ca")

        if self.idmax < self.idstart:
            raise RuntimeError(
                "idmax (%s) cannot be smaller than idstart (%s)" %
                (self.idmax, self.idstart))

        # Automatically disable pkinit w/ dogtag until that is supported
        self.ca.no_pkinit = True

        self.setup_ca = self.ca.setup_ca
        self.setup_kra = self.ca.setup_kra
        self.external_ca = self.ca.external_ca
        self.external_ca_type = self.ca.external_ca_type
        self.external_cert_files = self.ca.external_cert_files
        self.no_pkinit = self.ca.no_pkinit
        self.dirsrv_cert_files = self.ca.dirsrv_cert_files
        self.http_cert_files = self.ca.http_cert_files
        self.pkinit_cert_files = self.ca.pkinit_cert_files
        self.dirsrv_pin = self.ca.dirsrv_pin
        self.http_pin = self.ca.http_pin
        self.pkinit_pin = self.ca.pkinit_pin
        self.dirsrv_cert_name = self.ca.dirsrv_cert_name
        self.http_cert_name = self.ca.http_cert_name
        self.pkinit_cert_name = self.ca.pkinit_cert_name
        self.ca_cert_files = self.ca.ca_cert_files
        self.subject = self.ca.subject
        self.ca_signing_algorithm = self.ca.ca_signing_algorithm
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
        self.zonemgr = self.dns.zonemgr
        self.no_host_dns = self.dns.no_host_dns
        self.no_dns_sshfp = self.dns.no_dns_sshfp

        self.unattended = not self.interactive

    @step()
    def main(self):
        install_check(self)
        yield
        install(self)

    @main.uninstaller
    def main(self):
        uninstall_check(self)
        yield
        uninstall(self)

    ca = core.Component(ServerCA)
    dns = core.Component(ServerDNS)
