#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import sys

from ipalib import api
from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython import sysrestore
from ipapython.ipa_log_manager import root_logger
from ipapython.ipaldap import AUTOBIND_ENABLED
from ipapython.ipautil import user_input
from ipaserver.install.installutils import get_server_ip_address
from ipaserver.install.installutils import read_dns_forwarders
from ipaserver.install import bindinstance
from ipaserver.install import dnskeysyncinstance
from ipaserver.install import ntpinstance
from ipaserver.install import odsexporterinstance
from ipaserver.install import opendnssecinstance

ip_addresses = []
dns_forwarders = []
reverse_zones = []


def install_check(standalone, replica, options, hostname):
    global ip_addresses
    global dns_forwarders
    global reverse_zones

    if standalone:
        print "=============================================================================="
        print "This program will setup DNS for the FreeIPA Server."
        print ""
        print "This includes:"
        print "  * Configure DNS (bind)"
        print "  * Configure SoftHSM (required by DNSSEC)"
        print "  * Configure ipa-dnskeysyncd (required by DNSSEC)"
        if options.dnssec_master:
            print "  * Configure ipa-ods-exporter (required by DNSSEC key master)"
            print "  * Configure OpenDNSSEC (required by DNSSEC key master)"
            print "  * Generate DNSSEC master key (required by DNSSEC key master)"
        print ""
        print "NOTE: DNSSEC zone signing is not enabled by default"
        print ""
        if options.dnssec_master:
            print "DNSSEC support is experimental!"
            print ""
            print "Plan carefully, current version doesn't allow you to move DNSSEC"
            print "key master to different server and master cannot be uninstalled"
            print ""
        print ""
        print "To accept the default shown in brackets, press the Enter key."
        print ""

    if (options.dnssec_master and not options.unattended and not
        ipautil.user_input(
            "Do you want to setup this IPA server as DNSSEC key master?",
            False)):
        sys.exit("Aborted")

    # Check bind packages are installed
    if not (bindinstance.check_inst(options.unattended) and
            dnskeysyncinstance.check_inst()):
        sys.exit("Aborting installation.")

    if options.dnssec_master:
        # check opendnssec packages are installed
        if not opendnssecinstance.check_inst():
            sys.exit("Aborting installation")

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    if options.dnssec_master:
        ods = opendnssecinstance.OpenDNSSECInstance(
            fstore, ldapi=True, autobind=AUTOBIND_ENABLED)
        ods.realm = api.env.realm
        dnssec_masters = ods.get_masters()
        # we can reinstall current server if it is dnssec master
        if api.env.host not in dnssec_masters and dnssec_masters:
            print "DNSSEC key master(s):", u','.join(dnssec_masters)
            sys.exit("Only one DNSSEC key master is supported in current "
                     "version.")

    ip_addresses = get_server_ip_address(
        hostname, fstore, options.unattended, True, options.ip_addresses)

    if options.no_forwarders:
        dns_forwarders = ()
    elif options.forwarders:
        dns_forwarders = options.forwarders
    elif standalone or not replica:
        dns_forwarders = read_dns_forwarders()

    # test DNSSEC forwarders
    if dns_forwarders:
        if (not bindinstance.check_forwarders(dns_forwarders, root_logger) and
                not options.no_dnssec_validation):
            options.no_dnssec_validation = True
            print "WARNING: DNSSEC validation will be disabled"

    root_logger.debug("will use dns_forwarders: %s\n", dns_forwarders)

    if not standalone:
        search_reverse_zones = False
    else:
        search_reverse_zones = True

    if not standalone and replica:
        reverse_zones_unattended_check = True
    else:
        reverse_zones_unattended_check = options.unattended

    reverse_zones = bindinstance.check_reverse_zones(
        ip_addresses, options.reverse_zones, options,
        reverse_zones_unattended_check, search_reverse_zones
    )

    if reverse_zones:
        print "Using reverse zone(s) %s" % ', '.join(reverse_zones)


def install(standalone, replica, options):
    global ip_addresses
    global dns_forwarders
    global reverse_zones

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    conf_ntp = ntpinstance.NTPInstance(fstore).is_enabled()

    bind = bindinstance.BindInstance(fstore, ldapi=True,
                                     autobind=AUTOBIND_ENABLED)
    bind.setup(api.env.host, ip_addresses, api.env.realm, api.env.domain,
               dns_forwarders, conf_ntp, reverse_zones, zonemgr=options.zonemgr,
               no_dnssec_validation=options.no_dnssec_validation,
               ca_configured=options.setup_ca)

    if standalone and not options.unattended:
        print ""
        print "The following operations may take some minutes to complete."
        print "Please wait until the prompt is returned."
        print ""

    bind.create_instance()

    # on dnssec master this must be installed last
    dnskeysyncd = dnskeysyncinstance.DNSKeySyncInstance(fstore, ldapi=True)
    dnskeysyncd.create_instance(api.env.host, api.env.realm)
    if options.dnssec_master:
        ods = opendnssecinstance.OpenDNSSECInstance(fstore, ldapi=True,
                                                    autobind=AUTOBIND_ENABLED)
        ods_exporter = odsexporterinstance.ODSExporterInstance(
            fstore, ldapi=True, autobind=AUTOBIND_ENABLED)

        ods_exporter.create_instance(api.env.host, api.env.realm)
        ods.create_instance(api.env.host, api.env.realm)

    dnskeysyncd.start_dnskeysyncd()
    bind.start_named()

    if standalone:
        print "=============================================================================="
        print "Setup complete"
        print ""
        bind.check_global_configuration()
        print ""
        print ""
        print "\tYou must make sure these network ports are open:"
        print "\t\tTCP Ports:"
        print "\t\t  * 53: bind"
        print "\t\tUDP Ports:"
        print "\t\t  * 53: bind"
    elif not standalone and replica:
        print ""
        bind.check_global_configuration()
        print ""


def uninstall_check(options):
    # test if server is DNSSEC key master
    masters = opendnssecinstance.get_dnssec_key_masters(api.Backend.ldap2)
    if api.env.host in masters:
        print "This server is active DNSSEC key master. Uninstall could break your DNS system."
        if not (options.unattended or user_input(
                "Are you sure you want to continue with the uninstall "
                "procedure?", False)):
            print ""
            print "Aborting uninstall operation."
            sys.exit(1)


def uninstall():
    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    ods = opendnssecinstance.OpenDNSSECInstance(fstore)
    if ods.is_configured():
        ods.uninstall()

    ods_exporter = odsexporterinstance.ODSExporterInstance(fstore)
    if ods_exporter.is_configured():
        ods_exporter.uninstall()

    bind = bindinstance.BindInstance(fstore)
    if bind.is_configured():
        bind.uninstall()

    dnskeysync = dnskeysyncinstance.DNSKeySyncInstance(fstore)
    if dnskeysync.is_configured():
        dnskeysync.uninstall()
