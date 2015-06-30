#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import sys

from subprocess import CalledProcessError

from ipalib import api
from ipalib import errors
from ipaplatform.paths import paths
from ipaplatform import services
from ipapython import ipautil
from ipapython import sysrestore
from ipapython.dn import DN
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

NEW_MASTER_MARK = 'NEW_DNSSEC_MASTER'


def _find_dnssec_enabled_zones(conn):
    search_kw = {'idnssecinlinesigning': True}
    dnssec_enabled_filter = conn.make_filter(search_kw)
    dn = DN('cn=dns', api.env.basedn)
    try:
        entries, truncated = conn.find_entries(
            base_dn=dn, filter=dnssec_enabled_filter, attrs_list=['idnsname'])
    except errors.NotFound:
        return []
    else:
        return [entry.single_value['idnsname'] for entry in entries
                if 'idnsname' in entry]


def _is_master():
    # test if server is DNSSEC key master
    masters = opendnssecinstance.get_dnssec_key_masters(api.Backend.ldap2)
    if api.env.host not in masters:
        raise RuntimeError("Current server is not DNSSEC key master")


def _disable_dnssec():
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    ods = opendnssecinstance.OpenDNSSECInstance(
            fstore, ldapi=True, autobind=AUTOBIND_ENABLED)
    ods.realm = api.env.realm

    ods_exporter = odsexporterinstance.ODSExporterInstance(fstore, ldapi=True)
    ods_exporter.realm = api.env.realm

    # unconfigure services first
    ods.uninstall()  # needs keytab to flush the latest ods database
    ods_exporter.uninstall()

    ods.ldap_connect()
    ods.ldap_disable('DNSSEC', api.env.host, api.env.basedn)

    ods_exporter.ldap_connect()
    ods_exporter.ldap_disable('DNSKeyExporter', api.env.host, api.env.basedn)
    ods_exporter.remove_service()

    ods.ldap_disconnect()
    ods_exporter.ldap_disconnect()

    conn = api.Backend.ldap2
    dn = DN(('cn', 'DNSSEC'), ('cn', api.env.host), ('cn', 'masters'),
            ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
    try:
        entry = conn.get_entry(dn)
    except errors.NotFound:
        pass
    else:
        ipa_config = entry.get('ipaConfigString', [])
        if opendnssecinstance.KEYMASTER in ipa_config:
            ipa_config.remove(opendnssecinstance.KEYMASTER)
            conn.update_entry(entry)


def install_check(standalone, replica, options, hostname):
    global ip_addresses
    global dns_forwarders
    global reverse_zones
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

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
        elif options.disable_dnssec_master:
            print "  * Unconfigure ipa-ods-exporter"
            print "  * Unconfigure OpenDNSSEC"
            print ""
            print "No new zones will be signed without DNSSEC key master IPA server."
            print ""
            print ("Please copy file from %s after uninstallation. This file is needed "
                   "on new DNSSEC key " % paths.IPA_KASP_DB_BACKUP)
            print "master server"
        print ""
        print "NOTE: DNSSEC zone signing is not enabled by default"
        print ""
        if options.dnssec_master:
            print "DNSSEC support is experimental!"
            print ""
            print "Plan carefully, replacing DNSSEC key master is not recommended"
            print ""
        print ""
        print "To accept the default shown in brackets, press the Enter key."
        print ""

    if (options.dnssec_master and not options.unattended and not
        ipautil.user_input(
            "Do you want to setup this IPA server as DNSSEC key master?",
            False)):
        sys.exit("Aborted")
    elif (options.disable_dnssec_master and not options.unattended and not
          ipautil.user_input(
            "Do you want to disable current DNSSEC key master?",
            False)):
        sys.exit("Aborted")

    # Check bind packages are installed
    if not (bindinstance.check_inst(options.unattended) and
            dnskeysyncinstance.check_inst()):
        sys.exit("Aborting installation.")

    if options.disable_dnssec_master:
        _is_master()

    if options.disable_dnssec_master or options.dnssec_master:
        dnssec_zones = _find_dnssec_enabled_zones(api.Backend.ldap2)

    if options.disable_dnssec_master:
        if dnssec_zones and not options.force:
            raise RuntimeError(
                "Cannot disable DNSSEC key master, DNSSEC signing is still "
                "enabled for following zone(s):\n"
                "%s\n"
                "It is possible to move DNSSEC key master role to a different "
                "server by using --force option to skip this check.\n\n"
                "WARNING: You have to immediatelly copy kasp.db file to a new "
                "server and run command 'ipa-dns-install --dnssec-master "
                "--kasp-db'.\n"
                "Your DNS zones will become unavailable if you "
                "do not reinstall the DNSSEC key master role immediatelly." %
                ", ".join([str(zone) for zone in dnssec_zones]))

    elif options.dnssec_master:
        ods = opendnssecinstance.OpenDNSSECInstance(
            fstore, ldapi=True)
        ods.realm = api.env.realm
        dnssec_masters = ods.get_masters()
        # we can reinstall current server if it is dnssec master
        if dnssec_masters and api.env.host not in dnssec_masters:
            print "DNSSEC key master(s):", u','.join(dnssec_masters)
            sys.exit("Only one DNSSEC key master is supported in current "
                     "version.")

        # check opendnssec packages are installed
        if not opendnssecinstance.check_inst():
            sys.exit("Aborting installation")
        if options.kasp_db_file:
            dnskeysyncd = services.service('ipa-dnskeysyncd')

            if not dnskeysyncd.is_installed():
                raise RuntimeError("ipa-dnskeysyncd is not configured on this "
                                   "server, you cannot reuse OpenDNSSEC "
                                   "database (kasp.db file)")

            # check if replica can be the DNSSEC master
            named = services.knownservices.named
            ods_enforcerd = services.knownservices.ods_enforcerd
            cmd = [paths.IPA_DNSKEYSYNCD_REPLICA]
            environment = {
                "SOFTHSM2_CONF": paths.DNSSEC_SOFTHSM2_CONF,
            }

            # stop dnskeysyncd before test
            dnskeysyncd_running = dnskeysyncd.is_running()
            dnskeysyncd.stop()
            try:
                ipautil.run(cmd, env=environment,
                            runas=ods_enforcerd.get_user_name(),
                            suplementary_groups=[named.get_group_name()])
            except CalledProcessError as e:
                root_logger.debug("%s", e)
                raise RuntimeError("This IPA server cannot be promoted to "
                                   "DNSSEC master role because some keys were "
                                   "not replicated from the original "
                                   "DNSSEC master server")
            finally:
                if dnskeysyncd_running:
                    dnskeysyncd.start()
        elif dnssec_zones and not options.force:
            # some zones have --dnssec=true, make sure a user really want to
            # install new database
            raise RuntimeError(
                "DNSSEC signing is already enabled for following zone(s): %s\n"
                "Installation cannot continue without the OpenDNSSEC database "
                "file from the original DNSSEC master server.\n"
                "Please use option --kasp-db to specify location "
                "of the kasp.db file copied from the original "
                "DNSSEC master server.\n"
                "WARNING: Zones will become unavailable if you do not provide "
                "the original kasp.db file." %
                ", ".join([str(zone) for zone in dnssec_zones]))

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

    local_dnskeysyncd_dn = DN(('cn', 'DNSKeySync'), ('cn', api.env.host),
                              ('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
                              api.env.basedn)
    conn = api.Backend.ldap2

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
        ods = opendnssecinstance.OpenDNSSECInstance(fstore, ldapi=True)
        ods_exporter = odsexporterinstance.ODSExporterInstance(
            fstore, ldapi=True)

        ods_exporter.create_instance(api.env.host, api.env.realm)
        ods.create_instance(api.env.host, api.env.realm,
                            kasp_db_file=options.kasp_db_file)
    elif options.disable_dnssec_master:
        _disable_dnssec()

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
