#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
DNS installer module
"""

from __future__ import absolute_import
from __future__ import print_function

import enum
import logging
import os

# absolute import is necessary because IPA module dns clashes with python-dns
from dns import resolver
import six

import sys

from subprocess import CalledProcessError

from ipalib import api
from ipalib import errors
from ipalib import util
from ipalib.install import hostname, sysrestore
from ipalib.install.service import enroll_only, prepare_only
from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipaplatform import services
from ipapython import ipautil
from ipapython import dnsutil
from ipapython.dn import DN
from ipapython.dnsutil import check_zone_overlap
from ipapython.install import typing
from ipapython.install.core import group, knob
from ipapython.admintool import ScriptError
from ipapython.ipautil import user_input
from ipaserver.install.installutils import get_server_ip_address
from ipaserver.install.installutils import read_dns_forwarders
from ipaserver.install.installutils import update_hosts_file
from ipaserver.install import bindinstance
from ipaserver.install import dnskeysyncinstance
from ipaserver.install import odsexporterinstance
from ipaserver.install import opendnssecinstance
from ipaserver.install import service

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

ip_addresses = []
reverse_zones = []


def _find_dnssec_enabled_zones(conn):
    search_kw = {'idnssecinlinesigning': True}
    dnssec_enabled_filter = conn.make_filter(search_kw)
    dn = DN('cn=dns', api.env.basedn)
    try:
        entries, _truncated = conn.find_entries(
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

    ods = opendnssecinstance.OpenDNSSECInstance(fstore)
    ods.realm = api.env.realm

    ods_exporter = odsexporterinstance.ODSExporterInstance(fstore)
    ods_exporter.realm = api.env.realm

    # unconfigure services first
    ods.uninstall()  # needs keytab to flush the latest ods database
    ods_exporter.uninstall()

    ods.ldap_disable('DNSSEC', api.env.host, api.env.basedn)
    ods.ldap_remove_service_container('DNSSEC', api.env.host, api.env.basedn)

    ods_exporter.ldap_disable('DNSKeyExporter', api.env.host, api.env.basedn)
    ods_exporter.remove_service()
    ods_exporter.ldap_remove_service_container('DNSKeyExporter', api.env.host,
                                               api.env.basedn)

    conn = api.Backend.ldap2
    dn = DN(('cn', 'DNSSEC'), ('cn', api.env.host),
            api.env.container_masters, api.env.basedn)
    try:
        entry = conn.get_entry(dn)
    except errors.NotFound:
        pass
    else:
        ipa_config = entry.get('ipaConfigString', [])
        if opendnssecinstance.KEYMASTER in ipa_config:
            ipa_config.remove(opendnssecinstance.KEYMASTER)
            conn.update_entry(entry)


def install_check(standalone, api, replica, options, hostname):
    global ip_addresses
    global reverse_zones
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    if not os.path.isfile(paths.IPA_DNS_INSTALL):
        raise RuntimeError("Integrated DNS requires '%s' package" %
                           constants.IPA_DNS_PACKAGE_NAME)

    # when installing first DNS instance we need to check zone overlap
    if replica or standalone:
        already_enabled = api.Command.dns_is_enabled()['result']
    else:
        already_enabled = False

    if not already_enabled:
        domain = dnsutil.DNSName(util.normalize_zone(api.env.domain))
        try:
            dnsutil.check_zone_overlap(domain, raise_on_error=False)
        except dnsutil.DNSZoneAlreadyExists as e:
            if options.force or options.allow_zone_overlap:
                logger.warning("%s Please make sure that the domain is "
                               "properly delegated to this IPA server.",
                               e)
            else:
                hst = dnsutil.DNSName(hostname).make_absolute().to_text()
                if hst not in e.kwargs['ns']:
                    raise ValueError(str(e))

    for reverse_zone in options.reverse_zones:
        try:
            dnsutil.check_zone_overlap(reverse_zone)
        except dnsutil.DNSZoneAlreadyExists as e:
            if options.force or options.allow_zone_overlap:
                logger.warning('%s', str(e))
            else:
                raise e

    if standalone:
        print("==============================================================================")
        print("This program will setup DNS for the FreeIPA Server.")
        print("")
        print("This includes:")
        print("  * Configure DNS (bind)")
        print("  * Configure SoftHSM (required by DNSSEC)")
        print("  * Configure ipa-dnskeysyncd (required by DNSSEC)")
        if options.dnssec_master:
            print("  * Configure ipa-ods-exporter (required by DNSSEC key master)")
            print("  * Configure OpenDNSSEC (required by DNSSEC key master)")
            print("  * Generate DNSSEC master key (required by DNSSEC key master)")
        elif options.disable_dnssec_master:
            print("  * Unconfigure ipa-ods-exporter")
            print("  * Unconfigure OpenDNSSEC")
            print("")
            print("No new zones will be signed without DNSSEC key master IPA server.")
            print("")
            print(("Please copy file from %s after uninstallation. This file is needed "
                   "on new DNSSEC key " % paths.IPA_KASP_DB_BACKUP))
            print("master server")
        print("")
        print("NOTE: DNSSEC zone signing is not enabled by default")
        print("")
        if options.dnssec_master:
            print("Plan carefully, replacing DNSSEC key master is not recommended")
            print("")
        print("")
        print("To accept the default shown in brackets, press the Enter key.")
        print("")

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
                "WARNING: You have to immediately copy kasp.db file to a new "
                "server and run command 'ipa-dns-install --dnssec-master "
                "--kasp-db'.\n"
                "Your DNS zones will become unavailable if you "
                "do not reinstall the DNSSEC key master role immediately." %
                ", ".join([str(zone) for zone in dnssec_zones]))

    elif options.dnssec_master:
        ods = opendnssecinstance.OpenDNSSECInstance(fstore)
        ods.realm = api.env.realm
        dnssec_masters = ods.get_masters()
        # we can reinstall current server if it is dnssec master
        if dnssec_masters and api.env.host not in dnssec_masters:
            print("DNSSEC key master(s):", u','.join(dnssec_masters))
            raise ScriptError(
                "Only one DNSSEC key master is supported in current version.")

        if options.kasp_db_file:
            dnskeysyncd = services.service('ipa-dnskeysyncd', api)

            if not dnskeysyncd.is_installed():
                raise RuntimeError("ipa-dnskeysyncd is not configured on this "
                                   "server, you cannot reuse OpenDNSSEC "
                                   "database (kasp.db file)")

            # check if replica can be the DNSSEC master
            cmd = [paths.IPA_DNSKEYSYNCD_REPLICA]
            environment = {
                "SOFTHSM2_CONF": paths.DNSSEC_SOFTHSM2_CONF,
            }

            # stop dnskeysyncd before test
            dnskeysyncd_running = dnskeysyncd.is_running()
            dnskeysyncd.stop()
            try:
                ipautil.run(cmd, env=environment,
                            runas=constants.ODS_USER,
                            suplementary_groups=[constants.NAMED_GROUP])
            except CalledProcessError as e:
                logger.debug("%s", e)
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

    ip_addresses = get_server_ip_address(hostname, options.unattended,
                                         True, options.ip_addresses)

    util.no_matching_interface_for_ip_address_warning(ip_addresses)

    if not options.forward_policy:
        # user did not specify policy, derive it: default is 'first' but
        # if any of local IP addresses belongs to private ranges use 'only'
        options.forward_policy = 'first'
        for ip in ip_addresses:
            if dnsutil.inside_auto_empty_zone(dnsutil.DNSName(ip.reverse_dns)):
                options.forward_policy = 'only'
                logger.debug('IP address %s belongs to a private range, '
                             'using forward policy only', ip)
                break

    if options.no_forwarders:
        options.forwarders = []
    elif options.forwarders or options.auto_forwarders:
        if not options.forwarders:
            options.forwarders = []
        if options.auto_forwarders:
            options.forwarders += resolver.get_default_resolver().nameservers
    elif standalone or not replica:
        options.forwarders = read_dns_forwarders()

    # test DNSSEC forwarders
    if options.forwarders:
        if not options.no_dnssec_validation \
                and not bindinstance.check_forwarders(options.forwarders):
            options.no_dnssec_validation = True
            print("WARNING: DNSSEC validation will be disabled")

    logger.debug("will use DNS forwarders: %s\n", options.forwarders)

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
        print("Using reverse zone(s) %s" % ', '.join(reverse_zones))


def install(standalone, replica, options, api=api):
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    if standalone:
        # otherwise this is done by server/replica installer
        update_hosts_file(ip_addresses, api.env.host, fstore)

    bind = bindinstance.BindInstance(fstore, api=api)
    bind.setup(api.env.host, ip_addresses, api.env.realm, api.env.domain,
               options.forwarders, options.forward_policy,
               reverse_zones, zonemgr=options.zonemgr,
               no_dnssec_validation=options.no_dnssec_validation)

    if standalone and not options.unattended:
        print("")
        print("The following operations may take some minutes to complete.")
        print("Please wait until the prompt is returned.")
        print("")

    bind.create_instance()
    print("Restarting the web server to pick up resolv.conf changes")
    services.knownservices.httpd.restart(capture_output=True)

    # on dnssec master this must be installed last
    dnskeysyncd = dnskeysyncinstance.DNSKeySyncInstance(fstore)
    dnskeysyncd.create_instance(api.env.host, api.env.realm)
    if options.dnssec_master:
        ods = opendnssecinstance.OpenDNSSECInstance(fstore)
        ods_exporter = odsexporterinstance.ODSExporterInstance(fstore)

        ods_exporter.create_instance(api.env.host, api.env.realm)
        ods.create_instance(api.env.host, api.env.realm,
                            kasp_db_file=options.kasp_db_file)
    elif options.disable_dnssec_master:
        _disable_dnssec()

    dnskeysyncd.start_dnskeysyncd()
    bind.start_named()

    # Enable configured services for standalone check_global_configuration()
    if standalone:
        service.enable_services(api.env.host)

    # this must be done when bind is started and operational
    bind.update_system_records()

    if standalone:
        print("==============================================================================")
        print("Setup complete")
        print("")
        bind.check_global_configuration()
        print("")
        print("")
        print("\tYou must make sure these network ports are open:")
        print("\t\tTCP Ports:")
        print("\t\t  * 53: bind")
        print("\t\tUDP Ports:")
        print("\t\t  * 53: bind")
    elif not standalone and replica:
        print("")
        bind.check_global_configuration()
        print("")


def uninstall_check(options):
    # test if server is DNSSEC key master
    masters = opendnssecinstance.get_dnssec_key_masters(api.Backend.ldap2)
    if api.env.host in masters:
        print("This server is active DNSSEC key master. Uninstall could break your DNS system.")
        if not (options.unattended or user_input(
                "Are you sure you want to continue with the uninstall "
                "procedure?", False)):
            print("")
            print("Aborting uninstall operation.")
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


class DNSForwardPolicy(enum.Enum):
    ONLY = 'only'
    FIRST = 'first'


@group
class DNSInstallInterface(hostname.HostNameInstallInterface):
    """
    Interface of the DNS installer

    Knobs defined here will be available in:
    * ipa-server-install
    * ipa-replica-prepare
    * ipa-replica-install
    * ipa-dns-install
    """
    description = "DNS"

    allow_zone_overlap = knob(
        None,
        description="Create DNS zone even if it already exists",
    )
    allow_zone_overlap = prepare_only(allow_zone_overlap)

    reverse_zones = knob(
        # pylint: disable=invalid-sequence-index
        typing.List[str], [],
        description=("The reverse DNS zone to use. This option can be used "
                     "multiple times"),
        cli_names='--reverse-zone',
        cli_metavar='REVERSE_ZONE',
    )
    reverse_zones = prepare_only(reverse_zones)

    @reverse_zones.validator
    def reverse_zones(self, values):
        if not self.allow_zone_overlap:
            for zone in values:
                check_zone_overlap(zone)

    no_reverse = knob(
        None,
        description="Do not create new reverse DNS zone",
    )
    no_reverse = prepare_only(no_reverse)

    auto_reverse = knob(
        None,
        description="Create necessary reverse zones",
    )
    auto_reverse = prepare_only(auto_reverse)

    zonemgr = knob(
        str, None,
        description=("DNS zone manager e-mail address. Defaults to "
                     "hostmaster@DOMAIN"),
    )
    zonemgr = prepare_only(zonemgr)

    @zonemgr.validator
    def zonemgr(self, value):
        # validate the value first
        if six.PY3:
            bindinstance.validate_zonemgr_str(value)
        else:
            try:
                # IDNA support requires unicode
                encoding = getattr(sys.stdin, 'encoding', None)
                if encoding is None:
                    encoding = 'utf-8'

                # value is string in py2 and py3
                if not isinstance(value, unicode):
                    value = value.decode(encoding)

                bindinstance.validate_zonemgr_str(value)
            except ValueError as e:
                # FIXME we can do this in better way
                # https://fedorahosted.org/freeipa/ticket/4804
                # decode to proper stderr encoding
                stderr_encoding = getattr(sys.stderr, 'encoding', None)
                if stderr_encoding is None:
                    stderr_encoding = 'utf-8'
                error = unicode(e).encode(stderr_encoding)
                raise ValueError(error)

    forwarders = knob(
        # pylint: disable=invalid-sequence-index
        typing.List[ipautil.CheckedIPAddressLoopback], None,
        description=("Add a DNS forwarder. This option can be used multiple "
                     "times"),
        cli_names='--forwarder',
    )
    forwarders = enroll_only(forwarders)

    no_forwarders = knob(
        None,
        description="Do not add any DNS forwarders, use root servers instead",
    )
    no_forwarders = enroll_only(no_forwarders)

    auto_forwarders = knob(
        None,
        description="Use DNS forwarders configured in /etc/resolv.conf",
    )
    auto_forwarders = enroll_only(auto_forwarders)

    forward_policy = knob(
        DNSForwardPolicy, None,
        description=("DNS forwarding policy for global forwarders"),
    )
    forward_policy = enroll_only(forward_policy)

    no_dnssec_validation = knob(
        None,
        description="Disable DNSSEC validation",
    )
    no_dnssec_validation = enroll_only(no_dnssec_validation)

    dnssec_master = False
    disable_dnssec_master = False
    kasp_db_file = None
    force = False
