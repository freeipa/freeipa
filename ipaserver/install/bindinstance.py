# Authors: Simo Sorce <ssorce@redhat.com>
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

import tempfile
import os
import pwd
import netaddr
import re
import sys
import time

import ldap

import installutils
import service
from ipaserver.install.cainstance import IPA_CA_RECORD
from ipapython import sysrestore, ipautil, ipaldap
from ipapython.ipa_log_manager import *
from ipapython.dn import DN
import ipalib
from ipalib import api, errors
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipalib.util import (validate_zonemgr_str, normalize_zonemgr,
        get_dns_forward_zone_update_policy, get_dns_reverse_zone_update_policy,
        normalize_zone, get_reverse_zone_default, zone_is_reverse,
        validate_dnssec_global_forwarder, DNSSECSignatureMissingError,
        EDNS0UnsupportedError, UnresolvableRecordError)
from ipalib.constants import CACERT

NAMED_CONF = paths.NAMED_CONF
RESOLV_CONF = paths.RESOLV_CONF

named_conf_section_ipa_start_re = re.compile('\s*dynamic-db\s+"ipa"\s+{')
named_conf_section_options_start_re = re.compile('\s*options\s+{')
named_conf_section_end_re = re.compile('};')
named_conf_arg_ipa_re = re.compile(r'(?P<indent>\s*)arg\s+"(?P<name>\S+)\s(?P<value>[^"]+)";')
named_conf_arg_options_re = re.compile(r'(?P<indent>\s*)(?P<name>\S+)\s+"(?P<value>[^"]+)"\s*;')
named_conf_arg_ipa_template = "%(indent)sarg \"%(name)s %(value)s\";\n"
named_conf_arg_options_template = "%(indent)s%(name)s \"%(value)s\";\n"
# non string args for options section
named_conf_arg_options_re_nonstr = re.compile(r'(?P<indent>\s*)(?P<name>\S+)\s+(?P<value>[^"]+)\s*;')
named_conf_arg_options_template_nonstr = "%(indent)s%(name)s %(value)s;\n"
# include directive
named_conf_include_re = re.compile(r'\s*include\s+"(?P<path>)"\s*;')
named_conf_include_template = "include \"%(path)s\";\n"

def check_inst(unattended):
    has_bind = True
    named = services.knownservices.named
    if not os.path.exists(named.get_binary_path()):
        print "BIND was not found on this system"
        print ("Please install the '%s' package and start the installation again"
              % named.get_package_name())
        has_bind = False

    # Also check for the LDAP BIND plug-in
    if not os.path.exists(paths.BIND_LDAP_SO) and \
       not os.path.exists(paths.BIND_LDAP_SO_64):
        print "The BIND LDAP plug-in was not found on this system"
        print "Please install the 'bind-dyndb-ldap' package and start the installation again"
        has_bind = False

    if not has_bind:
        return False

    if not unattended and os.path.exists(NAMED_CONF):
        msg = "Existing BIND configuration detected, overwrite?"
        return ipautil.user_input(msg, False)

    return True

def create_reverse():
    return ipautil.user_input("Do you want to configure the reverse zone?", True)

def named_conf_exists():
    try:
        named_fd = open(NAMED_CONF, 'r')
    except IOError:
        return False
    lines = named_fd.readlines()
    named_fd.close()
    for line in lines:
        if line.startswith('dynamic-db "ipa"'):
            return True
    return False

NAMED_SECTION_OPTIONS = "options"
NAMED_SECTION_IPA = "ipa"
def named_conf_get_directive(name, section=NAMED_SECTION_IPA, str_val=True):
    """Get a configuration option in bind-dyndb-ldap section of named.conf

    :str_val - set to True if directive value is string
        (only for NAMED_SECTION_OPTIONS)
    """
    if section == NAMED_SECTION_IPA:
        named_conf_section_start_re = named_conf_section_ipa_start_re
        named_conf_arg_re = named_conf_arg_ipa_re
    elif section == NAMED_SECTION_OPTIONS:
        named_conf_section_start_re = named_conf_section_options_start_re
        if str_val:
            named_conf_arg_re = named_conf_arg_options_re
        else:
            named_conf_arg_re = named_conf_arg_options_re_nonstr
    else:
        raise NotImplementedError('Section "%s" is not supported' % section)

    with open(NAMED_CONF, 'r') as f:
        target_section = False
        for line in f:
            if named_conf_section_start_re.match(line):
                target_section = True
                continue
            if named_conf_section_end_re.match(line):
                if target_section:
                    break

            if target_section:
                match = named_conf_arg_re.match(line)

                if match and name == match.group('name'):
                    return match.group('value')

def named_conf_set_directive(name, value, section=NAMED_SECTION_IPA,
                             str_val=True):
    """
    Set configuration option in bind-dyndb-ldap section of named.conf.

    When the configuration option with given name does not exist, it
    is added at the end of ipa section in named.conf.

    If the value is set to None, the configuration option is removed
    from named.conf.

    :str_val - set to True if directive value is string
        (only for NAMED_SECTION_OPTIONS)
    """
    new_lines = []

    if section == NAMED_SECTION_IPA:
        named_conf_section_start_re = named_conf_section_ipa_start_re
        named_conf_arg_re = named_conf_arg_ipa_re
        named_conf_arg_template = named_conf_arg_ipa_template
    elif section == NAMED_SECTION_OPTIONS:
        named_conf_section_start_re = named_conf_section_options_start_re
        if str_val:
            named_conf_arg_re = named_conf_arg_options_re
            named_conf_arg_template = named_conf_arg_options_template
        else:
            named_conf_arg_re = named_conf_arg_options_re_nonstr
            named_conf_arg_template = named_conf_arg_options_template_nonstr
    else:
        raise NotImplementedError('Section "%s" is not supported' % section)

    with open(NAMED_CONF, 'r') as f:
        target_section = False
        matched = False
        last_indent = "\t"
        for line in f:
            if named_conf_section_start_re.match(line):
                target_section = True
            if named_conf_section_end_re.match(line):
                if target_section and not matched and \
                        value is not None:
                    # create a new conf
                    new_conf = named_conf_arg_template \
                            % dict(indent=last_indent,
                                   name=name,
                                   value=value)
                    new_lines.append(new_conf)
                target_section = False

            if target_section and not matched:
                match = named_conf_arg_re.match(line)

                if match:
                    last_indent = match.group('indent')
                    if name == match.group('name'):
                        matched = True
                        if value is not None:
                            if not isinstance(value, basestring):
                                value = str(value)
                            new_conf = named_conf_arg_template \
                                    % dict(indent=last_indent,
                                           name=name,
                                           value=value)
                            new_lines.append(new_conf)
                        continue
            new_lines.append(line)

    # write new configuration
    with open(NAMED_CONF, 'w') as f:
        f.write("".join(new_lines))

def named_conf_include_exists(path):
    """
    Check if include exists in named.conf
    :param path: path in include directive
    :return: True if include exists, else False
    """
    with open(NAMED_CONF, 'r') as f:
        for line in f:
            match = named_conf_include_re.match(line)
            if match and path == match.group('path'):
                return True

    return False

def named_conf_add_include(path):
    """
    append include at the end of file
    :param path: path to be insert to include directive
    """
    with open(NAMED_CONF, 'a') as f:
        f.write(named_conf_include_template % {'path': path})

def dns_container_exists(fqdn, suffix, dm_password=None, ldapi=False, realm=None,
                         autobind=ipaldap.AUTOBIND_DISABLED):
    """
    Test whether the dns container exists.
    """
    assert isinstance(suffix, DN)
    try:
        # At install time we may need to use LDAPI to avoid chicken/egg
        # issues with SSL certs and truting CAs
        if ldapi:
            conn = ipaldap.IPAdmin(host=fqdn, ldapi=True, realm=realm)
        else:
            conn = ipaldap.IPAdmin(host=fqdn, port=636, cacert=CACERT)

        conn.do_bind(dm_password, autobind=autobind)
    except ldap.SERVER_DOWN:
        raise RuntimeError('LDAP server on %s is not responding. Is IPA installed?' % fqdn)

    ret = conn.entry_exists(DN(('cn', 'dns'), suffix))
    conn.unbind()

    return ret

def dns_zone_exists(name, api=api):
    try:
        zone = api.Command.dnszone_show(unicode(name))
    except ipalib.errors.NotFound:
        return False

    if len(zone) == 0:
        return False
    else:
        return True

def get_reverse_record_name(zone, ip_address):
    ip = netaddr.IPAddress(ip_address)
    rev = '.' + normalize_zone(zone)
    fullrev = '.' + normalize_zone(ip.reverse_dns)

    if not fullrev.endswith(rev):
        raise ValueError("IP address does not match reverse zone")

    return fullrev[1:-len(rev)]

def verify_reverse_zone(zone, ip_address):
    try:
        get_reverse_record_name(zone, ip_address)
    except ValueError:
        return False

    return True

def find_reverse_zone(ip_address, api=api):
    ip = netaddr.IPAddress(ip_address)
    zone = normalize_zone(ip.reverse_dns)

    while len(zone) > 0:
        if dns_zone_exists(zone, api):
            return zone
        foo, bar, zone = zone.partition('.')

    return None

def get_reverse_zone(ip_address):
    return find_reverse_zone(ip_address) or get_reverse_zone_default(ip_address)

def read_reverse_zone(default, ip_address):
    while True:
        zone = ipautil.user_input("Please specify the reverse zone name", default=default)
        if not zone:
            return None
        if verify_reverse_zone(zone, ip_address):
            break
        else:
            print "Invalid reverse zone %s for IP address %s" % (zone, ip_address)

    return normalize_zone(zone)

def add_zone(name, zonemgr=None, dns_backup=None, ns_hostname=None,
       update_policy=None, force=False, api=api):

    # always normalize zones
    name = normalize_zone(name)

    if update_policy is None:
        if zone_is_reverse(name):
            update_policy = get_dns_reverse_zone_update_policy(api.env.realm, name)
        else:
            update_policy = get_dns_forward_zone_update_policy(api.env.realm)

    if zonemgr is None:
        zonemgr = 'hostmaster.%s' % name

    if ns_hostname:
        ns_hostname = normalize_zone(ns_hostname)
        ns_hostname = unicode(ns_hostname)

    try:
        api.Command.dnszone_add(unicode(name),
                                idnssoamname=ns_hostname,
                                idnssoarname=unicode(zonemgr),
                                idnsallowdynupdate=True,
                                idnsupdatepolicy=unicode(update_policy),
                                idnsallowquery=u'any',
                                idnsallowtransfer=u'none',
                                force=force)
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass

def add_rr(zone, name, type, rdata, dns_backup=None, api=api, **kwargs):
    addkw = { '%srecord' % str(type.lower()) : unicode(rdata) }
    addkw.update(kwargs)
    try:
        api.Command.dnsrecord_add(unicode(zone), unicode(name), **addkw)
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass
    if dns_backup:
        dns_backup.add(zone, type, name, rdata)

def add_fwd_rr(zone, host, ip_address, api=api):
    addr = netaddr.IPAddress(ip_address)
    if addr.version == 4:
        add_rr(zone, host, "A", ip_address, None, api)
    elif addr.version == 6:
        add_rr(zone, host, "AAAA", ip_address, None, api)

def add_ptr_rr(zone, ip_address, fqdn, dns_backup=None, api=api):
    name = get_reverse_record_name(zone, ip_address)
    add_rr(zone, name, "PTR", normalize_zone(fqdn), dns_backup, api)

def add_ns_rr(zone, hostname, dns_backup=None, force=True):
    hostname = normalize_zone(hostname)
    add_rr(zone, "@", "NS", hostname, dns_backup=dns_backup,
            force=force)

def del_rr(zone, name, type, rdata):
    delkw = { '%srecord' % str(type.lower()) : unicode(rdata) }
    try:
        api.Command.dnsrecord_del(unicode(zone), unicode(name), **delkw)
    except (errors.NotFound, errors.AttrValueNotFound, errors.EmptyModlist):
        pass

def del_fwd_rr(zone, host, ip_address):
    addr = netaddr.IPAddress(ip_address)
    if addr.version == 4:
        del_rr(zone, host, "A", ip_address)
    elif addr.version == 6:
        del_rr(zone, host, "AAAA", ip_address)

def del_ns_rr(zone, name, rdata):
    del_rr(zone, name, 'NS', rdata)

def get_rr(zone, name, type, api=api):
    rectype = '%srecord' % unicode(type.lower())
    ret = api.Command.dnsrecord_find(unicode(zone), unicode(name))
    if ret['count'] > 0:
        for r in ret['result']:
            if rectype in r:
                return r[rectype]

    return []

def get_fwd_rr(zone, host, api=api):
    return [x for t in ("A", "AAAA") for x in get_rr(zone, host, t, api)]

def zonemgr_callback(option, opt_str, value, parser):
    """
    Properly validate and convert --zonemgr Option to IA5String
    """
    if value is not None:
        # validate the value first
        try:
            # IDNA support requires unicode
            encoding = getattr(sys.stdin, 'encoding', None)
            if encoding is None:
                encoding = 'utf-8'
            value = value.decode(encoding)
            validate_zonemgr_str(value)
        except ValueError, e:
            # FIXME we can do this in better way
            # https://fedorahosted.org/freeipa/ticket/4804
            # decode to proper stderr encoding
            stderr_encoding = getattr(sys.stderr, 'encoding', None)
            if stderr_encoding is None:
                stderr_encoding = 'utf-8'
            error = unicode(e).encode(stderr_encoding)
            parser.error("invalid zonemgr: " + error)

    parser.values.zonemgr = value

def check_reverse_zones(ip_addresses, reverse_zones, options, unattended, search_reverse_zones=False):
    reverse_asked = False

    ret_reverse_zones = []
    # check that there is IP address in every reverse zone
    if reverse_zones:
        for rz in reverse_zones:
            for ip in ip_addresses:
                if verify_reverse_zone(rz, ip):
                    ret_reverse_zones.append(normalize_zone(rz))
                    break
            else:
                # no ip matching reverse zone found
                sys.exit("There is no IP address matching reverse zone %s." % rz)
    if not options.no_reverse:
        # check that there is reverse zone for every IP
        for ip in ip_addresses:
            if search_reverse_zones and find_reverse_zone(str(ip)):
                # reverse zone is already in LDAP
                continue
            for rz in ret_reverse_zones:
                if verify_reverse_zone(rz, ip):
                    # reverse zone was entered by user
                    break
            else:
                # no reverse zone for ip found
                if not reverse_asked:
                    if not unattended and not reverse_zones:
                        # user did not specify reverse_zone nor no_reverse
                        options.no_reverse = not create_reverse()
                        if options.no_reverse:
                            # user decided not to create reverse zone
                            return []
                    reverse_asked = True
                rz = get_reverse_zone_default(str(ip))
                if not unattended:
                    rz = read_reverse_zone(rz, str(ip))
                ret_reverse_zones.append(rz)

    return ret_reverse_zones

def check_forwarders(dns_forwarders, logger):
    print "Checking DNS forwarders, please wait ..."
    forwarders_dnssec_valid = True
    for forwarder in dns_forwarders:
        logger.debug("Checking DNS server: %s", forwarder)
        try:
            validate_dnssec_global_forwarder(forwarder, log=logger)
        except DNSSECSignatureMissingError as e:
            forwarders_dnssec_valid = False
            logger.warning("DNS server %s does not support DNSSEC: %s",
                           forwarder, e)
            logger.warning("Please fix forwarder configuration to enable DNSSEC support.\n"
                "(For BIND 9 add directive \"dnssec-enable yes;\" to \"options {}\")")
            print "DNS server %s: %s" % (forwarder, e)
            print "Please fix forwarder configuration to enable DNSSEC support."
            print "(For BIND 9 add directive \"dnssec-enable yes;\" to \"options {}\")"
        except EDNS0UnsupportedError as e:
            forwarders_dnssec_valid = False
            logger.warning("DNS server %s does not support ENDS0 "
                           "(RFC 6891): %s", forwarder, e)
            logger.warning("Please fix forwarder configuration. "
                           "DNSSEC support cannot be enabled without EDNS0")
            print ("WARNING: DNS server %s does not support EDNS0 "
                   "(RFC 6891): %s" % (forwarder, e))
        except UnresolvableRecordError as e:
            logger.error("DNS server %s: %s", forwarder, e)
            raise RuntimeError("DNS server %s: %s" % (forwarder, e))

    return forwarders_dnssec_valid


class DnsBackup(object):
    def __init__(self, service):
        self.service = service
        self.zones = {}

    def add(self, zone, record_type, host, rdata):
        """
        Backup a DNS record in the file store so it can later be removed.
        """
        if zone not in self.zones:
            zone_id = len(self.zones)
            self.zones[zone] = (zone_id, 0)
            self.service.backup_state("dns_zone_%s" % zone_id, zone)

        (zone_id, record_id) = self.zones[zone]
        self.service.backup_state("dns_record_%s_%s" % (zone_id, record_id),
                                  "%s %s %s" % (record_type, host, rdata))
        self.zones[zone] = (zone_id, record_id + 1)

    def clear_records(self, have_ldap):
        """
        Remove all records from the file store. If we are connected to
        ldap, we will also remove them there.
        """
        i = 0
        while True:
            zone = self.service.restore_state("dns_zone_%s" % i)
            if not zone:
                return

            j = 0
            while True:
                dns_record = self.service.restore_state("dns_record_%s_%s" % (i, j))
                if not dns_record:
                    break
                if have_ldap:
                    type, host, rdata = dns_record.split(" ", 2)
                    try:
                        delkw = { '%srecord' % str(type.lower()) : unicode(rdata) }
                        api.Command.dnsrecord_del(unicode(zone), unicode(host), **delkw)
                    except:
                        pass
                j += 1

            i += 1


class BindInstance(service.Service):
    def __init__(self, fstore=None, dm_password=None, api=api, ldapi=False,
                 start_tls=False, autobind=ipaldap.AUTOBIND_DISABLED):
        service.Service.__init__(
            self, "named",
            service_desc="DNS",
            dm_password=dm_password,
            ldapi=ldapi,
            autobind=autobind,
            start_tls=start_tls
        )
        self.dns_backup = DnsBackup(self)
        self.named_user = None
        self.domain = None
        self.host = None
        self.ip_addresses = []
        self.realm = None
        self.forwarders = None
        self.sub_dict = None
        self.reverse_zones = []
        self.dm_password = dm_password
        self.api = api
        self.named_regular = services.service('named-regular')

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

    suffix = ipautil.dn_attribute_property('_suffix')

    def setup(self, fqdn, ip_addresses, realm_name, domain_name, forwarders, ntp,
              reverse_zones, named_user="named", zonemgr=None,
              ca_configured=None, no_dnssec_validation=False):
        self.named_user = named_user
        self.fqdn = fqdn
        self.ip_addresses = ip_addresses
        self.realm = realm_name
        self.domain = domain_name
        self.forwarders = forwarders
        self.host = fqdn.split(".")[0]
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.ntp = ntp
        self.reverse_zones = reverse_zones
        self.ca_configured = ca_configured
        self.no_dnssec_validation=no_dnssec_validation

        if not zonemgr:
            self.zonemgr = 'hostmaster.%s' % normalize_zone(self.domain)
        else:
            self.zonemgr = normalize_zonemgr(zonemgr)

        self.first_instance = not dns_container_exists(
            self.fqdn, self.suffix, realm=self.realm, ldapi=True,
            dm_password=self.dm_password, autobind=self.autobind)

        self.__setup_sub_dict()

    @property
    def host_domain(self):
        return self.fqdn.split(".", 1)[1]

    @property
    def host_in_rr(self):
        # when a host is not in a default domain, it needs to be referred
        # with FQDN and not in a domain-relative host name
        if not self.host_in_default_domain():
            return normalize_zone(self.fqdn)
        return self.host

    def host_in_default_domain(self):
        return normalize_zone(self.host_domain) == normalize_zone(self.domain)

    def create_sample_bind_zone(self):
        bind_txt = ipautil.template_file(ipautil.SHARE_DIR + "bind.zone.db.template", self.sub_dict)
        [bind_fd, bind_name] = tempfile.mkstemp(".db","sample.zone.")
        os.write(bind_fd, bind_txt)
        os.close(bind_fd)
        print "Sample zone file for bind has been created in "+bind_name

    def create_instance(self):

        try:
            self.stop()
        except:
            pass

        # get a connection to the DS
        self.ldap_connect()

        for ip_address in self.ip_addresses:
            if installutils.record_in_hosts(str(ip_address), self.fqdn) is None:
                installutils.add_record_to_hosts(str(ip_address), self.fqdn)

        # Make sure generate-rndc-key.sh runs before named restart
        self.step("generating rndc key file", self.__generate_rndc_key)

        if self.first_instance:
            self.step("adding DNS container", self.__setup_dns_container)

        if not dns_zone_exists(self.domain):
            self.step("setting up our zone", self.__setup_zone)
        if self.reverse_zones:
            self.step("setting up reverse zone", self.__setup_reverse_zone)

        self.step("setting up our own record", self.__add_self)
        if self.first_instance:
            self.step("setting up records for other masters", self.__add_others)
        # all zones must be created before this step
        self.step("adding NS record to the zones", self.__add_self_ns)
        self.step("setting up CA record", self.__add_ipa_ca_record)

        self.step("setting up kerberos principal", self.__setup_principal)
        self.step("setting up named.conf", self.__setup_named_conf)

        # named has to be started after softhsm initialization
        # self.step("restarting named", self.__start)

        self.step("configuring named to start on boot", self.__enable)
        self.step("changing resolv.conf to point to ourselves", self.__setup_resolv_conf)
        self.start_creation()

    def start_named(self):
        self.print_msg("Restarting named")
        self.__start()

    def __start(self):
        try:
            if self.get_state("running") is None:
                # first time store status
                self.backup_state("running", self.is_running())
            self.restart()
        except Exception as e:
            root_logger.error("Named service failed to start (%s)", e)
            print "named service failed to start"

    def __enable(self):
        if self.get_state("enabled") is None:
            self.backup_state("enabled", self.is_running())
            self.backup_state("named-regular-enabled",
                              self.named_regular.is_running())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        try:
            self.ldap_enable('DNS', self.fqdn, self.dm_password, self.suffix)
        except errors.DuplicateEntry:
            # service already exists (forced DNS reinstall)
            # don't crash, just report error
            root_logger.error("DNS service already exists")

        # disable named, we need to run named-pkcs11 only
        if self.get_state("named-regular-running") is None:
            # first time store status
            self.backup_state("named-regular-running",
                              self.named_regular.is_running())
        try:
            self.named_regular.stop()
        except Exception as e:
            root_logger.debug("Unable to stop named (%s)", e)

        try:
            self.named_regular.mask()
        except Exception as e:
            root_logger.debug("Unable to mask named (%s)", e)

    def __setup_sub_dict(self):
        if self.forwarders:
            fwds = "\n"
            for forwarder in self.forwarders:
                fwds += "\t\t%s;\n" % forwarder
            fwds += "\t"
        else:
            fwds = " "

        if self.ntp:
            optional_ntp =  "\n;ntp server\n"
            optional_ntp += "_ntp._udp\t\tIN SRV 0 100 123\t%s" % self.host_in_rr
        else:
            optional_ntp = ""

        ipa_ca = ""
        for addr in self.ip_addresses:
            if addr.version in (4, 6):
                ipa_ca += "%s\t\t\tIN %s\t\t\t%s\n" % (
                    IPA_CA_RECORD,
                    "A" if addr.version == 4 else "AAAA",
                    str(addr))

        self.sub_dict = dict(
            FQDN=self.fqdn,
            IP=[str(ip) for ip in self.ip_addresses],
            DOMAIN=self.domain,
            HOST=self.host,
            REALM=self.realm,
            SERVER_ID=installutils.realm_to_serverid(self.realm),
            FORWARDERS=fwds,
            SUFFIX=self.suffix,
            OPTIONAL_NTP=optional_ntp,
            ZONEMGR=self.zonemgr,
            IPA_CA_RECORD=ipa_ca,
            BINDKEYS_FILE=paths.NAMED_BINDKEYS_FILE,
            MANAGED_KEYS_DIR=paths.NAMED_MANAGED_KEYS_DIR,
            ROOT_KEY=paths.NAMED_ROOT_KEY,
            NAMED_KEYTAB=paths.NAMED_KEYTAB,
            RFC1912_ZONES=paths.NAMED_RFC1912_ZONES,
            NAMED_PID=paths.NAMED_PID,
            NAMED_VAR_DIR=paths.NAMED_VAR_DIR,
            )

    def __setup_dns_container(self):
        self._ldap_mod("dns.ldif", self.sub_dict)
        self.__fix_dns_privilege_members()

    def __fix_dns_privilege_members(self):
        ldap = api.Backend.ldap2

        cn = 'Update PBAC memberOf %s' % time.time()
        task_dn = DN(('cn', cn), ('cn', 'memberof task'), ('cn', 'tasks'),
                     ('cn', 'config'))
        basedn = DN(api.env.container_privilege, api.env.basedn)
        entry = ldap.make_entry(
            task_dn,
            objectclass=['top', 'extensibleObject'],
            cn=[cn],
            basedn=[basedn],
            filter=['(objectclass=*)'],
            ttl=[10])
        ldap.add_entry(entry)

        start_time = time.time()
        while True:
            try:
                task = ldap.get_entry(task_dn)
            except errors.NotFound:
                break
            if 'nstaskexitcode' in task:
                break
            time.sleep(1)
            if time.time() > (start_time + 60):
                raise errors.TaskTimeout(task='memberof', task_dn=task_dn)

    def __setup_zone(self):
        # Always use force=True as named is not set up yet
        add_zone(self.domain, self.zonemgr, dns_backup=self.dns_backup,
                ns_hostname=api.env.host, force=True)

        add_rr(self.domain, "_kerberos", "TXT", self.realm)

    def __add_self_ns(self):
        # add NS record to all zones
        ns_hostname = normalize_zone(api.env.host)
        result = api.Command.dnszone_find()
        for zone in result['result']:
            zone = unicode(zone['idnsname'][0])  # we need unicode due to backup
            root_logger.debug("adding self NS to zone %s apex", zone)
            add_ns_rr(zone, ns_hostname, self.dns_backup, force=True)

    def __setup_reverse_zone(self):
        # Always use force=True as named is not set up yet
        for reverse_zone in self.reverse_zones:
            add_zone(reverse_zone, self.zonemgr, ns_hostname=api.env.host,
                dns_backup=self.dns_backup, force=True)

    def __add_master_records(self, fqdn, addrs):
        host, zone = fqdn.split(".", 1)

        if normalize_zone(zone) == normalize_zone(self.domain):
            host_in_rr = host
        else:
            host_in_rr = normalize_zone(fqdn)

        srv_records = (
            ("_ldap._tcp", "0 100 389 %s" % host_in_rr),
            ("_kerberos._tcp", "0 100 88 %s" % host_in_rr),
            ("_kerberos._udp", "0 100 88 %s" % host_in_rr),
            ("_kerberos-master._tcp", "0 100 88 %s" % host_in_rr),
            ("_kerberos-master._udp", "0 100 88 %s" % host_in_rr),
            ("_kpasswd._tcp", "0 100 464 %s" % host_in_rr),
            ("_kpasswd._udp", "0 100 464 %s" % host_in_rr),
        )
        if self.ntp:
            srv_records += (
                ("_ntp._udp", "0 100 123 %s" % host_in_rr),
            )

        for (rname, rdata) in srv_records:
            add_rr(self.domain, rname, "SRV", rdata, self.dns_backup, self.api)

        if not dns_zone_exists(zone, self.api):
            # add DNS domain for host first
            root_logger.debug(
                "Host domain (%s) is different from DNS domain (%s)!" % (
                    zone, self.domain))
            root_logger.debug("Add DNS zone for host first.")

            add_zone(zone, self.zonemgr, dns_backup=self.dns_backup,
                     ns_hostname=self.fqdn, force=True, api=self.api)

        # Add forward and reverse records to self
        for addr in addrs:
            add_fwd_rr(zone, host, addr, self.api)

            reverse_zone = find_reverse_zone(addr, self.api)
            if reverse_zone:
                add_ptr_rr(reverse_zone, addr, fqdn, None, self.api)

    def __add_self(self):
        self.__add_master_records(self.fqdn, self.ip_addresses)

    def __add_others(self):
        entries = self.admin_conn.get_entries(
            DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
               self.suffix),
            self.admin_conn.SCOPE_ONELEVEL, None, ['dn'])

        for entry in entries:
            fqdn = entry.dn[0]['cn']
            if fqdn == self.fqdn:
                continue

            addrs = installutils.resolve_host(fqdn)

            root_logger.debug("Adding DNS records for master %s" % fqdn)
            self.__add_master_records(fqdn, addrs)

    def __add_ipa_ca_records(self, fqdn, addrs, ca_configured):
        if ca_configured is False:
            root_logger.debug("CA is not configured")
            return
        elif ca_configured is None:
            # we do not know if CA is configured for this host and we can
            # add the CA record. So we need to find out
            root_logger.debug("Check if CA is enabled for this host")
            base_dn = DN(('cn', fqdn), ('cn', 'masters'), ('cn', 'ipa'),
                         ('cn', 'etc'), self.api.env.basedn)
            ldap_filter = '(&(objectClass=ipaConfigObject)(cn=CA))'
            try:
                self.api.Backend.ldap2.find_entries(filter=ldap_filter, base_dn=base_dn)
            except ipalib.errors.NotFound:
                root_logger.debug("CA is not configured")
                return
            else:
                root_logger.debug("CA is configured for this host")

        try:
            for addr in addrs:
                add_fwd_rr(self.domain, IPA_CA_RECORD, addr, self.api)
        except errors.ValidationError:
            # there is a CNAME record in ipa-ca, we can't add A/AAAA records
            pass

    def __add_ipa_ca_record(self):
        self.__add_ipa_ca_records(self.fqdn, self.ip_addresses,
                                  self.ca_configured)

        if self.first_instance:
            ldap = self.api.Backend.ldap2
            try:
                entries = ldap.get_entries(
                    DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
                       api.env.basedn),
                    ldap.SCOPE_SUBTREE, '(&(objectClass=ipaConfigObject)(cn=CA))',
                    ['dn'])
            except errors.NotFound:
                root_logger.debug('No server with CA found')
                entries = []

            for entry in entries:
                fqdn = entry.dn[1]['cn']
                if fqdn == self.fqdn:
                    continue

                host, zone = fqdn.split('.', 1)
                if dns_zone_exists(zone, self.api):
                    addrs = get_fwd_rr(zone, host, self.api)
                else:
                    addrs = installutils.resolve_host(fqdn)

                self.__add_ipa_ca_records(fqdn, addrs, True)

    def __setup_principal(self):
        dns_principal = "DNS/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(dns_principal)

        # Store the keytab on disk
        self.fstore.backup_file(paths.NAMED_KEYTAB)
        installutils.create_keytab(paths.NAMED_KEYTAB, dns_principal)
        p = self.move_service(dns_principal)
        if p is None:
            # the service has already been moved, perhaps we're doing a DNS reinstall
            dns_principal = DN(('krbprincipalname', dns_principal),
                               ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        else:
            dns_principal = p

        # Make sure access is strictly reserved to the named user
        pent = pwd.getpwnam(self.named_user)
        os.chown(paths.NAMED_KEYTAB, pent.pw_uid, pent.pw_gid)
        os.chmod(paths.NAMED_KEYTAB, 0400)

        # modify the principal so that it is marked as an ipa service so that
        # it can host the memberof attribute, then also add it to the
        # dnsserver role group, this way the DNS is allowed to perform
        # DNS Updates
        dns_group = DN(('cn', 'DNS Servers'), ('cn', 'privileges'), ('cn', 'pbac'), self.suffix)
        mod = [(ldap.MOD_ADD, 'member', dns_principal)]

        try:
            self.admin_conn.modify_s(dns_group, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass
        except Exception, e:
            root_logger.critical("Could not modify principal's %s entry: %s" \
                    % (dns_principal, str(e)))
            raise

        # bind-dyndb-ldap persistent search feature requires both size and time
        # limit-free connection
        mod = [(ldap.MOD_REPLACE, 'nsTimeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsSizeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsIdleTimeout', '-1'),
               (ldap.MOD_REPLACE, 'nsLookThroughLimit', '-1')]
        try:
            self.admin_conn.modify_s(dns_principal, mod)
        except Exception, e:
            root_logger.critical("Could not set principal's %s LDAP limits: %s" \
                    % (dns_principal, str(e)))
            raise

    def __setup_named_conf(self):
        if not self.fstore.has_file(NAMED_CONF):
            self.fstore.backup_file(NAMED_CONF)

        named_txt = ipautil.template_file(ipautil.SHARE_DIR + "bind.named.conf.template", self.sub_dict)
        named_fd = open(NAMED_CONF, 'w')
        named_fd.seek(0)
        named_fd.truncate(0)
        named_fd.write(named_txt)
        named_fd.close()

        if self.no_dnssec_validation:
            # disable validation
            named_conf_set_directive("dnssec-validation", "no",
                                     section=NAMED_SECTION_OPTIONS,
                                     str_val=False)

    def __setup_resolv_conf(self):
        if not self.fstore.has_file(RESOLV_CONF):
            self.fstore.backup_file(RESOLV_CONF)

        resolv_txt = "search "+self.domain+"\n"

        for ip_address in self.ip_addresses:
            if ip_address.version == 4:
                resolv_txt += "nameserver 127.0.0.1\n"
                break

        for ip_address in self.ip_addresses:
            if ip_address.version == 6:
                resolv_txt += "nameserver ::1\n"
                break
        try:
            resolv_fd = open(RESOLV_CONF, 'w')
            resolv_fd.seek(0)
            resolv_fd.truncate(0)
            resolv_fd.write(resolv_txt)
            resolv_fd.close()
        except IOError as e:
            root_logger.error('Could not write to resolv.conf: %s', e)

    def __generate_rndc_key(self):
        installutils.check_entropy()
        ipautil.run(['/usr/libexec/generate-rndc-key.sh'])

    def add_master_dns_records(self, fqdn, ip_addresses, realm_name, domain_name,
                               reverse_zones, ntp=False, ca_configured=None):
        self.fqdn = fqdn
        self.ip_addresses = ip_addresses
        self.realm = realm_name
        self.domain = domain_name
        self.host = fqdn.split(".")[0]
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.ntp = ntp
        self.reverse_zones = reverse_zones
        self.ca_configured = ca_configured
        self.first_instance = False
        self.zonemgr = 'hostmaster.%s' % self.domain

        self.__add_self()
        self.__add_ipa_ca_record()

    def add_ipa_ca_dns_records(self, fqdn, domain_name, ca_configured=True):
        host, zone = fqdn.split(".", 1)
        if dns_zone_exists(zone):
            addrs = get_fwd_rr(zone, host)
        else:
            addrs = installutils.resolve_host(fqdn)

        self.domain = domain_name

        self.__add_ipa_ca_records(fqdn, addrs, ca_configured)

    def convert_ipa_ca_cnames(self, domain_name):
        # get ipa-ca CNAMEs
        cnames = get_rr(domain_name, IPA_CA_RECORD, "CNAME")
        if not cnames:
            return

        root_logger.info('Converting IPA CA CNAME records to A/AAAA records')

        # create CNAME to FQDN mapping
        cname_fqdn = {}
        for cname in cnames:
            if cname.endswith('.'):
                fqdn = cname[:-1]
            else:
                fqdn = '%s.%s' % (cname, domain_name)
            cname_fqdn[cname] = fqdn

        # get FQDNs of all IPA masters
        ldap = api.Backend.ldap2
        try:
            entries = ldap.get_entries(
                DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
                   api.env.basedn),
                ldap.SCOPE_ONELEVEL, None, ['cn'])
            masters = set(e['cn'][0] for e in entries)
        except errors.NotFound:
            masters = set()

        # check if all CNAMEs point to IPA masters
        for cname in cnames:
            fqdn = cname_fqdn[cname]
            if fqdn not in masters:
                root_logger.warning(
                    "Cannot convert IPA CA CNAME records to A/AAAA records, "
                    "please convert them manually if necessary")
                return

        # delete all CNAMEs
        for cname in cnames:
            del_rr(domain_name, IPA_CA_RECORD, "CNAME", cname)

        # add A/AAAA records
        for cname in cnames:
            fqdn = cname_fqdn[cname]
            self.add_ipa_ca_dns_records(fqdn, domain_name, None)

    def remove_master_dns_records(self, fqdn, realm_name, domain_name):
        host, zone = fqdn.split(".", 1)
        self.host = host
        self.fqdn = fqdn
        self.domain = domain_name
        suffix = ipautil.realm_to_suffix(realm_name)

        resource_records = (
            ("_ldap._tcp", "SRV", "0 100 389 %s" % self.host_in_rr),
            ("_kerberos._tcp", "SRV", "0 100 88 %s" % self.host_in_rr),
            ("_kerberos._udp", "SRV", "0 100 88 %s" % self.host_in_rr),
            ("_kerberos-master._tcp", "SRV", "0 100 88 %s" % self.host_in_rr),
            ("_kerberos-master._udp", "SRV", "0 100 88 %s" % self.host_in_rr),
            ("_kpasswd._tcp", "SRV", "0 100 464 %s" % self.host_in_rr),
            ("_kpasswd._udp", "SRV", "0 100 464 %s" % self.host_in_rr),
            ("_ntp._udp", "SRV", "0 100 123 %s" % self.host_in_rr),
        )

        for (record, type, rdata) in resource_records:
            del_rr(self.domain, record, type, rdata)

        areclist = get_fwd_rr(zone, host)
        for rdata in areclist:
            del_fwd_rr(zone, host, rdata)

            rzone = find_reverse_zone(rdata)
            if rzone is not None:
                record = get_reverse_record_name(rzone, rdata)
                del_rr(rzone, record, "PTR", normalize_zone(fqdn))

    def remove_ipa_ca_dns_records(self, fqdn, domain_name):
        host, zone = fqdn.split(".", 1)
        if dns_zone_exists(zone):
            addrs = get_fwd_rr(zone, host)
        else:
            addrs = installutils.resolve_host(fqdn)

        for addr in addrs:
            del_fwd_rr(domain_name, IPA_CA_RECORD, addr)

    def remove_server_ns_records(self, fqdn):
        """
        Remove all NS records pointing to this server
        """
        ldap = api.Backend.ldap2
        ns_rdata = normalize_zone(fqdn)

        # find all NS records pointing to this server
        search_kw = {}
        search_kw['nsrecord'] = ns_rdata
        attr_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        attributes = ['idnsname', 'objectclass']
        dn = DN(api.env.container_dns, api.env.basedn)

        entries, truncated = ldap.find_entries(attr_filter, attributes, base_dn=dn)

        # remove records
        if entries:
            root_logger.debug("Removing all NS records pointing to %s:", ns_rdata)

        for entry in entries:
            if 'idnszone' in entry['objectclass']:
                # zone record
                zone = entry.single_value['idnsname']
                root_logger.debug("zone record %s", zone)
                del_ns_rr(zone, u'@', ns_rdata)
            else:
                zone = entry.dn[1].value  # get zone from DN
                record = entry.single_value['idnsname']
                root_logger.debug("record %s in zone %s", record, zone)
                del_ns_rr(zone, record, ns_rdata)

    def check_global_configuration(self):
        """
        Check global DNS configuration in LDAP server and inform user when it
        set and thus overrides his configured options in named.conf.
        """
        result = api.Command.dnsconfig_show()
        global_conf_set = any(param in result['result'] for \
                              param in api.Object['dnsconfig'].params)

        if not global_conf_set:
            print "Global DNS configuration in LDAP server is empty"
            print "You can use 'dnsconfig-mod' command to set global DNS options that"
            print "would override settings in local named.conf files"
            return

        print "Global DNS configuration in LDAP server is not empty"
        print "The following configuration options override local settings in named.conf:"
        print ""
        textui = ipalib.cli.textui(api)
        api.Command.dnsconfig_show.output_for_cli(textui, result, None, reverse=False)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")
        named_regular_running = self.restore_state("named-regular-running")
        named_regular_enabled = self.restore_state("named-regular-enabled")

        self.dns_backup.clear_records(api.Backend.ldap2.isconnected())


        for f in [NAMED_CONF, RESOLV_CONF]:
            try:
                self.fstore.restore_file(f)
            except ValueError, error:
                root_logger.debug(error)
                pass

        # disabled by default, by ldap_enable()
        if enabled:
            self.enable()

        if running:
            self.restart()

        self.named_regular.unmask()
        if named_regular_enabled:
            self.named_regular.enable()

        if named_regular_running:
            self.named_regular.start()
