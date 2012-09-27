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

import installutils
import ldap
import service
from ipaserver import ipaldap
from ipaserver.install.dsinstance import realm_to_serverid
from ipaserver.install.installutils import resolve_host
from ipapython import sysrestore
from ipapython import ipautil
from ipalib.parameters import IA5Str
from ipalib.util import (validate_zonemgr, normalize_zonemgr,
        get_dns_forward_zone_update_policy, get_dns_reverse_zone_update_policy,
        normalize_zone, get_reverse_zone_default, zone_is_reverse)
from ipapython.ipa_log_manager import *
from ipalib.text import _

import ipalib
from ipalib import api, util, errors
from ipapython.dn import DN

NAMED_CONF = '/etc/named.conf'
RESOLV_CONF = '/etc/resolv.conf'

named_conf_ipa_re = re.compile(r'(?P<indent>\s*)arg\s+"(?P<name>\S+)\s(?P<value>[^"]+)";')
named_conf_ipa_template = "%(indent)sarg \"%(name)s %(value)s\";\n"

def check_inst(unattended):
    has_bind = True
    # So far this file is always present in both RHEL5 and Fedora if all the necessary
    # bind packages are installed (RHEL5 requires also the pkg: caching-nameserver)
    if not os.path.exists('/etc/named.rfc1912.zones'):
        print "BIND was not found on this system"
        print "Please install the 'bind' package and start the installation again"
        has_bind = False

    # Also check for the LDAP BIND plug-in
    if not os.path.exists('/usr/lib/bind/ldap.so') and \
       not os.path.exists('/usr/lib64/bind/ldap.so'):
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

def named_conf_get_directive(name):
    """Get a configuration option in bind-dyndb-ldap section of named.conf"""

    with open(NAMED_CONF, 'r') as f:
        ipa_section = False
        for line in f:
            if line.startswith('dynamic-db "ipa"'):
                ipa_section = True
                continue
            if line.startswith('};'):
                if ipa_section:
                    break

            if ipa_section:
                match = named_conf_ipa_re.match(line)

                if match and name == match.group('name'):
                    return match.group('value')

def named_conf_set_directive(name, value):
    """
    Set configuration option in bind-dyndb-ldap section of named.conf.

    When the configuration option with given name does not exist, it
    is added at the end of ipa section in named.conf.

    If the value is set to None, the configuration option is removed
    from named.conf.
    """
    new_lines = []

    with open(NAMED_CONF, 'r') as f:
        ipa_section = False
        matched = False
        last_indent = "\t"
        for line in f:
            if line.startswith('dynamic-db "ipa"'):
                ipa_section = True
            if line.startswith('};'):
                if ipa_section and not matched:
                    # create a new conf
                    new_conf = named_conf_ipa_template \
                            % dict(indent=last_indent,
                                   name=name,
                                   value=value)
                    new_lines.append(new_conf)
                ipa_section = False

            if ipa_section and not matched:
                match = named_conf_ipa_re.match(line)

                if match:
                    last_indent = match.group('indent')
                    if name == match.group('name'):
                        matched = True
                        if value is not None:
                            if not isinstance(value, basestring):
                                value = str(value)
                            new_conf = named_conf_ipa_template \
                                    % dict(indent=last_indent,
                                           name=name,
                                           value=value)
                            new_lines.append(new_conf)
                        continue
            new_lines.append(line)

    # write new configuration
    with open(NAMED_CONF, 'w') as f:
        f.write("".join(new_lines))

def dns_container_exists(fqdn, suffix, dm_password=None, ldapi=False, realm=None):
    """
    Test whether the dns container exists.
    """

    def object_exists(dn):      # FIXME, this should be a IPAdmin/ldap2 method so it can be shared
        """
        Test whether the given object exists in LDAP.
        """
        assert isinstance(dn, DN)
        try:
            conn.search_ext_s(dn, ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT:
            return False
        else:
            return True

    assert isinstance(suffix, DN)
    try:
        # At install time we may need to use LDAPI to avoid chicken/egg
        # issues with SSL certs and truting CAs
        if ldapi:
            conn = ipaldap.IPAdmin(host=fqdn, ldapi=True, realm=realm)
        else:
            conn = ipaldap.IPAdmin(host=fqdn, port=636, cacert=service.CACERT)

        if dm_password:
            conn.do_simple_bind(bindpw=dm_password)
        else:
            conn.do_sasl_gssapi_bind()
    except ldap.SERVER_DOWN:
        raise RuntimeError('LDAP server on %s is not responding. Is IPA installed?' % fqdn)

    ret = object_exists(DN(('cn', 'dns'), suffix))
    conn.unbind_s()

    return ret

def dns_zone_exists(name):
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
        print "Invalid reverse zone %s" % zone
        return False

    return True

def find_reverse_zone(ip_address):
    ip = netaddr.IPAddress(ip_address)
    zone = normalize_zone(ip.reverse_dns)

    while len(zone) > 0:
        if dns_zone_exists(zone):
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

    return normalize_zone(zone)

def add_zone(name, zonemgr=None, dns_backup=None, ns_hostname=None, ns_ip_address=None,
       update_policy=None):
    if zone_is_reverse(name):
        # always normalize reverse zones
        name = normalize_zone(name)

    if update_policy is None:
        if zone_is_reverse(name):
            update_policy = get_dns_reverse_zone_update_policy(api.env.realm, name)
        else:
            update_policy = get_dns_forward_zone_update_policy(api.env.realm)

    if zonemgr is None:
        zonemgr = 'hostmaster.%s' % name

    if ns_hostname is None:
        # automatically retrieve list of DNS masters
        dns_masters = api.Object.dnsrecord.get_dns_masters()
        if not dns_masters:
            raise installutils.ScriptError(
                "No IPA server with DNS support found!")
        ns_main = dns_masters.pop(0)
        ns_replicas = dns_masters
        addresses = resolve_host(ns_main)

        if len(addresses) > 0:
            # use the first address
            ns_ip_address = addresses[0]
        else:
            ns_ip_address = None
    else:
        ns_main = ns_hostname
        ns_replicas = []
    ns_main = normalize_zone(ns_main)

    if ns_ip_address is not None:
        ns_ip_address = unicode(ns_ip_address)

    try:
        api.Command.dnszone_add(unicode(name),
                                idnssoamname=unicode(ns_main),
                                idnssoarname=unicode(zonemgr),
                                ip_address=ns_ip_address,
                                idnsallowdynupdate=True,
                                idnsupdatepolicy=unicode(update_policy),
                                idnsallowquery=u'any',
                                idnsallowtransfer=u'none',)
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass

    nameservers = ns_replicas + [ns_main]
    for hostname in nameservers:
        add_ns_rr(name, hostname, dns_backup=None, force=True)

def add_rr(zone, name, type, rdata, dns_backup=None, **kwargs):
    addkw = { '%srecord' % str(type.lower()) : unicode(rdata) }
    addkw.update(kwargs)
    try:
        api.Command.dnsrecord_add(unicode(zone), unicode(name), **addkw)
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass
    if dns_backup:
        dns_backup.add(zone, type, name, rdata)

def add_fwd_rr(zone, host, ip_address):
    addr = netaddr.IPAddress(ip_address)
    if addr.version == 4:
        add_rr(zone, host, "A", ip_address)
    elif addr.version == 6:
        add_rr(zone, host, "AAAA", ip_address)

def add_ptr_rr(zone, ip_address, fqdn, dns_backup=None):
    name = get_reverse_record_name(zone, ip_address)
    add_rr(zone, name, "PTR", fqdn+".", dns_backup)

def add_ns_rr(zone, hostname, dns_backup=None, force=True):
    if not hostname.endswith('.'):
        hostname += '.'
    add_rr(zone, "@", "NS", hostname, dns_backup=dns_backup,
            force=force)

def del_rr(zone, name, type, rdata):
    delkw = { '%srecord' % str(type.lower()) : unicode(rdata) }
    try:
        api.Command.dnsrecord_del(unicode(zone), unicode(name), **delkw)
    except (errors.NotFound, errors.EmptyModlist):
        pass

def get_rr(zone, name, type):
    rectype = '%srecord' % unicode(type.lower())
    ret = api.Command.dnsrecord_find(unicode(zone), unicode(name))
    if ret['count'] > 0:
        for r in ret['result']:
            if rectype in r:
                return r[rectype]

    return []

def zonemgr_callback(option, opt_str, value, parser):
    """
    Properly validate and convert --zonemgr Option to IA5String
    """
    # validate the value first
    try:
        validate_zonemgr(value)
    except ValueError, e:
        parser.error("invalid zonemgr: " + unicode(e))

    parser.values.zonemgr = value

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
    def __init__(self, fstore=None, dm_password=None):
        service.Service.__init__(self, "named", dm_password=dm_password, ldapi=False, autobind=service.DISABLED)
        self.dns_backup = DnsBackup(self)
        self.named_user = None
        self.domain = None
        self.host = None
        self.ip_address = None
        self.realm = None
        self.forwarders = None
        self.sub_dict = None
        self.reverse_zone = None
        self.dm_password = dm_password

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    suffix = ipautil.dn_attribute_property('_suffix')

    def setup(self, fqdn, ip_address, realm_name, domain_name, forwarders, ntp,
              reverse_zone, named_user="named", zonemgr=None,
              zone_refresh=0, persistent_search=True, serial_autoincrement=True):
        self.named_user = named_user
        self.fqdn = fqdn
        self.ip_address = ip_address
        self.realm = realm_name
        self.domain = domain_name
        self.forwarders = forwarders
        self.host = fqdn.split(".")[0]
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.ntp = ntp
        self.reverse_zone = reverse_zone
        self.zone_refresh = zone_refresh
        self.persistent_search = persistent_search
        self.serial_autoincrement = serial_autoincrement

        if not zonemgr:
            self.zonemgr = 'hostmaster.%s' % self.domain
        else:
            self.zonemgr = normalize_zonemgr(zonemgr)

        self.__setup_sub_dict()

    @property
    def host_domain(self):
        return '.'.join(self.fqdn.split(".")[1:])

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

        if installutils.record_in_hosts(self.ip_address, self.fqdn) is None:
            installutils.add_record_to_hosts(self.ip_address, self.fqdn)

        if not dns_container_exists(self.fqdn, self.suffix, realm=self.realm,
                                    ldapi=True, dm_password=self.dm_password):
            self.step("adding DNS container", self.__setup_dns_container)
        if dns_zone_exists(self.domain):
            self.step("adding NS record to the zone", self.__add_self_ns)
        else:
            self.step("setting up our zone", self.__setup_zone)
        if self.reverse_zone is not None:
            self.step("setting up reverse zone", self.__setup_reverse_zone)
        self.step("setting up our own record", self.__add_self)

        self.step("setting up kerberos principal", self.__setup_principal)
        self.step("setting up named.conf", self.__setup_named_conf)

        self.step("restarting named", self.__start)
        self.step("configuring named to start on boot", self.__enable)

        self.step("changing resolv.conf to point to ourselves", self.__setup_resolv_conf)
        self.start_creation("Configuring named:")

    def __start(self):
        try:
            self.backup_state("running", self.is_running())
            self.restart()
        except:
            print "named service failed to start"

    def __enable(self):
        self.backup_state("enabled", self.is_running())
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        try:
            self.ldap_enable('DNS', self.fqdn, self.dm_password, self.suffix)
        except errors.DuplicateEntry:
            # service already exists (forced DNS reinstall)
            # don't crash, just report error
            root_logger.error("DNS service already exists")

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

        boolean_var = {}
        for var in ('persistent_search', 'serial_autoincrement'):
            boolean_var[var] = "yes" if getattr(self, var, False) else "no"

        self.sub_dict = dict(FQDN=self.fqdn,
                             IP=self.ip_address,
                             DOMAIN=self.domain,
                             HOST=self.host,
                             REALM=self.realm,
                             SERVER_ID=realm_to_serverid(self.realm),
                             FORWARDERS=fwds,
                             SUFFIX=self.suffix,
                             OPTIONAL_NTP=optional_ntp,
                             ZONEMGR=self.zonemgr,
                             ZONE_REFRESH=self.zone_refresh,
                             PERSISTENT_SEARCH=boolean_var['persistent_search'],
                             SERIAL_AUTOINCREMENT=boolean_var['serial_autoincrement'],)

    def __setup_dns_container(self):
        self._ldap_mod("dns.ldif", self.sub_dict)

    def __setup_zone(self):
        if not self.host_in_default_domain():
            # add DNS domain for host first
            root_logger.debug("Host domain (%s) is different from DNS domain (%s)!" \
                    % (self.host_domain, self.domain))
            root_logger.debug("Add DNS zone for host first.")

            add_zone(self.host_domain, self.zonemgr, dns_backup=self.dns_backup,
                    ns_hostname=api.env.host, ns_ip_address=self.ip_address)
        add_zone(self.domain, self.zonemgr, dns_backup=self.dns_backup,
                ns_hostname=api.env.host, ns_ip_address=self.ip_address)

    def __add_self_ns(self):
        add_ns_rr(self.domain, api.env.host, self.dns_backup, force=True)

    def __add_self(self):
        zone = self.domain
        resource_records = (
            ("_ldap._tcp", "SRV", "0 100 389 %s" % self.host_in_rr),
            ("_kerberos", "TXT", self.realm),
            ("_kerberos._tcp", "SRV", "0 100 88 %s" % self.host_in_rr),
            ("_kerberos._udp", "SRV", "0 100 88 %s" % self.host_in_rr),
            ("_kerberos-master._tcp", "SRV", "0 100 88 %s" % self.host_in_rr),
            ("_kerberos-master._udp", "SRV", "0 100 88 %s" % self.host_in_rr),
            ("_kpasswd._tcp", "SRV", "0 100 464 %s" % self.host_in_rr),
            ("_kpasswd._udp", "SRV", "0 100 464 %s" % self.host_in_rr),
        )

        for (host, type, rdata) in resource_records:
            if type == "SRV":
                add_rr(zone, host, type, rdata, self.dns_backup)
            else:
                add_rr(zone, host, type, rdata)
        if self.ntp:
            add_rr(zone, "_ntp._udp", "SRV", "0 100 123 %s" % self.host_in_rr)

        # Add forward and reverse records to self
        add_fwd_rr(self.host_domain, self.host, self.ip_address)
        if self.reverse_zone is not None and dns_zone_exists(self.reverse_zone):
            add_ptr_rr(self.reverse_zone, self.ip_address, self.fqdn)

    def __setup_reverse_zone(self):
        add_zone(self.reverse_zone, self.zonemgr, ns_hostname=api.env.host,
                ns_ip_address=self.ip_address, dns_backup=self.dns_backup)

    def __setup_principal(self):
        dns_principal = "DNS/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(dns_principal)

        # Store the keytab on disk
        self.fstore.backup_file("/etc/named.keytab")
        installutils.create_keytab("/etc/named.keytab", dns_principal)
        p = self.move_service(dns_principal)
        if p is None:
            # the service has already been moved, perhaps we're doing a DNS reinstall
            dns_principal = DN(('krbprincipalname', dns_principal),
                               ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        else:
            dns_principal = p

        # Make sure access is strictly reserved to the named user
        pent = pwd.getpwnam(self.named_user)
        os.chown("/etc/named.keytab", pent.pw_uid, pent.pw_gid)
        os.chmod("/etc/named.keytab", 0400)

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
        self.fstore.backup_file(NAMED_CONF)
        named_txt = ipautil.template_file(ipautil.SHARE_DIR + "bind.named.conf.template", self.sub_dict)
        named_fd = open(NAMED_CONF, 'w')
        named_fd.seek(0)
        named_fd.truncate(0)
        named_fd.write(named_txt)
        named_fd.close()

    def __setup_resolv_conf(self):
        self.fstore.backup_file(RESOLV_CONF)
        resolv_txt = "search "+self.domain+"\nnameserver "+self.ip_address+"\n"
        resolv_fd = open(RESOLV_CONF, 'w')
        resolv_fd.seek(0)
        resolv_fd.truncate(0)
        resolv_fd.write(resolv_txt)
        resolv_fd.close()

    def add_master_dns_records(self, fqdn, ip_address, realm_name, domain_name,
                               reverse_zone, ntp=False):
        self.fqdn = fqdn
        self.ip_address = ip_address
        self.realm = realm_name
        self.domain = domain_name
        self.host = fqdn.split(".")[0]
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.ntp = ntp
        self.reverse_zone = reverse_zone

        self.__add_self()

    def remove_master_dns_records(self, fqdn, realm_name, domain_name):
        host = fqdn.split(".")[0]
        suffix = ipautil.realm_to_suffix(realm_name)

        zone = domain_name
        resource_records = (
            ("_ldap._tcp", "SRV", "0 100 389 %s" % host),
            ("_kerberos._tcp", "SRV", "0 100 88 %s" % host),
            ("_kerberos._udp", "SRV", "0 100 88 %s" % host),
            ("_kerberos-master._tcp", "SRV", "0 100 88 %s" % host),
            ("_kerberos-master._udp", "SRV", "0 100 88 %s" % host),
            ("_kpasswd._tcp", "SRV", "0 100 464 %s" % host),
            ("_kpasswd._udp", "SRV", "0 100 464 %s" % host),
            ("_ntp._udp", "SRV", "0 100 123 %s" % host),
            ("@", "NS", fqdn+"."),
        )

        for (record, type, rdata) in resource_records:
            del_rr(zone, record, type, rdata)

        areclist = [("A", x) for x in get_rr(zone, host, "A")] + [("AAAA", x) for x in get_rr(zone, host, "AAAA")]
        for (type, rdata) in areclist:
            del_rr(zone, host, type, rdata)

            rzone = find_reverse_zone(rdata)
            if rzone is not None:
                record = get_reverse_record_name(rzone, rdata)
                del_rr(rzone, record, "PTR", fqdn+".")
                # remove also master NS record from the reverse zone
                del_rr(rzone, "@", "NS", fqdn+".")

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
        textui = ipalib.cli.textui()
        api.Command.dnsconfig_show.output_for_cli(textui, result, None, reverse=False)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        self.dns_backup.clear_records(api.Backend.ldap2.isconnected())

        if not running is None:
            self.stop()

        for f in [NAMED_CONF, RESOLV_CONF]:
            try:
                self.fstore.restore_file(f)
            except ValueError, error:
                root_logger.debug(error)
                pass

        if not enabled is None and not enabled:
            self.disable()

        if not running is None and running:
            self.start()
