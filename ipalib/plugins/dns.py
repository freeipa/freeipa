# Authors:
#   Martin Kosek <mkosek@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from __future__ import absolute_import

import netaddr
import time
import re
import binascii
import dns.name
import dns.exception
import dns.rdatatype
import dns.resolver
import encodings.idna

from ipalib.request import context
from ipalib import api, errors, output
from ipalib import Command
from ipalib.capabilities import VERSION_WITHOUT_CAPABILITIES
from ipalib.parameters import (Flag, Bool, Int, Decimal, Str, StrEnum, Any,
                               DeprecatedParam, DNSNameParam)
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
from ipalib import messages
from ipalib.util import (normalize_zonemgr,
                         get_dns_forward_zone_update_policy,
                         get_dns_reverse_zone_update_policy,
                         get_reverse_zone_default, REVERSE_DNS_ZONES,
                         normalize_zone, validate_dnssec_global_forwarder,
                         DNSSECSignatureMissingError, UnresolvableRecordError,
                         EDNS0UnsupportedError, DNSSECValidationError,
                         validate_dnssec_zone_forwarder_step1,
                         validate_dnssec_zone_forwarder_step2)

from ipapython.ipautil import CheckedIPAddress, is_host_resolvable
from ipapython.dnsutil import DNSName

__doc__ = _("""
Domain Name System (DNS)
""") + _("""
Manage DNS zone and resource records.
""") + _("""
SUPPORTED ZONE TYPES

 * Master zone (dnszone-*), contains authoritative data.
 * Forward zone (dnsforwardzone-*), forwards queries to configured forwarders
 (a set of DNS servers).
""") + _("""
USING STRUCTURED PER-TYPE OPTIONS
""") + _("""
There are many structured DNS RR types where DNS data stored in LDAP server
is not just a scalar value, for example an IP address or a domain name, but
a data structure which may be often complex. A good example is a LOC record
[RFC1876] which consists of many mandatory and optional parts (degrees,
minutes, seconds of latitude and longitude, altitude or precision).
""") + _("""
It may be difficult to manipulate such DNS records without making a mistake
and entering an invalid value. DNS module provides an abstraction over these
raw records and allows to manipulate each RR type with specific options. For
each supported RR type, DNS module provides a standard option to manipulate
a raw records with format --<rrtype>-rec, e.g. --mx-rec, and special options
for every part of the RR structure with format --<rrtype>-<partname>, e.g.
--mx-preference and --mx-exchanger.
""") + _("""
When adding a record, either RR specific options or standard option for a raw
value can be used, they just should not be combined in one add operation. When
modifying an existing entry, new RR specific options can be used to change
one part of a DNS record, where the standard option for raw value is used
to specify the modified value. The following example demonstrates
a modification of MX record preference from 0 to 1 in a record without
modifying the exchanger:
ipa dnsrecord-mod --mx-rec="0 mx.example.com." --mx-preference=1
""") + _("""

EXAMPLES:
""") + _("""
 Add new zone:
   ipa dnszone-add example.com --admin-email=admin@example.com
""") + _("""
 Add system permission that can be used for per-zone privilege delegation:
   ipa dnszone-add-permission example.com
""") + _("""
 Modify the zone to allow dynamic updates for hosts own records in realm EXAMPLE.COM:
   ipa dnszone-mod example.com --dynamic-update=TRUE
""") + _("""
   This is the equivalent of:
     ipa dnszone-mod example.com --dynamic-update=TRUE \\
      --update-policy="grant EXAMPLE.COM krb5-self * A; grant EXAMPLE.COM krb5-self * AAAA; grant EXAMPLE.COM krb5-self * SSHFP;"
""") + _("""
 Modify the zone to allow zone transfers for local network only:
   ipa dnszone-mod example.com --allow-transfer=192.0.2.0/24
""") + _("""
 Add new reverse zone specified by network IP address:
   ipa dnszone-add --name-from-ip=192.0.2.0/24
""") + _("""
 Add second nameserver for example.com:
   ipa dnsrecord-add example.com @ --ns-rec=nameserver2.example.com
""") + _("""
 Add a mail server for example.com:
   ipa dnsrecord-add example.com @ --mx-rec="10 mail1"
""") + _("""
 Add another record using MX record specific options:
  ipa dnsrecord-add example.com @ --mx-preference=20 --mx-exchanger=mail2
""") + _("""
 Add another record using interactive mode (started when dnsrecord-add, dnsrecord-mod,
 or dnsrecord-del are executed with no options):
  ipa dnsrecord-add example.com @
  Please choose a type of DNS resource record to be added
  The most common types for this type of zone are: NS, MX, LOC

  DNS resource record type: MX
  MX Preference: 30
  MX Exchanger: mail3
    Record name: example.com
    MX record: 10 mail1, 20 mail2, 30 mail3
    NS record: nameserver.example.com., nameserver2.example.com.
""") + _("""
 Delete previously added nameserver from example.com:
   ipa dnsrecord-del example.com @ --ns-rec=nameserver2.example.com.
""") + _("""
 Add LOC record for example.com:
   ipa dnsrecord-add example.com @ --loc-rec="49 11 42.4 N 16 36 29.6 E 227.64m"
""") + _("""
 Add new A record for www.example.com. Create a reverse record in appropriate
 reverse zone as well. In this case a PTR record "2" pointing to www.example.com
 will be created in zone 2.0.192.in-addr.arpa.
   ipa dnsrecord-add example.com www --a-rec=192.0.2.2 --a-create-reverse
""") + _("""
 Add new PTR record for www.example.com
   ipa dnsrecord-add 2.0.192.in-addr.arpa. 2 --ptr-rec=www.example.com.
""") + _("""
 Add new SRV records for LDAP servers. Three quarters of the requests
 should go to fast.example.com, one quarter to slow.example.com. If neither
 is available, switch to backup.example.com.
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 3 389 fast.example.com"
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 1 389 slow.example.com"
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="1 1 389 backup.example.com"
""") + _("""
 The interactive mode can be used for easy modification:
  ipa dnsrecord-mod example.com _ldap._tcp
  No option to modify specific record provided.
  Current DNS record contents:

  SRV record: 0 3 389 fast.example.com, 0 1 389 slow.example.com, 1 1 389 backup.example.com

  Modify SRV record '0 3 389 fast.example.com'? Yes/No (default No):
  Modify SRV record '0 1 389 slow.example.com'? Yes/No (default No): y
  SRV Priority [0]:                     (keep the default value)
  SRV Weight [1]: 2                     (modified value)
  SRV Port [389]:                       (keep the default value)
  SRV Target [slow.example.com]:        (keep the default value)
  1 SRV record skipped. Only one value per DNS record type can be modified at one time.
    Record name: _ldap._tcp
    SRV record: 0 3 389 fast.example.com, 1 1 389 backup.example.com, 0 2 389 slow.example.com
""") + _("""
 After this modification, three fifths of the requests should go to
 fast.example.com and two fifths to slow.example.com.
""") + _("""
 An example of the interactive mode for dnsrecord-del command:
   ipa dnsrecord-del example.com www
   No option to delete specific record provided.
   Delete all? Yes/No (default No):     (do not delete all records)
   Current DNS record contents:

   A record: 192.0.2.2, 192.0.2.3

   Delete A record '192.0.2.2'? Yes/No (default No):
   Delete A record '192.0.2.3'? Yes/No (default No): y
     Record name: www
     A record: 192.0.2.2               (A record 192.0.2.3 has been deleted)
""") + _("""
 Show zone example.com:
   ipa dnszone-show example.com
""") + _("""
 Find zone with "example" in its domain name:
   ipa dnszone-find example
""") + _("""
 Find records for resources with "www" in their name in zone example.com:
   ipa dnsrecord-find example.com www
""") + _("""
 Find A records with value 192.0.2.2 in zone example.com
   ipa dnsrecord-find example.com --a-rec=192.0.2.2
""") + _("""
 Show records for resource www in zone example.com
   ipa dnsrecord-show example.com www
""") + _("""
 Delegate zone sub.example to another nameserver:
   ipa dnsrecord-add example.com ns.sub --a-rec=203.0.113.1
   ipa dnsrecord-add example.com sub --ns-rec=ns.sub.example.com.
""") + _("""
 Delete zone example.com with all resource records:
   ipa dnszone-del example.com
""") + _("""
 If a global forwarder is configured, all queries for which this server is not
 authoritative (e.g. sub.example.com) will be routed to the global forwarder.
 Global forwarding configuration can be overridden per-zone.
""") + _("""
 Semantics of forwarding in IPA matches BIND semantics and depends on the type
 of zone:
   * Master zone: local BIND replies authoritatively to queries for data in
   the given zone (including authoritative NXDOMAIN answers) and forwarding
   affects only queries for names below zone cuts (NS records) of locally
   served zones.

   * Forward zone: forward zone contains no authoritative data. BIND forwards
   queries, which cannot be answered from its local cache, to configured
   forwarders.
""") + _("""
 Semantics of the --forwarder-policy option:
   * none - disable forwarding for the given zone.
   * first - forward all queries to configured forwarders. If they fail,
   do resolution using DNS root servers.
   * only - forward all queries to configured forwarders and if they fail,
   return failure.
""") + _("""
 Disable global forwarding for given sub-tree:
   ipa dnszone-mod example.com --forward-policy=none
""") + _("""
 This configuration forwards all queries for names outside the example.com
 sub-tree to global forwarders. Normal recursive resolution process is used
 for names inside the example.com sub-tree (i.e. NS records are followed etc.).
""") + _("""
 Forward all requests for the zone external.example.com to another forwarder
 using a "first" policy (it will send the queries to the selected forwarder
 and if not answered it will use global root servers):
   ipa dnsforwardzone-add external.example.com --forward-policy=first \\
                               --forwarder=203.0.113.1
""") + _("""
 Change forward-policy for external.example.com:
   ipa dnsforwardzone-mod external.example.com --forward-policy=only
""") + _("""
 Show forward zone external.example.com:
   ipa dnsforwardzone-show external.example.com
""") + _("""
 List all forward zones:
   ipa dnsforwardzone-find
""") + _("""
 Delete forward zone external.example.com:
   ipa dnsforwardzone-del external.example.com
""") + _("""
 Resolve a host name to see if it exists (will add default IPA domain
 if one is not included):
   ipa dns-resolve www.example.com
   ipa dns-resolve www
""") + _("""

GLOBAL DNS CONFIGURATION
""") + _("""
DNS configuration passed to command line install script is stored in a local
configuration file on each IPA server where DNS service is configured. These
local settings can be overridden with a common configuration stored in LDAP
server:
""") + _("""
 Show global DNS configuration:
   ipa dnsconfig-show
""") + _("""
 Modify global DNS configuration and set a list of global forwarders:
   ipa dnsconfig-mod --forwarder=203.0.113.113
""")

register = Registry()

# supported resource record types
_record_types = (
    u'A', u'AAAA', u'A6', u'AFSDB', u'APL', u'CERT', u'CNAME', u'DHCID', u'DLV',
    u'DNAME', u'DNSKEY', u'DS', u'HIP', u'IPSECKEY', u'KEY', u'KX', u'LOC',
    u'MX', u'NAPTR', u'NS', u'NSEC', u'NSEC3', u'PTR',
    u'RRSIG', u'RP', u'SIG', u'SPF', u'SRV', u'SSHFP', u'TA', u'TKEY',
    u'TLSA', u'TSIG', u'TXT',
)

# DNS zone record identificator
_dns_zone_record = DNSName.empty

# most used record types, always ask for those in interactive prompt
_top_record_types = ('A', 'AAAA', )
_rev_top_record_types = ('PTR', )
_zone_top_record_types = ('NS', 'MX', 'LOC', )

# attributes derived from record types
_record_attributes = [str('%srecord' % t.lower()) for t in _record_types]

# Deprecated
# supported DNS classes, IN = internet, rest is almost never used
_record_classes = (u'IN', u'CS', u'CH', u'HS')

# IN record class
_IN = dns.rdataclass.IN

# NS record type
_NS = dns.rdatatype.from_text('NS')

_output_permissions = (
    output.summary,
    output.Output('result', bool, _('True means the operation was successful')),
    output.Output('value', unicode, _('Permission value')),
)


def _rname_validator(ugettext, zonemgr):
    try:
        DNSName(zonemgr)  # test only if it is valid domain name
    except (ValueError, dns.exception.SyntaxError) as e:
        return unicode(e)
    return None

def _create_zone_serial():
    """
    Generate serial number for zones. bind-dyndb-ldap expects unix time in
    to be used for SOA serial.

    SOA serial in a date format would also work, but it may be set to far
    future when many DNS updates are done per day (more than 100). Unix
    timestamp is more resilient to this issue.
    """
    return int(time.time())

def _reverse_zone_name(netstr):
    try:
        netaddr.IPAddress(str(netstr))
    except (netaddr.AddrFormatError, ValueError):
        pass
    else:
        # use more sensible default prefix than netaddr default
        return unicode(get_reverse_zone_default(netstr))

    net = netaddr.IPNetwork(netstr)
    items = net.ip.reverse_dns.split('.')
    if net.version == 4:
        return u'.'.join(items[4 - net.prefixlen / 8:])
    elif net.version == 6:
        return u'.'.join(items[32 - net.prefixlen / 4:])
    else:
        return None

def _validate_ipaddr(ugettext, ipaddr, ip_version=None):
    try:
        ip = netaddr.IPAddress(str(ipaddr), flags=netaddr.INET_PTON)

        if ip_version is not None:
            if ip.version != ip_version:
                return _('invalid IP address version (is %(value)d, must be %(required_value)d)!') \
                        % dict(value=ip.version, required_value=ip_version)
    except (netaddr.AddrFormatError, ValueError):
        return _('invalid IP address format')
    return None

def _validate_ip4addr(ugettext, ipaddr):
    return _validate_ipaddr(ugettext, ipaddr, 4)

def _validate_ip6addr(ugettext, ipaddr):
    return _validate_ipaddr(ugettext, ipaddr, 6)

def _validate_ipnet(ugettext, ipnet):
    try:
        net = netaddr.IPNetwork(ipnet)
    except (netaddr.AddrFormatError, ValueError, UnboundLocalError):
        return _('invalid IP network format')
    return None

def _validate_bind_aci(ugettext, bind_acis):
    if not bind_acis:
        return

    bind_acis = bind_acis.split(';')
    if bind_acis[-1]:
        return _('each ACL element must be terminated with a semicolon')
    else:
        bind_acis.pop(-1)

    for bind_aci in bind_acis:
        if bind_aci in ("any", "none", "localhost", "localnets"):
            continue

        if bind_aci.startswith('!'):
            bind_aci = bind_aci[1:]

        try:
            ip = CheckedIPAddress(bind_aci, parse_netmask=True,
                                  allow_network=True, allow_loopback=True)
        except (netaddr.AddrFormatError, ValueError), e:
            return unicode(e)
        except UnboundLocalError:
            return _(u"invalid address format")

def _normalize_bind_aci(bind_acis):
    if not bind_acis:
        return
    bind_acis = bind_acis.split(';')
    normalized = []
    for bind_aci in bind_acis:
        if not bind_aci:
            continue
        if bind_aci in ("any", "none", "localhost", "localnets"):
            normalized.append(bind_aci)
            continue

        prefix = ""
        if bind_aci.startswith('!'):
            bind_aci = bind_aci[1:]
            prefix = "!"

        try:
            ip = CheckedIPAddress(bind_aci, parse_netmask=True,
                                  allow_network=True, allow_loopback=True)
            if '/' in bind_aci:    # addr with netmask
                netmask = "/%s" % ip.prefixlen
            else:
                netmask = ""
            normalized.append(u"%s%s%s" % (prefix, str(ip), netmask))
            continue
        except:
            normalized.append(bind_aci)
            continue

    acis = u';'.join(normalized)
    acis += u';'
    return acis

def _validate_bind_forwarder(ugettext, forwarder):
    ip_address, sep, port = forwarder.partition(u' port ')

    ip_address_validation = _validate_ipaddr(ugettext, ip_address)

    if ip_address_validation is not None:
        return ip_address_validation

    if sep:
        try:
            port = int(port)
            if port < 0 or port > 65535:
                raise ValueError()
        except ValueError:
            return _('%(port)s is not a valid port' % dict(port=port))

    return None

def _validate_nsec3param_record(ugettext, value):
    _nsec3param_pattern = (r'^(?P<alg>\d+) (?P<flags>\d+) (?P<iter>\d+) '
        r'(?P<salt>([0-9a-fA-F]{2})+|-)$')
    rec = re.compile(_nsec3param_pattern, flags=re.U)
    result = rec.match(value)

    if result is None:
        return _(u'expected format: <0-255> <0-255> <0-65535> '
                 'even-length_hexadecimal_digits_or_hyphen')

    alg = int(result.group('alg'))
    flags = int(result.group('flags'))
    iterations = int(result.group('iter'))
    salt = result.group('salt')

    if alg > 255:
        return _('algorithm value: allowed interval 0-255')

    if flags > 255:
        return _('flags value: allowed interval 0-255')

    if iterations > 65535:
        return _('iterations value: allowed interval 0-65535')

    if salt == u'-':
        return None

    try:
        binascii.a2b_hex(salt)
    except TypeError, e:
        return _('salt value: %(err)s') % {'err': e}
    return None


def _hostname_validator(ugettext, value):
    assert isinstance(value, DNSName)
    if len(value.make_absolute().labels) < 3:
        return _('invalid domain-name: not fully qualified')

    return None

def _no_wildcard_validator(ugettext, value):
    """Disallow usage of wildcards as RFC 4592 section 4 recommends
    """
    assert isinstance(value, DNSName)
    if value.is_wild():
        return _('should not be a wildcard domain name (RFC 4592 section 4)')
    return None

def is_forward_record(zone, str_address):
    addr = netaddr.IPAddress(str_address)
    if addr.version == 4:
        result = api.Command['dnsrecord_find'](zone, arecord=str_address)
    elif addr.version == 6:
        result = api.Command['dnsrecord_find'](zone, aaaarecord=str_address)
    else:
        raise ValueError('Invalid address family')

    return result['count'] > 0

def add_forward_record(zone, name, str_address):
    addr = netaddr.IPAddress(str_address)
    try:
        if addr.version == 4:
            api.Command['dnsrecord_add'](zone, name, arecord=str_address)
        elif addr.version == 6:
            api.Command['dnsrecord_add'](zone, name, aaaarecord=str_address)
        else:
            raise ValueError('Invalid address family')
    except errors.EmptyModlist:
        pass # the entry already exists and matches

def get_reverse_zone(ipaddr, prefixlen=None):
    ip = netaddr.IPAddress(str(ipaddr))
    revdns = DNSName(unicode(ip.reverse_dns))

    if prefixlen is None:
        revzone = None

        result = api.Command['dnszone_find']()['result']
        for zone in result:
            zonename = zone['idnsname'][0]
            if (revdns.is_subdomain(zonename.make_absolute()) and
               (revzone is None or zonename.is_subdomain(revzone))):
                revzone = zonename
    else:
        if ip.version == 4:
            pos = 4 - prefixlen / 8
        elif ip.version == 6:
            pos = 32 - prefixlen / 4
        items = ip.reverse_dns.split('.')
        revzone = DNSName(items[pos:])

        try:
            api.Command['dnszone_show'](revzone)
        except errors.NotFound:
            revzone = None

    if revzone is None:
        raise errors.NotFound(
            reason=_('DNS reverse zone for IP address %(addr)s not found') % dict(addr=ipaddr)
        )

    revname = revdns.relativize(revzone)

    return revzone, revname

def add_records_for_host_validation(option_name, host, domain, ip_addresses, check_forward=True, check_reverse=True):
    assert isinstance(host, DNSName)
    assert isinstance(domain, DNSName)

    try:
        api.Command['dnszone_show'](domain)['result']
    except errors.NotFound:
        raise errors.NotFound(
            reason=_('DNS zone %(zone)s not found') % dict(zone=domain)
        )
    if not isinstance(ip_addresses, (tuple, list)):
        ip_addresses = [ip_addresses]

    for ip_address in ip_addresses:
        try:
            ip = CheckedIPAddress(ip_address, match_local=False)
        except Exception, e:
            raise errors.ValidationError(name=option_name, error=unicode(e))

        if check_forward:
            if is_forward_record(domain, unicode(ip)):
                raise errors.DuplicateEntry(
                        message=_(u'IP address %(ip)s is already assigned in domain %(domain)s.')\
                            % dict(ip=str(ip), domain=domain))

        if check_reverse:
            try:
                prefixlen = None
                if not ip.defaultnet:
                    prefixlen = ip.prefixlen
                # we prefer lookup of the IP through the reverse zone
                revzone, revname = get_reverse_zone(ip, prefixlen)
                reverse = api.Command['dnsrecord_find'](revzone, idnsname=revname)
                if reverse['count'] > 0:
                    raise errors.DuplicateEntry(
                            message=_(u'Reverse record for IP address %(ip)s already exists in reverse zone %(zone)s.')\
                            % dict(ip=str(ip), zone=revzone))
            except errors.NotFound:
                pass


def add_records_for_host(host, domain, ip_addresses, add_forward=True, add_reverse=True):
    assert isinstance(host, DNSName)
    assert isinstance(domain, DNSName)

    if not isinstance(ip_addresses, (tuple, list)):
        ip_addresses = [ip_addresses]

    for ip_address in ip_addresses:
        ip = CheckedIPAddress(ip_address, match_local=False)

        if add_forward:
            add_forward_record(domain, host, unicode(ip))

        if add_reverse:
            try:
                prefixlen = None
                if not ip.defaultnet:
                    prefixlen = ip.prefixlen
                revzone, revname = get_reverse_zone(ip, prefixlen)
                addkw = {'ptrrecord': host.derelativize(domain).ToASCII()}
                api.Command['dnsrecord_add'](revzone, revname, **addkw)
            except errors.EmptyModlist:
                # the entry already exists and matches
                pass

def _dns_name_to_string(value, raw=False):
    if isinstance(value, unicode):
        try:
            value = DNSName(value)
        except Exception:
            return value

    assert isinstance(value, DNSName)
    if raw:
        return value.ToASCII()
    else:
        return unicode(value)


def _check_entry_objectclass(entry, objectclasses):
    """
    Check if entry contains all objectclasses
    """
    if not isinstance(objectclasses, (list, tuple)):
        objectclasses = [objectclasses, ]
    if not entry.get('objectclass'):
        return False
    entry_objectclasses = [o.lower() for o in entry['objectclass']]
    for o in objectclasses:
        if o not in entry_objectclasses:
            return False
    return True


def _check_DN_objectclass(ldap, dn, objectclasses):
    try:
        entry = ldap.get_entry(dn, [u'objectclass', ])
    except Exception:
        return False
    else:
        return _check_entry_objectclass(entry, objectclasses)


class DNSRecord(Str):
    # a list of parts that create the actual raw DNS record
    parts = None
    # an optional list of parameters used in record-specific operations
    extra = None
    supported = True
    # supported RR types: https://fedorahosted.org/bind-dyndb-ldap/browser/doc/schema

    label_format = _("%s record")
    part_label_format = "%s %s"
    doc_format = _('Raw %s records')
    option_group_format = _('%s Record')
    see_rfc_msg = _("(see RFC %s for details)")
    part_name_format = "%s_part_%s"
    extra_name_format = "%s_extra_%s"
    cli_name_format = "%s_%s"
    format_error_msg = None

    kwargs = Str.kwargs + (
        ('validatedns', bool, True),
        ('normalizedns', bool, True),
    )

    # should be replaced in subclasses
    rrtype = None
    rfc = None

    def __init__(self, name=None, *rules, **kw):
        if self.rrtype not in _record_types:
            raise ValueError("Unknown RR type: %s. Must be one of %s" % \
                    (str(self.rrtype), ", ".join(_record_types)))
        if not name:
            name = "%srecord*" % self.rrtype.lower()
        kw.setdefault('cli_name', '%s_rec' % self.rrtype.lower())
        kw.setdefault('label', self.label_format % self.rrtype)
        kw.setdefault('doc', self.doc_format % self.rrtype)
        kw.setdefault('option_group', self.option_group_format % self.rrtype)
        kw['csv'] = True

        if not self.supported:
            kw['flags'] = ('no_option',)

        super(DNSRecord, self).__init__(name, *rules, **kw)

    def _get_part_values(self, value):
        values = value.split()
        if len(values) != len(self.parts):
            return None
        return tuple(values)

    def _part_values_to_string(self, values, index, idna=True):
        self._validate_parts(values)
        parts = []
        for v in values:
            if v is None:
                continue
            elif isinstance(v, DNSName) and idna:
                v = v.ToASCII()
            elif not isinstance(v, unicode):
                v = unicode(v)
            parts.append(v)

        return u" ".join(parts)

    def get_parts_from_kw(self, kw, raise_on_none=True):
        part_names = tuple(self.part_name_format % (self.rrtype.lower(), part.name) \
                               for part in self.parts)
        vals = tuple(kw.get(part_name) for part_name in part_names)

        if all(val is None for val in vals):
             return

        if raise_on_none:
            for val_id,val in enumerate(vals):
                 if val is None and self.parts[val_id].required:
                    cli_name = self.cli_name_format % (self.rrtype.lower(), self.parts[val_id].name)
                    raise errors.ConversionError(name=self.name,
                                error=_("'%s' is a required part of DNS record") % cli_name)

        return vals

    def _validate_parts(self, parts):
        if len(parts) != len(self.parts):
            raise errors.ValidationError(name=self.name,
                                         error=_("Invalid number of parts!"))

    def _convert_scalar(self, value, index=None):
        if isinstance(value, (tuple, list)):
            return self._part_values_to_string(value, index)
        return super(DNSRecord, self)._convert_scalar(value, index)

    def normalize(self, value):
        if self.normalizedns:
            if isinstance(value, (tuple, list)):
                value = tuple(
                            self._normalize_parts(v) for v in value \
                                    if v is not None
                        )
            elif value is not None:
                value = (self._normalize_parts(value),)

        return super(DNSRecord, self).normalize(value)

    def _normalize_parts(self, value):
        """
        Normalize a DNS record value using normalizers for its parts.
        """
        if self.parts is None:
            return value
        try:
            values = self._get_part_values(value)
            if not values:
                return value

            converted_values = [ part._convert_scalar(values[part_id]) \
                                 if values[part_id] is not None else None
                                 for part_id, part in enumerate(self.parts)
                               ]

            new_values = [ part.normalize(converted_values[part_id]) \
                            for part_id, part in enumerate(self.parts) ]

            value = self._convert_scalar(new_values)
        except Exception:
            # cannot normalize, rather return original value than fail
            pass
        return value

    def _rule_validatedns(self, _, value):
        if not self.validatedns:
            return

        if value is None:
            return

        if value is None:
            return

        if not self.supported:
            return _('DNS RR type "%s" is not supported by bind-dyndb-ldap plugin') \
                     % self.rrtype

        if self.parts is None:
            return

        # validate record format
        values = self._get_part_values(value)
        if not values:
            if not self.format_error_msg:
                part_names = [part.name.upper() for part in self.parts]

                if self.rfc:
                    see_rfc_msg = " " + self.see_rfc_msg % self.rfc
                else:
                    see_rfc_msg = ""
                return _('format must be specified as "%(format)s" %(rfcs)s') \
                    % dict(format=" ".join(part_names), rfcs=see_rfc_msg)
            else:
                return self.format_error_msg

        # validate every part
        for part_id, part in enumerate(self.parts):
            val = part.normalize(values[part_id])
            val = part.convert(val)
            part.validate(val)
        return None

    def _convert_dnsrecord_part(self, part):
        """
        All parts of DNSRecord need to be processed and modified before they
        can be added to global DNS API. For example a prefix need to be added
        before part name so that the name is unique in the global namespace.
        """
        name = self.part_name_format % (self.rrtype.lower(), part.name)
        cli_name = self.cli_name_format % (self.rrtype.lower(), part.name)
        label = self.part_label_format % (self.rrtype, unicode(part.label))
        option_group = self.option_group_format % self.rrtype
        flags = list(part.flags) + ['dnsrecord_part', 'virtual_attribute',]
        if not part.required:
            flags.append('dnsrecord_optional')
        if not self.supported:
            flags.append("no_option")

        return part.clone_rename(name,
                     cli_name=cli_name,
                     label=label,
                     required=False,
                     option_group=option_group,
                     flags=flags,
                     hint=self.name,)   # name of parent RR param

    def _convert_dnsrecord_extra(self, extra):
        """
        Parameters for special per-type behavior need to be processed in the
        same way as record parts in _convert_dnsrecord_part().
        """
        name = self.extra_name_format % (self.rrtype.lower(), extra.name)
        cli_name = self.cli_name_format % (self.rrtype.lower(), extra.name)
        label = self.part_label_format % (self.rrtype, unicode(extra.label))
        option_group = self.option_group_format % self.rrtype
        flags = list(extra.flags) + ['dnsrecord_extra', 'virtual_attribute',]

        return extra.clone_rename(name,
                     cli_name=cli_name,
                     label=label,
                     required=False,
                     option_group=option_group,
                     flags=flags,
                     hint=self.name,)   # name of parent RR param

    def get_parts(self):
        if self.parts is None:
            return tuple()

        return tuple(self._convert_dnsrecord_part(part) for part in self.parts)

    def get_extra(self):
        if self.extra is None:
            return tuple()

        return tuple(self._convert_dnsrecord_extra(extra) for extra in self.extra)

    def __get_part_param(self, cmd, part, output_kw, default=None):
        name = self.part_name_format % (self.rrtype.lower(), part.name)
        label = self.part_label_format % (self.rrtype, unicode(part.label))
        optional = not part.required

        output_kw[name] = cmd.prompt_param(part,
                                           optional=optional,
                                           label=label)

    def prompt_parts(self, cmd, mod_dnsvalue=None):
        mod_parts = None
        if mod_dnsvalue is not None:
            mod_parts = self._get_part_values(mod_dnsvalue)

        user_options = {}
        if self.parts is None:
            return user_options

        for part_id, part in enumerate(self.parts):
            if mod_parts:
                default = mod_parts[part_id]
            else:
                default = None

            self.__get_part_param(cmd, part, user_options, default)

        return user_options

    def prompt_missing_parts(self, cmd, kw, prompt_optional=False):
        user_options = {}
        if self.parts is None:
            return user_options

        for part in self.parts:
            name = self.part_name_format % (self.rrtype.lower(), part.name)

            if name in kw:
                continue

            optional = not part.required
            if optional and not prompt_optional:
                continue

            default = part.get_default(**kw)
            self.__get_part_param(cmd, part, user_options, default)

        return user_options

    # callbacks for per-type special record behavior
    def dnsrecord_add_pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

    def dnsrecord_add_post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)

class ForwardRecord(DNSRecord):
    extra = (
        Flag('create_reverse?',
            label=_('Create reverse'),
            doc=_('Create reverse record for this IP Address'),
            flags=['no_update']
        ),
    )

    def dnsrecord_add_pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        reverse_option = self._convert_dnsrecord_extra(self.extra[0])
        if options.get(reverse_option.name):
            records = entry_attrs.get(self.name, [])
            if not records:
                # --<rrtype>-create-reverse is set, but there are not records
                raise errors.RequirementError(name=self.name)

            for record in records:
                add_records_for_host_validation(self.name, keys[-1], keys[-2], record,
                        check_forward=False,
                        check_reverse=True)

            setattr(context, '%s_reverse' % self.name, entry_attrs.get(self.name))

    def dnsrecord_add_post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        rev_records = getattr(context, '%s_reverse' % self.name, [])

        if rev_records:
            # make sure we don't run this post callback action again in nested
            # commands, line adding PTR record in add_records_for_host
            delattr(context, '%s_reverse' % self.name)
            for record in rev_records:
                try:
                    add_records_for_host(keys[-1], keys[-2], record,
                        add_forward=False, add_reverse=True)
                except Exception, e:
                    raise errors.NonFatalError(
                        reason=_('Cannot create reverse record for "%(value)s": %(exc)s') \
                                % dict(value=record, exc=unicode(e)))

class UnsupportedDNSRecord(DNSRecord):
    """
    Records which are not supported by IPA CLI, but we allow to show them if
    LDAP contains these records.
    """
    supported = False

    def _get_part_values(self, value):
        return tuple()


class ARecord(ForwardRecord):
    rrtype = 'A'
    rfc = 1035
    parts = (
        Str('ip_address',
            _validate_ip4addr,
            label=_('IP Address'),
        ),
    )

class A6Record(DNSRecord):
    rrtype = 'A6'
    rfc = 3226
    parts = (
        Str('data',
            label=_('Record data'),
        ),
    )

    def _get_part_values(self, value):
        # A6 RR type is obsolete and only a raw interface is provided
        return (value,)

class AAAARecord(ForwardRecord):
    rrtype = 'AAAA'
    rfc = 3596
    parts = (
        Str('ip_address',
            _validate_ip6addr,
            label=_('IP Address'),
        ),
    )

class AFSDBRecord(DNSRecord):
    rrtype = 'AFSDB'
    rfc = 1183
    parts = (
        Int('subtype?',
            label=_('Subtype'),
            minvalue=0,
            maxvalue=65535,
        ),
        DNSNameParam('hostname',
            label=_('Hostname'),
        ),
    )

class APLRecord(UnsupportedDNSRecord):
    rrtype = 'APL'
    rfc = 3123

class CERTRecord(DNSRecord):
    rrtype = 'CERT'
    rfc = 4398
    parts = (
        Int('type',
            label=_('Certificate Type'),
            minvalue=0,
            maxvalue=65535,
        ),
        Int('key_tag',
            label=_('Key Tag'),
            minvalue=0,
            maxvalue=65535,
        ),
        Int('algorithm',
            label=_('Algorithm'),
            minvalue=0,
            maxvalue=255,
        ),
        Str('certificate_or_crl',
            label=_('Certificate/CRL'),
        ),
    )

class CNAMERecord(DNSRecord):
    rrtype = 'CNAME'
    rfc = 1035
    parts = (
        DNSNameParam('hostname',
            label=_('Hostname'),
            doc=_('A hostname which this alias hostname points to'),
        ),
    )

class DHCIDRecord(UnsupportedDNSRecord):
    rrtype = 'DHCID'
    rfc = 4701

class DNAMERecord(DNSRecord):
    rrtype = 'DNAME'
    rfc = 2672
    parts = (
        DNSNameParam('target',
            label=_('Target'),
        ),
    )

class DNSKEYRecord(UnsupportedDNSRecord):
    rrtype = 'DNSKEY'
    rfc = 4034

class DSRecord(DNSRecord):
    rrtype = 'DS'
    rfc = 4034
    parts = (
        Int('key_tag',
            label=_('Key Tag'),
            minvalue=0,
            maxvalue=65535,
        ),
        Int('algorithm',
            label=_('Algorithm'),
            minvalue=0,
            maxvalue=255,
        ),
        Int('digest_type',
            label=_('Digest Type'),
            minvalue=0,
            maxvalue=255,
        ),
        Str('digest',
            label=_('Digest'),
            pattern=r'^[0-9a-fA-F]+$',
            pattern_errmsg=u'only hexadecimal digits are allowed'
        ),
    )


class DLVRecord(DSRecord):
    # must use same attributes as DSRecord
    rrtype = 'DLV'
    rfc = 4431


class HIPRecord(UnsupportedDNSRecord):
    rrtype = 'HIP'
    rfc = 5205

class KEYRecord(UnsupportedDNSRecord):
    # managed by BIND itself
    rrtype = 'KEY'
    rfc = 2535

class IPSECKEYRecord(UnsupportedDNSRecord):
    rrtype = 'IPSECKEY'
    rfc = 4025

class KXRecord(DNSRecord):
    rrtype = 'KX'
    rfc = 2230
    parts = (
        Int('preference',
            label=_('Preference'),
            doc=_('Preference given to this exchanger. Lower values are more preferred'),
            minvalue=0,
            maxvalue=65535,
        ),
        DNSNameParam('exchanger',
            label=_('Exchanger'),
            doc=_('A host willing to act as a key exchanger'),
        ),
    )

class LOCRecord(DNSRecord):
    rrtype = 'LOC'
    rfc = 1876
    parts = (
        Int('lat_deg',
            label=_('Degrees Latitude'),
            minvalue=0,
            maxvalue=90,
        ),
        Int('lat_min?',
            label=_('Minutes Latitude'),
            minvalue=0,
            maxvalue=59,
        ),
        Decimal('lat_sec?',
            label=_('Seconds Latitude'),
            minvalue='0.0',
            maxvalue='59.999',
            precision=3,
        ),
        StrEnum('lat_dir',
            label=_('Direction Latitude'),
            values=(u'N', u'S',),
        ),
        Int('lon_deg',
            label=_('Degrees Longitude'),
            minvalue=0,
            maxvalue=180,
        ),
        Int('lon_min?',
            label=_('Minutes Longitude'),
            minvalue=0,
            maxvalue=59,
        ),
        Decimal('lon_sec?',
            label=_('Seconds Longitude'),
            minvalue='0.0',
            maxvalue='59.999',
            precision=3,
        ),
        StrEnum('lon_dir',
            label=_('Direction Longitude'),
            values=(u'E', u'W',),
        ),
        Decimal('altitude',
            label=_('Altitude'),
            minvalue='-100000.00',
            maxvalue='42849672.95',
            precision=2,
        ),
        Decimal('size?',
            label=_('Size'),
            minvalue='0.0',
            maxvalue='90000000.00',
            precision=2,
        ),
        Decimal('h_precision?',
            label=_('Horizontal Precision'),
            minvalue='0.0',
            maxvalue='90000000.00',
            precision=2,
        ),
        Decimal('v_precision?',
            label=_('Vertical Precision'),
            minvalue='0.0',
            maxvalue='90000000.00',
            precision=2,
        ),
    )

    format_error_msg = _("""format must be specified as
    "d1 [m1 [s1]] {"N"|"S"}  d2 [m2 [s2]] {"E"|"W"} alt["m"] [siz["m"] [hp["m"] [vp["m"]]]]"
    where:
       d1:     [0 .. 90]            (degrees latitude)
       d2:     [0 .. 180]           (degrees longitude)
       m1, m2: [0 .. 59]            (minutes latitude/longitude)
       s1, s2: [0 .. 59.999]        (seconds latitude/longitude)
       alt:    [-100000.00 .. 42849672.95] BY .01 (altitude in meters)
       siz, hp, vp: [0 .. 90000000.00] (size/precision in meters)
    See RFC 1876 for details""")

    def _get_part_values(self, value):
        regex = re.compile(
            r'(?P<d1>\d{1,2}\s+)'
            r'(?:(?P<m1>\d{1,2}\s+)'
            r'(?P<s1>\d{1,2}(?:\.\d{1,3})?\s+)?)?'
            r'(?P<dir1>[NS])\s+'
            r'(?P<d2>\d{1,3}\s+)'
            r'(?:(?P<m2>\d{1,2}\s+)'
            r'(?P<s2>\d{1,2}(?:\.\d{1,3})?\s+)?)?'
            r'(?P<dir2>[WE])\s+'
            r'(?P<alt>-?\d{1,8}(?:\.\d{1,2})?)m?'
            r'(?:\s+(?P<siz>\d{1,8}(?:\.\d{1,2})?)m?'
            r'(?:\s+(?P<hp>\d{1,8}(?:\.\d{1,2})?)m?'
            r'(?:\s+(?P<vp>\d{1,8}(?:\.\d{1,2})?)m?\s*)?)?)?$')

        m = regex.match(value)

        if m is None:
            return None

        return tuple(x.strip() if x is not None else x for x in m.groups())

    def _validate_parts(self, parts):
        super(LOCRecord, self)._validate_parts(parts)

        # create part_name -> part_id map first
        part_name_map = dict((part.name, part_id) \
                             for part_id,part in enumerate(self.parts))

        requirements = ( ('lat_sec', 'lat_min'),
                         ('lon_sec', 'lon_min'),
                         ('h_precision', 'size'),
                         ('v_precision', 'h_precision', 'size') )

        for req in requirements:
            target_part = req[0]

            if parts[part_name_map[target_part]] is not None:
                required_parts = req[1:]
                if any(parts[part_name_map[part]] is None for part in required_parts):
                    target_cli_name = self.cli_name_format % (self.rrtype.lower(), req[0])
                    required_cli_names = [ self.cli_name_format % (self.rrtype.lower(), part)
                                           for part in req[1:] ]
                    error = _("'%(required)s' must not be empty when '%(name)s' is set") % \
                                        dict(required=', '.join(required_cli_names),
                                             name=target_cli_name)
                    raise errors.ValidationError(name=self.name, error=error)

class MXRecord(DNSRecord):
    rrtype = 'MX'
    rfc = 1035
    parts = (
        Int('preference',
            label=_('Preference'),
            doc=_('Preference given to this exchanger. Lower values are more preferred'),
            minvalue=0,
            maxvalue=65535,
        ),
        DNSNameParam('exchanger',
            label=_('Exchanger'),
            doc=_('A host willing to act as a mail exchanger'),
        ),
    )

class NSRecord(DNSRecord):
    rrtype = 'NS'
    rfc = 1035

    parts = (
        DNSNameParam('hostname',
            label=_('Hostname'),
        ),
    )

class NSECRecord(UnsupportedDNSRecord):
    # managed by BIND itself
    rrtype = 'NSEC'
    rfc = 4034

class NSEC3Record(UnsupportedDNSRecord):
    rrtype = 'NSEC3'
    rfc = 5155

def _validate_naptr_flags(ugettext, flags):
    allowed_flags = u'SAUP'
    flags = flags.replace('"','').replace('\'','')

    for flag in flags:
        if flag not in allowed_flags:
            return _('flags must be one of "S", "A", "U", or "P"')

class NAPTRRecord(DNSRecord):
    rrtype = 'NAPTR'
    rfc = 2915

    parts = (
        Int('order',
            label=_('Order'),
            minvalue=0,
            maxvalue=65535,
        ),
        Int('preference',
            label=_('Preference'),
            minvalue=0,
            maxvalue=65535,
        ),
        Str('flags',
            _validate_naptr_flags,
            label=_('Flags'),
            normalizer=lambda x:x.upper()
        ),
        Str('service',
            label=_('Service'),
        ),
        Str('regexp',
            label=_('Regular Expression'),
        ),
        Str('replacement',
            label=_('Replacement'),
        ),
    )

class PTRRecord(DNSRecord):
    rrtype = 'PTR'
    rfc = 1035
    parts = (
        DNSNameParam('hostname',
            #RFC 2317 section 5.2 -- can be relative
            label=_('Hostname'),
            doc=_('The hostname this reverse record points to'),
        ),
    )

class RPRecord(UnsupportedDNSRecord):
    rrtype = 'RP'
    rfc = 1183

class SRVRecord(DNSRecord):
    rrtype = 'SRV'
    rfc = 2782
    parts = (
        Int('priority',
            label=_('Priority'),
            minvalue=0,
            maxvalue=65535,
        ),
        Int('weight',
            label=_('Weight'),
            minvalue=0,
            maxvalue=65535,
        ),
        Int('port',
            label=_('Port'),
            minvalue=0,
            maxvalue=65535,
        ),
        DNSNameParam('target',
            label=_('Target'),
            doc=_('The domain name of the target host or \'.\' if the service is decidedly not available at this domain'),
        ),
    )

def _sig_time_validator(ugettext, value):
    time_format = "%Y%m%d%H%M%S"
    try:
        time.strptime(value, time_format)
    except ValueError:
        return _('the value does not follow "YYYYMMDDHHMMSS" time format')


class SIGRecord(UnsupportedDNSRecord):
    # managed by BIND itself
    rrtype = 'SIG'
    rfc = 2535

class SPFRecord(UnsupportedDNSRecord):
    rrtype = 'SPF'
    rfc = 4408

class RRSIGRecord(UnsupportedDNSRecord):
    # managed by BIND itself
    rrtype = 'RRSIG'
    rfc = 4034

class SSHFPRecord(DNSRecord):
    rrtype = 'SSHFP'
    rfc = 4255
    parts = (
        Int('algorithm',
            label=_('Algorithm'),
            minvalue=0,
            maxvalue=255,
        ),
        Int('fp_type',
            label=_('Fingerprint Type'),
            minvalue=0,
            maxvalue=255,
        ),
        Str('fingerprint',
            label=_('Fingerprint'),
        ),
    )

    def _get_part_values(self, value):
        # fingerprint part can contain space in LDAP, return it as one part
        values = value.split(None, 2)
        if len(values) != len(self.parts):
            return None
        return tuple(values)


class TARecord(UnsupportedDNSRecord):
    rrtype = 'TA'


class TLSARecord(DNSRecord):
    rrtype = 'TLSA'
    rfc = 6698
    parts = (
        Int('cert_usage',
            label=_('Certificate Usage'),
            minvalue=0,
            maxvalue=255,
        ),
        Int('selector',
            label=_('Selector'),
            minvalue=0,
            maxvalue=255,
        ),
        Int('matching_type',
            label=_('Matching Type'),
            minvalue=0,
            maxvalue=255,
        ),
        Str('cert_association_data',
            label=_('Certificate Association Data'),
        ),
    )


class TKEYRecord(UnsupportedDNSRecord):
    rrtype = 'TKEY'

class TSIGRecord(UnsupportedDNSRecord):
    rrtype = 'TSIG'

class TXTRecord(DNSRecord):
    rrtype = 'TXT'
    rfc = 1035
    parts = (
        Str('data',
            label=_('Text Data'),
        ),
    )

    def _get_part_values(self, value):
        # ignore any space in TXT record
        return (value,)

_dns_records = (
    ARecord(),
    AAAARecord(),
    A6Record(),
    AFSDBRecord(),
    APLRecord(),
    CERTRecord(),
    CNAMERecord(),
    DHCIDRecord(),
    DLVRecord(),
    DNAMERecord(),
    DNSKEYRecord(),
    DSRecord(),
    HIPRecord(),
    IPSECKEYRecord(),
    KEYRecord(),
    KXRecord(),
    LOCRecord(),
    MXRecord(),
    NAPTRRecord(),
    NSRecord(),
    NSECRecord(),
    NSEC3Record(),
    PTRRecord(),
    RRSIGRecord(),
    RPRecord(),
    SIGRecord(),
    SPFRecord(),
    SRVRecord(),
    SSHFPRecord(),
    TARecord(),
    TLSARecord(),
    TKEYRecord(),
    TSIGRecord(),
    TXTRecord(),
)

def __dns_record_options_iter():
    for opt in (Any('dnsrecords?',
                    label=_('Records'),
                    flags=['no_create', 'no_search', 'no_update'],),
                Str('dnstype?',
                    label=_('Record type'),
                    flags=['no_create', 'no_search', 'no_update'],),
                Str('dnsdata?',
                    label=_('Record data'),
                    flags=['no_create', 'no_search', 'no_update'],)):
        # These 3 options are used in --structured format. They are defined
        # rather in takes_params than has_output_params because of their
        # order - they should be printed to CLI before any DNS part param
        yield opt
    for option in _dns_records:
        yield option

        for part in option.get_parts():
            yield part

        for extra in option.get_extra():
            yield extra

_dns_record_options = tuple(__dns_record_options_iter())
_dns_supported_record_types = tuple(record.rrtype for record in _dns_records \
                                    if record.supported)

def check_ns_rec_resolvable(zone, name):
    assert isinstance(zone, DNSName)
    assert isinstance(name, DNSName)

    if name.is_empty():
        name = zone.make_absolute()
    elif not name.is_absolute():
        # this is a DNS name relative to the zone
        name = name.derelativize(zone.make_absolute())
    try:
        return api.Command['dns_resolve'](unicode(name))
    except errors.NotFound:
        raise errors.NotFound(
            reason=_('Nameserver \'%(host)s\' does not have a corresponding '
                     'A/AAAA record') % {'host': name}
        )

def dns_container_exists(ldap):
    try:
        ldap.get_entry(DN(api.env.container_dns, api.env.basedn), [])
    except errors.NotFound:
        return False
    return True

def default_zone_update_policy(zone):
    if zone.is_reverse():
        return get_dns_reverse_zone_update_policy(api.env.realm, zone.ToASCII())
    else:
        return get_dns_forward_zone_update_policy(api.env.realm)

dnszone_output_params = (
    Str('managedby',
        label=_('Managedby permission'),
    ),
)


def _convert_to_idna(value):
    """
    Function converts a unicode value to idna, without extra validation.
    If conversion fails, None is returned
    """
    assert isinstance(value, unicode)

    try:
        idna_val = value
        start_dot = u''
        end_dot = u''
        if idna_val.startswith(u'.'):
            idna_val = idna_val[1:]
            start_dot = u'.'
        if idna_val.endswith(u'.'):
            idna_val = idna_val[:-1]
            end_dot = u'.'
        idna_val = encodings.idna.nameprep(idna_val)
        idna_val = re.split(r'(?<!\\)\.', idna_val)
        idna_val = u'%s%s%s' % (start_dot,
                                u'.'.join(encodings.idna.ToASCII(x)
                                          for x in idna_val),
                                end_dot)
        return idna_val
    except Exception:
        pass
    return None

def _create_idn_filter(cmd, ldap, *args, **options):
    term = args[-1]
    if term:
        #include idna values to search
        term_idna = _convert_to_idna(term)
        if term_idna and term != term_idna:
            term = (term, term_idna)

    search_kw = {}
    attr_extra_filters = []

    for attr, value in cmd.args_options_2_entry(**options).iteritems():
        if not isinstance(value, list):
            value = [value]
        for i, v in enumerate(value):
            if isinstance(v, DNSName):
                value[i] = v.ToASCII()
            elif attr in map_names_to_records:
                record = map_names_to_records[attr]
                parts = record._get_part_values(v)
                if parts is None:
                    value[i] = v
                    continue
                try:
                    value[i] = record._part_values_to_string(parts, None)
                except errors.ValidationError:
                    value[i] = v

        #create MATCH_ANY filter for multivalue
        if len(value) > 1:
            f = ldap.make_filter({attr: value}, rules=ldap.MATCH_ANY)
            attr_extra_filters.append(f)
        else:
            search_kw[attr] = value

    if cmd.obj.search_attributes:
        search_attrs = cmd.obj.search_attributes
    else:
        search_attrs = cmd.obj.default_attributes
    if cmd.obj.search_attributes_config:
        config = ldap.get_ipa_config()
        config_attrs = config.get(cmd.obj.search_attributes_config, [])
        if len(config_attrs) == 1 and (isinstance(config_attrs[0],
                                                  basestring)):
            search_attrs = config_attrs[0].split(',')

    search_kw['objectclass'] = cmd.obj.object_class
    attr_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
    if attr_extra_filters:
        #combine filter if there is any idna value
        attr_extra_filters.append(attr_filter)
        attr_filter = ldap.combine_filters(attr_extra_filters,
                                           rules=ldap.MATCH_ALL)

    search_kw = {}
    for a in search_attrs:
        search_kw[a] = term
    term_filter = ldap.make_filter(search_kw, exact=False)

    member_filter = cmd.get_member_filter(ldap, **options)

    filter = ldap.combine_filters(
        (term_filter, attr_filter, member_filter), rules=ldap.MATCH_ALL
    )
    return filter


map_names_to_records = {"%srecord" % record.rrtype.lower(): record for record
                        in _dns_records if record.supported}

def _records_idn_postprocess(record, **options):
    for attr in record.keys():
        attr = attr.lower()
        try:
            param = map_names_to_records[attr]
        except KeyError:
            continue
        if not isinstance(param, DNSRecord):
            continue

        part_params = param.get_parts()
        rrs = []
        for dnsvalue in record[attr]:
            parts = param._get_part_values(dnsvalue)
            if parts is None:
                continue
            parts = list(parts)
            try:
                for (i, p) in enumerate(parts):
                    if isinstance(part_params[i], DNSNameParam):
                        parts[i] = DNSName(p)
                rrs.append(param._part_values_to_string(parts, None,
                                            idna=options.get('raw', False)))
            except (errors.ValidationError, errors.ConversionError):
                rrs.append(dnsvalue)
        record[attr] = rrs

def _normalize_zone(zone):
    if isinstance(zone, unicode):
        # normalize only non-IDNA zones
        try:
            return unicode(zone.encode('ascii')).lower()
        except UnicodeError:
            pass
    return zone


def _get_auth_zone_ldap(name):
    """
    Find authoritative zone in LDAP for name. Only active zones are considered.
    :param name:
    :return: (zone, truncated)
    zone: authoritative zone, or None if authoritative zone is not in LDAP
    """
    assert isinstance(name, DNSName)
    ldap = api.Backend.ldap2

    # Create all possible parent zone names
    search_name = name.make_absolute()
    zone_names = []
    for i in xrange(len(search_name)):
        zone_name_abs = DNSName(search_name[i:]).ToASCII()
        zone_names.append(zone_name_abs)
        # compatibility with IPA < 4.0, zone name can be relative
        zone_names.append(zone_name_abs[:-1])

    # Create filters
    objectclass_filter = ldap.make_filter({'objectclass':'idnszone'})
    zonenames_filter = ldap.make_filter({'idnsname': zone_names})
    zoneactive_filter = ldap.make_filter({'idnsZoneActive': 'true'})
    complete_filter = ldap.combine_filters(
        [objectclass_filter, zonenames_filter, zoneactive_filter],
        rules=ldap.MATCH_ALL
    )

    try:
        entries, truncated = ldap.find_entries(
            filter=complete_filter,
            attrs_list=['idnsname'],
            base_dn=DN(api.env.container_dns, api.env.basedn),
            scope=ldap.SCOPE_ONELEVEL
        )
    except errors.NotFound:
        return None, False

    # always use absolute zones
    matched_auth_zones = [entry.single_value['idnsname'].make_absolute()
                          for entry in entries]

    # return longest match
    return max(matched_auth_zones, key=len), truncated


def _get_longest_match_ns_delegation_ldap(zone, name):
    """
    Searches for deepest delegation for name in LDAP zone.

    NOTE: NS record in zone apex is not considered as delegation.
    It returns None if there is no delegation outside of zone apex.

    Example:
    zone: example.com.
    name: ns.sub.example.com.

    records:
        extra.ns.sub.example.com.
        sub.example.com.
        example.com

    result: sub.example.com.

    :param zone: zone name
    :param name:
    :return: (match, truncated);
    match: delegation name if success, or None if no delegation record exists
    """
    assert isinstance(zone, DNSName)
    assert isinstance(name, DNSName)

    ldap = api.Backend.ldap2

    # get zone DN
    zone_dn = api.Object.dnszone.get_dn(zone)

    if name.is_absolute():
        relative_record_name = name.relativize(zone.make_absolute())
    else:
        relative_record_name = name

    # Name is zone apex
    if relative_record_name.is_empty():
        return None, False

    # create list of possible record names
    possible_record_names = [DNSName(relative_record_name[i:]).ToASCII()
                             for i in xrange(len(relative_record_name))]

    # search filters
    name_filter = ldap.make_filter({'idnsname': [possible_record_names]})
    objectclass_filter = ldap.make_filter({'objectclass': 'idnsrecord'})
    complete_filter = ldap.combine_filters(
        [name_filter, objectclass_filter],
        rules=ldap.MATCH_ALL
    )

    try:
        entries, truncated = ldap.find_entries(
            filter=complete_filter,
            attrs_list=['idnsname', 'nsrecord'],
            base_dn=zone_dn,
            scope=ldap.SCOPE_ONELEVEL
        )
    except errors.NotFound:
        return None, False

    matched_records = []

    # test if entry contains NS records
    for entry in entries:
        if entry.get('nsrecord'):
            matched_records.append(entry.single_value['idnsname'])

    if not matched_records:
        return None, truncated

    # return longest match
    return max(matched_records, key=len), truncated


def _find_subtree_forward_zones_ldap(name, child_zones_only=False):
    """
    Search for forwardzone <name> and all child forwardzones
    Filter: (|(*.<name>.)(<name>.))
    :param name:
    :param child_zones_only: search only for child zones
    :return: (list of zonenames,  truncated), list is empty if no zone found
    """
    assert isinstance(name, DNSName)
    ldap = api.Backend.ldap2

    # prepare for filter "*.<name>."
    search_name = u".%s" % name.make_absolute().ToASCII()

    # we need to search zone with and without last dot, due compatibility
    # with IPA < 4.0
    search_names = [search_name, search_name[:-1]]

    # Create filters
    objectclass_filter = ldap.make_filter({'objectclass':'idnsforwardzone'})
    zonenames_filter = ldap.make_filter({'idnsname': search_names}, exact=False,
                                        trailing_wildcard=False)
    if not child_zones_only:
        # find also zone with exact name
        exact_name = name.make_absolute().ToASCII()
        # we need to search zone with and without last dot, due compatibility
        # with IPA < 4.0
        exact_names = [exact_name, exact_name[-1]]
        exact_name_filter = ldap.make_filter({'idnsname': exact_names})
        zonenames_filter = ldap.combine_filters([zonenames_filter,
                                                 exact_name_filter])

    zoneactive_filter = ldap.make_filter({'idnsZoneActive': 'true'})
    complete_filter = ldap.combine_filters(
        [objectclass_filter, zonenames_filter, zoneactive_filter],
        rules=ldap.MATCH_ALL
    )

    try:
        entries, truncated = ldap.find_entries(
            filter=complete_filter,
            attrs_list=['idnsname'],
            base_dn=DN(api.env.container_dns, api.env.basedn),
            scope=ldap.SCOPE_ONELEVEL
        )
    except errors.NotFound:
        return [], False

    result = [entry.single_value['idnsname'].make_absolute()
              for entry in entries]

    return result, truncated


def _get_zone_which_makes_fw_zone_ineffective(fwzonename):
    """
    Check if forward zone is effective.

    If parent zone exists as authoritative zone, the forward zone will not
    forward queries by default. It is necessary to delegate authority
    to forward zone with a NS record.

    Example:

    Forward zone: sub.example.com
    Zone: example.com

    Forwarding will not work, because the server thinks it is authoritative
    for zone and will return NXDOMAIN

    Adding record: sub.example.com NS ns.sub.example.com.
    will delegate authority, and IPA DNS server will forward DNS queries.

    :param fwzonename: forwardzone
    :return: (zone, truncated)
    zone: None if effective, name of authoritative zone otherwise
    """
    assert isinstance(fwzonename, DNSName)

    auth_zone, truncated_zone = _get_auth_zone_ldap(fwzonename)
    if not auth_zone:
        return None, truncated_zone

    delegation_record_name, truncated_ns =\
        _get_longest_match_ns_delegation_ldap(auth_zone, fwzonename)

    truncated = truncated_ns or truncated_zone

    if delegation_record_name:
        return None, truncated

    return auth_zone, truncated


def _add_warning_fw_zone_is_not_effective(result, fwzone, version):
    """
    Adds warning message to result, if required
    """
    authoritative_zone, truncated = \
        _get_zone_which_makes_fw_zone_ineffective(fwzone)
    if authoritative_zone:
        # forward zone is not effective and forwarding will not work
        messages.add_message(
            version, result,
            messages.ForwardzoneIsNotEffectiveWarning(
                fwzone=fwzone, authzone=authoritative_zone,
                ns_rec=fwzone.relativize(authoritative_zone)
            )
        )


class DNSZoneBase(LDAPObject):
    """
    Base class for DNS Zone
    """
    container_dn = api.env.container_dns
    object_class = ['top']
    possible_objectclasses = ['ipadnszone']
    default_attributes = [
        'idnsname', 'idnszoneactive', 'idnsforwarders', 'idnsforwardpolicy'
    ]

    takes_params = (
        DNSNameParam('idnsname',
            _no_wildcard_validator,  # RFC 4592 section 4
            only_absolute=True,
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=lambda name_from_ip: _reverse_zone_name(name_from_ip),
            normalizer=_normalize_zone,
            primary_key=True,
        ),
        Str('name_from_ip?', _validate_ipnet,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
            flags=('virtual_attribute',),
        ),
        Bool('idnszoneactive?',
            cli_name='zone_active',
            label=_('Active zone'),
            doc=_('Is zone active?'),
            flags=['no_create', 'no_update'],
            attribute=True,
        ),
        Str('idnsforwarders*',
            _validate_bind_forwarder,
            cli_name='forwarder',
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified '
                  'for each forwarder using a standard format "IP_ADDRESS port PORT"'),
            csv=True,
        ),
        StrEnum('idnsforwardpolicy?',
            cli_name='forward_policy',
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to '
                  'disable forwarding to global forwarder for this zone. In '
                  'that case, conditional zone forwarders are disregarded.'),
            values=(u'only', u'first', u'none'),
        ),

    )

    def get_dn(self, *keys, **options):
        if not dns_container_exists(self.api.Backend.ldap2):
            raise errors.NotFound(reason=_('DNS is not configured'))

        zone = keys[-1]
        assert isinstance(zone, DNSName)
        assert zone.is_absolute()
        zone_a = zone.ToASCII()

        # special case when zone is the root zone ('.')
        if zone == DNSName.root:
            return super(DNSZoneBase, self).get_dn(zone_a, **options)

        # try first relative name, a new zone has to be added as absolute
        # otherwise ObjectViolation is raised
        zone_a = zone_a[:-1]
        dn = super(DNSZoneBase, self).get_dn(zone_a, **options)
        try:
            self.backend.get_entry(dn, [''])
        except errors.NotFound:
            zone_a = u"%s." % zone_a
            dn = super(DNSZoneBase, self).get_dn(zone_a, **options)

        return dn

    def permission_name(self, zone):
        assert isinstance(zone, DNSName)
        return u"Manage DNS zone %s" % zone.ToASCII()

    def get_name_in_zone(self, zone, hostname):
        """
        Get name of a record that is to be added to a new zone. I.e. when
        we want to add record "ipa.lab.example.com" in a zone "example.com",
        this function should return "ipa.lab". Returns None when record cannot
        be added to a zone. Returns '@' when the hostname is the zone record.
        """
        assert isinstance(zone, DNSName)
        assert zone.is_absolute()
        assert isinstance(hostname, DNSName)

        if not hostname.is_absolute():
            return hostname

        if hostname.is_subdomain(zone):
            return hostname.relativize(zone)

        return None

    def _remove_permission(self, zone):
        permission_name = self.permission_name(zone)
        try:
            api.Command['permission_del'](permission_name, force=True)
        except errors.NotFound, e:
            if zone == DNSName.root:  # special case root zone
                raise
            # compatibility, older IPA versions which allows to create zone
            # without absolute zone name
            permission_name_rel = self.permission_name(
                zone.relativize(DNSName.root)
            )
            try:
                api.Command['permission_del'](permission_name_rel, force=True)
            except errors.NotFound:
                raise e  # re-raise original exception

    def _make_zonename_absolute(self, entry_attrs, **options):
        """
        Zone names can be relative in IPA < 4.0, make sure we always return
        absolute zone name from ldap
        """
        if options.get('raw'):
            return

        if "idnsname" in entry_attrs:
            entry_attrs.single_value['idnsname'] = (
                entry_attrs.single_value['idnsname'].make_absolute())


class DNSZoneBase_add(LDAPCreate):

    has_output_params = LDAPCreate.has_output_params + dnszone_output_params

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        try:
            entry = ldap.get_entry(dn)
        except errors.NotFound:
            pass
        else:
            if _check_entry_objectclass(entry, self.obj.object_class):
                self.obj.handle_duplicate_entry(*keys)
            else:
                raise errors.DuplicateEntry(
                    message=_(u'Only one zone type is allowed per zone name')
                )

        entry_attrs['idnszoneactive'] = 'TRUE'

        return dn


class DNSZoneBase_del(LDAPDelete):

    def pre_callback(self, ldap, dn, *nkeys, **options):
        assert isinstance(dn, DN)
        if not _check_DN_objectclass(ldap, dn, self.obj.object_class):
            self.obj.handle_not_found(*nkeys)
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        try:
            self.obj._remove_permission(keys[-1])
        except errors.NotFound:
            pass

        return True


class DNSZoneBase_mod(LDAPUpdate):
    has_output_params = LDAPUpdate.has_output_params + dnszone_output_params

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj._make_zonename_absolute(entry_attrs, **options)
        return dn


class DNSZoneBase_find(LDAPSearch):
    __doc__ = _('Search for DNS zones (SOA records).')

    has_output_params = LDAPSearch.has_output_params + dnszone_output_params

    def args_options_2_params(self, *args, **options):
        # FIXME: Check that name_from_ip is valid. This is necessary because
        #        custom validation rules, including _validate_ipnet, are not
        #        used when doing a search. Once we have a parameter type for
        #        IP network objects, this will no longer be necessary, as the
        #        parameter type will handle the validation itself (see
        #        <https://fedorahosted.org/freeipa/ticket/2266>).
        if 'name_from_ip' in options:
            self.obj.params['name_from_ip'](unicode(options['name_from_ip']))
        return super(DNSZoneBase_find, self).args_options_2_params(*args, **options)

    def args_options_2_entry(self, *args, **options):
        if 'name_from_ip' in options:
            if 'idnsname' not in options:
                options['idnsname'] = self.obj.params['idnsname'].get_default(**options)
            del options['name_from_ip']
        search_kw = super(DNSZoneBase_find, self).args_options_2_entry(*args,
                                                                   **options)
        name = search_kw.get('idnsname')
        if name:
            search_kw['idnsname'] = [name, name.relativize(DNSName.root)]
        return search_kw

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        # Check if DNS container exists must be here for find methods
        if not dns_container_exists(self.api.Backend.ldap2):
            raise errors.NotFound(reason=_('DNS is not configured'))
        filter = _create_idn_filter(self, ldap, *args, **options)
        return (filter, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry_attrs in entries:
            self.obj._make_zonename_absolute(entry_attrs, **options)
        return truncated


class DNSZoneBase_show(LDAPRetrieve):
    has_output_params = LDAPRetrieve.has_output_params + dnszone_output_params

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if not _check_DN_objectclass(ldap, dn, self.obj.object_class):
            self.obj.handle_not_found(*keys)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj._make_zonename_absolute(entry_attrs, **options)
        return dn


class DNSZoneBase_disable(LDAPQuery):
    has_output = output.standard_value

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        entry = ldap.get_entry(dn, ['idnszoneactive', 'objectclass'])
        if not _check_entry_objectclass(entry, self.obj.object_class):
            self.obj.handle_not_found(*keys)

        entry['idnszoneactive'] = ['FALSE']

        try:
            ldap.update_entry(entry)
        except errors.EmptyModlist:
            pass

        return dict(result=True, value=pkey_to_value(keys[-1], options))


class DNSZoneBase_enable(LDAPQuery):
    has_output = output.standard_value

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        entry = ldap.get_entry(dn, ['idnszoneactive', 'objectclass'])
        if not _check_entry_objectclass(entry, self.obj.object_class):
            self.obj.handle_not_found(*keys)

        entry['idnszoneactive'] = ['TRUE']

        try:
            ldap.update_entry(entry)
        except errors.EmptyModlist:
            pass

        return dict(result=True, value=pkey_to_value(keys[-1], options))


class DNSZoneBase_add_permission(LDAPQuery):
    has_output = _output_permissions
    msg_summary = _('Added system permission "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend
        dn = self.obj.get_dn(*keys, **options)

        try:
            entry_attrs = ldap.get_entry(dn, ['objectclass'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        else:
            if not _check_entry_objectclass(entry_attrs, self.obj.object_class):
                self.obj.handle_not_found(*keys)

        permission_name = self.obj.permission_name(keys[-1])

        # compatibility with older IPA versions which allows relative zonenames
        if keys[-1] != DNSName.root:  # special case root zone
            permission_name_rel = self.obj.permission_name(
                keys[-1].relativize(DNSName.root)
            )
            try:
                api.Object['permission'].get_dn_if_exists(permission_name_rel)
            except errors.NotFound:
                pass
            else:
                # permission exists without absolute domain name
                raise errors.DuplicateEntry(
                    message=_('permission "%(value)s" already exists') % {
                        'value': permission_name
                    }
                )

        permission = api.Command['permission_add_noaci'](permission_name,
                         ipapermissiontype=u'SYSTEM'
                     )['result']

        dnszone_ocs = entry_attrs.get('objectclass')
        if dnszone_ocs:
            for oc in dnszone_ocs:
                if oc.lower() == 'ipadnszone':
                    break
            else:
                dnszone_ocs.append('ipadnszone')

        entry_attrs['managedby'] = [permission['dn']]
        ldap.update_entry(entry_attrs)

        return dict(
            result=True,
            value=pkey_to_value(permission_name, options),
        )


class DNSZoneBase_remove_permission(LDAPQuery):
    has_output = _output_permissions
    msg_summary = _('Removed system permission "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend
        dn = self.obj.get_dn(*keys, **options)
        try:
            entry = ldap.get_entry(dn, ['managedby', 'objectclass'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        else:
            if not _check_entry_objectclass(entry, self.obj.object_class):
                self.obj.handle_not_found(*keys)

        entry['managedby'] = None

        try:
            ldap.update_entry(entry)
        except errors.EmptyModlist:
            # managedBy attribute is clean, lets make sure there is also no
            # dangling DNS zone permission
            pass

        permission_name = self.obj.permission_name(keys[-1])
        self.obj._remove_permission(keys[-1])

        return dict(
            result=True,
            value=pkey_to_value(permission_name, options),
        )


@register()
class dnszone(DNSZoneBase):
    """
    DNS Zone, container for resource records.
    """
    object_name = _('DNS zone')
    object_name_plural = _('DNS zones')
    object_class = DNSZoneBase.object_class + ['idnsrecord', 'idnszone']
    default_attributes = DNSZoneBase.default_attributes + [
        'idnssoamname', 'idnssoarname', 'idnssoaserial', 'idnssoarefresh',
        'idnssoaretry', 'idnssoaexpire', 'idnssoaminimum', 'idnsallowquery',
        'idnsallowtransfer', 'idnssecinlinesigning',
    ] + _record_attributes
    label = _('DNS Zones')
    label_singular = _('DNS Zone')

    takes_params = DNSZoneBase.takes_params + (
        DNSNameParam('idnssoamname?',
            cli_name='name_server',
            label=_('Authoritative nameserver'),
            doc=_('Authoritative nameserver domain name'),
            default=None,  # value will be added in precallback from ldap
        ),
        DNSNameParam('idnssoarname',
            _rname_validator,
            cli_name='admin_email',
            label=_('Administrator e-mail address'),
            doc=_('Administrator e-mail address'),
            default=DNSName(u'hostmaster'),
            normalizer=normalize_zonemgr,
            autofill=True,
        ),
        Int('idnssoaserial',
            cli_name='serial',
            label=_('SOA serial'),
            doc=_('SOA record serial number'),
            minvalue=1,
            maxvalue=4294967295L,
            default_from=_create_zone_serial,
            autofill=True,
        ),
        Int('idnssoarefresh',
            cli_name='refresh',
            label=_('SOA refresh'),
            doc=_('SOA record refresh time'),
            minvalue=0,
            maxvalue=2147483647,
            default=3600,
            autofill=True,
        ),
        Int('idnssoaretry',
            cli_name='retry',
            label=_('SOA retry'),
            doc=_('SOA record retry time'),
            minvalue=0,
            maxvalue=2147483647,
            default=900,
            autofill=True,
        ),
        Int('idnssoaexpire',
            cli_name='expire',
            label=_('SOA expire'),
            doc=_('SOA record expire time'),
            default=1209600,
            minvalue=0,
            maxvalue=2147483647,
            autofill=True,
        ),
        Int('idnssoaminimum',
            cli_name='minimum',
            label=_('SOA minimum'),
            doc=_('How long should negative responses be cached'),
            default=3600,
            minvalue=0,
            maxvalue=2147483647,
            autofill=True,
        ),
        Int('dnsttl?',
            cli_name='ttl',
            label=_('Time to live'),
            doc=_('Time to live for records at zone apex'),
            minvalue=0,
            maxvalue=2147483647, # see RFC 2181
        ),
        StrEnum('dnsclass?',
            # Deprecated
            cli_name='class',
            flags=['no_option'],
            values=_record_classes,
        ),
        Str('idnsupdatepolicy?',
            cli_name='update_policy',
            label=_('BIND update policy'),
            doc=_('BIND update policy'),
            default_from=lambda idnsname: default_zone_update_policy(idnsname),
            autofill=True
        ),
        Bool('idnsallowdynupdate?',
            cli_name='dynamic_update',
            label=_('Dynamic update'),
            doc=_('Allow dynamic updates.'),
            attribute=True,
            default=False,
            autofill=True
        ),
        Str('idnsallowquery?',
            _validate_bind_aci,
            normalizer=_normalize_bind_aci,
            cli_name='allow_query',
            label=_('Allow query'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
            default=u'any;',   # anyone can issue queries by default
            autofill=True,
        ),
        Str('idnsallowtransfer?',
            _validate_bind_aci,
            normalizer=_normalize_bind_aci,
            cli_name='allow_transfer',
            label=_('Allow transfer'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
            default=u'none;',  # no one can issue queries by default
            autofill=True,
        ),
        Bool('idnsallowsyncptr?',
            cli_name='allow_sync_ptr',
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
        Bool('idnssecinlinesigning?',
            cli_name='dnssec',
            default=False,
            label=_('Allow in-line DNSSEC signing'),
            doc=_('Allow inline DNSSEC signing of records in the zone'),
        ),
        Str('nsec3paramrecord?',
            _validate_nsec3param_record,
            cli_name='nsec3param_rec',
            label=_('NSEC3PARAM record'),
            doc=_('NSEC3PARAM record for zone in format: hash_algorithm flags iterations salt'),
            pattern=r'^\d+ \d+ \d+ (([0-9a-fA-F]{2})+|-)$',
            pattern_errmsg=(u'expected format: <0-255> <0-255> <0-65535> '
                 'even-length_hexadecimal_digits_or_hyphen'),
        ),
    )
    # Permissions will be apllied for forwardzones too
    # Store permissions into api.env.basedn, dns container could not exists
    managed_permissions = {
        'System: Add DNS Entries': {
            'non_object': True,
            'ipapermright': {'add'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('idnsname=*', 'cn=dns', api.env.basedn),
            'replaces': [
                '(target = "ldap:///idnsname=*,cn=dns,$SUFFIX")(version 3.0;acl "permission:add dns entries";allow (add) groupdn = "ldap:///cn=add dns entries,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'DNS Administrators', 'DNS Servers'},
        },
        'System: Read DNS Entries': {
            'non_object': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('idnsname=*', 'cn=dns', api.env.basedn),
            'ipapermdefaultattr': {
                'objectclass',
                'a6record', 'aaaarecord', 'afsdbrecord', 'arecord',
                'certrecord', 'cn', 'cnamerecord', 'dlvrecord', 'dnamerecord',
                'dnsclass', 'dnsttl', 'dsrecord', 'hinforecord',
                'idnsallowdynupdate', 'idnsallowquery', 'idnsallowsyncptr',
                'idnsallowtransfer', 'idnsforwarders', 'idnsforwardpolicy',
                'idnsname', 'idnssecinlinesigning', 'idnssoaexpire',
                'idnssoaminimum', 'idnssoamname', 'idnssoarefresh',
                'idnssoaretry', 'idnssoarname', 'idnssoaserial',
                'idnsupdatepolicy', 'idnszoneactive', 'keyrecord', 'kxrecord',
                'locrecord', 'managedby', 'mdrecord', 'minforecord',
                'mxrecord', 'naptrrecord', 'nsecrecord', 'nsec3paramrecord',
                'nsrecord', 'nxtrecord', 'ptrrecord', 'rrsigrecord',
                'sigrecord', 'srvrecord', 'sshfprecord', 'tlsarecord',
                'txtrecord', 'unknownrecord',
            },
            'replaces_system': ['Read DNS Entries'],
            'default_privileges': {'DNS Administrators', 'DNS Servers'},
        },
        'System: Remove DNS Entries': {
            'non_object': True,
            'ipapermright': {'delete'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('idnsname=*', 'cn=dns', api.env.basedn),
            'replaces': [
                '(target = "ldap:///idnsname=*,cn=dns,$SUFFIX")(version 3.0;acl "permission:remove dns entries";allow (delete) groupdn = "ldap:///cn=remove dns entries,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'DNS Administrators', 'DNS Servers'},
        },
        'System: Update DNS Entries': {
            'non_object': True,
            'ipapermright': {'write'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('idnsname=*', 'cn=dns', api.env.basedn),
            'ipapermdefaultattr': {
                'a6record', 'aaaarecord', 'afsdbrecord', 'arecord',
                'certrecord', 'cn', 'cnamerecord', 'dlvrecord', 'dnamerecord',
                'dnsclass', 'dnsttl', 'dsrecord', 'hinforecord',
                'idnsallowdynupdate', 'idnsallowquery', 'idnsallowsyncptr',
                'idnsallowtransfer', 'idnsforwarders', 'idnsforwardpolicy',
                'idnsname', 'idnssecinlinesigning', 'idnssoaexpire',
                'idnssoaminimum', 'idnssoamname', 'idnssoarefresh',
                'idnssoaretry', 'idnssoarname', 'idnssoaserial',
                'idnsupdatepolicy', 'idnszoneactive', 'keyrecord', 'kxrecord',
                'locrecord', 'managedby', 'mdrecord', 'minforecord',
                'mxrecord', 'naptrrecord', 'nsecrecord', 'nsec3paramrecord',
                'nsrecord', 'nxtrecord', 'ptrrecord', 'rrsigrecord',
                'sigrecord', 'srvrecord', 'sshfprecord', 'tlsarecord',
                'txtrecord', 'unknownrecord',
            },
            'replaces': [
                '(targetattr = "idnsname || cn || idnsallowdynupdate || dnsttl || dnsclass || arecord || aaaarecord || a6record || nsrecord || cnamerecord || ptrrecord || srvrecord || txtrecord || mxrecord || mdrecord || hinforecord || minforecord || afsdbrecord || sigrecord || keyrecord || locrecord || nxtrecord || naptrrecord || kxrecord || certrecord || dnamerecord || dsrecord || sshfprecord || rrsigrecord || nsecrecord || idnsname || idnszoneactive || idnssoamname || idnssoarname || idnssoaserial || idnssoarefresh || idnssoaretry || idnssoaexpire || idnssoaminimum || idnsupdatepolicy")(target = "ldap:///idnsname=*,cn=dns,$SUFFIX")(version 3.0;acl "permission:update dns entries";allow (write) groupdn = "ldap:///cn=update dns entries,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetattr = "idnsname || cn || idnsallowdynupdate || dnsttl || dnsclass || arecord || aaaarecord || a6record || nsrecord || cnamerecord || ptrrecord || srvrecord || txtrecord || mxrecord || mdrecord || hinforecord || minforecord || afsdbrecord || sigrecord || keyrecord || locrecord || nxtrecord || naptrrecord || kxrecord || certrecord || dnamerecord || dsrecord || sshfprecord || rrsigrecord || nsecrecord || idnsname || idnszoneactive || idnssoamname || idnssoarname || idnssoaserial || idnssoarefresh || idnssoaretry || idnssoaexpire || idnssoaminimum || idnsupdatepolicy || idnsallowquery || idnsallowtransfer || idnsallowsyncptr || idnsforwardpolicy || idnsforwarders")(target = "ldap:///idnsname=*,cn=dns,$SUFFIX")(version 3.0;acl "permission:update dns entries";allow (write) groupdn = "ldap:///cn=update dns entries,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetattr = "idnsname || cn || idnsallowdynupdate || dnsttl || dnsclass || arecord || aaaarecord || a6record || nsrecord || cnamerecord || ptrrecord || srvrecord || txtrecord || mxrecord || mdrecord || hinforecord || minforecord || afsdbrecord || sigrecord || keyrecord || locrecord || nxtrecord || naptrrecord || kxrecord || certrecord || dnamerecord || dsrecord || sshfprecord || rrsigrecord || nsecrecord || idnsname || idnszoneactive || idnssoamname || idnssoarname || idnssoaserial || idnssoarefresh || idnssoaretry || idnssoaexpire || idnssoaminimum || idnsupdatepolicy || idnsallowquery || idnsallowtransfer || idnsallowsyncptr || idnsforwardpolicy || idnsforwarders || managedby")(target = "ldap:///idnsname=*,cn=dns,$SUFFIX")(version 3.0;acl "permission:update dns entries";allow (write) groupdn = "ldap:///cn=update dns entries,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'DNS Administrators', 'DNS Servers'},
        },
        'System: Read DNSSEC metadata': {
            'non_object': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=dns', api.env.basedn),
            'ipapermtargetfilter': ['(objectclass=idnsSecKey)'],
            'ipapermdefaultattr': {
                'idnsSecAlgorithm', 'idnsSecKeyCreated', 'idnsSecKeyPublish',
                'idnsSecKeyActivate', 'idnsSecKeyInactive', 'idnsSecKeyDelete',
                'idnsSecKeyZone', 'idnsSecKeyRevoke', 'idnsSecKeySep',
                'idnsSecKeyRef', 'cn', 'objectclass',
            },
            'default_privileges': {'DNS Administrators'},
        },
        'System: Manage DNSSEC metadata': {
            'non_object': True,
            'ipapermright': {'all'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=dns', api.env.basedn),
            'ipapermtargetfilter': ['(objectclass=idnsSecKey)'],
            'ipapermdefaultattr': {
                'idnsSecAlgorithm', 'idnsSecKeyCreated', 'idnsSecKeyPublish',
                'idnsSecKeyActivate', 'idnsSecKeyInactive', 'idnsSecKeyDelete',
                'idnsSecKeyZone', 'idnsSecKeyRevoke', 'idnsSecKeySep',
                'idnsSecKeyRef', 'cn', 'objectclass',
            },
            'default_privileges': {'DNS Servers'},
        },
        'System: Manage DNSSEC keys': {
            'non_object': True,
            'ipapermright': {'all'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=keys', 'cn=sec', 'cn=dns', api.env.basedn),
            'ipapermdefaultattr': {
                'ipaPublicKey', 'ipaPrivateKey', 'ipaSecretKey',
                'ipaWrappingMech','ipaWrappingKey',
                'ipaSecretKeyRef', 'ipk11Private', 'ipk11Modifiable', 'ipk11Label',
                'ipk11Copyable', 'ipk11Destroyable', 'ipk11Trusted',
                'ipk11CheckValue', 'ipk11StartDate', 'ipk11EndDate',
                'ipk11UniqueId', 'ipk11PublicKeyInfo', 'ipk11Distrusted',
                'ipk11Subject', 'ipk11Id', 'ipk11Local', 'ipk11KeyType',
                'ipk11Derive', 'ipk11KeyGenMechanism', 'ipk11AllowedMechanisms',
                'ipk11Encrypt', 'ipk11Verify', 'ipk11VerifyRecover', 'ipk11Wrap',
                'ipk11WrapTemplate', 'ipk11Sensitive', 'ipk11Decrypt',
                'ipk11Sign', 'ipk11SignRecover', 'ipk11Unwrap',
                'ipk11Extractable', 'ipk11AlwaysSensitive',
                'ipk11NeverExtractable', 'ipk11WrapWithTrusted',
                'ipk11UnwrapTemplate', 'ipk11AlwaysAuthenticate',
                'objectclass',
            },
            'default_privileges': {'DNS Servers'},
        },
    }

    def _rr_zone_postprocess(self, record, **options):
        #Decode IDN ACE form to Unicode, raw records are passed directly from LDAP
        if options.get('raw', False):
            return
        _records_idn_postprocess(record, **options)

    def _warning_forwarding(self, result, **options):
        if ('idnsforwarders' in result['result']):
            messages.add_message(options.get('version', VERSION_WITHOUT_CAPABILITIES),
                                 result, messages.ForwardersWarning())

    def _warning_dnssec_experimental(self, result, *keys, **options):
        # add warning when user use option --dnssec
        if 'idnssecinlinesigning' in options:
            if options['idnssecinlinesigning'] is True:
                messages.add_message(options['version'], result,
                    messages.DNSSECWarning(
                    additional_info=_("Visit 'http://www.freeipa.org/page/Releases/4.1.0#DNSSEC_Support'.")
                ))
            else:
                messages.add_message(options['version'], result,
                    messages.DNSSECWarning(
                    additional_info=_("If you encounter any problems please "
                    "report them and restart 'named' service on affected IPA "
                    "server.")
                ))

    def _warning_name_server_option(self, result, context, **options):
        if getattr(context, 'show_warning_nameserver_option', False):
            messages.add_message(
                options['version'],
                result, messages.OptionSemanticChangedWarning(
                    label=_(u"setting Authoritative nameserver"),
                    current_behavior=_(u"It is used only for setting the "
                                       u"SOA MNAME attribute."),
                    hint=_(u"NS record(s) can be edited in zone apex - '@'. ")
                )
            )

    def _warning_fw_zone_is_not_effective(self, result, *keys, **options):
        """
        Warning if any operation with zone causes, a child forward zone is
        not effective
        """
        zone = keys[-1]
        affected_fw_zones, truncated = _find_subtree_forward_zones_ldap(
            zone, child_zones_only=True)
        if not affected_fw_zones:
            return

        for fwzone in affected_fw_zones:
            _add_warning_fw_zone_is_not_effective(result, fwzone,
                                                  options['version'])


@register()
class dnszone_add(DNSZoneBase_add):
    __doc__ = _('Create new DNS zone (SOA record).')

    takes_options = DNSZoneBase_add.takes_options + (
        Flag('force',
             label=_('Force'),
             doc=_('Force DNS zone creation even if nameserver is not resolvable.'),
        ),

        # Deprecated
        # ip-address option is not used anymore, we have to keep it
        # due to compability with clients older than 4.1
        Str('ip_address?',
            flags=['no_option', ]
        ),
    )

    def _warning_deprecated_option(self, result, **options):
        if 'ip_address' in options:
            messages.add_message(
                options['version'],
                result,
                messages.OptionDeprecatedWarning(
                    option='ip-address',
                    additional_info=u"Value will be ignored.")
            )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        dn = super(dnszone_add, self).pre_callback(
            ldap, dn, entry_attrs, attrs_list, *keys, **options)

        nameservers = [normalize_zone(x) for x in api.Object.dnsrecord.get_dns_masters()]
        server = normalize_zone(api.env.host)
        zone = keys[-1]

        if entry_attrs.get('idnssoamname'):
            if zone.is_reverse() and not entry_attrs['idnssoamname'].is_absolute():
                raise errors.ValidationError(
                    name='name-server',
                    error=_("Nameserver for reverse zone cannot be a relative DNS name"))

            # verify if user specified server is resolvable
            if not options['force']:
                check_ns_rec_resolvable(keys[0], entry_attrs['idnssoamname'])
            # show warning about --name-server option
            context.show_warning_nameserver_option = True
        else:
            # user didn't specify SOA mname
            if server in nameservers:
                # current ipa server is authoritative nameserver in SOA record
                entry_attrs['idnssoamname'] = [server]
            else:
                # a first DNS capable server is authoritative nameserver in SOA record
                entry_attrs['idnssoamname'] = [nameservers[0]]

        # all ipa DNS servers should be in NS zone record (as absolute domain name)
        entry_attrs['nsrecord'] = nameservers

        return dn

    def execute(self, *keys, **options):
        result = super(dnszone_add, self).execute(*keys, **options)
        self._warning_deprecated_option(result, **options)
        self.obj._warning_forwarding(result, **options)
        self.obj._warning_dnssec_experimental(result, *keys, **options)
        self.obj._warning_name_server_option(result, context, **options)
        self.obj._warning_fw_zone_is_not_effective(result, *keys, **options)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)

        # Add entry to realmdomains
        # except for our own domain, forward zones, reverse zones and root zone
        zone = keys[0]

        if (zone != DNSName(api.env.domain).make_absolute() and
                not options.get('idnsforwarders') and
                not zone.is_reverse() and
                zone != DNSName.root):
            try:
                api.Command['realmdomains_mod'](add_domain=unicode(zone),
                                                force=True)
            except (errors.EmptyModlist, errors.ValidationError):
                pass

        self.obj._rr_zone_postprocess(entry_attrs, **options)
        return dn



@register()
class dnszone_del(DNSZoneBase_del):
    __doc__ = _('Delete DNS zone (SOA record).')

    msg_summary = _('Deleted DNS zone "%(value)s"')

    def execute(self, *keys, **options):
        result = super(dnszone_del, self).execute(*keys, **options)
        nkeys = keys[-1]  # we can delete more zones
        for key in nkeys:
            self.obj._warning_fw_zone_is_not_effective(result, key, **options)
        return result

    def post_callback(self, ldap, dn, *keys, **options):
        super(dnszone_del, self).post_callback(ldap, dn, *keys, **options)

        # Delete entry from realmdomains
        # except for our own domain, reverse zone, and root zone
        zone = keys[0].make_absolute()

        if (zone != DNSName(api.env.domain).make_absolute() and
                not zone.is_reverse() and zone != DNSName.root
        ):
            try:
                api.Command['realmdomains_mod'](del_domain=unicode(zone),
                                                force=True)
            except (errors.AttrValueNotFound, errors.ValidationError):
                pass

        return True



@register()
class dnszone_mod(DNSZoneBase_mod):
    __doc__ = _('Modify DNS zone (SOA record).')

    takes_options = DNSZoneBase_mod.takes_options + (
        Flag('force',
             label=_('Force'),
             doc=_('Force nameserver change even if nameserver not in DNS'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list,  *keys, **options):
        if not _check_DN_objectclass(ldap, dn, self.obj.object_class):
            self.obj.handle_not_found(*keys)
        if 'idnssoamname' in entry_attrs:
            nameserver = entry_attrs['idnssoamname']
            if nameserver:
                if not nameserver.is_empty() and not options['force']:
                    check_ns_rec_resolvable(keys[0], nameserver)
                context.show_warning_nameserver_option = True
            else:
                # empty value, this option is required by ldap
                raise errors.ValidationError(
                    name='name_server',
                    error=_(u"is required"))

        return dn

    def execute(self, *keys, **options):
        result = super(dnszone_mod, self).execute(*keys, **options)
        self.obj._warning_forwarding(result, **options)
        self.obj._warning_dnssec_experimental(result, *keys, **options)
        self.obj._warning_name_server_option(result, context, **options)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        dn = super(dnszone_mod, self).post_callback(ldap, dn, entry_attrs,
                                                    *keys, **options)
        self.obj._rr_zone_postprocess(entry_attrs, **options)
        return dn


@register()
class dnszone_find(DNSZoneBase_find):
    __doc__ = _('Search for DNS zones (SOA records).')

    takes_options = DNSZoneBase_find.takes_options + (
        Flag('forward_only',
            label=_('Forward zones only'),
            cli_name='forward_only',
            doc=_('Search for forward zones only'),
        ),
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)

        filter, base, dn = super(dnszone_find, self).pre_callback(ldap, filter,
            attrs_list, base_dn, scope, *args, **options)

        if options.get('forward_only', False):
            search_kw = {}
            search_kw['idnsname'] = [revzone.ToASCII() for revzone in
                                     REVERSE_DNS_ZONES.keys()]
            rev_zone_filter = ldap.make_filter(search_kw,
                                               rules=ldap.MATCH_NONE,
                                               exact=False,
                                               trailing_wildcard=False)
            filter = ldap.combine_filters((rev_zone_filter, filter),
                                          rules=ldap.MATCH_ALL)

        return (filter, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        truncated = super(dnszone_find, self).post_callback(ldap, entries,
                                                            truncated, *args,
                                                            **options)
        for entry_attrs in entries:
            self.obj._rr_zone_postprocess(entry_attrs, **options)
        return truncated



@register()
class dnszone_show(DNSZoneBase_show):
    __doc__ = _('Display information about a DNS zone (SOA record).')

    def execute(self, *keys, **options):
        result = super(dnszone_show, self).execute(*keys, **options)
        self.obj._warning_forwarding(result, **options)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        dn = super(dnszone_show, self).post_callback(ldap, dn, entry_attrs,
                                                     *keys, **options)
        self.obj._rr_zone_postprocess(entry_attrs, **options)
        return dn



@register()
class dnszone_disable(DNSZoneBase_disable):
    __doc__ = _('Disable DNS Zone.')
    msg_summary = _('Disabled DNS zone "%(value)s"')

    def execute(self, *keys, **options):
        result = super(dnszone_disable, self).execute(*keys, **options)
        self.obj._warning_fw_zone_is_not_effective(result, *keys, **options)
        return result


@register()
class dnszone_enable(DNSZoneBase_enable):
    __doc__ = _('Enable DNS Zone.')
    msg_summary = _('Enabled DNS zone "%(value)s"')

    def execute(self, *keys, **options):
        result = super(dnszone_enable, self).execute(*keys, **options)
        self.obj._warning_fw_zone_is_not_effective(result, *keys, **options)
        return result


@register()
class dnszone_add_permission(DNSZoneBase_add_permission):
    __doc__ = _('Add a permission for per-zone access delegation.')


@register()
class dnszone_remove_permission(DNSZoneBase_remove_permission):
    __doc__ = _('Remove a permission for per-zone access delegation.')


@register()
class dnsrecord(LDAPObject):
    """
    DNS record.
    """
    parent_object = 'dnszone'
    container_dn = api.env.container_dns
    object_name = _('DNS resource record')
    object_name_plural = _('DNS resource records')
    object_class = ['top', 'idnsrecord']
    permission_filter_objectclasses = ['idnsrecord']
    default_attributes = ['idnsname'] + _record_attributes
    rdn_is_primary_key = True

    label = _('DNS Resource Records')
    label_singular = _('DNS Resource Record')

    takes_params = (
        DNSNameParam('idnsname',
            cli_name='name',
            label=_('Record name'),
            doc=_('Record name'),
            primary_key=True,
        ),
        Int('dnsttl?',
            cli_name='ttl',
            label=_('Time to live'),
            doc=_('Time to live'),
        ),
        StrEnum('dnsclass?',
            # Deprecated
            cli_name='class',
            flags=['no_option'],
            values=_record_classes,
        ),
    ) + _dns_record_options

    structured_flag = Flag('structured',
                           label=_('Structured'),
                           doc=_('Parse all raw DNS records and return them in a structured way'),
                           )

    def _dsrecord_pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        dsrecords = entry_attrs.get('dsrecord')
        if dsrecords and self.is_pkey_zone_record(*keys):
            raise errors.ValidationError(
                name='dsrecord',
                error=unicode(_('DS record must not be in zone apex (RFC 4035 section 2.4)')))

    def _nsrecord_pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        nsrecords = entry_attrs.get('nsrecord')
        if options.get('force', False) or nsrecords is None:
            return
        for nsrecord in nsrecords:
            check_ns_rec_resolvable(keys[0], DNSName(nsrecord))

    def _idnsname_pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if keys[-1].is_absolute():
            if keys[-1].is_subdomain(keys[-2]):
                entry_attrs['idnsname'] = [keys[-1].relativize(keys[-2])]
            elif not self.is_pkey_zone_record(*keys):
                raise errors.ValidationError(name='idnsname',
                        error=unicode(_('out-of-zone data: record name must '
                                        'be a subdomain of the zone or a '
                                        'relative name')))
        # dissallowed wildcard (RFC 4592 section 4)
        no_wildcard_rtypes = ['DNAME', 'DS', 'NS']
        if (keys[-1].is_wild() and
            any(entry_attrs.get('%srecord' % r.lower())
            for r in no_wildcard_rtypes)
        ):
            raise errors.ValidationError(
                name='idnsname',
                error=(_('owner of %(types)s records '
                    'should not be a wildcard domain name (RFC 4592 section 4)') %
                    {'types': ', '.join(no_wildcard_rtypes)}
                )
            )

    def _ptrrecord_pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        ptrrecords = entry_attrs.get('ptrrecord')
        if ptrrecords is None:
            return

        zone = keys[-2]
        if self.is_pkey_zone_record(*keys):
            addr = _dns_zone_record
        else:
            addr = keys[-1]

        zone_len = 0
        for valid_zone in REVERSE_DNS_ZONES:
            if zone.is_subdomain(valid_zone):
                zone = zone.relativize(valid_zone)
                zone_name = valid_zone
                zone_len = REVERSE_DNS_ZONES[valid_zone]

        if not zone_len:
            allowed_zones = ', '.join([unicode(revzone) for revzone in
                                       REVERSE_DNS_ZONES.keys()])
            raise errors.ValidationError(name='ptrrecord',
                    error=unicode(_('Reverse zone for PTR record should be a sub-zone of one the following fully qualified domains: %s') % allowed_zones))

        addr_len = len(addr.labels)

        # Classless zones (0/25.0.0.10.in-addr.arpa.) -> skip check
        # zone has to be checked without reverse domain suffix (in-addr.arpa.)
        for sign in ('/', '-'):
            for name in (zone, addr):
                for label in name.labels:
                    if sign in label:
                        return

        ip_addr_comp_count = addr_len + len(zone.labels)
        if ip_addr_comp_count != zone_len:
            raise errors.ValidationError(name='ptrrecord',
                error=unicode(_('Reverse zone %(name)s requires exactly '
                                '%(count)d IP address components, '
                                '%(user_count)d given')
                % dict(name=zone_name,
                       count=zone_len,
                       user_count=ip_addr_comp_count)))

    def run_precallback_validators(self, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        ldap = self.api.Backend.ldap2

        for rtype in entry_attrs.keys():
            rtype_cb = getattr(self, '_%s_pre_callback' % rtype, None)
            if rtype_cb:
                rtype_cb(ldap, dn, entry_attrs, *keys, **options)

    def is_pkey_zone_record(self, *keys):
        assert isinstance(keys[-1], DNSName)
        assert isinstance(keys[-2], DNSName)
        idnsname = keys[-1]
        zonename = keys[-2]
        if idnsname.is_empty() or idnsname == zonename:
            return True
        return False

    def check_zone(self, zone, **options):
        """
        Check if zone exists and if is master zone
        """
        parent_object = self.api.Object[self.parent_object]
        dn = parent_object.get_dn(zone, **options)
        ldap = self.api.Backend.ldap2
        try:
            entry = ldap.get_entry(dn, ['objectclass'])
        except errors.NotFound:
            parent_object.handle_not_found(zone)
        else:
            # only master zones can contain records
            if 'idnszone' not in [x.lower() for x in entry.get('objectclass', [])]:
                raise errors.ValidationError(
                    name='dnszoneidnsname',
                    error=_(u'only master zones can contain records')
                )
        return dn


    def get_dn(self, *keys, **options):
        if not dns_container_exists(self.api.Backend.ldap2):
            raise errors.NotFound(reason=_('DNS is not configured'))

        dn = self.check_zone(keys[-2], **options)

        if self.is_pkey_zone_record(*keys):
            return dn

        #Make RR name relative if possible
        relative_name = keys[-1].relativize(keys[-2]).ToASCII()
        keys = keys[:-1] + (relative_name,)
        return super(dnsrecord, self).get_dn(*keys, **options)

    def attr_to_cli(self, attr):
        try:
            cliname = attr[:-len('record')].upper()
        except IndexError:
            cliname = attr
        return cliname

    def get_dns_masters(self):
        ldap = self.api.Backend.ldap2
        base_dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), self.api.env.basedn)
        ldap_filter = '(&(objectClass=ipaConfigObject)(cn=DNS))'
        dns_masters = []

        try:
            entries = ldap.find_entries(filter=ldap_filter, base_dn=base_dn)[0]

            for entry in entries:
                try:
                    master = entry.dn[1]['cn']
                    dns_masters.append(master)
                except (IndexError, KeyError):
                    pass
        except errors.NotFound:
            return []

        return dns_masters

    def has_cli_options(self, options, no_option_msg, allow_empty_attrs=False):
        if any(k in options for k in ('setattr', 'addattr', 'delattr', 'rename')):
            return

        has_options = False
        for attr in options.keys():
            if attr in self.params and not self.params[attr].primary_key:
                if options[attr] or allow_empty_attrs:
                    has_options = True
                    break

        if not has_options:
            raise errors.OptionError(no_option_msg)

    def get_record_entry_attrs(self, entry_attrs):
        entry_attrs = entry_attrs.copy()
        for attr in entry_attrs.keys():
            if attr not in self.params or self.params[attr].primary_key:
                del entry_attrs[attr]
        return entry_attrs

    def postprocess_record(self, record, **options):
        if options.get('structured', False):
            for attr in record.keys():
                # attributes in LDAPEntry may not be normalized
                attr = attr.lower()
                try:
                    param = self.params[attr]
                except KeyError:
                    continue

                if not isinstance(param, DNSRecord):
                    continue
                parts_params = param.get_parts()

                for dnsvalue in record[attr]:
                    dnsentry = {
                            u'dnstype' : unicode(param.rrtype),
                            u'dnsdata' : dnsvalue
                    }
                    values = param._get_part_values(dnsvalue)
                    if values is None:
                        continue
                    for val_id, val in enumerate(values):
                        if val is not None:
                            #decode IDN
                            if isinstance(parts_params[val_id], DNSNameParam):
                                dnsentry[parts_params[val_id].name] = \
                                _dns_name_to_string(val,
                                                    options.get('raw', False))
                            else:
                                dnsentry[parts_params[val_id].name] = val
                    record.setdefault('dnsrecords', []).append(dnsentry)
                del record[attr]

        elif not options.get('raw', False):
            #Decode IDN ACE form to Unicode, raw records are passed directly from LDAP
            _records_idn_postprocess(record, **options)

    def get_rrparam_from_part(self, part_name):
        """
        Get an instance of DNSRecord parameter that has part_name as its part.
        If such parameter is not found, None is returned

        :param part_name Part parameter name
        """
        try:
            param = self.params[part_name]

            if not any(flag in param.flags for flag in \
                    ('dnsrecord_part', 'dnsrecord_extra')):
                return None

            # All DNS record part or extra parameters contain a name of its
            # parent RR parameter in its hint attribute
            rrparam = self.params[param.hint]
        except (KeyError, AttributeError):
            return None

        return rrparam

    def iterate_rrparams_by_parts(self, kw, skip_extra=False):
        """
        Iterates through all DNSRecord instances that has at least one of its
        parts or extra options in given dictionary. It returns the DNSRecord
        instance only for the first occurence of part/extra option.

        :param kw Dictionary with DNS record parts or extra options
        :param skip_extra Skip DNS record extra options, yield only DNS records
                          with a real record part
        """
        processed = []
        for opt in kw:
            rrparam = self.get_rrparam_from_part(opt)
            if rrparam is None:
                continue

            if skip_extra and 'dnsrecord_extra' in self.params[opt].flags:
                continue

            if rrparam.name not in processed:
                processed.append(rrparam.name)
                yield rrparam

    def updated_rrattrs(self, old_entry, entry_attrs):
        """Returns updated RR attributes
        """
        rrattrs = {}
        if old_entry is not None:
            old_rrattrs = dict((key, value) for key, value in old_entry.iteritems()
                            if key in self.params and
                            isinstance(self.params[key], DNSRecord))
            rrattrs.update(old_rrattrs)
        new_rrattrs = dict((key, value) for key, value in entry_attrs.iteritems()
                        if key in self.params and
                        isinstance(self.params[key], DNSRecord))
        rrattrs.update(new_rrattrs)
        return rrattrs

    def check_record_type_collisions(self, keys, rrattrs):
        # Test that only allowed combination of record types was created

        # CNAME record validation
        cnames = rrattrs.get('cnamerecord')
        if cnames is not None:
            if len(cnames) > 1:
                raise errors.ValidationError(name='cnamerecord',
                    error=_('only one CNAME record is allowed per name '
                            '(RFC 2136, section 1.1.5)'))
            if any(rrvalue is not None
                   and rrattr != 'cnamerecord'
                   for rrattr, rrvalue in rrattrs.iteritems()):
                raise errors.ValidationError(name='cnamerecord',
                        error=_('CNAME record is not allowed to coexist '
                              'with any other record (RFC 1034, section 3.6.2)'))

        # DNAME record validation
        dnames = rrattrs.get('dnamerecord')
        if dnames is not None:
            if len(dnames) > 1:
                raise errors.ValidationError(name='dnamerecord',
                    error=_('only one DNAME record is allowed per name '
                            '(RFC 6672, section 2.4)'))
            # DNAME must not coexist with CNAME, but this is already checked earlier

        # NS record validation
        # NS record can coexist only with A, AAAA, DS, and other NS records (except zone apex)
        # RFC 2181 section 6.1,
        allowed_records = ['AAAA', 'A', 'DS', 'NS']
        nsrecords = rrattrs.get('nsrecord')
        if nsrecords and not self.is_pkey_zone_record(*keys):
            for r_type in _record_types:
                if (r_type not in allowed_records
                    and rrattrs.get('%srecord' % r_type.lower())
                ):
                    raise errors.ValidationError(
                        name='nsrecord',
                        error=_('NS record is not allowed to coexist with an '
                                '%(type)s record except when located in a '
                                'zone root record (RFC 2181, section 6.1)') %
                                {'type': r_type})

    def check_record_type_dependencies(self, keys, rrattrs):
        # Test that all record type dependencies are satisfied

        # DS record validation
        # DS record requires to coexists with NS record
        dsrecords = rrattrs.get('dsrecord')
        nsrecords = rrattrs.get('nsrecord')
        # DS record cannot be in zone apex, checked in pre-callback validators
        if dsrecords and not nsrecords:
            raise errors.ValidationError(
                name='dsrecord',
                error=_('DS record requires to coexist with an '
                         'NS record (RFC 4592 section 4.6, RFC 4035 section 2.4)'))

    def _entry2rrsets(self, entry_attrs, dns_name, dns_domain):
        '''Convert entry_attrs to a dictionary {rdtype: rrset}.

        :returns:
            None if entry_attrs is None
            {rdtype: None} if RRset of given type is empty
            {rdtype: RRset} if RRset of given type is non-empty
        '''
        record_attr_suf = 'record'
        ldap_rrsets = {}

        if not entry_attrs:
            # all records were deleted => name should not exist in DNS
            return None

        for attr, value in entry_attrs.iteritems():
            if not attr.endswith(record_attr_suf):
                continue

            rdtype = dns.rdatatype.from_text(attr[0:-len(record_attr_suf)])
            if not value:
                ldap_rrsets[rdtype] = None  # RRset is empty
                continue

            try:
                # TTL here can be arbitrary value because it is ignored
                # during comparison
                ldap_rrset = dns.rrset.from_text(
                    dns_name, 86400, dns.rdataclass.IN, rdtype,
                    *map(str, value))

                # make sure that all names are absolute so RRset
                # comparison will work
                for ldap_rr in ldap_rrset:
                    ldap_rr.choose_relativity(origin=dns_domain,
                                              relativize=False)
                ldap_rrsets[rdtype] = ldap_rrset

            except dns.exception.SyntaxError as e:
                self.log.error('DNS syntax error: %s %s %s: %s', dns_name,
                               dns.rdatatype.to_text(rdtype), value, e)
                raise

        return ldap_rrsets

    def wait_for_modified_attr(self, ldap_rrset, rdtype, dns_name):
        '''Wait until DNS resolver returns up-to-date answer for given RRset
            or until the maximum number of attempts is reached.
            Number of attempts is controlled by self.api.env['wait_for_dns'].

        :param ldap_rrset:
            None if given rdtype should not exist or
            dns.rrset.RRset to match against data in DNS.
        :param dns_name: FQDN to query
        :type dns_name: dns.name.Name
        :return: None if data in DNS and LDAP match
        :raises errors.DNSDataMismatch: if data in DNS and LDAP doesn't match
        :raises dns.exception.DNSException: if DNS resolution failed
        '''
        resolver = dns.resolver.Resolver()
        resolver.set_flags(0)  # disable recursion (for NS RR checks)
        max_attempts = int(self.api.env['wait_for_dns'])
        warn_attempts = max_attempts / 2
        period = 1  # second
        attempt = 0
        log_fn = self.log.debug
        log_fn('querying DNS server: expecting answer {%s}', ldap_rrset)
        wait_template = 'waiting for DNS answer {%s}: got {%s} (attempt %s); '\
                        'waiting %s seconds before next try'

        while attempt < max_attempts:
            if attempt >= warn_attempts:
                log_fn = self.log.warn
            attempt += 1
            try:
                dns_answer = resolver.query(dns_name, rdtype,
                                            dns.rdataclass.IN,
                                            raise_on_no_answer=False)
                dns_rrset = None
                if rdtype == _NS:
                    # NS records can be in Authority section (sometimes)
                    dns_rrset = dns_answer.response.get_rrset(
                        dns_answer.response.authority, dns_name, _IN, rdtype)

                if not dns_rrset:
                    # Look for NS and other data in Answer section
                    dns_rrset = dns_answer.rrset

                if dns_rrset == ldap_rrset:
                    log_fn('DNS answer matches expectations (attempt %s)',
                           attempt)
                    return

                log_msg = wait_template % (ldap_rrset, dns_answer.response,
                                           attempt, period)

            except (dns.resolver.NXDOMAIN,
                    dns.resolver.YXDOMAIN,
                    dns.resolver.NoNameservers,
                    dns.resolver.Timeout) as e:
                if attempt >= max_attempts:
                    raise
                else:
                    log_msg = wait_template % (ldap_rrset, type(e), attempt,
                                               period)

            log_fn(log_msg)
            time.sleep(period)

        # Maximum number of attempts was reached
        else:
            raise errors.DNSDataMismatch(expected=ldap_rrset, got=dns_rrset)

    def wait_for_modified_attrs(self, entry_attrs, dns_name, dns_domain):
        '''Wait until DNS resolver returns up-to-date answer for given entry
            or until the maximum number of attempts is reached.

        :param entry_attrs:
            None if the entry was deleted from LDAP or
            LDAPEntry instance containing at least all modified attributes.
        :param dns_name: FQDN
        :type dns_name: dns.name.Name
        :raises errors.DNSDataMismatch: if data in DNS and LDAP doesn't match
        '''

        # represent data in LDAP as dictionary rdtype => rrset
        ldap_rrsets = self._entry2rrsets(entry_attrs, dns_name, dns_domain)
        nxdomain = ldap_rrsets is None
        if nxdomain:
            # name should not exist => ask for A record and check result
            ldap_rrsets = {dns.rdatatype.from_text('A'): None}

        for rdtype, ldap_rrset in ldap_rrsets.iteritems():
            try:
                self.wait_for_modified_attr(ldap_rrset, rdtype, dns_name)

            except dns.resolver.NXDOMAIN as e:
                if nxdomain:
                    continue
                else:
                    e = errors.DNSDataMismatch(expected=ldap_rrset,
                                               got="NXDOMAIN")
                    self.log.error(e)
                    raise e

            except dns.resolver.NoNameservers as e:
                # Do not raise exception if we have got SERVFAILs.
                # Maybe the user has created an invalid zone intentionally.
                self.log.warn('waiting for DNS answer {%s}: got {%s}; '
                              'ignoring', ldap_rrset, type(e))
                continue

            except dns.exception.DNSException as e:
                err_desc = str(type(e))
                err_str = str(e)
                if err_str:
                    err_desc += ": %s" % err_str
                e = errors.DNSDataMismatch(expected=ldap_rrset, got=err_desc)
                self.log.error(e)
                raise e

    def wait_for_modified_entries(self, entries):
        '''Call wait_for_modified_attrs for all entries in given dict.

        :param entries:
            Dict {(dns_domain, dns_name): entry_for_wait_for_modified_attrs}
        '''
        for entry_name, entry in entries.iteritems():
            dns_domain = entry_name[0]
            dns_name = entry_name[1].derelativize(dns_domain)
            self.wait_for_modified_attrs(entry, dns_name, dns_domain)

    def warning_if_ns_change_cause_fwzone_ineffective(self, result, *keys,
                                                      **options):
        """Detect if NS record change can make forward zones ineffective due
        missing delegation. Run after parent's execute method.
        """
        record_name_absolute = keys[-1]
        zone = keys[-2]

        if not record_name_absolute.is_absolute():
            record_name_absolute = record_name_absolute.derelativize(zone)

        affected_fw_zones, truncated = _find_subtree_forward_zones_ldap(
            record_name_absolute)
        if not affected_fw_zones:
            return

        for fwzone in affected_fw_zones:
            _add_warning_fw_zone_is_not_effective(result, fwzone,
                                                  options['version'])


@register()
class dnsrecord_add(LDAPCreate):
    __doc__ = _('Add new DNS resource record.')

    no_option_msg = 'No options to add a specific record provided.\n' \
            "Command help may be consulted for all supported record types."
    takes_options = LDAPCreate.takes_options + (
        Flag('force',
             label=_('Force'),
             flags=['no_option', 'no_output'],
             doc=_('force NS record creation even if its hostname is not in DNS'),
        ),
        dnsrecord.structured_flag,
    )

    def args_options_2_entry(self, *keys, **options):
        self.obj.has_cli_options(options, self.no_option_msg)
        return super(dnsrecord_add, self).args_options_2_entry(*keys, **options)

    def interactive_prompt_callback(self, kw):
        try:
            self.obj.has_cli_options(kw, self.no_option_msg)

            # Some DNS records were entered, do not use full interactive help
            # We should still ask user for required parts of DNS parts he is
            # trying to add in the same way we do for standard LDAP parameters
            #
            # Do not ask for required parts when any "extra" option is used,
            # it can be used to fill all required params by itself
            new_kw = {}
            for rrparam in self.obj.iterate_rrparams_by_parts(kw, skip_extra=True):
                user_options = rrparam.prompt_missing_parts(self, kw,
                                                            prompt_optional=False)
                new_kw.update(user_options)
            kw.update(new_kw)
            return
        except errors.OptionError:
            pass

        try:
            idnsname = DNSName(kw['idnsname'])
        except Exception, e:
            raise errors.ValidationError(name='idnsname', error=unicode(e))

        try:
            zonename = DNSName(kw['dnszoneidnsname'])
        except Exception, e:
            raise errors.ValidationError(name='dnszoneidnsname', error=unicode(e))

        # check zone type
        if idnsname.is_empty():
            common_types = u', '.join(_zone_top_record_types)
        elif zonename.is_reverse():
            common_types = u', '.join(_rev_top_record_types)
        else:
            common_types = u', '.join(_top_record_types)

        self.Backend.textui.print_plain(_(u'Please choose a type of DNS resource record to be added'))
        self.Backend.textui.print_plain(_(u'The most common types for this type of zone are: %s\n') %\
                                          common_types)

        ok = False
        while not ok:
            rrtype = self.Backend.textui.prompt(_(u'DNS resource record type'))

            if rrtype is None:
                return

            try:
                name = '%srecord' % rrtype.lower()
                param = self.params[name]

                if not isinstance(param, DNSRecord):
                    raise ValueError()

                if not param.supported:
                    raise ValueError()
            except (KeyError, ValueError):
                all_types = u', '.join(_dns_supported_record_types)
                self.Backend.textui.print_plain(_(u'Invalid or unsupported type. Allowed values are: %s') % all_types)
                continue
            ok = True

        user_options = param.prompt_parts(self)
        kw.update(user_options)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        precallback_attrs = []
        processed_attrs = []
        for option in options:
            try:
                param = self.params[option]
            except KeyError:
                continue

            rrparam = self.obj.get_rrparam_from_part(option)
            if rrparam is None:
                continue

            if 'dnsrecord_part' in param.flags:
                if rrparam.name in processed_attrs:
                    # this record was already entered
                    continue
                if rrparam.name in entry_attrs:
                    # this record is entered both via parts and raw records
                    raise errors.ValidationError(name=param.cli_name or param.name,
                            error=_('Raw value of a DNS record was already set by "%(name)s" option') \
                                  % dict(name=rrparam.cli_name or rrparam.name))

                parts = rrparam.get_parts_from_kw(options)
                dnsvalue = [rrparam._convert_scalar(parts)]
                entry_attrs[rrparam.name] = dnsvalue
                processed_attrs.append(rrparam.name)
                continue

            if 'dnsrecord_extra' in param.flags:
                # do not run precallback for unset flags
                if isinstance(param, Flag) and not options[option]:
                    continue
                # extra option is passed, run per-type pre_callback for given RR type
                precallback_attrs.append(rrparam.name)

        # Run pre_callback validators
        self.obj.run_precallback_validators(dn, entry_attrs, *keys, **options)

        # run precallback also for all new RR type attributes in entry_attrs
        for attr in entry_attrs.keys():
            try:
                param = self.params[attr]
            except KeyError:
                continue

            if not isinstance(param, DNSRecord):
                continue
            precallback_attrs.append(attr)

        precallback_attrs = list(set(precallback_attrs))

        for attr in precallback_attrs:
            # run per-type
            try:
                param = self.params[attr]
            except KeyError:
                continue
            param.dnsrecord_add_pre_callback(ldap, dn, entry_attrs, attrs_list, *keys, **options)

        # Store all new attrs so that DNSRecord post callback is called for
        # new attributes only and not for all attributes in the LDAP entry
        setattr(context, 'dnsrecord_precallback_attrs', precallback_attrs)

        # We always want to retrieve all DNS record attributes to test for
        # record type collisions (#2601)
        try:
            old_entry = ldap.get_entry(dn, _record_attributes)
        except errors.NotFound:
            old_entry = None
        else:
            for attr in entry_attrs.keys():
                if attr not in _record_attributes:
                    continue
                if entry_attrs[attr] is None:
                    entry_attrs[attr] = []
                if not isinstance(entry_attrs[attr], (tuple, list)):
                    vals = [entry_attrs[attr]]
                else:
                    vals = list(entry_attrs[attr])
                entry_attrs[attr] = list(set(old_entry.get(attr, []) + vals))

        rrattrs = self.obj.updated_rrattrs(old_entry, entry_attrs)
        self.obj.check_record_type_dependencies(keys, rrattrs)
        self.obj.check_record_type_collisions(keys, rrattrs)
        context.dnsrecord_entry_mods = getattr(context, 'dnsrecord_entry_mods',
                                               {})
        context.dnsrecord_entry_mods[(keys[0], keys[1])] = entry_attrs.copy()

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.func_name == 'add_entry':
            if isinstance(exc, errors.DuplicateEntry):
                # A new record is being added to existing LDAP DNS object
                # Update can be safely run as old record values has been
                # already merged in pre_callback
                ldap = self.obj.backend
                entry_attrs = self.obj.get_record_entry_attrs(call_args[0])
                update = ldap.get_entry(entry_attrs.dn, entry_attrs.keys())
                update.update(entry_attrs)
                ldap.update_entry(update, **call_kwargs)
                return
        raise exc

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        for attr in getattr(context, 'dnsrecord_precallback_attrs', []):
            param = self.params[attr]
            param.dnsrecord_add_post_callback(ldap, dn, entry_attrs, *keys, **options)

        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [_dns_zone_record]

        self.obj.postprocess_record(entry_attrs, **options)

        if self.api.env['wait_for_dns']:
            self.obj.wait_for_modified_entries(context.dnsrecord_entry_mods)
        return dn



@register()
class dnsrecord_mod(LDAPUpdate):
    __doc__ = _('Modify a DNS resource record.')

    no_option_msg = 'No options to modify a specific record provided.'

    takes_options = LDAPUpdate.takes_options + (
        dnsrecord.structured_flag,
    )

    def args_options_2_entry(self, *keys, **options):
        self.obj.has_cli_options(options, self.no_option_msg, True)
        return super(dnsrecord_mod, self).args_options_2_entry(*keys, **options)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list,  *keys, **options):
        assert isinstance(dn, DN)
        if options.get('rename') and self.obj.is_pkey_zone_record(*keys):
            # zone rename is not allowed
            raise errors.ValidationError(name='rename',
                           error=_('DNS zone root record cannot be renamed'))

        # check if any attr should be updated using structured instead of replaced
        # format is recordname : (old_value, new_parts)
        updated_attrs = {}
        for param in self.obj.iterate_rrparams_by_parts(options, skip_extra=True):
            parts = param.get_parts_from_kw(options, raise_on_none=False)

            if parts is None:
                # old-style modification
                continue

            old_value = entry_attrs.get(param.name)
            if not old_value:
                raise errors.RequirementError(name=param.name)
            if isinstance(old_value, (tuple, list)):
                if len(old_value) > 1:
                    raise errors.ValidationError(name=param.name,
                           error=_('DNS records can be only updated one at a time'))
                old_value = old_value[0]

            updated_attrs[param.name] = (old_value, parts)

        # Run pre_callback validators
        self.obj.run_precallback_validators(dn, entry_attrs, *keys, **options)

        # current entry is needed in case of per-dns-record-part updates and
        # for record type collision check
        try:
            old_entry = ldap.get_entry(dn, _record_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if updated_attrs:
            for attr in updated_attrs:
                param = self.params[attr]
                old_dnsvalue, new_parts = updated_attrs[attr]

                if old_dnsvalue not in old_entry.get(attr, []):
                    attr_name = unicode(param.label or param.name)
                    raise errors.AttrValueNotFound(attr=attr_name,
                                                   value=old_dnsvalue)
                old_entry[attr].remove(old_dnsvalue)

                old_parts = param._get_part_values(old_dnsvalue)
                modified_parts = tuple(part if part is not None else old_parts[part_id] \
                                               for part_id,part in enumerate(new_parts))

                new_dnsvalue = [param._convert_scalar(modified_parts)]
                entry_attrs[attr] = list(set(old_entry[attr] + new_dnsvalue))

        rrattrs = self.obj.updated_rrattrs(old_entry, entry_attrs)
        self.obj.check_record_type_dependencies(keys, rrattrs)
        self.obj.check_record_type_collisions(keys, rrattrs)

        context.dnsrecord_entry_mods = getattr(context, 'dnsrecord_entry_mods',
                                               {})
        context.dnsrecord_entry_mods[(keys[0], keys[1])] = entry_attrs.copy()
        return dn

    def execute(self, *keys, **options):
        result = super(dnsrecord_mod, self).execute(*keys, **options)

        # remove if empty
        if not self.obj.is_pkey_zone_record(*keys):
            rename = options.get('rename')
            if rename is not None:
                keys = keys[:-1] + (rename,)
            dn = self.obj.get_dn(*keys, **options)
            ldap = self.obj.backend
            old_entry = ldap.get_entry(dn, _record_attributes)

            del_all = True
            for attr in old_entry.keys():
                if old_entry[attr]:
                    del_all = False
                    break

            if del_all:
                result = self.obj.methods.delentry(*keys,
                                                   version=options['version'])

                # we need to modify delete result to match mod output type
                # only one value is expected, not a list
                if client_has_capability(options['version'], 'primary_key_types'):
                    assert len(result['value']) == 1
                    result['value'] = result['value'][0]

                # indicate that entry was deleted
                context.dnsrecord_entry_mods[(keys[0], keys[1])] = None

        if self.api.env['wait_for_dns']:
            self.obj.wait_for_modified_entries(context.dnsrecord_entry_mods)
        if 'nsrecord' in options:
            self.obj.warning_if_ns_change_cause_fwzone_ineffective(result,
                                                                   *keys,
                                                                   **options)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [_dns_zone_record]

        self.obj.postprocess_record(entry_attrs, **options)
        return dn

    def interactive_prompt_callback(self, kw):
        try:
            self.obj.has_cli_options(kw, self.no_option_msg, True)
        except errors.OptionError:
            pass
        else:
            # some record type entered, skip this helper
            return

        # get DNS record first so that the NotFound exception is raised
        # before the helper would start
        dns_record = api.Command['dnsrecord_show'](kw['dnszoneidnsname'], kw['idnsname'])['result']
        rec_types = [rec_type for rec_type in dns_record if rec_type in _record_attributes]

        self.Backend.textui.print_plain(_("No option to modify specific record provided."))

        # ask user for records to be removed
        self.Backend.textui.print_plain(_(u'Current DNS record contents:\n'))
        record_params = []

        for attr in dns_record:
            try:
                param = self.params[attr]
            except KeyError:
                continue
            if not isinstance(param, DNSRecord):
                continue

            record_params.append(param)
            rec_type_content = u', '.join(dns_record[param.name])
            self.Backend.textui.print_plain(u'%s: %s' % (param.label, rec_type_content))
        self.Backend.textui.print_plain(u'')

        # ask what records to remove
        for param in record_params:
            rec_values = list(dns_record[param.name])
            for rec_value in dns_record[param.name]:
                rec_values.remove(rec_value)
                mod_value = self.Backend.textui.prompt_yesno(
                        _("Modify %(name)s '%(value)s'?") % dict(name=param.label, value=rec_value), default=False)
                if mod_value is True:
                    user_options = param.prompt_parts(self, mod_dnsvalue=rec_value)
                    kw[param.name] = [rec_value]
                    kw.update(user_options)

                    if rec_values:
                         self.Backend.textui.print_plain(ngettext(
                            u'%(count)d %(type)s record skipped. Only one value per DNS record type can be modified at one time.',
                            u'%(count)d %(type)s records skipped. Only one value per DNS record type can be modified at one time.',
                            0) % dict(count=len(rec_values), type=param.rrtype))
                         break



@register()
class dnsrecord_delentry(LDAPDelete):
    """
    Delete DNS record entry.
    """
    msg_summary = _('Deleted record "%(value)s"')
    NO_CLI = True



@register()
class dnsrecord_del(LDAPUpdate):
    __doc__ = _('Delete DNS resource record.')

    has_output = output.standard_multi_delete

    no_option_msg = _('Neither --del-all nor options to delete a specific record provided.\n'\
            "Command help may be consulted for all supported record types.")

    takes_options = (
            Flag('del_all',
                default=False,
                label=_('Delete all associated records'),
            ),
            dnsrecord.structured_flag,
    )

    def get_options(self):
        for option in super(dnsrecord_del, self).get_options():
            if any(flag in option.flags for flag in \
                    ('dnsrecord_part', 'dnsrecord_extra',)):
                continue
            elif option.name in ('rename', ):
                # options only valid for dnsrecord-mod
                continue
            elif isinstance(option, DNSRecord):
                yield option.clone(option_group=None)
                continue
            yield option

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            old_entry = ldap.get_entry(dn, _record_attributes)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        for attr in entry_attrs.keys():
            if attr not in _record_attributes:
                continue
            if not isinstance(entry_attrs[attr], (tuple, list)):
                vals = [entry_attrs[attr]]
            else:
                vals = entry_attrs[attr]

            for val in vals:
                try:
                    old_entry[attr].remove(val)
                except (KeyError, ValueError):
                    try:
                        param = self.params[attr]
                        attr_name = unicode(param.label or param.name)
                    except:
                        attr_name = attr
                    raise errors.AttrValueNotFound(attr=attr_name, value=val)
            entry_attrs[attr] = list(set(old_entry[attr]))

        rrattrs = self.obj.updated_rrattrs(old_entry, entry_attrs)
        self.obj.check_record_type_dependencies(keys, rrattrs)

        del_all = False
        if not self.obj.is_pkey_zone_record(*keys):
            record_found = False
            for attr in old_entry.keys():
                if old_entry[attr]:
                    record_found = True
                    break
            del_all = not record_found

        # set del_all flag in context
        # when the flag is enabled, the entire DNS record object is deleted
        # in a post callback
        context.del_all = del_all
        context.dnsrecord_entry_mods = getattr(context, 'dnsrecord_entry_mods',
                                               {})
        context.dnsrecord_entry_mods[(keys[0], keys[1])] = entry_attrs.copy()

        return dn

    def execute(self, *keys, **options):
        if options.get('del_all', False):
            if self.obj.is_pkey_zone_record(*keys):
                raise errors.ValidationError(
                        name='del_all',
                        error=_('Zone record \'%s\' cannot be deleted') \
                                % _dns_zone_record
                      )
            result = self.obj.methods.delentry(*keys,
                                               version=options['version'])
            if self.api.env['wait_for_dns']:
                entries = {(keys[0], keys[1]): None}
                self.obj.wait_for_modified_entries(entries)
        else:
            result = super(dnsrecord_del, self).execute(*keys, **options)
            result['value'] = pkey_to_value([keys[-1]], options)

            if getattr(context, 'del_all', False) and not \
                    self.obj.is_pkey_zone_record(*keys):
                result = self.obj.methods.delentry(*keys,
                                                   version=options['version'])
                context.dnsrecord_entry_mods[(keys[0], keys[1])] = None

            if self.api.env['wait_for_dns']:
                self.obj.wait_for_modified_entries(context.dnsrecord_entry_mods)

        if 'nsrecord' in options or options.get('del_all', False):
            self.obj.warning_if_ns_change_cause_fwzone_ineffective(result,
                                                                   *keys,
                                                                   **options)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [_dns_zone_record]
        self.obj.postprocess_record(entry_attrs, **options)
        return dn

    def args_options_2_entry(self, *keys, **options):
        self.obj.has_cli_options(options, self.no_option_msg)
        return super(dnsrecord_del, self).args_options_2_entry(*keys, **options)

    def interactive_prompt_callback(self, kw):
        if kw.get('del_all', False):
            return
        try:
            self.obj.has_cli_options(kw, self.no_option_msg)
        except errors.OptionError:
            pass
        else:
            # some record type entered, skip this helper
            return

        # get DNS record first so that the NotFound exception is raised
        # before the helper would start
        dns_record = api.Command['dnsrecord_show'](kw['dnszoneidnsname'], kw['idnsname'])['result']
        rec_types = [rec_type for rec_type in dns_record if rec_type in _record_attributes]

        self.Backend.textui.print_plain(_("No option to delete specific record provided."))
        user_del_all = self.Backend.textui.prompt_yesno(_("Delete all?"), default=False)

        if user_del_all is True:
            kw['del_all'] = True
            return

        # ask user for records to be removed
        self.Backend.textui.print_plain(_(u'Current DNS record contents:\n'))
        present_params = []

        for attr in dns_record:
            try:
                param = self.params[attr]
            except KeyError:
                continue
            if not isinstance(param, DNSRecord):
                continue

            present_params.append(param)
            rec_type_content = u', '.join(dns_record[param.name])
            self.Backend.textui.print_plain(u'%s: %s' % (param.label, rec_type_content))
        self.Backend.textui.print_plain(u'')

        # ask what records to remove
        for param in present_params:
            deleted_values = []
            for rec_value in dns_record[param.name]:
                user_del_value = self.Backend.textui.prompt_yesno(
                        _("Delete %(name)s '%(value)s'?")
                            % dict(name=param.label, value=rec_value), default=False)
                if user_del_value is True:
                     deleted_values.append(rec_value)
            if deleted_values:
                kw[param.name] = tuple(deleted_values)



@register()
class dnsrecord_show(LDAPRetrieve):
    __doc__ = _('Display DNS resource.')

    takes_options = LDAPRetrieve.takes_options + (
        dnsrecord.structured_flag,
    )

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [_dns_zone_record]
        self.obj.postprocess_record(entry_attrs, **options)
        return dn



@register()
class dnsrecord_find(LDAPSearch):
    __doc__ = _('Search for DNS resources.')

    takes_options = LDAPSearch.takes_options + (
        dnsrecord.structured_flag,
    )

    def get_options(self):
        for option in super(dnsrecord_find, self).get_options():
            if any(flag in option.flags for flag in \
                    ('dnsrecord_part', 'dnsrecord_extra',)):
                continue
            elif isinstance(option, DNSRecord):
                yield option.clone(option_group=None)
                continue
            yield option

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)

        # validate if zone is master zone
        self.obj.check_zone(args[-2], **options)

        filter = _create_idn_filter(self, ldap, *args, **options)
        return (filter, base_dn, ldap.SCOPE_SUBTREE)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if entries:
            zone_obj = self.api.Object[self.obj.parent_object]
            zone_dn = zone_obj.get_dn(args[0])
            if entries[0].dn == zone_dn:
                entries[0][zone_obj.primary_key.name] = [_dns_zone_record]
            for entry in entries:
                self.obj.postprocess_record(entry, **options)

        return truncated


@register()
class dns_resolve(Command):
    __doc__ = _('Resolve a host name in DNS.')

    has_output = output.standard_value
    msg_summary = _('Found \'%(value)s\'')

    takes_args = (
        Str('hostname',
            label=_('Hostname'),
        ),
    )

    def execute(self, *args, **options):
        query=args[0]
        if query.find(api.env.domain) == -1 and query.find('.') == -1:
            query = '%s.%s.' % (query, api.env.domain)
        if query[-1] != '.':
            query = query + '.'

        if not is_host_resolvable(query):
            raise errors.NotFound(
                reason=_('Host \'%(host)s\' not found') % {'host': query}
            )

        return dict(result=True, value=query)


@register()
class dns_is_enabled(Command):
    """
    Checks if any of the servers has the DNS service enabled.
    """
    NO_CLI = True
    has_output = output.standard_value

    base_dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
    filter = '(&(objectClass=ipaConfigObject)(cn=DNS))'

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2
        dns_enabled = False

        try:
            ent = ldap.find_entries(filter=self.filter, base_dn=self.base_dn)
            if len(ent):
                dns_enabled = True
        except Exception, e:
            pass

        return dict(result=dns_enabled, value=pkey_to_value(None, options))



@register()
class dnsconfig(LDAPObject):
    """
    DNS global configuration object
    """
    object_name = _('DNS configuration options')
    default_attributes = [
        'idnsforwardpolicy', 'idnsforwarders', 'idnsallowsyncptr'
    ]

    label = _('DNS Global Configuration')
    label_singular = _('DNS Global Configuration')

    takes_params = (
        Str('idnsforwarders*',
            _validate_bind_forwarder,
            cli_name='forwarder',
            label=_('Global forwarders'),
            doc=_('Global forwarders. A custom port can be specified for each '
                  'forwarder using a standard format "IP_ADDRESS port PORT"'),
            csv=True,
        ),
        StrEnum('idnsforwardpolicy?',
            cli_name='forward_policy',
            label=_('Forward policy'),
            doc=_('Global forwarding policy. Set to "none" to disable '
                  'any configured global forwarders.'),
            values=(u'only', u'first', u'none'),
        ),
        Bool('idnsallowsyncptr?',
            cli_name='allow_sync_ptr',
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records'),
        ),
        DeprecatedParam('idnszonerefresh?',
            cli_name='zone_refresh',
            label=_('Zone refresh interval'),
        ),
    )
    managed_permissions = {
        'System: Write DNS Configuration': {
            'non_object': True,
            'ipapermright': {'write'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=dns', api.env.basedn),
            'ipapermtargetfilter': ['(objectclass=idnsConfigObject)'],
            'ipapermdefaultattr': {
                'idnsallowsyncptr', 'idnsforwarders', 'idnsforwardpolicy',
                'idnspersistentsearch', 'idnszonerefresh'
            },
            'replaces': [
                '(targetattr = "idnsforwardpolicy || idnsforwarders || idnsallowsyncptr || idnszonerefresh || idnspersistentsearch")(target = "ldap:///cn=dns,$SUFFIX")(version 3.0;acl "permission:Write DNS Configuration";allow (write) groupdn = "ldap:///cn=Write DNS Configuration,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'DNS Administrators', 'DNS Servers'},
        },
        'System: Read DNS Configuration': {
            'non_object': True,
            'ipapermright': {'read'},
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=dns', api.env.basedn),
            'ipapermtargetfilter': ['(objectclass=idnsConfigObject)'],
            'ipapermdefaultattr': {
                'objectclass',
                'idnsallowsyncptr', 'idnsforwarders', 'idnsforwardpolicy',
                'idnspersistentsearch', 'idnszonerefresh'
            },
            'default_privileges': {'DNS Administrators', 'DNS Servers'},
        },
    }

    def get_dn(self, *keys, **kwargs):
        if not dns_container_exists(self.api.Backend.ldap2):
            raise errors.NotFound(reason=_('DNS is not configured'))
        return DN(api.env.container_dns, api.env.basedn)

    def get_dnsconfig(self, ldap):
        entry = ldap.get_entry(self.get_dn(), None)

        return entry

    def postprocess_result(self, result):
        if not any(param in result['result'] for param in self.params):
            result['summary'] = unicode(_('Global DNS configuration is empty'))



@register()
class dnsconfig_mod(LDAPUpdate):
    __doc__ = _('Modify global DNS configuration.')

    def interactive_prompt_callback(self, kw):

        # show informative message on client side
        # server cannot send messages asynchronous
        if kw.get('idnsforwarders', False):
            self.Backend.textui.print_plain(
                _("Server will check DNS forwarder(s)."))
            self.Backend.textui.print_plain(
                _("This may take some time, please wait ..."))

    def execute(self, *keys, **options):
        # test dnssec forwarders
        forwarders = options.get('idnsforwarders')

        result = super(dnsconfig_mod, self).execute(*keys, **options)
        self.obj.postprocess_result(result)

        if forwarders:
            for forwarder in forwarders:
                try:
                    validate_dnssec_global_forwarder(forwarder, log=self.log)
                except DNSSECSignatureMissingError as e:
                    messages.add_message(
                        options['version'],
                        result, messages.DNSServerDoesNotSupportDNSSECWarning(
                            server=forwarder, error=e,
                        )
                    )
                except EDNS0UnsupportedError as e:
                    messages.add_message(
                        options['version'],
                        result, messages.DNSServerDoesNotSupportEDNS0Warning(
                            server=forwarder, error=e,
                        )
                    )
                except UnresolvableRecordError as e:
                    messages.add_message(
                        options['version'],
                        result, messages.DNSServerValidationWarning(
                            server=forwarder, error=e
                        )
                    )

        return result



@register()
class dnsconfig_show(LDAPRetrieve):
    __doc__ = _('Show the current global DNS configuration.')

    def execute(self, *keys, **options):
        result = super(dnsconfig_show, self).execute(*keys, **options)
        self.obj.postprocess_result(result)
        return result


@register()
class dnsforwardzone(DNSZoneBase):
    """
    DNS Forward zone, container for resource records.
    """
    object_name = _('DNS forward zone')
    object_name_plural = _('DNS forward zones')
    object_class = DNSZoneBase.object_class + ['idnsforwardzone']
    label = _('DNS Forward Zones')
    label_singular = _('DNS Forward Zone')
    default_forward_policy = u'first'

    # managed_permissions: permissions was apllied in dnszone class, do NOT
    # add them here, they should not be applied twice.

    def _warning_fw_zone_is_not_effective(self, result, *keys, **options):
        fwzone = keys[-1]
        _add_warning_fw_zone_is_not_effective(result, fwzone,
                                              options['version'])

    def _warning_if_forwarders_do_not_work(self, result, new_zone,
                                           *keys, **options):
        fwzone = keys[-1]
        forwarders = options.get('idnsforwarders', [])
        any_forwarder_work = False

        for forwarder in forwarders:
            try:
                validate_dnssec_zone_forwarder_step1(forwarder, fwzone,
                                                     log=self.log)
            except UnresolvableRecordError as e:
                messages.add_message(
                    options['version'],
                    result, messages.DNSServerValidationWarning(
                        server=forwarder, error=e
                    )
                )
            except EDNS0UnsupportedError as e:
                messages.add_message(
                    options['version'],
                    result, messages.DNSServerDoesNotSupportEDNS0Warning(
                        server=forwarder, error=e
                    )
                )
            else:
                any_forwarder_work = True

        if not any_forwarder_work:
            # do not test DNSSEC validation if there is no valid forwarder
            return

        # resolve IP address of any DNS replica
        # FIXME: https://fedorahosted.org/bind-dyndb-ldap/ticket/143
        # we currenly should to test all IPA DNS replica, because DNSSEC
        # validation is configured just in named.conf per replica

        ipa_dns_masters = [normalize_zone(x) for x in
                           api.Object.dnsrecord.get_dns_masters()]

        if not ipa_dns_masters:
            # something very bad happened, DNS is installed, but no IPA DNS
            # servers available
            self.log.error("No IPA DNS server can be found, but integrated DNS "
                           "is installed")
            return

        ipa_dns_ip = None
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            try:
                ans = dns.resolver.query(ipa_dns_masters[0], rdtype)
            except dns.exception.DNSException:
                continue
            else:
                ipa_dns_ip = str(ans.rrset.items[0])
                break

        if not ipa_dns_ip:
            self.log.error("Cannot resolve %s hostname", ipa_dns_masters[0])
            return

        # sleep a bit, adding new zone to BIND from LDAP may take a while
        if new_zone:
            time.sleep(5)

        # Test if IPA is able to receive replies from forwarders
        try:
            validate_dnssec_zone_forwarder_step2(ipa_dns_ip, fwzone,
                                                 log=self.log)
        except DNSSECValidationError as e:
            messages.add_message(
                options['version'],
                result, messages.DNSSECValidationFailingWarning(error=e)
            )
        except UnresolvableRecordError as e:
            messages.add_message(
                options['version'],
                result, messages.DNSServerValidationWarning(
                    server=ipa_dns_ip, error=e
                )
            )

@register()
class dnsforwardzone_add(DNSZoneBase_add):
    __doc__ = _('Create new DNS forward zone.')

    def interactive_prompt_callback(self, kw):
        # show informative message on client side
        # server cannot send messages asynchronous
        if kw.get('idnsforwarders', False):
            self.Backend.textui.print_plain(
                _("Server will check DNS forwarder(s)."))
            self.Backend.textui.print_plain(
                _("This may take some time, please wait ..."))

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        dn = super(dnsforwardzone_add, self).pre_callback(ldap, dn,
            entry_attrs, attrs_list, *keys, **options)

        if 'idnsforwardpolicy' not in entry_attrs:
            entry_attrs['idnsforwardpolicy'] = self.obj.default_forward_policy

        if (not entry_attrs.get('idnsforwarders') and
                entry_attrs['idnsforwardpolicy'] != u'none'):
            raise errors.ValidationError(name=u'idnsforwarders',
                                         error=_('Please specify forwarders.'))

        return dn

    def execute(self, *keys, **options):
        result = super(dnsforwardzone_add, self).execute(*keys, **options)
        self.obj._warning_fw_zone_is_not_effective(result, *keys, **options)
        if options.get('idnsforwarders'):
            print result, keys, options
            self.obj._warning_if_forwarders_do_not_work(
                result, True, *keys, **options)
        return result


@register()
class dnsforwardzone_del(DNSZoneBase_del):
    __doc__ = _('Delete DNS forward zone.')

    msg_summary = _('Deleted DNS forward zone "%(value)s"')


@register()
class dnsforwardzone_mod(DNSZoneBase_mod):
    __doc__ = _('Modify DNS forward zone.')

    def interactive_prompt_callback(self, kw):
        # show informative message on client side
        # server cannot send messages asynchronous
        if kw.get('idnsforwarders', False):
            self.Backend.textui.print_plain(
                _("Server will check DNS forwarder(s)."))
            self.Backend.textui.print_plain(
                _("This may take some time, please wait ..."))

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        try:
            entry = ldap.get_entry(dn)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if not _check_entry_objectclass(entry, self.obj.object_class):
            self.obj.handle_not_found(*keys)

        policy = self.obj.default_forward_policy
        forwarders = []

        if 'idnsforwarders' in entry_attrs:
            forwarders = entry_attrs['idnsforwarders']
        elif 'idnsforwarders' in entry:
            forwarders = entry['idnsforwarders']

        if 'idnsforwardpolicy' in entry_attrs:
            policy = entry_attrs['idnsforwardpolicy']
        elif 'idnsforwardpolicy' in entry:
            policy = entry['idnsforwardpolicy']

        if not forwarders and policy != u'none':
            raise errors.ValidationError(name=u'idnsforwarders',
                                         error=_('Please specify forwarders.'))

        return dn

    def execute(self, *keys, **options):
        result = super(dnsforwardzone_mod, self).execute(*keys, **options)
        if options.get('idnsforwarders'):
            self.obj._warning_if_forwarders_do_not_work(result, False, *keys,
                                                        **options)
        return result

@register()
class dnsforwardzone_find(DNSZoneBase_find):
    __doc__ = _('Search for DNS forward zones.')


@register()
class dnsforwardzone_show(DNSZoneBase_show):
    __doc__ = _('Display information about a DNS forward zone.')

    has_output_params = LDAPRetrieve.has_output_params + dnszone_output_params


@register()
class dnsforwardzone_disable(DNSZoneBase_disable):
    __doc__ = _('Disable DNS Forward Zone.')
    msg_summary = _('Disabled DNS forward zone "%(value)s"')


@register()
class dnsforwardzone_enable(DNSZoneBase_enable):
    __doc__ = _('Enable DNS Forward Zone.')
    msg_summary = _('Enabled DNS forward zone "%(value)s"')

    def execute(self, *keys, **options):
        result = super(dnsforwardzone_enable, self).execute(*keys, **options)
        self.obj._warning_fw_zone_is_not_effective(result, *keys, **options)
        return result


@register()
class dnsforwardzone_add_permission(DNSZoneBase_add_permission):
    __doc__ = _('Add a permission for per-forward zone access delegation.')


@register()
class dnsforwardzone_remove_permission(DNSZoneBase_remove_permission):
    __doc__ = _('Remove a permission for per-forward zone access delegation.')
