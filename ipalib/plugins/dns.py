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
import dns.name

from ipalib.request import context
from ipalib import api, errors, output
from ipalib import Command
from ipalib.parameters import Flag, Bool, Int, Decimal, Str, StrEnum, Any
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
from ipalib.util import (validate_zonemgr, normalize_zonemgr,
        validate_hostname, validate_dns_label, validate_domain_name,
        get_dns_forward_zone_update_policy, get_dns_reverse_zone_update_policy,
        get_reverse_zone_default, zone_is_reverse, REVERSE_DNS_ZONES)
from ipapython.ipautil import valid_ip, CheckedIPAddress, is_host_resolvable

__doc__ = _("""
Domain Name System (DNS)

Manage DNS zone and resource records.


USING STRUCTURED PER-TYPE OPTIONS

There are many structured DNS RR types where DNS data stored in LDAP server
is not just a scalar value, for example an IP address or a domain name, but
a data structure which may be often complex. A good example is a LOC record
[RFC1876] which consists of many mandatory and optional parts (degrees,
minutes, seconds of latitude and longitude, altitude or precision).

It may be difficult to manipulate such DNS records without making a mistake
and entering an invalid value. DNS module provides an abstraction over these
raw records and allows to manipulate each RR type with specific options. For
each supported RR type, DNS module provides a standard option to manipulate
a raw records with format --<rrtype>-rec, e.g. --mx-rec, and special options
for every part of the RR structure with format --<rrtype>-<partname>, e.g.
--mx-preference and --mx-exchanger.

When adding a record, either RR specific options or standard option for a raw
value can be used, they just should not be combined in one add operation. When
modifying an existing entry, new RR specific options can be used to change
one part of a DNS record, where the standard option for raw value is used
to specify the modified value. The following example demonstrates
a modification of MX record preference from 0 to 1 in a record without
modifying the exchanger:
ipa dnsrecord-mod --mx-rec="0 mx.example.com." --mx-preference=1


EXAMPLES:

 Add new zone:
   ipa dnszone-add example.com --name-server=nameserver.example.com \\
                               --admin-email=admin@example.com

 Add system permission that can be used for per-zone privilege delegation:
   ipa dnszone-add-permission example.com

 Modify the zone to allow dynamic updates for hosts own records in realm EXAMPLE.COM:
   ipa dnszone-mod example.com --dynamic-update=TRUE

   This is the equivalent of:
     ipa dnszone-mod example.com --dynamic-update=TRUE \\
      --update-policy="grant EXAMPLE.COM krb5-self * A; grant EXAMPLE.COM krb5-self * AAAA; grant EXAMPLE.COM krb5-self * SSHFP;"

 Modify the zone to allow zone transfers for local network only:
   ipa dnszone-mod example.com --allow-transfer=10.0.0.0/8

 Add new reverse zone specified by network IP address:
   ipa dnszone-add --name-from-ip=80.142.15.0/24 \\
                   --name-server=nameserver.example.com

 Add second nameserver for example.com:
   ipa dnsrecord-add example.com @ --ns-rec=nameserver2.example.com

 Add a mail server for example.com:
   ipa dnsrecord-add example.com @ --mx-rec="10 mail1"

 Add another record using MX record specific options:
  ipa dnsrecord-add example.com @ --mx-preference=20 --mx-exchanger=mail2

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

 Delete previously added nameserver from example.com:
   ipa dnsrecord-del example.com @ --ns-rec=nameserver2.example.com.

 Add LOC record for example.com:
   ipa dnsrecord-add example.com @ --loc-rec="49 11 42.4 N 16 36 29.6 E 227.64m"

 Add new A record for www.example.com. Create a reverse record in appropriate
 reverse zone as well. In this case a PTR record "2" pointing to www.example.com
 will be created in zone 15.142.80.in-addr.arpa.
   ipa dnsrecord-add example.com www --a-rec=80.142.15.2 --a-create-reverse

 Add new PTR record for www.example.com
   ipa dnsrecord-add 15.142.80.in-addr.arpa. 2 --ptr-rec=www.example.com.

 Add new SRV records for LDAP servers. Three quarters of the requests
 should go to fast.example.com, one quarter to slow.example.com. If neither
 is available, switch to backup.example.com.
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 3 389 fast.example.com"
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 1 389 slow.example.com"
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="1 1 389 backup.example.com"

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

 After this modification, three fifths of the requests should go to
 fast.example.com and two fifths to slow.example.com.

 An example of the interactive mode for dnsrecord-del command:
   ipa dnsrecord-del example.com www
   No option to delete specific record provided.
   Delete all? Yes/No (default No):     (do not delete all records)
   Current DNS record contents:

   A record: 1.2.3.4, 11.22.33.44

   Delete A record '1.2.3.4'? Yes/No (default No):
   Delete A record '11.22.33.44'? Yes/No (default No): y
     Record name: www
     A record: 1.2.3.4                  (A record 11.22.33.44 has been deleted)

 Show zone example.com:
   ipa dnszone-show example.com

 Find zone with "example" in its domain name:
   ipa dnszone-find example

 Find records for resources with "www" in their name in zone example.com:
   ipa dnsrecord-find example.com www

 Find A records with value 10.10.0.1 in zone example.com
   ipa dnsrecord-find example.com --a-rec=10.10.0.1

 Show records for resource www in zone example.com
   ipa dnsrecord-show example.com www

 Forward all requests for the zone external.com to another nameserver using
 a "first" policy (it will send the queries to the selected forwarder and if
 not answered it will use global resolvers):
   ipa dnszone-add external.com
   ipa dnszone-mod external.com --forwarder=10.20.0.1 \\
                                --forward-policy=first

 Delete zone example.com with all resource records:
   ipa dnszone-del example.com

 Resolve a host name to see if it exists (will add default IPA domain
 if one is not included):
   ipa dns-resolve www.example.com
   ipa dns-resolve www


GLOBAL DNS CONFIGURATION

DNS configuration passed to command line install script is stored in a local
configuration file on each IPA server where DNS service is configured. These
local settings can be overridden with a common configuration stored in LDAP
server:

 Show global DNS configuration:
   ipa dnsconfig-show

 Modify global DNS configuration and set a list of global forwarders:
   ipa dnsconfig-mod --forwarder=10.0.0.1
""")

# supported resource record types
_record_types = (
    u'A', u'AAAA', u'A6', u'AFSDB', u'APL', u'CERT', u'CNAME', u'DHCID', u'DLV',
    u'DNAME', u'DNSKEY', u'DS', u'HIP', u'IPSECKEY', u'KEY', u'KX', u'LOC',
    u'MX', u'NAPTR', u'NS', u'NSEC', u'NSEC3', u'NSEC3PARAM', u'PTR',
    u'RRSIG', u'RP', u'SIG', u'SPF', u'SRV', u'SSHFP', u'TA', u'TKEY',
    u'TSIG', u'TXT',
)

# DNS zone record identificator
_dns_zone_record = u'@'

# most used record types, always ask for those in interactive prompt
_top_record_types = ('A', 'AAAA', )
_rev_top_record_types = ('PTR', )
_zone_top_record_types = ('NS', 'MX', 'LOC', )

# attributes derived from record types
_record_attributes = [str('%srecord' % t.lower()) for t in _record_types]

# supported DNS classes, IN = internet, rest is almost never used
_record_classes = (u'IN', u'CS', u'CH', u'HS')

def _rname_validator(ugettext, zonemgr):
    try:
        validate_zonemgr(zonemgr)
    except ValueError, e:
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
        netaddr.IPAddress(netstr)
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
        ip = netaddr.IPAddress(ipaddr, flags=netaddr.INET_PTON)

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

def _bind_hostname_validator(ugettext, value):
    try:
        # Allow domain name which is not fully qualified. These are supported
        # in bind and then translated as <non-fqdn-name>.<domain>.
        validate_hostname(value, check_fqdn=False)
    except ValueError, e:
        return _('invalid domain-name: %s') \
            % unicode(e)

    return None

def _dns_record_name_validator(ugettext, value):
    if value == _dns_zone_record:
        return

    try:
        map(lambda label:validate_dns_label(label, allow_underscore=True), \
            value.split(u'.'))
    except ValueError, e:
        return unicode(e)

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

def _domain_name_validator(ugettext, value):
    try:
        validate_domain_name(value)
    except ValueError, e:
        return unicode(e)

def _hostname_validator(ugettext, value):
    try:
        validate_hostname(value)
    except ValueError, e:
        return _('invalid domain-name: %s') \
            % unicode(e)

    return None

def _normalize_hostname(domain_name):
    """Make it fully-qualified"""
    if domain_name[-1] != '.':
        return domain_name + '.'
    else:
        return domain_name

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
    ip = netaddr.IPAddress(ipaddr)
    revdns = unicode(ip.reverse_dns)

    if prefixlen is None:
        revzone = u''

        result = api.Command['dnszone_find']()['result']
        for zone in result:
            zonename = zone['idnsname'][0]
            if revdns.endswith(zonename) and len(zonename) > len(revzone):
                revzone = zonename
    else:
        if ip.version == 4:
            pos = 4 - prefixlen / 8
        elif ip.version == 6:
            pos = 32 - prefixlen / 4
        items = ip.reverse_dns.split('.')
        revzone = u'.'.join(items[pos:])

        try:
            api.Command['dnszone_show'](revzone)
        except errors.NotFound:
            revzone = u''

    if len(revzone) == 0:
        raise errors.NotFound(
            reason=_('DNS reverse zone for IP address %(addr)s not found') % dict(addr=ipaddr)
        )

    revname = revdns[:-len(revzone)-1]

    return revzone, revname

def add_records_for_host_validation(option_name, host, domain, ip_addresses, check_forward=True, check_reverse=True):
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
                addkw = { 'ptrrecord' : host + "." + domain }
                api.Command['dnsrecord_add'](revzone, revname, **addkw)
            except errors.EmptyModlist:
                # the entry already exists and matches
                pass

class DNSRecord(Str):
    # a list of parts that create the actual raw DNS record
    parts = None
    # an optional list of parameters used in record-specific operations
    extra = None
    supported = True
    # supported RR types: https://fedorahosted.org/bind-dyndb-ldap/browser/doc/schema

    label_format = _("%s record")
    part_label_format = "%s %s"
    doc_format = _('Comma-separated list of raw %s records')
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

    def _part_values_to_string(self, values, index):
        self._validate_parts(values)
        return u" ".join(super(DNSRecord, self)._convert_scalar(v, index) \
                             for v in values if v is not None)

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
        if self.normalizedns: #pylint: disable=E1101
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
        if not self.validatedns: #pylint: disable=E1101
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

    def __get_part_param(self, backend, part, output_kw, default=None):
        name = self.part_name_format % (self.rrtype.lower(), part.name)
        label = self.part_label_format % (self.rrtype, unicode(part.label))
        optional = not part.required

        while True:
            try:
                raw = backend.textui.prompt(label,
                                            optional=optional,
                                            default=default)
                if not raw.strip():
                    raw = default

                output_kw[name] = part(raw)
                break
            except (errors.ValidationError, errors.ConversionError), e:
                backend.textui.print_prompt_attribute_error(
                        unicode(label), unicode(e.error))

    def prompt_parts(self, backend, mod_dnsvalue=None):
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

            self.__get_part_param(backend, part, user_options, default)

        return user_options

    def prompt_missing_parts(self, backend, kw, prompt_optional=False):
        user_options = {}
        if self.parts is None:
            return user_options

        for part in self.parts:
            name = self.part_name_format % (self.rrtype.lower(), part.name)
            label = self.part_label_format % (self.rrtype, unicode(part.label))

            if name in kw:
                continue

            optional = not part.required
            if optional and not prompt_optional:
                continue

            default = part.get_default(**kw)
            self.__get_part_param(backend, part, user_options, default)

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
        Str('hostname',
            _bind_hostname_validator,
            label=_('Hostname'),
        ),
    )

class APLRecord(DNSRecord):
    rrtype = 'APL'
    rfc = 3123
    supported = False

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
        Str('hostname',
            _bind_hostname_validator,
            label=_('Hostname'),
            doc=_('A hostname which this alias hostname points to'),
        ),
    )

class DHCIDRecord(DNSRecord):
    rrtype = 'DHCID'
    rfc = 4701
    supported = False

class DLVRecord(DNSRecord):
    rrtype = 'DLV'
    rfc = 4431
    supported = False

class DNAMERecord(DNSRecord):
    rrtype = 'DNAME'
    rfc = 2672
    parts = (
        Str('target',
            _bind_hostname_validator,
            label=_('Target'),
        ),
    )

class DNSKEYRecord(DNSRecord):
    rrtype = 'DNSKEY'
    rfc = 4034
    supported = False

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
        ),
    )

class HIPRecord(DNSRecord):
    rrtype = 'HIP'
    rfc = 5205
    supported = False

class KEYRecord(DNSRecord):
    rrtype = 'KEY'
    rfc = 2535
    parts = (
        Int('flags',
            label=_('Flags'),
            minvalue=0,
            maxvalue=65535,
        ),
        Int('protocol',
            label=_('Protocol'),
            minvalue=0,
            maxvalue=255,
        ),
        Int('algorithm',
            label=_('Algorithm'),
            minvalue=0,
            maxvalue=255,
        ),
        Str('public_key',
            label=_('Public Key'),
        ),
    )

class IPSECKEYRecord(DNSRecord):
    rrtype = 'IPSECKEY'
    rfc = 4025
    supported = False

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
        Str('exchanger',
            _bind_hostname_validator,
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
        regex = re.compile(\
            r'(?P<d1>\d{1,2}\s+)(?P<m1>\d{1,2}\s+)?(?P<s1>\d{1,2}\.?\d{1,3}?\s+)?'\
            r'(?P<dir1>[N|S])\s+'\
            r'(?P<d2>\d{1,3}\s+)(?P<m2>\d{1,2}\s+)?(?P<s2>\d{1,2}\.?\d{1,3}?\s+)?'\
            r'(?P<dir2>[W|E])\s+'\
            r'(?P<alt>-?\d{1,8}\.?\d{1,2}?)m?\s*'\
            r'(?P<siz>\d{1,8}\.?\d{1,2}?)?m?\s*'\
            r'(?P<hp>\d{1,8}\.?\d{1,2}?)?m?\s*(?P<vp>\d{1,8}\.?\d{1,2}?)?m?\s*$')

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
        Str('exchanger',
            _bind_hostname_validator,
            label=_('Exchanger'),
            doc=_('A host willing to act as a mail exchanger'),
        ),
    )

class NSRecord(DNSRecord):
    rrtype = 'NS'
    rfc = 1035

    parts = (
        Str('hostname',
            _bind_hostname_validator,
            label=_('Hostname'),
        ),
    )

class NSECRecord(DNSRecord):
    rrtype = 'NSEC'
    rfc = 4034
    format_error_msg = _('format must be specified as "NEXT TYPE1 '\
                         '[TYPE2 [TYPE3 [...]]]" (see RFC 4034 for details)')
    _allowed_types = (u'SOA',) + _record_types

    parts = (
        Str('next',
            _bind_hostname_validator,
            label=_('Next Domain Name'),
        ),
        StrEnum('types+',
            label=_('Type Map'),
            values=_allowed_types,
            csv=True,
        ),
    )

    def _get_part_values(self, value):
        values = value.split()

        if len(values) < 2:
            return None

        return (values[0], tuple(values[1:]))

    def _part_values_to_string(self, values, index):
        self._validate_parts(values)
        values_flat = [values[0],]  # add "next" part
        types = values[1]
        if not isinstance(types, (list, tuple)):
            types = [types,]
        values_flat.extend(types)
        return u" ".join(Str._convert_scalar(self, v, index) \
                             for v in values_flat if v is not None)

class NSEC3Record(DNSRecord):
    rrtype = 'NSEC3'
    rfc = 5155
    supported = False

class NSEC3PARAMRecord(DNSRecord):
    rrtype = 'NSEC3PARAM'
    rfc = 5155
    supported = False

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
        Str('hostname',
            _hostname_validator,
            normalizer=_normalize_hostname,
            label=_('Hostname'),
            doc=_('The hostname this reverse record points to'),
        ),
    )

class RPRecord(DNSRecord):
    rrtype = 'RP'
    rfc = 1183
    supported = False

def _srv_target_validator(ugettext, value):
    if value == u'.':
        # service not available
        return
    return _bind_hostname_validator(ugettext, value)

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
        Str('target',
            _srv_target_validator,
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


class SIGRecord(DNSRecord):
    rrtype = 'SIG'
    rfc = 2535
    _allowed_types = tuple([u'SOA'] + [x for x in _record_types if x != u'SIG'])

    parts = (
        StrEnum('type_covered',
            label=_('Type Covered'),
            values=_allowed_types,
        ),
        Int('algorithm',
            label=_('Algorithm'),
            minvalue=0,
            maxvalue=255,
        ),
        Int('labels',
            label=_('Labels'),
            minvalue=0,
            maxvalue=255,
        ),
        Int('original_ttl',
            label=_('Original TTL'),
            minvalue=0,
        ),
        Str('signature_expiration',
            _sig_time_validator,
            label=_('Signature Expiration'),
        ),
        Str('signature_inception',
            _sig_time_validator,
            label=_('Signature Inception'),
        ),
        Int('key_tag',
            label=_('Key Tag'),
            minvalue=0,
            maxvalue=65535,
        ),
        Str('signers_name',
            label=_('Signer\'s Name'),
        ),
        Str('signature',
            label=_('Signature'),
        ),
    )

class SPFRecord(DNSRecord):
    rrtype = 'SPF'
    rfc = 4408
    supported = False

class RRSIGRecord(SIGRecord):
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

class TARecord(DNSRecord):
    rrtype = 'TA'
    supported = False

class TKEYRecord(DNSRecord):
    rrtype = 'TKEY'
    supported = False

class TSIGRecord(DNSRecord):
    rrtype = 'TSIG'
    supported = False

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
    NSEC3PARAMRecord(),
    PTRRecord(),
    RRSIGRecord(),
    RPRecord(),
    SIGRecord(),
    SPFRecord(),
    SRVRecord(),
    SSHFPRecord(),
    TARecord(),
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
    if not name.endswith('.'):
        # this is a DNS name relative to the zone
        zone = dns.name.from_text(zone)
        name = unicode(dns.name.from_text(name, origin=zone))
    try:
        return api.Command['dns_resolve'](name)
    except errors.NotFound:
        raise errors.NotFound(
            reason=_('Nameserver \'%(host)s\' does not have a corresponding A/AAAA record') % {'host': name}
        )

def dns_container_exists(ldap):
    try:
        ldap.get_entry(api.env.container_dns, [])
    except errors.NotFound:
        return False
    return True

def default_zone_update_policy(zone):
    if zone_is_reverse(zone):
        return get_dns_reverse_zone_update_policy(api.env.realm, zone)
    else:
        return get_dns_forward_zone_update_policy(api.env.realm)

dnszone_output_params = (
    Str('managedby',
        label=_('Managedby permission'),
    ),
)

class dnszone(LDAPObject):
    """
    DNS Zone, container for resource records.
    """
    container_dn = api.env.container_dns
    object_name = _('DNS zone')
    object_name_plural = _('DNS zones')
    object_class = ['top', 'idnsrecord', 'idnszone']
    possible_objectclasses = ['ipadnszone']
    default_attributes = [
        'idnsname', 'idnszoneactive', 'idnssoamname', 'idnssoarname',
        'idnssoaserial', 'idnssoarefresh', 'idnssoaretry', 'idnssoaexpire',
        'idnssoaminimum', 'idnsallowquery', 'idnsallowtransfer',
        'idnsforwarders', 'idnsforwardpolicy'
    ] + _record_attributes
    label = _('DNS Zones')
    label_singular = _('DNS Zone')

    takes_params = (
        Str('idnsname',
            _domain_name_validator,
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=lambda name_from_ip: _reverse_zone_name(name_from_ip),
            normalizer=lambda value: value.lower(),
            primary_key=True,
        ),
        Str('name_from_ip?', _validate_ipnet,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
            flags=('virtual_attribute',),
        ),
        Str('idnssoamname',
            cli_name='name_server',
            label=_('Authoritative nameserver'),
            doc=_('Authoritative nameserver domain name'),
        ),
        Str('idnssoarname',
            _rname_validator,
            cli_name='admin_email',
            label=_('Administrator e-mail address'),
            doc=_('Administrator e-mail address'),
            default_from=lambda idnsname: 'hostmaster.%s' % idnsname,
            normalizer=normalize_zonemgr,
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
            label=_('SOA time to live'),
            doc=_('SOA record time to live'),
            minvalue=0,
            maxvalue=2147483647, # see RFC 2181
        ),
        StrEnum('dnsclass?',
            cli_name='class',
            label=_('SOA class'),
            doc=_('SOA record class'),
            values=_record_classes,
        ),
        Str('idnsupdatepolicy?',
            cli_name='update_policy',
            label=_('BIND update policy'),
            doc=_('BIND update policy'),
            default_from=lambda idnsname: default_zone_update_policy(idnsname),
            autofill=True
        ),
        Bool('idnszoneactive?',
            cli_name='zone_active',
            label=_('Active zone'),
            doc=_('Is zone active?'),
            flags=['no_create', 'no_update'],
            attribute=True,
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
        Str('idnsforwarders*',
            _validate_bind_forwarder,
            cli_name='forwarder',
            label=_('Zone forwarders'),
            doc=_('A list of per-zone forwarders. A custom port can be specified '
                  'for each forwarder using a standard format "IP_ADDRESS port PORT"'),
            csv=True,
        ),
        StrEnum('idnsforwardpolicy?',
            cli_name='forward_policy',
            label=_('Forward policy'),
            values=(u'only', u'first',),
        ),
        Bool('idnsallowsyncptr?',
            cli_name='allow_sync_ptr',
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
    )

    def get_dn(self, *keys, **options):
        zone = keys[-1]
        dn = super(dnszone, self).get_dn(zone, **options)
        try:
            self.backend.get_entry(dn, [''])
        except errors.NotFound:
            if zone.endswith(u'.'):
                zone = zone[:-1]
            else:
                zone = zone + u'.'
            test_dn = super(dnszone, self).get_dn(zone, **options)

            try:
                (dn, entry_attrs) = self.backend.get_entry(test_dn, [''])
            except errors.NotFound:
                pass

        return dn

    def permission_name(self, zone):
        return u"Manage DNS zone %s" % zone

api.register(dnszone)


class dnszone_add(LDAPCreate):
    __doc__ = _('Create new DNS zone (SOA record).')

    has_output_params = LDAPCreate.has_output_params + dnszone_output_params
    takes_options = LDAPCreate.takes_options + (
        Flag('force',
             label=_('Force'),
             doc=_('Force DNS zone creation even if nameserver not in DNS.'),
        ),
        Str('ip_address?', _validate_ipaddr,
            doc=_('Add the nameserver to DNS with this IP address'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if not dns_container_exists(self.api.Backend.ldap2):
            raise errors.NotFound(reason=_('DNS is not configured'))

        entry_attrs['idnszoneactive'] = 'TRUE'

        # Check nameserver has a forward record
        nameserver = entry_attrs['idnssoamname']

        # NS record must contain domain name
        if valid_ip(nameserver):
            raise errors.ValidationError(name='name-server',
                    error=unicode(_("Nameserver address is not a fully qualified domain name")))

        if nameserver[-1] != '.':
            nameserver += '.'

        if not 'ip_address' in options and not options['force']:
            check_ns_rec_resolvable(keys[0], nameserver)

        entry_attrs['nsrecord'] = nameserver
        entry_attrs['idnssoamname'] = nameserver
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if 'ip_address' in options:
            nameserver = entry_attrs['idnssoamname'][0][:-1] # ends with a dot
            nsparts = nameserver.split('.')
            add_forward_record('.'.join(nsparts[1:]),
                               nsparts[0],
                               options['ip_address'])

        return dn

api.register(dnszone_add)


class dnszone_del(LDAPDelete):
    __doc__ = _('Delete DNS zone (SOA record).')

    def post_callback(self, ldap, dn, *keys, **options):
        try:
            api.Command['permission_del'](self.obj.permission_name(keys[-1]),
                    force=True)
        except errors.NotFound:
            pass
        return True

api.register(dnszone_del)


class dnszone_mod(LDAPUpdate):
    __doc__ = _('Modify DNS zone (SOA record).')

    has_output_params = LDAPUpdate.has_output_params + dnszone_output_params

api.register(dnszone_mod)


class dnszone_find(LDAPSearch):
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
        return super(dnszone_find, self).args_options_2_params(*args, **options)

    def args_options_2_entry(self, *args, **options):
        if 'name_from_ip' in options:
            if 'idnsname' not in options:
                options['idnsname'] = self.obj.params['idnsname'].get_default(**options)
            del options['name_from_ip']
        return super(dnszone_find, self).args_options_2_entry(*args, **options)

    takes_options = LDAPSearch.takes_options + (
        Flag('forward_only',
            label=_('Forward zones only'),
            cli_name='forward_only',
            doc=_('Search for forward zones only'),
        ),
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        if options.get('forward_only', False):
            search_kw = {}
            search_kw['idnsname'] = REVERSE_DNS_ZONES.keys()
            rev_zone_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_NONE, exact=False,
                    trailing_wildcard=False)
            filter = ldap.combine_filters((rev_zone_filter, filter), rules=ldap.MATCH_ALL)

        return (filter, base_dn, scope)


api.register(dnszone_find)


class dnszone_show(LDAPRetrieve):
    __doc__ = _('Display information about a DNS zone (SOA record).')

    has_output_params = LDAPRetrieve.has_output_params + dnszone_output_params

api.register(dnszone_show)


class dnszone_disable(LDAPQuery):
    __doc__ = _('Disable DNS Zone.')

    has_output = output.standard_value
    msg_summary = _('Disabled DNS zone "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        try:
            ldap.update_entry(dn, {'idnszoneactive': 'FALSE'})
        except errors.EmptyModlist:
            pass

        return dict(result=True, value=keys[-1])

api.register(dnszone_disable)


class dnszone_enable(LDAPQuery):
    __doc__ = _('Enable DNS Zone.')

    has_output = output.standard_value
    msg_summary = _('Enabled DNS zone "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        try:
            ldap.update_entry(dn, {'idnszoneactive': 'TRUE'})
        except errors.EmptyModlist:
            pass

        return dict(result=True, value=keys[-1])

api.register(dnszone_enable)

class dnszone_add_permission(LDAPQuery):
    __doc__ = _('Add a permission for per-zone access delegation.')

    has_output = output.standard_value
    msg_summary = _('Added system permission "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend
        dn = self.obj.get_dn(*keys, **options)

        try:
            (dn_, entry_attrs) = ldap.get_entry(dn, ['objectclass'])
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        permission_name = self.obj.permission_name(keys[-1])
        permission = api.Command['permission_add_noaci'](permission_name,
                         permissiontype=u'SYSTEM'
                     )['result']

        update = {}
        dnszone_ocs = entry_attrs.get('objectclass')
        if dnszone_ocs:
            dnszone_ocs.append('ipadnszone')
            update['objectclass'] = list(set(dnszone_ocs))

        update['managedby'] = [permission['dn']]
        ldap.update_entry(dn, update)

        return dict(
            result=True,
            value=permission_name,
        )

api.register(dnszone_add_permission)

class dnszone_remove_permission(LDAPQuery):
    __doc__ = _('Remove a permission for per-zone access delegation.')

    has_output = output.standard_value
    msg_summary = _('Removed system permission "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend
        dn = self.obj.get_dn(*keys, **options)

        try:
            ldap.update_entry(dn, {'managedby': None})
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        except errors.EmptyModlist:
            # managedBy attribute is clean, lets make sure there is also no
            # dangling DNS zone permission
            pass

        permission_name = self.obj.permission_name(keys[-1])
        api.Command['permission_del'](permission_name, force=True)

        return dict(
            result=True,
            value=permission_name,
        )

api.register(dnszone_remove_permission)

class dnsrecord(LDAPObject):
    """
    DNS record.
    """
    parent_object = 'dnszone'
    container_dn = api.env.container_dns
    object_name = _('DNS resource record')
    object_name_plural = _('DNS resource records')
    object_class = ['top', 'idnsrecord']
    default_attributes = ['idnsname'] + _record_attributes
    rdn_is_primary_key = True

    label = _('DNS Resource Records')
    label_singular = _('DNS Resource Record')

    takes_params = (
        Str('idnsname',
            _dns_record_name_validator,
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
            cli_name='class',
            label=_('Class'),
            doc=_('DNS class'),
            values=_record_classes,
        ),
    ) + _dns_record_options

    structured_flag = Flag('structured',
                           label=_('Structured'),
                           doc=_('Parse all raw DNS records and return them in a structured way'),
                           )

    def _nsrecord_pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        nsrecords = entry_attrs.get('nsrecord')
        if options.get('force', False) or nsrecords is None:
            return
        for nsrecord in nsrecords:
            check_ns_rec_resolvable(keys[0], nsrecord)

    def _ptrrecord_pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        ptrrecords = entry_attrs.get('ptrrecord')
        if ptrrecords is None:
            return
        zone = keys[-2]
        if self.is_pkey_zone_record(*keys):
            addr = u''
        else:
            addr = keys[-1]
        zone_len = 0
        for valid_zone in REVERSE_DNS_ZONES:
            if zone.endswith(valid_zone):
                zone = zone.replace(valid_zone,'')
                zone_name = valid_zone
                zone_len = REVERSE_DNS_ZONES[valid_zone]

        if not zone_len:
            allowed_zones = ', '.join(REVERSE_DNS_ZONES)
            raise errors.ValidationError(name='ptrrecord',
                    error=unicode(_('Reverse zone for PTR record should be a sub-zone of one the following fully qualified domains: %s') % allowed_zones))

        addr_len = len(addr.split('.')) if addr else 0
        ip_addr_comp_count = addr_len + len(zone.split('.'))
        if ip_addr_comp_count != zone_len:
            raise errors.ValidationError(name='ptrrecord',
                error=unicode(_('Reverse zone %(name)s requires exactly %(count)d IP address components, %(user_count)d given')
                % dict(name=zone_name, count=zone_len, user_count=ip_addr_comp_count)))

    def run_precallback_validators(self, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        ldap = self.api.Backend.ldap2

        for rtype in entry_attrs:
            rtype_cb = getattr(self, '_%s_pre_callback' % rtype, None)
            if rtype_cb:
                rtype_cb(ldap, dn, entry_attrs, *keys, **options)

    def is_pkey_zone_record(self, *keys):
        idnsname = keys[-1]
        if idnsname == str(_dns_zone_record) or idnsname == ('%s.' % keys[-2]):
            return True
        return False

    def get_dn(self, *keys, **options):
        if self.is_pkey_zone_record(*keys):
            dn = self.api.Object[self.parent_object].get_dn(*keys[:-1], **options)
            # zone must exist
            ldap = self.api.Backend.ldap2
            try:
                (dn_, zone) = ldap.get_entry(dn, [])
            except errors.NotFound:
                self.api.Object['dnszone'].handle_not_found(keys[-2])
            return self.api.Object[self.parent_object].get_dn(*keys[:-1], **options)
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
                master_dn = entry[0]
                assert isinstance(master_dn, DN)
                try:
                    master = master_dn[1]['cn']
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
        return dict((attr, val) for attr,val in entry_attrs.iteritems() \
                    if attr in self.params and not self.params[attr].primary_key)

    def postprocess_record(self, record, **options):
        if options.get('structured', False):
            for attr in record.keys():
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
                            dnsentry[parts_params[val_id].name] = val
                    record.setdefault('dnsrecords', []).append(dnsentry)
                del record[attr]

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

    def check_record_type_collisions(self, old_entry, entry_attrs):
        # Test that only allowed combination of record types was created
        attrs = set(attr for attr in entry_attrs if attr in _record_attributes
                        and entry_attrs[attr])
        attrs.update(attr for attr in old_entry if attr not in entry_attrs)
        try:
            attrs.remove('cnamerecord')
        except KeyError:
            rec_has_cname = False
        else:
            rec_has_cname = True
        # CNAME and PTR record combination is allowed
        attrs.discard('ptrrecord')
        rec_has_other_types = True if attrs else False

        if rec_has_cname and rec_has_other_types:
            raise errors.ValidationError(name='cnamerecord',
                      error=_('CNAME record is not allowed to coexist with any other '
                              'records except PTR'))

api.register(dnsrecord)


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
                user_options = rrparam.prompt_missing_parts(self.Backend, kw,
                                                            prompt_optional=False)
                new_kw.update(user_options)
            kw.update(new_kw)
            return
        except errors.OptionError:
            pass

        # check zone type
        if kw['idnsname'] == _dns_zone_record:
            common_types = u', '.join(_zone_top_record_types)
        elif zone_is_reverse(kw['dnszoneidnsname']):
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

        user_options = param.prompt_parts(self.Backend)
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
        for attr in entry_attrs:
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
            (dn_, old_entry) = ldap.get_entry(
                        dn, _record_attributes,
                        normalize=self.obj.normalize_dn)
        except errors.NotFound:
            pass
        else:
            for attr in entry_attrs:
                if attr not in _record_attributes:
                    continue
                if entry_attrs[attr] is None:
                    entry_attrs[attr] = []
                if not isinstance(entry_attrs[attr], (tuple, list)):
                    vals = [entry_attrs[attr]]
                else:
                    vals = list(entry_attrs[attr])
                entry_attrs[attr] = list(set(old_entry.get(attr, []) + vals))

            self.obj.check_record_type_collisions(old_entry, entry_attrs)
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.func_name == 'add_entry':
            if isinstance(exc, errors.DuplicateEntry):
                # A new record is being added to existing LDAP DNS object
                # Update can be safely run as old record values has been
                # already merged in pre_callback
                ldap = self.obj.backend
                dn = call_args[0]
                entry_attrs = self.obj.get_record_entry_attrs(call_args[1])
                ldap.update_entry(dn, entry_attrs, **call_kwargs)
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

        return dn

api.register(dnsrecord_add)


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
            (dn_, old_entry) = ldap.get_entry(dn, _record_attributes,
                                              normalize=self.obj.normalize_dn)
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

        self.obj.check_record_type_collisions(old_entry, entry_attrs)
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
            (dn_, old_entry) = ldap.get_entry(
                    dn, _record_attributes,
                    normalize=self.obj.normalize_dn)

            del_all = True
            for attr in old_entry:
                if old_entry[attr]:
                    del_all = False
                    break

            if del_all:
                return self.obj.methods.delentry(*keys)
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
                    user_options = param.prompt_parts(self.Backend, mod_dnsvalue=rec_value)
                    kw[param.name] = [rec_value]
                    kw.update(user_options)

                    if rec_values:
                         self.Backend.textui.print_plain(ngettext(
                            u'%(count)d %(type)s record skipped. Only one value per DNS record type can be modified at one time.',
                            u'%(count)d %(type)s records skipped. Only one value per DNS record type can be modified at one time.',
                            0) % dict(count=len(rec_values), type=param.rrtype))
                         break

api.register(dnsrecord_mod)


class dnsrecord_delentry(LDAPDelete):
    """
    Delete DNS record entry.
    """
    msg_summary = _('Deleted record "%(value)s"')
    NO_CLI = True

api.register(dnsrecord_delentry)


class dnsrecord_del(LDAPUpdate):
    __doc__ = _('Delete DNS resource record.')

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
            (dn_, old_entry) = ldap.get_entry(
                    dn, _record_attributes,
                    normalize=self.obj.normalize_dn)
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

        del_all = False
        if not self.obj.is_pkey_zone_record(*keys):
            record_found = False
            for attr in old_entry:
                if old_entry[attr]:
                    record_found = True
                    break
            del_all = not record_found

        # set del_all flag in context
        # when the flag is enabled, the entire DNS record object is deleted
        # in a post callback
        setattr(context, 'del_all', del_all)

        return dn

    def execute(self, *keys, **options):
        if options.get('del_all', False):
            if self.obj.is_pkey_zone_record(*keys):
                raise errors.ValidationError(
                        name='del_all',
                        error=_('Zone record \'%s\' cannot be deleted') \
                                % _dns_zone_record
                      )
            return self.obj.methods.delentry(*keys)

        result = super(dnsrecord_del, self).execute(*keys, **options)

        if getattr(context, 'del_all', False) and not \
                self.obj.is_pkey_zone_record(*keys):
            return self.obj.methods.delentry(*keys)
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
                        _("Delete %(name)s '%(value)s'?") \
                            % dict(name=param.label, value=rec_value), default=False)
                if user_del_value is True:
                     deleted_values.append(rec_value)
            if deleted_values:
                kw[param.name] = tuple(deleted_values)

api.register(dnsrecord_del)


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

api.register(dnsrecord_show)


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
        # include zone record (root entry) in the search
        return (filter, base_dn, ldap.SCOPE_SUBTREE)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if entries:
            zone_obj = self.api.Object[self.obj.parent_object]
            zone_dn = zone_obj.get_dn(args[0])
            if entries[0][0] == zone_dn:
                entries[0][1][zone_obj.primary_key.name] = [_dns_zone_record]
            for entry in entries:
                self.obj.postprocess_record(entry[1], **options)

        return truncated

api.register(dnsrecord_find)

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

api.register(dns_resolve)

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

        return dict(result=dns_enabled, value=u'')

api.register(dns_is_enabled)


class dnsconfig(LDAPObject):
    """
    DNS global configuration object
    """
    object_name = _('DNS configuration options')
    default_attributes = [
        'idnsforwardpolicy', 'idnsforwarders', 'idnsallowsyncptr',
        'idnszonerefresh'
    ]

    label = _('DNS Global Configuration')
    label_singular = _('DNS Global Configuration')

    takes_params = (
        Str('idnsforwarders*',
            _validate_bind_forwarder,
            cli_name='forwarder',
            label=_('Global forwarders'),
            doc=_('A list of global forwarders. A custom port can be specified ' \
                  'for each forwarder using a standard format "IP_ADDRESS port PORT"'),
            csv=True,
        ),
        StrEnum('idnsforwardpolicy?',
            cli_name='forward_policy',
            label=_('Forward policy'),
            values=(u'only', u'first',),
        ),
        Bool('idnsallowsyncptr?',
            cli_name='allow_sync_ptr',
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records'),
        ),
        Int('idnszonerefresh?',
            cli_name='zone_refresh',
            label=_('Zone refresh interval'),
            doc=_('An interval between regular polls of the name server for new DNS zones'),
            minvalue=0,
        ),
    )

    def get_dn(self, *keys, **kwargs):
        return api.env.container_dns

    def get_dnsconfig(self, ldap):
        (dn, entry) = ldap.get_entry(self.get_dn(), None,
                           normalize=self.normalize_dn)

        return entry

    def postprocess_result(self, result):
        if not any(param in result['result'] for param in self.params):
            result['summary'] = unicode(_('Global DNS configuration is empty'))

api.register(dnsconfig)


class dnsconfig_mod(LDAPUpdate):
    __doc__ = _('Modify global DNS configuration.')

    def execute(self, *keys, **options):
        result = super(dnsconfig_mod, self).execute(*keys, **options)
        self.obj.postprocess_result(result)
        return result

api.register(dnsconfig_mod)


class dnsconfig_show(LDAPRetrieve):
    __doc__ = _('Show the current global DNS configuration.')

    def execute(self, *keys, **options):
        result = super(dnsconfig_show, self).execute(*keys, **options)
        self.obj.postprocess_result(result)
        return result

api.register(dnsconfig_show)
