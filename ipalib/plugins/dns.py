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

import netaddr
import time
import re

from ipalib.request import context
from ipalib import api, errors, output
from ipalib import Command
from ipalib.parameters import Flag, Bool, Int, Decimal, Str, StrEnum, Any
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
from ipalib.util import validate_zonemgr, normalize_zonemgr, validate_hostname
from ipapython import dnsclient
from ipapython.ipautil import valid_ip
from ldap import explode_dn

__doc__ = _("""
Domain Name System (DNS)

Manage DNS zone and resource records.

EXAMPLES:

 Add new zone:
   ipa dnszone-add example.com --name-server=nameserver.example.com \\
                               --admin-email=admin@example.com

 Modify the zone to allow dynamic updates for hosts own records in realm EXAMPLE.COM:
   ipa dnszone-mod example.com --dynamic-update=TRUE \\
        --update-policy="grant EXAMPLE.COM krb5-self * A; grant EXAMPLE.COM krb5-self * AAAA;"

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

 Add new A record for www.example.com: (random IP)
   ipa dnsrecord-add example.com www --a-rec=80.142.15.2

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

 Delete zone example.com with all resource records:
   ipa dnszone-del example.com

 Resolve a host name to see if it exists (will add default IPA domain
 if one is not included):
   ipa dns-resolve www.example.com
   ipa dns-resolve www
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

def _create_zone_serial(**kwargs):
    """Generate serial number for zones."""
    return int('%s01' % time.strftime('%Y%d%m'))

def _reverse_zone_name(netstr):
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
        ip = netaddr.IPAddress(ipaddr)

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

def _domain_name_validator(ugettext, value):
    try:
        # Allow domain name which is not fully qualified. These are supported
        # in bind and then translated as <non-fqdn-name>.<domain>.
        validate_hostname(value, check_fqdn=False)
    except ValueError, e:
        return _('invalid domain-name: %s') \
            % unicode(e)

    return None

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

class DNSRecord(Str):
    parts = None
    supported = True
    # supported RR types: https://fedorahosted.org/bind-dyndb-ldap/browser/doc/schema

    label_format = _("%s record")
    part_label_format = "%s %s"
    doc_format = _('Comma-separated list of raw %s records')
    option_group_format = _('%s Record')
    see_rfc_msg = _("(see RFC %s for details)")
    part_name_format = "%s_part_%s"
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
            # convert parsed values to the string
            self._validate_parts(value)
            return u" ".join(super(DNSRecord, self)._convert_scalar(v, index) \
                             for v in value if v is not None)
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

    def get_parts(self):
        if self.parts is None:
            return tuple()

        parts = []

        for part in self.parts:
            name = self.part_name_format % (self.rrtype.lower(), part.name)
            cli_name = self.cli_name_format % (self.rrtype.lower(), part.name)
            label = self.part_label_format % (self.rrtype, unicode(part.label))
            option_group = self.option_group_format % self.rrtype
            flags = list(part.flags) + ['dnsrecord_part', 'virtual_attribute',]

            if not part.required:
                flags.append('dnsrecord_optional')

            parts.append(part.clone_rename(name,
                         cli_name=cli_name,
                         label=label,
                         required=False,
                         option_group=option_group,
                         flags=flags))

        return tuple(parts)

    def prompt_parts(self, backend, mod_dnsvalue=None):
        mod_parts = None
        if mod_dnsvalue is not None:
            mod_parts = self._get_part_values(mod_dnsvalue)

        user_options = {}
        if self.parts is None:
            return user_options

        for part_id, part in enumerate(self.parts):
            name = self.part_name_format % (self.rrtype.lower(), part.name)
            label = self.part_label_format % (self.rrtype, unicode(part.label))
            optional = not part.required
            if mod_parts:
                default = mod_parts[part_id]
            else:
                default = None

            raw = backend.textui.prompt(label,
                                        optional=optional,
                                        default=default)
            if not raw.strip():
                raw = default

            user_options[name] = part(raw)

        return user_options

class ARecord(DNSRecord):
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
    parts = None    # experimental rr type

class AAAARecord(DNSRecord):
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
            _domain_name_validator,
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
            _domain_name_validator,
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
            _domain_name_validator,
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
            _domain_name_validator,
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
            label=_('Degrees Longtitude'),
            minvalue=0,
            maxvalue=180,
        ),
        Int('lon_min?',
            label=_('Minutes Longtitude'),
            minvalue=0,
            maxvalue=59,
        ),
        Decimal('lon_sec?',
            label=_('Seconds Longtitude'),
            minvalue='0.0',
            maxvalue='59.999',
            precision=3,
        ),
        StrEnum('lon_dir',
            label=_('Direction Longtitude'),
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
            _domain_name_validator,
            label=_('Exchanger'),
            doc=_('A host willing to act as a mail exchanger'),
        ),
    )

class NSRecord(DNSRecord):
    rrtype = 'NS'
    rfc = 1035

    parts = (
        Str('hostname',
            _domain_name_validator,
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
            _domain_name_validator,
            label=_('Next Domain Name'),
        ),
        StrEnum('types',
            label=_('Type Map'),
            multivalue=True,
            values=_allowed_types,
        ),
    )

    def _get_part_values(self, value):
        values = value.split()

        if len(values) < 2:
            return None

        return (values[0], tuple(values[1:]))

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

_dns_record_options = tuple(__dns_record_options_iter())

# dictionary of valid reverse zone -> number of address components
_valid_reverse_zones = {
    '.in-addr.arpa.' : 4,
    '.ip6.arpa.' : 32,
}

def zone_is_reverse(zone_name):
    for rev_zone_name in _valid_reverse_zones.keys():
        if zone_name.endswith(rev_zone_name):
            return True

    return False

def is_ns_rec_resolvable(name):
    try:
        return api.Command['dns_resolve'](name)
    except errors.NotFound:
        raise errors.NotFound(
            reason=_('Nameserver \'%(host)s\' does not have a corresponding A/AAAA record') % {'host': name}
        )

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

def dns_container_exists(ldap):
    try:
        ldap.get_entry(api.env.container_dns, [])
    except errors.NotFound:
        return False
    return True

class dnszone(LDAPObject):
    """
    DNS Zone, container for resource records.
    """
    container_dn = api.env.container_dns
    object_name = _('DNS zone')
    object_name_plural = _('DNS zones')
    object_class = ['top', 'idnsrecord', 'idnszone']
    default_attributes = [
        'idnsname', 'idnszoneactive', 'idnssoamname', 'idnssoarname',
        'idnssoaserial', 'idnssoarefresh', 'idnssoaretry', 'idnssoaexpire',
        'idnssoaminimum'
    ] + _record_attributes
    label = _('DNS Zones')
    label_singular = _('DNS Zone')

    takes_params = (
        Str('idnsname',
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
            create_default=_create_zone_serial,
            autofill=True,
        ),
        Int('idnssoarefresh',
            cli_name='refresh',
            label=_('SOA refresh'),
            doc=_('SOA record refresh time'),
            minvalue=0,
            default=3600,
            autofill=True,
        ),
        Int('idnssoaretry',
            cli_name='retry',
            label=_('SOA retry'),
            doc=_('SOA record retry time'),
            minvalue=0,
            default=900,
            autofill=True,
        ),
        Int('idnssoaexpire',
            cli_name='expire',
            label=_('SOA expire'),
            doc=_('SOA record expire time'),
            default=1209600,
            minvalue=0,
            autofill=True,
        ),
        Int('idnssoaminimum',
            cli_name='minimum',
            label=_('SOA minimum'),
            doc=_('How long should negative responses be cached'),
            default=3600,
            minvalue=0,
            maxvalue=10800,
            autofill=True,
        ),
        Int('dnsttl?',
            cli_name='ttl',
            label=_('SOA time to live'),
            doc=_('SOA record time to live'),
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
    )

api.register(dnszone)


class dnszone_add(LDAPCreate):
    __doc__ = _('Create new DNS zone (SOA record).')

    takes_options = LDAPCreate.takes_options + (
        Flag('force',
             label=_('Force'),
             doc=_('Force DNS zone creation even if nameserver not in DNS.'),
        ),
        Str('ip_address?', _validate_ipaddr,
            doc=_('Add the nameserver to DNS with this IP address'),
        ),
    )

    def args_options_2_params(self, *args, **options):
        # FIXME: Check if name_from_ip is valid. The framework should do that,
        #        but it does not. Before it's fixed, this should suffice.
        if 'name_from_ip' in options:
            self.obj.params['name_from_ip'](unicode(options['name_from_ip']))
        return super(dnszone_add, self).args_options_2_params(*args, **options)

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if not dns_container_exists(self.api.Backend.ldap2):
            raise errors.NotFound(reason=_('DNS is not configured'))

        entry_attrs['idnszoneactive'] = 'TRUE'

        # Check nameserver has a forward record
        nameserver = entry_attrs['idnssoamname']

        # NS record must contain domain name
        if valid_ip(nameserver):
            raise errors.ValidationError(name='name-server',
                    error=unicode(_("Nameserver address is not a fully qualified domain name")))

        if not 'ip_address' in options and not options['force']:
            is_ns_rec_resolvable(nameserver)

        if nameserver[-1] != '.':
            nameserver += '.'

        entry_attrs['nsrecord'] = nameserver
        entry_attrs['idnssoamname'] = nameserver
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
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

api.register(dnszone_del)


class dnszone_mod(LDAPUpdate):
    __doc__ = _('Modify DNS zone (SOA record).')

    def args_options_2_params(self, *args, **options):
        # FIXME: Check if name_from_ip is valid. The framework should do that,
        #        but it does not. Before it's fixed, this should suffice.
        if 'name_from_ip' in options:
            self.obj.params['name_from_ip'](unicode(options['name_from_ip']))
        return super(dnszone_mod, self).args_options_2_params(*args, **options)

api.register(dnszone_mod)


class dnszone_find(LDAPSearch):
    __doc__ = _('Search for DNS zones (SOA records).')

    def args_options_2_params(self, *args, **options):
        # FIXME: Check if name_from_ip is valid. The framework should do that,
        #        but it does not. Before it's fixed, this should suffice.
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
        if options.get('forward_only', False):
            search_kw = {}
            search_kw['idnsname'] = _valid_reverse_zones.keys()
            rev_zone_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_NONE, exact=False,
                    trailing_wildcard=False)
            filter = ldap.combine_filters((rev_zone_filter, filter), rules=ldap.MATCH_ALL)

        return (filter, base_dn, scope)


api.register(dnszone_find)


class dnszone_show(LDAPRetrieve):
    __doc__ = _('Display information about a DNS zone (SOA record).')

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

    label = _('DNS Resource Records')
    label_singular = _('DNS Resource Record')

    takes_params = (
        Str('idnsname',
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
        if options.get('force', False):
            return dn

        for ns in options['nsrecord']:
            is_ns_rec_resolvable(ns)
        return dn

    def _ptrrecord_pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        components = dn.split(',',2)
        addr = components[0].split('=')[1]
        zone = components[1].split('=')[1]
        zone_len = 0
        for valid_zone in _valid_reverse_zones:
            if zone.find(valid_zone) != -1:
                zone = zone.replace(valid_zone,'')
                zone_name = valid_zone
                zone_len = _valid_reverse_zones[valid_zone]

        if not zone_len:
            allowed_zones = ', '.join(_valid_reverse_zones)
            raise errors.ValidationError(name='cn',
                    error=unicode(_('Reverse zone for PTR record should be a sub-zone of one the following fully qualified domains: %s') % allowed_zones))

        ip_addr_comp_count = len(addr.split('.')) + len(zone.split('.'))
        if ip_addr_comp_count != zone_len:
            raise errors.ValidationError(name='cn',
                error=unicode(_('Reverse zone %(name)s requires exactly %(count)d IP address components, %(user_count)d given')
                % dict(name=zone_name, count=zone_len, user_count=ip_addr_comp_count)))

        return dn

    def is_pkey_zone_record(self, *keys):
        idnsname = keys[-1]
        if idnsname == str(_dns_zone_record) or idnsname == ('%s.' % keys[-2]):
            return True
        return False

    def get_dn(self, *keys, **options):
        if self.is_pkey_zone_record(*keys):
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
        base_dn = 'cn=masters,cn=ipa,cn=etc,%s' % self.api.env.basedn
        ldap_filter = '(&(objectClass=ipaConfigObject)(cn=DNS))'
        dns_masters = []

        try:
            entries = ldap.find_entries(filter=ldap_filter, base_dn=base_dn)[0]

            for entry in entries:
                master_dn = entry[0]
                if master_dn.startswith('cn='):
                    master = explode_dn(master_dn)[1].replace('cn=','')
                    dns_masters.append(master)
        except errors.NotFound:
            return []

        return dns_masters

    def has_cli_options(self, options, no_option_msg, allow_empty_attrs=False):
        if any(k in options for k in ('setattr', 'addattr', 'delattr')):
            return

        has_options = False
        for attr in options.keys():
            if attr in self.params and not self.params[attr].primary_key:
                if options[attr] or allow_empty_attrs:
                    has_options = True
                    break

        if not has_options:
            raise errors.OptionError(no_option_msg)

    def get_record_option(self, rec_type):
        name = '%srecord' % rec_type.lower()
        if name in self.params:
            return self.params[name]
        else:
            return None

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
                    for val_id, val in enumerate(values):
                        if val is not None:
                            dnsentry[parts_params[val_id].name] = val
                    record.setdefault('dnsrecords', []).append(dnsentry)
                del record[attr]

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
        except errors.OptionError:
            pass
        else:
            # some record type entered, skip this helper
            return

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
            except KeyError, ValueError:
                all_types = u', '.join(_record_types)
                self.Backend.textui.print_plain(_(u'Invalid type. Allowed values are: %s') % all_types)
                continue
            ok = True

        user_options = param.prompt_parts(self.Backend)
        kw.update(user_options)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        for rtype in options:
            rtype_cb = '_%s_pre_callback' % rtype
            if hasattr(self.obj, rtype_cb):
                dn = getattr(self.obj, rtype_cb)(ldap, dn, entry_attrs, *keys, **options)

        # check if any record part was added
        for option in options:
            option_part_re = re.match(r'([a-z]+)_part_', option)

            if option_part_re is not None:
                record_option = self.obj.get_record_option(option_part_re.group(1))
                if record_option.name in entry_attrs:
                    # this record was already entered
                    continue

                parts = record_option.get_parts_from_kw(options)
                dnsvalue = [record_option._convert_scalar(parts)]
                entry_attrs[record_option.name] = dnsvalue

        try:
            (dn_, old_entry) = ldap.get_entry(
                        dn, entry_attrs.keys(),
                        normalize=self.obj.normalize_dn)
            for attr in old_entry.keys():
                if attr not in _record_attributes:
                    continue
                if not isinstance(entry_attrs[attr], (tuple, list)):
                    vals = [entry_attrs[attr]]
                else:
                    vals = list(entry_attrs[attr])
                entry_attrs[attr] = list(set(old_entry[attr] + vals))
        except errors.NotFound:
            pass
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

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        for rtype in options:
            rtype_cb = '_%s_pre_callback' % rtype
            if options[rtype] is None and rtype in _record_attributes:
                options[rtype] = []
            if hasattr(self.obj, rtype_cb):
                dn = getattr(self.obj, rtype_cb)(ldap, dn, entry_attrs, *keys, **options)

        # check if any attr should be updated using structured instead of replaced
        # format is recordname : (old_value, new_parts)
        updated_attrs = {}
        for attr in entry_attrs:
            param = self.params[attr]
            if not isinstance(param, DNSRecord):
                continue

            parts = param.get_parts_from_kw(options, raise_on_none=False)

            if parts is None:
                # old-style modification
                continue

            if isinstance(entry_attrs[attr], (tuple, list)):
                if len(entry_attrs[attr]) > 1:
                    raise errors.ValidationError(name=param.name,
                           error=_('DNS records can be only updated one at a time'))
                old_value = entry_attrs[attr][0]
            else:
                old_value = entry_attrs[attr]

            updated_attrs[attr] = (old_value, parts)

        if len(updated_attrs):
            try:
                (dn_, old_entry) = ldap.get_entry(
                            dn, updated_attrs.keys(),
                            normalize=self.obj.normalize_dn)
            except errors.NotFound:
                self.obj.handle_not_found(*keys)

            for attr in updated_attrs:
                param = self.params[attr]
                old_dnsvalue, new_parts = updated_attrs[attr]

                if old_dnsvalue not in old_entry.get(attr, []):
                    raise errors.AttrValueNotFound(attr=attr,
                                                   value=old_dnsvalue)
                old_entry[attr].remove(old_dnsvalue)

                old_parts = param._get_part_values(old_dnsvalue)
                modified_parts = tuple(part if part is not None else old_parts[part_id] \
                                               for part_id,part in enumerate(new_parts))

                new_dnsvalue = [param._convert_scalar(modified_parts)]
                entry_attrs[attr] = list(set(old_entry[attr] + new_dnsvalue))

        return dn

    def execute(self, *keys, **options):
        result = super(dnsrecord_mod, self).execute(*keys, **options)

        # remove if empty
        if not self.obj.is_pkey_zone_record(*keys):
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
        self.obj.postprocess_record(entry_attrs, **options)

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
            if 'dnsrecord_part' in option.flags:
                continue
            elif isinstance(option, DNSRecord):
                yield option.clone(option_group=None)
                continue
            yield option

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
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
                    raise errors.AttrValueNotFound(attr=attr,
                                                   value=val)
            entry_attrs[attr] = list(set(old_entry[attr]))

        if not self.obj.is_pkey_zone_record(*keys):
            del_all = True
            for attr in old_entry:
                if old_entry[attr]:
                    del_all = False
                    break
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

        if getattr(context, 'del_all', False):
            return self.obj.methods.delentry(*keys)
        return result

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [_dns_zone_record]
        self.obj.postprocess_record(entry_attrs, **options)

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
                deleted_list = u','.join(deleted_values)
                kw[param.name] = param(deleted_list)

api.register(dnsrecord_del)


class dnsrecord_show(LDAPRetrieve):
    __doc__ = _('Display DNS resource.')

    takes_options = LDAPRetrieve.takes_options + (
        dnsrecord.structured_flag,
    )

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
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

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
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
        reca = dnsclient.query(query, dnsclient.DNS_C_IN, dnsclient.DNS_T_A)
        rec6 = dnsclient.query(query, dnsclient.DNS_C_IN, dnsclient.DNS_T_AAAA)
        records = reca + rec6
        found = False
        for rec in records:
            if rec.dns_type == dnsclient.DNS_T_A or \
              rec.dns_type == dnsclient.DNS_T_AAAA:
                found = True
                break

        if not found:
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

    base_dn = 'cn=masters,cn=ipa,cn=etc,%s' % api.env.basedn
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
