# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#   Martin Kosek <mkosek@redhat.com>
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

from ipalib import api, errors, output
from ipalib import Command
from ipalib import Flag, Bool, Int, Str, StrEnum
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
   ipa dnszone-add example.com --name-server nameserver.example.com
                               --admin-email admin@example.com

 Modify the zone to allow dynamic updates for hosts own records in realm EXAMPLE.COM:
   ipa dnszone-mod example.com --dynamic-update=TRUE \\
        --update-policy="grant EXAMPLE.COM krb5-self * A; grant EXAMPLE.COM krb5-self * AAAA;"

 Add new reverse zone specified by network IP address:
   ipa dnszone-add --name-from-ip 80.142.15.0/24
                   --name-server nameserver.example.com

 Add second nameserver for example.com:
   ipa dnsrecord-add example.com @ --ns-rec nameserver2.example.com

 Add a mail server for example.com:
   ipa dnsrecord-add example.com @ --mx-rec="10 mail2"

 Delete previously added nameserver from example.com:
   ipa dnsrecord-del example.com @ --ns-rec nameserver2.example.com

 Add LOC record for example.com:
   ipa dnsrecord-add example.com @ --loc-rec "49 11 42.4 N 16 36 29.6 E 227.64m"

 Add new A record for www.example.com: (random IP)
   ipa dnsrecord-add example.com www --a-rec 80.142.15.2

 Add new PTR record for www.example.com
   ipa dnsrecord-add 15.142.80.in-addr.arpa. 2 --ptr-rec www.example.com.

 Add new SRV records for LDAP servers. Three quarters of the requests
 should go to fast.example.com, one quarter to slow.example.com. If neither
 is available, switch to backup.example.com.
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 3 389 fast.example.com"
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 1 389 slow.example.com"
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="1 1 389 backup.example.com"

 When dnsrecord-add command is executed with no option to add a specific record
 an interactive mode is started. The mode interactively prompts for the most
 typical record types for the respective zone:
   ipa dnsrecord-add example.com www
   [A record]: 1.2.3.4,11.22.33.44      (2 interactively entered random IPs)
   [AAAA record]:                       (no AAAA address entered)
     Record name: www
     A record: 1.2.3.4, 11.22.33.44

 The interactive mode can also be used for deleting the DNS records:
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
   ipa dnsrecord-find example.com --a-rec 10.10.0.1

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

def _validate_ipaddr(ugettext, ipaddr):
    try:
        ip = netaddr.IPAddress(ipaddr)
    except (netaddr.AddrFormatError, ValueError):
        return _('invalid IP address format')
    return None

def _validate_ipnet(ugettext, ipnet):
    try:
        net = netaddr.IPNetwork(ipnet)
    except (netaddr.AddrFormatError, ValueError, UnboundLocalError):
        return _('invalid IP network format')
    return None

def _validate_srv(ugettext, srv):
    """see RFC 2782"""
    try:
        prio, weight, port, host = srv.split()
    except ValueError:
        return _('format must be specified as "priority weight port target"')

    try:
        prio = int(prio)
        weight = int(weight)
        port = int(port)
    except ValueError:
        return _('format must be specified as "priority weight port target" '\
                 '(see RFC 2782 for details)')

    return None

def _validate_mx(ugettext, mx):
    """see RFC 1035"""
    try:
        prio, host = mx.split()
    except ValueError:
        return _('format must be specified as "priority mailserver" '\
                 '(see RFC 1035 for details)')

    try:
        prio = int(prio)
    except ValueError:
        return _('the value of priority must be integer')

    if prio < 0 or prio > 65535:
        return _('the value of priority must be between 0 and 65535')

    return None

def _validate_naptr(ugettext, naptr):
    """see RFC 2915"""
    try:
        order, pref, flags, svc, regexp, replacement = naptr.split()
    except ValueError:
        return _('format must be specified as "order preference flags service '\
                 'regexp replacement" (see RFC 2915 for details)')

    try:
        order = int(order)
        pref = int(pref)
    except ValueError:
        return _('order and preference must be integers')

    if order < 0 or order > 65535 or pref < 0 or pref > 65535:
        return _('the value of order and preference must be between 0 and 65535')

    flags = flags.replace('"','')
    flags = flags.replace('\'','')
    if len(flags) != 1:
        return _('flag must be a single character (quotation is allowed)')
    if flags.upper() not in "SAUP":
        return _('flag must be one of "S", "A", "U", or "P"')

    return None

def _validate_afsdb(ugettext, afsdb):
    """see RFC 1183"""
    try:
        sub, host = afsdb.split()
    except ValueError:
        return _('format must be specified as "subtype hostname" (see RFC 1183 for details)')

    try:
        sub = int(sub)
    except ValueError:
        return _('the value of subtype must be integer')

    if sub < 0 or sub > 65535:
        return _('the value of subtype must be between 0 and 65535')

    return None

def _validate_cert(ugettext, cert):
    """see RFC 4398"""
    try:
        cert_type, key_tag, algorithm, certificate = cert.split()
    except ValueError:
        return _('format must be specified as "type key_tag algorithm certificate_or_crl" '\
                 '(see RFC 4398 for details)')

    try:
        cert_type = int(cert_type)
        key_tag = int(key_tag)
        algorithm = int(algorithm)
    except ValueError:
        return _('key_tag, algorithm and digest_type must be integers')

    if cert_type < 0 or cert_type > 65535 or key_tag < 0 or key_tag > 65535:
        return _('the value of type and key_tag must be between 0 and 65535')

    if algorithm < 0 or algorithm > 255:
        return _('the value of algorithm must be between 0 and 255')

    return None

def _validate_cname(ugettext, cname):
    """see RFC 1035"""
    try:
        validate_hostname(cname)
    except ValueError, e:
        return _('format must be specified as "domain_name" (see RFC 1035 for details): %s') \
            % unicode(e)

    return None

def _validate_dname(ugettext, dname):
    """see RFC 2672"""
    try:
        validate_hostname(dname)
    except ValueError, e:
        return _('format must be specified as "target" (see RFC 2672 for details): %s') \
            % unicode(e)

    return None

def _validate_ds(ugettext, ds):
    """see RFC 4034"""
    try:
        key_tag, algorithm, digest_type, digest = ds.split()
    except ValueError:
        return _('format must be specified as "key_tag algorithm digest_type digest" '\
                 '(see RFC 4034 for details)')

    try:
        key_tag = int(key_tag)
        algorithm = int(algorithm)
        digest_type = int(digest_type)
    except ValueError:
        return _('key_tag, algorithm and digest_type must be integers')

    if key_tag < 0 or key_tag > 65535:
        return _('the value of flags must be between 0 and 65535')

    if algorithm < 0 or algorithm > 255 or digest_type < 0 or digest_type > 255:
        return _('the value of algorithm and digest_type must be between 0 and 255')

    return None

def _validate_key(ugettext, key):
    """see RFC 2535"""
    try:
        flags, protocol, algorithm, digest = key.split()
    except ValueError:
        return _('format must be specified as "flags protocol algorithm public_key" '\
                 '(see RFC 2535 for details)')

    try:
        flags = int(flags)
        protocol = int(protocol)
        algorithm = int(algorithm)
    except ValueError:
        return _('flags, protocol and algorithm must be integers')

    if flags < 0 or flags > 65535:
        return _('the value of flags must be between 0 and 65535')

    if protocol < 0 or protocol > 255:
        return _('the value of protocol must be between 0 and 255')

    if algorithm < 0 or algorithm > 255:
        return _('the value of algorithm must be between 0 and 255')

    return None

def _validate_loc(ugettext, loc):
    """see RFC 1876"""
    regex = re.compile(\
        r'(?P<d1>\d{1,2}\s+)(?P<m1>\d{1,2}\s+)?(?P<s1>\d{1,2}\.?\d{1,3}?\s+)'\
        r'?[N|S]\s+'\
        r'(?P<d2>\d{1,2}\s+)(?P<m2>\d{1,2}\s+)?(?P<s2>\d{1,2}\.?\d{1,3}?\s+)'\
        r'?[W|E]\s+'\
        r'(?P<alt>-?\d{1,8}\.?\d{1,2}?)m?\s*'\
        r'(?P<siz>\d{1,8}\.?\d{1,2}?)?m?\s*'\
        r'(?P<hp>\d{1,8}\.?\d{1,2}?)?m?\s*(?P<vp>\d{1,8}\.?\d{1,2}?)?m?\s*$')

    m = regex.match(loc)

    if m is None:
        return _("""format must be specified as
    "d1 [m1 [s1]] {"N"|"S"}  d2 [m2 [s2]] {"E"|"W"} alt["m"] [siz["m"] [hp["m"] [vp["m"]]]]"
    where:
       d1:     [0 .. 90]            (degrees latitude)
       d2:     [0 .. 180]           (degrees longitude)
       m1, m2: [0 .. 59]            (minutes latitude/longitude)
       s1, s2: [0 .. 59.999]        (seconds latitude/longitude)
       alt:    [-100000.00 .. 42849672.95] BY .01 (altitude in meters)
       siz, hp, vp: [0 .. 90000000.00] (size/precision in meters)
    See RFC 1876 for details""")

    attrs = {}
    for attr in ('d1', 'd2', 'm1', 'm2'):
        if m.group(attr) is not None:
            try:
                attrs[attr] = int(m.group(attr))
            except ValueError:
                return _('%s must be integer') % attr

    for attr in ('s1', 's2', 'alt', 'siz', 'hp', 'vp'):
        if m.group(attr) is not None:
            try:
                attrs[attr] = float(m.group(attr))
            except ValueError:
                return _('%s must be float') % attr

    if attrs.get('d1', 0) > 90 or attrs.get('d2', 0) > 90:
        return _(u'd1 and d2 must be between 0 and 90')

    if attrs.get('m1', 0) >= 60 or attrs.get('m2', 0) >= 60 or \
       attrs.get('s1', 0) >= 60 or attrs.get('s2', 0) >= 60:
        return _('m1, m2, s1 and s2 must be between 0 and 59.999')

    if attrs.get('alt', 0) < -100000.00 or attrs.get('alt', 0) > 42849672.95:
        return _('alt must be between -100000.00 and 42849672.95')

    if attrs.get('siz', 0) > 90000000.00 or attrs.get('hp', 0) > 90000000.00 or \
       attrs.get('vp', 0) > 90000000.00:
        return _('siz, hp and vp must be between 0 and 90000000.00')

    return None

def _validate_ns(ugettext, ns):
    """see RFC 1035"""
    try:
        ns, = ns.split()
    except ValueError:
        return _('format must be specified as "domain_name" (see RFC 1035 for details)')

    return None

def _validate_nsec(ugettext, nsec):
    """see RFC 4034"""
    fields = nsec.split()

    if len(fields) < 2:
        return _('format must be specified as "next_domain_name type1 '\
                '[type2 [type3 [...]]]" (see RFC 4034 for details)')

    allowed_types = (u'SOA',) + _record_types
    for i in range(1, len(fields)):
        sig_type = fields[i]
        if sig_type not in allowed_types:
            return _('type must be one of ' + u', '.join(allowed_types))

    return None

def _validate_kx(ugettext, kx):
    """see RFC 2230"""
    try:
        preference, exchanger = kx.split()
    except ValueError:
        return _('format must be specified as "preference exchanger" '\
                 '(see RFC 2230 for details)')

    try:
        preference = int(preference)
    except ValueError:
        return _(u'the value of preference must be integer')

    if preference < 0 or preference > 65535:
        return _('the value of preference must be between 0 and 65535')

    return None

def _validate_ptr(ugettext, ptr):
    """see RFC 1035"""
    try:
        validate_hostname(ptr)
    except ValueError, e:
        return _('format must be specified as "domain_name" (see RFC 1035 for details): %s') \
            % unicode(e)

    return None

def _validate_sig(ugettext, sig):
    """see RFCs 2535, 4034"""
    try:
        sig_type, algorithm, labels, ttl, sig_expiration, \
                sig_inception, tag, signer, signature = sig.split()
    except ValueError:
        return _('format must be specified as "type_covered algorithm labels original_ttl ' \
               'signature_expiration signature_inception key_tag signers_name signature" '\
               '(see RFC 2535, 4034 for details)')

    allowed_types = [x for x in _record_types if x != u'SIG']
    if sig_type not in allowed_types:
        return _('type_covered must be one of ' + u', '.join(allowed_types))

    try:
        algorithm = int(algorithm)
        labels = int(labels)
        ttl = int(ttl)
        tag = int(tag)
    except ValueError:
        return _('algorithm, labels, original_ttl and key_tag must be integers')

    try:
        time_format = "%Y%m%d%H%M%S"
        sig_inception = time.strptime(sig_inception, time_format)
        sig_expiration = time.strptime(sig_expiration, time_format)
    except ValueError, e:
        return _('signature_expiration and signature_inception must follow time ' \
               'format "YYYYMMDDHHMMSS"')

    if algorithm < 0 or algorithm > 255 or labels < 0 or labels > 255:
        return _('the value of algorithm and labels must be between 0 and 255')

    if ttl < 0 or ttl > 4294967295:
        return _('the value of original_ttl must be between 0 and 4294967295')

    if tag < 0 or tag > 65535:
        return _('the value of tag must be between 0 and 65535')

    return None

def _validate_sshfp(ugettext, sshfp):
    """see RFCs 4255"""
    try:
       algorithm, fp_type, fingerprint = sshfp.split()
    except ValueError:
        return _('format must be specified as "algorithm fp_type fingerprint" '\
                 '(see RFC 4255 for details)')

    try:
        algorithm = int(algorithm)
        fp_type = int(fp_type)
    except ValueError:
        return _('algorithm and fp_type must be integers')

    if algorithm < 0 or algorithm > 255 or fp_type < 0 or fp_type > 255:
        return _('the value of algorithm and fp_type must be between 0 and 255')

    return None

def _validate_unsupported(ugettext, val):
    """
    See https://fedorahosted.org/bind-dyndb-ldap/browser/doc/schema for a
    list of supported records in bind-dyndb-ldap plugin
    """
    return _('This DNS RR type is not supported by bind-dyndb-ldap plugin')


def _normalize_domain_name(domain_name):
    """Make it fully-qualified"""
    if domain_name[-1] != '.':
        return domain_name + '.'
    else:
        return domain_name

# Not validated RR types:
#   - A6: downgraded to experimental state by RFC 3363, AAAA is preferred

_record_validators = {
    u'A': _validate_ipaddr,
    u'AAAA': _validate_ipaddr,
    u'AFSDB': _validate_afsdb,
    u'APL': _validate_unsupported,
    u'CERT': _validate_cert,
    u'CNAME': _validate_cname,
    u'DHCID': _validate_unsupported,
    u'DLV': _validate_unsupported,
    u'DNAME': _validate_dname,
    u'DNSKEY': _validate_unsupported,
    u'DS': _validate_ds,
    u'HIP': _validate_unsupported,
    u'KEY': _validate_key,
    u'IPSECKEY': _validate_unsupported,
    u'KX': _validate_kx,
    u'LOC': _validate_loc,
    u'MX': _validate_mx,
    u'NS': _validate_ns,
    u'NSEC': _validate_nsec,
    u'NSEC3': _validate_unsupported,
    u'NSEC3PARAM': _validate_unsupported,
    u'NAPTR': _validate_naptr,
    u'PTR': _validate_ptr,
    u'RP': _validate_unsupported,
    u'SRV': _validate_srv,
    u'SIG': _validate_sig,
    u'RRSIG': _validate_sig,
    u'SSHFP': _validate_sshfp,
    u'TA': _validate_unsupported,
    u'TKEY': _validate_unsupported,
    u'TSIG': _validate_unsupported,
}

_record_normalizers = {
    u'CNAME': _normalize_domain_name,
    u'DNAME': _normalize_domain_name,
    u'NS': _normalize_domain_name,
    u'PTR': _normalize_domain_name,
}

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


def has_cli_options(entry, no_option_msg, allow_empty_attrs=False):
    entry = dict((t, entry.get(t, [])) for t in _record_attributes)
    if allow_empty_attrs:
        numattr = len(entry)
    else:
        numattr = reduce(lambda x,y: x+y,
                      map(lambda x: len(x), [ v for v in entry.values() if v is not None ]))
    if numattr == 0:
        raise errors.OptionError(no_option_msg)
    return entry

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
        return super(dnszone_find, self).args_options_2_entry(self, *args, **options)

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
    default_attributes = _record_attributes + ['idnsname']

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
                error=unicode(_('Reverse zone %s requires exactly %d IP address components, %d given')
                % (zone_name, zone_len, ip_addr_comp_count)))

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

api.register(dnsrecord)


class dnsrecord_cmd_w_record_options(Command):
    """
    Base class for DNS record commands with record options.
    """
    record_param_doc = 'comma-separated list of %s records'

    def get_record_options(self):
        for t in _record_types:
            t = t.encode('utf-8')
            yield self.get_record_option(t)

    def record_options_2_entry(self, **options):
        entries = dict((t, options.get(t, [])) for t in _record_attributes)
        entries.update(dict((k, []) for (k,v) in entries.iteritems() if v == None ))
        return entries

    def get_record_option(self, rec_type):
        doc = self.record_param_doc % rec_type
        validator = _record_validators.get(rec_type)
        normalizer = _record_normalizers.get(rec_type)
        if validator:
            return Str(
                '%srecord*' % rec_type.lower(), validator, normalizer=normalizer,
                cli_name='%s_rec' % rec_type.lower(), doc=doc,
                label='%s record' % rec_type, csv=True, attribute=True
            )
        else:
            return Str(
                '%srecord*' % rec_type.lower(), cli_name='%s_rec' % rec_type.lower(),
                normalizer=normalizer, doc=doc, label='%s record' % rec_type,
                csv=True, attribute=True
            )

    def prompt_record_options(self, rec_type_list):
        user_options = {}
        # ask for all usual record types
        for rec_type in rec_type_list:
            rec_option = self.get_record_option(rec_type)
            raw = self.Backend.textui.prompt(rec_option.label,optional=True)
            rec_value = rec_option(raw)
            if rec_value is not None:
                 user_options[rec_option.name] = rec_value

        return user_options


class dnsrecord_mod_record(LDAPQuery, dnsrecord_cmd_w_record_options):
    """
    Base class for adding/removing records from DNS resource entries.
    """
    has_output = output.standard_entry

    def get_options(self):
        for option in super(dnsrecord_mod_record, self).get_options():
            yield option
        for option in self.get_record_options():
            yield option

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        entry_attrs = self.record_options_2_entry(**options)

        dn = self.pre_callback(ldap, dn, entry_attrs, *keys, **options)

        try:
            (dn, old_entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        self.update_old_entry_callback(entry_attrs, old_entry_attrs)

        try:
            ldap.update_entry(dn, old_entry_attrs)
        except errors.EmptyModlist:
            pass

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = list(
                set(self.obj.default_attributes + entry_attrs.keys())
            )

        try:
            (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [_dns_zone_record]

        retval = self.post_callback(keys, entry_attrs)
        if retval:
            return retval

        return dict(result=entry_attrs, value=keys[-1])

    def update_old_entry_callback(self, entry_attrs, old_entry_attrs):
        pass

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn

    def post_callback(self, keys, entry_attrs):
        pass


class dnsrecord_add_record(dnsrecord_mod_record):
    """
    Add records to DNS resource.
    """
    NO_CLI = True

    def update_old_entry_callback(self, entry_attrs, old_entry_attrs):
        for (a, v) in entry_attrs.iteritems():
            if not isinstance(v, (list, tuple)):
                v = [v]
            old_entry_attrs.setdefault(a, [])
            old_entry_attrs[a] += v

api.register(dnsrecord_add_record)


class dnsrecord_add(LDAPCreate, dnsrecord_cmd_w_record_options):
    __doc__ = _('Add new DNS resource record.')

    no_option_msg = 'No options to add a specific record provided.\n' \
            "Command help may be consulted for all supported record types."
    takes_options = LDAPCreate.takes_options + (
        Flag('force',
             label=_('Force'),
             flags=['no_option', 'no_output'],
             doc=_('force NS record creation even if its hostname is not in DNS'),
        ),
    )

    def get_options(self):
        for option in super(dnsrecord_add, self).get_options():
            yield option
        for option in self.get_record_options():
            yield option

    def args_options_2_entry(self, *keys, **options):
        has_cli_options(options, self.no_option_msg)
        return super(dnsrecord_add, self).args_options_2_entry(*keys, **options)

    def interactive_prompt_callback(self, kw):
        for param in kw.keys():
            if param in _record_attributes:
                # some record type entered, skip this helper
                return

        # check zone type
        if kw['idnsname'] == _dns_zone_record:
            top_record_types = _zone_top_record_types
        elif zone_is_reverse(kw['dnszoneidnsname']):
            top_record_types = _rev_top_record_types
        else:
            top_record_types = _top_record_types

        # ask for all usual record types
        user_options = self.prompt_record_options(top_record_types)
        kw.update(user_options)

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        for rtype in options:
            rtype_cb = '_%s_pre_callback' % rtype
            if hasattr(self.obj, rtype_cb):
                dn = getattr(self.obj, rtype_cb)(ldap, dn, entry_attrs, *keys, **options)

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.func_name == 'add_entry':
            if isinstance(exc, errors.DuplicateEntry):
                self.obj.methods.add_record(
                    *keys, **self.record_options_2_entry(**options)
                )
                return
        raise exc

api.register(dnsrecord_add)


class dnsrecord_mod(dnsrecord_mod_record):
    __doc__ = _('Modify a DNS resource record.')

    no_option_msg = 'No options to modify a specific record provided.'

    def update_old_entry_callback(self, entry_attrs, old_entry_attrs):
        for (a, v) in entry_attrs.iteritems():
            if not isinstance(v, (list, tuple)):
                v = [v]
            old_entry_attrs.setdefault(a, [])
            if v or v is None:   # overwrite the old entry
                old_entry_attrs[a] = v

    def record_options_2_entry(self, **options):
        entries = dict((t, options.get(t, [])) for t in _record_attributes)
        return has_cli_options(entries, self.no_option_msg, True)

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        for rtype in options:
            rtype_cb = '_%s_pre_callback' % rtype
            if options[rtype] is None and rtype in _record_attributes:
                options[rtype] = []
            if hasattr(self.obj, rtype_cb):
                dn = getattr(self.obj, rtype_cb)(ldap, dn, entry_attrs, *keys, **options)

        return dn

    def post_callback(self, keys, entry_attrs):
        if not self.obj.is_pkey_zone_record(*keys):
            for a in _record_attributes:
                if a in entry_attrs and entry_attrs[a]:
                    return
            return self.obj.methods.delentry(*keys)

api.register(dnsrecord_mod)


class dnsrecord_delentry(LDAPDelete):
    """
    Delete DNS record entry.
    """
    msg_summary = _('Deleted record "%(value)s"')
    NO_CLI = True

api.register(dnsrecord_delentry)


class dnsrecord_del(dnsrecord_mod_record):
    __doc__ = _('Delete DNS resource record.')

    no_option_msg = _('Neither --del-all nor options to delete a specific record provided.\n'\
            "Command help may be consulted for all supported record types.")
    takes_options = (
            Flag('del_all',
                default=False,
                label=_('Delete all associated records'),
            ),
    )

    def execute(self, *keys, **options):
        if options.get('del_all', False):
            return self.obj.methods.delentry(*keys)

        return super(dnsrecord_del, self).execute(*keys, **options)

    def record_options_2_entry(self, **options):
        entry = super(dnsrecord_del, self).record_options_2_entry(**options)
        return has_cli_options(entry, self.no_option_msg)

    def interactive_prompt_callback(self, kw):
        if kw.get('del_all', False):
            return
        for param in kw.keys():
            if param in _record_attributes:
                # we have something to delete, skip this helper
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
        dns_record = api.Command['dnsrecord_show'](kw['dnszoneidnsname'], kw['idnsname'])['result']
        rec_types = [rec_type for rec_type in dns_record if rec_type in _record_attributes]

        self.Backend.textui.print_plain(_(u'Current DNS record contents:\n'))
        present_params = []
        for param in self.params():
            if param.name in _record_attributes and param.name in dns_record:
                present_params.append(param)
                rec_type_content = u', '.join(dns_record[param.name])
                self.Backend.textui.print_plain(u'%s: %s' % (param.label, rec_type_content))
        self.Backend.textui.print_plain(u'')

        # ask what records to remove
        for param in present_params:
            deleted_values = []
            for rec_value in dns_record[param.name]:
                user_del_value = self.Backend.textui.prompt_yesno(
                        _("Delete %s '%s'?") % (param.label, rec_value), default=False)
                if user_del_value is True:
                     deleted_values.append(rec_value)
            if deleted_values:
                deleted_list = u','.join(deleted_values)
                kw[param.name] = param(deleted_list)

    def update_old_entry_callback(self, entry_attrs, old_entry_attrs):
        for (a, v) in entry_attrs.iteritems():
            if not isinstance(v, (list, tuple)):
                v = [v]
            for val in v:
                try:
                    old_entry_attrs[a].remove(val)
                except (KeyError, ValueError):
                    raise errors.NotFound(reason=_('%s record with value %s not found') %
                                          (self.obj.attr_to_cli(a), val))

    def post_callback(self, keys, entry_attrs):
        if not self.obj.is_pkey_zone_record(*keys):
            for a in _record_attributes:
                if a in entry_attrs and entry_attrs[a]:
                    return
            return self.obj.methods.delentry(*keys)

api.register(dnsrecord_del)


class dnsrecord_show(LDAPRetrieve, dnsrecord_cmd_w_record_options):
    __doc__ = _('Display DNS resource.')

    def has_output_params(self):
        for option in self.get_record_options():
            yield option

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [_dns_zone_record]
        return dn

api.register(dnsrecord_show)


class dnsrecord_find(LDAPSearch, dnsrecord_cmd_w_record_options):
    __doc__ = _('Search for DNS resources.')

    def get_options(self):
        for option in super(dnsrecord_find, self).get_options():
            yield option
        for option in self.get_record_options():
            yield option.clone(query=True)

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        record_attrs = self.record_options_2_entry(**options)
        record_filter = ldap.make_filter(record_attrs, rules=ldap.MATCH_ALL)
        filter = ldap.combine_filters(
            (filter, record_filter), rules=ldap.MATCH_ALL
        )
        return (filter, base_dn, ldap.SCOPE_SUBTREE)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if entries:
            zone_obj = self.api.Object[self.obj.parent_object]
            zone_dn = zone_obj.get_dn(args[0])
            if entries[0][0] == zone_dn:
                entries[0][1][zone_obj.primary_key.name] = [_dns_zone_record]

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
