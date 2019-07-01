# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

"""
Various utility functions.
"""

from __future__ import (
    absolute_import,
    print_function,
)

import logging
import os
import socket
import re
import decimal
import dns
import encodings
import sys
import ssl
import termios
import fcntl
import struct
import subprocess

import netaddr
from dns import resolver, rdatatype
from dns.exception import DNSException
from dns.resolver import NXDOMAIN
from netaddr.core import AddrFormatError
import six

try:
    from httplib import HTTPSConnection
except ImportError:
    # Python 3
    from http.client import HTTPSConnection

from ipalib import errors, messages
from ipalib.constants import (
    DOMAIN_LEVEL_0,
    TLS_VERSIONS, TLS_VERSION_MINIMAL, TLS_HIGH_CIPHERS,
    TLS_VERSION_DEFAULT_MIN, TLS_VERSION_DEFAULT_MAX,
)
from ipalib.text import _
from ipaplatform.paths import paths
from ipapython.ssh import SSHPublicKey
from ipapython.dn import DN, RDN
from ipapython.dnsutil import DNSName
from ipapython.dnsutil import resolve_ip_addresses
from ipapython.admintool import ScriptError

if sys.version_info >= (3, 2):
    import reprlib  # pylint: disable=import-error
else:
    reprlib = None

if six.PY3:
    unicode = str

_IPA_CLIENT_SYSRESTORE = "/var/lib/ipa-client/sysrestore"
_IPA_DEFAULT_CONF = "/etc/ipa/default.conf"

logger = logging.getLogger(__name__)


def json_serialize(obj):
    if isinstance(obj, (list, tuple)):
        return [json_serialize(o) for o in obj]
    if isinstance(obj, dict):
        return {k: json_serialize(v) for (k, v) in obj.items()}
    if isinstance(obj, (bool, float, unicode, type(None), six.integer_types)):
        return obj
    if isinstance(obj, str):
        return obj.decode('utf-8')
    if isinstance(obj, (decimal.Decimal, DN)):
        return str(obj)
    if not callable(getattr(obj, '__json__', None)):
        # raise TypeError('%r is not JSON serializable')
        return ''
    return json_serialize(obj.__json__())


def verify_host_resolvable(fqdn):
    try:
        if not resolve_ip_addresses(fqdn):
            raise errors.DNSNotARecordError(hostname=fqdn)
    except dns.exception.DNSException as ex:
        # wrap DNSException in a PublicError
        raise errors.DNSResolverError(exception=ex)


def has_soa_or_ns_record(domain):
    """
    Checks to see if given domain has SOA or NS record.
    Returns True or False.
    """
    try:
        resolver.query(domain, rdatatype.SOA)
        soa_record_found = True
    except DNSException:
        soa_record_found = False

    try:
        resolver.query(domain, rdatatype.NS)
        ns_record_found = True
    except DNSException:
        ns_record_found = False

    return soa_record_found or ns_record_found


def normalize_name(name):
    result = dict()
    components = name.split('@')
    if len(components) == 2:
        result['domain'] = unicode(components[1]).lower()
        result['name'] = unicode(components[0]).lower()
    else:
        components = name.split('\\')
        if len(components) == 2:
            result['flatname'] = unicode(components[0]).lower()
            result['name'] = unicode(components[1]).lower()
        else:
            result['name'] = unicode(name).lower()
    return result

def isvalid_base64(data):
    """
    Validate the incoming data as valid base64 data or not. This is only
    used in the ipalib.Parameters module which expects ``data`` to be unicode.

    The character set must only include of a-z, A-Z, 0-9, + or / and
    be padded with = to be a length divisible by 4 (so only 0-2 =s are
    allowed). Its length must be divisible by 4. White space is
    not significant so it is removed.

    This doesn't guarantee we have a base64-encoded value, just that it
    fits the base64 requirements.
    """

    data = ''.join(data.split())

    if len(data) % 4 > 0 or \
        re.match('^[a-zA-Z0-9\+\/]+\={0,2}$', data) is None:
        return False
    else:
        return True


def strip_csr_header(csr):
    """
    Remove the header and footer (and surrounding material) from a CSR.
    """
    headerlen = 40
    s = csr.find(b"-----BEGIN NEW CERTIFICATE REQUEST-----")
    if s == -1:
        headerlen = 36
        s = csr.find(b"-----BEGIN CERTIFICATE REQUEST-----")
    if s >= 0:
        e = csr.find(b"-----END")
        csr = csr[s + headerlen:e]

    return csr


def validate_ipaddr(ipaddr):
    """
    Check to see if the given IP address is a valid IPv4 or IPv6 address.

    Returns True or False
    """
    try:
        socket.inet_pton(socket.AF_INET, ipaddr)
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ipaddr)
        except socket.error:
            return False
    return True

def check_writable_file(filename):
    """
    Determine if the file is writable. If the file doesn't exist then
    open the file to test writability.
    """
    if filename is None:
        raise errors.FileError(reason=_('Filename is empty'))
    try:
        if os.path.isfile(filename):
            if not os.access(filename, os.W_OK):
                raise errors.FileError(reason=_('Permission denied: %(file)s') % dict(file=filename))
        else:
            fp = open(filename, 'w')
            fp.close()
    except (IOError, OSError) as e:
        raise errors.FileError(reason=str(e))

def normalize_zonemgr(zonemgr):
    if not zonemgr or not isinstance(zonemgr, six.string_types):
        return zonemgr
    if '@' in zonemgr:
        # local-part needs to be normalized
        name, _at, domain = zonemgr.partition('@')
        name = name.replace('.', '\\.')
        zonemgr = u''.join((name, u'.', domain))

    return zonemgr

def normalize_zone(zone):
    if zone[-1] != '.':
        return zone + '.'
    else:
        return zone


def get_proper_tls_version_span(tls_version_min, tls_version_max):
    """
    This function checks whether the given TLS versions are known in
    FreeIPA and that these versions fulfill the requirements for minimal
    TLS version (see
    `ipalib.constants: TLS_VERSIONS, TLS_VERSION_MINIMAL`).

    :param tls_version_min:
        the lower value in the TLS min-max span, raised to the lowest
        allowed value if too low
    :param tls_version_max:
        the higher value in the TLS min-max span, raised to tls_version_min
        if lower than TLS_VERSION_MINIMAL
    :raises: ValueError
    """
    min_allowed_idx = TLS_VERSIONS.index(TLS_VERSION_MINIMAL)

    try:
        min_version_idx = TLS_VERSIONS.index(tls_version_min)
    except ValueError:
        raise ValueError("tls_version_min ('{val}') is not a known "
                         "TLS version.".format(val=tls_version_min))

    try:
        max_version_idx = TLS_VERSIONS.index(tls_version_max)
    except ValueError:
        raise ValueError("tls_version_max ('{val}') is not a known "
                         "TLS version.".format(val=tls_version_max))

    if min_version_idx > max_version_idx:
        raise ValueError("tls_version_min is higher than "
                         "tls_version_max.")

    if min_version_idx < min_allowed_idx:
        min_version_idx = min_allowed_idx
        logger.warning("tls_version_min set too low ('%s'),using '%s' instead",
                       tls_version_min, TLS_VERSIONS[min_version_idx])

    if max_version_idx < min_allowed_idx:
        max_version_idx = min_version_idx
        logger.warning("tls_version_max set too low ('%s'),using '%s' instead",
                       tls_version_max, TLS_VERSIONS[max_version_idx])
    return TLS_VERSIONS[min_version_idx:max_version_idx+1]


def create_https_connection(
    host, port=HTTPSConnection.default_port,
    cafile=None,
    client_certfile=None, client_keyfile=None,
    keyfile_passwd=None,
    tls_version_min=TLS_VERSION_DEFAULT_MIN,
    tls_version_max=TLS_VERSION_DEFAULT_MAX,
    **kwargs
):
    """
    Create a customized HTTPSConnection object.

    :param host:  The host to connect to
    :param port:  The port to connect to, defaults to
               HTTPSConnection.default_port
    :param cafile:  A PEM-format file containning the trusted
                    CA certificates
    :param client_certfile:
            A PEM-format client certificate file that will be used to
            identificate the user to the server.
    :param client_keyfile:
            A file with the client private key. If this argument is not
            supplied, the key will be sought in client_certfile.
    :param keyfile_passwd:
            A path to the file which stores the password that is used to
            encrypt client_keyfile. Leave default value if the keyfile
            is not encrypted.
    :returns An established HTTPS connection to host:port
    """
    # pylint: disable=no-member
    tls_cutoff_map = {
        "ssl2": ssl.OP_NO_SSLv2,
        "ssl3": ssl.OP_NO_SSLv3,
        "tls1.0": ssl.OP_NO_TLSv1,
        "tls1.1": ssl.OP_NO_TLSv1_1,
        "tls1.2": ssl.OP_NO_TLSv1_2,
        "tls1.3": getattr(ssl, "OP_NO_TLSv1_3", 0),
    }
    # pylint: enable=no-member

    if cafile is None:
        raise RuntimeError("cafile argument is required to perform server "
                           "certificate verification")

    if not os.path.isfile(cafile) or not os.access(cafile, os.R_OK):
        raise RuntimeError("cafile \'{file}\' doesn't exist or is unreadable".
                           format(file=cafile))

    # remove the slice of negating protocol options according to options
    tls_span = get_proper_tls_version_span(tls_version_min, tls_version_max)

    # official Python documentation states that the best option to get
    # TLSv1 and later is to setup SSLContext with PROTOCOL_SSLv23
    # and then negate the insecure SSLv2 and SSLv3
    # pylint: disable=no-member
    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.options |= (
        ssl.OP_ALL | ssl.OP_NO_COMPRESSION | ssl.OP_SINGLE_DH_USE |
        ssl.OP_SINGLE_ECDH_USE
    )

    # high ciphers without RC4, MD5, TripleDES, pre-shared key
    # and secure remote password
    ctx.set_ciphers(TLS_HIGH_CIPHERS)

    # pylint: enable=no-member
    # set up the correct TLS version flags for the SSL context
    for version in TLS_VERSIONS:
        if version in tls_span:
            # make sure the required TLS versions are available if Python
            # decides to modify the default TLS flags
            ctx.options &= ~tls_cutoff_map[version]
        else:
            # disable all TLS versions not in tls_span
            ctx.options |= tls_cutoff_map[version]

    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile)

    if client_certfile is not None:
        if keyfile_passwd is not None:
            with open(keyfile_passwd) as pwd_f:
                passwd = pwd_f.read()
        else:
            passwd = None
        ctx.load_cert_chain(client_certfile, client_keyfile, passwd)

    return HTTPSConnection(host, port, context=ctx, **kwargs)


def validate_dns_label(dns_label, allow_underscore=False, allow_slash=False):
    base_chars = 'a-z0-9'
    extra_chars = ''
    middle_chars = ''

    if allow_underscore:
        extra_chars += '_'
    if allow_slash:
        middle_chars += '/'

    middle_chars = middle_chars + '-' #has to be always the last in the regex [....-]

    label_regex = r'''^[%(base)s%(extra)s] # must begin with an alphanumeric
                                           # character, or underscore if
                                           # allow_underscore is True
        ([%(base)s%(extra)s%(middle)s]*    # can contain all allowed character
                                           # classes in the middle
        [%(base)s%(extra)s])*$             # must end with alphanumeric
                                           # character or underscore if
                                           # allow_underscore is True
        ''' % dict(base=base_chars, extra=extra_chars, middle=middle_chars)
    regex = re.compile(label_regex, re.IGNORECASE | re.VERBOSE)

    if not dns_label:
        raise ValueError(_('empty DNS label'))

    if len(dns_label) > 63:
        raise ValueError(_('DNS label cannot be longer that 63 characters'))

    if not regex.match(dns_label):
        chars = ', '.join("'%s'" % c for c in extra_chars + middle_chars)
        chars2 = ', '.join("'%s'" % c for c in middle_chars)
        raise ValueError(_("only letters, numbers, %(chars)s are allowed. " \
                           "DNS label may not start or end with %(chars2)s") \
                           % dict(chars=chars, chars2=chars2))


def validate_domain_name(
    domain_name, allow_underscore=False,
    allow_slash=False, entity='domain'
):
    if domain_name.endswith('.'):
        domain_name = domain_name[:-1]

    domain_name = domain_name.split(".")

    if len(domain_name) < 2:
        raise ValueError(_(
            'single label {}s are not supported'.format(entity)))

    # apply DNS name validator to every name part
    for label in domain_name:
        validate_dns_label(label, allow_underscore, allow_slash)


def validate_zonemgr(zonemgr):
    assert isinstance(zonemgr, DNSName)
    if any(b'@' in label for label in zonemgr.labels):
        raise ValueError(_('too many \'@\' characters'))


def validate_zonemgr_str(zonemgr):
    zonemgr = normalize_zonemgr(zonemgr)
    validate_idna_domain(zonemgr)
    zonemgr = DNSName(zonemgr)
    return validate_zonemgr(zonemgr)

def validate_hostname(hostname, check_fqdn=True, allow_underscore=False, allow_slash=False):
    """ See RFC 952, 1123

    :param hostname Checked value
    :param check_fqdn Check if hostname is fully qualified
    """
    if len(hostname) > 255:
        raise ValueError(_('cannot be longer that 255 characters'))

    if hostname.endswith('.'):
        hostname = hostname[:-1]

    if '..' in hostname:
        raise ValueError(_('hostname contains empty label (consecutive dots)'))

    if '.' not in hostname:
        if check_fqdn:
            raise ValueError(_('not fully qualified'))
        validate_dns_label(hostname, allow_underscore, allow_slash)
    else:
        validate_domain_name(hostname, allow_underscore, allow_slash)

def normalize_sshpubkey(value):
    return SSHPublicKey(value).openssh()


def validate_sshpubkey(ugettext, value):
    try:
        SSHPublicKey(value)
    except (ValueError, UnicodeDecodeError):
        return _('invalid SSH public key')
    else:
        return None


def validate_sshpubkey_no_options(ugettext, value):
    try:
        pubkey = SSHPublicKey(value)
    except (ValueError, UnicodeDecodeError):
        return _('invalid SSH public key')

    if pubkey.has_options():
        return _('options are not allowed')
    else:
        return None


def convert_sshpubkey_post(entry_attrs):
    pubkeys = entry_attrs.get('ipasshpubkey')
    if not pubkeys:
        return

    newpubkeys = []
    fingerprints = []
    for pubkey in pubkeys:
        try:
            pubkey = SSHPublicKey(pubkey)
        except (ValueError, UnicodeDecodeError):
            continue

        fp = pubkey.fingerprint_hex_sha256()
        comment = pubkey.comment()
        if comment:
            fp = u'%s %s' % (fp, comment)
        fp = u'%s (%s)' % (fp, pubkey.keytype())

        newpubkeys.append(pubkey.openssh())
        fingerprints.append(fp)

    if 'ipasshpubkey' in entry_attrs:
        entry_attrs['ipasshpubkey'] = newpubkeys or None
    if fingerprints:
        entry_attrs['sshpubkeyfp'] = fingerprints


def add_sshpubkey_to_attrs_pre(context, attrs_list):
    """
    Attribute ipasshpubkey should be added to attrs_list to be able compute
    ssh fingerprint. This attribute must be removed later if was added here
    (see remove_sshpubkey_from_output_post).
    """
    if not ('ipasshpubkey' in attrs_list or '*' in attrs_list):
        setattr(context, 'ipasshpubkey_added', True)
        attrs_list.append('ipasshpubkey')


def remove_sshpubkey_from_output_post(context, entry_attrs):
    """
    Remove ipasshpubkey from output if it was added in pre_callbacks
    """
    if getattr(context, 'ipasshpubkey_added', False):
        entry_attrs.pop('ipasshpubkey', None)
        delattr(context, 'ipasshpubkey_added')


def remove_sshpubkey_from_output_list_post(context, entries):
    """
    Remove ipasshpubkey from output if it was added in pre_callbacks
    """
    if getattr(context, 'ipasshpubkey_added', False):
        for entry_attrs in entries:
            entry_attrs.pop('ipasshpubkey', None)
        delattr(context, 'ipasshpubkey_added')


# regexp matching signed floating point number (group 1) followed by
# optional whitespace followed by time unit, e.g. day, hour (group 7)
time_duration_re = re.compile(r'([-+]?((\d+)|(\d+\.\d+)|(\.\d+)|(\d+\.)))\s*([a-z]+)', re.IGNORECASE)

# number of seconds in a time unit
time_duration_units = {
    'year'    : 365*24*60*60,
    'years'   : 365*24*60*60,
    'y'       : 365*24*60*60,
    'month'   : 30*24*60*60,
    'months'  : 30*24*60*60,
    'week'    : 7*24*60*60,
    'weeks'   : 7*24*60*60,
    'w'       : 7*24*60*60,
    'day'     : 24*60*60,
    'days'    : 24*60*60,
    'd'       : 24*60*60,
    'hour'    : 60*60,
    'hours'   : 60*60,
    'h'       : 60*60,
    'minute'  : 60,
    'minutes' : 60,
    'min'     : 60,
    'second'  : 1,
    'seconds' : 1,
    'sec'     : 1,
    's'       : 1,
}

def parse_time_duration(value):
    '''

    Given a time duration string, parse it and return the total number
    of seconds represented as a floating point value. Negative values
    are permitted.

    The string should be composed of one or more numbers followed by a
    time unit. Whitespace and punctuation is optional. The numbers may
    be optionally signed.  The time units are case insenstive except
    for the single character 'M' or 'm' which means month and minute
    respectively.

    Recognized time units are:

        * year, years, y
        * month, months, M
        * week, weeks, w
        * day, days, d
        * hour, hours, h
        * minute, minutes, min, m
        * second, seconds, sec, s

    Examples:
        "1h"                    # 1 hour
        "2 HOURS, 30 Minutes"   # 2.5 hours
        "1week -1 day"          # 6 days
        ".5day"                 # 12 hours
        "2M"                    # 2 months
        "1h:15m"                # 1.25 hours
        "1h, -15min"            # 45 minutes
        "30 seconds"            # .5 minute

    Note: Despite the appearance you can perform arithmetic the
    parsing is much simpler, the parser searches for signed values and
    adds the signed value to a running total. Only + and - are permitted
    and must appear prior to a digit.

    :parameters:
        value : string
            A time duration string in the specified format
    :returns:
        total number of seconds as float (may be negative)
    '''

    matches = 0
    duration = 0.0
    for match in time_duration_re.finditer(value):
        matches += 1
        magnitude = match.group(1)
        unit = match.group(7)

        # Get the unit, only M and m are case sensitive
        if unit == 'M':         # month
            seconds_per_unit = 30*24*60*60
        elif unit == 'm':       # minute
            seconds_per_unit = 60
        else:
            unit = unit.lower()
            seconds_per_unit = time_duration_units.get(unit)
            if seconds_per_unit is None:
                raise ValueError('unknown time duration unit "%s"' % unit)
        magnitude = float(magnitude)
        seconds = magnitude * seconds_per_unit
        duration += seconds

    if matches == 0:
        raise ValueError('no time duration found in "%s"' % value)

    return duration

def get_dns_forward_zone_update_policy(realm, rrtypes=('A', 'AAAA', 'SSHFP')):
    """
    Generate update policy for a forward DNS zone (idnsUpdatePolicy
    attribute). Bind uses this policy to grant/reject access for client
    machines trying to dynamically update their records.

    :param realm: A realm of the of the client
    :param rrtypes: A list of resource records types that client shall be
                    allowed to update
    """
    policy_element = "grant %(realm)s krb5-self * %(rrtype)s"
    policies = [ policy_element % dict(realm=realm, rrtype=rrtype) \
               for rrtype in rrtypes ]
    policy = "; ".join(policies)
    policy += ";"

    return policy

def get_dns_reverse_zone_update_policy(realm, reverse_zone, rrtypes=('PTR',)):
    """
    Generate update policy for a reverse DNS zone (idnsUpdatePolicy
    attribute). Bind uses this policy to grant/reject access for client
    machines trying to dynamically update their records.

    :param realm: A realm of the of the client
    :param reverse_zone: Name of the actual zone. All clients with IPs in this
                         sub-domain will be allowed to perform changes
    :param rrtypes: A list of resource records types that client shall be
                    allowed to update
    """
    policy_element = "grant %(realm)s krb5-subdomain %(zone)s %(rrtype)s"
    policies = [ policy_element \
                    % dict(realm=realm, zone=reverse_zone, rrtype=rrtype) \
                 for rrtype in rrtypes ]
    policy = "; ".join(policies)
    policy += ";"

    return policy

# dictionary of valid reverse zone -> number of address components
REVERSE_DNS_ZONES = {
    DNSName.ip4_rev_zone : 4,
    DNSName.ip6_rev_zone : 32,
}

def zone_is_reverse(zone_name):
    return DNSName(zone_name).is_reverse()

def get_reverse_zone_default(ip_address):
    ip = netaddr.IPAddress(str(ip_address))
    items = ip.reverse_dns.split('.')

    if ip.version == 4:
        items = items[1:]   # /24 for IPv4
    elif ip.version == 6:
        items = items[16:]  # /64 for IPv6

    return normalize_zone('.'.join(items))


def validate_rdn_param(ugettext, value):
    try:
        RDN(value)
    except Exception as e:
        return str(e)
    else:
        return None


def validate_hostmask(ugettext, hostmask):
    try:
        netaddr.IPNetwork(hostmask)
    except (ValueError, AddrFormatError):
        return _('invalid hostmask')
    else:
        return None


class ForwarderValidationError(Exception):
    format = None

    def __init__(self, format=None, message=None, **kw):
        messages.process_message_arguments(self, format, message, **kw)
        super(ForwarderValidationError, self).__init__(self.msg)


class UnresolvableRecordError(ForwarderValidationError):
    format = _("query '%(owner)s %(rtype)s': %(error)s")


class EDNS0UnsupportedError(ForwarderValidationError):
    format = _("query '%(owner)s %(rtype)s' with EDNS0: %(error)s")


class DNSSECSignatureMissingError(ForwarderValidationError):
    format = _("answer to query '%(owner)s %(rtype)s' is missing DNSSEC "
               "signatures (no RRSIG data)")


class DNSSECValidationError(ForwarderValidationError):
    format = _("record '%(owner)s %(rtype)s' "
               "failed DNSSEC validation on server %(ip)s")


def _log_response(e):
    """
    If exception contains response from server, log this response to debug log
    :param log: if log is None, do not log
    :param e: DNSException
    """
    assert isinstance(e, DNSException)
    response = getattr(e, 'kwargs', {}).get('response')
    if response:
        logger.debug("DNSException: %s; server response: %s", e, response)


def _resolve_record(owner, rtype, nameserver_ip=None, edns0=False,
                    dnssec=False, flag_cd=False, timeout=10):
    """
    :param nameserver_ip: if None, default resolvers will be used
    :param edns0: enables EDNS0
    :param dnssec: enabled EDNS0, flags: DO
    :param flag_cd: requires dnssec=True, adds flag CD
    :raise DNSException: if error occurs
    """
    assert isinstance(nameserver_ip, six.string_types) or nameserver_ip is None
    assert isinstance(rtype, six.string_types)

    res = dns.resolver.Resolver()
    if nameserver_ip:
        res.nameservers = [nameserver_ip]
    res.lifetime = timeout

    # Recursion Desired,
    # this option prevents to get answers in authority section instead of answer
    res.set_flags(dns.flags.RD)

    if dnssec:
        res.use_edns(0, dns.flags.DO, 4096)
        flags = dns.flags.RD
        if flag_cd:
            flags = flags | dns.flags.CD
        res.set_flags(flags)
    elif edns0:
        res.use_edns(0, 0, 4096)

    return res.query(owner, rtype)


def _validate_edns0_forwarder(owner, rtype, ip_addr, timeout=10):
    """
    Validate if forwarder supports EDNS0

    :raise UnresolvableRecordError: record cannot be resolved
    :raise EDNS0UnsupportedError: EDNS0 is not supported by forwarder
    """

    try:
        _resolve_record(owner, rtype, nameserver_ip=ip_addr, timeout=timeout)
    except DNSException as e:
        _log_response(e)
        raise UnresolvableRecordError(owner=owner, rtype=rtype, ip=ip_addr,
                                      error=e)

    try:
        _resolve_record(owner, rtype, nameserver_ip=ip_addr, edns0=True,
                        timeout=timeout)
    except DNSException as e:
        _log_response(e)
        raise EDNS0UnsupportedError(owner=owner, rtype=rtype, ip=ip_addr,
                                    error=e)


def validate_dnssec_global_forwarder(ip_addr, timeout=10):
    """Test DNS forwarder properties. against root zone.

    Global forwarders should be able return signed root zone

    :raise UnresolvableRecordError: record cannot be resolved
    :raise EDNS0UnsupportedError: EDNS0 is not supported by forwarder
    :raise DNSSECSignatureMissingError: did not receive RRSIG for root zone
    """

    ip_addr = str(ip_addr)
    owner = "."
    rtype = "SOA"

    _validate_edns0_forwarder(owner, rtype, ip_addr, timeout=timeout)

    # DNS root has to be signed
    try:
        ans = _resolve_record(owner, rtype, nameserver_ip=ip_addr, dnssec=True,
                              timeout=timeout)
    except DNSException as e:
        _log_response(e)
        raise DNSSECSignatureMissingError(owner=owner, rtype=rtype, ip=ip_addr)

    try:
        ans.response.find_rrset(
            ans.response.answer, dns.name.root, dns.rdataclass.IN,
            dns.rdatatype.RRSIG, dns.rdatatype.SOA
        )
    except KeyError:
        raise DNSSECSignatureMissingError(owner=owner, rtype=rtype, ip=ip_addr)


def validate_dnssec_zone_forwarder_step1(ip_addr, fwzone, timeout=10):
    """
    Only forwarders in forward zones can be validated in this way
    :raise UnresolvableRecordError: record cannot be resolved
    :raise EDNS0UnsupportedError: ENDS0 is not supported by forwarder
    """
    _validate_edns0_forwarder(fwzone, "SOA", ip_addr, timeout=timeout)


def validate_dnssec_zone_forwarder_step2(ipa_ip_addr, fwzone, timeout=10):
    """
    This step must be executed after forwarders are added into LDAP, and only
    when we are sure the forwarders work.
    Query will be send to IPA DNS server, to verify if reply passed,
    or DNSSEC validation failed.
    Only forwarders in forward zones can be validated in this way
    :raise UnresolvableRecordError: record cannot be resolved
    :raise DNSSECValidationError: response from forwarder is not DNSSEC valid
    """
    rtype = "SOA"
    try:
        ans_cd = _resolve_record(fwzone, rtype, nameserver_ip=ipa_ip_addr,
                                 edns0=True, dnssec=True, flag_cd=True,
                                 timeout=timeout)
    except NXDOMAIN as e:
        # sometimes CD flag is ignored and NXDomain is returned
        _log_response(e)
        raise DNSSECValidationError(owner=fwzone, rtype=rtype, ip=ipa_ip_addr)
    except DNSException as e:
        _log_response(e)
        raise UnresolvableRecordError(owner=fwzone, rtype=rtype,
                                      ip=ipa_ip_addr, error=e)

    try:
        ans_do = _resolve_record(fwzone, rtype, nameserver_ip=ipa_ip_addr,
                                 edns0=True, dnssec=True, timeout=timeout)
    except DNSException as e:
        _log_response(e)
        raise DNSSECValidationError(owner=fwzone, rtype=rtype, ip=ipa_ip_addr)
    else:
        if (ans_do.canonical_name == ans_cd.canonical_name
            and ans_do.rrset == ans_cd.rrset):
            return
        # records received with and without CD flag are not equivalent:
        # this might be caused by an DNSSEC validation failure in cases where
        # existing zone id being 'shadowed' by another zone on forwarder
        raise DNSSECValidationError(owner=fwzone, rtype=rtype, ip=ipa_ip_addr)


def validate_idna_domain(value):
    """
    Validate if value is valid IDNA domain.

    If domain is not valid, raises ValueError
    :param value:
    :return:
    """
    error = None

    try:
        DNSName(value)
    except dns.name.BadEscape:
        error = _('invalid escape code in domain name')
    except dns.name.EmptyLabel:
        error = _('empty DNS label')
    except dns.name.NameTooLong:
        error = _('domain name cannot be longer than 255 characters')
    except dns.name.LabelTooLong:
        error = _('DNS label cannot be longer than 63 characters')
    except dns.exception.SyntaxError:
        error = _('invalid domain name')
    else:
        #compare if IDN normalized and original domain match
        #there is N:1 mapping between unicode and IDNA names
        #user should use normalized names to avoid mistakes
        labels = re.split(u'[.\uff0e\u3002\uff61]', value, flags=re.UNICODE)
        try:
            for label in labels:
                label.encode("ascii")
        except UnicodeError:
            # IDNA
            is_nonnorm = any(encodings.idna.nameprep(x) != x for x in labels)
            if is_nonnorm:
                error = _("domain name '%(domain)s' should be normalized to"
                          ": %(normalized)s") % {
                          'domain': value,
                          'normalized': '.'.join([encodings.idna.nameprep(x)
                                                  for x in labels])}

    if error:
        raise ValueError(error)


def detect_dns_zone_realm_type(api, domain):
    """
    Detects the type of the realm that the given DNS zone belongs to.
    Note: This method is heuristic. Possible values:
      - 'current': For IPA domains belonging in the current realm.
      - 'foreign': For domains belonging in a foreing kerberos realm.
      - 'unknown': For domains whose allegiance could not be detected.
    """

    # First, try to detect _kerberos TXT record in the domain
    # This would indicate that the domain belongs to IPA realm

    kerberos_prefix = DNSName('_kerberos')
    domain_suffix = DNSName(domain)
    kerberos_record_name = kerberos_prefix + domain_suffix

    try:
        result = resolver.query(kerberos_record_name, rdatatype.TXT)
        answer = result.response.answer

        # IPA domain will have only one _kerberos TXT record
        if (len(answer) == 1 and
            len(answer[0]) == 1 and
            answer[0].rdtype == rdatatype.TXT):

            record = answer[0][0]

            # If the record contains our current realm, it is 'ipa-current'
            if record.to_text() == '"{0}"'.format(api.env.realm):
                return 'current'
            else:
                return 'foreign'

    except DNSException:
        pass

    # Try to detect AD specific record in the zone.
    # This would indicate that the domain belongs to foreign (AD) realm

    gc_prefix = DNSName('_ldap._tcp.gc._msdcs')
    ad_specific_record_name = gc_prefix + domain_suffix

    try:
        # The presence of this record is enough, return foreign in such case
        resolver.query(ad_specific_record_name, rdatatype.SRV)
    except DNSException:
        # If we could not detect type with certainty, return unknown
        return 'unknown'
    else:
        return 'foreign'


def has_managed_topology(api):
    domainlevel = api.Command['domainlevel_get']().get('result', DOMAIN_LEVEL_0)
    return domainlevel > DOMAIN_LEVEL_0


class classproperty(object):
    __slots__ = ('__doc__', 'fget')

    def __init__(self, fget=None, doc=None):
        if doc is None and fget is not None:
            doc = fget.__doc__

        self.fget = fget
        self.__doc__ = doc

    def __get__(self, obj, obj_type):
        if self.fget is not None:
            return self.fget.__get__(obj, obj_type)()
        raise AttributeError("unreadable attribute")

    def __set__(self, obj, value):
        raise AttributeError("can't set attribute")

    def __delete__(self, obj):
        raise AttributeError("can't delete attribute")

    def getter(self, fget):
        self.fget = fget
        return self


def normalize_hostname(hostname):
    """Use common fqdn form without the trailing dot"""
    if hostname.endswith(u'.'):
        hostname = hostname[:-1]
    hostname = hostname.lower()
    return hostname


def hostname_validator(ugettext, value):
    try:
        validate_hostname(value)
    except ValueError as e:
        return _('invalid domain-name: %s') % unicode(e)

    return None


def ipaddr_validator(ugettext, ipaddr, ip_version=None):
    try:
        ip = netaddr.IPAddress(str(ipaddr), flags=netaddr.INET_PTON)

        if ip_version is not None:
            if ip.version != ip_version:
                return _(
                    'invalid IP address version (is %(value)d, must be '
                    '%(required_value)d)!') % dict(
                    value=ip.version,
                    required_value=ip_version
                )
    except (netaddr.AddrFormatError, ValueError):
        return _('invalid IP address format')
    return None


def validate_bind_forwarder(ugettext, forwarder):
    ip_address, sep, port = forwarder.partition(u' port ')

    ip_address_validation = ipaddr_validator(ugettext, ip_address)

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


def set_krbcanonicalname(entry_attrs):
    objectclasses = set(i.lower() for i in entry_attrs['objectclass'])

    if 'krbprincipalaux' not in objectclasses:
        return

    if ('krbprincipalname' in entry_attrs
            and 'krbcanonicalname' not in entry_attrs):
        entry_attrs['krbcanonicalname'] = entry_attrs['krbprincipalname']


def ensure_last_krbprincipalname(ldap, entry_attrs, *keys):
    """
    ensure that the LDAP entry has at least one value of krbprincipalname
    and that this value is equal to krbcanonicalname

    :param ldap: LDAP connection object
    :param entry_attrs: LDAP entry made prior to update
    :param options: command options
    """
    entry = ldap.get_entry(
        entry_attrs.dn, ['krbcanonicalname', 'krbprincipalname'])

    krbcanonicalname = entry.single_value.get('krbcanonicalname', None)

    if krbcanonicalname in keys[-1]:
        raise errors.ValidationError(
            name='krbprincipalname',
            error=_('at least one value equal to the canonical '
                    'principal name must be present')
        )


def ensure_krbcanonicalname_set(ldap, entry_attrs):
    old_entry = ldap.get_entry(
        entry_attrs.dn,
        ['krbcanonicalname', 'krbprincipalname', 'objectclass'])

    if old_entry.single_value.get('krbcanonicalname', None) is not None:
        return

    set_krbcanonicalname(old_entry)

    old_entry.pop('krbprincipalname', None)
    old_entry.pop('objectclass', None)

    entry_attrs.update(old_entry)


def check_client_configuration(env=None):
    """
    Check if IPA client is configured on the system.

    Hardcode return code to avoid recursive imports
    """
    if ((env is not None and not os.path.isfile(env.conf_default)) or
       (not os.path.isfile(paths.IPA_DEFAULT_CONF) or
            not os.path.isdir(paths.IPA_CLIENT_SYSRESTORE) or
            not os.listdir(paths.IPA_CLIENT_SYSRESTORE))):
        raise ScriptError('IPA client is not configured on this system',
                          2)  # CLIENT_NOT_CONFIGURED


def check_principal_realm_in_trust_namespace(api_instance, *keys):
    """
    Check that principal name's suffix does not overlap with UPNs and realm
    names of trusted forests.

    :param api_instance: API instance
    :param suffixes: principal suffixes

    :raises: ValidationError if the suffix coincides with realm name, UPN
    suffix or netbios name of trusted domains
    """
    trust_objects = api_instance.Command.trust_find(u'', sizelimit=0)['result']

    trust_suffix_namespace = set()

    for obj in trust_objects:
        nt_suffixes = obj.get('ipantadditionalsuffixes', [])

        trust_suffix_namespace.update(
            set(upn.lower() for upn in nt_suffixes))

        if 'ipantflatname' in obj:
            trust_suffix_namespace.add(obj['ipantflatname'][0].lower())

        trust_suffix_namespace.add(obj['cn'][0].lower())

    for principal in keys[-1]:
        realm = principal.realm
        upn = principal.upn_suffix if principal.is_enterprise else None

        if realm in trust_suffix_namespace or upn in trust_suffix_namespace:
            raise errors.ValidationError(
                name='krbprincipalname',
                error=_('realm or UPN suffix overlaps with trusted domain '
                        'namespace'))


def no_matching_interface_for_ip_address_warning(addr_list):
    for ip in addr_list:
        if not ip.get_matching_interface():
            logger.warning(
                "No network interface matches the IP address %s", ip)
            # fixme: once when loggers will be fixed, we can remove this
            # print
            print(
                "WARNING: No network interface matches the IP address "
                "{}".format(ip),
                file=sys.stderr
            )


def get_terminal_height(fd=1):
    """
    Get current terminal height

    Args:
        fd (int): file descriptor. Default: 1 (stdout)

    Returns:
        int: Terminal height
    """
    try:
        return struct.unpack(
            'hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, b'1234'))[0]
    except (IOError, OSError, struct.error):
        return os.environ.get("LINES", 25)


def open_in_pager(data):
    """
    Open text data in pager

    Args:
        data (bytes): data to view in pager

    Returns:
        None
    """
    pager = os.environ.get("PAGER", "less")
    pager_process = subprocess.Popen([pager], stdin=subprocess.PIPE)

    try:
        pager_process.stdin.write(data)
        pager_process.communicate()
    except IOError:
        pass


if reprlib is not None:
    class APIRepr(reprlib.Repr):
        builtin_types = {
            bool, int, float,
            str, bytes,
            dict, tuple, list, set, frozenset,
            type(None),
        }

        def __init__(self):
            super(APIRepr, self).__init__()
            # no limitation
            for k, v in self.__dict__.items():
                if isinstance(v, int):
                    setattr(self, k, sys.maxsize)

        def repr_str(self, x, level):
            """Output with u'' prefix"""
            return 'u' + repr(x)

        def repr_type(self, x, level):
            if x is str:
                return "<type 'unicode'>"
            if x in self.builtin_types:
                return "<type '{}'>".format(x.__name__)
            else:
                return repr(x)

    apirepr = APIRepr().repr
else:
    apirepr = repr
