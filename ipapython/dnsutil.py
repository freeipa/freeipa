# Authors: Martin Basti <mbasti@redhat.com>
#
# Copyright (C) 2007-2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import dns.name
import dns.exception
import copy

import six

if six.PY3:
    unicode = str


@six.python_2_unicode_compatible
class DNSName(dns.name.Name):
    labels = None  # make pylint happy

    @classmethod
    def from_text(cls, labels, origin=None):
        return cls(dns.name.from_text(labels, origin))

    def __init__(self, labels, origin=None):
        try:
            if isinstance(labels, six.string_types):
                #pylint: disable=E1101
                labels = dns.name.from_text(unicode(labels), origin).labels
            elif isinstance(labels, dns.name.Name):
                labels = labels.labels

            super(DNSName, self).__init__(labels)
        except UnicodeError as e:
            # dnspython bug, an invalid domain name returns the UnicodeError
            # instead of a dns.exception
            raise dns.exception.SyntaxError(e)

    def __bool__(self):
        #dns.name.from_text('@') is represented like empty tuple
        #we need to acting '@' as nonzero value
        return True

    __nonzero__ = __bool__  # for Python 2

    def __copy__(self):
        return DNSName(self.labels)

    def __deepcopy__(self, memo):
        return DNSName(copy.deepcopy(self.labels, memo))

    def __str__(self):
        return self.to_unicode()

    def ToASCII(self):
        #method named by RFC 3490 and python standard library
        return self.to_text().decode('ascii')  # must be unicode string

    def canonicalize(self):
        return DNSName(super(DNSName, self).canonicalize())

    def concatenate(self, other):
        return DNSName(super(DNSName, self).concatenate(other))

    def relativize(self, origin):
        return DNSName(super(DNSName, self).relativize(origin))

    def derelativize(self, origin):
        return DNSName(super(DNSName, self).derelativize(origin))

    def choose_relativity(self, origin=None, relativize=True):
        return DNSName(super(DNSName, self).choose_relativity(origin=origin,
                       relativize=relativize))

    def make_absolute(self):
        return self.derelativize(self.root)

    def is_idn(self):
        return any(label.startswith('xn--') for label in self.labels)

    def is_ip4_reverse(self):
        return self.is_subdomain(self.ip4_rev_zone)

    def is_ip6_reverse(self):
        return self.is_subdomain(self.ip6_rev_zone)

    def is_reverse(self):
        return self.is_ip4_reverse() or self.is_ip6_reverse()

    def is_empty(self):
        return len(self.labels) == 0


#DNS public constants
DNSName.root = DNSName(dns.name.root)  # '.'
DNSName.empty = DNSName(dns.name.empty)  # '@'
DNSName.ip4_rev_zone = DNSName(('in-addr', 'arpa', ''))
DNSName.ip6_rev_zone = DNSName(('ip6', 'arpa', ''))

# Empty zones are defined in various RFCs. BIND is by default serving them.
# This constat should contain everything listed in
# IANA registry "Locally-Served DNS Zones"
# URL: http://www.iana.org/assignments/locally-served-dns-zones
# + AS112 zone defined in RFC 7534. It is not in the registry for some
# reason but BIND 9.10 is serving it as automatic empty zones.
EMPTY_ZONES = [DNSName(aez).make_absolute() for aez in [
        # RFC 1918
        "10.IN-ADDR.ARPA", "16.172.IN-ADDR.ARPA", "17.172.IN-ADDR.ARPA",
        "18.172.IN-ADDR.ARPA", "19.172.IN-ADDR.ARPA", "20.172.IN-ADDR.ARPA",
        "21.172.IN-ADDR.ARPA", "22.172.IN-ADDR.ARPA", "23.172.IN-ADDR.ARPA",
        "24.172.IN-ADDR.ARPA", "25.172.IN-ADDR.ARPA", "26.172.IN-ADDR.ARPA",
        "27.172.IN-ADDR.ARPA", "28.172.IN-ADDR.ARPA", "29.172.IN-ADDR.ARPA",
        "30.172.IN-ADDR.ARPA", "31.172.IN-ADDR.ARPA", "168.192.IN-ADDR.ARPA",
        # RFC 6598
        "64.100.IN-ADDR.ARPA", "65.100.IN-ADDR.ARPA", "66.100.IN-ADDR.ARPA",
        "67.100.IN-ADDR.ARPA", "68.100.IN-ADDR.ARPA", "69.100.IN-ADDR.ARPA",
        "70.100.IN-ADDR.ARPA", "71.100.IN-ADDR.ARPA", "72.100.IN-ADDR.ARPA",
        "73.100.IN-ADDR.ARPA", "74.100.IN-ADDR.ARPA", "75.100.IN-ADDR.ARPA",
        "76.100.IN-ADDR.ARPA", "77.100.IN-ADDR.ARPA", "78.100.IN-ADDR.ARPA",
        "79.100.IN-ADDR.ARPA", "80.100.IN-ADDR.ARPA", "81.100.IN-ADDR.ARPA",
        "82.100.IN-ADDR.ARPA", "83.100.IN-ADDR.ARPA", "84.100.IN-ADDR.ARPA",
        "85.100.IN-ADDR.ARPA", "86.100.IN-ADDR.ARPA", "87.100.IN-ADDR.ARPA",
        "88.100.IN-ADDR.ARPA", "89.100.IN-ADDR.ARPA", "90.100.IN-ADDR.ARPA",
        "91.100.IN-ADDR.ARPA", "92.100.IN-ADDR.ARPA", "93.100.IN-ADDR.ARPA",
        "94.100.IN-ADDR.ARPA", "95.100.IN-ADDR.ARPA", "96.100.IN-ADDR.ARPA",
        "97.100.IN-ADDR.ARPA", "98.100.IN-ADDR.ARPA", "99.100.IN-ADDR.ARPA",
        "100.100.IN-ADDR.ARPA", "101.100.IN-ADDR.ARPA",
        "102.100.IN-ADDR.ARPA", "103.100.IN-ADDR.ARPA",
        "104.100.IN-ADDR.ARPA", "105.100.IN-ADDR.ARPA",
        "106.100.IN-ADDR.ARPA", "107.100.IN-ADDR.ARPA",
        "108.100.IN-ADDR.ARPA", "109.100.IN-ADDR.ARPA",
        "110.100.IN-ADDR.ARPA", "111.100.IN-ADDR.ARPA",
        "112.100.IN-ADDR.ARPA", "113.100.IN-ADDR.ARPA",
        "114.100.IN-ADDR.ARPA", "115.100.IN-ADDR.ARPA",
        "116.100.IN-ADDR.ARPA", "117.100.IN-ADDR.ARPA",
        "118.100.IN-ADDR.ARPA", "119.100.IN-ADDR.ARPA",
        "120.100.IN-ADDR.ARPA", "121.100.IN-ADDR.ARPA",
        "122.100.IN-ADDR.ARPA", "123.100.IN-ADDR.ARPA",
        "124.100.IN-ADDR.ARPA", "125.100.IN-ADDR.ARPA",
        "126.100.IN-ADDR.ARPA", "127.100.IN-ADDR.ARPA",
        # RFC 5735 and RFC 5737
        "0.IN-ADDR.ARPA", "127.IN-ADDR.ARPA", "254.169.IN-ADDR.ARPA",
        "2.0.192.IN-ADDR.ARPA", "100.51.198.IN-ADDR.ARPA",
        "113.0.203.IN-ADDR.ARPA", "255.255.255.255.IN-ADDR.ARPA",
        # Local IPv6 Unicast Addresses
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA",
        # LOCALLY ASSIGNED LOCAL ADDRESS SCOPE
        "D.F.IP6.ARPA", "8.E.F.IP6.ARPA", "9.E.F.IP6.ARPA", "A.E.F.IP6.ARPA",
        "B.E.F.IP6.ARPA",
        # Example Prefix, RFC 3849.
        "8.B.D.0.1.0.0.2.IP6.ARPA",
        # RFC 7534
        "EMPTY.AS112.ARPA",
    ]]


def assert_absolute_dnsname(name):
    """Raise AssertionError if name is not DNSName or is not absolute.

    >>> assert_absolute_dnsname(DNSName('absolute.name.example.'))
    >>> assert_absolute_dnsname(DNSName('relative.name.example'))
    Traceback (most recent call last):
      ...
    AssertionError: name must be absolute, ...
    >>> assert_absolute_dnsname('absolute.string.example.')
    Traceback (most recent call last):
      ...
    AssertionError: name must be DNSName instance, ...
    """

    assert isinstance(name, DNSName), ("name must be DNSName instance, "
                                       "got '%s'" % type(name))
    assert name.is_absolute(), "name must be absolute, got '%s'" % name


def is_auto_empty_zone(zone):
    """True if specified zone name exactly matches an automatic empty zone."""
    assert isinstance(zone, DNSName)
    return zone in EMPTY_ZONES
