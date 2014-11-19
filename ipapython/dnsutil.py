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


class DNSName(dns.name.Name):
    labels = None  # make pylint happy

    def __init__(self, labels, origin=None):
        try:
            if isinstance(labels, str):
                #pylint: disable=E1101
                labels = dns.name.from_text(labels, origin).labels
            elif isinstance(labels, unicode):
                #pylint: disable=E1101
                labels = dns.name.from_unicode(labels, origin).labels
            elif isinstance(labels, dns.name.Name):
                labels = labels.labels

            super(DNSName, self).__init__(labels)
        except UnicodeError, e:
            # dnspython bug, an invalid domain name returns the UnicodeError
            # instead of a dns.exception
            raise dns.exception.SyntaxError(e)

    def __nonzero__(self):
        #dns.name.from_text('@') is represented like empty tuple
        #we need to acting '@' as nonzero value
        return True

    def __copy__(self):
        return DNSName(self.labels)

    def __deepcopy__(self, memo):
        return DNSName(copy.deepcopy(self.labels, memo))

    def __str__(self):
        return self.to_text()

    def __unicode__(self):
        return self.to_unicode()

    def ToASCII(self):
        #method named by RFC 3490 and python standard library
        return str(self).decode('ascii')  # must be unicode string

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
