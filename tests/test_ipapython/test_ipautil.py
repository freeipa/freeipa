# Authors:
#   Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2011  Red Hat
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
Test the `ipapython/ipautil.py` module.
"""

import nose

from ipapython import ipautil

class CheckIPAddress:
    def __init__(self, addr):
        self.description = "Test IP address parsing and verification (%s)" % addr

    def __call__(self, addr, words=None, prefixlen=None):
        try:
            ip = ipautil.CheckedIPAddress(addr, match_local=False)
            assert ip.words == words and ip.prefixlen == prefixlen
        except:
            assert words is None and prefixlen is None

def test_ip_address():
    addrs = [
        ('10.11.12.13',     (10, 11, 12, 13),   8),
        ('10.11.12.13/14',  (10, 11, 12, 13),   14),
        ('10.11.12.13%zoneid',),
        ('10.11.12.13%zoneid/14',),
        ('10.11.12.1337',),
        ('10.11.12.13/33',),
        ('127.0.0.1',),
        ('241.1.2.3',),
        ('169.254.1.2',),
        ('10.11.12.0/24',),
        ('224.5.6.7',),
        ('10.11.12.255/24',),

        ('2001::1',         (0x2001, 0, 0, 0, 0, 0, 0, 1), 64),
        ('2001::1/72',      (0x2001, 0, 0, 0, 0, 0, 0, 1), 72),
        ('2001::1%zoneid',  (0x2001, 0, 0, 0, 0, 0, 0, 1), 64),
        ('2001::1%zoneid/72',),
        ('2001::1beef',),
        ('2001::1/129',),
        ('::1',),
        ('6789::1',),
        ('fe89::1',),
        ('2001::/64',),
        ('ff01::1',),

        ('junk',)
    ]

    for addr in addrs:
        yield (CheckIPAddress(addr[0]),) + addr
