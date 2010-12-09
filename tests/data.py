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
Data frequently used in the unit tests, especially Unicode related tests.
"""

import struct


# A string that should have bytes 'x\00' through '\xff':
binary_bytes = ''.join(struct.pack('B', d) for d in xrange(256))
assert '\x00' in binary_bytes and '\xff' in binary_bytes
assert type(binary_bytes) is str and len(binary_bytes) == 256

# A UTF-8 encoded str:
utf8_bytes = '\xd0\x9f\xd0\xb0\xd0\xb2\xd0\xb5\xd0\xbb'

# The same UTF-8 data decoded (a unicode instance):
unicode_str = u'\u041f\u0430\u0432\u0435\u043b'
assert utf8_bytes.decode('UTF-8') == unicode_str
assert unicode_str.encode('UTF-8') == utf8_bytes
