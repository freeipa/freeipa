# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2012  Red Hat
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
Test the `ipalib.errors` module.
"""

from ipalib.capabilities import capabilities, client_has_capability

import pytest

pytestmark = pytest.mark.tier0

def test_client_has_capability():
    assert capabilities['messages'] == u'2.52'
    assert client_has_capability(u'2.52', 'messages')
    assert client_has_capability(u'2.60', 'messages')
    assert client_has_capability(u'3.0', 'messages')
    assert not client_has_capability(u'2.11', 'messages')
    assert not client_has_capability(u'0.1', 'messages')
