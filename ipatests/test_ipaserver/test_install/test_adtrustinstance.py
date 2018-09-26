# Authors:
#   Sumit Bose <sbose@redhat.com>
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
Test `adtrustinstance`
"""
import pytest
import six

from ipaserver.install import adtrustinstance

if six.PY3:
    unicode = str


@pytest.mark.tier0
class test_adtrustinstance:
    """
    Test `adtrustinstance`.
    """

    def test_make_netbios_name(self):
        s = adtrustinstance.make_netbios_name("ABCDEF")
        assert s == 'ABCDEF' and isinstance(s, str)
        s = adtrustinstance.make_netbios_name(U"ABCDEF")
        assert s == 'ABCDEF' and isinstance(s, unicode)
        s = adtrustinstance.make_netbios_name("abcdef")
        assert s == 'ABCDEF'
        s = adtrustinstance.make_netbios_name("abc.def")
        assert s == 'ABC'
        s = adtrustinstance.make_netbios_name("abcdefghijklmnopqr.def")
        assert s == 'ABCDEFGHIJKLMNO'
        s = adtrustinstance.make_netbios_name("A!$%B&/()C=?+*D")
        assert s == 'ABCD'
        s = adtrustinstance.make_netbios_name("!$%&/()=?+*")
        assert not s

    def test_check_netbios_name(self):
        assert adtrustinstance.check_netbios_name("ABCDEF")
        assert not adtrustinstance.check_netbios_name("abcdef")
        assert adtrustinstance.check_netbios_name("ABCDE12345ABCDE")
        assert not adtrustinstance.check_netbios_name("ABCDE12345ABCDE1")
        assert not adtrustinstance.check_netbios_name("")

        assert adtrustinstance.check_netbios_name(U"ABCDEF")
        assert not adtrustinstance.check_netbios_name(U"abcdef")
        assert adtrustinstance.check_netbios_name(U"ABCDE12345ABCDE")
        assert not adtrustinstance.check_netbios_name(U"ABCDE12345ABCDE1")
