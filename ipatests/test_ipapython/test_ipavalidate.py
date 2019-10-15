#
# Copyright (C) 2007    Red Hat
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

import sys
sys.path.insert(0, ".")

import pytest

from ipapython import ipavalidate

pytestmark = pytest.mark.tier0


class TestValidate:
    def test_validEmail(self):
        assert ipavalidate.Email("test@freeipa.org") is True
        assert ipavalidate.Email("", notEmpty=False) is True

    def test_invalidEmail(self):
        assert ipavalidate.Email("test") is False
        assert ipavalidate.Email("test@freeipa") is False
        assert ipavalidate.Email("test@.com") is False
        assert ipavalidate.Email("") is False
        assert ipavalidate.Email(None) is False

    def test_validPlain(self):
        assert ipavalidate.Plain("Joe User") is True
        assert ipavalidate.Plain("Joe O'Malley") is True
        assert ipavalidate.Plain("", notEmpty=False) is True
        assert ipavalidate.Plain(None, notEmpty=False) is True
        assert ipavalidate.Plain("JoeUser", allowSpaces=False) is True
        assert ipavalidate.Plain("JoeUser", allowSpaces=True) is True

    def test_invalidPlain(self):
        assert ipavalidate.Plain("Joe (User)") is False
        assert ipavalidate.Plain("Joe C. User") is False
        assert ipavalidate.Plain("", notEmpty=True) is False
        assert ipavalidate.Plain(None, notEmpty=True) is False
        assert ipavalidate.Plain("Joe User", allowSpaces=False) is False
        assert ipavalidate.Plain("Joe C. User") is False

    def test_validString(self):
        assert ipavalidate.String("Joe User") is True
        assert ipavalidate.String("Joe O'Malley") is True
        assert ipavalidate.String("", notEmpty=False) is True
        assert ipavalidate.String(None, notEmpty=False) is True
        assert ipavalidate.String("Joe C. User") is True

    def test_invalidString(self):
        assert ipavalidate.String("", notEmpty=True) is False
        assert ipavalidate.String(None, notEmpty=True) is False

    def test_validPath(self):
        assert ipavalidate.Path("/") is True
        assert ipavalidate.Path("/home/user") is True
        assert ipavalidate.Path("../home/user") is True
        assert ipavalidate.Path("", notEmpty=False) is True
        assert ipavalidate.Path(None, notEmpty=False) is True

    def test_invalidPath(self):
        assert ipavalidate.Path("(foo)") is False
        assert ipavalidate.Path("", notEmpty=True) is False
        assert ipavalidate.Path(None, notEmpty=True) is False

    def test_validName(self):
        assert ipavalidate.GoodName("foo") is True
        assert ipavalidate.GoodName("1foo") is True
        assert ipavalidate.GoodName("foo.bar") is True
        assert ipavalidate.GoodName("foo.bar$") is True

    def test_invalidName(self):
        assert ipavalidate.GoodName("foo bar") is False
        assert ipavalidate.GoodName("foo%bar") is False
        assert ipavalidate.GoodName("*foo") is False
        assert ipavalidate.GoodName("$foo.bar$") is False
