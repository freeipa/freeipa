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

import unittest
import pytest

from ipapython import ipavalidate

pytestmark = pytest.mark.tier0

class TestValidate(unittest.TestCase):
    def test_validEmail(self):
        self.assertEqual(True, ipavalidate.Email("test@freeipa.org"))
        self.assertEqual(True, ipavalidate.Email("", notEmpty=False))

    def test_invalidEmail(self):
        self.assertEqual(False, ipavalidate.Email("test"))
        self.assertEqual(False, ipavalidate.Email("test@freeipa"))
        self.assertEqual(False, ipavalidate.Email("test@.com"))
        self.assertEqual(False, ipavalidate.Email(""))
        self.assertEqual(False, ipavalidate.Email(None))

    def test_validPlain(self):
        self.assertEqual(True, ipavalidate.Plain("Joe User"))
        self.assertEqual(True, ipavalidate.Plain("Joe O'Malley"))
        self.assertEqual(True, ipavalidate.Plain("", notEmpty=False))
        self.assertEqual(True, ipavalidate.Plain(None, notEmpty=False))
        self.assertEqual(True, ipavalidate.Plain("JoeUser", allowSpaces=False))
        self.assertEqual(True, ipavalidate.Plain("JoeUser", allowSpaces=True))

    def test_invalidPlain(self):
        self.assertEqual(False, ipavalidate.Plain("Joe (User)"))
        self.assertEqual(False, ipavalidate.Plain("Joe C. User"))
        self.assertEqual(False, ipavalidate.Plain("", notEmpty=True))
        self.assertEqual(False, ipavalidate.Plain(None, notEmpty=True))
        self.assertEqual(False, ipavalidate.Plain("Joe User", allowSpaces=False))
        self.assertEqual(False, ipavalidate.Plain("Joe C. User"))

    def test_validString(self):
        self.assertEqual(True, ipavalidate.String("Joe User"))
        self.assertEqual(True, ipavalidate.String("Joe O'Malley"))
        self.assertEqual(True, ipavalidate.String("", notEmpty=False))
        self.assertEqual(True, ipavalidate.String(None, notEmpty=False))
        self.assertEqual(True, ipavalidate.String("Joe C. User"))

    def test_invalidString(self):
        self.assertEqual(False, ipavalidate.String("", notEmpty=True))
        self.assertEqual(False, ipavalidate.String(None, notEmpty=True))

    def test_validPath(self):
        self.assertEqual(True, ipavalidate.Path("/"))
        self.assertEqual(True, ipavalidate.Path("/home/user"))
        self.assertEqual(True, ipavalidate.Path("../home/user"))
        self.assertEqual(True, ipavalidate.Path("", notEmpty=False))
        self.assertEqual(True, ipavalidate.Path(None, notEmpty=False))

    def test_invalidPath(self):
        self.assertEqual(False, ipavalidate.Path("(foo)"))
        self.assertEqual(False, ipavalidate.Path("", notEmpty=True))
        self.assertEqual(False, ipavalidate.Path(None, notEmpty=True))

    def test_validName(self):
        self.assertEqual(True, ipavalidate.GoodName("foo"))
        self.assertEqual(True, ipavalidate.GoodName("1foo"))
        self.assertEqual(True, ipavalidate.GoodName("foo.bar"))
        self.assertEqual(True, ipavalidate.GoodName("foo.bar$"))

    def test_invalidName(self):
        self.assertEqual(False, ipavalidate.GoodName("foo bar"))
        self.assertEqual(False, ipavalidate.GoodName("foo%bar"))
        self.assertEqual(False, ipavalidate.GoodName("*foo"))
        self.assertEqual(False, ipavalidate.GoodName("$foo.bar$"))
