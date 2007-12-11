#! /usr/bin/python -E
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import sys
sys.path.insert(0, ".")

import unittest

import ipavalidate

class TestValidate(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_validEmail(self):
        self.assertEqual(0, ipavalidate.Email("test@freeipa.org"))
        self.assertEqual(0, ipavalidate.Email("", notEmpty=False))

    def test_invalidEmail(self):
        self.assertEqual(1, ipavalidate.Email("test"))
        self.assertEqual(1, ipavalidate.Email("test@freeipa"))
        self.assertEqual(1, ipavalidate.Email("test@.com"))
        self.assertEqual(1, ipavalidate.Email(""))
        self.assertEqual(1, ipavalidate.Email(None))

    def test_validPlain(self):
        self.assertEqual(0, ipavalidate.Plain("Joe User"))
        self.assertEqual(0, ipavalidate.Plain("Joe O'Malley"))
        self.assertEqual(0, ipavalidate.Plain("", notEmpty=False))
        self.assertEqual(0, ipavalidate.Plain(None, notEmpty=False))
        self.assertEqual(0, ipavalidate.Plain("JoeUser", allowSpaces=False))
        self.assertEqual(0, ipavalidate.Plain("JoeUser", allowSpaces=True))

    def test_invalidPlain(self):
        self.assertEqual(1, ipavalidate.Plain("Joe (User)"))
        self.assertEqual(1, ipavalidate.Plain("Joe C. User"))
        self.assertEqual(1, ipavalidate.Plain("", notEmpty=True))
        self.assertEqual(1, ipavalidate.Plain(None, notEmpty=True))
        self.assertEqual(1, ipavalidate.Plain("Joe User", allowSpaces=False))

    def test_validString(self):
        self.assertEqual(0, ipavalidate.String("Joe User"))
        self.assertEqual(0, ipavalidate.String("Joe O'Malley"))
        self.assertEqual(1, ipavalidate.Plain("Joe C. User"))
        self.assertEqual(0, ipavalidate.String("", notEmpty=False))
        self.assertEqual(0, ipavalidate.String(None, notEmpty=False))

    def test_invalidString(self):
        self.assertEqual(1, ipavalidate.String("", notEmpty=True))
        self.assertEqual(1, ipavalidate.String(None, notEmpty=True))

    def test_validPath(self):
        self.assertEqual(0, ipavalidate.Path("/"))
        self.assertEqual(0, ipavalidate.Path("/home/user"))
        self.assertEqual(0, ipavalidate.Path("../home/user"))
        self.assertEqual(0, ipavalidate.Path("", notEmpty=False))
        self.assertEqual(0, ipavalidate.Path(None, notEmpty=False))

    def test_invalidPath(self):
        self.assertEqual(1, ipavalidate.Path("(foo)"))
        self.assertEqual(1, ipavalidate.Path("", notEmpty=True))
        self.assertEqual(1, ipavalidate.Path(None, notEmpty=True))

if __name__ == '__main__':
    unittest.main()

