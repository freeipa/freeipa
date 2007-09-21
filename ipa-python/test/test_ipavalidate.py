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

    def test_validemail(self):
        self.assertEqual(0, ipavalidate.email("test@freeipa.org"))
        self.assertEqual(0, ipavalidate.email("", notEmpty=False))

    def test_invalidemail(self):
        self.assertEqual(1, ipavalidate.email("test"))
        self.assertEqual(1, ipavalidate.email("test@freeipa"))
        self.assertEqual(1, ipavalidate.email("test@.com"))
        self.assertEqual(1, ipavalidate.email(""))
        self.assertEqual(1, ipavalidate.email(None))

    def test_validplain(self):
        self.assertEqual(0, ipavalidate.plain("Joe User"))
        self.assertEqual(0, ipavalidate.plain("Joe O'Malley"))
        self.assertEqual(0, ipavalidate.plain("", notEmpty=False))
        self.assertEqual(0, ipavalidate.plain(None, notEmpty=False))

    def test_invalidplain(self):
        self.assertEqual(1, ipavalidate.plain("Joe (User)"))
        self.assertEqual(1, ipavalidate.plain("", notEmpty=True))
        self.assertEqual(1, ipavalidate.plain(None, notEmpty=True))

    def test_validpath(self):
        self.assertEqual(0, ipavalidate.path("/"))
        self.assertEqual(0, ipavalidate.path("/home/user"))
        self.assertEqual(0, ipavalidate.path("../home/user"))
        self.assertEqual(0, ipavalidate.path("", notEmpty=False))
        self.assertEqual(0, ipavalidate.path(None, notEmpty=False))

    def test_invalidpath(self):
        self.assertEqual(1, ipavalidate.path("(foo)"))
        self.assertEqual(1, ipavalidate.path("", notEmpty=True))
        self.assertEqual(1, ipavalidate.path(None, notEmpty=True))

if __name__ == '__main__':
    unittest.main()

