#! /usr/bin/python -E
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
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
import aci
import urllib


class TestACI(unittest.TestCase):
    acitemplate = ('(targetattr="%s")' +
               '(targetfilter="(memberOf=%s)")' +
               '(version 3.0;' +
               'acl "%s";' +
               'allow (write) ' +
               'groupdn="ldap:///%s";)')

    def setUp(self):
        self.aci = aci.ACI()

    def tearDown(self):
        pass

    def testExport(self):
        self.aci.source_group = 'cn=foo, dc=freeipa, dc=org'
        self.aci.dest_group = 'cn=bar, dc=freeipa, dc=org'
        self.aci.name = 'this is a "name'
        self.aci.attrs = ['field1', 'field2', 'field3']

        exportaci = self.aci.export_to_string()
        aci = TestACI.acitemplate % ('field1 || field2 || field3',
                                     self.aci.dest_group,
                                     'this is a "name',
                                     self.aci.source_group)

        self.assertEqual(aci, exportaci)

    def testURLEncodedExport(self):
        self.aci.source_group = 'cn=foo " bar, dc=freeipa, dc=org'
        self.aci.dest_group = 'cn=bar, dc=freeipa, dc=org'
        self.aci.name = 'this is a "name'
        self.aci.attrs = ['field1', 'field2', 'field3']

        exportaci = self.aci.export_to_string()
        aci = TestACI.acitemplate % ('field1 || field2 || field3',
                                     self.aci.dest_group,
                                     'this is a "name',
                                     urllib.quote(self.aci.source_group, "/=, "))

        self.assertEqual(aci, exportaci)

    def testSimpleParse(self):
        attr_str = 'field3 || field4 || field5'
        dest_dn = 'cn=dest\\"group, dc=freeipa, dc=org'
        name = 'my name'
        src_dn = 'cn=srcgroup, dc=freeipa, dc=org'

        acistr = TestACI.acitemplate % (attr_str, dest_dn, name, src_dn)
        self.aci.parse_acistr(acistr)

        self.assertEqual(['field3', 'field4', 'field5'], self.aci.attrs)
        self.assertEqual(dest_dn, self.aci.dest_group)
        self.assertEqual(name, self.aci.name)
        self.assertEqual(src_dn, self.aci.source_group)

    def testUrlEncodedParse(self):
        attr_str = 'field3 || field4 || field5'
        dest_dn = 'cn=dest\\"group, dc=freeipa, dc=org'
        name = 'my name'
        src_dn = 'cn=src " group, dc=freeipa, dc=org'

        acistr = TestACI.acitemplate % (attr_str, dest_dn, name, 
                urllib.quote(src_dn, "/=, "))
        self.aci.parse_acistr(acistr)

        self.assertEqual(['field3', 'field4', 'field5'], self.aci.attrs)
        self.assertEqual(dest_dn, self.aci.dest_group)
        self.assertEqual(name, self.aci.name)
        self.assertEqual(src_dn, self.aci.source_group)

    def testInvalidParse(self):
        try:
          self.aci.parse_acistr('foo bar')
          self.fail('Should have failed to parse')
        except SyntaxError:
            pass

        try:
          self.aci.parse_acistr('')
          self.fail('Should have failed to parse')
        except SyntaxError:
            pass

        attr_str = 'field3 || field4 || field5'
        dest_dn = 'cn=dest\\"group, dc=freeipa, dc=org'
        name = 'my name'
        src_dn = 'cn=srcgroup, dc=freeipa, dc=org'

        acistr = TestACI.acitemplate % (attr_str, dest_dn, name, src_dn)
        acistr += 'trailing garbage'
        try:
          self.aci.parse_acistr('')
          self.fail('Should have failed to parse')
        except SyntaxError:
            pass


if __name__ == '__main__':
    unittest.main()
