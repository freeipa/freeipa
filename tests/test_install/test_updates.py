# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipaserver/install/ldapupdate.py` module.
"""

import unittest
import os
import sys
import ldap
import nose
from ipalib import api
from ipalib import errors
from ipaserver.install.ldapupdate import LDAPUpdate, BadSyntax, UPDATES_DIR
from ipaserver.install import installutils
from ipaserver import ipaldap
from ipapython import ipautil
from ipapython.dn import DN

"""
The updater works through files only so this is just a thin-wrapper controlling
which file we test at any given point.

IMPORTANT NOTE: It is easy for these tests to get out of sync. Any changes
made to the update files may require changes to the test cases as well.
Some cases pull records from LDAP and do comparisons to ensure that updates
have occurred as expected.

The DM password needs to be set in ~/.ipa/.dmpw
"""

class test_update(unittest.TestCase):
    """
    Test the LDAP updater.
    """

    def setUp(self):
        fqdn = installutils.get_fqdn()
        pwfile = api.env.dot_ipa + os.sep + ".dmpw"
        if ipautil.file_exists(pwfile):
            fp = open(pwfile, "r")
            self.dm_password = fp.read().rstrip()
            fp.close()
        else:
            raise nose.SkipTest("No directory manager password")
        self.updater = LDAPUpdate(dm_password=self.dm_password, sub_dict={}, live_run=True)
        self.ld = ipaldap.IPAdmin(fqdn)
        self.ld.do_simple_bind(bindpw=self.dm_password)
        if ipautil.file_exists("0_reset.update"):
            self.testdir="./"
        elif ipautil.file_exists("tests/test_install/0_reset.update"):
            self.testdir= "./tests/test_install/"
        else:
            raise nose.SkipTest("Unable to find test update files")

        self.container_dn = DN(self.updater._template_str('cn=test, cn=accounts, $SUFFIX'))
        self.user_dn = DN(self.updater._template_str('uid=tuser, cn=test, cn=accounts, $SUFFIX'))

    def tearDown(self):
        if self.ld:
            self.ld.unbind()

    def test_0_reset(self):
        """
        Reset the updater test data to a known initial state (test_0_reset)
        """
        try:
            modified = self.updater.update([self.testdir + "0_reset.update"])
        except errors.NotFound:
            # Just means the entry doesn't exist yet
            modified = True

        self.assertTrue(modified)

        with self.assertRaises(errors.NotFound):
            entries = self.ld.getList(self.container_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])

        with self.assertRaises(errors.NotFound):
            entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])

    def test_1_add(self):
        """
        Test the updater with an add directive (test_1_add)
        """
        modified = self.updater.update([self.testdir + "1_add.update"])

        self.assertTrue(modified)

        entries = self.ld.getList(self.container_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]

        objectclasses = entry.getValues('objectclass')
        for item in ('top', 'nsContainer'):
            self.assertTrue(item in objectclasses)

        self.assertEqual(entry.getValue('cn'), 'test')

        entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]

        objectclasses = entry.getValues('objectclass')
        for item in ('top', 'person', 'posixaccount', 'krbprincipalaux', 'inetuser'):
            self.assertTrue(item in objectclasses)

        self.assertEqual(entry.getValue('loginshell'), '/bin/bash')
        self.assertEqual(entry.getValue('sn'), 'User')
        self.assertEqual(entry.getValue('uid'), 'tuser')
        self.assertEqual(entry.getValue('cn'), 'Test User')


    def test_2_update(self):
        """
        Test the updater when adding an attribute to an existing entry (test_2_update)
        """
        modified = self.updater.update([self.testdir + "2_update.update"])
        self.assertTrue(modified)

        entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.getValue('gecos'), 'Test User')

    def test_3_update(self):
        """
        Test the updater forcing an attribute to a given value (test_3_update)
        """
        modified = self.updater.update([self.testdir + "3_update.update"])
        self.assertTrue(modified)

        entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.getValue('gecos'), 'Test User New')

    def test_4_update(self):
        """
        Test the updater adding a new value to a single-valued attribute (test_4_update)
        """
        modified = self.updater.update([self.testdir + "4_update.update"])
        self.assertTrue(modified)

        entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.getValue('gecos'), 'Test User New2')

    def test_5_update(self):
        """
        Test the updater adding a new value to a multi-valued attribute (test_5_update)
        """
        modified = self.updater.update([self.testdir + "5_update.update"])
        self.assertTrue(modified)

        entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(sorted(entry.getValues('cn')), sorted(['Test User', 'Test User New']))

    def test_6_update(self):
        """
        Test the updater removing a value from a multi-valued attribute (test_6_update)
        """
        modified = self.updater.update([self.testdir + "6_update.update"])
        self.assertTrue(modified)

        entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(sorted(entry.getValues('cn')), sorted(['Test User']))

    def test_6_update_1(self):
        """
        Test the updater removing a non-existent value from a multi-valued attribute (test_6_update_1)
        """
        modified = self.updater.update([self.testdir + "6_update.update"])
        self.assertFalse(modified)

        entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(sorted(entry.getValues('cn')), sorted(['Test User']))

    def test_7_cleanup(self):
        """
        Reset the test data to a known initial state (test_7_cleanup)
        """
        try:
            modified = self.updater.update([self.testdir + "0_reset.update"])
        except errors.NotFound:
            # Just means the entry doesn't exist yet
            modified = True

        self.assertTrue(modified)

        with self.assertRaises(errors.NotFound):
            entries = self.ld.getList(self.container_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])

        with self.assertRaises(errors.NotFound):
            entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])

    def test_8_badsyntax(self):
        """
        Test the updater with an unknown keyword (test_8_badsyntax)
        """
        with self.assertRaises(BadSyntax):
            modified = self.updater.update([self.testdir + "8_badsyntax.update"])

    def test_9_badsyntax(self):
        """
        Test the updater with an incomplete line (test_9_badsyntax)
        """
        with self.assertRaises(BadSyntax):
            modified = self.updater.update([self.testdir + "9_badsyntax.update"])

    def test_from_dict(self):
        """
        Test updating from a dict.

        This replicates what was done in test 1.
        """

        # First make sure we're clean
        with self.assertRaises(errors.NotFound):
            entries = self.ld.getList(self.container_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])

        with self.assertRaises(errors.NotFound):
            entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])


        update = {
            self.container_dn:
                {'dn': self.container_dn,
                 'updates': ['add:objectClass: top',
                             'add:objectClass: nsContainer',
                             'add:cn: test'
                            ],
                },
            self.user_dn:
                {'dn': self.user_dn,
                 'updates': ['add:objectclass: top',
                             'add:objectclass: person',
                             'add:objectclass: posixaccount',
                             'add:objectclass: krbprincipalaux',
                             'add:objectclass: inetuser',
                             'add:homedirectory: /home/tuser',
                             'add:loginshell: /bin/bash',
                             'add:sn: User',
                             'add:uid: tuser',
                             'add:uidnumber: 999',
                             'add:gidnumber: 999',
                             'add:cn: Test User',
                            ],
                },
        }

        modified = self.updater.update_from_dict(update)
        self.assertTrue(modified)

        entries = self.ld.getList(self.container_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]

        objectclasses = entry.getValues('objectclass')
        for item in ('top', 'nsContainer'):
            self.assertTrue(item in objectclasses)

        self.assertEqual(entry.getValue('cn'), 'test')

        entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        self.assertEqual(len(entries), 1)
        entry = entries[0]

        objectclasses = entry.getValues('objectclass')
        for item in ('top', 'person', 'posixaccount', 'krbprincipalaux', 'inetuser'):
            self.assertTrue(item in objectclasses)

        self.assertEqual(entry.getValue('loginshell'), '/bin/bash')
        self.assertEqual(entry.getValue('sn'), 'User')
        self.assertEqual(entry.getValue('uid'), 'tuser')
        self.assertEqual(entry.getValue('cn'), 'Test User')

        # Now delete

        update = {
            self.container_dn:
                {'dn': self.container_dn,
                 'deleteentry': None,
                },
            self.user_dn:
                {'dn': self.user_dn,
                 'deleteentry': 'deleteentry: reset: nada',
                },
        }

        modified = self.updater.update_from_dict(update)
        self.assertTrue(modified)

        with self.assertRaises(errors.NotFound):
            entries = self.ld.getList(self.container_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])

        with self.assertRaises(errors.NotFound):
            entries = self.ld.getList(self.user_dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
