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

import os
import sys
import ldap
import nose
from tests.util import raises, PluginTester
from tests.data import unicode_str
from ipalib import api
from ipalib import errors
from ipaserver.install.ldapupdate import LDAPUpdate, BadSyntax, UPDATES_DIR
from ipaserver.install import installutils
from ipaserver import ipaldap
from ipapython import ipautil

"""
The updater works through files only so this is just a thin-wrapper controlling
which file we test at any given point.

IMPORTANT NOTE: It is easy for these tests to get out of sync. Any changes
made to the update files may require changes to the test cases as well.
Some cases pull records from LDAP and do comparisons to ensure that updates
have occurred as expected.

The DM password needs to be set in ~/.ipa/.dmpw
"""

class test_update(object):
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

    def tearDown(self):
        if self.ld:
            self.ld.unbind()

    def test_0_reset(self):
        """
        Reset the updater test data to a known initial state
        """
        try:
            modified = self.updater.update([self.testdir + "0_reset.update"])
        except errors.NotFound:
            # Just means the entry doesn't exist yet
            modified = True

        assert(modified == True)

    def test_1_add(self):
        """
        Test the updater with an add directive
        """
        modified = self.updater.update([self.testdir + "1_add.update"])

        assert(modified == True)

    def test_2_update(self):
        """
        Test the updater when adding an attribute to an existing entry
        """
        modified = self.updater.update([self.testdir + "2_update.update"])
        assert(modified == True)

        # The update passed, lets look at the record and see if it is
        # really updated
        dn = self.updater._template_str('uid=tuser, cn=test, cn=accounts, $SUFFIX')
        entry = self.ld.getList(dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        assert (len(entry) == 1)
        assert(entry[0].gecos == 'Test User')

    def test_3_update(self):
        """
        Test the updater forcing an attribute to a given value
        """
        modified = self.updater.update([self.testdir + "3_update.update"])
        assert(modified == True)

        # The update passed, lets look at the record and see if it is
        # really updated
        dn = self.updater._template_str('uid=tuser, cn=test, cn=accounts, $SUFFIX')
        entry = self.ld.getList(dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        assert (len(entry) == 1)
        assert(entry[0].gecos == 'Test User New')

    def test_4_update(self):
        """
        Test the updater adding a new value to a single-valued attribute
        """
        modified = self.updater.update([self.testdir + "4_update.update"])
        assert(modified == True)

    def test_5_update(self):
        """
        Test the updater adding a new value to a multi-valued attribute
        """
        modified = self.updater.update([self.testdir + "5_update.update"])
        assert(modified == True)

        # The update passed, lets look at the record and see if it is
        # really updated
        dn = self.updater._template_str('uid=tuser, cn=test, cn=accounts, $SUFFIX')
        entry = self.ld.getList(dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        assert (len(entry) == 1)
        assert(entry[0].getValues('cn') == ['Test User', 'Test User New'])

    def test_6_update(self):
        """
        Test the updater removing a value from a multi-valued attribute
        """
        modified = self.updater.update([self.testdir + "6_update.update"])
        assert(modified == True)

        # The update passed, lets look at the record and see if it is
        # really updated
        dn = self.updater._template_str('uid=tuser, cn=test, cn=accounts, $SUFFIX')
        entry = self.ld.getList(dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        assert (len(entry) == 1)
        assert(entry[0].cn == 'Test User')

    def test_6_update_1(self):
        """
        Test the updater removing a non-existent value from a multi-valued attribute
        """
        modified = self.updater.update([self.testdir + "6_update.update"])
        assert(modified == False)

        # The update passed, lets look at the record and see if it is
        # really updated
        dn = self.updater._template_str('uid=tuser, cn=test, cn=accounts, $SUFFIX')
        entry = self.ld.getList(dn, ldap.SCOPE_BASE, 'objectclass=*', ['*'])
        assert (len(entry) == 1)
        assert(entry[0].cn == 'Test User')

    def test_7_cleanup(self):
        """
        Reset the test data to a known initial state
        """
        try:
            modified = self.updater.update([self.testdir + "0_reset.update"])
        except errors.NotFound:
            # Just means the entry doesn't exist yet
            modified = True

        assert(modified == True)

    def test_8_badsyntax(self):
        """
        Test the updater with an unknown keyword
        """
        try:
            modified = self.updater.update([self.testdir + "8_badsyntax.update"])
        except BadSyntax:
            pass

    def test_9_badsyntax(self):
        """
        Test the updater with an incomplete line
        """
        try:
            modified = self.updater.update([self.testdir + "9_badsyntax.update"])
        except BadSyntax:
            pass
