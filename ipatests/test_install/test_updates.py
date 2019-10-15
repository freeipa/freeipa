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

from __future__ import absolute_import

import os

import pytest

from ipalib import api
from ipalib import errors
from ipaserver.install.ldapupdate import LDAPUpdate, BadSyntax
from ipaserver.install import installutils
from ipapython import ipaldap
from ipaplatform.constants import constants as platformconstants
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


@pytest.mark.tier0
@pytest.mark.needs_ipaapi
class TestUpdate:
    """
    Test the LDAP updater.
    """

    @pytest.fixture(autouse=True)
    def update_setup(self, request):
        fqdn = installutils.get_fqdn()
        pwfile = api.env.dot_ipa + os.sep + ".dmpw"
        if os.path.isfile(pwfile):
            with open(pwfile, "r") as fp:
                self.dm_password = fp.read().rstrip()
        else:
            pytest.skip("No directory manager password")
        self.updater = LDAPUpdate(dm_password=self.dm_password, sub_dict={})
        self.ld = ipaldap.LDAPClient.from_hostname_secure(fqdn)
        self.ld.simple_bind(bind_dn=ipaldap.DIRMAN_DN,
                            bind_password=self.dm_password)
        self.testdir = os.path.abspath(os.path.dirname(__file__))
        if not os.path.isfile(os.path.join(self.testdir,
                                                "0_reset.update")):
            pytest.skip("Unable to find test update files")

        self.container_dn = DN(self.updater._template_str('cn=test, cn=accounts, $SUFFIX'))
        self.user_dn = DN(self.updater._template_str('uid=tuser, cn=test, cn=accounts, $SUFFIX'))

        def fin():
            if self.ld:
                self.ld.unbind()
        request.addfinalizer(fin)

    def test_0_reset(self):
        """
        Reset the updater test data to a known initial state (test_0_reset)
        """
        try:
            modified = self.updater.update([os.path.join(self.testdir,
                                                         "0_reset.update")])
        except errors.NotFound:
            # Just means the entry doesn't exist yet
            modified = True

        assert modified

        with pytest.raises(errors.NotFound):
            self.ld.get_entries(
                self.container_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])

        with pytest.raises(errors.NotFound):
            self.ld.get_entries(
                self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])

    def test_1_add(self):
        """
        Test the updater with an add directive (test_1_add)
        """
        modified = self.updater.update([os.path.join(self.testdir,
                                                     "1_add.update")])

        assert modified

        entries = self.ld.get_entries(
            self.container_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])
        assert len(entries) == 1
        entry = entries[0]

        objectclasses = entry.get('objectclass')
        for item in ('top', 'nsContainer'):
            assert item in objectclasses

        assert entry.single_value['cn'] == 'test'

        entries = self.ld.get_entries(
            self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])
        assert len(entries) == 1
        entry = entries[0]

        objectclasses = entry.get('objectclass')
        for item in ('top', 'person', 'posixaccount', 'krbprincipalaux', 'inetuser'):
            assert item in objectclasses

        actual = entry.single_value['loginshell']
        assert actual == platformconstants.DEFAULT_ADMIN_SHELL
        assert entry.single_value['sn'] == 'User'
        assert entry.single_value['uid'] == 'tuser'
        assert entry.single_value['cn'] == 'Test User'


    def test_2_update(self):
        """
        Test the updater when adding an attribute to an existing entry (test_2_update)
        """
        modified = self.updater.update([os.path.join(self.testdir,
                                                     "2_update.update")])
        assert modified

        entries = self.ld.get_entries(
            self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])
        assert len(entries) == 1
        entry = entries[0]
        assert entry.single_value['gecos'] == 'Test User'

    def test_3_update(self):
        """
        Test the updater forcing an attribute to a given value (test_3_update)
        """
        modified = self.updater.update([os.path.join(self.testdir,
                                                     "3_update.update")])
        assert modified

        entries = self.ld.get_entries(
            self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])
        assert len(entries) == 1
        entry = entries[0]
        assert entry.single_value['gecos'] == 'Test User New'

    def test_4_update(self):
        """
        Test the updater adding a new value to a single-valued attribute (test_4_update)
        """
        modified = self.updater.update([os.path.join(self.testdir,
                                                     "4_update.update")])
        assert modified

        entries = self.ld.get_entries(
            self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])
        assert len(entries) == 1
        entry = entries[0]
        assert entry.single_value['gecos'] == 'Test User New2'

    def test_5_update(self):
        """
        Test the updater adding a new value to a multi-valued attribute (test_5_update)
        """
        modified = self.updater.update([os.path.join(self.testdir,
                                                     "5_update.update")])
        assert modified

        entries = self.ld.get_entries(
            self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])
        assert len(entries) == 1
        entry = entries[0]
        actual = sorted(entry.get('cn'))
        expected = sorted(['Test User', 'Test User New'])
        assert actual == expected

    def test_6_update(self):
        """
        Test the updater removing a value from a multi-valued attribute (test_6_update)
        """
        modified = self.updater.update([os.path.join(self.testdir,
                                                     "6_update.update")])
        assert modified

        entries = self.ld.get_entries(
            self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])
        assert len(entries) == 1
        entry = entries[0]
        assert sorted(entry.get('cn')) == sorted(['Test User'])

    def test_6_update_1(self):
        """
        Test the updater removing a non-existent value from a multi-valued attribute (test_6_update_1)
        """
        modified = self.updater.update([os.path.join(self.testdir,
                                                     "6_update.update")])
        assert not modified

        entries = self.ld.get_entries(
            self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])
        assert len(entries) == 1
        entry = entries[0]
        assert sorted(entry.get('cn')) == sorted(['Test User'])

    def test_7_cleanup(self):
        """
        Reset the test data to a known initial state (test_7_cleanup)
        """
        try:
            modified = self.updater.update([os.path.join(self.testdir,
                                                         "0_reset.update")])
        except errors.NotFound:
            # Just means the entry doesn't exist yet
            modified = True

        assert modified

        with pytest.raises(errors.NotFound):
            self.ld.get_entries(
                self.container_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])

        with pytest.raises(errors.NotFound):
            self.ld.get_entries(
                self.user_dn, self.ld.SCOPE_BASE, 'objectclass=*', ['*'])

    def test_8_badsyntax(self):
        """
        Test the updater with an unknown keyword (test_8_badsyntax)
        """
        with pytest.raises(BadSyntax):
            self.updater.update(
                [os.path.join(self.testdir, "8_badsyntax.update")])

    def test_9_badsyntax(self):
        """
        Test the updater with an incomplete line (test_9_badsyntax)
        """
        with pytest.raises(BadSyntax):
            self.updater.update(
                [os.path.join(self.testdir, "9_badsyntax.update")])
