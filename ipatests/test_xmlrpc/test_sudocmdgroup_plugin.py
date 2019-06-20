# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
#
# Copyright (C) 2010  Red Hat
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
Test the `ipaserver/plugins/sudocmdgroup.py` module.
"""

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.test_xmlrpc.tracker.sudocmd_plugin import SudoCmdTracker
from ipatests.test_xmlrpc.tracker.sudocmdgroup_plugin import (
    SudoCmdGroupTracker
    )
import pytest


@pytest.fixture(scope='class')
def sudocmd1(request, xmlrpc_setup):
    tracker = SudoCmdTracker(command=u'/usr/bin/sudotestcmd1',
                             description=u'Test sudo command 1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def sudocmd2(request, xmlrpc_setup):
    tracker = SudoCmdTracker(command=u'/usr/bin/sudoTestCmd1',
                             description=u'Test sudo command 2')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def sudocmd_plus(request, xmlrpc_setup):
    tracker = SudoCmdTracker(command=u'/bin/ls -l /lost+found/*',
                             description=u'Test sudo command 3')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def sudocmdgroup1(request, xmlrpc_setup):
    tracker = SudoCmdGroupTracker(u'testsudocmdgroup1', u'Test desc1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def sudocmdgroup2(request, xmlrpc_setup):
    tracker = SudoCmdGroupTracker(u'testsudocmdgroup2', u'Test desc2')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestSudoCmdGroupNonexistent(XMLRPC_test):
    def test_retrieve_nonexistent(self, sudocmdgroup1, sudocmdgroup2):
        """ Try to retrieve non-existent sudocmdgroups """
        sudocmdgroup1.ensure_missing()
        command = sudocmdgroup1.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command group not found' %
                sudocmdgroup1.cn)):
            command()

        sudocmdgroup2.ensure_missing()
        command = sudocmdgroup2.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command group not found' %
                sudocmdgroup2.cn)):
            command()

    def test_update_nonexistent(self, sudocmdgroup1, sudocmdgroup2):
        """ Try to update non-existent sudocmdgroups """
        sudocmdgroup1.ensure_missing()
        command = sudocmdgroup1.make_update_command(dict(description=u'Foo'))
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command group not found' %
                sudocmdgroup1.cn)):
            command()

        sudocmdgroup2.ensure_missing()
        command = sudocmdgroup2.make_update_command(dict(description=u'Foo2'))
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command group not found' %
                sudocmdgroup2.cn)):
            command()

    def test_delete_nonexistent(self, sudocmdgroup1, sudocmdgroup2):
        """ Try to delete non-existent sudocmdgroups """
        sudocmdgroup1.ensure_missing()
        command = sudocmdgroup1.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command group not found' %
                sudocmdgroup1.cn)):
            command()

        sudocmdgroup2.ensure_missing()
        command = sudocmdgroup2.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command group not found' %
                sudocmdgroup2.cn)):
            command()


@pytest.mark.tier1
class TestSudoCmdGroupSCRUD(XMLRPC_test):
    def test_create_sudocmds_and_verify(self, sudocmd1, sudocmd2):
        """ Create sudocmd and sudocmd with camelcase'd command
        and verify the managed sudo command sudocmds were created """
        sudocmd1.ensure_exists()
        sudocmd2.ensure_exists()
        sudocmd1.retrieve()
        sudocmd2.retrieve()

    def test_create(self, sudocmdgroup1):
        """ Create sudocmdgroup """
        sudocmdgroup1.create()

    def test_create_duplicate(self, sudocmdgroup1):
        """ Try to create duplicate sudocmdgroup """
        sudocmdgroup1.ensure_exists()
        command = sudocmdgroup1.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message=u'sudo command group ' +
                        u'with name "%s" already exists' % sudocmdgroup1.cn)):
            command()

    def test_retrieve(self, sudocmdgroup1):
        """ Retrieve sudocmdgroup """
        sudocmdgroup1.ensure_exists()
        sudocmdgroup1.retrieve()

    def test_update(self, sudocmdgroup1):
        """ Update sudocmdgroup and retrieve to verify update """
        sudocmdgroup1.ensure_exists()
        sudocmdgroup1.update(dict(description=u'New desc 1'))
        sudocmdgroup1.retrieve()

    def test_search(self, sudocmdgroup1):
        """ Search for sudocmdgroup """
        sudocmdgroup1.ensure_exists()
        sudocmdgroup1.find()

    def test_search_all(self, sudocmdgroup1):
        """ Search for sudocmdgroup """
        sudocmdgroup1.ensure_exists()
        sudocmdgroup1.find(all=True)

    def test_create_another(self, sudocmdgroup2):
        """ Create a second sudocmdgroup """
        sudocmdgroup2.create()

    def test_search_for_both(self, sudocmdgroup1, sudocmdgroup2):
        """ Search for all sudocmdgroups, find two """
        sudocmdgroup1.ensure_exists()
        sudocmdgroup2.ensure_exists()
        sudocmdgroup1.find(all=True)


@pytest.mark.tier1
class TestSudoCmdGroupMembers(XMLRPC_test):
    def test_add_sudocmd_to_sudocmdgroup(self, sudocmd1, sudocmdgroup1):
        """ Add member sudocmd to sudocmdgroup """
        sudocmdgroup1.ensure_exists()
        sudocmd1.ensure_exists()
        sudocmdgroup1.add_member(dict(sudocmd=sudocmd1.cmd))

    def test_retrieve_sudocmd_show_membership(self, sudocmd1, sudocmdgroup1):
        """ Retrieve sudocmd to show membership """
        sudocmd1.ensure_exists()
        sudocmd1.attrs.update(memberof_sudocmdgroup=[sudocmdgroup1.cn])
        sudocmd1.retrieve()

    def test_add_nonexistent_member_to_sudocmdgroup(self, sudocmdgroup1):
        """ Try to add non-existent member to sudocmdgroup """
        options = dict(sudocmd=u'notfound')
        sudocmdgroup1.ensure_exists()
        command = sudocmdgroup1.make_add_member_command(options)
        result = command()
        sudocmdgroup1.check_add_member_negative(result, options)

    def test_add_member_sudocmd_to_sudocmdgroup(self, sudocmdgroup1, sudocmd2):
        """ Add member sudocmdgroup to sudocmdgroup """
        sudocmdgroup1.ensure_exists()
        sudocmd2.ensure_exists()
        sudocmdgroup1.add_member(dict(sudocmd=sudocmd2.cmd))

    def test_remove_member_sudocmd_from_sudocmdgroup(self, sudocmdgroup1,
                                                     sudocmd1):
        """ Remove member sudocmd from sudocmdgroup """
        sudocmdgroup1.ensure_exists()
        sudocmdgroup1.remove_member(dict(sudocmd=sudocmd1.cmd))

    def test_remove_nonexistent_member_from_sudocmdgroup(self, sudocmdgroup1):
        """ Try to remove non-existent member from sudocmdgroup """
        options = dict(sudocmd=u'notfound')
        sudocmdgroup1.ensure_exists()
        command = sudocmdgroup1.make_remove_member_command(options)
        result = command()
        sudocmdgroup1.check_remove_member_negative(result, options)

    def test_special_member_sudocmd_with_sudocmdgroup(self, sudocmdgroup1,
                                                      sudocmd_plus):
        """ Test add and remove sudocmd with special
        characters as sudocmdgroup member """
        sudocmdgroup1.ensure_exists()
        sudocmd_plus.ensure_exists()
        sudocmdgroup1.add_member(dict(sudocmd=sudocmd_plus.cmd))
        sudocmdgroup1.remove_member(dict(sudocmd=sudocmd_plus.cmd))
