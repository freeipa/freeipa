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
Test the `ipaserver/plugins/sudocmd.py` module.
"""

from ipalib import api, errors
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.xmlrpc_test import (XMLRPC_test, raises_exact)
from ipatests.test_xmlrpc.tracker.sudocmd_plugin import SudoCmdTracker
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
def sudorule1(request, xmlrpc_setup):
    name = u'test_sudorule1'

    def fin():
        api.Command['sudorule_del'](name)
    request.addfinalizer(fin)
    return name


@pytest.mark.tier1
class TestNonexistentSudoCmd(XMLRPC_test):
    def test_retrieve_nonexistent(self, sudocmd1):
        """ Try to retrieve non-existent sudocmd """
        command = sudocmd1.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1.cmd)):
            command()

    def test_update_nonexistent(self, sudocmd1):
        """ Try to update non-existent sudocmd """
        command = sudocmd1.make_update_command(dict(description=u'Nope'))
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1.cmd)):
            command()

    def test_delete_nonexistent(self, sudocmd1):
        """ Try to delete non-existent sudocmd """
        command = sudocmd1.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1.cmd)):
            command()


@pytest.mark.tier1
class TestSudoCmd(XMLRPC_test):
    def test_create(self, sudocmd1, sudocmd2):
        """ Create sudocmd and sudocmd with camelcase'd command """
        sudocmd1.ensure_exists()
        sudocmd2.ensure_exists()

    def test_create_duplicates(self, sudocmd1, sudocmd2):
        """ Try to create duplicate sudocmds """
        sudocmd1.ensure_exists()
        sudocmd2.ensure_exists()
        command1 = sudocmd1.make_create_command()
        command2 = sudocmd2.make_create_command()

        with raises_exact(errors.DuplicateEntry(
                message=u'sudo command with name "%s" already exists' %
                sudocmd1.cmd)):
            command1()
        with raises_exact(errors.DuplicateEntry(
                message=u'sudo command with name "%s" already exists' %
                sudocmd2.cmd)):
            command2()

    def test_retrieve(self, sudocmd1):
        """ Retrieve sudocmd """
        sudocmd1.ensure_exists()
        sudocmd1.retrieve()

    def test_search(self, sudocmd1, sudocmd2):
        """ Search for sudocmd """
        sudocmd1.find()
        sudocmd2.find()

    def test_update_and_verify(self, sudocmd1):
        """ Update sudocmd description and verify by retrieve """
        sudocmd1_desc_new = u'Updated sudo command 1'
        sudocmd1.update(dict(description=sudocmd1_desc_new),
                        dict(description=[sudocmd1_desc_new]))
        sudocmd1.retrieve()


@pytest.mark.tier1
class TestSudoCmdInSudoRuleLists(XMLRPC_test):
    def test_add_sudocmd_to_sudorule_allow_list(self, sudocmd1, sudorule1):
        """ Add sudocmd to sudorule allow list """
        sudocmd1.ensure_exists()
        api.Command['sudorule_add'](sudorule1)
        result = api.Command['sudorule_add_allow_command'](
            sudorule1, sudocmd=sudocmd1.cmd
        )
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                memberallowcmd=dict(sudocmdgroup=(), sudocmd=())),
            result=lambda result: True,
        ), result)

    def test_del_dependent_sudocmd_sudorule_allow(self, sudocmd1, sudorule1):
        """ Try to delete sudocmd that is in sudorule allow list """
        sudocmd1.ensure_exists()
        command = sudocmd1.make_delete_command()
        with raises_exact(errors.DependentEntry(
                key=sudocmd1.cmd,
                label='sudorule',
                dependent=sudorule1)):
            command()

    def test_remove_sudocmd_from_sudorule_allow(self, sudocmd1, sudorule1):
        """ Remove sudocmd from sudorule allow list """
        sudocmd1.ensure_exists()
        result = api.Command['sudorule_remove_allow_command'](
            sudorule1, sudocmd=sudocmd1.cmd
        )
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                memberallowcmd=dict(sudocmdgroup=(), sudocmd=())),
            result=lambda result: True),
            result)

    def test_add_sudocmd_to_sudorule_deny_list(self, sudocmd1, sudorule1):
        """ Add sudocmd to sudorule deny list """
        sudocmd1.ensure_exists()
        result = api.Command['sudorule_add_deny_command'](
            sudorule1, sudocmd=sudocmd1.cmd
        )
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                memberdenycmd=dict(sudocmdgroup=(), sudocmd=())),
            result=lambda result: True),
            result)

    def test_del_dependent_sudocmd_sudorule_deny(self, sudocmd1, sudorule1):
        """ Try to delete sudocmd that is in sudorule deny list """
        sudocmd1.ensure_exists()
        command = sudocmd1.make_delete_command()
        with raises_exact(errors.DependentEntry(
                key=sudocmd1.cmd,
                label='sudorule',
                dependent=sudorule1)):
            command()

    def test_remove_sudocmd_from_sudorule_deny(self, sudocmd1, sudorule1):
        """ Remove sudocmd from sudorule deny list """
        sudocmd1.ensure_exists()
        result = api.Command['sudorule_remove_deny_command'](
            sudorule1, sudocmd=sudocmd1.cmd
        )
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                memberdenycmd=dict(sudocmdgroup=(), sudocmd=())),
            result=lambda result: True),
            result)
