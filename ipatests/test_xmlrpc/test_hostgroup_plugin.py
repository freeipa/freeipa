# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008, 2009  Red Hat
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
Test the `ipalib.plugins.hostgroup` module.
"""


from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.test_xmlrpc.tracker.hostgroup_plugin import HostGroupTracker
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipalib import errors
import pytest


@pytest.fixture(scope='class')
def hostgroup(request, xmlrpc_setup):
    tracker = HostGroupTracker(name=u'hostgroup')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def hostgroup_invalid(request, xmlrpc_setup):
    tracker = HostGroupTracker(name=u'@invalid')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def hostgroup_single(request, xmlrpc_setup):
    tracker = HostGroupTracker(name=u'a')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host(request, xmlrpc_setup):
    tracker = HostTracker(name=u'host')
    return tracker.make_fixture(request)


class TestNonexistentHostGroup(XMLRPC_test):
    def test_retrieve_nonexistent(self, hostgroup):
        """ Try to retrieve non-existent hostgroup """
        hostgroup.ensure_missing()
        command = hostgroup.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: host group not found' % hostgroup.cn)):
            command()

    def test_update_nonexistent(self, hostgroup):
        """ Try to update non-existent hostgroup """
        hostgroup.ensure_missing()
        command = hostgroup.make_update_command(
            dict(description=u'Updated hostgroup 1')
        )
        with raises_exact(errors.NotFound(
                reason=u'%s: host group not found' % hostgroup.cn)):
            command()

    def test_delete_nonexistent(self, hostgroup):
        """ Try to delete non-existent hostgroup """
        hostgroup.ensure_missing()
        command = hostgroup.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: host group not found' % hostgroup.cn)):
            command()


class TestHostGroup(XMLRPC_test):
    def test_invalid_name(self, hostgroup_invalid):
        """ Test an invalid hostgroup name """
        hostgroup_invalid.ensure_missing()
        command = hostgroup_invalid.make_create_command()
        with raises_exact(errors.ValidationError(
                name='hostgroup_name',
                error=u'may only include letters, numbers, _, -, and .')):
            command()

    def test_create_hostgroup(self, hostgroup):
        """ Create hostgroup """
        hostgroup.create()

    def test_create_duplicate_hostgroup(self, hostgroup):
        """ Try to create duplicate hostgroup """
        hostgroup.ensure_exists()
        command = hostgroup.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message=u'host group with name "%s" already exists' %
                hostgroup.cn)):
            command()

    def test_create_host_add_to_hostgroup(self, hostgroup, host):
        """ Check that host can be added to hostgroup """
        host.create()
        hostgroup.add_member(dict(host=host.fqdn))
        hostgroup.retrieve()

    def test_search_for_hostgroup(self, hostgroup):
        """ Search for hostgroup """
        hostgroup.ensure_exists()
        hostgroup.find()

    def test_search_for_hostgroup_with_all(self, hostgroup):
        """ Search for hostgroup """
        hostgroup.ensure_exists()
        hostgroup.find(all=True)

    def test_update_hostgroup(self, hostgroup):
        """ Update description of hostgroup and verify """
        hostgroup.ensure_exists()
        hostgroup.update(dict(description=u'Updated hostgroup 1'))
        hostgroup.retrieve()

    def test_remove_host_from_hostgroup(self, hostgroup, host):
        """ Remove host from hostgroup """
        hostgroup.ensure_exists()
        hostgroup.remove_member(dict(host=host.fqdn))

    def test_delete_hostgroup(self, hostgroup):
        """ Delete hostgroup """
        hostgroup.ensure_exists()
        hostgroup.delete()

    def test_one_letter_hostgroup(self, hostgroup_single):
        """ Create hostgroup with name containing only one letter """
        hostgroup_single.create()
        hostgroup_single.delete()
