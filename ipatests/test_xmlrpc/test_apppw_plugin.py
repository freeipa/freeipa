# Authors:
#   Richard Kalinec <rkalinec@gmail.com>
#
# Copyright (C) 2020  Red Hat
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
Test the `ipaserver/plugins/apppw.py` module.
"""
import pytest

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import (
    XMLRPC_test, fuzzy_password, raises_exact)

from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.tracker.apppw_plugin import ApppwTracker

invalidapppw1 = u'100'
invalidapppw2 = u'c13'
invalidapppw3 = u'B6'


@pytest.fixture(scope='class')
def apppw(request, xmlrpc_setup):
    tracker = ApppwTracker(uid=u'1',
                           description='My eMail app password for tablet',
                           appname='eMail')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def apppw2(request, xmlrpc_setup):
    tracker = ApppwTracker(uid=u'2',
                           description='My Slack app password for smartphone',
                           appname='Slack')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestNonexistentApppw(XMLRPC_test):
    def test_retrieve_nonexistent(self, apppw):
        """ Try to retrieve a non-existent app password """
        apppw.ensure_missing()
        command = apppw.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: app password not found' % apppw.uid)):
            command()

    def test_delete_nonexistent(self, apppw):
        """ Try to delete a non-existent app password """
        apppw.ensure_missing()
        command = apppw.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: app password not found' % apppw.uid)):
            command()


@pytest.mark.tier1
class TestApppw(XMLRPC_test):
    def test_retrieve(self, apppw):
        """ Create app password and try to retrieve it """
        apppw.ensure_exists()
        apppw.retrieve()

    def test_delete(self, apppw):
        """ Delete app password """
        apppw.delete()


@pytest.mark.tier1
class TestFind(XMLRPC_test):
    def test_find(self, apppw):
        """ Basic check of apppw-find """
        apppw.ensure_exists()
        apppw.find()

    def test_find_with_all(self, apppw):
        """ Basic check of apppw-find with --all """
        apppw.ensure_exists()
        apppw.find(all=True)

    def test_find_with_pkey_only(self, apppw):
        """ Basic check of apppw-find with primary keys only """
        apppw.ensure_exists()
        command = apppw.make_find_command(
            uid=apppw.uid, pkey_only=True
        )
        result = command()
        apppw.check_find(result, pkey_only=True)

    def test_find_nomatch(self, apppw):
        """ Basic check of apppw-find """
        apppw.ensure_missing()
        command = apppw.make_find_command(uid=apppw.uid)
        result = command()
        apppw.check_find_nomatch(result)


@pytest.mark.tier1
class TestCreate(XMLRPC_test):
    def test_create_apppw(self, apppw):
        """ Create app password """
        apppw.ensure_missing()
        command = apppw.make_create_command()
        command()

    def test_create_apppw2(self, apppw2):
        """ Create another app password """
        apppw2.ensure_missing()
        command = apppw2.make_create_command()
        command()

    def test_create_with_random_passwd(self):
        """ Create user with random password """
        testapppw = ApppwTracker(uid=u'3',
                                 description='My Gmail app password for tablet',
                                 appname='Gmail')
        testapppw.track_create()
        testapppw.attrs.update(
            randompassword=fuzzy_password,
            has_password=True,
        )
        command = testapppw.make_create_command()
        result = command()
        testapppw.check_create(result)
        testapppw.delete()

    def test_create_with_too_high_uid(self, request, xmlrpc_setup):
        testapppw = ApppwTracker(uid=invalidapppw1,
                                 description=('My Facebook app password '
                                              'for laptop'),
                                 appname='Facebook')
        command = testapppw.make_create_command()
        with raises_exact(errors.ValidationError(
                name=u'uid',
                error=u'can be a number from 0 to 99')):
            command()

    def test_create_with_too_long_uid_with_lowercase(self, request,
                                                     xmlrpc_setup):
        testapppw = ApppwTracker(uid=invalidapppw2,
                                 description='My IS app password for home PC',
                                 appname='IS')
        command = testapppw.make_create_command()
        with raises_exact(errors.ValidationError(
                name=u'uid',
                error=u'can be a number from 0 to 99')):
            command()

    def test_create_with_uid_with_uppercase(self, request, xmlrpc_setup):
        testapppw = ApppwTracker(uid=invalidapppw3,
                                 description='My IS app password for laptop',
                                 appname='IS')
        command = testapppw.make_create_command()
        with raises_exact(errors.ValidationError(
                name=u'uid',
                error=u'can be a number from 0 to 99')):
            command()

    def test_create_with_appname_with_dots(self, request, xmlrpc_setup):
        testapppw = ApppwTracker(uid=u'26',
                                 description='My special app password',
                                 appname='service.company.com')
        command = testapppw.make_create_command()
        with raises_exact(errors.ValidationError(
                name=u'appname',
                error=u'may only include letters, numbers, _, - and $')):
            command()


@pytest.mark.tier1
class TestValidation(XMLRPC_test):
    # The assumption for this class of tests is that if we don't
    # get a validation error then the request was processed normally.

    def test_validation_disabled_on_deletes(self):
        """ Test that validation is disabled on app password deletes """
        tracker = Tracker()
        command = tracker.make_command('apppw_del', invalidapppw2)
        with raises_exact(errors.NotFound(
                reason=u'%s: app password not found' % invalidapppw2)):
            command()

    def test_validation_disabled_on_show(self):
        """ Test that validation is disabled on app password retrieves """
        tracker = Tracker()
        command = tracker.make_command('apppw_show', invalidapppw2)
        with raises_exact(errors.NotFound(
                reason=u'%s: app password not found' % invalidapppw2)):
            command()

    def test_validation_disabled_on_find(self, apppw):
        """ Test that validation is disabled on app password searches """
        result = apppw.run_command('apppw_find', invalidapppw2)
        apppw.check_find_nomatch(result)
