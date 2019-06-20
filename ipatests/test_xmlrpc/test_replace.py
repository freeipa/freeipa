# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Filip Skola <fskola@redhat.com>
#
# Copyright (C) 2011  Red Hat
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
Test the modlist replace logic. Some attributes require a MOD_REPLACE
while others are fine using ADD/DELETE.

Note that member management in other tests also exercises the
gen_modlist code.
"""


from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
import pytest


@pytest.fixture(scope='class')
def user(request, xmlrpc_setup):
    tracker = UserTracker(
        name=u'user1', givenname=u'Test', sn=u'User1',
        mail=[u'test1@example.com', u'test2@example.com']
    )
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestReplace(XMLRPC_test):
    def test_create(self, user):
        """ Create a user account with two mail addresses """
        user.create()

    def test_drop_one_add_another_mail(self, user):
        """ Drop one mail address and add another to the user """
        updates = {'mail': [u'test1@example.com', u'test3@example.com']}
        user.update(updates, updates)

    def test_set_new_single_mail(self, user):
        """ Reset mail attribute to one single value """
        updates = {'mail': u'test4@example.com'}
        user.update(updates)

    def test_set_three_new_mails(self, user):
        """ Assign three new mail addresses to the user """
        updates = {'mail': [
            u'test5@example.com', u'test6@example.com', u'test7@example.com'
        ]}
        user.update(updates, updates)

    def test_remove_all_mails(self, user):
        """ Remove all email addresses from the user """
        updates = {'mail': u''}
        user.update(updates)

    def test_replace_initials(self, user):
        """ Test single value attribute by replacing initials """
        updates = {'initials': u'ABC'}
        user.update(updates)

    def test_drop_initials(self, user):
        """ Test drop of single value attribute by dropping initials """
        updates = {'initials': u''}
        user.update(updates)
