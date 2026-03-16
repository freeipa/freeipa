# Authors:
#   Pranav Thube <pthube@redhat.com>
#
# Copyright (C) 2026  Red Hat
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
Test the i18n (internationalization) support for user plugin.

This module tests that IPA correctly handles international characters
in user attributes such as first name (givenname) and last name (sn).
"""

import pytest

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker


# Test data Users with i18n names
I18N_USERS = {
    'user1': {
        'name': 'i18nuser1',
        'givenname': 'Çándide',
        'sn': 'Rùiz',
    },
    'user2': {
        'name': 'i18nuser2',
        'givenname': 'Rôséñe',
        'sn': 'zackr',
    },
    'user3': {
        'name': 'i18nuser3',
        'givenname': 'Älka',
        'sn': 'Màrzella',
    },
    'user4': {
        'name': 'i18nuser4',
        'givenname': 'Feâtlëss',
        'sn': 'Watérmân',
    },
}

# CNS test data - Swedish/European last names
CNS_LASTNAMES = [
    'Oskar',
    'Anders',
    'Örjan',
    'Jonas',
    'Ulf',
    'Äke',
    'Bertold',
    'Bruno',
    'Didier',
    'Éric',
    'Jean-Luc',
    'Laurent',
    'Têko',
]

# European names with mixed accents for firstname tests
EUROPEAN_FIRSTNAMES = [
    'Rôséñel',
    'Tàrqùinio',
    'PASSWÖRD',
    'Nomeuropéen',
    # Names with special characters (apostrophe, space)
    "O'Brian",
    'Maria José',
]

# Firstname test data - Single characters including accented
# 73 characters total: 26 ASCII A-Z + 47 accented/special characters
FIRSTNAME_SINGLE_CHARS = [
    # ASCII uppercase letters A-Z (26 characters)
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',
    # Extended Latin uppercase characters (20 characters)
    'À', 'Á', 'Â', 'Ä', 'Ç', 'È', 'É', 'Ê', 'Ë',
    'Í', 'Î', 'Ï', 'Ñ', 'Ó', 'Ô', 'Ö', 'Ù', 'Ú', 'Û', 'Ü',
    # German eszett (1 character)
    'ß',
    # Extended Latin lowercase characters (20 characters)
    'à', 'á', 'â', 'ä', 'ç', 'è', 'é', 'ê', 'ë',
    'í', 'î', 'ï', 'ñ', 'ó', 'ô', 'ö', 'ù', 'ú', 'û', 'ü',
    # Nordic characters (4 characters)
    'Ø', 'ø', 'Å', 'å',
    # Polish character (2 characters)
    'Ł', 'ł',
]


@pytest.fixture(scope='class')
def i18n_users(request, xmlrpc_setup):
    """Single fixture providing all i18n test users as a dictionary"""
    users = {}
    for user_key, user_data in I18N_USERS.items():
        tracker = UserTracker(
            name=user_data['name'],
            givenname=user_data['givenname'],
            sn=user_data['sn']
        )
        users[user_key] = tracker.make_fixture(request)
    return users


@pytest.mark.tier1
class TestI18nUser(XMLRPC_test):
    """
    Test i18n (internationalization) support for user plugin.

    Tests that IPA correctly handles international characters in user
    attributes such as first name (givenname) and last name (sn).
    """

    ##########################################################################
    # User Creation Tests
    ##########################################################################

    @pytest.mark.parametrize('user_key', I18N_USERS.keys())
    def test_add_i18n_user(self, i18n_users, user_key):
        """Adding i18n user"""
        i18n_users[user_key].create()

    @pytest.mark.parametrize('user_key', I18N_USERS.keys())
    def test_verify_i18n_user(self, i18n_users, user_key):
        """Verify i18n user has correct full name"""
        user = i18n_users[user_key]
        user.ensure_exists()
        command = user.make_find_command(uid=user.uid, all=True)
        result = command()
        assert result['count'] == 1
        entry = result['result'][0]
        assert I18N_USERS[user_key]['givenname'] in entry['givenname']
        assert I18N_USERS[user_key]['sn'] in entry['sn']

    ##########################################################################
    # CNS Tests - Lastname modification with Swedish/European names
    ##########################################################################

    @pytest.mark.parametrize('lastname', CNS_LASTNAMES)
    def test_cns_modify_lastname(self, i18n_users, lastname):
        """Modify lastname to Swedish/European name"""
        user = i18n_users['user1']
        user.ensure_exists()
        user.update(dict(sn=lastname))

    ##########################################################################
    # European accented firstname tests
    ##########################################################################

    @pytest.mark.parametrize('firstname', EUROPEAN_FIRSTNAMES)
    def test_european_modify_firstname(self, i18n_users, firstname):
        """Modify firstname to European accented name"""
        user = i18n_users['user2']
        user.ensure_exists()
        user.update(dict(givenname=firstname))

    ##########################################################################
    # Firstname Tests - Single character modification
    ##########################################################################

    @pytest.mark.parametrize('char', FIRSTNAME_SINGLE_CHARS)
    def test_firstname_modify_single_char(self, i18n_users, char):
        """Modify firstname to single character"""
        user = i18n_users['user3']
        user.ensure_exists()
        user.update(dict(givenname=char))
