# Copyright (C) 2023  Red Hat
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

import os
import pytest
import uuid

from ipatests.test_ipaserver.httptest import Unauthorized_HTTP_test
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.util import assert_equal
from ipalib import api, errors
from ipapython.ipautil import run

testuser = u'tuser'
password = u'password'


@pytest.mark.tier1
class test_referer(XMLRPC_test, Unauthorized_HTTP_test):

    @pytest.fixture(autouse=True)
    def login_setup(self, request):
        ccache = os.path.join('/tmp', str(uuid.uuid4()))
        tokenid = None
        try:
            api.Command['user_add'](uid=testuser, givenname=u'Test', sn=u'User')
            api.Command['passwd'](testuser, password=password)
            run(['kinit', testuser], stdin='{0}\n{0}\n{0}\n'.format(password),
                env={"KRB5CCNAME": ccache})
            result = api.Command["otptoken_add"](
                type='HOTP', description='testotp',
                ipatokenotpalgorithm='sha512', ipatokenowner=testuser,
                ipatokenotpdigits='6')
            tokenid = result['result']['ipatokenuniqueid'][0]
        except errors.ExecutionError as e:
            pytest.skip(
                'Cannot set up test user: %s' % e
            )

        def fin():
            try:
                api.Command['user_del']([testuser])
                api.Command['otptoken_del']([tokenid])
            except errors.NotFound:
                pass
            os.unlink(ccache)

        request.addfinalizer(fin)

    def _request(self, params={}, host=None):
        # implicit is that self.app_uri is set to the appropriate value
        return self.send_request(params=params, host=host)

    def test_login_password_valid(self):
        """Valid authentication of a user"""
        self.app_uri = "/ipa/session/login_password"
        response = self._request(
            params={'user': 'tuser', 'password': password})
        assert_equal(response.status, 200, self.app_uri)

    def test_change_password_valid(self):
        """This actually changes the user password"""
        self.app_uri = "/ipa/session/change_password"
        response = self._request(
            params={'user': 'tuser',
                    'old_password': password,
                    'new_password': 'new_password'}
        )
        assert_equal(response.status, 200, self.app_uri)

    def test_sync_token_valid(self):
        """We aren't testing that sync works, just that we can get there"""
        self.app_uri = "/ipa/session/sync_token"
        response = self._request(
            params={'user': 'tuser',
                    'first_code': '1234',
                    'second_code': '5678',
                    'password': 'password'})
        assert_equal(response.status, 200, self.app_uri)

    def test_i18n_messages_valid(self):
        # i18n_messages requires a valid JSON request and we send
        # nothing. If we get a 500 error then it got past the
        # referer check.
        self.app_uri = "/ipa/i18n_messages"
        response = self._request()
        assert_equal(response.status, 500, self.app_uri)

    # /ipa/session/login_x509 is not tested yet as it requires
    # significant additional setup.
    # This can be manually verified by adding
    # Satisfy Any and Require all granted to the configuration
    # section and comment out all Auth directives. The request
    # will fail and log that there is no KRB5CCNAME which comes
    # after the referer check.

    def test_endpoints_auth_required(self):
        """Test endpoints that require pre-authorization which will
           fail before we even get to the Referer check
        """
        self.endpoints = {
            "/ipa/xml",
            "/ipa/session/login_kerberos",
            "/ipa/session/json",
            "/ipa/session/xml"
        }
        for self.app_uri in self.endpoints:
            response = self._request(host="attacker.test")

            # referer is checked after auth
            assert_equal(response.status, 401, self.app_uri)

    def notest_endpoints_invalid(self):
        """Pass in a bad Referer, expect a 400 Bad Request"""
        self.endpoints = {
            "/ipa/session/login_password",
            "/ipa/session/change_password",
            "/ipa/session/sync_token",
        }
        for self.app_uri in self.endpoints:
            response = self._request(host="attacker.test")

            assert_equal(response.status, 400, self.app_uri)
