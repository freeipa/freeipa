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
class test_login_password(XMLRPC_test, Unauthorized_HTTP_test):
    app_uri = '/ipa/session/login_password'

    @pytest.fixture(autouse=True)
    def login_setup(self, request):
        ccache = os.path.join('/tmp', str(uuid.uuid4()))
        try:
            api.Command['user_add'](uid=testuser, givenname=u'Test', sn=u'User')
            api.Command['passwd'](testuser, password=password)
            run(['kinit', testuser], stdin='{0}\n{0}\n{0}\n'.format(password),
                env={"KRB5CCNAME": ccache})
        except errors.ExecutionError as e:
            pytest.skip(
                'Cannot set up test user: %s' % e
            )

        def fin():
            try:
                api.Command['user_del']([testuser])
            except errors.NotFound:
                pass
            os.unlink(ccache)

        request.addfinalizer(fin)

    def _login(self, user, password, host=None):
        return self.send_request(params={'user': str(user),
                                 'password' : str(password)},
                                 host=host)

    def test_bad_options(self):
        for params in (
            None,                             # no params
            {"user": "foo"},                  # missing options
            {"user": "foo", "password": ""},  # empty option
        ):
            response = self.send_request(params=params)
            assert_equal(response.status, 400)
            assert_equal(response.reason, 'Bad Request')

    def test_invalid_auth(self):
        response = self._login(testuser, 'wrongpassword')

        assert_equal(response.status, 401)
        assert_equal(response.getheader('X-IPA-Rejection-Reason'),
                     'invalid-password')

    def test_invalid_referer(self):
        response = self._login(testuser, password, 'attacker.test')

        assert_equal(response.status, 400)

    def test_success(self):
        response = self._login(testuser, password)

        assert_equal(response.status, 200)
        assert response.getheader('X-IPA-Rejection-Reason') is None
