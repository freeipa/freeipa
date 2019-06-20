#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

import pytest

from ipatests.test_ipaserver.httptest import Unauthorized_HTTP_test
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.util import assert_equal
from ipalib import api, errors

testuser = u'tuser'
password = u'password'


@pytest.mark.tier1
class test_migratepw(XMLRPC_test, Unauthorized_HTTP_test):
    """
    Test password migrate end point
    """
    app_uri = '/ipa/migration/migration.py'

    @pytest.fixture(autouse=True)
    def migratepw_setup(self, request):
        """
        Prepare for tests
        """
        api.Command['user_add'](uid=testuser, givenname=u'Test', sn=u'User')
        api.Command['passwd'](testuser, password=password)

        def fin():
            try:
                api.Command['user_del']([testuser])
            except errors.NotFound:
                pass

        request.addfinalizer(fin)

    def _migratepw(self, user, password, method='POST'):
        """
        Make password migrate request to server
        """
        return self.send_request(method, params={'username': str(user),
                                                 'password': str(password)},
                                 )

    def test_bad_params(self):
        """
        Test against bad (missing, empty) params
        """
        for params in (None,                     # no params
                       {'username': 'foo'},       # missing password
                       {'password': 'bar'},       # missing username
                       {'username': '',
                        'password': ''},         # empty options
                       {'username': '',
                        'password': 'bar'},      # empty username
                       {'username': 'foo',
                        'password': ''},         # empty password
                       ):
            response = self.send_request(params=params)
            assert_equal(response.status, 400)
            assert_equal(response.reason, 'Bad Request')

    def test_not_post_method(self):
        """
        Test redirection of non POST request
        """
        response = self._migratepw(testuser, password, method='GET')

        assert_equal(response.status, 302)
        assert response.msg
        assert_equal(response.msg['Location'], 'index.html')

    def test_invalid_password(self):
        """
        Test invalid password
        """
        response = self._migratepw(testuser, 'wrongpassword')

        assert_equal(response.status, 200)
        assert_equal(response.getheader('X-IPA-Migrate-Result'),
                     'invalid-password')

    def test_migration_success(self):
        """
        Test successful migration scenario
        """
        response = self._migratepw(testuser, password)

        assert_equal(response.status, 200)
        assert_equal(response.getheader('X-IPA-Migrate-Result'), 'ok')
