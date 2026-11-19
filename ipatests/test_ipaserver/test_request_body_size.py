#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Tests for MAX_REQUEST_BODY_SIZE enforcement on unauthenticated endpoints.
"""

import pytest

from ipatests.test_ipaserver.httptest import Unauthorized_HTTP_test
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.util import assert_equal
from ipaserver.rpcserver import MAX_REQUEST_BODY_SIZE


@pytest.mark.tier1
class test_session_request_body_size(XMLRPC_test, Unauthorized_HTTP_test):
    """
    Unauthenticated session endpoints must reject oversized bodies with 413
    before credential validation (CVE-2026-86593).
    """

    content_type = 'application/x-www-form-urlencoded'

    @pytest.mark.parametrize('app_uri', [
        '/ipa/session/login_password',
        '/ipa/session/change_password',
        '/ipa/session/sync_token',
    ])
    def test_oversized_body_returns_413(self, app_uri):
        self.app_uri = app_uri
        # urlencode adds 'x=' (2 bytes); value sized for body length
        # MAX_REQUEST_BODY_SIZE + 1
        response = self.send_request(
            params={'x': 'x' * (MAX_REQUEST_BODY_SIZE - 1)}
        )
        assert_equal(response.status, 413)
        assert_equal(response.reason, 'Request Entity Too Large')

    @pytest.mark.parametrize('app_uri', [
        '/ipa/session/login_password',
        '/ipa/session/change_password',
        '/ipa/session/sync_token',
    ])
    def test_max_size_body_not_413(self, app_uri):
        """
        A body of exactly MAX_REQUEST_BODY_SIZE must not be rejected as 413.
        Further validation may still return 400 for invalid form fields.
        """
        self.app_uri = app_uri
        # urlencode adds 'x=' (2 bytes); value sized for body length
        # MAX_REQUEST_BODY_SIZE
        response = self.send_request(
            params={'x': 'x' * (MAX_REQUEST_BODY_SIZE - 2)}
        )
        assert response.status != 413

    @pytest.mark.parametrize('app_uri', [
        '/ipa/session/login_password',
        '/ipa/session/change_password',
        '/ipa/session/sync_token',
    ])
    @pytest.mark.parametrize('content_length', [
        '-1',
        'not-a-number',
        '',
    ])
    def test_invalid_content_length_returns_400(
            self, app_uri, content_length):
        """
        Negative or nonsense Content-Length must return 400, not 413.
        """
        self.app_uri = app_uri
        response = self.send_request(
            params={'x': 'x'},
            headers={'Content-Length': content_length},
        )
        assert_equal(response.status, 400)
        assert_equal(response.reason, 'Bad Request')
