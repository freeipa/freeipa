#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

import json
import os
import pytest

from ipalib import api

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_ipaserver.httptest import Unauthorized_HTTP_test
from ipatests.util import (assert_equal, assert_deepequal, raises,
                           assert_not_equal)

from ipapython.version import API_VERSION
from ipaserver.plugins.internal import i18n_messages


@pytest.mark.tier1
class test_i18n_messages(XMLRPC_test, Unauthorized_HTTP_test):
    """
    Tests for i18n_messages end point
    """
    app_uri = '/ipa/i18n_messages'
    content_type = 'application/json'

    def _prepare_data(self, method):
        """
        Construct json data required for request
        """
        return {"method": "{0}".format(method),
                "params": [[], {"version": "{0}".format(API_VERSION)}]}

    def _prepare_accept_lang(self):
        try:
            return os.environ['LANGUAGE']
        except KeyError:
            pass

        try:
            return os.environ['LANG'].split('.')[0].replace('_', '-')
        except KeyError:
            return ''

    def _fetch_i18n_msgs(self):
        """
        Build translations directly via command instance
        """
        return i18n_messages({}).execute()

    def _fetch_i18n_msgs_http(self, accept_lang):
        """
        Fetch translations via http request
        """
        self.accept_language = accept_lang
        params = json.dumps(self._prepare_data('i18n_messages'))
        response = self.send_request(params=params)

        assert_equal(response.status, 200)
        response_data = response.read()
        jsondata = json.loads(response_data)
        assert_equal(jsondata['error'], None)
        assert jsondata['result']
        assert jsondata['result']['texts']

        return jsondata['result']

    def test_only_i18n_serves(self):
        """
        Test if end point doesn't fulfill other RPC commands
        """
        assert api.Command.get('user_find')
        params = json.dumps(self._prepare_data('user_find/1'))
        response = self.send_request(params=params)

        assert_equal(response.status, 403)
        assert_equal(response.reason, 'Forbidden')

        response_data = response.read()
        assert_equal(response_data, b'Invalid RPC command')
        raises(ValueError, json.loads, response_data)

    def test_only_post_serves(self):
        """
        Test if end point fulfills only POST method
        """
        params = json.dumps(self._prepare_data('i18n_messages'))
        response = self.send_request(method='GET', params=params)

        assert_equal(response.status, 405)
        assert_equal(response.reason, 'Method Not Allowed')
        assert response.msg
        assert_equal(response.msg['allow'], 'POST')

        response_data = response.read()
        raises(ValueError, json.loads, response_data)

    def test_i18n_receive(self):
        """
        Test if translations request is successful
        """
        expected_msgs = self._fetch_i18n_msgs()
        actual_msgs = self._fetch_i18n_msgs_http(self._prepare_accept_lang())

        assert_deepequal(expected_msgs, actual_msgs)

    def test_i18n_consequence_receive(self):
        """
        Test if consequence translations requests for different languages are
        successful. Every request's result have to contain messages in it's
        locale.
        """
        prev_i18n_msgs = self._fetch_i18n_msgs_http('en-us')
        cur_i18n_msgs = self._fetch_i18n_msgs_http('fr-fr')
        try:
            assert_equal(prev_i18n_msgs['texts']['true'], u'True')
            assert_equal(cur_i18n_msgs['texts']['true'], u'Vrai')
        except KeyError:
            assert_not_equal(prev_i18n_msgs, cur_i18n_msgs)
