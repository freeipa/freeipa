# Copyright (C) 2020  FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import os
import pytest

from ipatests.test_ipaserver.httptest import Unauthorized_HTTP_test
from ipatests.util import assert_equal, assert_not_equal
from ipaplatform.paths import paths


@pytest.mark.tier1
class test_jsplugins(Unauthorized_HTTP_test):
    app_uri = '/ipa/ui/js/freeipa/plugins.js'
    jsplugins = (('foo', 'foo.js'), ('bar', ''))
    content_type = 'application/javascript'

    def test_jsplugins(self):
        empty_response = u"define([],function(){return[];});"

        # Step 1: make sure default response has no additional plugins
        response = self.send_request(method='GET')
        assert_equal(response.status, 200)
        response_data = response.read().decode(encoding='utf-8')
        assert_equal(response_data, empty_response)

        # Step 2: add fake plugins
        try:
            for (d, f) in self.jsplugins:
                dir = os.path.join(paths.IPA_JS_PLUGINS_DIR, d)
                if not os.path.exists(dir):
                    os.mkdir(dir, 0o755)
                if f:
                    with open(os.path.join(dir, f), 'w') as js:
                        js.write("/* test js plugin */")

        except OSError as e:
            pytest.skip(
                'Cannot set up test JS plugin: %s' % e
            )

        # Step 3: query plugins to see if our plugins exist
        response = self.send_request(method='GET')
        assert_equal(response.status, 200)
        response_data = response.read().decode(encoding='utf-8')
        assert_not_equal(response_data, empty_response)
        for (d, f) in self.jsplugins:
            if f:
                assert "'" + d + "'" in response_data
            else:
                assert "'" + d + "'" not in response_data

        # Step 4: remove fake plugins
        try:
            for (d, f) in self.jsplugins:
                dir = os.path.join(paths.IPA_JS_PLUGINS_DIR, d)
                file = os.path.join(dir, f)
                if f and os.path.exists(file):
                    os.unlink(file)
                if os.path.exists(dir):
                    os.rmdir(dir)
        except OSError:
            pass

        # Step 5: make sure default response has no additional plugins
        response = self.send_request(method='GET')
        assert_equal(response.status, 200)
        response_data = response.read().decode(encoding='utf-8')
        assert_equal(response_data, empty_response)
