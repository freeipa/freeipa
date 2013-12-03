# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2014  Red Hat
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
Base class for all REST tests
"""

import requests
import json
import nose
from ipatests.util import assert_deepequal, Fuzzy
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_uuid, fuzzy_password

FQDN = 'localhost'
PORT = 8090

EXPECTED = """Expected %r to raise %s.
  options = %r
  output = %r"""

UNEXPECTED = """Expected %r to raise %s, but caught different.
  options = %r
  %s: %s"""

try:
    response = requests.get(
        'http://%s:%d/ipa/smartproxy/host/host.example.com' % (FQDN, PORT),
        data={})
    server_available = True
except requests.ConnectionError:
    server_available = False


class REST_test(object):
    """
    Base class for all REST tests

    A Declarative test suite is controlled by the ``tests`` and
    ``cleanup`` class variables.

    The ``tests`` is a list of dictionaries with the following keys:

    ``desc``
        A name/description of the test
    ``command``
        A (command, args, kwargs) triple specifying the command to run
    ``expected``
        Can be either an ``errors.PublicError`` instance, in which case
        the command must fail with the given error; or the
        expected result.
        The result is checked with ``tests.util.assert_deepequal``.
    ``extra_check`` (optional)
        A checking function that is called with the response. It must
        return true for the test to pass.

    The ``cleanup`` is a list of (command, args, kwargs)
    triples. These are commands get run both before and after tests,
    and must not fail.
    """

    cleanup = tuple()
    tests = tuple()

    @classmethod
    def setUpClass(cls):
        if not server_available:
            raise nose.SkipTest('%r: Server not available' %
                                cls.__module__)

    def cleanup_generate(self, stage):
        for (i, request) in enumerate(self.cleanup):
            func = lambda: self.run_cleanup(request)
            func.description = '%s %s-cleanup[%d]: %r' % (
                self.__class__.__name__, stage, i, request
            )
            yield (func,)

    def make_request(self, method, uri, data=None):
        request = method('http://%s:%d%s' % (FQDN, PORT, uri), data=data)
        return request

    def run_cleanup(self, request):
        (uri, data) = request
        try:
            result = self.make_request(requests.delete, uri, data)
            assert request.status_code in [401, 201, 200]
        except Exception:
            pass

    def test_generator(self):
        """
        Iterate through tests.

        nose reports each one as a separate test.
        """

        # Iterate through pre-cleanup:
        for tup in self.cleanup_generate('pre'):
            yield tup

        # Iterate through the tests:
        name = self.__class__.__name__
        for (i, test) in enumerate(self.tests):
            nice = '%s[%d]: %s: %s' % (
                name, i, test['request'][0], test.get('desc', '')
            )
            func = lambda: self.check(nice, **test)
            func.description = nice
            yield (func,)

        # Iterate through post-cleanup:
        for tup in self.cleanup_generate('post'):
            yield tup

    def check(self, nice, desc, request, method, expected_status, expected):
        (uri, data) = request
        if isinstance(expected, Exception):
            self.check_exception(nice, method, uri, data, expected)
        else:
            self.check_result(nice,
                              method,
                              uri,
                              data,
                              expected_status,
                              expected)

    def check_exception(self, nice, method, uri, data, expected):
        klass = expected.__class__
        name = klass.__name__
        try:
            output = self.make_request(method, uri, data)
        except StandardError, e:
            pass
        else:
            raise AssertionError(
                EXPECTED % (uri, name, method, data, output)
            )
        if not isinstance(e, klass):
            raise AssertionError(
                UNEXPECTED % (uri, name, method, data, e.__class__.__name__, e)
            )

    def check_result(self, nice, method, uri, data, expected_status, expected):
        request = self.make_request(method, uri, data)
        assert expected_status == request.status_code

        if request.status_code in [200, 201]:
            try:
                data = json.loads(request.text)
            except ValueError, e:
                raise AssertionError(
                    'Could not parse JSON: %s' % e
                )
            assert_deepequal(expected, data, nice)
