# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Base class for all XML-RPC tests
"""

import sys
import socket
import nose
from tests.util import assert_deepequal, Fuzzy
from ipalib import api, request
from ipalib import errors
from ipalib.x509 import valid_issuer


# Matches a gidnumber like '1391016742'
# FIXME: Does it make more sense to return gidnumber, uidnumber, etc. as `int`
# or `long`?  If not, we still need to return them as `unicode` instead of `str`.
fuzzy_digits = Fuzzy('^\d+$', type=basestring)

# Matches an ipauniqueid like u'784d85fd-eae7-11de-9d01-54520012478b'
fuzzy_uuid = Fuzzy(
    '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
)

# Matches netgroup dn. Note (?i) at the beginning of the regexp is the ingnore case flag
fuzzy_netgroupdn = Fuzzy(
    '(?i)ipauniqueid=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12},cn=ng,cn=alt,%s' % api.env.basedn
)

# Matches a hash signature, not enforcing length
fuzzy_hash = Fuzzy('^([a-f0-9][a-f0-9]:)+[a-f0-9][a-f0-9]$', type=basestring)

# Matches a date, like Tue Apr 26 17:45:35 2016 UTC
fuzzy_date = Fuzzy('^[a-zA-Z]{3} [a-zA-Z]{3} \d{2} \d{2}:\d{2}:\d{2} \d{4} UTC$')

fuzzy_issuer = Fuzzy(type=basestring, test=lambda issuer: valid_issuer(issuer))

fuzzy_hex = Fuzzy('^0x[0-9a-fA-F]+$', type=basestring)

# Matches password - password consists of all printable characters without whitespaces
# The only exception is space, but space cannot be at the beggingin or end of the pwd
fuzzy_password = Fuzzy('^\S([\S ]*\S)*$')

# Matches generalized time value. Time format is: %Y%m%d%H%M%SZ
fuzzy_dergeneralizedtime = Fuzzy('^[0-9]{14}Z$')

# match any string
fuzzy_string = Fuzzy(type=basestring)

try:
    if not api.Backend.xmlclient.isconnected():
        api.Backend.xmlclient.connect(fallback=False)
    res = api.Command['user_show'](u'notfound')
except errors.NetworkError:
    server_available = False
except IOError:
    server_available = False
except errors.NotFound:
    server_available = True



def assert_attr_equal(entry, key, value):
    if type(entry) is not dict:
        raise AssertionError(
            'assert_attr_equal: entry must be a %r; got a %r: %r' % (
                dict, type(entry), entry)
        )
    if key not in entry:
        raise AssertionError(
            'assert_attr_equal: entry has no key %r: %r' % (key, entry)
        )
    if value not in entry[key]:
        raise AssertionError(
            'assert_attr_equal: %r: %r not in %r' % (key, value, entry[key])
        )


def assert_is_member(entry, value, key='member'):
    if type(entry) is not dict:
        raise AssertionError(
            'assert_is_member: entry must be a %r; got a %r: %r' % (
                dict, type(entry), entry)
        )
    if key not in entry:
        raise AssertionError(
            'assert_is_member: entry has no key %r: %r' % (key, entry)
        )
    for member in entry[key]:
        if member.startswith(value):
            return
    raise AssertionError(
        'assert_is_member: %r: %r not in %r' % (key, value, entry[key])
    )


# Initialize the API. We do this here so that one can run the tests
# individually instead of at the top-level. If API.bootstrap()
# has already been called we continue gracefully. Other errors will be
# raised.

class XMLRPC_test(object):
    """
    Base class for all XML-RPC plugin tests
    """

    @classmethod
    def setUpClass(cls):
        if not server_available:
            raise nose.SkipTest('%r: Server not available: %r' %
                                (cls.__module__, api.env.xmlrpc_uri))

    def setUp(self):
        if not api.Backend.xmlclient.isconnected():
            api.Backend.xmlclient.connect(fallback=False)

    def tearDown(self):
        """
        nose tear-down fixture.
        """
        request.destroy_context()

    def failsafe_add(self, obj, pk, **options):
        """
        Delete possible leftover entry first, then add.

        This helps speed us up when a partial test failure has left LDAP in a
        dirty state.

        :param obj: An Object like api.Object.user
        :param pk: The primary key of the entry to be created
        :param options: Kwargs to be passed to obj.add()
        """
        try:
            obj.methods['del'](pk)
        except errors.NotFound:
            pass
        return obj.methods['add'](pk, **options)


IGNORE = """Command %r is missing attribute %r in output entry.
  args = %r
  options = %r
  entry = %r"""


EXPECTED = """Expected %r to raise %s.
  args = %r
  options = %r
  output = %r"""


UNEXPECTED = """Expected %r to raise %s, but caught different.
  args = %r
  options = %r
  %s: %s"""


KWARGS = """Command %r raised %s with wrong kwargs.
  args = %r
  options = %r
  kw_expected = %r
  kw_got = %r"""


class Declarative(XMLRPC_test):
    """A declarative-style test suite

    A Declarative test suite is controlled by the ``tests`` and
    ``cleanup_commands`` class variables.

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

    The ``cleanup_commands`` is a list of (command, args, kwargs)
    triples. These are commands get run both before and after tests,
    and must not fail.
    """

    cleanup_commands = tuple()
    tests = tuple()

    def cleanup_generate(self, stage):
        for (i, command) in enumerate(self.cleanup_commands):
            func = lambda: self.cleanup(command)
            func.description = '%s %s-cleanup[%d]: %r' % (
                self.__class__.__name__, stage, i, command
            )
            yield (func,)

    def cleanup(self, command):
        (cmd, args, options) = command
        if cmd not in api.Command:
            raise nose.SkipTest(
                'cleanup command %r not in api.Command' % cmd
            )
        try:
            api.Command[cmd](*args, **options)
        except (errors.NotFound, errors.EmptyModlist):
            pass

    def test_generator(self):
        """
        Iterate through tests.

        nose reports each one as a seperate test.
        """

        # Iterate through pre-cleanup:
        for tup in self.cleanup_generate('pre'):
            yield tup

        # Iterate through the tests:
        name = self.__class__.__name__
        for (i, test) in enumerate(self.tests):
            nice = '%s[%d]: %s: %s' % (
                name, i, test['command'][0], test.get('desc', '')
            )
            func = lambda: self.check(nice, **test)
            func.description = nice
            yield (func,)

        # Iterate through post-cleanup:
        for tup in self.cleanup_generate('post'):
            yield tup

    def check(self, nice, desc, command, expected, extra_check=None):
        (cmd, args, options) = command
        if cmd not in api.Command:
            raise nose.SkipTest('%r not in api.Command' % cmd)
        if isinstance(expected, errors.PublicError):
            self.check_exception(nice, cmd, args, options, expected)
        elif hasattr(expected, '__call__'):
            self.check_callable(nice, cmd, args, options, expected)
        else:
            self.check_output(nice, cmd, args, options, expected, extra_check)

    def check_exception(self, nice, cmd, args, options, expected):
        klass = expected.__class__
        name = klass.__name__
        try:
            output = api.Command[cmd](*args, **options)
        except StandardError, e:
            pass
        else:
            raise AssertionError(
                EXPECTED % (cmd, name, args, options, output)
            )
        if not isinstance(e, klass):
            raise AssertionError(
                UNEXPECTED % (cmd, name, args, options, e.__class__.__name__, e)
            )
        # FIXME: the XML-RPC transport doesn't allow us to return structured
        # information through the exception, so we can't test the kw on the
        # client side.  However, if we switch to using JSON-RPC for the default
        # transport, the exception is a free-form data structure (dict).
        # For now just compare the strings
        assert_deepequal(expected.strerror, e.strerror)

    def check_callable(self, nice, cmd, args, options, expected):
        output = dict()
        e = None
        try:
            output = api.Command[cmd](*args, **options)
        except StandardError, e:
           pass
        if not expected(e, output):
            raise AssertionError(
                UNEXPECTED % (cmd, args, options, e.__class__.__name__, e)
            )

    def check_output(self, nice, cmd, args, options, expected, extra_check):
        got = api.Command[cmd](*args, **options)
        assert_deepequal(expected, got, nice)
        if extra_check and not extra_check(got):
            raise AssertionError('Extra check %s failed' % extra_check)
