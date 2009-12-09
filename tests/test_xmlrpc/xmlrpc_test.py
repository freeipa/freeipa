# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Base class for all XML-RPC tests
"""

import sys
import socket
import nose
from tests.util import assert_deepequal
from ipalib import api, request
from ipalib import errors


try:
    if not api.Backend.xmlclient.isconnected():
        api.Backend.xmlclient.connect()
    res = api.Command['user_show'](u'notfound')
except errors.NetworkError:
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

    def setUp(self):
        if not server_available:
            raise nose.SkipTest(
                'Server not available: %r' % api.env.xmlrpc_uri
            )
        if not api.Backend.xmlclient.isconnected():
            api.Backend.xmlclient.connect()

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
    cleanup_commands = tuple()
    tests = tuple()

    def cleanup_generate(self, stage):
        for command in self.cleanup_commands:
            func = lambda: self.cleanup(command)
            func.description = '%s %s-cleanup: %r' % (
                self.__class__.__name__, stage, command
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
        except errors.NotFound:
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
            func = lambda: self.check(nice, test)
            func.description = nice
            yield (func,)

        # Iterate through post-cleanup:
        for tup in self.cleanup_generate('post'):
            yield tup

    def check(self, nice, test):
        (cmd, args, options) = test['command']
        if cmd not in api.Command:
            raise nose.SkipTest('%r not in api.Command' % cmd)
        expected = test['expected']
        ignore_values = test.get('ignore_values')
        if isinstance(expected, errors.PublicError):
            self.check_exception(nice, cmd, args, options, expected)
        else:
            self.check_output(nice, cmd, args, options, expected, ignore_values)

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
#        if e.kw != expected.kw:
#            raise AssertionError(
#                KWARGS % (cmd, name, args, options, expected.kw, e.kw)
#            )

    def check_output(self, nice, cmd, args, options, expected, ignore_values):
            got = api.Command[cmd](*args, **options)
            result = got['result']
            if ignore_values:
                if isinstance(result, dict):
                    self.clean_entry(
                        nice, cmd, args, options, result, ignore_values
                    )
                elif isinstance(result, (list, tuple)):
                    for entry in result:
                        self.clean_entry(
                            nice, cmd, args, options, entry, ignore_values
                        )
            assert_deepequal(expected, got, nice)

    def clean_entry(self, nice, cmd, args, options, entry, ignore_values):
        """
        Remove attributes like 'ipauniqueid' whose value is unpredictable.
        """
        for key in ignore_values:
            if key not in entry:
                raise AssertionError(
                    IGNORE % (cmd, key, args, options, entry)
                )
            entry.pop(key)
