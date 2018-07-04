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
from __future__ import print_function

import datetime
import inspect
import unittest

import contextlib
import six

from ipatests.util import assert_deepequal, Fuzzy
from ipalib import api, request, errors
from ipapython.version import API_VERSION

# pylint: disable=no-name-in-module, import-error
if six.PY3:
    from collections.abc import Sequence
else:
    from collections import Sequence
# pylint: enable=no-name-in-module, import-error

# Matches a gidnumber like '1391016742'
# FIXME: Does it make more sense to return gidnumber, uidnumber, etc. as `int`
# or `long`?  If not, we still need to return them as `unicode` instead of `str`.
fuzzy_digits = Fuzzy('^\d+$', type=six.string_types)

uuid_re = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

# Matches an ipauniqueid like u'784d85fd-eae7-11de-9d01-54520012478b'
fuzzy_uuid = Fuzzy('^%s$' % uuid_re)

# Matches an automember task DN
fuzzy_automember_dn = Fuzzy(
    '^cn=%s,cn=automember rebuild membership,cn=tasks,cn=config$' % uuid_re
)

# base64-encoded value
fuzzy_base64 = Fuzzy('^[0-9A-Za-z/+]+={0,2}$')


def fuzzy_sequence_of(fuzzy):
    """Construct a Fuzzy for a Sequence of values matching the given Fuzzy."""
    def test(xs):
        if not isinstance(xs, Sequence):
            return False
        else:
            return all(fuzzy == x for x in xs)

    return Fuzzy(test=test)

# Matches an automember task finish message
fuzzy_automember_message = Fuzzy(
    '^Automember rebuild task finished\. Processed \(\d+\) entries\.$'
)

# Matches trusted domain GUID, like u'463bf2be-3456-4a57-979e-120304f2a0eb'
fuzzy_guid = fuzzy_uuid

# Matches SID of a trusted domain
# SID syntax: http://msdn.microsoft.com/en-us/library/ff632068.aspx
_sid_identifier_authority = '(0x[0-9a-f]{1,12}|[0-9]{1,10})'
fuzzy_domain_sid = Fuzzy(
    '^S-1-5-21-%(idauth)s-%(idauth)s-%(idauth)s$' % dict(idauth=_sid_identifier_authority)
)
fuzzy_user_or_group_sid = Fuzzy(
    '^S-1-5-21-%(idauth)s-%(idauth)s-%(idauth)s-%(idauth)s$' % dict(idauth=_sid_identifier_authority)
)

# Matches netgroup dn. Note (?i) at the beginning of the regexp is the ingnore case flag
fuzzy_netgroupdn = Fuzzy(
    '(?i)ipauniqueid=%s,cn=ng,cn=alt,%s' % (uuid_re, api.env.basedn)
)

# Matches sudocmd dn
fuzzy_sudocmddn = Fuzzy(
    '(?i)ipauniqueid=%s,cn=sudocmds,cn=sudo,%s' % (uuid_re, api.env.basedn)
)

# Matches caacl dn
fuzzy_caacldn = Fuzzy(
    '(?i)ipauniqueid=%s,cn=caacls,cn=ca,%s' % (uuid_re, api.env.basedn)
)

# Matches internal CA ID
fuzzy_caid = fuzzy_uuid

# Matches fuzzy ipaUniqueID DN group (RDN)
fuzzy_ipauniqueid = Fuzzy('(?i)ipauniqueid=%s' % uuid_re)

# Matches a hash signature, not enforcing length
fuzzy_hash = Fuzzy('^([a-f0-9][a-f0-9]:)+[a-f0-9][a-f0-9]$', type=six.string_types)

# Matches a date, like Tue Apr 26 17:45:35 2016 UTC
fuzzy_date = Fuzzy('^[a-zA-Z]{3} [a-zA-Z]{3} \d{2} \d{2}:\d{2}:\d{2} \d{4} UTC$')

fuzzy_issuer = Fuzzy(type=six.string_types)

fuzzy_hex = Fuzzy('^0x[0-9a-fA-F]+$', type=six.string_types)

# Matches password - password consists of all printable characters without
# whitespaces. The only exception is space, but space cannot be at the
# beginning or end of the pwd.
fuzzy_password = Fuzzy('^\S([\S ]*\S)*$')

# Matches generalized time value. Time format is: %Y%m%d%H%M%SZ
fuzzy_dergeneralizedtime = Fuzzy(type=datetime.datetime)

# match any string
fuzzy_string = Fuzzy(type=six.string_types)

fuzzy_bytes = Fuzzy(type=bytes)

# case insensitive match of sets
def fuzzy_set_ci(s):
    return Fuzzy(test=lambda other: set(x.lower() for x in other) == set(y.lower() for y in s))

try:
    if not api.Backend.rpcclient.isconnected():
        api.Backend.rpcclient.connect()
    res = api.Command['user_show'](u'notfound')
except errors.NetworkError:
    server_available = False
except IOError:
    server_available = False
except errors.NotFound:
    server_available = True

adtrust_is_enabled = api.Command['adtrust_is_enabled']()['result']
sidgen_was_run = api.Command['sidgen_was_run']()['result']


def add_sid(d, check_sidgen=False):
    if adtrust_is_enabled and (not check_sidgen or sidgen_was_run):
        d['ipantsecurityidentifier'] = (fuzzy_user_or_group_sid,)
    return d


def add_oc(l, oc, check_sidgen=False):
    if adtrust_is_enabled and (not check_sidgen or sidgen_was_run):
        return l + [oc]
    return l


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
    def setup_class(cls):
        if not server_available:
            raise unittest.SkipTest('%r: Server not available: %r' %
                                (cls.__module__, api.env.xmlrpc_uri))
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

    @classmethod
    def teardown_class(cls):
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
        self.failsafe_del(obj, pk)
        return obj.methods['add'](pk, **options)

    @classmethod
    def failsafe_del(cls, obj, pk):
        """
        Delete an entry if it exists
        :param obj: An Object like api.Object.user
        :param pk: The primary key of the entry to be deleted
        """
        try:
            obj.methods['del'](pk)
        except errors.NotFound:
            pass


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
  expected = %s: %s
  got = %s: %s"""


KWARGS = """Command %r raised %s with wrong kwargs.
  args = %r
  options = %r
  kw_expected = %r
  kw_got = %r"""


class Declarative(XMLRPC_test):
    """A declarative-style test suite

    This class is DEPRECATED. Use RPCTest instead.
    See host plugin tests for an example.

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

    default_version = API_VERSION
    cleanup_commands = tuple()
    tests = tuple()

    @classmethod
    def setup_class(cls):
        super(Declarative, cls).setup_class()
        for command in cls.cleanup_commands:
            cls.cleanup(command)

    @classmethod
    def teardown_class(cls):
        for command in cls.cleanup_commands:
            cls.cleanup(command)
        super(Declarative, cls).teardown_class()

    @classmethod
    def cleanup(cls, command):
        (cmd, args, options) = command
        print('Cleanup:', cmd, args, options)
        if cmd not in api.Command:
            raise unittest.SkipTest(
                'cleanup command %r not in api.Command' % cmd
            )
        try:
            api.Command[cmd](*args, **options)
        except (errors.NotFound, errors.EmptyModlist) as e:
            print(e)

    def test_command(self, index, declarative_test_definition):
        """Run an individual test

        The arguments are provided by the pytest plugin.
        """
        if callable(declarative_test_definition):
            declarative_test_definition(self)
        else:
            self.check(**declarative_test_definition)

    def check(self, nice, desc, command, expected, extra_check=None):
        (cmd, args, options) = command
        options.setdefault('version', self.default_version)
        if cmd not in api.Command:
            raise unittest.SkipTest('%r not in api.Command' % cmd)
        if isinstance(expected, errors.PublicError):
            self.check_exception(nice, cmd, args, options, expected)
        elif hasattr(expected, '__call__'):
            self.check_callable(nice, cmd, args, options, expected)
        else:
            self.check_output(nice, cmd, args, options, expected, extra_check)

    def check_exception(self, nice, cmd, args, options, expected):
        klass = expected.__class__
        expected_name = klass.__name__
        try:
            output = api.Command[cmd](*args, **options)
        except Exception as e:
            got = e
        else:
            raise AssertionError(
                EXPECTED % (cmd, expected_name, args, options, output)
            )
        if not isinstance(got, klass):
            raise AssertionError(
                UNEXPECTED % (cmd, expected_name, args, options,
                              expected_name, expected,
                              got.__class__.__name__, got)
            )
        # FIXME: the XML-RPC transport doesn't allow us to return structured
        # information through the exception, so we can't test the kw on the
        # client side.  However, if we switch to using JSON-RPC for the default
        # transport, the exception is a free-form data structure (dict).
        # For now just compare the strings
        # pylint: disable=no-member
        assert_deepequal(expected.strerror, got.strerror)
        # pylint: enable=no-member

    def check_callable(self, nice, cmd, args, options, expected):
        expected_name = expected.__class__.__name__
        try:
            expected_text = inspect.getsource(expected).strip()
        except TypeError:
            expected_text = str(expected)
        output = dict()
        got = None
        try:
            output = api.Command[cmd](*args, **options)
        except Exception as e:
            got = e
        if not expected(got, output):
            raise AssertionError(
                UNEXPECTED % (cmd, expected_name, args, options,
                              expected_name, expected_text,
                              got.__class__.__name__, got)
            )

    def check_output(self, nice, cmd, args, options, expected, extra_check):
        got = api.Command[cmd](*args, **options)
        assert_deepequal(expected, got, nice)
        if extra_check and not extra_check(got):
            raise AssertionError('Extra check %s failed' % extra_check)


@contextlib.contextmanager
def raises_exact(expected_exception):
    """Check that a specific PublicError is raised

    Both type and message of the error are checked.

    >>> with raises_exact(errors.ValidationError(name='x', error='y')):
    ...     raise errors.ValidationError(name='x', error='y')
    """
    try:
        yield
    except errors.PublicError as got_exception:
        assert type(expected_exception) is type(got_exception)
        # FIXME: We should return error information in a structured way.
        # For now just compare the strings
        assert expected_exception.strerror == got_exception.strerror
    else:
        raise AssertionError('did not raise!')
