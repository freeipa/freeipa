# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Common utility functions and classes for unit tests.
"""

from __future__ import absolute_import

import inspect
import os
from os import path
import tempfile
import shutil
import re
import uuid
import pytest
from contextlib import contextmanager
from pprint import pformat

import six
import ldap
import ldap.sasl
import ldap.modlist

import ipalib
from ipalib import api
from ipalib.plugable import Plugin
from ipalib.request import context
from ipapython.dn import DN
from ipapython.ipaldap import ldap_initialize
from ipapython.ipautil import run


try:
    # not available with client-only wheel packages
    from ipalib.install.kinit import kinit_keytab, kinit_password
except ImportError:
    kinit_keytab = kinit_password = None

try:
    # not available with client-only wheel packages
    from ipaplatform.paths import paths
except ImportError:
    paths = None


if six.PY3:
    unicode = str


PYTEST_VERSION = tuple(int(v) for v in pytest.__version__.split('.'))

# settings are configured by conftest
IPACLIENT_UNITTESTS = None
SKIP_IPAAPI = None
PRETTY_PRINT = None


def check_ipaclient_unittests(reason="Skip in ipaclient unittest mode"):
    """Call this in a package to skip the package in ipaclient-unittest mode
    """
    if IPACLIENT_UNITTESTS:
        if PYTEST_VERSION[0] >= 3:
            # pytest 3+ does no longer allow pytest.skip() on module level
            # pylint: disable=unexpected-keyword-arg
            raise pytest.skip.Exception(reason, allow_module_level=True)
            # pylint: enable=unexpected-keyword-arg
        else:
            raise pytest.skip(reason)


def check_no_ipaapi(reason="Skip tests that needs an IPA API"):
    """Call this in a package to skip the package in no-ipaapi mode
    """
    if SKIP_IPAAPI:
        if PYTEST_VERSION[0] >= 3:
            # pylint: disable=unexpected-keyword-arg
            raise pytest.skip.Exception(reason, allow_module_level=True)
            # pylint: enable=unexpected-keyword-arg
        else:
            raise pytest.skip(reason)


class TempDir(object):
    def __init__(self):
        self.__path = tempfile.mkdtemp(prefix='ipa.tests.')
        assert self.path == self.__path

    def __get_path(self):
        assert path.abspath(self.__path) == self.__path
        assert self.__path.startswith(path.join(tempfile.gettempdir(),
                                                'ipa.tests.'))
        assert path.isdir(self.__path) and not path.islink(self.__path)
        return self.__path
    path = property(__get_path)

    def rmtree(self):
        if self.__path is not None:
            shutil.rmtree(self.path)
            self.__path = None

    def makedirs(self, *parts):
        d = self.join(*parts)
        if not path.exists(d):
            os.makedirs(d)
        assert path.isdir(d) and not path.islink(d)
        return d

    def touch(self, *parts):
        d = self.makedirs(*parts[:-1])
        f = path.join(d, parts[-1])
        assert not path.exists(f)
        open(f, 'w').close()
        assert path.isfile(f) and not path.islink(f)
        return f

    def write(self, content, *parts):
        d = self.makedirs(*parts[:-1])
        f = path.join(d, parts[-1])
        assert not path.exists(f)
        open(f, 'w').write(content)
        assert path.isfile(f) and not path.islink(f)
        return f

    def join(self, *parts):
        return path.join(self.path, *parts)

    def __del__(self):
        self.rmtree()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.rmtree()


class TempHome(TempDir):
    def __init__(self):
        super(TempHome, self).__init__()
        self.__home = os.environ['HOME']
        os.environ['HOME'] = self.path


class ExceptionNotRaised(Exception):
    """
    Exception raised when an *expected* exception is *not* raised during a
    unit test.
    """
    msg = 'expected %s'

    def __init__(self, expected):
        self.expected = expected

    def __str__(self):
        return self.msg % self.expected.__name__


def assert_equal(val1, val2):
    """
    Assert ``val1`` and ``val2`` are the same type and of equal value.
    """
    assert type(val1) is type(val2), '%r != %r' % (val1, val2)
    assert val1 == val2, '%r != %r' % (val1, val2)


def assert_not_equal(val1, val2):
    """
    Assert ``val1`` and ``val2`` are the same type and of non-equal value.
    """
    assert type(val1) is type(val2), '%r != %r' % (val1, val2)
    assert val1 != val2, '%r == %r' % (val1, val2)


class Fuzzy(object):
    """
    Perform a fuzzy (non-strict) equality tests.

    `Fuzzy` instances will likely be used when comparing nesting
    data-structures using `assert_deepequal()`.

    By default a `Fuzzy` instance is equal to everything.  For example, all of
    these evaluate to ``True``:

    >>> Fuzzy() == False
    True
    >>> 7 == Fuzzy()  # Order doesn't matter
    True
    >>> Fuzzy() == u'Hello False, Lucky 7!'
    True

    The first optional argument *regex* is a regular expression pattern to
    match.  For example, you could match a phone number like this:

    >>> phone = Fuzzy(r'^\d{3}-\d{3}-\d{4}$')
    >>> u'123-456-7890' == phone
    True

    Use of a regular expression by default implies the ``unicode`` type, so
    comparing with an ``str`` instance will evaluate to ``False``:

    >>> phone.type is six.text_type
    True
    >>> b'123-456-7890' == phone
    False

    The *type* kwarg allows you to specify a type constraint, so you can force
    the above to work on ``str`` instances instead:

    >>> '123-456-7890' == Fuzzy(r'^\d{3}-\d{3}-\d{4}$', type=str)
    True

    You can also use the *type* constraint on its own without the *regex*, for
    example:

    >>> 42 == Fuzzy(type=int)
    True
    >>> 42.0 == Fuzzy(type=int)
    False
    >>> 42.0 == Fuzzy(type=(int, float))
    True

    Finally the *test* kwarg is an optional callable that will be called to
    perform the loose equality test.  For example:

    >>> 42 == Fuzzy(test=lambda other: other > 42)
    False
    >>> 43 == Fuzzy(test=lambda other: other > 42)
    True

    You can use *type* and *test* together.  For example:

    >>> 43 == Fuzzy(type=float, test=lambda other: other > 42)
    False
    >>> 42.5 == Fuzzy(type=float, test=lambda other: other > 42)
    True

    The *regex*, *type*, and *test* kwargs are all availabel via attributes on
    the `Fuzzy` instance:

    >>> fuzzy = Fuzzy('.+', type=str, test=lambda other: True)
    >>> fuzzy.regex
    '.+'
    >>> fuzzy.type is str
    True
    >>> fuzzy.test  # doctest:+ELLIPSIS
    <function <lambda> at 0x...>

    To aid debugging, `Fuzzy.__repr__()` reveals these kwargs as well:

    >>> fuzzy  # doctest:+ELLIPSIS
    Fuzzy('.+', <... 'str'>, <function <lambda> at 0x...>)
    """

    __hash__ = None

    def __init__(self, regex=None, type=None, test=None):
        r"""
        Initialize.

        :param regex: A regular expression pattern to match, e.g.
            ``u'^\d+foo'``

        :param type: A type or tuple of types to test using ``isinstance()``,
            e.g. ``(int, float)``

        :param test: A callable used to perform equality test, e.g.
            ``lambda other: other >= 18``
        """
        assert regex is None or isinstance(regex, six.string_types)
        assert test is None or callable(test)
        if regex is None:
            self.re = None
        else:
            self.re = re.compile(regex)
            if type is None:
                type = unicode
            assert type in (unicode, bytes, six.string_types)
        self.regex = regex
        self.type = type
        self.test = test

    def __repr__(self):
        return '%s(%r, %r, %r)' % (
            self.__class__.__name__, self.regex, self.type, self.test
        )

    def __eq__(self, other):
        if not (self.type is None or isinstance(other, self.type)):
            return False
        if not (self.re is None or self.re.search(other)):
            return False
        if not (self.test is None or self.test(other)):
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)


VALUE = """assert_deepequal: expected != got.
  %s
  expected = %r
  got = %r
  path = %r"""

TYPE = """assert_deepequal: type(expected) is not type(got).
  %s
  type(expected) = %r
  type(got) = %r
  expected = %r
  got = %r
  path = %r"""

LEN = """assert_deepequal: list length mismatch.
  %s
  len(expected) = %r
  len(got) = %r
  expected = %s
  got = %s
  path = %r"""

KEYS = """assert_deepequal: dict keys mismatch.
  %s
  missing keys = %r
  extra keys = %r
  expected = %s
  got = %s
  path = %r"""

EXPECTED_LEN = len('  expected = ')
GOT_LEN = len('  got = ')


def struct_to_string(struct, indent=1):
    """
    Function to pretty-format a structure and optionally indent its lines
    so they match the visual indention of the first line
    """
    return pformat(struct).replace('\n', '\n' + ' ' * indent)


def assert_deepequal(expected, got, doc='', stack=tuple()):
    """
    Recursively check for type and equality.

    If a value in expected is callable then it will used as a callback to
    test for equality on the got value. The callback is passed the got
    value and returns True if equal, False otherwise.

    If the tests fails, it will raise an ``AssertionError`` with detailed
    information, including the path to the offending value.  For example:

    >>> expected = [u'Hello', dict(world=1)]
    >>> got = [u'Hello', dict(world=1.0)]
    >>> expected == got
    True
    >>> assert_deepequal(
    ...    expected, got, doc='Testing my nested data')  # doctest: +ELLIPSIS
    Traceback (most recent call last):
      ...
    AssertionError: assert_deepequal: type(expected) is not type(got).
      Testing my nested data
      type(expected) = <... 'int'>
      type(got) = <... 'float'>
      expected = 1
      got = 1.0
      path = (..., 'world')

    Note that lists and tuples are considered equivalent, and the order of
    their elements does not matter.
    """
    if PRETTY_PRINT:
        expected_str = struct_to_string(expected, EXPECTED_LEN)
        got_str = struct_to_string(got, GOT_LEN)
    else:
        expected_str = repr(expected)
        got_str = repr(got)

    if isinstance(expected, tuple):
        expected = list(expected)
    if isinstance(got, tuple):
        got = list(got)
    if isinstance(expected, DN):
        if isinstance(got, six.string_types):
            got = DN(got)
    if (
        not (isinstance(expected, Fuzzy)
             or callable(expected)
             or type(expected) is type(got))
    ):
        raise AssertionError(
            TYPE % (doc, type(expected), type(got), expected, got, stack)
        )
    if isinstance(expected, (list, tuple)):
        if len(expected) != len(got):
            raise AssertionError(
                LEN % (doc, len(expected), len(got), expected_str, got_str,
                       stack)
            )
        # Sort list elements, unless they are dictionaries
        if expected and isinstance(expected[0], dict):
            s_got = got
            s_expected = expected
        else:
            try:
                s_got = sorted(got)
            except TypeError:
                s_got = got
            try:
                s_expected = sorted(expected)
            except TypeError:
                s_expected = expected
        for (i, e_sub) in enumerate(s_expected):
            g_sub = s_got[i]
            assert_deepequal(e_sub, g_sub, doc, stack + (i,))
    elif isinstance(expected, dict):
        missing = set(expected).difference(got)
        extra = set(got).difference(expected)
        if missing or extra:
            raise AssertionError(KEYS % (
                    doc, sorted(missing), sorted(extra), expected_str, got_str,
                    stack)
            )
        for key in sorted(expected):
            e_sub = expected[key]
            g_sub = got[key]
            assert_deepequal(e_sub, g_sub, doc, stack + (key,))
    elif callable(expected):
        if not expected(got):
            raise AssertionError(
                VALUE % (doc, expected, got, stack)
                )
    elif expected != got:
        raise AssertionError(
            VALUE % (doc, expected, got, stack)
        )


def raises(exception, callback, *args, **kw):
    """
    Tests that the expected exception is raised; raises ExceptionNotRaised
    if test fails.
    """
    try:
        callback(*args, **kw)
    except exception as e:
        return e
    raise ExceptionNotRaised(exception)


def getitem(obj, key):
    """
    Works like getattr but for dictionary interface. Use this in combination
    with raises() to test that, for example, KeyError is raised.
    """
    return obj[key]


def setitem(obj, key, value):
    """
    Works like setattr but for dictionary interface. Use this in combination
    with raises() to test that, for example, TypeError is raised.
    """
    obj[key] = value


def delitem(obj, key):
    """
    Works like delattr but for dictionary interface. Use this in combination
    with raises() to test that, for example, TypeError is raised.
    """
    del obj[key]


def no_set(obj, name, value='some_new_obj'):
    """
    Tests that attribute cannot be set.
    """
    raises(AttributeError, setattr, obj, name, value)


def no_del(obj, name):
    """
    Tests that attribute cannot be deleted.
    """
    raises(AttributeError, delattr, obj, name)


def read_only(obj, name, value='some_new_obj'):
    """
    Tests that attribute is read-only. Returns attribute.
    """
    # Test that it cannot be set:
    no_set(obj, name, value)

    # Test that it cannot be deleted:
    no_del(obj, name)

    # Return the attribute
    return getattr(obj, name)


def is_prop(prop):
    return type(prop) is property


class ClassChecker(object):
    __cls = None
    __subcls = None

    def __get_cls(self):
        if self.__cls is None:
            self.__cls = self._cls  # pylint: disable=E1101
        assert inspect.isclass(self.__cls)
        return self.__cls
    cls = property(__get_cls)

    def __get_subcls(self):
        if self.__subcls is None:
            self.__subcls = self.get_subcls()
        assert inspect.isclass(self.__subcls)
        return self.__subcls
    subcls = property(__get_subcls)

    def get_subcls(self):
        raise AttributeError(
            self.__class__.__name__,
            'get_subcls()'
        )

    def teardown(self):
        """
        nose tear-down fixture.
        """
        context.__dict__.clear()


def get_api(**kw):
    """
    Returns (api, home) tuple.

    This function returns a tuple containing an `ipalib.plugable.API`
    instance and a `TempHome` instance.
    """
    home = TempHome()
    api = ipalib.create_api(mode='unit_test')
    api.env.in_tree = True
    for (key, value) in kw.items():
        api.env[key] = value
    return (api, home)


def create_test_api(**kw):
    """
    Returns (api, home) tuple.

    This function returns a tuple containing an `ipalib.plugable.API`
    instance and a `TempHome` instance.
    """
    home = TempHome()
    api = ipalib.create_api(mode='unit_test')
    api.env.in_tree = True
    for (key, value) in kw.items():
        api.env[key] = value
    return (api, home)


class PluginTester(object):
    __plugin = None

    def __get_plugin(self):
        if self.__plugin is None:
            self.__plugin = self._plugin  # pylint: disable=E1101
        assert issubclass(self.__plugin, Plugin)
        return self.__plugin
    plugin = property(__get_plugin)

    def register(self, *plugins, **kw):
        r"""
        Create a testing api and register ``self.plugin``.

        This method returns an (api, home) tuple.

        :param plugins: Additional \*plugins to register.
        :param kw: Additional \**kw args to pass to `create_test_api`.
        """
        (api, home) = create_test_api(**kw)
        api.add_plugin(self.plugin)
        for p in plugins:
            api.add_plugin(p)
        return (api, home)

    def finalize(self, *plugins, **kw):
        (api, home) = self.register(*plugins, **kw)
        api.finalize()
        return (api, home)

    def instance(self, namespace, *plugins, **kw):
        (api, home) = self.finalize(*plugins, **kw)
        o = api[namespace][self.plugin.__name__]
        return (o, api, home)

    def teardown(self):
        """
        nose tear-down fixture.
        """
        context.__dict__.clear()


class dummy_ugettext(object):
    __called = False

    def __init__(self, translation=None):
        if translation is None:
            translation = u'The translation'
        self.translation = translation
        assert type(self.translation) is unicode

    def __call__(self, message):
        assert self.__called is False
        self.__called = True
        assert type(message) is str
        assert not hasattr(self, 'message')
        self.message = message
        assert type(self.translation) is unicode
        return self.translation

    def called(self):
        return self.__called

    def reset(self):
        assert type(self.translation) is unicode
        assert type(self.message) is str
        del self.message
        assert self.__called is True
        self.__called = False


class dummy_ungettext(object):
    __called = False

    def __init__(self):
        self.translation_singular = u'The singular translation'
        self.translation_plural = u'The plural translation'

    def __call__(self, singular, plural, n):
        assert type(singular) is str
        assert type(plural) is str
        assert type(n) is int
        assert self.__called is False
        self.__called = True
        self.singular = singular
        self.plural = plural
        self.n = n
        if n == 1:
            return self.translation_singular
        return self.translation_plural


class DummyMethod(object):
    def __init__(self, callback, name):
        self.__callback = callback
        self.__name = name

    def __call__(self, *args, **kw):
        return self.__callback(self.__name, args, kw)


class DummyClass(object):
    def __init__(self, *calls):
        self.__calls = calls
        self.__i = 0
        for (name, _args, _kw, _result) in calls:
            method = DummyMethod(self.__process, name)
            setattr(self, name, method)

    def __process(self, name_, args_, kw_):
        if self.__i >= len(self.__calls):
            raise AssertionError(
                "extra call: {name!s}, {args!r}, {kwargs!r}".format(
                    name=name_, args=args_, kwargs=kw_
                )
            )
        (name, args, kw, result) = self.__calls[self.__i]
        self.__i += 1
        i = self.__i
        if name_ != name:
            raise AssertionError(
                "call {0:d} should be to method {1!r}; got {2!r}".format(
                    i, name, name_
                )
            )
        if args_ != args:
            raise AssertionError(
                "call {0:d} to {1!r} should have args {2!r}; got {3!r}".format(
                    i, name, args, args_
                )
            )
        if kw_ != kw:
            raise AssertionError(
                "call {0:d} to {1!r} should have kw {2!r}, got {3!r}".format(
                    i, name, kw, kw_
                )
            )
        if isinstance(result, Exception):
            raise result
        return result

    def _calledall(self):
        return self.__i == len(self.__calls)


class MockLDAP(object):
    def __init__(self):
        self.connection = ldap_initialize(
            'ldap://{host}'.format(host=ipalib.api.env.host)
        )

        auth = ldap.sasl.gssapi('')
        self.connection.sasl_interactive_bind_s('', auth)

    def add_entry(self, dn, mods):
        try:
            ldif = ldap.modlist.addModlist(mods)
            self.connection.add_s(dn, ldif)
        except ldap.ALREADY_EXISTS:
            pass

    def mod_entry(self, dn, mods):
        self.connection.modify_s(dn, mods)

    def del_entry(self, dn):
        try:
            self.connection.delete_s(dn)
        except ldap.NO_SUCH_OBJECT:
            pass

    def unbind(self):
        if self.connection is not None:
            self.connection.unbind_s()

    # contextmanager protocol
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.unbind()


def prepare_config(template, values):
    with open(template) as f:
        template = f.read()

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as config:
        config.write(template.format(**values))

    return config.name


def unlock_principal_password(user, oldpw, newpw):
    userdn = "uid={},{},{}".format(
        user, api.env.container_user, api.env.basedn)

    args = [paths.LDAPPASSWD, '-D', userdn, '-w', oldpw, '-a', oldpw,
            '-s', newpw, '-x', '-H', api.env.ldap_uri]
    return run(args)


@contextmanager
def change_principal(principal, password=None, client=None, path=None,
                     canonicalize=False, enterprise=False, keytab=None):
    """Temporarily change the kerberos principal

    Most of the test cases run with the admin ipa user which is granted
    all access and exceptions from rules on some occasions.

    When the test needs to test for an application of some kind
    of a restriction it needs to authenticate as a different principal
    with required set of rights to the operation.

    The context manager changes the principal identity in two ways:

    * using password
    * using keytab

    If the context manager is to be used with a keytab, the keytab
    option must be its absolute path.

    The context manager can be used to authenticate with enterprise
    principals and aliases when given respective options.
    """

    if path:
        ccache_name = path
    else:
        ccache_name = os.path.join('/tmp', str(uuid.uuid4()))

    if client is None:
        client = api

    client.Backend.rpcclient.disconnect()

    try:
        if keytab:
            kinit_keytab(principal, keytab, ccache_name)
        else:
            kinit_password(principal, password, ccache_name,
                           canonicalize=canonicalize,
                           enterprise=enterprise)
        client.Backend.rpcclient.connect(ccache=ccache_name)

        try:
            yield
        finally:
            client.Backend.rpcclient.disconnect()
    finally:
        # If we generated a ccache name, try to remove it, but don't fail
        if not path:
            try:
                os.remove(ccache_name)
            except OSError:
                pass
        client.Backend.rpcclient.connect()


@contextmanager
def get_entity_keytab(principal, options=None):
    """Requests a keytab for an entity

    The keytab will generate new keys if not specified
    otherwise in the options.
    To retrieve existing keytab, use the -r option
    """
    keytab_filename = os.path.join('/tmp', str(uuid.uuid4()))

    try:
        cmd = [paths.IPA_GETKEYTAB, '-p', principal, '-k', keytab_filename]

        if options:
            cmd.extend(options)
        run(cmd)

        yield keytab_filename
    finally:
        if os.path.isfile(keytab_filename):
            os.remove(keytab_filename)


@contextmanager
def host_keytab(hostname, options=None):
    """Retrieves keytab for a particular host

    After leaving the context manager, the keytab file is
    deleted.
    """
    principal = u'host/{}'.format(hostname)

    with get_entity_keytab(principal, options) as keytab:
        yield keytab


def get_group_dn(cn):
    return DN(('cn', cn), api.env.container_group, api.env.basedn)


def get_user_dn(uid):
    return DN(('uid', uid), api.env.container_user, api.env.basedn)
