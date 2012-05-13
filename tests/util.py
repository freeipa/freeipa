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

import inspect
import os
from os import path
import tempfile
import shutil
import re
import ipalib
from ipalib.plugable import Plugin
from ipalib.request import context
from ipapython.dn import DN

class TempDir(object):
    def __init__(self):
        self.__path = tempfile.mkdtemp(prefix='ipa.tests.')
        assert self.path == self.__path

    def __get_path(self):
        assert path.abspath(self.__path) == self.__path
        assert self.__path.startswith('/tmp/ipa.tests.')
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

    `Fuzzy` instances will likely be used when comparing nesting data-structures
    using `assert_deepequal()`.

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

    >>> phone = Fuzzy('^\d{3}-\d{3}-\d{4}$')
    >>> u'123-456-7890' == phone
    True

    Use of a regular expression by default implies the ``unicode`` type, so
    comparing with an ``str`` instance will evaluate to ``False``:

    >>> phone.type
    <type 'unicode'>
    >>> '123-456-7890' == phone
    False

    The *type* kwarg allows you to specify a type constraint, so you can force
    the above to work on ``str`` instances instead:

    >>> '123-456-7890' == Fuzzy('^\d{3}-\d{3}-\d{4}$', type=str)
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
    >>> fuzzy.type
    <type 'str'>
    >>> fuzzy.test  # doctest:+ELLIPSIS
    <function <lambda> at 0x...>

    To aid debugging, `Fuzzy.__repr__()` revealse these kwargs as well:

    >>> fuzzy  # doctest:+ELLIPSIS
    Fuzzy('.+', <type 'str'>, <function <lambda> at 0x...>)
    """

    def __init__(self, regex=None, type=None, test=None):
        """
        Initialize.

        :param regex: A regular expression pattern to match, e.g.
            ``u'^\d+foo'``

        :param type: A type or tuple of types to test using ``isinstance()``,
            e.g. ``(int, float)``

        :param test: A callable used to perform equality test, e.g.
            ``lambda other: other >= 18``
        """
        assert regex is None or isinstance(regex, basestring)
        assert test is None or callable(test)
        if regex is None:
            self.re = None
        else:
            self.re = re.compile(regex)
            if type is None:
                type = unicode
            assert type in (unicode, str, basestring)
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
  expected = %r
  got = %r
  path = %r"""

KEYS = """assert_deepequal: dict keys mismatch.
  %s
  missing keys = %r
  extra keys = %r
  expected = %r
  got = %r
  path = %r"""


def assert_deepequal(expected, got, doc='', stack=tuple()):
    """
    Recursively check for type and equality.

    If a value in expected is callable then it will used as a callback to
    test for equality on the got value. The callback is passed the got
    value and returns True if equal, False otherwise.

    If the tests fails, it will raise an ``AssertionError`` with detailed
    information, including the path to the offending value.  For example:

    >>> expected = [u'Hello', dict(world=u'how are you?')]
    >>> got = [u'Hello', dict(world='how are you?')]
    >>> expected == got
    True
    >>> assert_deepequal(expected, got, doc='Testing my nested data')
    Traceback (most recent call last):
      ...
    AssertionError: assert_deepequal: type(expected) is not type(got).
      Testing my nested data
      type(expected) = <type 'unicode'>
      type(got) = <type 'str'>
      expected = u'how are you?'
      got = 'how are you?'
      path = (0, 'world')

    Note that lists and tuples are considered equivalent, and the order of
    their elements does not matter.
    """
    if isinstance(expected, tuple):
        expected = list(expected)
    if isinstance(got, tuple):
        got = list(got)
    if isinstance(expected, DN):
        if isinstance(got, basestring):
            got = DN(got)
    if not (isinstance(expected, Fuzzy) or callable(expected) or type(expected) is type(got)):
        raise AssertionError(
            TYPE % (doc, type(expected), type(got), expected, got, stack)
        )
    if isinstance(expected, (list, tuple)):
        if len(expected) != len(got):
            raise AssertionError(
                LEN % (doc, len(expected), len(got), expected, got, stack)
            )
        s_got = sorted(got)
        s_expected = sorted(expected)
        for (i, e_sub) in enumerate(s_expected):
            g_sub = s_got[i]
            assert_deepequal(e_sub, g_sub, doc, stack + (i,))
    elif isinstance(expected, dict):
        missing = set(expected).difference(got)
        extra = set(got).difference(expected)
        if missing or extra:
            raise AssertionError(KEYS % (
                    doc, sorted(missing), sorted(extra), expected, got, stack
                )
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
    raised = False
    try:
        callback(*args, **kw)
    except exception, e:
        raised = True
    if not raised:
        raise ExceptionNotRaised(exception)
    return e


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
            self.__cls = self._cls
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
        raise NotImplementedError(
            self.__class__.__name__,
            'get_subcls()'
        )

    def tearDown(self):
        """
        nose tear-down fixture.
        """
        context.__dict__.clear()








def check_TypeError(value, type_, name, callback, *args, **kw):
    """
    Tests a standard TypeError raised with `errors.raise_TypeError`.
    """
    e = raises(TypeError, callback, *args, **kw)
    assert e.value is value
    assert e.type is type_
    assert e.name == name
    assert type(e.name) is str
    assert str(e) == ipalib.errors.TYPE_ERROR % (name, type_, value)
    return e


def get_api(**kw):
    """
    Returns (api, home) tuple.

    This function returns a tuple containing an `ipalib.plugable.API`
    instance and a `TempHome` instance.
    """
    home = TempHome()
    api = ipalib.create_api(mode='unit_test')
    api.env.in_tree = True
    for (key, value) in kw.iteritems():
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
    for (key, value) in kw.iteritems():
        api.env[key] = value
    return (api, home)


class PluginTester(object):
    __plugin = None

    def __get_plugin(self):
        if self.__plugin is None:
            self.__plugin = self._plugin
        assert issubclass(self.__plugin, Plugin)
        return self.__plugin
    plugin = property(__get_plugin)

    def register(self, *plugins, **kw):
        """
        Create a testing api and register ``self.plugin``.

        This method returns an (api, home) tuple.

        :param plugins: Additional \*plugins to register.
        :param kw: Additional \**kw args to pass to `create_test_api`.
        """
        (api, home) = create_test_api(**kw)
        api.register(self.plugin)
        for p in plugins:
            api.register(p)
        return (api, home)

    def finalize(self, *plugins, **kw):
        (api, home) = self.register(*plugins, **kw)
        api.finalize()
        return (api, home)

    def instance(self, namespace, *plugins, **kw):
        (api, home) = self.finalize(*plugins, **kw)
        o = api[namespace][self.plugin.__name__]
        return (o, api, home)

    def tearDown(self):
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
        for (name, args, kw, result) in calls:
            method = DummyMethod(self.__process, name)
            setattr(self, name, method)

    def __process(self, name_, args_, kw_):
        if self.__i >= len(self.__calls):
            raise AssertionError(
                'extra call: %s, %r, %r' % (name_, args_, kw_)
            )
        (name, args, kw, result) = self.__calls[self.__i]
        self.__i += 1
        i = self.__i
        if name_ != name:
            raise AssertionError(
                'call %d should be to method %r; got %r' % (i, name, name_)
            )
        if args_ != args:
            raise AssertionError(
                'call %d to %r should have args %r; got %r' % (i, name, args, args_)
            )
        if kw_ != kw:
            raise AssertionError(
                'call %d to %r should have kw %r, got %r' % (i, name, kw, kw_)
            )
        if isinstance(result, Exception):
            raise result
        return result

    def _calledall(self):
        return self.__i == len(self.__calls)
