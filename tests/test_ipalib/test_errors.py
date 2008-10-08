# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Test the `ipalib.errors` module.
"""

from tests.util import raises, ClassChecker
from ipalib import errors


type_format = '%s: need a %r; got %r'


def check_TypeError(f, value, type_, name, **kw):
    e = raises(TypeError, f, value, type_, name, **kw)
    assert e.value is value
    assert e.type is type_
    assert e.name is name
    assert str(e) == type_format % (name, type_, value)


def test_raise_TypeError():
    """
    Tests the `errors.raise_TypeError` function.
    """
    f = errors.raise_TypeError
    value = 'Hello.'
    type_ = unicode
    name = 'message'

    check_TypeError(f, value, type_, name)

    # name not an str
    fail_name = 42
    e = raises(AssertionError, f, value, type_, fail_name)
    assert str(e) == type_format % ('name', str, fail_name), str(e)

    # type_ not a type:
    fail_type = unicode()
    e = raises(AssertionError, f, value, fail_type, name)
    assert str(e) == type_format % ('type_', type, fail_type)

    # type(value) is type_:
    fail_value = u'How are you?'
    e = raises(AssertionError, f, fail_value, type_, name)
    assert str(e) == 'value: %r is a %r' % (fail_value, type_)


def test_check_type():
    """
    Tests the `errors.check_type` function.
    """
    f = errors.check_type
    value = 'How are you?'
    type_ = str
    name = 'greeting'

    # Should pass:
    assert value is f(value, type_, name)
    assert None is f(None, type_, name, allow_none=True)

    # Should raise TypeError
    check_TypeError(f, None, type_, name)
    check_TypeError(f, value, basestring, name)
    check_TypeError(f, value, unicode, name)

    # name not an str
    fail_name = unicode(name)
    e = raises(AssertionError, f, value, type_, fail_name)
    assert str(e) == type_format % ('name', str, fail_name)

    # type_ not a type:
    fail_type = 42
    e = raises(AssertionError, f, value, fail_type, name)
    assert str(e) == type_format % ('type_', type, fail_type)

    # allow_none not a bool:
    fail_bool = 0
    e = raises(AssertionError, f, value, type_, name, allow_none=fail_bool)
    assert str(e) == type_format % ('allow_none', bool, fail_bool)


def test_check_isinstance():
    """
    Tests the `errors.check_isinstance` function.
    """
    f = errors.check_isinstance
    value = 'How are you?'
    type_ = str
    name = 'greeting'

    # Should pass:
    assert value is f(value, type_, name)
    assert value is f(value, basestring, name)
    assert None is f(None, type_, name, allow_none=True)

    # Should raise TypeError
    check_TypeError(f, None, type_, name)
    check_TypeError(f, value, unicode, name)

    # name not an str
    fail_name = unicode(name)
    e = raises(AssertionError, f, value, type_, fail_name)
    assert str(e) == type_format % ('name', str, fail_name)

    # type_ not a type:
    fail_type = 42
    e = raises(AssertionError, f, value, fail_type, name)
    assert str(e) == type_format % ('type_', type, fail_type)

    # allow_none not a bool:
    fail_bool = 0
    e = raises(AssertionError, f, value, type_, name, allow_none=fail_bool)
    assert str(e) == type_format % ('allow_none', bool, fail_bool)


class test_IPAError(ClassChecker):
    """
    Tests the `errors.IPAError` exception.
    """
    _cls = errors.IPAError

    def test_class(self):
        assert self.cls.__bases__ == (Exception,)

    def test_init(self):
        """
        Tests the `errors.IPAError.__init__` method.
        """
        args = ('one fish', 'two fish')
        e = self.cls(*args)
        assert e.args == args
        assert self.cls().args == tuple()

    def test_str(self):
        """
        Tests the `errors.IPAError.__str__` method.
        """
        f = 'The %s color is %s.'
        class custom_error(self.cls):
            format = f
        for args in [('sexiest', 'red'), ('most-batman-like', 'black')]:
            e = custom_error(*args)
            assert e.args == args
            assert str(e) == f % args


class test_ValidationError(ClassChecker):
    """
    Tests the `errors.ValidationError` exception.
    """
    _cls = errors.ValidationError

    def test_class(self):
        assert self.cls.__bases__ == (errors.IPAError,)

    def test_init(self):
        """
        Tests the `errors.ValidationError.__init__` method.
        """
        name = 'login'
        value = 'Whatever'
        error = 'Must be lowercase.'
        for index in (None, 3):
            e = self.cls(name, value, error, index=index)
            assert e.name is name
            assert e.value is value
            assert e.error is error
            assert e.index is index
            assert str(e) == 'invalid %r value %r: %s' % (name, value, error)
        # Check that index default is None:
        assert self.cls(name, value, error).index is None
        # Check non str name raises AssertionError:
        raises(AssertionError, self.cls, unicode(name), value, error)
        # Check non int index raises AssertionError:
        raises(AssertionError, self.cls, name, value, error, index=5.0)
        # Check negative index raises AssertionError:
        raises(AssertionError, self.cls, name, value, error, index=-2)


class test_ConversionError(ClassChecker):
    """
    Tests the `errors.ConversionError` exception.
    """
    _cls = errors.ConversionError

    def test_class(self):
        assert self.cls.__bases__ == (errors.ValidationError,)

    def test_init(self):
        """
        Tests the `errors.ConversionError.__init__` method.
        """
        name = 'some_arg'
        value = '42.0'
        class type_(object):
            conversion_error = 'Not an integer'
        for index in (None, 7):
            e = self.cls(name, value, type_, index=index)
            assert e.name is name
            assert e.value is value
            assert e.type is type_
            assert e.error is type_.conversion_error
            assert e.index is index
            assert str(e) == 'invalid %r value %r: %s' % (name, value,
                type_.conversion_error)
        # Check that index default is None:
        assert self.cls(name, value, type_).index is None


class test_RuleError(ClassChecker):
    """
    Tests the `errors.RuleError` exception.
    """
    _cls = errors.RuleError

    def test_class(self):
        assert self.cls.__bases__ == (errors.ValidationError,)

    def test_init(self):
        """
        Tests the `errors.RuleError.__init__` method.
        """
        name = 'whatever'
        value = 'The smallest weird number.'
        def my_rule(value):
            return 'Value is bad.'
        error = my_rule(value)
        for index in (None, 42):
            e = self.cls(name, value, error, my_rule, index=index)
            assert e.name is name
            assert e.value is value
            assert e.error is error
            assert e.rule is my_rule
        # Check that index default is None:
        assert self.cls(name, value, error, my_rule).index is None


class test_RequirementError(ClassChecker):
    """
    Tests the `errors.RequirementError` exception.
    """
    _cls = errors.RequirementError

    def test_class(self):
        assert self.cls.__bases__ == (errors.ValidationError,)

    def test_init(self):
        """
        Tests the `errors.RequirementError.__init__` method.
        """
        name = 'givenname'
        e = self.cls(name)
        assert e.name is name
        assert e.value is None
        assert e.error == 'Required'
        assert e.index is None
