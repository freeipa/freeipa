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
Test the `ipalib.parameter` module.
"""

from types import NoneType
from tests.util import raises, ClassChecker, read_only
from tests.util import dummy_ugettext, assert_equal
from tests.data import binary_bytes, utf8_bytes, unicode_str
from ipalib import parameter, request, errors2
from ipalib.constants import TYPE_ERROR, CALLABLE_ERROR, NULLS


class test_DefaultFrom(ClassChecker):
    """
    Test the `ipalib.parameter.DefaultFrom` class.
    """
    _cls = parameter.DefaultFrom

    def test_init(self):
        """
        Test the `ipalib.parameter.DefaultFrom.__init__` method.
        """
        def callback(*args):
            return args
        keys = ('givenname', 'sn')
        o = self.cls(callback, *keys)
        assert read_only(o, 'callback') is callback
        assert read_only(o, 'keys') == keys
        lam = lambda first, last: first[0] + last
        o = self.cls(lam)
        assert read_only(o, 'keys') == ('first', 'last')

        # Test that TypeError is raised when callback isn't callable:
        e = raises(TypeError, self.cls, 'whatever')
        assert str(e) == CALLABLE_ERROR % ('callback', 'whatever', str)

        # Test that TypeError is raised when a key isn't an str:
        e = raises(TypeError, self.cls, callback, 'givenname', 17)
        assert str(e) == TYPE_ERROR % ('keys', str, 17, int)

    def test_call(self):
        """
        Test the `ipalib.parameter.DefaultFrom.__call__` method.
        """
        def callback(givenname, sn):
            return givenname[0] + sn[0]
        keys = ('givenname', 'sn')
        o = self.cls(callback, *keys)
        kw = dict(
            givenname='John',
            sn='Public',
            hello='world',
        )
        assert o(**kw) == 'JP'
        assert o() is None
        for key in ('givenname', 'sn'):
            kw_copy = dict(kw)
            del kw_copy[key]
            assert o(**kw_copy) is None

        # Test using implied keys:
        o = self.cls(lambda first, last: first[0] + last)
        assert o(first='john', last='doe') == 'jdoe'
        assert o(first='', last='doe') is None
        assert o(one='john', two='doe') is None

        # Test that co_varnames slice is used:
        def callback2(first, last):
            letter = first[0]
            return letter + last
        o = self.cls(callback2)
        assert o.keys == ('first', 'last')
        assert o(first='john', last='doe') == 'jdoe'


def test_parse_param_spec():
    """
    Test the `ipalib.parameter.parse_param_spec` function.
    """
    f = parameter.parse_param_spec
    assert f('name') == ('name', dict(required=True, multivalue=False))
    assert f('name?') == ('name', dict(required=False, multivalue=False))
    assert f('name*') == ('name', dict(required=False, multivalue=True))
    assert f('name+') == ('name', dict(required=True, multivalue=True))

    # Make sure other "funny" endings are *not* treated special:
    assert f('name^') == ('name^', dict(required=True, multivalue=False))

    # Test that TypeError is raised if spec isn't an str:
    e = raises(TypeError, f, u'name?')
    assert str(e) == TYPE_ERROR % ('spec', str, u'name?', unicode)

    # Test that ValueError is raised if len(spec) < 2:
    e = raises(ValueError, f, 'n')
    assert str(e) == "spec must be at least 2 characters; got 'n'"


class DummyRule(object):
    def __init__(self, error=None):
        assert error is None or type(error) is unicode
        self.error = error
        self.reset()

    def __call__(self, *args):
        self.calls.append(args)
        return self.error

    def reset(self):
        self.calls = []


class test_Param(ClassChecker):
    """
    Test the `ipalib.parameter.Param` class.
    """
    _cls = parameter.Param

    def test_init(self):
        """
        Test the `ipalib.parameter.Param.__init__` method.
        """
        name = 'my_param'
        o = self.cls(name)
        assert o.param_spec is name
        assert o.name is name
        assert o.nice == "Param('my_param')"
        assert o.__islocked__() is True

        # Test default rules:
        assert o.rules == tuple()
        assert o.class_rules == tuple()
        assert o.all_rules == tuple()

        # Test default kwarg values:
        assert o.cli_name is name
        assert o.label is None
        assert o.doc == ''
        assert o.required is True
        assert o.multivalue is False
        assert o.primary_key is False
        assert o.normalizer is None
        assert o.default is None
        assert o.default_from is None
        assert o.create_default is None
        assert o._get_default is None
        assert o.flags == frozenset()

        # Test that ValueError is raised when a kwarg from a subclass
        # conflicts with an attribute:
        class Subclass(self.cls):
            kwargs = self.cls.kwargs + (
                ('convert', callable, None),
            )
        e = raises(ValueError, Subclass, name)
        assert str(e) == "kwarg 'convert' conflicts with attribute on Subclass"

        # Test type validation of keyword arguments:
        class Subclass(self.cls):
            kwargs = self.cls.kwargs + (
                ('extra1', bool, True),
                ('extra2', str, 'Hello'),
                ('extra3', (int, float), 42),
                ('extra4', callable, lambda whatever: whatever + 7),
            )
        o = Subclass('my_param')  # Test with no **kw:
        for (key, kind, default) in o.kwargs:
            # Test with a type invalid for all:
            value = object()
            kw = {key: value}
            e = raises(TypeError, Subclass, 'my_param', **kw)
            if kind is callable:
                assert str(e) == CALLABLE_ERROR % (key, value, type(value))
            else:
                assert str(e) == TYPE_ERROR % (key, kind, value, type(value))
            # Test with None:
            kw = {key: None}
            Subclass('my_param', **kw)

        # Test when using unknown kwargs:
        e = raises(TypeError, self.cls, 'my_param',
            flags=['hello', 'world'],
            whatever=u'Hooray!',
        )
        assert str(e) == \
            "Param('my_param'): takes no such kwargs: 'whatever'"
        e = raises(TypeError, self.cls, 'my_param', great='Yes', ape='he is!')
        assert str(e) == \
            "Param('my_param'): takes no such kwargs: 'ape', 'great'"

        # Test that ValueError is raised if you provide both default_from and
        # create_default:
        e = raises(ValueError, self.cls, 'my_param',
            default_from=lambda first, last: first[0] + last,
            create_default=lambda **kw: 'The Default'
        )
        assert str(e) == '%s: cannot have both %r and %r' % (
            "Param('my_param')", 'default_from', 'create_default',
        )

        # Test that _get_default gets set:
        call1 = lambda first, last: first[0] + last
        call2 = lambda **kw: 'The Default'
        o = self.cls('my_param', default_from=call1)
        assert o.default_from.callback is call1
        assert o._get_default is o.default_from
        o = self.cls('my_param', create_default=call2)
        assert o.create_default is call2
        assert o._get_default is call2

    def test_repr(self):
        """
        Test the `ipalib.parameter.Param.__repr__` method.
        """
        for name in ['name', 'name?', 'name*', 'name+']:
            o = self.cls(name)
            assert repr(o) == 'Param(%r)' % name
        o = self.cls('name', required=False)
        assert repr(o) == "Param('name', required=False)"
        o = self.cls('name', multivalue=True)
        assert repr(o) == "Param('name', multivalue=True)"

    def test_get_label(self):
        """
        Test the `ipalib.parameter.get_label` method.
        """
        context = request.context
        cli_name = 'the_cli_name'
        message = 'The Label'
        label = lambda _: _(message)
        o = self.cls('name', cli_name=cli_name, label=label)
        assert o.label is label

        ## Scenario 1: label=callable (a lambda form)

        # Test with no context.ugettext:
        assert not hasattr(context, 'ugettext')
        assert_equal(o.get_label(), u'The Label')

        # Test with dummy context.ugettext:
        assert not hasattr(context, 'ugettext')
        dummy = dummy_ugettext()
        context.ugettext = dummy
        assert o.get_label() is dummy.translation
        assert dummy.message is message
        del context.ugettext

        ## Scenario 2: label=None
        o = self.cls('name', cli_name=cli_name)
        assert o.label is None

        # Test with no context.ugettext:
        assert not hasattr(context, 'ugettext')
        assert_equal(o.get_label(), u'the_cli_name')

        # Test with dummy context.ugettext:
        assert not hasattr(context, 'ugettext')
        dummy = dummy_ugettext()
        context.ugettext = dummy
        assert_equal(o.get_label(), u'the_cli_name')
        assert not hasattr(dummy, 'message')

        # Cleanup
        del context.ugettext
        assert not hasattr(context, 'ugettext')

    def test_convert(self):
        """
        Test the `ipalib.parameter.Param.convert` method.
        """
        okay = ('Hello', u'Hello', 0, 4.2, True, False)
        class Subclass(self.cls):
            def _convert_scalar(self, value, index=None):
                return value

        # Test when multivalue=False:
        o = Subclass('my_param')
        for value in NULLS:
            assert o.convert(value) is None
        for value in okay:
            assert o.convert(value) is value

        # Test when multivalue=True:
        o = Subclass('my_param', multivalue=True)
        for value in NULLS:
            assert o.convert(value) is None
        assert o.convert(okay) == okay
        assert o.convert(NULLS) is None
        assert o.convert(okay + NULLS) == okay
        assert o.convert(NULLS + okay) == okay
        for value in okay:
            assert o.convert(value) == (value,)
            assert o.convert([None, value]) == (value,)
            assert o.convert([value, None]) == (value,)

    def test_convert_scalar(self):
        """
        Test the `ipalib.parameter.Param._convert_scalar` method.
        """
        o = self.cls('my_param')
        e = raises(NotImplementedError, o._convert_scalar, 'some value')
        assert str(e) == 'Param._convert_scalar()'
        class Subclass(self.cls):
            pass
        o = Subclass('my_param')
        e = raises(NotImplementedError, o._convert_scalar, 'some value')
        assert str(e) == 'Subclass._convert_scalar()'

    def test_validate(self):
        """
        Test the `ipalib.parameter.Param.validate` method.
        """

        # Test with required=True/False:
        o = self.cls('my_param')
        assert o.required is True
        e = raises(errors2.RequirementError, o.validate, None)
        assert e.name == 'my_param'
        o = self.cls('my_param', required=False)
        assert o.required is False
        assert o.validate(None) is None

        # Test with multivalue=True:
        o = self.cls('my_param', multivalue=True)
        e = raises(TypeError, o.validate, [])
        assert str(e) == TYPE_ERROR % ('value', tuple, [], list)
        e = raises(ValueError, o.validate, tuple())
        assert str(e) == 'value: empty tuple must be converted to None'

        # Test with wrong (scalar) type:
        e = raises(TypeError, o.validate, (None, None, 42, None))
        assert str(e) == TYPE_ERROR % ('value[2]', NoneType, 42, int)
        o = self.cls('my_param')
        e = raises(TypeError, o.validate, 'Hello')
        assert str(e) == TYPE_ERROR % ('value', NoneType, 'Hello', str)

        class Example(self.cls):
            type = int

        # Test with some rules and multivalue=False
        pass1 = DummyRule()
        pass2 = DummyRule()
        fail = DummyRule(u'no good')
        o = Example('example', pass1, pass2)
        assert o.multivalue is False
        assert o.validate(11) is None
        assert pass1.calls == [(request.ugettext, 11)]
        assert pass2.calls == [(request.ugettext, 11)]
        pass1.reset()
        pass2.reset()
        o = Example('example', pass1, pass2, fail)
        e = raises(errors2.ValidationError, o.validate, 42)
        assert e.name == 'example'
        assert e.error == u'no good'
        assert e.index is None
        assert pass1.calls == [(request.ugettext, 42)]
        assert pass2.calls == [(request.ugettext, 42)]
        assert fail.calls == [(request.ugettext, 42)]

        # Test with some rules and multivalue=True
        pass1 = DummyRule()
        pass2 = DummyRule()
        fail = DummyRule(u'this one is not good')
        o = Example('example', pass1, pass2, multivalue=True)
        assert o.multivalue is True
        assert o.validate((3, 9)) is None
        assert pass1.calls == [
            (request.ugettext, 3),
            (request.ugettext, 9),
        ]
        assert pass2.calls == [
            (request.ugettext, 3),
            (request.ugettext, 9),
        ]
        pass1.reset()
        pass2.reset()
        o = Example('multi_example', pass1, pass2, fail, multivalue=True)
        assert o.multivalue is True
        e = raises(errors2.ValidationError, o.validate, (3, 9))
        assert e.name == 'multi_example'
        assert e.error == u'this one is not good'
        assert e.index == 0
        assert pass1.calls == [(request.ugettext, 3)]
        assert pass2.calls == [(request.ugettext, 3)]
        assert fail.calls == [(request.ugettext, 3)]

    def test_validate_scalar(self):
        """
        Test the `ipalib.parameter.Param._validate_scalar` method.
        """
        class MyParam(self.cls):
            type = bool
        okay = DummyRule()
        o = MyParam('my_param', okay)

        # Test that TypeError is appropriately raised:
        e = raises(TypeError, o._validate_scalar, 0)
        assert str(e) == TYPE_ERROR % ('value', bool, 0, int)
        e = raises(TypeError, o._validate_scalar, 'Hi', index=4)
        assert str(e) == TYPE_ERROR % ('value[4]', bool, 'Hi', str)
        e = raises(TypeError, o._validate_scalar, True, index=3.0)
        assert str(e) == TYPE_ERROR % ('index', int, 3.0, float)

        # Test with passing rule:
        assert o._validate_scalar(True, index=None) is None
        assert o._validate_scalar(False, index=None) is None
        assert okay.calls == [
            (request.ugettext, True),
            (request.ugettext, False),
        ]

        # Test with a failing rule:
        okay = DummyRule()
        fail = DummyRule(u'this describes the error')
        o = MyParam('my_param', okay, fail)
        e = raises(errors2.ValidationError, o._validate_scalar, True)
        assert e.name == 'my_param'
        assert e.error == u'this describes the error'
        assert e.index is None
        e = raises(errors2.ValidationError, o._validate_scalar, False, index=2)
        assert e.name == 'my_param'
        assert e.error == u'this describes the error'
        assert e.index == 2
        assert okay.calls == [
            (request.ugettext, True),
            (request.ugettext, False),
        ]
        assert fail.calls == [
            (request.ugettext, True),
            (request.ugettext, False),
        ]

    def test_get_default(self):
        """
        Test the `ipalib.parameter.Param._get_default` method.
        """
        class PassThrough(object):
            value = None

            def __call__(self, value):
                assert self.value is None
                assert value is not None
                self.value = value
                return value

            def reset(self):
                assert self.value is not None
                self.value = None

        class Str(self.cls):
            type = unicode

            def __init__(self, name, **kw):
                self._convert_scalar = PassThrough()
                super(Str, self).__init__(name, **kw)

        # Test with only a static default:
        o = Str('my_str',
            normalizer=PassThrough(),
            default=u'Static Default',
        )
        assert_equal(o.get_default(), u'Static Default')
        assert o._convert_scalar.value is None
        assert o.normalizer.value is None

        # Test with default_from:
        o = Str('my_str',
            normalizer=PassThrough(),
            default=u'Static Default',
            default_from=lambda first, last: first[0] + last,
        )
        assert_equal(o.get_default(), u'Static Default')
        assert o._convert_scalar.value is None
        assert o.normalizer.value is None
        default = o.get_default(first=u'john', last='doe')
        assert_equal(default, u'jdoe')
        assert o._convert_scalar.value is default
        assert o.normalizer.value is default

        # Test with create_default:
        o = Str('my_str',
            normalizer=PassThrough(),
            default=u'Static Default',
            create_default=lambda **kw: u'The created default',
        )
        default = o.get_default(first=u'john', last='doe')
        assert_equal(default, u'The created default')
        assert o._convert_scalar.value is default
        assert o.normalizer.value is default


class test_Bytes(ClassChecker):
    """
    Test the `ipalib.parameter.Bytes` class.
    """
    _cls = parameter.Bytes

    def test_init(self):
        """
        Test the `ipalib.parameter.Bytes.__init__` method.
        """
        o = self.cls('my_bytes')
        assert o.type is str
        assert o.rules == tuple()
        assert o.class_rules == tuple()
        assert o.all_rules == tuple()
        assert o.minlength is None
        assert o.maxlength is None
        assert o.length is None
        assert o.pattern is None

        # Test mixing length with minlength or maxlength:
        o = self.cls('my_bytes', length=5)
        assert o.length == 5
        assert len(o.class_rules) == 1
        assert len(o.rules) == 0
        assert len(o.all_rules) == 1
        permutations = [
            dict(minlength=3),
            dict(maxlength=7),
            dict(minlength=3, maxlength=7),
        ]
        for kw in permutations:
            o = self.cls('my_bytes', **kw)
            assert len(o.class_rules) == len(kw)
            assert len(o.rules) == 0
            assert len(o.all_rules) == len(kw)
            for (key, value) in kw.iteritems():
                assert getattr(o, key) == value
            e = raises(ValueError, self.cls, 'my_bytes', length=5, **kw)
            assert str(e) == \
                "Bytes('my_bytes'): cannot mix length with minlength or maxlength"

        # Test when minlength or maxlength are less than 1:
        e = raises(ValueError, self.cls, 'my_bytes', minlength=0)
        assert str(e) == "Bytes('my_bytes'): minlength must be >= 1; got 0"
        e = raises(ValueError, self.cls, 'my_bytes', maxlength=0)
        assert str(e) == "Bytes('my_bytes'): maxlength must be >= 1; got 0"

        # Test when minlength > maxlength:
        e = raises(ValueError, self.cls, 'my_bytes', minlength=22, maxlength=15)
        assert str(e) == \
            "Bytes('my_bytes'): minlength > maxlength (minlength=22, maxlength=15)"

        # Test when minlength == maxlength
        e = raises(ValueError, self.cls, 'my_bytes', minlength=7, maxlength=7)
        assert str(e) == \
            "Bytes('my_bytes'): minlength == maxlength; use length=7 instead"

    def test_rule_minlength(self):
        """
        Test the `ipalib.parameter.Bytes._rule_minlength` method.
        """
        name = 'My Bytes'
        o = self.cls('my_bytes', minlength=3)
        assert o.minlength == 3
        m = o._rule_minlength
        translation = u'name=%(name)r, minlength=%(minlength)r'
        dummy = dummy_ugettext(translation)
        assert dummy.translation is translation

        # Test with passing values:
        for value in ('abc', 'four', '12345'):
            assert m(dummy, name, value) is None
            assert not hasattr(dummy, 'message')

        # Test with a failing value:
        assert_equal(
            m(dummy, name, 'ab'),
            translation % dict(name=name, minlength=3),
        )
        assert dummy.message == \
            '%(name)s must be at least %(minlength)d bytes'

    def test_rule_maxlength(self):
        """
        Test the `ipalib.parameter.Bytes._rule_maxlength` method.
        """
        name = 'My Bytes'
        o = self.cls('my_bytes', maxlength=4)
        assert o.maxlength == 4
        m = o._rule_maxlength
        translation = u'name=%(name)r, maxlength=%(maxlength)r'
        dummy = dummy_ugettext(translation)
        assert dummy.translation is translation

        # Test with passing values:
        for value in ('ab', '123', 'four'):
            assert m(dummy, name, value) is None
            assert not hasattr(dummy, 'message')

        # Test with a failing value:
        assert_equal(
            m(dummy, name, '12345'),
            translation % dict(name=name, maxlength=4),
        )
        assert dummy.message == \
            '%(name)s can be at most %(maxlength)d bytes'

    def test_rule_length(self):
        """
        Test the `ipalib.parameter.Bytes._rule_length` method.
        """
        name = 'My Bytes'
        o = self.cls('my_bytes', length=4)
        assert o.length == 4
        m = o._rule_length
        translation = u'name=%(name)r, length=%(length)r'
        dummy = dummy_ugettext(translation)
        assert dummy.translation is translation

        # Test with passing values:
        for value in ('1234', 'four'):
            assert m(dummy, name, value) is None
            assert not hasattr(dummy, 'message')

        # Test with failing values:
        for value in ('ab', '123', '12345', 'abcdef'):
            assert_equal(
                m(dummy, name, value),
                translation % dict(name=name, length=4),
            )
            assert dummy.message == \
                '%(name)s must be exactly %(length)d bytes'
            dummy = dummy_ugettext(translation)


class test_Str(ClassChecker):
    """
    Test the `ipalib.parameter.Str` class.
    """
    _cls = parameter.Str

    def test_init(self):
        """
        Test the `ipalib.parameter.Str.__init__` method.
        """
        o = self.cls('my_str')
        assert o.type is unicode
        assert o.minlength is None
        assert o.maxlength is None
        assert o.length is None
        assert o.pattern is None

    def test_convert_scalar(self):
        """
        Test the `ipalib.parameter.Str._convert_scalar` method.
        """
        o = self.cls('my_str')
        for value in (u'Hello', 42, 1.2, True):
            assert o._convert_scalar(value) == unicode(value)
        for value in ('Hello', (None,), [u'42', '42'], dict(hello=u'world')):
            e = raises(TypeError, o._convert_scalar, value)
            assert str(e) == \
                'Can only implicitly convert int, float, or bool; got %r' % value

    def test_rule_minlength(self):
        """
        Test the `ipalib.parameter.Str._rule_minlength` method.
        """
        name = 'My Str'
        o = self.cls('my_str', minlength=3)
        assert o.minlength == 3
        m = o._rule_minlength
        translation = u'name=%(name)r, minlength=%(minlength)r'
        dummy = dummy_ugettext(translation)
        assert dummy.translation is translation

        # Test with passing values:
        for value in (u'abc', u'four', u'12345'):
            assert m(dummy, name, value) is None
            assert not hasattr(dummy, 'message')

        # Test with a failing value:
        assert_equal(
            m(dummy, name, u'ab'),
            translation % dict(name=name, minlength=3),
        )
        assert dummy.message == \
            '%(name)s must be at least %(minlength)d characters'

    def test_rule_maxlength(self):
        """
        Test the `ipalib.parameter.Str._rule_maxlength` method.
        """
        name = 'My Str'
        o = self.cls('my_str', maxlength=4)
        assert o.maxlength == 4
        m = o._rule_maxlength
        translation = u'name=%(name)r, maxlength=%(maxlength)r'
        dummy = dummy_ugettext(translation)
        assert dummy.translation is translation

        # Test with passing values:
        for value in (u'ab', u'123', u'four'):
            assert m(dummy, name, value) is None
            assert not hasattr(dummy, 'message')

        # Test with a failing value:
        assert_equal(
            m(dummy, name, u'12345'),
            translation % dict(name=name, maxlength=4),
        )
        assert dummy.message == \
            '%(name)s can be at most %(maxlength)d characters'

    def test_rule_length(self):
        """
        Test the `ipalib.parameter.Str._rule_length` method.
        """
        name = 'My Str'
        o = self.cls('my_str', length=4)
        assert o.length == 4
        m = o._rule_length
        translation = u'name=%(name)r, length=%(length)r'
        dummy = dummy_ugettext(translation)
        assert dummy.translation is translation

        # Test with passing values:
        for value in (u'1234', u'four'):
            assert m(dummy, name, value) is None
            assert not hasattr(dummy, 'message')

        # Test with failing values:
        for value in (u'ab', u'123', u'12345', u'abcdef'):
            assert_equal(
                m(dummy, name, value),
                translation % dict(name=name, length=4),
            )
            assert dummy.message == \
                '%(name)s must be exactly %(length)d characters'
            dummy = dummy_ugettext(translation)


def test_create_param():
    """
    Test the `ipalib.parameter.create_param` function.
    """
    f = parameter.create_param

    # Test that Param instances are returned unchanged:
    params = (
        parameter.Param('one?'),
        parameter.Int('two+'),
        parameter.Str('three*'),
        parameter.Bytes('four'),
    )
    for p in params:
        assert f(p) is p

    # Test that the spec creates an Str instance:
    for spec in ('one?', 'two+', 'three*', 'four'):
        (name, kw) = parameter.parse_param_spec(spec)
        p = f(spec)
        assert p.param_spec is spec
        assert p.name == name
        assert p.required is kw['required']
        assert p.multivalue is kw['multivalue']

    # Test that TypeError is raised when spec is neither a Param nor a str:
    for spec in (u'one', 42, parameter.Param, parameter.Str):
        e = raises(TypeError, f, spec)
        assert str(e) == \
            TYPE_ERROR % ('spec', (str, parameter.Param), spec, type(spec))
