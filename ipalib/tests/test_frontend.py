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
Unit tests for `ipalib.frontend` module.
"""

from tstutil import raises, getitem, no_set, no_del, read_only, ClassChecker
from tstutil import check_TypeError
from ipalib import frontend, plugable, errors, ipa_types


def test_RULE_FLAG():
    assert frontend.RULE_FLAG == 'validation_rule'


def test_rule():
    """
    Tests the `frontend.rule` function.
    """
    flag = frontend.RULE_FLAG
    rule = frontend.rule
    def my_func():
        pass
    assert not hasattr(my_func, flag)
    rule(my_func)
    assert getattr(my_func, flag) is True
    @rule
    def my_func2():
        pass
    assert getattr(my_func2, flag) is True


def test_is_rule():
    """
    Tests the `frontend.is_rule` function.
    """
    is_rule = frontend.is_rule
    flag = frontend.RULE_FLAG

    class no_call(object):
        def __init__(self, value):
            if value is not None:
                assert value in (True, False)
                setattr(self, flag, value)

    class call(no_call):
        def __call__(self):
            pass

    assert is_rule(call(True))
    assert not is_rule(no_call(True))
    assert not is_rule(call(False))
    assert not is_rule(call(None))


class test_DefaultFrom(ClassChecker):
    """
    Tests the `frontend.DefaultFrom` class.
    """
    _cls = frontend.DefaultFrom

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        """
        Tests the `frontend.DefaultFrom.__init__` method.
        """
        def callback(*args):
            return args
        keys = ('givenname', 'sn')
        o = self.cls(callback, *keys)
        assert read_only(o, 'callback') is callback
        assert read_only(o, 'keys') == keys

    def test_call(self):
        """
        Tests the `frontend.DefaultFrom.__call__` method.
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


class test_Option(ClassChecker):
    """
    Tests the `frontend.Param` class.
    """
    _cls = frontend.Param

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        """
        Tests the `frontend.Param.__init__` method.
        """
        name = 'sn'
        type_ = ipa_types.Unicode()
        o = self.cls(name, type_)
        assert o.__islocked__() is True
        assert read_only(o, 'name') is name
        assert read_only(o, 'type') is type_
        assert read_only(o, 'doc') == ''
        assert read_only(o, 'required') is False
        assert read_only(o, 'multivalue') is False
        assert read_only(o, 'default') is None
        assert read_only(o, 'default_from') is None
        assert read_only(o, 'rules') == (type_.validate,)

    def test_convert(self):
        """
        Tests the `frontend.Param.convert` method.
        """
        name = 'some_number'
        type_ = ipa_types.Int()
        okay = (7, 7L, 7.0, ' 7 ')
        fail = ('7.0', '7L', 'whatever', object)

        # Scenario 1: multivalue=False
        o = self.cls(name, type_)
        e = raises(TypeError, o.convert, None)
        assert str(e) == 'value cannot be None'
        for value in okay:
            new = o.convert(value)
            assert new == 7
            assert type(new) is int
        for value in fail:
            e = raises(errors.ConversionError, o.convert, value)
            assert e.name is name
            assert e.value is value
            assert e.error is type_.conversion_error
            assert e.index is None

        # Scenario 2: multivalue=True
        o = self.cls(name, type_, multivalue=True)
        for none in [None, (7, None)]:
            e = raises(TypeError, o.convert, none)
            assert str(e) == 'value cannot be None'
        for value in okay:
            assert o.convert((value,)) == (7,)
            assert o.convert([value]) == (7,)
        assert o.convert(okay) == tuple(int(v) for v in okay)
        cnt = 5
        for value in fail:
            for i in xrange(cnt):
                others = list(7 for x in xrange(cnt))
                others[i] = value
                for v in [tuple(others), list(others)]:
                    e = raises(errors.ConversionError, o.convert, v)
                    assert e.name is name
                    assert e.value is value
                    assert e.error is type_.conversion_error
                    assert e.index == i

    def test_normalize(self):
        """
        Tests the `frontend.Param.normalize` method.
        """
        name = 'sn'
        t = ipa_types.Unicode()
        callback = lambda value: value.lower()
        values = (None, u'Hello', (u'Hello',), 'hello', ['hello'])

        # Scenario 1: multivalue=False, normalize=None
        o = self.cls(name, t)
        for v in values:
            # When normalize=None, value is returned, no type checking:
            assert o.normalize(v) is v

        # Scenario 2: multivalue=False, normalize=callback
        o = self.cls(name, t, normalize=callback)
        for v in (u'Hello', u'hello', 'Hello'): # Okay
            assert o.normalize(v) == 'hello'
        for v in [None, 42, (u'Hello',)]: # Not basestring
            check_TypeError(v, basestring, 'value', o.normalize, v)

        # Scenario 3: multivalue=True, normalize=None
        o = self.cls(name, t, multivalue=True)
        for v in values:
            # When normalize=None, value is returned, no type checking:
            assert o.normalize(v) is v

        # Scenario 4: multivalue=True, normalize=callback
        o = self.cls(name, t, multivalue=True, normalize=callback)
        for value in [(u'Hello',), (u'hello',), 'Hello', ['Hello']]: # Okay
            assert o.normalize(value) == (u'hello',)
        fail = 42 # Not basestring
        for v in [fail, [fail], (u'Hello', fail)]: # Non unicode member
            check_TypeError(fail, basestring, 'value', o.normalize, v)

    def test_validate(self):
        """
        Tests the `frontend.Param.validate` method.
        """
        name = 'sn'
        type_ = ipa_types.Unicode()
        def case_rule(value):
            if not value.islower():
                return 'Must be lower case'
        my_rules = (case_rule,)
        okay = u'whatever'
        fail_case = u'Whatever'
        fail_type = 'whatever'

        # Scenario 1: multivalue=False
        o = self.cls(name, type_, rules=my_rules)
        assert o.rules == (type_.validate, case_rule)
        o.validate(okay)
        e = raises(errors.RuleError, o.validate, fail_case)
        assert e.name is name
        assert e.value is fail_case
        assert e.error == 'Must be lower case'
        assert e.rule is case_rule
        assert e.index is None
        check_TypeError(fail_type, unicode, 'value', o.validate, fail_type)

        ## Scenario 2: multivalue=True
        o = self.cls(name, type_, multivalue=True, rules=my_rules)
        o.validate((okay,))
        cnt = 5
        for i in xrange(cnt):
            others = list(okay for x in xrange(cnt))
            others[i] = fail_case
            value = tuple(others)
            e = raises(errors.RuleError, o.validate, value)
            assert e.name is name
            assert e.value is fail_case
            assert e.error == 'Must be lower case'
            assert e.rule is case_rule
            assert e.index == i
        for not_tuple in (okay, [okay]):
            check_TypeError(not_tuple, tuple, 'value', o.validate, not_tuple)
        for has_str in [(fail_type,), (okay, fail_type)]:
            check_TypeError(fail_type, unicode, 'value', o.validate, has_str)

    def test_get_default(self):
        """
        Tests the `frontend.Param.get_default` method.
        """
        name = 'greeting'
        type_ = ipa_types.Unicode()
        default = u'Hello, world!'
        default_from = frontend.DefaultFrom(
            lambda first, last: u'Hello, %s %s!' % (first, last),
            'first', 'last'
        )

        # Scenario 1: multivalue=False
        o = self.cls(name, type_,
            default=default,
            default_from=default_from,
        )
        assert o.default is default
        assert o.default_from is default_from
        assert o.get_default() == default
        assert o.get_default(first='John', last='Doe') == 'Hello, John Doe!'

        # Scenario 2: multivalue=True
        default = (default,)
        o = self.cls(name, type_,
            default=default,
            default_from=default_from,
            multivalue=True,
        )
        assert o.default is default
        assert o.default_from is default_from
        assert o.get_default() == default
        assert o.get_default(first='John', last='Doe') == ('Hello, John Doe!',)

    def test_get_value(self):
        """
        Tests the `frontend.Param.get_values` method.
        """
        name = 'status'
        values = (u'Active', u'Inactive')
        o = self.cls(name, ipa_types.Unicode())
        assert o.get_values() == tuple()
        o = self.cls(name, ipa_types.Enum(*values))
        assert o.get_values() == values


def test_create_param():
    """
    Test the `frontend.create_param` function.
    """
    f = frontend.create_param
    for name in ['arg', 'arg?', 'arg*', 'arg+']:
        o = f(name)
        assert type(o) is frontend.Param
        assert type(o.type) is ipa_types.Unicode
        assert o.name == 'arg'
        assert f(o) is o
    o = f('arg')
    assert o.required is True
    assert o.multivalue is False
    o = f('arg?')
    assert o.required is False
    assert o.multivalue is False
    o = f('arg*')
    assert o.required is False
    assert o.multivalue is True
    o = f('arg+')
    assert o.required is True
    assert o.multivalue is True


class test_Command(ClassChecker):
    """
    Tests the `frontend.Command` class.
    """
    _cls = frontend.Command

    def get_subcls(self):
        class Rule(object):
            def __init__(self, name):
                self.name = name

            def __call__(self, value):
                if value != self.name:
                    return 'must equal %s' % self.name

        default_from = frontend.DefaultFrom(
                lambda arg: arg,
                'default_from'
        )
        normalize = lambda value: value.lower()
        type_ = ipa_types.Unicode()

        class example(self.cls):
            takes_options = (
                frontend.Param('option0', type_,
                    normalize=normalize,
                    default_from=default_from,
                    rules=(Rule('option0'),)
                ),
                frontend.Param('option1', type_,
                    normalize=normalize,
                    default_from=default_from,
                    rules=(Rule('option1'),),
                    required=True,
                ),
            )
        return example

    def get_instance(self, args=tuple(), options=tuple()):
        """
        Helper method used to test args and options.
        """
        class example(self.cls):
            takes_args = args
            takes_options = options
        o = example()
        o.finalize()
        return o

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert self.cls.takes_options == tuple()
        assert self.cls.takes_args == tuple()

    def test_get_args(self):
        """
        Tests the `frontend.Command.get_args` method.
        """
        assert list(self.cls().get_args()) == []
        args = ('login', 'stuff')
        o = self.get_instance(args=args)
        assert o.get_args() is args

    def test_get_options(self):
        """
        Tests the `frontend.Command.get_options` method.
        """
        assert list(self.cls().get_options()) == []
        options = ('verbose', 'debug')
        o = self.get_instance(options=options)
        assert o.get_options() is options

    def test_args(self):
        """
        Tests the ``Command.args`` instance attribute.
        """
        assert 'args' in self.cls.__public__ # Public
        assert self.cls().args is None
        o = self.cls()
        o.finalize()
        assert type(o.args) is plugable.NameSpace
        assert len(o.args) == 0
        args = ('destination', 'source?')
        ns = self.get_instance(args=args).args
        assert type(ns) is plugable.NameSpace
        assert len(ns) == len(args)
        assert list(ns) == ['destination', 'source']
        assert type(ns.destination) is frontend.Param
        assert type(ns.source) is frontend.Param
        assert ns.destination.required is True
        assert ns.destination.multivalue is False
        assert ns.source.required is False
        assert ns.source.multivalue is False

        # Test TypeError:
        e = raises(TypeError, self.get_instance, args=(u'whatever',))
        assert str(e) == \
            'create_param() takes %r or %r; got %r' % (str, frontend.Param, u'whatever')

        # Test ValueError, required after optional:
        e = raises(ValueError, self.get_instance, args=('arg1?', 'arg2'))
        assert str(e) == 'arg2: required argument after optional'

         # Test ValueError, scalar after multivalue:
        e = raises(ValueError, self.get_instance, args=('arg1+', 'arg2'))
        assert str(e) == 'arg2: only final argument can be multivalue'

    def test_max_args(self):
        """
        Test the ``Command.max_args`` instance attribute.
        """
        o = self.get_instance()
        assert o.max_args == 0
        o = self.get_instance(args=('one?',))
        assert o.max_args == 1
        o = self.get_instance(args=('one', 'two?'))
        assert o.max_args == 2
        o = self.get_instance(args=('one', 'multi+',))
        assert o.max_args is None
        o = self.get_instance(args=('one', 'multi*',))
        assert o.max_args is None

    def test_options(self):
        """
        Tests the ``Command.options`` instance attribute.
        """
        assert 'options' in self.cls.__public__ # Public
        assert self.cls().options is None
        o = self.cls()
        o.finalize()
        assert type(o.options) is plugable.NameSpace
        assert len(o.options) == 0
        options = ('target', 'files*')
        ns = self.get_instance(options=options).options
        assert type(ns) is plugable.NameSpace
        assert len(ns) == len(options)
        assert list(ns) == ['target', 'files']
        assert type(ns.target) is frontend.Param
        assert type(ns.files) is frontend.Param
        assert ns.target.required is True
        assert ns.target.multivalue is False
        assert ns.files.required is False
        assert ns.files.multivalue is True

    def test_convert(self):
        """
        Tests the `frontend.Command.convert` method.
        """
        assert 'convert' in self.cls.__public__ # Public
        kw = dict(
            option0='option0',
            option1='option1',
            whatever=False,
            also=object,
        )
        expected = dict(kw)
        expected.update(dict(option0=u'option0', option1=u'option1'))
        o = self.subcls()
        o.finalize()
        for (key, value) in o.convert(**kw).iteritems():
            v = expected[key]
            assert value == v
            assert type(value) is type(v)

    def test_normalize(self):
        """
        Tests the `frontend.Command.normalize` method.
        """
        assert 'normalize' in self.cls.__public__ # Public
        kw = dict(
            option0=u'OPTION0',
            option1=u'OPTION1',
            option2=u'option2',
        )
        norm = dict((k, v.lower()) for (k, v) in kw.items())
        sub = self.subcls()
        sub.finalize()
        assert sub.normalize(**kw) == norm

    def test_get_default(self):
        """
        Tests the `frontend.Command.get_default` method.
        """
        assert 'get_default' in self.cls.__public__ # Public
        no_fill = dict(
            option0='value0',
            option1='value1',
            whatever='hello world',
        )
        fill = dict(
            default_from='the default',
        )
        default = dict(
            option0='the default',
            option1='the default',
        )
        sub = self.subcls()
        sub.finalize()
        assert sub.get_default(**no_fill) == {}
        assert sub.get_default(**fill) == default

    def test_validate(self):
        """
        Tests the `frontend.Command.validate` method.
        """
        assert 'validate' in self.cls.__public__ # Public

        sub = self.subcls()
        sub.finalize()

        # Check with valid args
        okay = dict(
            option0=u'option0',
            option1=u'option1',
            another_option='some value',
        )
        sub.validate(**okay)

        # Check with an invalid arg
        fail = dict(okay)
        fail['option0'] = u'whatever'
        e = raises(errors.RuleError, sub.validate, **fail)
        assert e.name == 'option0'
        assert e.value == u'whatever'
        assert e.error == 'must equal option0'
        assert e.rule.__class__.__name__ == 'Rule'
        assert e.index is None

        # Check with a missing required arg
        fail = dict(okay)
        fail.pop('option1')
        e = raises(errors.RequirementError, sub.validate, **fail)
        assert e.name == 'option1'
        assert e.value is None
        assert e.index is None

    def test_execute(self):
        """
        Tests the `frontend.Command.execute` method.
        """
        assert 'execute' in self.cls.__public__ # Public

    def test_args_to_kw(self):
        """
        Test the `frontend.Command.args_to_kw` method.
        """
        assert 'args_to_kw' in self.cls.__public__ # Public
        o = self.get_instance(args=('one', 'two?'))
        assert o.args_to_kw(1) == dict(one=1)
        assert o.args_to_kw(1, 2) == dict(one=1, two=2)

        o = self.get_instance(args=('one', 'two*'))
        assert o.args_to_kw(1) == dict(one=1)
        assert o.args_to_kw(1, 2) == dict(one=1, two=(2,))
        assert o.args_to_kw(1, 2, 3) == dict(one=1, two=(2, 3))

        o = self.get_instance(args=('one', 'two+'))
        assert o.args_to_kw(1) == dict(one=1)
        assert o.args_to_kw(1, 2) == dict(one=1, two=(2,))
        assert o.args_to_kw(1, 2, 3) == dict(one=1, two=(2, 3))

        o = self.get_instance()
        e = raises(errors.ArgumentError, o.args_to_kw, 1)
        assert str(e) == 'example takes no arguments'

        o = self.get_instance(args=('one?',))
        e = raises(errors.ArgumentError, o.args_to_kw, 1, 2)
        assert str(e) == 'example takes at most 1 argument'

        o = self.get_instance(args=('one', 'two?'))
        e = raises(errors.ArgumentError, o.args_to_kw, 1, 2, 3)
        assert str(e) == 'example takes at most 2 arguments'

    def test_kw_to_args(self):
        """
        Tests the `frontend.Command.kw_to_args` method.
        """
        assert 'kw_to_args' in self.cls.__public__ # Public
        o = self.get_instance(args=('one', 'two?'))
        assert o.kw_to_args() == (None, None)
        assert o.kw_to_args(whatever='hello') == (None, None)
        assert o.kw_to_args(one='the one') == ('the one', None)
        assert o.kw_to_args(two='the two') == (None, 'the two')
        assert o.kw_to_args(whatever='hello', two='Two', one='One') == \
            ('One', 'Two')


class test_Object(ClassChecker):
    """
    Tests the `frontend.Object` class.
    """
    _cls = frontend.Object

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert type(self.cls.Method) is property
        assert type(self.cls.Property) is property

    def test_init(self):
        """
        Tests the `frontend.Object.__init__` method.
        """
        o = self.cls()
        assert read_only(o, 'Method') is None
        assert read_only(o, 'Property') is None

    def test_set_api(self):
        """
        Tests the `frontend.Object.set_api` method.
        """
        # Setup for test:
        class DummyAttribute(object):
            def __init__(self, obj_name, attr_name, name=None):
                self.obj_name = obj_name
                self.attr_name = attr_name
                if name is None:
                    self.name = '%s_%s' % (obj_name, attr_name)
                else:
                    self.name = name
            def __clone__(self, attr_name):
                return self.__class__(
                    self.obj_name,
                    self.attr_name,
                    getattr(self, attr_name)
                )

        def get_attributes(cnt, format):
            for name in ['other', 'user', 'another']:
                for i in xrange(cnt):
                    yield DummyAttribute(name, format % i)

        cnt = 10
        formats = dict(
            Method='method_%d',
            Property='property_%d',
        )

        class api(object):
            Method = plugable.NameSpace(
                get_attributes(cnt, formats['Method'])
            )
            Property = plugable.NameSpace(
                get_attributes(cnt, formats['Property'])
            )
        assert len(api.Method) == cnt * 3
        assert len(api.Property) == cnt * 3

        class user(self.cls):
            pass

        # Actually perform test:
        o = user()
        o.set_api(api)
        assert read_only(o, 'api') is api
        for name in ['Method', 'Property']:
            namespace = getattr(o, name)
            assert isinstance(namespace, plugable.NameSpace)
            assert len(namespace) == cnt
            f = formats[name]
            for i in xrange(cnt):
                attr_name = f % i
                attr = namespace[attr_name]
                assert isinstance(attr, DummyAttribute)
                assert attr is getattr(namespace, attr_name)
                assert attr.obj_name == 'user'
                assert attr.attr_name == attr_name
                assert attr.name == attr_name

    def test_params(self):
        """
        Test the ``frontend.Object.params`` instance attribute.
        """
        ns = self.cls().params
        assert type(ns) is plugable.NameSpace
        assert len(ns) == 0
        class example(self.cls):
            takes_params = ('banana', 'apple')
        ns = example().params
        assert type(ns) is plugable.NameSpace
        assert len(ns) == 2, repr(ns)
        assert list(ns) == ['banana', 'apple']
        for p in ns():
            assert type(p) is frontend.Param
            assert p.required is True
            assert p.multivalue is False


class test_Attribute(ClassChecker):
    """
    Tests the `frontend.Attribute` class.
    """
    _cls = frontend.Attribute

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert type(self.cls.obj) is property
        assert type(self.cls.obj_name) is property
        assert type(self.cls.attr_name) is property

    def test_init(self):
        """
        Tests the `frontend.Attribute.__init__` method.
        """
        class user_add(self.cls):
            pass
        o = user_add()
        assert read_only(o, 'obj') is None
        assert read_only(o, 'obj_name') == 'user'
        assert read_only(o, 'attr_name') == 'add'

    def test_set_api(self):
        """
        Tests the `frontend.Attribute.set_api` method.
        """
        user_obj = 'The user frontend.Object instance'
        class api(object):
            Object = dict(user=user_obj)
        class user_add(self.cls):
            pass
        o = user_add()
        assert read_only(o, 'api') is None
        assert read_only(o, 'obj') is None
        o.set_api(api)
        assert read_only(o, 'api') is api
        assert read_only(o, 'obj') is user_obj


class test_Method(ClassChecker):
    """
    Tests the `frontend.Method` class.
    """
    _cls = frontend.Method

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Attribute, frontend.Command)
        assert self.cls.implements(frontend.Command)

    def get_subcls(self):
        class example_prop0(frontend.Property):
            'Prop zero'
        class example_prop1(frontend.Property):
            'Prop one'
        class example_obj(object):
            __prop = None
            def __get_prop(self):
                if self.__prop is None:
                    self.__prop = plugable.NameSpace([
                        plugable.PluginProxy(
                            frontend.Property, example_prop0(), 'attr_name'
                        ),
                        plugable.PluginProxy(
                            frontend.Property, example_prop1(),  'attr_name'
                        ),
                    ])
                return self.__prop
            Property = property(__get_prop)
        type_ = ipa_types.Unicode()
        class noun_verb(self.cls):
            takes_options= (
                frontend.Param('option0', type_),
                frontend.Param('option1', type_),
            )
            obj = example_obj()
        return noun_verb

    def test_get_options(self):
        """
        Tests the `frontend.Method.get_options` method.
        """
        sub = self.subcls()
        names = ('option0', 'option1', 'prop0', 'prop1')
        options = tuple(sub.get_options())
        assert len(options) == 4
        for (i, option) in enumerate(options):
            assert option.name == names[i]
            assert isinstance(option, frontend.Param)


class test_Property(ClassChecker):
    """
    Tests the `frontend.Property` class.
    """
    _cls = frontend.Property

    def get_subcls(self):
        class user_givenname(self.cls):
            'User first name'

            @frontend.rule
            def rule0_lowercase(self, value):
                if not value.islower():
                    return 'Must be lowercase'
        return user_givenname

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Attribute,)
        assert isinstance(self.cls.type, ipa_types.Unicode)
        assert self.cls.required is False
        assert self.cls.multivalue is False
        assert self.cls.default is None
        assert self.cls.default_from is None
        assert self.cls.normalize is None

    def test_init(self):
        """
        Tests the `frontend.Property.__init__` method.
        """
        o = self.subcls()
        assert len(o.rules) == 1
        assert o.rules[0].__name__ == 'rule0_lowercase'
        param = o.param
        assert isinstance(param, frontend.Param)
        assert param.name == 'givenname'
        assert param.doc == 'User first name'


class test_Application(ClassChecker):
    """
    Tests the `frontend.Application` class.
    """
    _cls = frontend.Application

    def test_class(self):
        assert self.cls.__bases__ == (frontend.Command,)
        assert type(self.cls.application) is property

    def test_application(self):
        """
        Tests the `frontend.Application.application` property.
        """
        assert 'application' in self.cls.__public__ # Public
        assert 'set_application' in self.cls.__public__ # Public
        app = 'The external application'
        class example(self.cls):
            'A subclass'
        for o in (self.cls(), example()):
            assert read_only(o, 'application') is None
            e = raises(TypeError, o.set_application, None)
            assert str(e) == (
                '%s.application cannot be None' % o.__class__.__name__
            )
            o.set_application(app)
            assert read_only(o, 'application') is app
            e = raises(AttributeError, o.set_application, app)
            assert str(e) == (
                '%s.application can only be set once' % o.__class__.__name__
            )
            assert read_only(o, 'application') is app
