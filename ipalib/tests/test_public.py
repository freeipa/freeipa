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
Unit tests for `ipalib.public` module.
"""

from tstutil import raises, getitem, no_set, no_del, read_only, ClassChecker
from tstutil import check_TypeError
from ipalib import public, plugable, errors, ipa_types


def test_RULE_FLAG():
    assert public.RULE_FLAG == 'validation_rule'


def test_rule():
    """
    Tests the `public.rule` function.
    """
    flag = public.RULE_FLAG
    rule = public.rule
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
    Tests the `public.is_rule` function.
    """
    is_rule = public.is_rule
    flag = public.RULE_FLAG

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
    Tests the `public.DefaultFrom` class.
    """
    _cls = public.DefaultFrom

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        """
        Tests the `public.DefaultFrom.__init__` method.
        """
        def callback(*args):
            return args
        keys = ('givenname', 'sn')
        o = self.cls(callback, *keys)
        assert read_only(o, 'callback') is callback
        assert read_only(o, 'keys') == keys

    def test_call(self):
        """
        Tests the `public.DefaultFrom.__call__` method.
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
    Tests the `public.Option` class.
    """
    _cls = public.Option

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        """
        Tests the `public.Option.__init__` method.
        """
        name = 'sn'
        doc = 'Last Name'
        type_ = ipa_types.Unicode()
        o = self.cls(name, doc, type_)
        assert o.__islocked__() is True
        assert read_only(o, 'name') is name
        assert read_only(o, 'doc') is doc
        assert read_only(o, 'type') is type_
        assert read_only(o, 'required') is False
        assert read_only(o, 'multivalue') is False
        assert read_only(o, 'default') is None
        assert read_only(o, 'default_from') is None
        assert read_only(o, 'rules') == (type_.validate,)

    def test_convert(self):
        """
        Tests the `public.Option.convert` method.
        """
        name = 'some_number'
        doc = 'Some number'
        type_ = ipa_types.Int()
        okay = (7, 7L, 7.0, ' 7 ')
        fail = ('7.0', '7L', 'whatever', object)

        # Scenario 1: multivalue=False
        o = self.cls(name, doc, type_)
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
        o = self.cls(name, doc, type_, multivalue=True)
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
        Tests the `public.Option.normalize` method.
        """
        name = 'sn'
        doc = 'User last name'
        t = ipa_types.Unicode()
        callback = lambda value: value.lower()
        values = (None, u'Hello', (u'Hello',), 'hello', ['hello'])

        # Scenario 1: multivalue=False, normalize=None
        o = self.cls(name, doc, t)
        for v in values:
            # When normalize=None, value is returned, no type checking:
            assert o.normalize(v) is v

        # Scenario 2: multivalue=False, normalize=callback
        o = self.cls(name, doc, t, normalize=callback)
        for v in (u'Hello', u'hello'): # Okay
            assert o.normalize(v) == u'hello'
        for v in [None, 'hello', (u'Hello',)]: # Not unicode
            check_TypeError(v, unicode, 'value', o.normalize, v)

        # Scenario 3: multivalue=True, normalize=None
        o = self.cls(name, doc, t, multivalue=True)
        for v in values:
            # When normalize=None, value is returned, no type checking:
            assert o.normalize(v) is v

        # Scenario 4: multivalue=True, normalize=callback
        o = self.cls(name, doc, t, multivalue=True, normalize=callback)
        for value in [(u'Hello',), (u'hello',)]: # Okay
            assert o.normalize(value) == (u'hello',)
        for v in (None, u'Hello', [u'hello']): # Not tuple
            check_TypeError(v, tuple, 'value', o.normalize, v)
        fail = 'Hello' # Not unicode
        for v in [(fail,), (u'Hello', fail)]: # Non unicode member
            check_TypeError(fail, unicode, 'value', o.normalize, v)

    def test_validate(self):
        """
        Tests the `public.Option.validate` method.
        """
        name = 'sn'
        doc = 'User last name'
        type_ = ipa_types.Unicode()
        def case_rule(value):
            if not value.islower():
                return 'Must be lower case'
        my_rules = (case_rule,)
        okay = u'whatever'
        fail_case = u'Whatever'
        fail_type = 'whatever'

        # Scenario 1: multivalue=False
        o = self.cls(name, doc, type_, rules=my_rules)
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
        o = self.cls(name, doc, type_, multivalue=True, rules=my_rules)
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
        Tests the `public.Option.get_default` method.
        """
        name = 'greeting'
        doc = 'User greeting'
        type_ = ipa_types.Unicode()
        default = u'Hello, world!'
        default_from = public.DefaultFrom(
            lambda first, last: u'Hello, %s %s!' % (first, last),
            'first', 'last'
        )

        # Scenario 1: multivalue=False
        o = self.cls(name, doc, type_,
            default=default,
            default_from=default_from,
        )
        assert o.default is default
        assert o.default_from is default_from
        assert o.get_default() == default
        assert o.get_default(first='John', last='Doe') == 'Hello, John Doe!'

        # Scenario 2: multivalue=True
        o = self.cls(name, doc, type_,
            default=default,
            default_from=default_from,
            multivalue=True,
        )
        assert o.default is default
        assert o.default_from is default_from
        assert o.get_default() == (default,)
        assert o.get_default(first='John', last='Doe') == ('Hello, John Doe!',)

    def test_get_value(self):
        """
        Tests the `public.Option.get_values` method.
        """
        name = 'status'
        doc = 'Account status'
        values = (u'Active', u'Inactive')
        o = self.cls(name, doc, ipa_types.Unicode())
        assert o.get_values() == tuple()
        o = self.cls(name, doc, ipa_types.Enum(*values))
        assert o.get_values() == values


class test_Command(ClassChecker):
    """
    Tests the `public.Command` class.
    """
    _cls = public.Command

    def get_subcls(self):
        class Rule(object):
            def __init__(self, name):
                self.name = name

            def __call__(self, value):
                if value != self.name:
                    return 'must equal %s' % self.name

        default_from = public.DefaultFrom(
                lambda arg: arg,
                'default_from'
        )
        normalize = lambda value: value.lower()
        type_ = ipa_types.Unicode()

        class example(self.cls):
            options = (
                public.Option('option0', 'Option zero', type_,
                    normalize=normalize,
                    default_from=default_from,
                    rules=(Rule('option0'),)
                ),
                public.Option('option1', 'Option one', type_,
                    normalize=normalize,
                    default_from=default_from,
                    rules=(Rule('option1'),),
                    required=True,
                ),
            )
        return example

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert self.cls.options == tuple()

    def test_get_options(self):
        """
        Tests the `public.Command.get_options` method.
        """
        assert list(self.cls().get_options()) == []
        sub = self.subcls()
        for (i, option) in enumerate(sub.get_options()):
            assert isinstance(option, public.Option)
            assert read_only(option, 'name') == 'option%d' % i
        assert i == 1

    def test_Option(self):
        """
        Tests the `public.Command.Option` property.
        """
        assert 'Option' in self.cls.__public__ # Public
        sub = self.subcls()
        O = sub.Option
        assert type(O) is plugable.NameSpace
        assert len(O) == 2
        for name in ('option0', 'option1'):
            assert name in O
            option = O[name]
            assert getattr(O, name) is option
            assert isinstance(option, public.Option)
            assert option.name == name

    def test_convert(self):
        """
        Tests the `public.Command.convert` method.
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
        for (key, value) in o.convert(**kw).iteritems():
            v = expected[key]
            assert value == v
            assert type(value) is type(v)

    def test_normalize(self):
        """
        Tests the `public.Command.normalize` method.
        """
        assert 'normalize' in self.cls.__public__ # Public
        kw = dict(
            option0=u'OPTION0',
            option1=u'OPTION1',
            option2=u'option2',
        )
        norm = dict((k, v.lower()) for (k, v) in kw.items())
        sub = self.subcls()
        assert sub.normalize(**kw) == norm

    def test_get_default(self):
        """
        Tests the `public.Command.get_default` method.
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
        assert sub.get_default(**no_fill) == {}
        assert sub.get_default(**fill) == default

    def test_validate(self):
        """
        Tests the `public.Command.validate` method.
        """
        assert 'validate' in self.cls.__public__ # Public

        sub = self.subcls()

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
        Tests the `public.Command.execute` method.
        """
        assert 'execute' in self.cls.__public__ # Public


class test_Object(ClassChecker):
    """
    Tests the `public.Object` class.
    """
    _cls = public.Object

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert type(self.cls.Method) is property
        assert type(self.cls.Property) is property

    def test_init(self):
        """
        Tests the `public.Object.__init__` method.
        """
        o = self.cls()
        assert read_only(o, 'Method') is None
        assert read_only(o, 'Property') is None

    def test_finalize(self):
        """
        Tests the `public.Object.finalize` method.
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
        o.finalize(api)
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


class test_Attribute(ClassChecker):
    """
    Tests the `public.Attribute` class.
    """
    _cls = public.Attribute

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert type(self.cls.obj) is property
        assert type(self.cls.obj_name) is property
        assert type(self.cls.attr_name) is property

    def test_init(self):
        """
        Tests the `public.Attribute.__init__` method.
        """
        class user_add(self.cls):
            pass
        o = user_add()
        assert read_only(o, 'obj') is None
        assert read_only(o, 'obj_name') == 'user'
        assert read_only(o, 'attr_name') == 'add'

    def test_finalize(self):
        """
        Tests the `public.Attribute.finalize` method.
        """
        user_obj = 'The user public.Object instance'
        class api(object):
            Object = dict(user=user_obj)
        class user_add(self.cls):
            pass
        o = user_add()
        assert read_only(o, 'api') is None
        assert read_only(o, 'obj') is None
        o.finalize(api)
        assert read_only(o, 'api') is api
        assert read_only(o, 'obj') is user_obj


class test_Method(ClassChecker):
    """
    Tests the `public.Method` class.
    """
    _cls = public.Method

    def test_class(self):
        assert self.cls.__bases__ == (public.Attribute, public.Command)
        assert self.cls.implements(public.Command)

    def get_subcls(self):
        class example_prop0(public.Property):
            'Prop zero'
        class example_prop1(public.Property):
            'Prop one'
        class example_obj(object):
            __prop = None
            def __get_prop(self):
                if self.__prop is None:
                    self.__prop = plugable.NameSpace([
                        plugable.PluginProxy(
                            public.Property, example_prop0(), 'attr_name'
                        ),
                        plugable.PluginProxy(
                            public.Property, example_prop1(),  'attr_name'
                        ),
                    ])
                return self.__prop
            Property = property(__get_prop)
        type_ = ipa_types.Unicode()
        class noun_verb(self.cls):
            options= (
                public.Option('option0', 'Option zero', type_),
                public.Option('option1', 'Option one', type_),
            )
            obj = example_obj()
        return noun_verb

    def test_get_options(self):
        """
        Tests the `public.Method.get_options` method.
        """
        sub = self.subcls()
        names = ('option0', 'option1', 'prop0', 'prop1')
        options = tuple(sub.get_options())
        assert len(options) == 4
        for (i, option) in enumerate(options):
            assert option.name == names[i]
            assert isinstance(option, public.Option)


class test_Property(ClassChecker):
    """
    Tests the `public.Property` class.
    """
    _cls = public.Property

    def get_subcls(self):
        class user_givenname(self.cls):
            'User first name'

            @public.rule
            def rule0_lowercase(self, value):
                if not value.islower():
                    return 'Must be lowercase'
        return user_givenname

    def test_class(self):
        assert self.cls.__bases__ == (public.Attribute,)
        assert isinstance(self.cls.type, ipa_types.Unicode)
        assert self.cls.required is False
        assert self.cls.multivalue is False
        assert self.cls.default is None
        assert self.cls.default_from is None
        assert self.cls.normalize is None

    def test_init(self):
        """
        Tests the `public.Property.__init__` method.
        """
        o = self.subcls()
        assert len(o.rules) == 1
        assert o.rules[0].__name__ == 'rule0_lowercase'
        opt = o.option
        assert isinstance(opt, public.Option)
        assert opt.name == 'givenname'
        assert opt.doc == 'User first name'
