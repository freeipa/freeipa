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
from ipalib import public, plugable, errors


def test_RULE_FLAG():
    assert public.RULE_FLAG == 'validation_rule'


def test_rule():
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


class test_DefaltFrom(ClassChecker):
    """
    Tests the `public.DefaltFrom` class.
    """
    _cls = public.DefaultFrom

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        def callback(*args):
            return args
        keys = ('givenname', 'sn')
        o = self.cls(callback, *keys)
        assert read_only(o, 'callback') is callback
        assert read_only(o, 'keys') == keys

    def test_call(self):
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

    def get_subcls(self):
        rule = public.rule
        class int_opt(self.cls):
            type = int
            @rule
            def rule_0(self, value):
                if value == 0:
                    return 'cannot be 0'
            @rule
            def rule_1(self, value):
                if value == 1:
                    return 'cannot be 1'
            @rule
            def rule_2(self, value):
                if value == 2:
                    return 'cannot be 2'
        return int_opt

    def test_class(self):
        """
        Perform some tests on the class (not an instance).
        """
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert type(self.cls.rules) is property

    def test_normalize(self):
        """
        Tests the `public.Option.normalize` method.
        """
        assert 'normalize' in self.cls.__public__
        o = self.subcls()
        # Test with values that can't be converted:
        nope = (
            '7.0'
            'whatever',
            object,
            None,
        )
        for val in nope:
            e = raises(errors.NormalizationError, o.normalize, val)
            assert isinstance(e, errors.ValidationError)
            assert e.name == 'int_opt'
            assert e.value == val
            assert e.error == "not <type 'int'>"
            assert e.type is int
        # Test with values that can be converted:
        okay = (
            7,
            7.0,
            7.2,
            7L,
            '7',
            ' 7 ',
        )
        for val in okay:
            assert o.normalize(val) == 7

    def test_validate(self):
        """
        Tests the `public.Option.validate` method.
        """
        assert 'validate' in self.cls.__public__
        o = self.subcls()
        o.validate(9)
        for i in xrange(3):
            e = raises(errors.RuleError, o.validate, i)
            assert e.error == 'cannot be %d' % i
            assert e.value == i

    def test_rules(self):
        """
        Tests the `public.Option.rules` property.
        """
        o = self.subcls()
        assert len(o.rules) == 3
        def get_rule(i):
            return getattr(o, 'rule_%d' % i)
        rules = tuple(get_rule(i) for i in xrange(3))
        assert o.rules == rules

    def test_default(self):
        """
        Tests the `public.Option.default` method.
        """
        assert 'default' in self.cls.__public__
        assert self.cls().default() is None


class test_Command(ClassChecker):
    """
    Tests the `public.Command` class.
    """
    _cls = public.Command

    def get_subcls(self):
        class my_option(public.Option):
            def normalize(self, value):
                return super(my_option, self).normalize(value).lower()
            @public.rule
            def my_rule(self, value):
                if value != self.name:
                    return 'must equal %r' % self.name
            def default(self, **kw):
                return kw['default_from']

        class option0(my_option):
            pass
        class option1(my_option):
            required = True
        class example(self.cls):
            option_classes = (option0, option1)
        return example

    def test_class(self):
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert type(self.cls.options) == property

    def test_get_options(self):
        """
        Tests the `public.Command.get_options` method.
        """
        assert list(self.cls().get_options()) == []
        sub = self.subcls()
        for (i, proxy) in enumerate(sub.get_options()):
            assert isinstance(proxy, plugable.PluginProxy)
            assert read_only(proxy, 'name') == 'option%d' % i
            assert proxy.implements(public.Option)
        assert i == 1

    def test_options(self):
        """
        Tests the `public.Command.options` property.
        """
        assert 'options' in self.cls.__public__ # Public
        sub = self.subcls()
        options = sub.options
        assert type(options) == plugable.NameSpace
        assert len(options) == 2
        for name in ('option0', 'option1'):
            assert name in options
            proxy = options[name]
            assert getattr(options, name) is proxy
            assert isinstance(proxy, plugable.PluginProxy)
            assert proxy.name == name

    def test_normalize(self):
        """
        Tests the `public.Command.normalize` method.
        """
        assert 'normalize' in self.cls.__public__ # Public
        kw = dict(
            option0='OPTION0',
            option1='OPTION1',
            option2='option2',
        )
        norm = dict((k, v.lower()) for (k, v) in kw.items())
        sub = self.subcls()
        assert sub.normalize(**kw) == norm

    def test_default(self):
        """
        Tests the `public.Command.default` method.
        """
        assert 'default' in self.cls.__public__ # Public
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
        assert sub.default(**no_fill) == {}
        assert sub.default(**fill) == default

    def test_validate(self):
        """
        Tests the `public.Command.validate` method.
        """
        assert 'validate' in self.cls.__public__ # Public

        sub = self.subcls()

        # Check with valid args
        okay = dict(
            option0='option0',
            option1='option1',
            another_option='some value',
        )
        sub.validate(**okay)

        # Check with an invalid arg
        fail = dict(okay)
        fail['option0'] = 'whatever'
        raises(errors.RuleError, sub.validate, **fail)

        # Check with a missing required arg
        fail = dict(okay)
        fail.pop('option1')
        raises(errors.RequirementError, sub.validate, **fail)

        # Check with missing *not* required arg
        okay.pop('option0')
        sub.validate(**okay)

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
        class user_add(self.cls):
            pass
        o = user_add()
        assert read_only(o, 'obj') is None
        assert read_only(o, 'obj_name') == 'user'
        assert read_only(o, 'attr_name') == 'add'

    def test_finalize(self):
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
        class option0(public.Option):
            pass
        class option1(public.Option):
            pass
        class example_prop0(public.Property):
            pass
        class example_prop1(public.Property):
            pass
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
        class noun_verb(self.cls):
            option_classes = (option0, option1)
            obj = example_obj()
        return noun_verb

    def test_get_options(self):
        """
        Tests the `public.Method.get_options` method.
        """
        sub = self.subcls()
        names = ('option0', 'option1', 'prop0', 'prop1')
        proxies = tuple(sub.get_options())
        assert len(proxies) == 4
        for (i, proxy) in enumerate(proxies):
            assert proxy.name == names[i]
            assert isinstance(proxy, plugable.PluginProxy)
            assert proxy.implements(public.Option)


class test_prop(ClassChecker):
    _cls = public.Property

    def test_class(self):
        assert self.cls.__bases__ == (public.Attribute, public.Option)
        assert self.cls.implements(public.Option)
