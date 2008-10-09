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
Test the `ipalib.frontend` module.
"""

from tests.util import raises, getitem, no_set, no_del, read_only
from tests.util import check_TypeError, ClassChecker
from ipalib import frontend, backend, plugable, errors, ipa_types, config


def test_RULE_FLAG():
    assert frontend.RULE_FLAG == 'validation_rule'


def test_rule():
    """
    Test the `ipalib.frontend.rule` function.
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
    Test the `ipalib.frontend.is_rule` function.
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
    Test the `ipalib.frontend.DefaultFrom` class.
    """
    _cls = frontend.DefaultFrom

    def test_class(self):
        """
        Test the `ipalib.frontend.DefaultFrom` class.
        """
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        """
        Test the `ipalib.frontend.DefaultFrom.__init__` method.
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

    def test_call(self):
        """
        Test the `ipalib.frontend.DefaultFrom.__call__` method.
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
        o = self.cls(lambda first, last: first[0] + last)
        assert o(first='john', last='doe') == 'jdoe'
        assert o(first='', last='doe') is None
        assert o(one='john', two='doe') is None


def test_parse_param_spec():
    """
    Test the `ipalib.frontend.parse_param_spec` function.
    """
    f = frontend.parse_param_spec

    assert f('name') == ('name', dict(required=True, multivalue=False))
    assert f('name?') == ('name', dict(required=False, multivalue=False))
    assert f('name*') == ('name', dict(required=False, multivalue=True))
    assert f('name+') == ('name', dict(required=True, multivalue=True))


class test_Param(ClassChecker):
    """
    Test the `ipalib.frontend.Param` class.
    """
    _cls = frontend.Param

    def test_class(self):
        """
        Test the `ipalib.frontend.Param` class.
        """
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        """
        Test the `ipalib.frontend.Param.__init__` method.
        """
        name = 'sn'
        o = self.cls(name)
        assert o.__islocked__() is True

        # Test default values
        assert read_only(o, 'name') is name
        assert isinstance(read_only(o, 'type'), ipa_types.Unicode)
        assert read_only(o, 'doc') == ''
        assert read_only(o, 'required') is True
        assert read_only(o, 'multivalue') is False
        assert read_only(o, 'default') is None
        assert read_only(o, 'default_from') is None
        assert read_only(o, 'rules') == tuple()
        assert len(read_only(o, 'all_rules')) == 1
        assert read_only(o, 'primary_key') is False

        # Test all kw args:
        t = ipa_types.Int()
        assert self.cls(name, type=t).type is t
        assert self.cls(name, doc='the doc').doc == 'the doc'
        assert self.cls(name, required=False).required is False
        assert self.cls(name, multivalue=True).multivalue is True
        assert self.cls(name, default=u'Hello').default == u'Hello'
        df = frontend.DefaultFrom(lambda f, l: f + l,
            'first', 'last',
        )
        lam = lambda first, last: first + last
        for cb in (df, lam):
            o = self.cls(name, default_from=cb)
            assert type(o.default_from) is frontend.DefaultFrom
            assert o.default_from.keys == ('first', 'last')
            assert o.default_from.callback('butt', 'erfly') == 'butterfly'
        rules = (lambda whatever: 'Not okay!',)
        o = self.cls(name, rules=rules)
        assert o.rules is rules
        assert o.all_rules[1:] == rules
        assert self.cls(name, primary_key=True).primary_key is True

        # Test default type_:
        o = self.cls(name)
        assert isinstance(o.type, ipa_types.Unicode)

        # Test param spec parsing:
        o = self.cls('name?')
        assert o.name == 'name'
        assert o.required is False
        assert o.multivalue is False

        o = self.cls('name*')
        assert o.name == 'name'
        assert o.required is False
        assert o.multivalue is True

        o = self.cls('name+')
        assert o.name == 'name'
        assert o.required is True
        assert o.multivalue is True

        e = raises(TypeError, self.cls, name, whatever=True, another=False)
        assert str(e) == \
            'Param.__init__() takes no such kwargs: another, whatever'

    def test_clone(self):
        """
        Test the `ipalib.frontend.Param.__clone__` method.
        """
        def compare(o, kw):
            for (k, v) in kw.iteritems():
                assert getattr(o, k) == v, (k, v, getattr(o, k))
        default = dict(
            required=False,
            multivalue=False,
            default=None,
            default_from=None,
            rules=tuple(),
        )
        name = 'hair_color?'
        type_ = ipa_types.Int()
        o = self.cls(name, type=type_)
        compare(o, default)

        override = dict(multivalue=True, default=42)
        d = dict(default)
        d.update(override)
        clone = o.__clone__(**override)
        assert clone.name == 'hair_color'
        assert clone.type is o.type
        compare(clone, d)

    def test_convert(self):
        """
        Test the `ipalib.frontend.Param.convert` method.
        """
        name = 'some_number'
        type_ = ipa_types.Int()
        okay = (7, 7L, 7.0, ' 7 ')
        fail = ('7.0', '7L', 'whatever', object)
        none = (None, '', u'', tuple(), [])

        # Scenario 1: multivalue=False
        o = self.cls(name, type=type_)
        for n in none:
            assert o.convert(n) is None
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
        o = self.cls(name, type=type_, multivalue=True)
        for n in none:
            assert o.convert(n) is None
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
        Test the `ipalib.frontend.Param.normalize` method.
        """
        name = 'sn'
        callback = lambda value: value.lower()
        values = (None, u'Hello', (u'Hello',), 'hello', ['hello'])
        none = (None, '', u'', tuple(), [])

        # Scenario 1: multivalue=False, normalize=None
        o = self.cls(name)
        for v in values:
            # When normalize=None, value is returned, no type checking:
            assert o.normalize(v) is v

        # Scenario 2: multivalue=False, normalize=callback
        o = self.cls(name, normalize=callback)
        for v in (u'Hello', u'hello', 'Hello'): # Okay
            assert o.normalize(v) == 'hello'
        for v in [None, 42, (u'Hello',)]: # Not basestring
            assert o.normalize(v) is v
        for n in none:
            assert o.normalize(n) is None

        # Scenario 3: multivalue=True, normalize=None
        o = self.cls(name, multivalue=True)
        for v in values:
            # When normalize=None, value is returned, no type checking:
            assert o.normalize(v) is v

        # Scenario 4: multivalue=True, normalize=callback
        o = self.cls(name, multivalue=True, normalize=callback)
        assert o.normalize([]) is None
        assert o.normalize(tuple()) is None
        for value in [(u'Hello',), (u'hello',), 'Hello', ['Hello']]: # Okay
            assert o.normalize(value) == (u'hello',)
        fail = 42 # Not basestring
        for v in [[fail], (u'hello', fail)]: # Non basestring member
            assert o.normalize(v) == tuple(v)
        for n in none:
            assert o.normalize(n) is None

    def test_validate(self):
        """
        Test the `ipalib.frontend.Param.validate` method.
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
        o = self.cls(name, type=type_, rules=my_rules)
        assert o.rules == my_rules
        assert o.all_rules == (type_.validate, case_rule)
        o.validate(okay)
        e = raises(errors.RuleError, o.validate, fail_case)
        assert e.name is name
        assert e.value is fail_case
        assert e.error == 'Must be lower case'
        assert e.rule is case_rule
        assert e.index is None
        check_TypeError(fail_type, unicode, 'value', o.validate, fail_type)

        ## Scenario 2: multivalue=True
        o = self.cls(name, type=type_, multivalue=True, rules=my_rules)
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
        Test the `ipalib.frontend.Param.get_default` method.
        """
        name = 'greeting'
        default = u'Hello, world!'
        default_from = frontend.DefaultFrom(
            lambda first, last: u'Hello, %s %s!' % (first, last),
            'first', 'last'
        )

        # Scenario 1: multivalue=False
        o = self.cls(name,
            default=default,
            default_from=default_from,
        )
        assert o.default is default
        assert o.default_from is default_from
        assert o.get_default() == default
        assert o.get_default(first='John', last='Doe') == 'Hello, John Doe!'

        # Scenario 2: multivalue=True
        default = (default,)
        o = self.cls(name,
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
        Test the `ipalib.frontend.Param.get_values` method.
        """
        name = 'status'
        values = (u'Active', u'Inactive')
        o = self.cls(name, type=ipa_types.Unicode())
        assert o.get_values() == tuple()
        o = self.cls(name, type=ipa_types.Enum(*values))
        assert o.get_values() == values


def test_create_param():
    """
    Test the `ipalib.frontend.create_param` function.
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
    Test the `ipalib.frontend.Command` class.
    """

    _cls = frontend.Command

    def get_subcls(self):
        """
        Return a standard subclass of `ipalib.frontend.Command`.
        """
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

        class example(self.cls):
            takes_options = (
                frontend.Param('option0',
                    normalize=normalize,
                    default_from=default_from,
                    rules=(Rule('option0'),)
                ),
                frontend.Param('option1',
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
        """
        Test the `ipalib.frontend.Command` class.
        """
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert self.cls.takes_options == tuple()
        assert self.cls.takes_args == tuple()

    def test_get_args(self):
        """
        Test the `ipalib.frontend.Command.get_args` method.
        """
        assert list(self.cls().get_args()) == []
        args = ('login', 'stuff')
        o = self.get_instance(args=args)
        assert o.get_args() is args

    def test_get_options(self):
        """
        Test the `ipalib.frontend.Command.get_options` method.
        """
        assert list(self.cls().get_options()) == []
        options = ('verbose', 'debug')
        o = self.get_instance(options=options)
        assert o.get_options() is options

    def test_args(self):
        """
        Test the ``ipalib.frontend.Command.args`` instance attribute.
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
        Test the ``ipalib.frontend.Command.max_args`` instance attribute.
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
        Test the ``ipalib.frontend.Command.options`` instance attribute.
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
        Test the `ipalib.frontend.Command.convert` method.
        """
        assert 'convert' in self.cls.__public__ # Public
        kw = dict(
            option0='option0',
            option1='option1',
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
        Test the `ipalib.frontend.Command.normalize` method.
        """
        assert 'normalize' in self.cls.__public__ # Public
        kw = dict(
            option0=u'OPTION0',
            option1=u'OPTION1',
        )
        norm = dict((k, v.lower()) for (k, v) in kw.items())
        sub = self.subcls()
        sub.finalize()
        assert sub.normalize(**kw) == norm

    def test_get_default(self):
        """
        Test the `ipalib.frontend.Command.get_default` method.
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
        Test the `ipalib.frontend.Command.validate` method.
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
        Test the `ipalib.frontend.Command.execute` method.
        """
        assert 'execute' in self.cls.__public__ # Public
        o = self.cls()
        e = raises(NotImplementedError, o.execute)
        assert str(e) == 'Command.execute()'

    def test_args_to_kw(self):
        """
        Test the `ipalib.frontend.Command.args_to_kw` method.
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
        Test the `ipalib.frontend.Command.kw_to_args` method.
        """
        assert 'kw_to_args' in self.cls.__public__ # Public
        o = self.get_instance(args=('one', 'two?'))
        assert o.kw_to_args() == (None, None)
        assert o.kw_to_args(whatever='hello') == (None, None)
        assert o.kw_to_args(one='the one') == ('the one', None)
        assert o.kw_to_args(two='the two') == (None, 'the two')
        assert o.kw_to_args(whatever='hello', two='Two', one='One') == \
            ('One', 'Two')

    def test_run(self):
        """
        Test the `ipalib.frontend.Command.run` method.
        """
        class my_cmd(self.cls):
            def execute(self, *args, **kw):
                return ('execute', args, kw)

            def forward(self, *args, **kw):
                return ('forward', args, kw)

        args = ('Hello,', 'world,')
        kw = dict(how_are='you', on_this='fine day?')

        # Test in server context:
        api = plugable.API(self.cls)
        api.env.update(dict(server_context=True))
        api.finalize()
        o = my_cmd()
        o.set_api(api)
        assert o.run.im_func is self.cls.run.im_func
        assert ('execute', args, kw) == o.run(*args, **kw)
        assert o.run.im_func is my_cmd.execute.im_func

        # Test in non-server context
        api = plugable.API(self.cls)
        api.env.update(dict(server_context=False))
        api.finalize()
        o = my_cmd()
        o.set_api(api)
        assert o.run.im_func is self.cls.run.im_func
        assert ('forward', args, kw) == o.run(*args, **kw)
        assert o.run.im_func is my_cmd.forward.im_func


class test_Object(ClassChecker):
    """
    Test the `ipalib.frontend.Object` class.
    """
    _cls = frontend.Object

    def test_class(self):
        """
        Test the `ipalib.frontend.Object` class.
        """
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert self.cls.backend is None
        assert self.cls.methods is None
        assert self.cls.properties is None
        assert self.cls.params is None
        assert self.cls.params_minus_pk is None
        assert self.cls.takes_params == tuple()

    def test_init(self):
        """
        Test the `ipalib.frontend.Object.__init__` method.
        """
        o = self.cls()
        assert o.backend is None
        assert o.methods is None
        assert o.properties is None
        assert o.params is None
        assert o.params_minus_pk is None
        assert o.properties is None

    def test_set_api(self):
        """
        Test the `ipalib.frontend.Object.set_api` method.
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
                self.param = frontend.create_param(attr_name)

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
            methods='method_%d',
            properties='property_%d',
        )


        _d = dict(
            Method=plugable.NameSpace(
                get_attributes(cnt, formats['methods'])
            ),
            Property=plugable.NameSpace(
                get_attributes(cnt, formats['properties'])
            ),
        )
        api = plugable.MagicDict(_d)
        assert len(api.Method) == cnt * 3
        assert len(api.Property) == cnt * 3

        class user(self.cls):
            pass

        # Actually perform test:
        o = user()
        o.set_api(api)
        assert read_only(o, 'api') is api
        for name in ['methods', 'properties']:
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

        # Test params instance attribute
        o = self.cls()
        o.set_api(api)
        ns = o.params
        assert type(ns) is plugable.NameSpace
        assert len(ns) == 0
        class example(self.cls):
            takes_params = ('banana', 'apple')
        o = example()
        o.set_api(api)
        ns = o.params
        assert type(ns) is plugable.NameSpace
        assert len(ns) == 2, repr(ns)
        assert list(ns) == ['banana', 'apple']
        for p in ns():
            assert type(p) is frontend.Param
            assert p.required is True
            assert p.multivalue is False

    def test_primary_key(self):
        """
        Test the `ipalib.frontend.Object.primary_key` attribute.
        """
        api = plugable.API(
            frontend.Method,
            frontend.Property,
        )
        api.env.update(config.generate_env())
        api.finalize()

        # Test with no primary keys:
        class example1(self.cls):
            takes_params = (
                'one',
                'two',
            )
        o = example1()
        o.set_api(api)
        assert o.primary_key is None
        assert o.params_minus_pk is None

        # Test with 1 primary key:
        class example2(self.cls):
            takes_params = (
                'one',
                'two',
                frontend.Param('three',
                    primary_key=True,
                ),
                'four',
            )
        o = example2()
        o.set_api(api)
        pk = o.primary_key
        assert isinstance(pk, frontend.Param)
        assert pk.name == 'three'
        assert pk.primary_key is True
        assert o.params[2] is o.primary_key
        assert isinstance(o.params_minus_pk, plugable.NameSpace)
        assert list(o.params_minus_pk) == ['one', 'two', 'four']

        # Test with multiple primary_key:
        class example3(self.cls):
            takes_params = (
                frontend.Param('one', primary_key=True),
                frontend.Param('two', primary_key=True),
                'three',
                frontend.Param('four', primary_key=True),
            )
        o = example3()
        e = raises(ValueError, o.set_api, api)
        assert str(e) == \
            'example3 (Object) has multiple primary keys: one, two, four'

    def test_backend(self):
        """
        Test the `ipalib.frontend.Object.backend` attribute.
        """
        api = plugable.API(
            frontend.Object,
            frontend.Method,
            frontend.Property,
            backend.Backend,
        )
        api.env.update(config.generate_env())
        class ldap(backend.Backend):
            whatever = 'It worked!'
        api.register(ldap)
        class user(frontend.Object):
            backend_name = 'ldap'
        api.register(user)
        api.finalize()
        b = api.Object.user.backend
        assert isinstance(b, ldap)
        assert b.whatever == 'It worked!'


class test_Attribute(ClassChecker):
    """
    Test the `ipalib.frontend.Attribute` class.
    """
    _cls = frontend.Attribute

    def test_class(self):
        """
        Test the `ipalib.frontend.Attribute` class.
        """
        assert self.cls.__bases__ == (plugable.Plugin,)
        assert type(self.cls.obj) is property
        assert type(self.cls.obj_name) is property
        assert type(self.cls.attr_name) is property

    def test_init(self):
        """
        Test the `ipalib.frontend.Attribute.__init__` method.
        """
        class user_add(self.cls):
            pass
        o = user_add()
        assert read_only(o, 'obj') is None
        assert read_only(o, 'obj_name') == 'user'
        assert read_only(o, 'attr_name') == 'add'

    def test_set_api(self):
        """
        Test the `ipalib.frontend.Attribute.set_api` method.
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
    Test the `ipalib.frontend.Method` class.
    """
    _cls = frontend.Method

    def test_class(self):
        """
        Test the `ipalib.frontend.Method` class.
        """
        assert self.cls.__bases__ == (frontend.Attribute, frontend.Command)
        assert self.cls.implements(frontend.Command)
        assert self.cls.implements(frontend.Attribute)

    def test_init(self):
        """
        Test the `ipalib.frontend.Method.__init__` method.
        """
        class user_add(self.cls):
            pass
        o = user_add()
        assert o.name == 'user_add'
        assert o.obj_name == 'user'
        assert o.attr_name == 'add'
        assert frontend.Command.implemented_by(o)
        assert frontend.Attribute.implemented_by(o)


class test_Property(ClassChecker):
    """
    Test the `ipalib.frontend.Property` class.
    """
    _cls = frontend.Property

    def get_subcls(self):
        """
        Return a standard subclass of `ipalib.frontend.Property`.
        """
        class user_givenname(self.cls):
            'User first name'

            @frontend.rule
            def rule0_lowercase(self, value):
                if not value.islower():
                    return 'Must be lowercase'
        return user_givenname

    def test_class(self):
        """
        Test the `ipalib.frontend.Property` class.
        """
        assert self.cls.__bases__ == (frontend.Attribute,)
        assert isinstance(self.cls.type, ipa_types.Unicode)
        assert self.cls.required is False
        assert self.cls.multivalue is False
        assert self.cls.default is None
        assert self.cls.default_from is None
        assert self.cls.normalize is None

    def test_init(self):
        """
        Test the `ipalib.frontend.Property.__init__` method.
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
    Test the `ipalib.frontend.Application` class.
    """
    _cls = frontend.Application

    def test_class(self):
        """
        Test the `ipalib.frontend.Application` class.
        """
        assert self.cls.__bases__ == (frontend.Command,)
        assert type(self.cls.application) is property

    def test_application(self):
        """
        Test the `ipalib.frontend.Application.application` property.
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
