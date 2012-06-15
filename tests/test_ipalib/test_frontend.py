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
Test the `ipalib.frontend` module.
"""

from tests.util import raises, getitem, no_set, no_del, read_only
from tests.util import check_TypeError, ClassChecker, create_test_api
from tests.util import assert_equal
from ipalib.constants import TYPE_ERROR
from ipalib.base import NameSpace
from ipalib import frontend, backend, plugable, errors, parameters, config
from ipalib import output
from ipalib.parameters import Str
from ipapython.version import API_VERSION

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


class test_HasParam(ClassChecker):
    """
    Test the `ipalib.frontend.Command` class.
    """

    _cls = frontend.HasParam

    def test_get_param_iterable(self):
        """
        Test the `ipalib.frontend.HasParam._get_param_iterable` method.
        """
        class WithTuple(self.cls):
            takes_stuff = ('one', 'two')
        o = WithTuple()
        assert o._get_param_iterable('stuff') is WithTuple.takes_stuff

        junk = ('three', 'four')
        class WithCallable(self.cls):
            def takes_stuff(self):
                return junk
        o = WithCallable()
        assert o._get_param_iterable('stuff') is junk

        class WithParam(self.cls):
            takes_stuff = parameters.Str('five')
        o = WithParam()
        assert o._get_param_iterable('stuff') == (WithParam.takes_stuff,)

        class WithStr(self.cls):
            takes_stuff = 'six'
        o = WithStr()
        assert o._get_param_iterable('stuff') == ('six',)

        class Wrong(self.cls):
            takes_stuff = ['seven', 'eight']
        o = Wrong()
        e = raises(TypeError, o._get_param_iterable, 'stuff')
        assert str(e) == '%s.%s must be a tuple, callable, or spec; got %r' % (
            'Wrong', 'takes_stuff', Wrong.takes_stuff
        )

    def test_filter_param_by_context(self):
        """
        Test the `ipalib.frontend.HasParam._filter_param_by_context` method.
        """
        class Example(self.cls):
            def get_stuff(self):
                return (
                    'one',  # Make sure create_param() is called for each spec
                    'two',
                    parameters.Str('three', include='cli'),
                    parameters.Str('four', exclude='server'),
                    parameters.Str('five', exclude=['whatever', 'cli']),
                )
        o = Example()

        # Test when env is None:
        params = list(o._filter_param_by_context('stuff'))
        assert list(p.name for p in params) == [
            'one', 'two', 'three', 'four', 'five'
        ]
        for p in params:
            assert type(p) is parameters.Str

        # Test when env.context == 'cli':
        cli = config.Env(context='cli')
        assert cli.context == 'cli'
        params = list(o._filter_param_by_context('stuff', cli))
        assert list(p.name for p in params) == ['one', 'two', 'three', 'four']
        for p in params:
            assert type(p) is parameters.Str

        # Test when env.context == 'server'
        server = config.Env(context='server')
        assert server.context == 'server'
        params = list(o._filter_param_by_context('stuff', server))
        assert list(p.name for p in params) == ['one', 'two', 'five']
        for p in params:
            assert type(p) is parameters.Str

        # Test with no get_stuff:
        class Missing(self.cls):
            pass
        o = Missing()
        gen = o._filter_param_by_context('stuff')
        e = raises(NotImplementedError, list, gen)
        assert str(e) == 'Missing.get_stuff()'

        # Test when get_stuff is not callable:
        class NotCallable(self.cls):
            get_stuff = ('one', 'two')
        o = NotCallable()
        gen = o._filter_param_by_context('stuff')
        e = raises(TypeError, list, gen)
        assert str(e) == '%s.%s must be a callable; got %r' % (
            'NotCallable', 'get_stuff', NotCallable.get_stuff
        )


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

            def __call__(self, _, value):
                if value != self.name:
                    return _('must equal %r') % self.name

        default_from = parameters.DefaultFrom(
                lambda arg: arg,
                'default_from'
        )
        normalizer = lambda value: value.lower()

        class example(self.cls):
            takes_options = (
                parameters.Str('option0', Rule('option0'),
                    normalizer=normalizer,
                    default_from=default_from,
                ),
                parameters.Str('option1', Rule('option1'),
                    normalizer=normalizer,
                    default_from=default_from,
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
        assert self.cls.takes_options == tuple()
        assert self.cls.takes_args == tuple()

    def test_get_args(self):
        """
        Test the `ipalib.frontend.Command.get_args` method.
        """
        assert list(self.cls().get_args()) == []
        args = ('login', 'stuff')
        o = self.get_instance(args=args)
        assert tuple(o.get_args()) == args

    def test_get_options(self):
        """
        Test the `ipalib.frontend.Command.get_options` method.
        """
        assert list(self.cls().get_options()) == []
        options = ('verbose', 'debug')
        o = self.get_instance(options=options)
        assert tuple(o.get_options()) == options

    def test_args(self):
        """
        Test the ``ipalib.frontend.Command.args`` instance attribute.
        """
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
        assert type(ns.destination) is parameters.Str
        assert type(ns.source) is parameters.Str
        assert ns.destination.required is True
        assert ns.destination.multivalue is False
        assert ns.source.required is False
        assert ns.source.multivalue is False

        # Test TypeError:
        e = raises(TypeError, self.get_instance, args=(u'whatever',))
        assert str(e) == TYPE_ERROR % (
            'spec', (str, parameters.Param), u'whatever', unicode)

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
        assert type(ns.target) is parameters.Str
        assert type(ns.files) is parameters.Str
        assert ns.target.required is True
        assert ns.target.multivalue is False
        assert ns.files.required is False
        assert ns.files.multivalue is True

    def test_output(self):
        """
        Test the ``ipalib.frontend.Command.output`` instance attribute.
        """
        inst = self.cls()
        assert inst.output is None
        inst.finalize()
        assert type(inst.output) is plugable.NameSpace
        assert list(inst.output) == ['result']
        assert type(inst.output.result) is output.Output

    def test_iter_output(self):
        """
        Test the ``ipalib.frontend.Command._iter_output`` instance attribute.
        """
        class Example(self.cls):
            pass
        inst = Example()

        inst.has_output = tuple()
        assert list(inst._iter_output()) == []

        wrong = ['hello', 'world']
        inst.has_output = wrong
        e = raises(TypeError, list, inst._iter_output())
        assert str(e) == 'Example.has_output: need a %r; got a %r: %r' % (
            tuple, list, wrong
        )

        wrong = ('hello', 17)
        inst.has_output = wrong
        e = raises(TypeError, list, inst._iter_output())
        assert str(e) == 'Example.has_output[1]: need a %r; got a %r: %r' % (
            (str, output.Output), int, 17
        )

        okay = ('foo', output.Output('bar'), 'baz')
        inst.has_output = okay
        items = list(inst._iter_output())
        assert len(items) == 3
        assert list(o.name for o in items) == ['foo', 'bar', 'baz']
        for o in items:
            assert type(o) is output.Output

    def test_soft_validate(self):
        """
        Test the `ipalib.frontend.Command.soft_validate` method.
        """
        class user_add(frontend.Command):
            takes_args = parameters.Str('uid',
                normalizer=lambda value: value.lower(),
                default_from=lambda givenname, sn: givenname[0] + sn,
            )

            takes_options = ('givenname', 'sn')

        cmd = user_add()
        cmd.env = config.Env(context='cli')
        cmd.finalize()
        assert list(cmd.params) == ['givenname', 'sn', 'uid']
        ret = cmd.soft_validate({})
        assert len(ret['values']) == 0
        assert len(ret['errors']) == 3
        assert cmd.soft_validate(dict(givenname=u'First', sn=u'Last')) == dict(
            values=dict(givenname=u'First', sn=u'Last', uid=u'flast'),
            errors=dict(),
        )

    def test_convert(self):
        """
        Test the `ipalib.frontend.Command.convert` method.
        """
        kw = dict(
            option0=u'1.5',
            option1=u'7',
        )
        o = self.subcls()
        o.finalize()
        for (key, value) in o.convert(**kw).iteritems():
            assert_equal(unicode(kw[key]), value)

    def test_normalize(self):
        """
        Test the `ipalib.frontend.Command.normalize` method.
        """
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
        # FIXME: Add an updated unit tests for get_default()

    def test_default_from_chaining(self):
        """
        Test chaining of parameters through default_from.
        """
        class my_cmd(self.cls):
            takes_options = (
                Str('option0'),
                Str('option1', default_from=lambda option0: option0),
                Str('option2', default_from=lambda option1: option1),
            )

            def run(self, *args, **options):
                return dict(result=options)

        kw = dict(option0=u'some value')

        (api, home) = create_test_api()
        api.finalize()
        o = my_cmd()
        o.set_api(api)
        o.finalize()
        e = o(**kw)
        assert type(e) is dict
        assert 'result' in e
        assert 'option2' in e['result']
        assert e['result']['option2'] == u'some value'

    def test_validate(self):
        """
        Test the `ipalib.frontend.Command.validate` method.
        """

        sub = self.subcls()
        sub.env = config.Env(context='cli')
        sub.finalize()

        # Check with valid values
        okay = dict(
            option0=u'option0',
            option1=u'option1',
            another_option='some value',
            version=API_VERSION,
        )
        sub.validate(**okay)

        # Check with an invalid value
        fail = dict(okay)
        fail['option0'] = u'whatever'
        e = raises(errors.ValidationError, sub.validate, **fail)
        assert_equal(e.name, 'option0')
        assert_equal(e.value, u'whatever')
        assert_equal(e.error, u"must equal 'option0'")
        assert e.rule.__class__.__name__ == 'Rule'
        assert e.index is None

        # Check with a missing required arg
        fail = dict(okay)
        fail.pop('option1')
        e = raises(errors.RequirementError, sub.validate, **fail)
        assert e.name == 'option1'

    def test_execute(self):
        """
        Test the `ipalib.frontend.Command.execute` method.
        """
        o = self.cls()
        e = raises(NotImplementedError, o.execute)
        assert str(e) == 'Command.execute()'

    def test_args_options_2_params(self):
        """
        Test the `ipalib.frontend.Command.args_options_2_params` method.
        """

        # Test that ZeroArgumentError is raised:
        o = self.get_instance()
        e = raises(errors.ZeroArgumentError, o.args_options_2_params, 1)
        assert e.name == 'example'

        # Test that MaxArgumentError is raised (count=1)
        o = self.get_instance(args=('one?',))
        e = raises(errors.MaxArgumentError, o.args_options_2_params, 1, 2)
        assert e.name == 'example'
        assert e.count == 1
        assert str(e) == "command 'example' takes at most 1 argument"

        # Test that MaxArgumentError is raised (count=2)
        o = self.get_instance(args=('one', 'two?'))
        e = raises(errors.MaxArgumentError, o.args_options_2_params, 1, 2, 3)
        assert e.name == 'example'
        assert e.count == 2
        assert str(e) == "command 'example' takes at most 2 arguments"

        # Test that OptionError is raised when an extra option is given:
        o = self.get_instance()
        e = raises(errors.OptionError, o.args_options_2_params, bad_option=True)
        assert e.option == 'bad_option'

        # Test that OverlapError is raised:
        o = self.get_instance(args=('one', 'two'), options=('three', 'four'))
        e = raises(errors.OverlapError, o.args_options_2_params,
            1, 2, three=3, two=2, four=4, one=1)
        assert e.names == ['one', 'two']

        # Test the permutations:
        o = self.get_instance(args=('one', 'two*'), options=('three', 'four'))
        mthd = o.args_options_2_params
        assert mthd() == dict()
        assert mthd(1) == dict(one=1)
        assert mthd(1, 2) == dict(one=1, two=(2,))
        assert mthd(1, 21, 22, 23) == dict(one=1, two=(21, 22, 23))
        assert mthd(1, (21, 22, 23)) == dict(one=1, two=(21, 22, 23))
        assert mthd(three=3, four=4) == dict(three=3, four=4)
        assert mthd(three=3, four=4, one=1, two=2) == \
            dict(one=1, two=2, three=3, four=4)
        assert mthd(1, 21, 22, 23, three=3, four=4) == \
            dict(one=1, two=(21, 22, 23), three=3, four=4)
        assert mthd(1, (21, 22, 23), three=3, four=4) == \
            dict(one=1, two=(21, 22, 23), three=3, four=4)

    def test_args_options_2_entry(self):
        """
        Test `ipalib.frontend.Command.args_options_2_entry` method.
        """
        class my_cmd(self.cls):
            takes_args = (
                parameters.Str('one', attribute=True),
                parameters.Str('two', attribute=False),
            )
            takes_options = (
                parameters.Str('three', attribute=True, multivalue=True),
                parameters.Str('four', attribute=True, multivalue=False),
            )

            def run(self, *args, **kw):
                return self.args_options_2_entry(*args, **kw)

        args = ('one', 'two')
        kw = dict(three=('three1', 'three2'), four='four')

        (api, home) = create_test_api()
        api.finalize()
        o = my_cmd()
        o.set_api(api)
        o.finalize()
        e = o.run(*args, **kw)
        assert type(e) is dict
        assert 'one' in e
        assert 'two' not in e
        assert 'three' in e
        assert 'four' in e
        assert e['one'] == 'one'
        assert e['three'] == ['three1', 'three2']
        assert e['four'] == 'four'

    def test_params_2_args_options(self):
        """
        Test the `ipalib.frontend.Command.params_2_args_options` method.
        """
        o = self.get_instance(args='one', options='two')
        assert o.params_2_args_options() == ((None,), {})
        assert o.params_2_args_options(one=1) == ((1,), {})
        assert o.params_2_args_options(two=2) == ((None,), dict(two=2))
        assert o.params_2_args_options(two=2, one=1) == ((1,), dict(two=2))

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
        kw = dict(how_are='you', on_this='fine day?', version=API_VERSION)

        # Test in server context:
        (api, home) = create_test_api(in_server=True)
        api.finalize()
        o = my_cmd()
        o.set_api(api)
        assert o.run.im_func is self.cls.run.im_func
        out = o.run(*args, **kw)
        del kw['version']
        assert ('execute', args, kw) == out

        # Test in non-server context
        (api, home) = create_test_api(in_server=False)
        api.finalize()
        o = my_cmd()
        o.set_api(api)
        assert o.run.im_func is self.cls.run.im_func
        assert ('forward', args, kw) == o.run(*args, **kw)

    def test_validate_output_basic(self):
        """
        Test the `ipalib.frontend.Command.validate_output` method.
        """
        class Example(self.cls):
            has_output = ('foo', 'bar', 'baz')

        inst = Example()
        inst.finalize()

        # Test with wrong type:
        wrong = ('foo', 'bar', 'baz')
        e = raises(TypeError, inst.validate_output, wrong)
        assert str(e) == '%s.validate_output(): need a %r; got a %r: %r' % (
            'Example', dict, tuple, wrong
        )

        # Test with a missing keys:
        wrong = dict(bar='hello')
        e = raises(ValueError, inst.validate_output, wrong)
        assert str(e) == '%s.validate_output(): missing keys %r in %r' % (
            'Example', ['baz', 'foo'], wrong
        )

        # Test with extra keys:
        wrong = dict(foo=1, bar=2, baz=3, fee=4, azz=5)
        e = raises(ValueError, inst.validate_output, wrong)
        assert str(e) == '%s.validate_output(): unexpected keys %r in %r' % (
            'Example', ['azz', 'fee'], wrong
        )

        # Test with different keys:
        wrong = dict(baz=1, xyzzy=2, quux=3)
        e = raises(ValueError, inst.validate_output, wrong)
        assert str(e) == '%s.validate_output(): missing keys %r in %r' % (
            'Example', ['bar', 'foo'], wrong
        ), str(e)

    def test_validate_output_per_type(self):
        """
        Test `ipalib.frontend.Command.validate_output` per-type validation.
        """

        class Complex(self.cls):
            has_output = (
                output.Output('foo', int),
                output.Output('bar', list),
            )
        inst = Complex()
        inst.finalize()

        wrong = dict(foo=17.9, bar=[18])
        e = raises(TypeError, inst.validate_output, wrong)
        assert str(e) == '%s:\n  output[%r]: need %r; got %r: %r' % (
            'Complex.validate_output()', 'foo', int, float, 17.9
        )

        wrong = dict(foo=18, bar=17)
        e = raises(TypeError, inst.validate_output, wrong)
        assert str(e) == '%s:\n  output[%r]: need %r; got %r: %r' % (
            'Complex.validate_output()', 'bar', list, int, 17
        )

    def test_validate_output_nested(self):
        """
        Test `ipalib.frontend.Command.validate_output` nested validation.
        """

        class Subclass(output.ListOfEntries):
            pass

        # Test nested validation:
        class nested(self.cls):
            has_output = (
                output.Output('hello', int),
                Subclass('world'),
            )
        inst = nested()
        inst.finalize()
        okay = dict(foo='bar')
        nope = ('aye', 'bee')

        wrong = dict(hello=18, world=[okay, nope, okay])
        e = raises(TypeError, inst.validate_output, wrong)
        assert str(e) == output.emsg % (
            'nested', 'Subclass', 'world', 1, dict, tuple, nope
        )

        wrong = dict(hello=18, world=[okay, okay, okay, okay, nope])
        e = raises(TypeError, inst.validate_output, wrong)
        assert str(e) == output.emsg % (
            'nested', 'Subclass', 'world', 4, dict, tuple, nope
        )

    def test_get_output_params(self):
        """
        Test the `ipalib.frontend.Command.get_output_params` method.
        """
        class example(self.cls):
            has_output_params = (
                'one',
                'two',
                'three',
            )
            takes_args = (
                'foo',
            )
            takes_options = (
                Str('bar', flags='no_output'),
                'baz',
            )

        inst = example()
        assert list(inst.get_output_params()) == ['one', 'two', 'three']
        inst.finalize()
        assert list(inst.get_output_params()) == [
            'one', 'two', 'three', inst.params.foo, inst.params.baz
        ]
        assert list(inst.output_params) == ['one', 'two', 'three', 'foo', 'baz']


class test_LocalOrRemote(ClassChecker):
    """
    Test the `ipalib.frontend.LocalOrRemote` class.
    """
    _cls = frontend.LocalOrRemote

    def test_init(self):
        """
        Test the `ipalib.frontend.LocalOrRemote.__init__` method.
        """
        o = self.cls()
        o.finalize()
        assert list(o.args) == []
        assert list(o.options) == ['server']
        op = o.options.server
        assert op.required is False
        assert op.default is False

    def test_run(self):
        """
        Test the `ipalib.frontend.LocalOrRemote.run` method.
        """
        class example(self.cls):
            takes_args = 'key?'

            def forward(self, *args, **options):
                return dict(result=('forward', args, options))

            def execute(self, *args, **options):
                return dict(result=('execute', args, options))

        # Test when in_server=False:
        (api, home) = create_test_api(in_server=False)
        api.register(example)
        api.finalize()
        cmd = api.Command.example
        assert cmd() == dict(
            result=('execute', (None,), dict(server=False))
        )
        assert cmd(u'var') == dict(
            result=('execute', (u'var',), dict(server=False))
        )
        assert cmd(server=True) == dict(
            result=('forward', (None,), dict(server=True))
        )
        assert cmd(u'var', server=True) == dict(
            result=('forward', (u'var',), dict(server=True))
        )

        # Test when in_server=True (should always call execute):
        (api, home) = create_test_api(in_server=True)
        api.register(example)
        api.finalize()
        cmd = api.Command.example
        assert cmd() == dict(
            result=('execute', (None,), dict(server=False))
        )
        assert cmd(u'var') == dict(
            result=('execute', (u'var',), dict(server=False))
        )
        assert cmd(server=True) == dict(
            result=('execute', (None,), dict(server=True))
        )
        assert cmd(u'var', server=True) == dict(
            result=('execute', (u'var',), dict(server=True))
        )


class test_Object(ClassChecker):
    """
    Test the `ipalib.frontend.Object` class.
    """
    _cls = frontend.Object

    def test_class(self):
        """
        Test the `ipalib.frontend.Object` class.
        """
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
                assert attr.name == '%s_%s' % ('user', attr_name)

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
            assert type(p) is parameters.Str
            assert p.required is True
            assert p.multivalue is False

    def test_primary_key(self):
        """
        Test the `ipalib.frontend.Object.primary_key` attribute.
        """
        (api, home) = create_test_api()
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

        # Test with 1 primary key:
        class example2(self.cls):
            takes_params = (
                'one',
                'two',
                parameters.Str('three', primary_key=True),
                'four',
            )
        o = example2()
        o.set_api(api)
        pk = o.primary_key
        assert type(pk) is parameters.Str
        assert pk.name == 'three'
        assert pk.primary_key is True
        assert o.params[2] is o.primary_key
        assert isinstance(o.params_minus_pk, plugable.NameSpace)
        assert list(o.params_minus_pk) == ['one', 'two', 'four']

        # Test with multiple primary_key:
        class example3(self.cls):
            takes_params = (
                parameters.Str('one', primary_key=True),
                parameters.Str('two', primary_key=True),
                'three',
                parameters.Str('four', primary_key=True),
            )
        o = example3()
        o.set_api(api)
        e = raises(ValueError, o.finalize)
        assert str(e) == \
            'example3 (Object) has multiple primary keys: one, two, four'

    def test_backend(self):
        """
        Test the `ipalib.frontend.Object.backend` attribute.
        """
        (api, home) = create_test_api()
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

    def test_get_dn(self):
        """
        Test the `ipalib.frontend.Object.get_dn` method.
        """
        o = self.cls()
        e = raises(NotImplementedError, o.get_dn, 'primary key')
        assert str(e) == 'Object.get_dn()'
        class user(self.cls):
            pass
        o = user()
        e = raises(NotImplementedError, o.get_dn, 'primary key')
        assert str(e) == 'user.get_dn()'

    def test_params_minus(self):
        """
        Test the `ipalib.frontend.Object.params_minus` method.
        """
        class example(self.cls):
            takes_params = ('one', 'two', 'three', 'four')
        o = example()
        (api, home) = create_test_api()
        o.set_api(api)
        p = o.params
        assert tuple(o.params_minus()) == tuple(p())
        assert tuple(o.params_minus([])) == tuple(p())
        assert tuple(o.params_minus('two', 'three')) == (p.one, p.four)
        assert tuple(o.params_minus(['two', 'three'])) == (p.one, p.four)
        assert tuple(o.params_minus(p.two, p.three)) == (p.one, p.four)
        assert tuple(o.params_minus([p.two, p.three])) == (p.one, p.four)
        ns = NameSpace([p.two, p.three])
        assert tuple(o.params_minus(ns)) == (p.one, p.four)


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

    def get_api(self, args=tuple(), options=tuple()):
        """
        Return a finalized `ipalib.plugable.API` instance.
        """
        (api, home) = create_test_api()
        class user(frontend.Object):
            takes_params = (
                'givenname',
                'sn',
                frontend.Param('uid', primary_key=True),
                'initials',
            )
        class user_verb(self.cls):
            takes_args = args
            takes_options = options
        api.register(user)
        api.register(user_verb)
        api.finalize()
        return api

    def test_class(self):
        """
        Test the `ipalib.frontend.Method` class.
        """
        assert self.cls.__bases__ == (frontend.Attribute, frontend.Command)

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
        assert self.cls.klass is parameters.Str

    def test_init(self):
        """
        Test the `ipalib.frontend.Property.__init__` method.
        """
        o = self.subcls()
        assert len(o.rules) == 1
        assert o.rules[0].__name__ == 'rule0_lowercase'
        param = o.param
        assert isinstance(param, parameters.Str)
        assert param.name == 'givenname'
        assert unicode(param.doc) == u'User first name'
