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
Base classes for all front-end plugins.
"""

import re
import inspect
from base import lock, check_name, NameSpace
from plugable import Plugin
from parameters import create_param, parse_param_spec, Param, Str, Flag, Password
from util import make_repr

from errors import ZeroArgumentError, MaxArgumentError, OverlapError, RequiresRoot
from constants import TYPE_ERROR


RULE_FLAG = 'validation_rule'

def rule(obj):
    assert not hasattr(obj, RULE_FLAG)
    setattr(obj, RULE_FLAG, True)
    return obj

def is_rule(obj):
    return callable(obj) and getattr(obj, RULE_FLAG, False) is True


class HasParam(Plugin):
    """
    Base class for plugins that have `Param` `NameSpace` attributes.

    Subclasses of `HasParam` will on one or more attributes store `NameSpace`
    instances containing zero or more `Param` instances.  These parameters might
    describe, for example, the arguments and options a command takes, or the
    attributes an LDAP entry can include, or whatever else the subclass sees
    fit.

    Although the interface a subclass must implement is very simple, it must
    conform to a specific naming convention: if you want a namespace
    ``SubClass.foo``, you must define a ``Subclass.takes_foo`` attribute and a
    ``SubCLass.get_foo()`` method, and you may optionally define a
    ``SubClass.check_foo()`` method.


    A quick big-picture example
    ===========================

    Say you want the ``options`` instance attribute on your subclass to be a
    `Param` `NameSpace`... then according to the enforced naming convention,
    your subclass must define a ``takes_options`` attribute and a
    ``get_options()`` method.  For example:

    >>> from ipalib import Str, Int
    >>> class Example(HasParam):
    ...
    ...     options = None  # This will be replaced with your namespace
    ...
    ...     takes_options = (Str('one'), Int('two'))
    ...
    ...     def get_options(self):
    ...         return self._get_param_iterable('options')
    ...
    >>> eg = Example()

    The ``Example.takes_options`` attribute is a ``tuple`` defining the
    parameters you want your ``Example.options`` namespace to contain.  Your
    ``Example.takes_options`` attribute will be accessed via
    `HasParam._get_param_iterable()`, which, among other things, enforces the
    ``('takes_' + name)`` naming convention.  For example:

    >>> eg._get_param_iterable('options')
    (Str('one'), Int('two'))

    The ``Example.get_options()`` method simply returns
    ``Example.takes_options`` by calling `HasParam._get_param_iterable()`.  Your
    ``Example.get_options()`` method will be called via
    `HasParam._filter_param_by_context()`, which, among other things, enforces
    the ``('get_' + name)`` naming convention.  For example:

    >>> list(eg._filter_param_by_context('options'))
    [Str('one'), Int('two')]

    At this point, the ``eg.options`` instance attribute is still ``None``:

    >>> eg.options is None
    True

    `HasParam._create_param_namespace()` will create the ``eg.options``
    namespace from the parameters yielded by
    `HasParam._filter_param_by_context()`.  For example:

    >>> eg._create_param_namespace('options')
    >>> eg.options
    NameSpace(<2 members>, sort=False)
    >>> list(eg.options)  # Like dict.__iter__()
    ['one', 'two']

    Your subclass can optionally define a ``check_options()`` method to perform
    sanity checks.  If it exists, the ``check_options()`` method is called by
    `HasParam._create_param_namespace()` with a single value, the `NameSpace`
    instance it created.  For example:

    >>> class Example2(Example):
    ...
    ...     def check_options(self, namespace):
    ...         for param in namespace():  # Like dict.itervalues()
    ...             if param.name == 'three':
    ...                 raise ValueError("I dislike the param 'three'")
    ...         print '  ** Looks good! **'  # Note output below
    ...
    >>> eg = Example2()
    >>> eg._create_param_namespace('options')
      ** Looks good! **
    >>> eg.options
    NameSpace(<2 members>, sort=False)

    However, if we subclass again and add a `Param` named ``'three'``:

    >>> class Example3(Example2):
    ...
    ...     takes_options = (Str('one'), Int('two'), Str('three'))
    ...
    >>> eg = Example3()
    >>> eg._create_param_namespace('options')
    Traceback (most recent call last):
      ...
    ValueError: I dislike the param 'three'
    >>> eg.options is None  # eg.options was not set
    True


    The Devil and the details
    =========================

    In the above example, ``takes_options`` is a ``tuple``, but it can also be
    a param spec (see `create_param()`), or a callable that returns an iterable
    containing one or more param spec.  Regardless of how ``takes_options`` is
    defined, `HasParam._get_param_iterable()` will return a uniform iterable,
    conveniently hiding the details.

    The above example uses the simplest ``get_options()`` method possible, but
    you could instead implement a ``get_options()`` method that would, for
    example, produce (or withhold) certain parameters based on the whether
    certain plugins are loaded.

    Think of ``takes_options`` as declarative, a simple definition of *what*
    parameters should be included in the namespace.  You should only implement
    a ``takes_options()`` method if a `Param` must reference attributes on your
    plugin instance (for example, for validation rules); you should not use a
    ``takes_options()`` method to filter the parameters or add any other
    procedural behaviour.

    On the other hand, think of the ``get_options()`` method as imperative, a
    procedure for *how* the parameters should be created and filtered.  In the
    example above the *how* just returns the *what* unchanged, but arbitrary
    logic can be implemented in the ``get_options()`` method.  For example, you
    might filter certain parameters from ``takes_options`` base on some
    criteria, or you might insert additional parameters provided by other
    plugins.

    The typical use case for using ``get_options()`` this way is to procedurally
    generate the arguments and options for all the CRUD commands operating on a
    specific LDAP object: the `Object` plugin defines the possible LDAP entry
    attributes (as `Param`), and then the CRUD commands intelligently build
    their ``args`` and ``options`` namespaces based on which attribute is the
    primary key.  In this way new LDAP attributes (aka parameters) can be added
    to the single point of definition (the `Object` plugin), and all the
    corresponding CRUD commands pick up these new parameters without requiring
    modification.  For an example of how this is done, see the
    `ipalib.crud.Create` base class.

    However, there is one type of filtering you should not implement in your
    ``get_options()`` method, because it's already provided at a higher level:
    you should not filter parameters based on the value of ``api.env.context``
    nor (preferably) on any values in ``api.env``.
    `HasParam._filter_param_by_context()` already does this by calling
    `Param.use_in_context()` for each parameter.  Although the base
    `Param.use_in_context()` implementation makes a decision solely on the value
    of ``api.env.context``, subclasses can override this with implementations
    that consider arbitrary ``api.env`` values.
    """

    def _get_param_iterable(self, name):
        """
        Return an iterable of params defined by the attribute named ``name``.

        A sequence of params can be defined one of three ways: as a ``tuple``;
        as a callable that returns an iterable; or as a param spec (a `Param` or
        ``str`` instance).  This method returns a uniform iterable regardless of
        how the param sequence was defined.

        For example, when defined with a tuple:

        >>> class ByTuple(HasParam):
        ...     takes_args = (Param('foo'), Param('bar'))
        ...
        >>> by_tuple = ByTuple()
        >>> list(by_tuple._get_param_iterable('args'))
        [Param('foo'), Param('bar')]

        Or you can define your param sequence with a callable when you need to
        reference attributes on your plugin instance (for validation rules,
        etc.).  For example:

        >>> class ByCallable(HasParam):
        ...     def takes_args(self):
        ...         yield Param('foo', self.validate_foo)
        ...         yield Param('bar', self.validate_bar)
        ...
        ...     def validate_foo(self, _, value, **kw):
        ...         if value != 'Foo':
        ...             return _("must be 'Foo'")
        ...
        ...     def validate_bar(self, _, value, **kw):
        ...         if value != 'Bar':
        ...             return _("must be 'Bar'")
        ...
        >>> by_callable = ByCallable()
        >>> list(by_callable._get_param_iterable('args'))
        [Param('foo', validate_foo), Param('bar', validate_bar)]

        Lastly, as a convenience for when a param sequence contains a single
        param, your defining attribute may a param spec (either a `Param`
        or an ``str`` instance).  For example:

        >>> class BySpec(HasParam):
        ...     takes_args = Param('foo')
        ...     takes_options = 'bar?'
        ...
        >>> by_spec = BySpec()
        >>> list(by_spec._get_param_iterable('args'))
        [Param('foo')]
        >>> list(by_spec._get_param_iterable('options'))
        ['bar?']

        For information on how an ``str`` param spec is interpreted, see the
        `create_param()` and `parse_param_spec()` functions in the
        `ipalib.parameters` module.

        Also see `HasParam._filter_param_by_context()`.
        """
        takes_name = 'takes_' + name
        takes = getattr(self, takes_name, None)
        if type(takes) is tuple:
            return takes
        if isinstance(takes, (Param, str)):
            return (takes,)
        if callable(takes):
            return takes()
        if takes is None:
            return tuple()
        raise TypeError(
            '%s.%s must be a tuple, callable, or spec; got %r' % (
                self.name, takes_name, takes
            )
        )

    def _filter_param_by_context(self, name, env=None):
        """
        Filter params on attribute named ``name`` by environment ``env``.

        For example:

        >>> from ipalib.config import Env
        >>> class Example(HasParam):
        ...
        ...     takes_args = (
        ...         Str('foo_only', include=['foo']),
        ...         Str('not_bar', exclude=['bar']),
        ...         'both',
        ...     )
        ...
        ...     def get_args(self):
        ...         return self._get_param_iterable('args')
        ...
        ...
        >>> eg = Example()
        >>> foo = Env(context='foo')
        >>> bar = Env(context='bar')
        >>> another = Env(context='another')
        >>> (foo.context, bar.context, another.context)
        ('foo', 'bar', 'another')
        >>> list(eg._filter_param_by_context('args', foo))
        [Str('foo_only', include=['foo']), Str('not_bar', exclude=['bar']), Str('both')]
        >>> list(eg._filter_param_by_context('args', bar))
        [Str('both')]
        >>> list(eg._filter_param_by_context('args', another))
        [Str('not_bar', exclude=['bar']), Str('both')]
        """
        env = getattr(self, 'env', env)
        get_name = 'get_' + name
        if not hasattr(self, get_name):
            raise NotImplementedError(
                '%s.%s()' % (self.name, get_name)
            )
        get = getattr(self, get_name)
        if not callable(get):
            raise TypeError(
                '%s.%s must be a callable; got %r' % (self.name, get_name, get)
            )
        for spec in get():
            param = create_param(spec)
            if env is None or param.use_in_context(env):
                yield param

    def _create_param_namespace(self, name, env=None):
        namespace = NameSpace(
            self._filter_param_by_context(name, env),
            sort=False
        )
        check = getattr(self, 'check_' + name, None)
        if callable(check):
            check(namespace)
        setattr(self, name, namespace)


class Command(HasParam):
    """
    A public IPA atomic operation.

    All plugins that subclass from `Command` will be automatically available
    as a CLI command and as an XML-RPC method.

    Plugins that subclass from Command are registered in the ``api.Command``
    namespace. For example:

    >>> from ipalib import create_api
    >>> api = create_api()
    >>> class my_command(Command):
    ...     pass
    ...
    >>> api.register(my_command)
    >>> api.finalize()
    >>> list(api.Command)
    ['my_command']
    >>> api.Command.my_command # doctest:+ELLIPSIS
    ipalib.frontend.my_command()
    """

    __public__ = frozenset((
        'get_default',
        'convert',
        'normalize',
        'validate',
        'execute',
        '__call__',
        'args',
        'options',
        'params',
        'params_2_args_options',
        'args_options_2_params',
        'output_for_cli',
    ))
    takes_options = tuple()
    takes_args = tuple()
    args = None
    options = None
    params = None
    output_for_cli = None
    obj = None

    def __call__(self, *args, **options):
        """
        Perform validation and then execute the command.

        If not in a server context, the call will be forwarded over
        XML-RPC and the executed an the nearest IPA server.
        """
        params = self.args_options_2_params(*args, **options)
        self.debug(
            'raw: %s(%s)', self.name, ', '.join(self._repr_iter(**params))
        )
        params = self.normalize(**params)
        params = self.convert(**params)
        params.update(self.get_default(**params))
        self.info(
            '%s(%s)', self.name, ', '.join(self._repr_iter(**params))
        )
        self.validate(**params)
        (args, options) = self.params_2_args_options(**params)
        result = self.run(*args, **options)
        self.debug('result from %s(): %r', self.name, result)
        return result

    def _repr_iter(self, **params):
        """
        Iterate through ``repr()`` of *safe* values of args and options.

        This method uses `parameters.Param.safe_value()` to mask passwords when
        logging.  Logging the exact call is extremely useful, but we obviously
        don't want to log the cleartext password.

        For example:

        >>> class my_cmd(Command):
        ...     takes_args = ('login',)
        ...     takes_options=(Password('passwd'),)
        ...
        >>> c = my_cmd()
        >>> c.finalize()
        >>> list(c._repr_iter(login=u'Okay.', passwd=u'Private!'))
        ["u'Okay.'", "passwd=u'********'"]
        """
        for arg in self.args():
            value = params.get(arg.name, None)
            yield repr(arg.safe_value(value))
        for option in self.options():
            if option.name not in params:
                continue
            value = params[option.name]
            yield '%s=%r' % (option.name, option.safe_value(value))

    def args_options_2_params(self, *args, **options):
        """
        Merge (args, options) into params.
        """
        if self.max_args is not None and len(args) > self.max_args:
            if self.max_args == 0:
                raise ZeroArgumentError(name=self.name)
            raise MaxArgumentError(name=self.name, count=self.max_args)
        params = dict(self.__options_2_params(options))
        if len(args) > 0:
            arg_kw = dict(self.__args_2_params(args))
            intersection = set(arg_kw).intersection(params)
            if len(intersection) > 0:
                raise OverlapError(names=sorted(intersection))
            params.update(arg_kw)
        return params

    def __args_2_params(self, values):
        multivalue = False
        for (i, arg) in enumerate(self.args()):
            assert not multivalue
            if len(values) > i:
                if arg.multivalue:
                    multivalue = True
                    if len(values) == i + 1 and type(values[i]) in (list, tuple):
                        yield (arg.name, values[i])
                    else:
                        yield (arg.name, values[i:])
                else:
                    yield (arg.name, values[i])
            else:
                break

    def __options_2_params(self, options):
        for name in self.params:
            if name in options:
                yield (name, options[name])

    def args_options_2_entry(self, *args, **options):
        """
        Creates a LDAP entry from attributes in args and options.
        """
        kw = self.args_options_2_params(*args, **options)
        return dict(self.__attributes_2_entry(kw))

    def __attributes_2_entry(self, kw):
        for name in self.params:
            if self.params[name].attribute and name in kw:
                value = kw[name]
                if isinstance(value, tuple):
                    yield (name, [v for v in value])
                else:
                    yield (name, kw[name])

    def params_2_args_options(self, **params):
        """
        Split params into (args, options).
        """
        args = tuple(params.get(name, None) for name in self.args)
        options = dict(self.__params_2_options(params))
        return (args, options)

    def __params_2_options(self, params):
        for name in self.options:
            if name in params:
                yield(name, params[name])

    def normalize(self, **kw):
        """
        Return a dictionary of normalized values.

        For example:

        >>> class my_command(Command):
        ...     takes_options = (
        ...         Param('first', normalizer=lambda value: value.lower()),
        ...         Param('last'),
        ...     )
        ...
        >>> c = my_command()
        >>> c.finalize()
        >>> c.normalize(first=u'JOHN', last=u'DOE')
        {'last': u'DOE', 'first': u'john'}
        """
        return dict(
            (k, self.params[k].normalize(v)) for (k, v) in kw.iteritems()
        )

    def convert(self, **kw):
        """
        Return a dictionary of values converted to correct type.

        >>> from ipalib import Int
        >>> class my_command(Command):
        ...     takes_args = (
        ...         Int('one'),
        ...         'two',
        ...     )
        ...
        >>> c = my_command()
        >>> c.finalize()
        >>> c.convert(one=1, two=2)
        {'two': u'2', 'one': 1}
        """
        return dict(
            (k, self.params[k].convert(v)) for (k, v) in kw.iteritems()
        )

    def __convert_iter(self, kw):
        for param in self.params():
            if kw.get(param.name, None) is None:
                continue

    def get_default(self, **kw):
        """
        Return a dictionary of defaults for all missing required values.

        For example:

        >>> from ipalib import Str
        >>> class my_command(Command):
        ...     takes_args = Str('color', default=u'Red')
        ...
        >>> c = my_command()
        >>> c.finalize()
        >>> c.get_default()
        {'color': u'Red'}
        >>> c.get_default(color=u'Yellow')
        {}
        """
        return dict(self.__get_default_iter(kw))

    def __get_default_iter(self, kw):
        """
        Generator method used by `Command.get_default`.
        """
        for param in self.params():
            if param.name in kw:
                continue
            if param.required or param.autofill:
                default = param.get_default(**kw)
                if default is not None:
                    yield (param.name, default)

    def validate(self, **kw):
        """
        Validate all values.

        If any value fails the validation, `ipalib.errors.ValidationError`
        (or a subclass thereof) will be raised.
        """
        for param in self.params():
            value = kw.get(param.name, None)
            param.validate(value)

    def run(self, *args, **options):
        """
        Dispatch to `Command.execute` or `Command.forward`.

        If running in a server context, `Command.execute` is called and the
        actually work this command performs is executed locally.

        If running in a non-server context, `Command.forward` is called,
        which forwards this call over XML-RPC to the exact same command
        on the nearest IPA server and the actual work this command
        performs is executed remotely.
        """
        if self.api.env.in_server:
            return self.execute(*args, **options)
        return self.forward(*args, **options)

    def execute(self, *args, **kw):
        """
        Perform the actual work this command does.

        This method should be implemented only against functionality
        in self.api.Backend.  For example, a hypothetical
        user_add.execute() might be implemented like this:

        >>> class user_add(Command):
        ...     def execute(self, **kw):
        ...         return self.api.Backend.ldap.add(**kw)
        ...
        """
        raise NotImplementedError('%s.execute()' % self.name)

    def forward(self, *args, **kw):
        """
        Forward call over XML-RPC to this same command on server.
        """
        return self.Backend.xmlclient.forward(self.name, *args, **kw)

    def finalize(self):
        """
        Finalize plugin initialization.

        This method creates the ``args``, ``options``, and ``params``
        namespaces.  This is not done in `Command.__init__` because
        subclasses (like `crud.Add`) might need to access other plugins
        loaded in self.api to determine what their custom `Command.get_args`
        and `Command.get_options` methods should yield.
        """
        self._create_param_namespace('args')
        if len(self.args) == 0 or not self.args[-1].multivalue:
            self.max_args = len(self.args)
        else:
            self.max_args = None
        self._create_param_namespace('options')
        def get_key(p):
            if p.required:
                if p.default_from is None:
                    return 0
                return 1
            return 2
        self.params = NameSpace(
            sorted(tuple(self.args()) + tuple(self.options()), key=get_key),
            sort=False
        )
        super(Command, self).finalize()

    def get_args(self):
        """
        Iterate through parameters for ``Command.args`` namespace.

        This method gets called by `HasParam._create_param_namespace()`.

        Subclasses can override this to customize how the arguments are
        determined.  For an example of why this can be useful, see the
        `ipalib.crud.Create` subclass.
        """
        for arg in self._get_param_iterable('args'):
            yield arg

    def check_args(self, args):
        """
        Sanity test for args namespace.

        This method gets called by `HasParam._create_param_namespace()`.
        """
        optional = False
        multivalue = False
        for arg in args():
            if optional and arg.required:
                raise ValueError(
                    '%s: required argument after optional' % arg.name
                )
            if multivalue:
                raise ValueError(
                    '%s: only final argument can be multivalue' % arg.name
                )
            if not arg.required:
                optional = True
            if arg.multivalue:
                multivalue = True

    def get_options(self):
        """
        Iterate through parameters for ``Command.options`` namespace.

        This method gets called by `HasParam._create_param_namespace()`.

        Subclasses can override this to customize how the arguments are
        determined.  For an example of why this can be useful, see the
        `ipalib.crud.Create` subclass.
        """
        for option in self._get_param_iterable('options'):
            yield option


class LocalOrRemote(Command):
    """
    A command that is explicitly executed locally or remotely.

    This is for commands that makes sense to execute either locally or
    remotely to return a perhaps different result.  The best example of
    this is the `ipalib.plugins.f_misc.env` plugin which returns the
    key/value pairs describing the configuration state: it can be
    """

    takes_options = (
        Flag('server?',
            doc='Forward to server instead of running locally',
        ),
    )

    def run(self, *args, **options):
        """
        Dispatch to forward() or execute() based on ``server`` option.

        When running in a client context, this command is executed remotely if
        ``options['server']`` is true; otherwise it is executed locally.

        When running in a server context, this command is always executed
        locally and the value of ``options['server']`` is ignored.
        """
        if options['server'] and not self.env.in_server:
            return self.forward(*args, **options)
        return self.execute(*args, **options)


class Object(HasParam):
    __public__ = frozenset((
        'backend',
        'methods',
        'properties',
        'params',
        'primary_key',
        'params_minus_pk',
        'params_minus',
        'get_dn',
    ))
    backend = None
    methods = None
    properties = None
    params = None
    primary_key = None
    params_minus_pk = None

    # Can override in subclasses:
    backend_name = None
    takes_params = tuple()

    def set_api(self, api):
        super(Object, self).set_api(api)
        self.methods = NameSpace(
            self.__get_attrs('Method'), sort=False, name_attr='attr_name'
        )
        self.properties = NameSpace(
            self.__get_attrs('Property'), sort=False, name_attr='attr_name'
        )
        self._create_param_namespace('params')
        pkeys = filter(lambda p: p.primary_key, self.params())
        if len(pkeys) > 1:
            raise ValueError(
                '%s (Object) has multiple primary keys: %s' % (
                    self.name,
                    ', '.join(p.name for p in pkeys),
                )
            )
        if len(pkeys) == 1:
            self.primary_key = pkeys[0]
            self.params_minus_pk = NameSpace(
                filter(lambda p: not p.primary_key, self.params()), sort=False
            )
        else:
            self.params_minus_pk = self.params

        if 'Backend' in self.api and self.backend_name in self.api.Backend:
            self.backend = self.api.Backend[self.backend_name]

    def params_minus(self, *names):
        """
        Yield all Param whose name is not in ``names``.
        """
        if len(names) == 1 and not isinstance(names[0], (Param, str)):
            names = names[0]
        minus = frozenset(names)
        for param in self.params():
            if param.name in minus or param in minus:
                continue
            yield param

    def get_dn(self, *args, **kwargs):
        """
        Construct an LDAP DN.
        """
        raise NotImplementedError('%s.get_dn()' % self.name)

    def __get_attrs(self, name):
        if name not in self.api:
            return
        namespace = self.api[name]
        assert type(namespace) is NameSpace
        for plugin in namespace(): # Equivalent to dict.itervalues()
            if plugin.obj_name == self.name:
                yield plugin

    def get_params(self):
        """
        This method gets called by `HasParam._create_param_namespace()`.
        """
        props = self.properties.__todict__()
        for spec in self._get_param_iterable('params'):
            if type(spec) is str:
                key = spec.rstrip('?*+')
            else:
                assert isinstance(spec, Param)
                key = spec.name
            if key in props:
                yield props.pop(key).param
            else:
                yield create_param(spec)
        def get_key(p):
            if p.param.required:
                if p.param.default_from is None:
                    return 0
                return 1
            return 2
        for prop in sorted(props.itervalues(), key=get_key):
            yield prop.param


class Attribute(Plugin):
    """
    Base class implementing the attribute-to-object association.

    `Attribute` plugins are associated with an `Object` plugin to group
    a common set of commands that operate on a common set of parameters.

    The association between attribute and object is done using a simple
    naming convention: the first part of the plugin class name (up to the
    first underscore) is the object name, and rest is the attribute name,
    as this table shows:

    ===============  ===========  ==============
    Class name       Object name  Attribute name
    ===============  ===========  ==============
    noun_verb        noun         verb
    user_add         user         add
    user_first_name  user         first_name
    ===============  ===========  ==============

    For example:

    >>> class user_add(Attribute):
    ...     pass
    ...
    >>> instance = user_add()
    >>> instance.obj_name
    'user'
    >>> instance.attr_name
    'add'

    In practice the `Attribute` class is not used directly, but rather is
    only the base class for the `Method` and `Property` classes.  Also see
    the `Object` class.
    """
    __public__ = frozenset((
        'obj',
        'obj_name',
    ))
    __obj = None

    def __init__(self):
        m = re.match(
            '^([a-z][a-z0-9]+)_([a-z][a-z0-9]+(?:_[a-z][a-z0-9]+)*)$',
            self.__class__.__name__
        )
        assert m
        self.__obj_name = m.group(1)
        self.__attr_name = m.group(2)
        super(Attribute, self).__init__()

    def __get_obj_name(self):
        return self.__obj_name
    obj_name = property(__get_obj_name)

    def __get_attr_name(self):
        return self.__attr_name
    attr_name = property(__get_attr_name)

    def __get_obj(self):
        """
        Returns the obj instance this attribute is associated with, or None
        if no association has been set.
        """
        return self.__obj
    obj = property(__get_obj)

    def set_api(self, api):
        self.__obj = api.Object[self.obj_name]
        super(Attribute, self).set_api(api)


class Method(Attribute, Command):
    """
    A command with an associated object.

    A `Method` plugin must have a corresponding `Object` plugin.  The
    association between object and method is done through a simple naming
    convention: the first part of the method name (up to the first under
    score) is the object name, as the examples in this table show:

    =============  ===========  ==============
    Method name    Object name  Attribute name
    =============  ===========  ==============
    user_add       user         add
    noun_verb      noun         verb
    door_open_now  door         open_now
    =============  ===========  ==============

    There are three different places a method can be accessed.  For example,
    say you created a `Method` plugin and its corresponding `Object` plugin
    like this:

    >>> from ipalib import create_api
    >>> api = create_api()
    >>> class user_add(Method):
    ...     def run(self):
    ...             return 'Added the user!'
    ...
    >>> class user(Object):
    ...     pass
    ...
    >>> api.register(user_add)
    >>> api.register(user)
    >>> api.finalize()

    First, the ``user_add`` plugin can be accessed through the ``api.Method``
    namespace:

    >>> list(api.Method)
    ['user_add']
    >>> api.Method.user_add() # Will call user_add.run()
    'Added the user!'

    Second, because `Method` is a subclass of `Command`, the ``user_add``
    plugin can also be accessed through the ``api.Command`` namespace:

    >>> list(api.Command)
    ['user_add']
    >>> api.Command.user_add() # Will call user_add.run()
    'Added the user!'

    And third, ``user_add`` can be accessed as an attribute on the ``user``
    `Object`:

    >>> list(api.Object)
    ['user']
    >>> list(api.Object.user.methods)
    ['add']
    >>> api.Object.user.methods.add() # Will call user_add.run()
    'Added the user!'

    The `Attribute` base class implements the naming convention for the
    attribute-to-object association.  Also see the `Object` and the
    `Property` classes.
    """
    __public__ = Attribute.__public__.union(Command.__public__)
    extra_options_first = False
    extra_args_first = False

    def __init__(self):
        super(Method, self).__init__()


class Property(Attribute):
    __public__ = frozenset((
        'rules',
        'param',
        'type',
    )).union(Attribute.__public__)

    klass = Str
    default = None
    default_from = None
    normalizer = None

    def __init__(self):
        super(Property, self).__init__()
        self.rules = tuple(
            sorted(self.__rules_iter(), key=lambda f: getattr(f, '__name__'))
        )
        self.kwargs = tuple(
            sorted(self.__kw_iter(), key=lambda keyvalue: keyvalue[0])
        )
        kw = dict(self.kwargs)
        self.param = self.klass(self.attr_name, *self.rules, **kw)

    def __kw_iter(self):
        for (key, kind, default) in self.klass.kwargs:
            if getattr(self, key, None) is not None:
                yield (key, getattr(self, key))

    def __rules_iter(self):
        """
        Iterates through the attributes in this instance to retrieve the
        methods implementing validation rules.
        """
        for name in dir(self.__class__):
            if name.startswith('_'):
                continue
            base_attr = getattr(self.__class__, name)
            if is_rule(base_attr):
                attr = getattr(self, name)
                if is_rule(attr):
                    yield attr


class Application(Command):
    """
    Base class for commands register by an external application.

    Special commands that only apply to a particular application built atop
    `ipalib` should subclass from ``Application``.

    Because ``Application`` subclasses from `Command`, plugins that subclass
    from ``Application`` with be available in both the ``api.Command`` and
    ``api.Application`` namespaces.
    """

    __public__ = frozenset((
        'application',
        'set_application'
    )).union(Command.__public__)
    __application = None

    def __get_application(self):
        """
        Returns external ``application`` object.
        """
        return self.__application
    application = property(__get_application)

    def set_application(self, application):
        """
        Sets the external application object to ``application``.
        """
        if self.__application is not None:
            raise AttributeError(
                '%s.application can only be set once' % self.name
            )
        if application is None:
            raise TypeError(
                '%s.application cannot be None' % self.name
            )
        object.__setattr__(self, '_Application__application', application)
        assert self.application is application
