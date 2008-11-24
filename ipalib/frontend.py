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
import plugable
from plugable import lock, check_name
import errors
from errors import check_type, check_isinstance, raise_TypeError
import ipa_types
from util import make_repr


RULE_FLAG = 'validation_rule'

def rule(obj):
    assert not hasattr(obj, RULE_FLAG)
    setattr(obj, RULE_FLAG, True)
    return obj

def is_rule(obj):
    return callable(obj) and getattr(obj, RULE_FLAG, False) is True


class DefaultFrom(plugable.ReadOnly):
    """
    Derive a default value from other supplied values.

    For example, say you wanted to create a default for the user's login from
    the user's first and last names. It could be implemented like this:

    >>> login = DefaultFrom(lambda first, last: first[0] + last)
    >>> login(first='John', last='Doe')
    'JDoe'

    If you do not explicitly provide keys when you create a DefaultFrom
    instance, the keys are implicitly derived from your callback by
    inspecting ``callback.func_code.co_varnames``. The keys are available
    through the ``DefaultFrom.keys`` instance attribute, like this:

    >>> login.keys
    ('first', 'last')

    The callback is available through the ``DefaultFrom.callback`` instance
    attribute, like this:

    >>> login.callback # doctest:+ELLIPSIS
    <function <lambda> at 0x...>
    >>> login.callback.func_code.co_varnames # The keys
    ('first', 'last')

    The keys can be explicitly provided as optional positional arguments after
    the callback. For example, this is equivalent to the ``login`` instance
    above:

    >>> login2 = DefaultFrom(lambda a, b: a[0] + b, 'first', 'last')
    >>> login2.keys
    ('first', 'last')
    >>> login2.callback.func_code.co_varnames # Not the keys
    ('a', 'b')
    >>> login2(first='John', last='Doe')
    'JDoe'

    If any keys are missing when calling your DefaultFrom instance, your
    callback is not called and None is returned. For example:

    >>> login(first='John', lastname='Doe') is None
    True
    >>> login() is None
    True

    Any additional keys are simply ignored, like this:

    >>> login(last='Doe', first='John', middle='Whatever')
    'JDoe'

    As above, because `DefaultFrom.__call__` takes only pure keyword
    arguments, they can be supplied in any order.

    Of course, the callback need not be a lambda expression. This third
    example is equivalent to both the ``login`` and ``login2`` instances
    above:

    >>> def get_login(first, last):
    ...     return first[0] + last
    ...
    >>> login3 = DefaultFrom(get_login)
    >>> login3.keys
    ('first', 'last')
    >>> login3.callback.func_code.co_varnames
    ('first', 'last')
    >>> login3(first='John', last='Doe')
    'JDoe'
    """

    def __init__(self, callback, *keys):
        """
        :param callback: The callable to call when all keys are present.
        :param keys: Optional keys used for source values.
        """
        if not callable(callback):
            raise TypeError('callback must be callable; got %r' % callback)
        self.callback = callback
        if len(keys) == 0:
            fc = callback.func_code
            self.keys = fc.co_varnames[:fc.co_argcount]
        else:
            self.keys = keys
        for key in self.keys:
            if type(key) is not str:
                raise_TypeError(key, str, 'keys')
        lock(self)

    def __call__(self, **kw):
        """
        If all keys are present, calls the callback; otherwise returns None.

        :param kw: The keyword arguments.
        """
        vals = tuple(kw.get(k, None) for k in self.keys)
        if None in vals:
            return
        try:
            return self.callback(*vals)
        except StandardError:
            pass


def parse_param_spec(spec):
    """
    Parse a param spec into to (name, kw).

    The ``spec`` string determines the param name, whether the param is
    required, and whether the param is multivalue according the following
    syntax:

    ======  =====  ========  ==========
    Spec    Name   Required  Multivalue
    ======  =====  ========  ==========
    'var'   'var'  True      False
    'var?'  'var'  False     False
    'var*'  'var'  False     True
    'var+'  'var'  True      True
    ======  =====  ========  ==========

    For example,

    >>> parse_param_spec('login')
    ('login', {'required': True, 'multivalue': False})
    >>> parse_param_spec('gecos?')
    ('gecos', {'required': False, 'multivalue': False})
    >>> parse_param_spec('telephone_numbers*')
    ('telephone_numbers', {'required': False, 'multivalue': True})
    >>> parse_param_spec('group+')
    ('group', {'required': True, 'multivalue': True})

    :param spec: A spec string.
    """
    if type(spec) is not str:
        raise_TypeError(spec, str, 'spec')
    if len(spec) < 2:
        raise ValueError(
            'param spec must be at least 2 characters; got %r' % spec
        )
    _map = {
        '?': dict(required=False, multivalue=False),
        '*': dict(required=False, multivalue=True),
        '+': dict(required=True, multivalue=True),
    }
    end = spec[-1]
    if end in _map:
        return (spec[:-1], _map[end])
    return (spec, dict(required=True, multivalue=False))


class Param(plugable.ReadOnly):
    """
    A parameter accepted by a `Command`.

    ============  =================  ==================
    Keyword       Type               Default
    ============  =================  ==================
    cli_name      str                defaults to name
    type          ipa_type.Type      ipa_type.Unicode()
    doc           str                ""
    required      bool               True
    multivalue    bool               False
    primary_key   bool               False
    normalize     callable           None
    default       same as type.type  None
    default_from  callable           None
    flags         frozenset          frozenset()
    ============  =================  ==================
    """
    __nones = (None, '', tuple(), [])
    __defaults = dict(
        cli_name=None,
        type=ipa_types.Unicode(),
        doc='',
        required=True,
        multivalue=False,
        primary_key=False,
        normalize=None,
        default=None,
        default_from=None,
        flags=frozenset(),
        rules=tuple(),
    )

    def __init__(self, name, **override):
        self.__param_spec = name
        self.__override = override
        self.__kw = dict(self.__defaults)
        if not ('required' in override or 'multivalue' in override):
            (name, kw_from_spec) = parse_param_spec(name)
            self.__kw.update(kw_from_spec)
        self.__kw['cli_name'] = name
        if not set(self.__kw).issuperset(override):
            extra = sorted(set(override) - set(self.__kw))
            raise TypeError(
                'Param.__init__() takes no such kwargs: %s' % ', '.join(extra)
            )
        self.__kw.update(override)
        self.name = check_name(name)
        self.cli_name = check_name(self.__kw.get('cli_name', name))
        self.type = self.__check_isinstance(ipa_types.Type, 'type')
        self.doc = self.__check_type(str, 'doc')
        self.required = self.__check_type(bool, 'required')
        self.multivalue = self.__check_type(bool, 'multivalue')
        self.default = self.__kw['default']
        df = self.__kw['default_from']
        if callable(df) and not isinstance(df, DefaultFrom):
            df = DefaultFrom(df)
        self.default_from = check_type(df, DefaultFrom, 'default_from',
            allow_none=True
        )
        self.flags = frozenset(self.__kw['flags'])
        self.__normalize = self.__kw['normalize']
        self.rules = self.__check_type(tuple, 'rules')
        self.all_rules = (self.type.validate,) + self.rules
        self.primary_key = self.__check_type(bool, 'primary_key')
        lock(self)

    def ispassword(self):
        """
        Return ``True`` is this Param is a password.
        """
        return 'password' in self.flags

    def __clone__(self, **override):
        """
        Return a new `Param` instance similar to this one.
        """
        kw = dict(self.__kw)
        kw.update(override)
        return self.__class__(self.name, **kw)

    def __check_type(self, type_, name, allow_none=False):
        value = self.__kw[name]
        return check_type(value, type_, name, allow_none)

    def __check_isinstance(self, type_, name, allow_none=False):
        value = self.__kw[name]
        return check_isinstance(value, type_, name, allow_none)

    def __dispatch(self, value, scalar):
        """
        Helper method used by `normalize` and `convert`.
        """
        if value in self.__nones:
            return
        if self.multivalue:
            if type(value) in (tuple, list):
                return tuple(
                    scalar(v, i) for (i, v) in enumerate(value)
                )
            return (scalar(value, 0),) # tuple
        return scalar(value)

    def __normalize_scalar(self, value, index=None):
        """
        Normalize a scalar value.

        This method is called once with each value in multivalue.
        """
        if not isinstance(value, basestring):
            return value
        try:
            return self.__normalize(value)
        except StandardError:
            return value

    def normalize(self, value):
        """
        Normalize ``value`` using normalize callback.

        For example:

        >>> param = Param('telephone',
        ...     normalize=lambda value: value.replace('.', '-')
        ... )
        >>> param.normalize('800.123.4567')
        '800-123-4567'

        If this `Param` instance does not have a normalize callback,
        ``value`` is returned unchanged.

        If this `Param` instance has a normalize callback and ``value`` is
        a basestring, the normalize callback is called and its return value
        is returned.

        If ``value`` is not a basestring, or if an exception is caught
        when calling the normalize callback, ``value`` is returned unchanged.

        :param value: A proposed value for this parameter.
        """
        if self.__normalize is None:
            return value
        return self.__dispatch(value, self.__normalize_scalar)

    def __convert_scalar(self, value, index=None):
        """
        Convert a scalar value.

        This method is called once with each value in multivalue.
        """
        if value in self.__nones:
            return
        converted = self.type(value)
        if converted is None:
            raise errors.ConversionError(
                self.name, value, self.type, index=index
            )
        return converted

    def convert(self, value):
        """
        Convert/coerce ``value`` to Python type for this `Param`.

        For example:

        >>> param = Param('an_int', type=ipa_types.Int())
        >>> param.convert(7.2)
        7
        >>> param.convert(" 7 ")
        7

        If ``value`` can not be converted, ConversionError is raised, which
        is as subclass of ValidationError.

        If ``value`` is None, conversion is not attempted and None is
        returned.

        :param value: A proposed value for this parameter.
        """
        return self.__dispatch(value, self.__convert_scalar)

    def __validate_scalar(self, value, index=None):
        """
        Validate a scalar value.

        This method is called once with each value in multivalue.
        """
        if type(value) is not self.type.type:
            raise_TypeError(value, self.type.type, 'value')
        for rule in self.rules:
            error = rule(value)
            if error is not None:
                raise errors.RuleError(
                    self.name, value, error, rule, index=index
                )

    def validate(self, value):
        """
        Check validity of a value.

        Each validation rule is called in turn and if any returns and error,
        RuleError is raised, which is a subclass of ValidationError.

        :param value: A proposed value for this parameter.
        """
        if value is None:
            if self.required:
                raise errors.RequirementError(self.name)
            return
        if self.multivalue:
            if type(value) is not tuple:
                raise_TypeError(value, tuple, 'value')
            for (i, v) in enumerate(value):
                self.__validate_scalar(v, i)
        else:
            self.__validate_scalar(value)

    def get_default(self, **kw):
        """
        Return a default value for this parameter.

        If this `Param` instance does not have a default_from() callback, this
        method always returns the static Param.default instance attribute.

        On the other hand, if this `Param` instance has a default_from()
        callback, the callback is called and its return value is returned
        (assuming that value is not None).

        If the default_from() callback returns None, or if an exception is
        caught when calling the default_from() callback, the static
        Param.default instance attribute is returned.

        :param kw: Optional keyword arguments to pass to default_from().
        """
        if self.default_from is not None:
            default = self.default_from(**kw)
            if default is not None:
                try:
                    return self.convert(self.normalize(default))
                except errors.ValidationError:
                    return None
        return self.default

    def get_values(self):
        """
        Return a tuple of possible values.

        For enumerable types, a tuple containing the possible values is
        returned.  For all other types, an empty tuple is returned.
        """
        if self.type.name in ('Enum', 'CallbackEnum'):
            return self.type.values
        return tuple()

    def __call__(self, value, **kw):
        if value in self.__nones:
            value = self.get_default(**kw)
        else:
            value = self.convert(self.normalize(value))
        self.validate(value)
        return value

    def __repr__(self):
        """
        Return an expresion that could construct this `Param` instance.
        """
        return make_repr(
            self.__class__.__name__,
            self.__param_spec,
            **self.__override
        )


def create_param(spec):
    """
    Create a `Param` instance from a param spec.

    If ``spec`` is a `Param` instance, ``spec`` is returned unchanged.

    If ``spec`` is an str instance, then ``spec`` is parsed and an
    appropriate `Param` instance is created and returned.

    See `parse_param_spec` for the definition of the spec syntax.

    :param spec: A spec string or a `Param` instance.
    """
    if type(spec) is Param:
        return spec
    if type(spec) is not str:
        raise TypeError(
            'create_param() takes %r or %r; got %r' % (str, Param, spec)
        )
    return Param(spec)


class Command(plugable.Plugin):
    """
    A public IPA atomic operation.

    All plugins that subclass from `Command` will be automatically available
    as a CLI command and as an XML-RPC method.

    Plugins that subclass from Command are registered in the ``api.Command``
    namespace. For example:

    >>> api = plugable.API(Command)
    >>> class my_command(Command):
    ...     pass
    ...
    >>> api.register(my_command)
    >>> api.finalize()
    >>> list(api.Command)
    ['my_command']
    >>> api.Command.my_command # doctest:+ELLIPSIS
    PluginProxy(Command, ...my_command())
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
        'args_to_kw',
        'params_2_args_options',
        'output_for_cli',
    ))
    takes_options = tuple()
    takes_args = tuple()
    args = None
    options = None
    params = None
    output_for_cli = None

    def __call__(self, *args, **kw):
        """
        Perform validation and then execute the command.

        If not in a server context, the call will be forwarded over
        XML-RPC and the executed an the nearest IPA server.
        """
        self.debug(make_repr(self.name, *args, **kw))
        if len(args) > 0:
            arg_kw = self.args_to_kw(*args)
            assert set(arg_kw).intersection(kw) == set()
            kw.update(arg_kw)
        kw = self.normalize(**kw)
        kw = self.convert(**kw)
        kw.update(self.get_default(**kw))
        self.validate(**kw)
        (args, options) = self.params_2_args_options(kw)
        result = self.run(*args, **options)
        self.debug('%s result: %r', self.name, result)
        return result

    def args_to_kw(self, *values):
        """
        Map positional into keyword arguments.
        """
        if self.max_args is not None and len(values) > self.max_args:
            if self.max_args == 0:
                raise errors.ArgumentError(self, 'takes no arguments')
            if self.max_args == 1:
                raise errors.ArgumentError(self, 'takes at most 1 argument')
            raise errors.ArgumentError(self,
                'takes at most %d arguments' % len(self.args)
            )
        return dict(self.__args_to_kw_iter(values))

    def __args_to_kw_iter(self, values):
        """
        Generator used by `Command.args_to_kw` method.
        """
        multivalue = False
        for (i, arg) in enumerate(self.args()):
            assert not multivalue
            if len(values) > i:
                if arg.multivalue:
                    multivalue = True
                    yield (arg.name, values[i:])
                else:
                    yield (arg.name, values[i])
            else:
                break

    def params_2_args_options(self, params):
        """
        Split params into (args, kw).
        """
        args = tuple(params.get(name, None) for name in self.args)
        options = dict(
            (name, params.get(name, None)) for name in self.options
        )
        return (args, options)

    def normalize(self, **kw):
        """
        Return a dictionary of normalized values.

        For example:

        >>> class my_command(Command):
        ...     takes_options = (
        ...         Param('first', normalize=lambda value: value.lower()),
        ...         Param('last'),
        ...     )
        ...
        >>> c = my_command()
        >>> c.finalize()
        >>> c.normalize(first='JOHN', last='DOE')
        {'last': 'DOE', 'first': 'john'}
        """
        return dict(
            (k, self.params[k].normalize(v)) for (k, v) in kw.iteritems()
        )

    def convert(self, **kw):
        """
        Return a dictionary of values converted to correct type.

        >>> from ipalib import ipa_types
        >>> class my_command(Command):
        ...     takes_args = (
        ...         Param('one', type=ipa_types.Int()),
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

    def get_default(self, **kw):
        """
        Return a dictionary of defaults for all missing required values.

        For example:

        >>> class my_command(Command):
        ...     takes_args = [Param('color', default='Red')]
        ...
        >>> c = my_command()
        >>> c.finalize()
        >>> c.get_default()
        {'color': 'Red'}
        >>> c.get_default(color='Yellow')
        {}
        """
        return dict(self.__get_default_iter(kw))

    def __get_default_iter(self, kw):
        """
        Generator method used by `Command.get_default`.
        """
        for param in self.params():
            if kw.get(param.name, None) is None:
                if param.required:
                    yield (param.name, param.get_default(**kw))
                elif isinstance(param.type, ipa_types.Bool):
                    yield (param.name, param.default)
                else:
                    yield (param.name, None)

    def validate(self, **kw):
        """
        Validate all values.

        If any value fails the validation, `ipalib.errors.ValidationError`
        (or a subclass thereof) will be raised.
        """
        for param in self.params():
            value = kw.get(param.name, None)
            if value is not None:
                param.validate(value)
            elif param.required:
                raise errors.RequirementError(param.name)

    def run(self, *args, **kw):
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
            target = self.execute
        else:
            target = self.forward
        object.__setattr__(self, 'run', target)
        return target(*args, **kw)

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
        return self.Backend.xmlrpc.forward_call(self.name, *args, **kw)

    def finalize(self):
        """
        Finalize plugin initialization.

        This method creates the ``args``, ``options``, and ``params``
        namespaces.  This is not done in `Command.__init__` because
        subclasses (like `crud.Add`) might need to access other plugins
        loaded in self.api to determine what their custom `Command.get_args`
        and `Command.get_options` methods should yield.
        """
        self.args = plugable.NameSpace(self.__create_args(), sort=False)
        if len(self.args) == 0 or not self.args[-1].multivalue:
            self.max_args = len(self.args)
        else:
            self.max_args = None
        self.options = plugable.NameSpace(
            (create_param(spec) for spec in self.get_options()),
            sort=False
        )
        def get_key(p):
            if p.required:
                if p.default_from is None:
                    return 0
                return 1
            return 2
        self.params = plugable.NameSpace(
            sorted(tuple(self.args()) + tuple(self.options()), key=get_key),
            sort=False
        )
        super(Command, self).finalize()

    def get_args(self):
        """
        Return iterable with arguments for Command.args namespace.

        Subclasses can override this to customize how the arguments
        are determined.  For an example of why this can be useful,
        see `ipalib.crud.Mod`.
        """
        return self.takes_args

    def get_options(self):
        """
        Return iterable with options for Command.options namespace.

        Subclasses can override this to customize how the options
        are determined.  For an example of why this can be useful,
        see `ipalib.crud.Mod`.
        """
        return self.takes_options

    def __create_args(self):
        """
        Generator used to create args namespace.
        """
        optional = False
        multivalue = False
        for arg in self.get_args():
            arg = create_param(arg)
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
            yield arg


class LocalOrRemote(Command):
    """
    A command that is explicitly executed locally or remotely.

    This is for commands that makes sense to execute either locally or
    remotely to return a perhaps different result.  The best example of
    this is the `ipalib.plugins.f_misc.env` plugin which returns the
    key/value pairs describing the configuration state: it can be
    """

    takes_options = (
        Param('server?', type=ipa_types.Bool(), default=False,
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


class Object(plugable.Plugin):
    __public__ = frozenset((
        'backend',
        'methods',
        'properties',
        'params',
        'primary_key',
        'params_minus_pk',
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
        self.methods = plugable.NameSpace(
            self.__get_attrs('Method'), sort=False
        )
        self.properties = plugable.NameSpace(
            self.__get_attrs('Property'), sort=False
        )
        self.params = plugable.NameSpace(
            self.__get_params(), sort=False
        )
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
            self.params_minus_pk = plugable.NameSpace(
                filter(lambda p: not p.primary_key, self.params()), sort=False
            )

        if 'Backend' in self.api and self.backend_name in self.api.Backend:
            self.backend = self.api.Backend[self.backend_name]

    def get_dn(self, primary_key):
        """
        Construct an LDAP DN from a primary_key.
        """
        raise NotImplementedError('%s.get_dn()' % self.name)

    def __get_attrs(self, name):
        if name not in self.api:
            return
        namespace = self.api[name]
        assert type(namespace) is plugable.NameSpace
        for proxy in namespace(): # Equivalent to dict.itervalues()
            if proxy.obj_name == self.name:
                yield proxy.__clone__('attr_name')

    def __get_params(self):
        props = self.properties.__todict__()
        for spec in self.takes_params:
            if type(spec) is str:
                key = spec.rstrip('?*+')
            else:
                assert type(spec) is Param
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


class Attribute(plugable.Plugin):
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
            '^([a-z][a-z0-9]+)_([a-z][a-z0-9]+)$',
            self.__class__.__name__
        )
        assert m
        self.__obj_name = m.group(1)
        self.__attr_name = m.group(2)

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

    >>> api = plugable.API(Command, Object, Method, Property)
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

    def __init__(self):
        Attribute.__init__(self)
        Command.__init__(self)


class Property(Attribute):
    __public__ = frozenset((
        'rules',
        'param',
        'type',
    )).union(Attribute.__public__)

    type = ipa_types.Unicode()
    required = False
    multivalue = False
    default = None
    default_from = None
    normalize = None

    def __init__(self):
        super(Property, self).__init__()
        self.rules = tuple(sorted(
            self.__rules_iter(),
            key=lambda f: getattr(f, '__name__'),
        ))
        self.param = Param(self.attr_name,
            type=self.type,
            doc=self.doc,
            required=self.required,
            multivalue=self.multivalue,
            default=self.default,
            default_from=self.default_from,
            rules=self.rules,
            normalize=self.normalize,
        )

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
