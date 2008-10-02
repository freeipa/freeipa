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

    >>> login.callback
    <function <lambda> at 0x7fdd225cd7d0>
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
            self.keys = callback.func_code.co_varnames
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
    type          ipa_type.Type      ipa_type.Unicode()
    doc           str                ''
    required      bool               True
    multivalue    bool               False
    primary_key   bool               False
    normalize     callable           None
    default       same as type.type  None
    default_from  callable           None
    ============  =================  ==================
    """
    __nones = (None, '', tuple(), [])
    __defaults = dict(
        type=ipa_types.Unicode(),
        doc='',
        required=True,
        multivalue=False,
        primary_key=False,
        normalize=None,
        default=None,
        default_from=None,
        rules=tuple(),
    )

    def __init__(self, name, **override):
        if not ('required' in override or 'multivalue' in override):
            (name, kw_from_spec) = parse_param_spec(name)
            override.update(kw_from_spec)
        kw = dict(self.__defaults)
        if not set(kw).issuperset(override):
            extra = sorted(set(override) - set(kw))
            raise TypeError(
                'Param.__init__() takes no such kwargs: %s' % ', '.join(extra)
            )
        kw.update(override)
        self.__kw = kw
        self.name = check_name(name)
        self.type = self.__check_isinstance(ipa_types.Type, 'type')
        self.doc = self.__check_type(str, 'doc')
        self.required = self.__check_type(bool, 'required')
        self.multivalue = self.__check_type(bool, 'multivalue')
        self.default = kw['default']
        df = kw['default_from']
        if callable(df) and not isinstance(df, DefaultFrom):
            df = DefaultFrom(df)
        self.default_from = check_type(df, DefaultFrom, 'default_from',
            allow_none=True
        )
        self.__normalize = kw['normalize']
        self.rules = self.__check_type(tuple, 'rules')
        self.all_rules = (self.type.validate,) + self.rules
        self.primary_key = self.__check_type(bool, 'primary_key')
        lock(self)

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
        return '%s(%r, %s())' % (
            self.__class__.__name__,
            self.name,
            self.type.name,
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
        'kw_to_args',
    ))
    takes_options = tuple()
    takes_args = tuple()
    args = None
    options = None
    params = None
    can_forward = True

    def finalize(self):
        self.args = plugable.NameSpace(self.__create_args(), sort=False)
        if len(self.args) == 0 or not self.args[-1].multivalue:
            self.max_args = len(self.args)
        else:
            self.max_args = None
        self.options = plugable.NameSpace(self.__create_options(), sort=False)
        self.params = plugable.NameSpace(
            tuple(self.args()) + tuple(self.options()), sort=False
        )
        super(Command, self).finalize()

    def get_args(self):
        return self.takes_args

    def get_options(self):
        return self.takes_options

    def __create_args(self):
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

    def __create_options(self):
        for option in self.get_options():
            yield create_param(option)

    def convert(self, **kw):
        return dict(
            (k, self.params[k].convert(v)) for (k, v) in kw.iteritems()
        )

    def normalize(self, **kw):
        return dict(
            (k, self.params[k].normalize(v)) for (k, v) in kw.iteritems()
        )

    def __get_default_iter(self, kw):
        for param in self.params():
            if param.name not in kw:
                yield (param.name, param.get_default(**kw))

    def get_default(self, **kw):
        return dict(self.__get_default_iter(kw))

    def validate(self, **kw):
        for param in self.params():
            value = kw.get(param.name, None)
            if value is not None:
                param.validate(value)
            elif param.required:
                raise errors.RequirementError(param.name)

    def execute(self, *args, **kw):
        print '%s.execute():' % self.name
        print '  args =', args
        print '  kw =', kw

    def forward(self, *args, **kw):
        xmlrpc_client = self.api.Backend.xmlrpc.get_client()
        return getattr(xmlrpc_client, self.name)(kw, *args)


    def __call__(self, *args, **kw):
        if len(args) > 0:
            arg_kw = self.args_to_kw(*args)
            assert set(arg_kw).intersection(kw) == set()
            kw.update(arg_kw)
        kw = self.normalize(**kw)
        kw = self.convert(**kw)
        kw.update(self.get_default(**kw))
        self.validate(**kw)
        args = tuple(kw.pop(name) for name in self.args)
        return self.run(*args, **kw)

    def run(self, *args, **kw):
        if self.api.env.server_context:
            target = self.execute
        else:
            target = self.forward
        object.__setattr__(self, 'run', target)
        return target(*args, **kw)

    def args_to_kw(self, *values):
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

    def kw_to_args(self, **kw):
        return tuple(kw.get(name, None) for name in self.args)


class Object(plugable.Plugin):
    __public__ = frozenset((
        'backend',
        'methods',
        'properties',
        'params',
        'primary_key',
        'params_minus_pk',
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
