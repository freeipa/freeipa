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
from parameters import create_param, Param, Str, Flag, Password
from util import make_repr

from errors2 import ZeroArgumentError, MaxArgumentError, OverlapError
from constants import TYPE_ERROR


RULE_FLAG = 'validation_rule'

def rule(obj):
    assert not hasattr(obj, RULE_FLAG)
    setattr(obj, RULE_FLAG, True)
    return obj

def is_rule(obj):
    return callable(obj) and getattr(obj, RULE_FLAG, False) is True


class Command(plugable.Plugin):
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
                if type(kw[name]) is tuple:
                    yield (name, [str(value) for value in kw[name]])
                else:
                    yield (name, str(kw[name]))

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
        ...     takes_args = [Str('color', default=u'Red')]
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

        If any value fails the validation, `ipalib.errors2.ValidationError`
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

    def _get_takes(self, name):
        attr = getattr(self, name)
        if isinstance(attr, (Param, str)):
            return (attr,)
        if callable(attr):
            return attr()
        return attr

    def get_args(self):
        """
        Iterate through parameters for ``Command.args`` namespace.

        Subclasses can override this to customize how the arguments
        are determined.  For an example of why this can be useful,
        see `ipalib.crud.Mod`.
        """
        for arg in self._get_takes('takes_args'):
            yield arg

    def get_options(self):
        """
        Iterate through parameters for ``Command.options`` namespace.

        Subclasses can override this to customize how the options
        are determined.  For an example of why this can be useful,
        see `ipalib.crud.Mod`.
        """
        for option in self._get_takes('takes_options'):
            yield option

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


class Object(plugable.Plugin):
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
