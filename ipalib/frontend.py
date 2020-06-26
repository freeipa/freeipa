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
Base classes for all front-end plugins.
"""
import logging

import six

from ipapython.version import API_VERSION
from ipapython.ipautil import APIVersion
from ipalib.base import NameSpace
from ipalib.plugable import Plugin, APINameSpace
from ipalib.parameters import create_param, Param, Str, Flag
from ipalib.parameters import create_signature
from ipalib.parameters import Password  # pylint: disable=unused-import
from ipalib.output import Output, Entry, ListOfEntries
from ipalib.text import _
from ipalib.errors import (ZeroArgumentError, MaxArgumentError, OverlapError,
    VersionError, OptionError,
    ValidationError, ConversionError)
from ipalib import errors, messages
from ipalib.request import context, context_frame
from ipalib.util import classproperty, classobjectproperty, json_serialize

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

RULE_FLAG = 'validation_rule'

def rule(obj):
    assert not hasattr(obj, RULE_FLAG)
    setattr(obj, RULE_FLAG, True)
    return obj

def is_rule(obj):
    return callable(obj) and getattr(obj, RULE_FLAG, False) is True


def entry_count(entry):
    """
    Return the number of entries in an entry. This is primarly for the
    failed output parameter so we don't print empty values.

    We also use this to determine if a non-zero return value is needed.
    """
    num_entries = 0
    for f in entry:
        if type(entry[f]) is dict:
            num_entries = num_entries + entry_count(entry[f])
        else:
            num_entries = num_entries + len(entry[f])

    return num_entries


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
    # HasParam is the base class for most frontend plugins, that make it to users
    # This flag indicates that the command should not be available in the cli
    NO_CLI = False

    def _get_param_iterable(self, name, verb='takes'):
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
        src_name = verb + '_' + name
        src = getattr(self, src_name, None)
        if type(src) is tuple:
            return src
        if isinstance(src, (Param, str)):
            return (src,)
        if callable(src):
            return src()
        if src is None:
            return tuple()
        raise TypeError(
            '%s.%s must be a tuple, callable, or spec; got %r' % (
                self.name, src_name, src
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
        (u'foo', u'bar', u'another')
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
        if not self.api.is_production_mode():
            check = getattr(self, 'check_' + name, None)
            if callable(check):
                check(namespace)
        setattr(self, name, namespace)

    @property
    def context(self):
        return context.current_frame


_callback_registry = {}


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
    >>> api.add_plugin(my_command)
    >>> api.finalize()
    >>> list(api.Command)
    [<class '__main__.my_command'>]
    >>> api.Command.my_command # doctest:+ELLIPSIS
    ipalib.frontend.my_command()

    This class's subclasses allow different types of callbacks to be added and
    removed to them.
    Registering a callback is done either by ``register_callback``, or by
    defining a ``<type>_callback`` method.

    Subclasses should define the `callback_types` attribute as a tuple of
    allowed callback types.
    """

    takes_options = tuple()
    takes_args = tuple()
    # Create stubs for attributes that are set in _on_finalize()
    args = Plugin.finalize_attr('args')
    options = Plugin.finalize_attr('options')
    params = Plugin.finalize_attr('params')
    params_by_default = Plugin.finalize_attr('params_by_default')
    obj = None

    use_output_validation = True
    output = Plugin.finalize_attr('output')
    has_output = ('result',)
    output_params = Plugin.finalize_attr('output_params')
    has_output_params = tuple()

    internal_options = tuple()

    msg_summary = None
    msg_truncated = _('Results are truncated, try a more specific search')

    callback_types = ('interactive_prompt',)

    api_version = API_VERSION

    @classmethod
    def __topic_getter(cls):
        return cls.__module__.rpartition('.')[2]

    topic = classproperty(__topic_getter)

    @classobjectproperty
    @classmethod
    def __signature__(cls, obj):
        # signature is cached on the class object
        if hasattr(cls, "_signature"):
            return cls._signature
        # can only create signature for 'final' classes
        # help(api.Command.user_show) breaks because pydoc inspects parent
        # classes and baseuser plugin is not a registered object.
        if cls.__subclasses__():
            cls._signature = None
            return None
        # special, rare case: user calls help() on a plugin class instead of
        # an instance
        if obj is None:
            from ipalib import api
            obj = cls(api=api)
        cls._signature = signature = create_signature(obj)
        return signature

    @property
    def forwarded_name(self):
        return self.full_name

    def __call__(self, *args, **options):
        """
        Perform validation and then execute the command.

        If not in a server context, the call will be forwarded over
        XML-RPC and the executed an the nearest IPA server.
        """
        self.ensure_finalized()
        with context_frame():
            self.context.principal = getattr(context, 'principal', None)
            return self.__do_call(*args, **options)

    def __do_call(self, *args, **options):
        self.context.__messages = []
        if 'version' in options:
            self.verify_client_version(unicode(options['version']))
        elif self.api.env.skip_version_check and not self.api.env.in_server:
            options['version'] = u'2.0'
        else:
            options['version'] = self.api_version
            if self.api.env.in_server:
                # add message only on server side
                self.add_message(
                    messages.VersionMissing(server_version=self.api_version))
        params = self.args_options_2_params(*args, **options)
        logger.debug(
            'raw: %s(%s)', self.name, ', '.join(self._repr_iter(**params))
        )
        if self.api.env.in_server:
            params.update(self.get_default(**params))
        params = self.normalize(**params)
        params = self.convert(**params)
        logger.debug(
            '%s(%s)', self.name, ', '.join(self._repr_iter(**params))
        )
        if self.api.env.in_server:
            self.validate(**params)
        (args, options) = self.params_2_args_options(**params)
        ret = self.run(*args, **options)
        if isinstance(ret, dict):
            for message in self.context.__messages:
                messages.add_message(options['version'], ret, message)
        if (
            isinstance(ret, dict)
            and 'summary' in self.output
            and 'summary' not in ret
        ):
            ret['summary'] = self.get_summary_default(ret)
        if self.use_output_validation and (self.output or ret is not None):
            self.validate_output(ret, options['version'])
        return ret

    def add_message(self, message):
        self.context.__messages.append(message)

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
                yield (name, options.pop(name))
        # If any options remain, they are either internal or unknown
        unused_keys = set(options).difference(self.internal_options)
        if unused_keys:
            raise OptionError(_('Unknown option: %(option)s'),
                option=unused_keys.pop())

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
                    yield (name, list(value))
                else:
                    yield (name, kw[name])

    def params_2_args_options(self, **params):
        """
        Split params into (args, options).
        """
        args = tuple()
        options = dict(self.__params_2_options(params))

        is_arg = True
        for name in self.args:
            try:
                value = params[name]
            except KeyError:
                is_arg = False
                continue
            if is_arg:
                args += (value,)
            else:
                options[name] = value

        return (args, options)

    def __params_2_options(self, params):
        for name in self.options:
            if name in params:
                yield(name, params[name])

    def prompt_param(self, param, default=None, optional=False, kw=dict(),
                     label=None):
        """
        Prompts the user for the value of given parameter.

        Returns the parameter instance.
        """

        if label is None:
            label = param.label

        while True:
            raw = self.Backend.textui.prompt(label, default, optional=optional)

            # Backend.textui.prompt does not fill in the default value,
            # we have to do it ourselves
            if not raw.strip():
                return None

            try:
                return param(raw, **kw)
            except (ValidationError, ConversionError) as e:
                # Display error and prompt again
                self.Backend.textui.print_prompt_attribute_error(unicode(label),
                                                             unicode(e.error))

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
            (k, self.params[k].normalize(v)) for (k, v) in kw.items()
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
            (k, self.params[k].convert(v)) for (k, v) in kw.items()
        )

    def __convert_iter(self, kw):
        for param in self.params():
            if kw.get(param.name, None) is None:
                continue

    def get_default(self, _params=None, **kw):
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
        if _params is None:
            _params = [p.name for p in self.params()
                       if p.name not in kw and (p.required or p.autofill)]
        return dict(self.__get_default_iter(_params, kw))

    def get_default_of(self, _name, **kw):
        """
        Return default value for parameter `_name`.
        """
        default = dict(self.__get_default_iter([_name], kw))
        return default.get(_name)

    def __get_default_iter(self, params, kw):
        """
        Generator method used by `Command.get_default` and `Command.get_default_of`.
        """
        # Find out what additional parameters are needed to dynamically create
        # the default values with default_from.
        dep = set()
        for param in reversed(self.params_by_default):
            if param.name in params or param.name in dep:
                if param.default_from is None:
                    continue
                for name in param.default_from.keys:
                    dep.add(name)

        for param in self.params_by_default():
            default = None
            hasdefault = False
            if param.name in dep:
                if param.name in kw:
                    # Parameter is specified, convert and validate the value.
                    value = param(kw[param.name], **kw)
                    if self.api.env.in_server:
                        param.validate(value, supplied=True)
                    kw[param.name] = value
                else:
                    # Parameter is not specified, use default value. Convert
                    # and validate the value, it might not be returned so
                    # there's no guarantee it will be converted and validated
                    # later.
                    default = param(None, **kw)
                    if self.api.env.in_server:
                        param.validate(default)
                    if default is not None:
                        kw[param.name] = default
                    hasdefault = True
            if param.name in params:
                if not hasdefault:
                    # Default value is not available from the previous step,
                    # get it now. At this point it is certain that the value
                    # will be returned, so let the caller care about conversion
                    # and validation.
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
            param.validate(value, supplied=param.name in kw)

    def verify_client_version(self, client_version):
        """
        Compare the version the client provided to the version of the
        server.

        If the client major version does not match then return an error.
        If the client minor version is less than or equal to the server
        then let the request proceed.
        """
        server_apiver = APIVersion(self.api_version)
        try:
            client_apiver = APIVersion(client_version)
        except ValueError:
            raise VersionError(cver=client_version,
                               sver=self.api_version,
                               server=self.env.xmlrpc_uri)

        if client_apiver.major != server_apiver.major:
            raise VersionError(cver=client_version,
                               sver=self.api_version,
                               server=self.env.xmlrpc_uri)

    def run(self, *args, **options):
        """
        Dispatch to `Command.execute` or `Command.forward`.

        If running in a server context, `Command.execute` is called and the
        actually work this command performs is executed locally.

        If running in a non-server context, `Command.forward` is called,
        which forwards this call over RPC to the exact same command
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
        Forward call over RPC to this same command on server.
        """
        try:
            return self.Backend.rpcclient.forward(self.forwarded_name,
                                                  *args, **kw)
        except errors.RequirementError as e:
            if self.api.env.context != 'cli':
                raise
            name = getattr(e, 'name', None)
            if name is None or name not in self.params:
                raise
            raise errors.RequirementError(name=self.params[name].cli_name)

    def _on_finalize(self):
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
        params_nosort = tuple(self.args()) + tuple(self.options())
        def get_key(p):
            if p.required:
                if p.sortorder < 0:
                    return p.sortorder
                if p.default_from is None:
                    return 0
                return 1
            return 2
        self.params = NameSpace(
            sorted(params_nosort, key=get_key),
            sort=False
        )
        # Sort params so that the ones with default_from come after the ones
        # that the default_from might depend on and save the result in
        # params_by_default namespace.
        params = []
        for i in params_nosort:
            pos = len(params)
            for j in params_nosort:
                if j.default_from is None:
                    continue
                if i.name not in j.default_from.keys:
                    continue
                try:
                    pos = min(pos, params.index(j))
                except ValueError:
                    pass
            params.insert(pos, i)
        self.params_by_default = NameSpace(params, sort=False)
        self.output = NameSpace(self._iter_output(), sort=False)
        self._create_param_namespace('output_params')
        super(Command, self)._on_finalize()

    def _iter_output(self):
        if type(self.has_output) is not tuple:
            raise TypeError('%s.has_output: need a %r; got a %r: %r' % (
                self.name, tuple, type(self.has_output), self.has_output)
            )
        for (i, o) in enumerate(self.has_output):
            if isinstance(o, str):
                o = Output(o)
            if not isinstance(o, Output):
                raise TypeError('%s.has_output[%d]: need a %r; got a %r: %r' % (
                    self.name, i, (str, Output), type(o), o)
                )
            yield o

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
                    '%s: required argument after optional in %s arguments %s' % (arg.name,
                    self.name, [x.param_spec for x in args()])
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

        For commands that return entries two special options are generated:
        --all   makes the command retrieve/display all attributes
        --raw   makes the command display attributes as they are stored

        Subclasses can override this to customize how the arguments are
        determined.  For an example of why this can be useful, see the
        `ipalib.crud.Create` subclass.
        """
        for option in self._get_param_iterable('options'):
            yield option
        for o in self.has_output:
            if isinstance(o, (Entry, ListOfEntries)):
                yield Flag('all',
                    cli_name='all',
                    doc=_('Retrieve and print all attributes from the server. Affects command output.'),
                    exclude='webui',
                    flags=['no_output'],
                )
                yield Flag('raw',
                    cli_name='raw',
                    doc=_('Print entries as stored on the server. Only affects output format.'),
                    exclude='webui',
                    flags=['no_output'],
                )
                break
        yield Str('version?',
            doc=_('Client version. Used to determine if server will accept request.'),
            exclude='webui',
            flags=['no_option', 'no_output'],
        )

    def validate_output(self, output, version=API_VERSION):
        """
        Validate the return value to make sure it meets the interface contract.
        """
        nice = '%s.validate_output()' % self.name
        if not isinstance(output, dict):
            raise TypeError('%s: need a %r; got a %r: %r' % (
                nice, dict, type(output), output)
            )
        expected_set = set(self.output)
        actual_set = set(output) - set(['messages'])
        if expected_set != actual_set:
            missing = expected_set - actual_set
            if missing:
                raise ValueError('%s: missing keys %r in %r' % (
                    nice, sorted(missing), output)
                )
            extra = actual_set - expected_set
            if extra:
                raise ValueError('%s: unexpected keys %r in %r' % (
                    nice, sorted(extra), output)
                )
        for o in self.output():
            value = output[o.name]
            if not (o.type is None or isinstance(value, o.type)):
                raise TypeError('%s:\n  output[%r]: need %r; got %r: %r' % (
                    nice, o.name, o.type, type(value), value)
                )
            if callable(o.validate):
                o.validate(self, value, version)

    def get_output_params(self):
        for param in self._get_param_iterable('output_params', verb='has'):
            yield param

    def get_summary_default(self, output):
        if self.msg_summary:
            return self.msg_summary % output
        else:
            return None

    def log_messages(self, output):
        logger_functions = dict(
            debug=logger.debug,
            info=logger.info,
            warning=logger.warning,
            error=logger.error,
        )
        for message in output.get('messages', ()):
            try:
                function = logger_functions[message['type']]
            except KeyError:
                logger.error('Server sent a message with a wrong type')
                function = logger.error
            function(message.get('message'))

    def output_for_cli(self, textui, output, *args, **options):
        """
        Generic output method. Prints values the output argument according
        to their type and self.output.

        Entry attributes are labeled and printed in the order specified in
        self.output_params. Attributes that aren't present in
        self.output_params are not printed unless the command was invokend
        with the --all option. Attribute labelling is disabled if the --raw
        option was given.

        Subclasses can override this method, if custom output is needed.
        """
        if not isinstance(output, dict):
            return None

        rv = 0

        self.log_messages(output)

        order = []
        labels = {}
        flags = {}

        for p in self.output_params():
            order.append(p.name)
            labels[p.name] = unicode(p.label)
            flags[p.name] = p.flags

        if options.get('all', False):
            order.insert(0, 'dn')
            print_all = True
        else:
            print_all = False

        if options.get('raw', False):
            labels = None

        for o in self.output:
            outp = self.output[o]
            if 'no_display' in outp.flags:
                continue
            result = output.get(o)

            if o == 'value':
                continue
            if o.lower() == 'count' and result == 0:
                rv = 1
            elif o.lower() == 'failed':
                if entry_count(result) == 0:
                    # Don't display an empty failed list
                    continue
                # Return an error to the shell
                rv = 1
            if isinstance(outp, ListOfEntries):
                textui.print_entries(result, order, labels, flags, print_all)
            elif isinstance(result, (tuple, list)):
                textui.print_entries(result, order, labels, flags, print_all)
            elif isinstance(outp, Entry):
                textui.print_entry(result, order, labels, flags, print_all)
            elif isinstance(result, dict):
                textui.print_entry(result, order, labels, flags, print_all)
            elif isinstance(result, unicode):
                if o == 'summary':
                    textui.print_summary(result)
                else:
                    textui.print_indented(result)
            elif isinstance(result, bool):
                # the Delete commands return a boolean indicating
                # success or failure. Ignore these.
                pass
            elif isinstance(result, int):
                textui.print_count(result, '%s %%d' % unicode(self.output[o].doc))

        return rv

    # list of attributes we want exported to JSON
    json_friendly_attributes = (
        'name', 'doc', 'NO_CLI'
    )

    def __json__(self):
        json_dict = dict(
            (a, getattr(self, a)) for a in self.json_friendly_attributes
        )

        json_dict['takes_args'] = list(self.get_args())
        json_dict['takes_options'] = list(self.get_options())

        return json_dict

    @classmethod
    def get_callbacks(cls, callback_type):
        """Yield callbacks of the given type"""
        # Use one shared callback registry, keyed on class, to avoid problems
        # with missing attributes being looked up in superclasses
        callbacks = _callback_registry.get(callback_type, {}).get(cls, [None])
        for callback in callbacks:
            if callback is None:
                try:
                    yield getattr(cls, '%s_callback' % callback_type)
                except AttributeError:
                    pass
            else:
                yield callback

    @classmethod
    def register_callback(cls, callback_type, callback, first=False):
        """Register a callback

        :param callback_type: The callback type (e.g. 'pre', 'post')
        :param callback: The callable added
        :param first: If true, the new callback will be added before all
            existing callbacks; otherwise it's added after them

        Note that callbacks registered this way will be attached to this class
        only, not to its subclasses.
        """
        assert callback_type in cls.callback_types
        assert callable(callback)
        _callback_registry.setdefault(callback_type, {})
        try:
            callbacks = _callback_registry[callback_type][cls]
        except KeyError:
            callbacks = _callback_registry[callback_type][cls] = [None]
        if first:
            callbacks.insert(0, callback)
        else:
            callbacks.append(callback)

    @classmethod
    def register_interactive_prompt_callback(cls, callback, first=False):
        """Shortcut for register_callback('interactive_prompt', ...)"""
        cls.register_callback('interactive_prompt', callback, first)

    def interactive_prompt_callback(self, kw):
        pass


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
            doc=_('Forward to server instead of running locally'),
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
        if options.get('server', False) and not self.env.in_server:
            return self.forward(*args, **options)
        return self.execute(*args, **options)


class Local(Command):
    """
    A command that is explicitly executed locally.

    This is for commands that makes sense to execute only locally
    such as the help command.
    """

    def run(self, *args, **options):
        """
        Dispatch to forward() onlly.
        """
        return self.forward(*args, **options)

    def forward(self, *args, **options):
        return self.execute(*args, **options)


class Object(HasParam):
    # Create stubs for attributes that are set in _on_finalize()
    backend = Plugin.finalize_attr('backend')
    methods = Plugin.finalize_attr('methods')
    params = Plugin.finalize_attr('params')
    primary_key = Plugin.finalize_attr('primary_key')
    params_minus_pk = Plugin.finalize_attr('params_minus_pk')

    # Can override in subclasses:
    backend_name = None
    takes_params = tuple()

    def _on_finalize(self):
        self.methods = NameSpace(
            self.__get_attrs('Method'), sort=False, name_attr='attr_name'
        )
        self._create_param_namespace('params')
        pkeys = [p for p in self.params() if p.primary_key]
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
                [p for p in self.params() if not p.primary_key], sort=False
            )
        else:
            self.primary_key = None
            self.params_minus_pk = self.params

        if 'Backend' in self.api and self.backend_name in self.api.Backend:
            self.backend = self.api.Backend[self.backend_name]

        super(Object, self)._on_finalize()

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
        assert type(namespace) is APINameSpace
        for plugin in namespace(): # Equivalent to dict.itervalues()
            if plugin is not namespace[plugin.name]:
                continue
            if plugin.obj_name == self.name:
                yield plugin

    def get_params(self):
        """
        This method gets called by `HasParam._create_param_namespace()`.
        """
        for spec in self._get_param_iterable('params'):
            assert isinstance(spec, (str, Param))
            yield create_param(spec)

    json_friendly_attributes = (
        'name', 'takes_params',
    )

    def __json__(self):
        json_dict = dict(
            (a, json_serialize(getattr(self, a)))
            for a in self.json_friendly_attributes
        )
        if self.primary_key:
            json_dict['primary_key'] = self.primary_key.name
        json_dict['methods'] = list(self.methods)
        return json_dict


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
    only the base class for the `Method` class.  Also see the `Object` class.
    """
    obj_version = '1'

    @property
    def obj_name(self):
        return self.name.partition('_')[0]

    @property
    def obj_full_name(self):
        if self.obj is not None:
            return self.obj.full_name
        else:
            return None

    @property
    def attr_name(self):
        prefix = '{}_'.format(self.obj_name)
        assert self.name.startswith(prefix)
        return self.name[len(prefix):]

    @property
    def obj(self):
        if self.obj_name is not None and self.obj_version is not None:
            return self.api.Object[self.obj_name, self.obj_version]
        else:
            return None


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
    ...     def run(self, **options):
    ...             return dict(result='Added the user!')
    ...
    >>> class user(Object):
    ...     pass
    ...
    >>> api.add_plugin(user_add)
    >>> api.add_plugin(user)
    >>> api.finalize()

    First, the ``user_add`` plugin can be accessed through the ``api.Method``
    namespace:

    >>> list(api.Method)
    [<class '__main__.user_add'>]
    >>> api.Method.user_add(version=u'2.88')  # Will call user_add.run()
    {'result': 'Added the user!'}

    (The "version" argument is the API version to use.
    The current API version can be found in ipalib.version.API_VERSION.)

    Second, because `Method` is a subclass of `Command`, the ``user_add``
    plugin can also be accessed through the ``api.Command`` namespace:

    >>> list(api.Command)
    [<class '__main__.user_add'>]
    >>> api.Command.user_add(version=u'2.88') # Will call user_add.run()
    {'result': 'Added the user!'}

    And third, ``user_add`` can be accessed as an attribute on the ``user``
    `Object`:

    >>> list(api.Object)
    [<class '__main__.user'>]
    >>> list(api.Object.user.methods)
    ['add']
    >>> api.Object.user.methods.add(version=u'2.88') # Will call user_add.run()
    {'result': 'Added the user!'}

    The `Attribute` base class implements the naming convention for the
    attribute-to-object association.  Also see the `Object` class.
    """
    extra_options_first = False
    extra_args_first = False

    def get_output_params(self):
        if self.obj is not None:
            for param in self.obj.params():
                if 'no_output' in param.flags:
                    continue
                yield param
        for param in super(Method, self).get_output_params():
            yield param


class Updater(Plugin):
    """
    An LDAP update with an associated object (always update).

    All plugins that subclass from `Updater` will be automatically available
    as a server update function.

    Plugins that subclass from Updater are registered in the ``api.Updater``
    namespace. For example:

    >>> from ipalib import create_api
    >>> api = create_api()
    >>> class my(Object):
    ...     pass
    ...
    >>> api.add_plugin(my)
    >>> class my_update(Updater):
    ...     pass
    ...
    >>> api.add_plugin(my_update)
    >>> api.finalize()
    >>> list(api.Updater)
    [<class '__main__.my_update'>]
    >>> api.Updater.my_update # doctest:+ELLIPSIS
    ipalib.frontend.my_update()
    """
    def execute(self, **options):
        raise NotImplementedError('%s.execute()' % self.name)

    def __call__(self, **options):
        logger.debug(
            'raw: %s', self.name
        )

        return self.execute(**options)
