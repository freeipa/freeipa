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
Plugin framework.

The classes in this module make heavy use of Python container emulation. If
you are unfamiliar with this Python feature, see
http://docs.python.org/ref/sequence-types.html
"""

import re
import sys
import inspect
import threading
import logging
import os
from os import path
import subprocess
import optparse
import errors
from config import Env
import util
from base import ReadOnly, NameSpace, lock, islocked, check_name
from constants import DEFAULT_CONFIG, FORMAT_STDERR, FORMAT_FILE


class SetProxy(ReadOnly):
    """
    A read-only container with set/sequence behaviour.

    This container acts as a proxy to an actual set-like object (a set,
    frozenset, or dict) that is passed to the constructor. To the extent
    possible in Python, this underlying set-like object cannot be modified
    through the SetProxy... which just means you wont do it accidentally.
    """
    def __init__(self, s):
        """
        :param s: The target set-like object (a set, frozenset, or dict)
        """
        allowed = (set, frozenset, dict)
        if type(s) not in allowed:
            raise TypeError('%r not in %r' % (type(s), allowed))
        self.__s = s
        lock(self)

    def __len__(self):
        """
        Return the number of items in this container.
        """
        return len(self.__s)

    def __iter__(self):
        """
        Iterate (in ascending order) through keys.
        """
        for key in sorted(self.__s):
            yield key

    def __contains__(self, key):
        """
        Return True if this container contains ``key``.

        :param key: The key to test for membership.
        """
        return key in self.__s


class DictProxy(SetProxy):
    """
    A read-only container with mapping behaviour.

    This container acts as a proxy to an actual mapping object (a dict) that
    is passed to the constructor. To the extent possible in Python, this
    underlying mapping object cannot be modified through the DictProxy...
    which just means you wont do it accidentally.

    Also see `SetProxy`.
    """
    def __init__(self, d):
        """
        :param d: The target mapping object (a dict)
        """
        if type(d) is not dict:
            raise TypeError('%r is not %r' % (type(d), dict))
        self.__d = d
        super(DictProxy, self).__init__(d)

    def __getitem__(self, key):
        """
        Return the value corresponding to ``key``.

        :param key: The key of the value you wish to retrieve.
        """
        return self.__d[key]

    def __call__(self):
        """
        Iterate (in ascending order by key) through values.
        """
        for key in self:
            yield self.__d[key]


class MagicDict(DictProxy):
    """
    A mapping container whose values can be accessed as attributes.

    For example:

    >>> magic = MagicDict({'the_key': 'the value'})
    >>> magic['the_key']
    'the value'
    >>> magic.the_key
    'the value'

    This container acts as a proxy to an actual mapping object (a dict) that
    is passed to the constructor. To the extent possible in Python, this
    underlying mapping object cannot be modified through the MagicDict...
    which just means you wont do it accidentally.

    Also see `DictProxy` and `SetProxy`.
    """

    def __getattr__(self, name):
        """
        Return the value corresponding to ``name``.

        :param name: The name of the attribute you wish to retrieve.
        """
        try:
            return self[name]
        except KeyError:
            raise AttributeError('no magic attribute %r' % name)


class Plugin(ReadOnly):
    """
    Base class for all plugins.
    """

    def __init__(self):
        self.__api = None
        cls = self.__class__
        self.name = cls.__name__
        self.module = cls.__module__
        self.fullname = '%s.%s' % (self.module, self.name)
        self.bases = tuple(
            '%s.%s' % (b.__module__, b.__name__) for b in cls.__bases__
        )
        self.doc = inspect.getdoc(cls)
        if self.doc is None:
            self.summary = '<%s>' % self.fullname
        else:
            self.summary = self.doc.split('\n\n', 1)[0]
        log = logging.getLogger(self.fullname)
        for name in ('debug', 'info', 'warning', 'error', 'critical', 'exception'):
            if hasattr(self, name):
                raise StandardError(
                    '%s.%s attribute (%r) conflicts with Plugin logger' % (
                        self.name, name, getattr(self, name))
                )
            setattr(self, name, getattr(log, name))

    def __get_api(self):
        """
        Return `API` instance passed to `finalize()`.

        If `finalize()` has not yet been called, None is returned.
        """
        return self.__api
    api = property(__get_api)

    def finalize(self):
        """
        """
        lock(self)

    def set_api(self, api):
        """
        Set reference to `API` instance.
        """
        assert self.__api is None, 'set_api() can only be called once'
        assert api is not None, 'set_api() argument cannot be None'
        self.__api = api
        if not isinstance(api, API):
            return
        for name in api:
            assert not hasattr(self, name)
            setattr(self, name, api[name])
        # FIXME: the 'log' attribute is depreciated.  See Plugin.__init__()
        for name in ('env', 'context', 'log'):
            if hasattr(api, name):
                assert not hasattr(self, name)
                setattr(self, name, getattr(api, name))

    def call(self, executable, *args):
        """
        Call ``executable`` with ``args`` using subprocess.call().

        If the call exits with a non-zero exit status,
        `ipalib.errors.SubprocessError` is raised, from which you can retrieve
        the exit code by checking the SubprocessError.returncode attribute.

        This method does *not* return what ``executable`` sent to stdout... for
        that, use `Plugin.callread()`.
        """
        argv = (executable,) + args
        self.debug('Calling %r', argv)
        code = subprocess.call(argv)
        if code != 0:
            raise errors.SubprocessError(returncode=code, argv=argv)

    def __repr__(self):
        """
        Return 'module_name.class_name()' representation.

        This representation could be used to instantiate this Plugin
        instance given the appropriate environment.
        """
        return '%s.%s()' % (
            self.__class__.__module__,
            self.__class__.__name__
        )


class Registrar(DictProxy):
    """
    Collects plugin classes as they are registered.

    The Registrar does not instantiate plugins... it only implements the
    override logic and stores the plugins in a namespace per allowed base
    class.

    The plugins are instantiated when `API.finalize()` is called.
    """
    def __init__(self, *allowed):
        """
        :param allowed: Base classes from which plugins accepted by this
            Registrar must subclass.
        """
        self.__allowed = dict((base, {}) for base in allowed)
        self.__registered = set()
        super(Registrar, self).__init__(
            dict(self.__base_iter())
        )

    def __base_iter(self):
        for (base, sub_d) in self.__allowed.iteritems():
            assert inspect.isclass(base)
            name = base.__name__
            assert not hasattr(self, name)
            setattr(self, name, MagicDict(sub_d))
            yield (name, base)

    def __findbases(self, klass):
        """
        Iterates through allowed bases that ``klass`` is a subclass of.

        Raises `errors.PluginSubclassError` if ``klass`` is not a subclass of
        any allowed base.

        :param klass: The plugin class to find bases for.
        """
        assert inspect.isclass(klass)
        found = False
        for (base, sub_d) in self.__allowed.iteritems():
            if issubclass(klass, base):
                found = True
                yield (base, sub_d)
        if not found:
            raise errors.PluginSubclassError(
                plugin=klass, bases=self.__allowed.keys()
            )

    def __call__(self, klass, override=False):
        """
        Register the plugin ``klass``.

        :param klass: A subclass of `Plugin` to attempt to register.
        :param override: If true, override an already registered plugin.
        """
        if not inspect.isclass(klass):
            raise TypeError('plugin must be a class; got %r' % klass)

        # Raise DuplicateError if this exact class was already registered:
        if klass in self.__registered:
            raise errors.PluginDuplicateError(plugin=klass)

        # Find the base class or raise SubclassError:
        for (base, sub_d) in self.__findbases(klass):
            # Check override:
            if klass.__name__ in sub_d:
                if not override:
                    # Must use override=True to override:
                    raise errors.PluginOverrideError(
                        base=base.__name__,
                        name=klass.__name__,
                        plugin=klass,
                    )
            else:
                if override:
                    # There was nothing already registered to override:
                    raise errors.PluginMissingOverrideError(
                        base=base.__name__,
                        name=klass.__name__,
                        plugin=klass,
                    )

            # The plugin is okay, add to sub_d:
            sub_d[klass.__name__] = klass

        # The plugin is okay, add to __registered:
        self.__registered.add(klass)


class API(DictProxy):
    """
    Dynamic API object through which `Plugin` instances are accessed.
    """

    def __init__(self, *allowed):
        self.__d = dict()
        self.__done = set()
        self.register = Registrar(*allowed)
        self.env = Env()
        super(API, self).__init__(self.__d)

    def __doing(self, name):
        if name in self.__done:
            raise StandardError(
                '%s.%s() already called' % (self.__class__.__name__, name)
            )
        self.__done.add(name)

    def __do_if_not_done(self, name):
        if name not in self.__done:
            getattr(self, name)()

    def isdone(self, name):
        return name in self.__done

    def bootstrap(self, **overrides):
        """
        Initialize environment variables and logging.
        """
        self.__doing('bootstrap')
        self.env._bootstrap(**overrides)
        self.env._finalize_core(**dict(DEFAULT_CONFIG))
        log = logging.getLogger()
        object.__setattr__(self, 'log', log)
        if self.env.debug:
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.INFO)

        # Add stderr handler:
        stderr = logging.StreamHandler()
        if self.env.debug:
            stderr.setLevel(logging.DEBUG)
        elif self.env.verbose:
            stderr.setLevel(logging.INFO)
        else:
            stderr.setLevel(logging.WARNING)
        stderr.setFormatter(util.LogFormatter(FORMAT_STDERR))
        log.addHandler(stderr)

        # Add file handler:
        if self.env.mode in ('dummy', 'unit_test'):
            return  # But not if in unit-test mode
        if self.env.log is None:
            return
        log_dir = path.dirname(self.env.log)
        if not path.isdir(log_dir):
            try:
                os.makedirs(log_dir)
            except OSError:
                log.error('Could not create log_dir %r', log_dir)
                return
        try:
            handler = logging.FileHandler(self.env.log)
        except IOError, e:
            log.error('Cannot open log file %r: %s', self.env.log, e.strerror)
            return
        handler.setFormatter(util.LogFormatter(FORMAT_FILE))
        if self.env.debug:
            handler.setLevel(logging.DEBUG)
        else:
            handler.setLevel(logging.INFO)
        log.addHandler(handler)

    def build_global_parser(self, parser=None, context=None):
        """
        Add global options to an optparse.OptionParser instance.
        """
        if parser is None:
            parser = optparse.OptionParser()
            parser.disable_interspersed_args()
        parser.add_option('-e', dest='env', metavar='KEY=VAL', action='append',
            help='Set environment variable KEY to VAL',
        )
        parser.add_option('-c', dest='conf', metavar='FILE',
            help='Load configuration from FILE',
        )
        parser.add_option('-d', '--debug', action='store_true',
            help='Produce full debuging output',
        )
        parser.add_option('-v', '--verbose', action='store_true',
            help='Produce more verbose output',
        )
        if context == 'cli':
            parser.add_option('-a', '--prompt-all', action='store_true',
                help='Prompt for ALL values (even if optional)'
            )
            parser.add_option('-n', '--no-prompt', action='store_false',
                dest='interactive',
                help='Prompt for NO values (even if required)'
            )
        topics = optparse.OptionGroup(parser, "Available help topics",
                    "ipa help topics")
        cmds = optparse.OptionGroup(parser, "Available commands",
                    "ipa help commands")
        parser.add_option_group(topics)
        parser.add_option_group(cmds)

        return parser

    def bootstrap_with_global_options(self, parser=None, context=None):
        parser = self.build_global_parser(parser, context)
        (options, args) = parser.parse_args()
        overrides = {}
        if options.env is not None:
            assert type(options.env) is list
            for item in options.env:
                try:
                    (key, value) = item.split('=', 1)
                except ValueError:
                    # FIXME: this should raise an IPA exception with an
                    # error code.
                    # --Jason, 2008-10-31
                    pass
                overrides[str(key.strip())] = value.strip()
        for key in ('conf', 'debug', 'verbose', 'prompt_all', 'interactive'):
            value = getattr(options, key, None)
            if value is not None:
                overrides[key] = value
        if hasattr(options, 'prod'):
            overrides['webui_prod'] = options.prod
        if context is not None:
            overrides['context'] = context
        self.bootstrap(**overrides)
        return (options, args)

    def load_plugins(self):
        """
        Load plugins from all standard locations.

        `API.bootstrap` will automatically be called if it hasn't been
        already.
        """
        self.__doing('load_plugins')
        self.__do_if_not_done('bootstrap')
        if self.env.mode in ('dummy', 'unit_test'):
            return
        self.import_plugins('ipalib')
        if self.env.in_server:
            self.import_plugins('ipaserver')

    # FIXME: This method has no unit test
    def import_plugins(self, package):
        """
        Import modules in ``plugins`` sub-package of ``package``.
        """
        subpackage = '%s.plugins' % package
        try:
            parent = __import__(package)
            plugins = __import__(subpackage).plugins
        except ImportError, e:
            self.log.error(
                'cannot import plugins sub-package %s: %s', subpackage, e
            )
            raise e
        parent_dir = path.dirname(path.abspath(parent.__file__))
        plugins_dir = path.dirname(path.abspath(plugins.__file__))
        if parent_dir == plugins_dir:
            raise errors.PluginsPackageError(
                name=subpackage, file=plugins.__file__
            )
        self.log.debug('importing all plugin modules in %r...', plugins_dir)
        for (name, pyfile) in util.find_modules_in_dir(plugins_dir):
            fullname = '%s.%s' % (subpackage, name)
            self.log.debug('importing plugin module %r', pyfile)
            try:
                __import__(fullname)
            except errors.SkipPluginModule, e:
                self.log.info(
                    'skipping plugin module %s: %s', fullname, e.reason
                )
            except StandardError, e:
                import traceback
                self.log.error('could not load plugin module %r\n%s', pyfile, traceback.format_exc())
                raise e

    def finalize(self):
        """
        Finalize the registration, instantiate the plugins.

        `API.bootstrap` will automatically be called if it hasn't been
        already.
        """
        self.__doing('finalize')
        self.__do_if_not_done('load_plugins')

        class PluginInstance(object):
            """
            Represents a plugin instance.
            """

            i = 0

            def __init__(self, klass):
                self.created = self.next()
                self.klass = klass
                self.instance = klass()
                self.bases = []

            @classmethod
            def next(cls):
                cls.i += 1
                return cls.i

        class PluginInfo(ReadOnly):
            def __init__(self, p):
                assert isinstance(p, PluginInstance)
                self.created = p.created
                self.name = p.klass.__name__
                self.module = str(p.klass.__module__)
                self.plugin = '%s.%s' % (self.module, self.name)
                self.bases = tuple(b.__name__ for b in p.bases)
                lock(self)

        plugins = {}
        def plugin_iter(base, subclasses):
            for klass in subclasses:
                assert issubclass(klass, base)
                if klass not in plugins:
                    plugins[klass] = PluginInstance(klass)
                p = plugins[klass]
                assert base not in p.bases
                p.bases.append(base)
                yield p.instance

        for name in self.register:
            base = self.register[name]
            magic = getattr(self.register, name)
            namespace = NameSpace(
                plugin_iter(base, (magic[k] for k in magic))
            )
            assert not (
                name in self.__d or hasattr(self, name)
            )
            self.__d[name] = namespace
            object.__setattr__(self, name, namespace)

        for p in plugins.itervalues():
            p.instance.set_api(self)
            assert p.instance.api is self

        for p in plugins.itervalues():
            p.instance.finalize()
            assert islocked(p.instance) is True
        object.__setattr__(self, '_API__finalized', True)
        tuple(PluginInfo(p) for p in plugins.itervalues())
        object.__setattr__(self, 'plugins',
            tuple(PluginInfo(p) for p in plugins.itervalues())
        )
